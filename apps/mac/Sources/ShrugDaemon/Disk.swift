import CryptoKit
import Darwin
import Foundation
import ShrugCore

/// The disk image behind ~/ShrugDisk, as Shrug drives it. `SparseDisk` is the real one; tests
/// stand in for it.
public protocol DiskImage {
    /// Whether the image has been made.
    var exists: Bool { get }
    /// Makes a new, empty disk that `key` opens.
    func create(key: String) throws
    /// Attaches the disk and shows it at ~/ShrugDisk.
    func attach(key: String) throws
    /// Ejects the disk, whoever has files open on it, and whatever a crash left attached.
    /// Throws if it's still there afterwards.
    func eject() throws
    var isAttached: Bool { get }
    /// While attached: the bytes its files take.
    var used: Int64? { get }
    /// While attached: whether anything has been put on it.
    var holdsFiles: Bool { get }
    /// The bytes the image takes on this Mac's own disk.
    var onDisk: Int64 { get }
    /// Gives this Mac back the space the image holds for files that are gone. Only while ejected.
    func reclaim(key: String) throws
}

/// ~/ShrugDisk: an encrypted disk for working data (code, customer files, anything large or
/// with many files), which ~/Shrug is too slow for. Its rules are local/'s: this Mac only,
/// never uploaded, opened by this Mac's local key. It is attached while Shrug is unlocked and
/// ejected when Shrug locks. Unlike ~/Shrug it can't ask to unlock when a program opens a file:
/// while Shrug is locked it's an empty folder.
final class WorkDisk {
    enum State: Equatable { case closed, opening, open, failed(String) }

    /// The image is only worth shrinking when that gives back this much, and more than its
    /// files take (it means moving them, which can run to minutes).
    static var worthReclaiming: Int64 = ProcessInfo.processInfo.environment["SHRUG_TEST_RECLAIM_MB"]
        .flatMap(Int64.init).map { $0 << 20 } ?? 2 << 30

    /// Weak: work on the queue can outlast the engine (in tests; the app's lives as long as it does).
    private weak var engine: Engine?
    private let paths: ShrugPaths
    let image: DiskImage
    /// Making, attaching and ejecting take a second or so each, and go one at a time.
    private let queue = DispatchQueue(label: "shrug.disk")
    private let lock = NSLock()
    private var state = State.closed
    /// Goes up with every open and close: work started for an earlier one stops.
    private var turn = 0
    private var reclaiming = false
    private var reclaimDue = false
    /// The disk didn't eject when Shrug locked: `retry` keeps at it, one try at a time.
    private var stuck = false
    private var retrying = false

    init(engine: Engine, image: DiskImage) {
        self.engine = engine
        paths = engine.paths
        self.image = image
    }

    /// What `key` is to the image: derived from this Mac's local key, so the disk opens with
    /// whatever unlocks Shrug here and nowhere else.
    static func key(_ local: SymmetricKey) -> String {
        ShrugCrypto.subkey(local, "shrug-disk-v1").rawData.hex
    }

    /// ~/ShrugDisk as you'd type it.
    var shown: String { paths.contract(paths.disk) }

    /// At start: nothing of the disk stays attached while Shrug is locked, whatever the last
    /// run left behind.
    func reset() {
        queue.sync { ejectNow() }
    }

    /// Shrug unlocked: makes the disk if this Mac has none yet, and attaches it. Returns at once.
    func open(key: String) {
        lock.lock()
        turn += 1
        let mine = turn
        state = .opening
        lock.unlock()
        queue.async { [self] in
            guard isTurn(mine) else { return }
            do {
                if !image.exists {
                    try image.create(key: key)
                    engine?.log("made the disk")
                } else {
                    reclaimIfDue(key: key, turn: mine)
                }
                guard isTurn(mine) else { return } // locked meanwhile: nothing to attach
                try image.attach(key: key)
                finish(mine, .open)
            } catch {
                engine?.log("the disk didn't open: \(error)")
                finish(mine, .failed("\(error)"))
            }
        }
    }

    /// Shrug locked: ejects the disk before returning, whoever is using it. True if it was
    /// attached with files on it.
    @discardableResult
    func close() -> Bool {
        lock.lock()
        turn += 1
        state = .closed
        let busy = reclaiming
        lock.unlock()
        // Nothing is attached while space is given back, which can take minutes and can't be
        // cut short safely: it runs to its end with the disk's key, then stops.
        if busy { return false }
        return queue.sync {
            guard image.isAttached else { return false }
            let files = image.holdsFiles
            let used = image.used ?? 0
            ejectNow()
            let due = image.onDisk - used > max(WorkDisk.worthReclaiming, used)
            lock.lock()
            reclaimDue = due
            lock.unlock()
            return files
        }
    }

    /// Every second while it matters: a disk that didn't eject is tried again.
    func retry() {
        lock.lock()
        let again = stuck && state == .closed && !retrying
        if again { retrying = true }
        lock.unlock()
        guard again else { return }
        queue.async { [self] in
            if isClosed { ejectNow() }
            lock.lock()
            retrying = false
            lock.unlock()
        }
    }

    /// Waits for an open under way, but not for long: for commands that should return with
    /// the disk there.
    func settle(_ seconds: TimeInterval = 20) {
        let done = DispatchSemaphore(value: 0)
        queue.async { done.signal() }
        _ = done.wait(timeout: .now() + seconds)
    }

    /// For status. While Shrug is locked there's nothing to say, unless the disk didn't eject.
    func status(unlocked: Bool) -> DiskInfo? {
        lock.lock()
        let (now, stuck) = (state, stuck)
        lock.unlock()
        var info = DiskInfo(path: paths.disk.path)
        if stuck {
            info.problem = "STILL OPEN: it couldn't be ejected, and Shrug keeps trying"
            return info
        }
        guard unlocked else { return nil }
        switch now {
        case .closed: break
        case .opening: info.opening = true
        case .failed(let why): info.problem = "not open: \(why)"
        case .open:
            guard image.isAttached else {
                info.problem = "not open: it was ejected (lock and unlock Shrug to open it again)"
                break
            }
            info.open = true
            info.used = image.used
            var s = statfs()
            if statfs(paths.state.path, &s) == 0 { info.free = Int64(s.f_bavail) * Int64(s.f_bsize) }
        }
        return info
    }

    // MARK: - On the queue

    private func ejectNow() {
        do {
            try image.eject()
            setStuck(false)
        } catch {
            setStuck(true)
            engine?.log("the disk didn't eject: \(error)")
            engine?.changed()
        }
    }

    private func reclaimIfDue(key: String, turn mine: Int) {
        lock.lock()
        let go = reclaimDue && turn == mine
        if go {
            reclaimDue = false
            reclaiming = true
        }
        lock.unlock()
        guard go else { return }
        defer {
            lock.lock()
            reclaiming = false
            lock.unlock()
        }
        let before = image.onDisk
        engine?.event("Giving unused space on \(shown) back to this Mac", log: "giving the disk's unused space back")
        do {
            try image.reclaim(key: key)
            engine?.log("gave back \((before - image.onDisk) >> 20) MB of the disk's unused space")
        } catch {
            // The disk is whole either way: it just keeps the space for now.
            engine?.log("giving the disk's space back failed: \(error)")
        }
    }

    // MARK: - State

    private func isTurn(_ mine: Int) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return turn == mine
    }

    private var isClosed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return state == .closed
    }

    private func setStuck(_ value: Bool) {
        lock.lock()
        stuck = value
        lock.unlock()
    }

    private func finish(_ mine: Int, _ new: State) {
        lock.lock()
        let current = turn == mine
        if current { state = new }
        lock.unlock()
        if current { engine?.changed() }
    }
}

/// The real disk: an encrypted APFS sparse bundle in ~/.shrug, driven with hdiutil. A sparse
/// bundle keeps the disk as many 8 MB files, so a backup copies only the ones that changed
/// (Time Machine is the only backup this disk gets).
final class SparseDisk: DiskImage {
    let image: URL
    let mount: URL
    /// The helper that ejects the disk if Shrug dies, and the pipe it waits on.
    private var watchdog: (helper: Process, pipe: Pipe)?

    init(paths: ShrugPaths) {
        image = paths.diskImage
        mount = paths.disk
    }

    var exists: Bool { FileManager.default.fileExists(atPath: image.path) }

    /// As large as this Mac's own disk: the image only takes the space its files do, so the
    /// real limit is what's free on the Mac.
    private var size: String {
        var s = statfs()
        guard statfs(image.deletingLastPathComponent().path, &s) == 0 else { return "256g" }
        return "\(max(16, Int((UInt64(s.f_blocks) * UInt64(s.f_bsize) + (1 << 30) - 1) >> 30)))g"
    }

    func create(key: String) throws {
        // Under another name until it's whole: an image that is there can always be attached.
        let new = image.deletingLastPathComponent().appendingPathComponent("disk.new.sparsebundle")
        try? FileManager.default.removeItem(at: new)
        try hdiutil(["create", "-type", "SPARSEBUNDLE", "-fs", "APFS", "-volname", "ShrugDisk", "-size", size,
                     "-encryption", "AES-256", "-stdinpass", "-uid", "\(getuid())", "-gid", "\(getgid())", new.path],
                    key: key)
        try FileManager.default.moveItem(at: new, to: image)
    }

    func attach(key: String) throws {
        if isAttached { return }
        // Never hide someone's files: only attach over an empty folder.
        if let there = try? FileManager.default.contentsOfDirectory(atPath: mount.path),
           !there.filter({ $0 != ".DS_Store" && $0 != ".localized" }).isEmpty {
            throw ShrugError("\(mount.path) already has files in it. Move them somewhere else, then lock and unlock Shrug.")
        }
        try FileManager.default.createDirectory(at: mount, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o500])
        // Giving space back was cut short: the disk may still be smaller than it should be.
        // It opens either way, and the next attach tries again.
        if FileManager.default.fileExists(atPath: resizing.path) { try? regrow(key: key) }
        try watch()
        do {
            try hdiutil(["attach", "-stdinpass", "-mountpoint", mount.path, "-nobrowse", "-owners", "on", image.path],
                        key: key)
        } catch {
            // Attached but not shown (the mount failed): nothing of it may stay behind.
            for device in devices() { _ = try? hdiutil(["detach", device, "-force"]) }
            dismissWatchdog()
            throw error
        }
        // Only this user: the disk honours owners, and its top folder starts out open to all.
        chmod(mount.path, 0o700)
    }

    func eject() throws {
        if isAttached {
            // Plainly first, which fails if anything has a file open; then whoever does.
            if (try? hdiutil(["detach", mount.path])) == nil { _ = try? hdiutil(["detach", mount.path, "-force"]) }
        } else {
            // Attached without showing at ~/ShrugDisk (a crash between the two): found by its image.
            for device in devices() { _ = try? hdiutil(["detach", device, "-force"]) }
        }
        guard !isAttached else { throw ShrugError("it is still attached") }
        dismissWatchdog()
        // Without the disk, ~/ShrugDisk is an empty folder nobody can write into, so nothing
        // lands there unencrypted by mistake. A folder with files in it is someone's: left alone.
        try? FileManager.default.createDirectory(at: mount, withIntermediateDirectories: true)
        if (try? FileManager.default.contentsOfDirectory(atPath: mount.path))?.isEmpty == true { chmod(mount.path, 0o500) }
    }

    var isAttached: Bool { Mounter.fileSystem(at: mount) != nil }

    /// What the disk's files take. Asked of the disk itself: going by its free space says
    /// nothing, since that is this Mac's free space.
    var used: Int64? {
        guard isAttached else { return nil }
        var want = attrlist()
        want.bitmapcount = UInt16(ATTR_BIT_MAP_COUNT)
        want.volattr = attrgroup_t(ATTR_VOL_INFO) | attrgroup_t(ATTR_VOL_SPACEUSED)
        var got = [UInt8](repeating: 0, count: 12) // its length, then the bytes used
        guard getattrlist(mount.path, &want, &got, got.count, 0) == 0 else { return nil }
        return got.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 4, as: Int64.self) }
    }

    /// What macOS puts on every disk by itself doesn't count.
    var holdsFiles: Bool {
        let system: Set = [".fseventsd", ".Spotlight-V100", ".Trashes", ".DS_Store", ".TemporaryItems",
                           ".DocumentRevisions-V100", ".VolumeIcon.icns", ".apdisk"]
        guard isAttached, let names = try? FileManager.default.contentsOfDirectory(atPath: mount.path) else { return false }
        return names.contains { !system.contains($0) }
    }

    var onDisk: Int64 {
        let bands = image.appendingPathComponent("bands")
        var total: Int64 = 0
        for name in (try? FileManager.default.contentsOfDirectory(atPath: bands.path)) ?? [] {
            var s = stat()
            if stat(bands.appendingPathComponent(name).path, &s) == 0 { total += Int64(s.st_blocks) * 512 }
        }
        return total
    }

    // MARK: - Giving space back

    /// Marks a reclaim under way, so one cut short (a crash, a power cut) is finished by the
    /// next attach.
    private var resizing: URL { image.deletingLastPathComponent().appendingPathComponent("disk.resizing") }

    /// macOS never tells a disk image which of its space was freed, so the image only grows:
    /// a deleted file's space stays taken on the Mac. Shrinking the disk as far as it goes
    /// moves its files to the front and drops the rest of the image; it then grows back to
    /// full size, which takes no space.
    func reclaim(key: String) throws {
        guard !isAttached else { return }
        FileManager.default.createFile(atPath: resizing.path, contents: nil)
        let shrunk = Result { try hdiutil(["resize", "-size", "min", "-stdinpass", image.path], key: key) }
        try regrow(key: key)
        _ = try shrunk.get()
    }

    private func regrow(key: String) throws {
        try hdiutil(["resize", "-size", size, "-stdinpass", image.path], key: key)
        try? FileManager.default.removeItem(at: resizing)
    }

    // MARK: - If Shrug dies

    /// Waits for a word from Shrug. If the pipe closes without one, Shrug is gone, and it ejects
    /// the disk, trying for a while in case the attach was still under way. It unmounts first:
    /// that takes effect at once, where detaching the image can wait several seconds on a
    /// system that still expects an answer from the Shrug that died.
    private static let watchdogScript = """
    trap '' INT TERM HUP
    IFS= read -r word
    [ "$word" = closed ] && exit 0
    n=0
    while [ $n -lt 20 ]; do
      device=$(/sbin/mount | /usr/bin/awk -v at=" on $1 (" 'index($0, at) { print $1; exit }')
      if [ -n "$device" ]; then
        /sbin/umount -f "$1" >/dev/null 2>&1
        /usr/bin/hdiutil detach "$device" -force >/dev/null 2>&1 && exit 0
      fi
      n=$((n + 1))
      sleep 1
    done
    """

    /// Started before the attach, so there's never a disk with nobody watching it.
    private func watch() throws {
        dismissWatchdog()
        let helper = Process()
        helper.executableURL = URL(fileURLWithPath: "/bin/sh")
        helper.arguments = ["-c", SparseDisk.watchdogScript, "shrug-disk-watch", mount.path]
        let pipe = Pipe()
        // Only Shrug may hold the writing end. A copy inherited by the helper itself, or by
        // any other program Shrug starts, would keep the pipe open after Shrug is gone.
        for end in [pipe.fileHandleForReading, pipe.fileHandleForWriting] { _ = fcntl(end.fileDescriptor, F_SETFD, FD_CLOEXEC) }
        helper.standardInput = pipe
        helper.standardOutput = FileHandle.nullDevice
        helper.standardError = FileHandle.nullDevice
        do {
            try helper.run()
        } catch {
            throw ShrugError("Couldn't start the helper that ejects the disk if Shrug stops: \(error)")
        }
        watchdog = (helper, pipe)
    }

    private func dismissWatchdog() {
        guard let (helper, pipe) = watchdog else { return }
        watchdog = nil
        try? pipe.fileHandleForWriting.write(contentsOf: Data("closed\n".utf8))
        try? pipe.fileHandleForWriting.close()
        helper.waitUntilExit()
    }

    // MARK: - hdiutil

    /// Runs hdiutil, handing it the key on its input. Returns what it said; throws that if it failed.
    @discardableResult
    private func hdiutil(_ args: [String], key: String? = nil) throws -> String {
        let r = try Mounter.run("/usr/bin/hdiutil", args, input: key.map { Data($0.utf8) + [0] })
        // Newer macOS calls these options deprecated on every run (it wants `diskutil image`,
        // which older ones don't have).
        let said = r.output.split(separator: "\n").filter { !$0.hasPrefix("hdiutil: WARNING") }.joined(separator: "\n")
        guard r.code == 0 else { throw ShrugError(said.isEmpty ? "hdiutil \(args[0]) failed" : said) }
        return said
    }

    /// The devices this image is attached as, if any.
    private func devices() -> [String] {
        guard let said = try? hdiutil(["info", "-plist"]), let start = said.range(of: "<?xml"),
              let end = said.range(of: "</plist>"),
              let plist = try? PropertyListSerialization.propertyList(
                  from: Data(said[start.lowerBound..<end.upperBound].utf8), format: nil) as? [String: Any],
              let images = plist["images"] as? [[String: Any]]
        else { return [] }
        let mine = ShrugPaths.realpath(image.path) ?? image.path
        return images.compactMap { attached in
            guard let path = attached["image-path"] as? String, (ShrugPaths.realpath(path) ?? path) == mine,
                  let parts = attached["system-entities"] as? [[String: Any]]
            else { return nil }
            // The whole disk, which takes the rest with it.
            let whole = parts.first { $0["content-hint"] as? String == "GUID_partition_scheme" } ?? parts.first
            return whole?["dev-entry"] as? String
        }
    }
}
