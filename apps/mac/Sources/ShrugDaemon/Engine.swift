import AppKit
import CryptoKit
import Foundation
import ShrugCore
import ShrugNFS

/// Everything this Mac keeps about itself, sealed with the local key in ~/.shrug/state.enc.
struct LocalState: Codable {
    var deviceID: String
    var deviceName: String
    var storage: StorageConfig
    var credentials: Credentials?
    /// The profile this Mac follows, and its links as last seen.
    var profile: String?
    var links: [Link] = []
    var profileEditedAt: Date?
    var profileETag: String?
    var profileDirty = false
    var profileGen = 0
    /// Links Shrug placed on this Mac (path -> target), so it only ever removes its own.
    var recorded: [String: String] = [:]
    /// Things worth telling you about, like a link waiting for you to choose.
    var notices: [String] = []
    var profileNames: [String] = []
    var macs: [String] = []
    /// Set after the first complete pass. Until then this Mac doesn't know what the bucket
    /// holds, so it must not touch links: a file here could look new and overwrite the real one.
    var everSynced = false
}

/// What a pass over the bucket needs, valid until the next lock.
struct Session {
    let store: Store
    let storage: ObjectStorage
    let keys: VaultKeys
    let generation: Int
}

/// Owns the lock state and the rules around it.
///
/// Locked: no keys, no bucket credentials and no file names in memory, and no
/// contact with the storage. Shrug locks when the screen locks or the Mac sleeps. While
/// locked, anything that needs a file asks Touch ID (or the Mac password) to unlock.
public final class Engine {
    public let paths: ShrugPaths
    let touchID: TouchIDStore

    /// Guards the state below. Never held while waiting for Touch ID or the network.
    let lock = NSRecursiveLock()
    /// One Touch ID prompt at a time.
    let promptLock = NSLock()
    let reconcileLock = NSLock()

    private var _unlocked = false
    private var _keys: VaultKeys?
    private var _localKey: SymmetricKey?
    private var _store: Store?
    private var _state: LocalState?
    private var _storage: ObjectStorage?
    private var generation = 0
    private var deniedUntil: Date?
    private var globalEpoch: UInt64 = 0
    var lastEventText: String?
    private var previewers: [String: (Bool, Date)] = [:]
    private var passDue: Date?
    private var reconcileDue = false
    var mounted = false

    var fs: VaultFS!
    var replicator: Replicator!
    var nfs: NFSServer?
    var ipc: IPCServer?
    var timer: DispatchSourceTimer?
    var ticks = 0
    var observers: [(NotificationCenter, NSObjectProtocol)] = []
    let logHandle: FileHandle?

    /// Called on any state change; the menu bar redraws from `status()`.
    public var onChange: (() -> Void)?

    /// Seconds between passes over the bucket while unlocked (SHRUG_SYNC_SECONDS).
    let syncInterval: Int
    /// Quiet time after a change before it uploads, so one save is one upload (SHRUG_DEBOUNCE_SECONDS).
    let debounce: TimeInterval
    let denyCooldown: TimeInterval = 3

    public init(paths: ShrugPaths) {
        self.paths = paths
        touchID = TouchIDStore(url: paths.touchIDFile)
        let env = ProcessInfo.processInfo.environment
        syncInterval = max(1, Int(env["SHRUG_SYNC_SECONDS"].flatMap(Double.init) ?? 60))
        debounce = env["SHRUG_DEBOUNCE_SECONDS"].flatMap(Double.init) ?? 3
        try? FileManager.default.createDirectory(at: paths.state, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        chmod(paths.state.path, 0o700)
        if !FileManager.default.fileExists(atPath: paths.logFile.path) {
            FileManager.default.createFile(atPath: paths.logFile.path, contents: nil, attributes: [.posixPermissions: 0o600])
        }
        logHandle = try? FileHandle(forWritingTo: paths.logFile)
        _ = try? logHandle?.seekToEnd()
        fs = VaultFS(engine: self)
        replicator = Replicator(engine: self)
    }

    // MARK: - Lifecycle

    public func start() throws {
        let ipc = IPCServer(socket: paths.socket, engine: self)
        try ipc.start()
        self.ipc = ipc

        let server = NFSServer(fs: fs)
        server.log = { [weak self] in self?.log($0) }
        try server.start()
        nfs = server
        do {
            try server.whileMounting { try Mounter.mount(port: server.port, at: paths.mount) }
            mounted = true
            log("mounted (port \(server.port))")
        } catch {
            log("\(error)")
            lastEventText = "\(error)"
        }

        let distributed = DistributedNotificationCenter.default()
        observers.append((distributed, distributed.addObserver(forName: .init("com.apple.screenIsLocked"), object: nil,
                                                               queue: nil) { [weak self] _ in
            self?.lockNow("screen locked")
        }))
        let workspace = NSWorkspace.shared.notificationCenter
        observers.append((workspace, workspace.addObserver(forName: NSWorkspace.willSleepNotification, object: nil,
                                                           queue: nil) { [weak self] _ in
            self?.lockNow("Mac went to sleep")
        }))

        let t = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "shrug.timer"))
        t.schedule(deadline: .now() + 1, repeating: 1)
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
        log("started")
    }

    public func stop() {
        lockNow("Shrug quit")
        timer?.cancel()
        if mounted { Mounter.unmount(paths.mount) }
        mounted = false
        Mounter.seal(paths.mount)
        nfs?.stop()
        ipc?.stop()
        for (center, o) in observers { center.removeObserver(o) }
        log("stopped")
    }

    /// The log never names files: it's on disk in the clear.
    func log(_ message: String) {
        let line = "\(ISO8601.format(Date())) \(message)\n"
        logHandle?.write(Data(line.utf8))
        if ProcessInfo.processInfo.environment["SHRUG_LOG_STDERR"] != nil { FileHandle.standardError.write(Data(line.utf8)) }
    }

    func changed() {
        if let cb = onChange { DispatchQueue.main.async(execute: cb) }
    }

    /// Shown in status and the menu (memory only, so it may name files).
    func event(_ message: String, log line: String? = nil) {
        lock.lock()
        lastEventText = message
        lock.unlock()
        log(line ?? message)
        changed()
    }

    // MARK: - State access

    var isUnlocked: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _unlocked
    }

    var store: Store? {
        lock.lock()
        defer { lock.unlock() }
        return _unlocked ? _store : nil
    }

    var epoch: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return globalEpoch
    }

    func session() -> Session? {
        lock.lock()
        defer { lock.unlock() }
        guard _unlocked, let store = _store, let storage = _storage, let keys = _keys else { return nil }
        return Session(store: store, storage: storage, keys: keys, generation: generation)
    }

    func isCurrent(_ s: Session) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return _unlocked && generation == s.generation
    }

    func stateCopy() -> LocalState? {
        lock.lock()
        defer { lock.unlock() }
        return _unlocked ? _state : nil
    }

    func updateState(_ body: (inout LocalState) -> Void) {
        lock.lock()
        guard _unlocked, var s = _state, let key = _localKey else {
            lock.unlock()
            return
        }
        body(&s)
        _state = s
        lock.unlock()
        do { try Engine.writeState(s, to: paths.stateFile, key: key) } catch { log("saving state failed: \(error)") }
        changed()
    }

    static let stateAAD = Data("shrug-state-v1".utf8)

    static func writeState(_ s: LocalState, to url: URL, key: SymmetricKey) throws {
        let sealed = try ShrugCrypto.seal(JSONFile.encode(s), key: ShrugCrypto.subkey(key, "shrug-state-v1"), aad: stateAAD)
        try JSONFile.writeAtomically(sealed, to: url)
    }

    static func readState(_ url: URL, key: SymmetricKey) throws -> LocalState {
        guard let sealed = try? Data(contentsOf: url),
              let plain = try? ShrugCrypto.open(sealed, key: ShrugCrypto.subkey(key, "shrug-state-v1"), aad: stateAAD)
        else { throw ShrugError("Can't open this Mac's Shrug settings") }
        return try JSONFile.decode(LocalState.self, from: plain)
    }

    // MARK: - Unlocking

    public func unlock(password: String?) throws {
        guard paths.isSetUp else { throw ShrugError("Not set up yet: run ./setup") }
        if isUnlocked { return }
        guard let password else {
            guard touchID.isEnrolled else { throw ShrugError("password-needed") }
            try unlockWithTouchID(reason: "unlock your vault")
            return
        }
        let keys = try JSONFile.load(LocalKeys.self, from: paths.keyringFile)
        let cache = KEKCache()
        let master = try keys.vault.open(password: password, cache: cache)
        let local = try keys.local.open(password: password, cache: cache)
        if !touchID.isEnrolled {
            do { try touchID.enroll(secret: master.rawData + local.rawData) } catch { log("Touch ID enroll: \(error)") }
        }
        try opened(master, local)
    }

    func unlockWithTouchID(reason: String) throws {
        let keys = try touchID.unlock(reason: reason)
        guard keys.count == 64 else { throw ShrugError("Touch ID data is damaged") }
        try opened(SymmetricKey(data: keys.prefix(32)), SymmetricKey(data: keys.suffix(32)))
    }

    /// Everything an unlock does once the keys are known.
    func opened(_ master: SymmetricKey, _ local: SymmetricKey) throws {
        let vault = VaultKeys(master: master)
        let state = try Engine.readState(paths.stateFile, key: local)
        let store = try Store(paths: paths, keys: vault, localKey: local)
        let storage = try Storage.make(state.storage, state.credentials)
        lock.lock()
        if _unlocked {
            lock.unlock()
            return
        }
        _keys = vault
        _localKey = local
        _state = state
        _store = store
        _storage = storage
        _unlocked = true
        generation += 1
        deniedUntil = nil
        reconcileDue = true
        passDue = Date()
        lock.unlock()
        event("Unlocked")
    }

    public func lockNow(_ reason: String) {
        lock.lock()
        let wasOpen = _unlocked
        let store = _store
        _unlocked = false
        _keys = nil
        _localKey = nil
        _state = nil
        _store = nil
        _storage = nil
        generation += 1
        globalEpoch += 1 // makes the kernel drop cached contents on the next open
        passDue = nil
        previewers = [:]
        lock.unlock()
        store?.close()
        fs.reset()
        replicator.forget()
        if wasOpen { event("Locked: \(reason)") }
    }

    /// For the virtual folder: unlock with Touch ID if possible, else refuse quietly.
    func unlockForAccess(_ prompt: String) -> Bool {
        if isUnlocked { return true }
        lock.lock()
        let refusing = deniedUntil.map { $0 > Date() } ?? false
        lock.unlock()
        guard !refusing, touchID.isEnrolled else { return false }
        promptLock.lock()
        defer { promptLock.unlock() }
        if isUnlocked { return true }
        do {
            try unlockWithTouchID(reason: prompt)
            return true
        } catch {
            lock.lock()
            deniedUntil = Date().addingTimeInterval(denyCooldown)
            lock.unlock()
            event("Stayed locked: \(prompt)", log: "stayed locked")
            return false
        }
    }

    /// For commands: immediate when unlocked, otherwise one Touch ID prompt.
    func requireUnlocked(_ reason: String) throws {
        if isUnlocked { return }
        guard touchID.isEnrolled else { throw ShrugError("Shrug is locked: run 'shrug unlock' first") }
        promptLock.lock()
        defer { promptLock.unlock() }
        if isUnlocked { return }
        do {
            try unlockWithTouchID(reason: reason)
        } catch {
            throw ShrugError("Shrug stayed locked: \(error)")
        }
    }

    // MARK: - Previews

    /// Whether the program reading a file is Finder, Quick Look or Spotlight, which would
    /// otherwise download every remote/ file you browse past.
    func isPreviewer(reading path: String) -> Bool {
        lock.lock()
        if let (answer, at) = previewers[path], Date().timeIntervalSince(at) < 10 {
            lock.unlock()
            return answer
        }
        lock.unlock()
        let mountPath = (ShrugPaths.realpath(paths.mount.path) ?? paths.mount.path) + "/" + path
        let name = ProcessFinder.holder(of: mountPath) ?? ""
        let previewer = ["Finder", "QuickLook", "com.apple.quicklook", "quicklookd", "mds", "mdworker", "Thumbnail",
                         "iconservices"].contains { name.hasPrefix($0) }
        lock.lock()
        previewers[path] = (previewer, Date())
        lock.unlock()
        return previewer
    }

    // MARK: - Timers

    /// Something in ~/Shrug changed: upload it shortly.
    func localChange() {
        lock.lock()
        let soon = Date().addingTimeInterval(debounce + 0.5)
        if passDue == nil || passDue! > soon { passDue = soon }
        lock.unlock()
    }

    func passSoon() {
        lock.lock()
        passDue = Date()
        lock.unlock()
    }

    func reconcileSoon() {
        lock.lock()
        reconcileDue = true
        lock.unlock()
    }

    func tick() {
        ticks += 1
        lock.lock()
        let store = _unlocked ? _store : nil
        var runPass = false
        if _unlocked {
            if let due = passDue, due <= Date() { runPass = true; passDue = nil }
            if ticks % syncInterval == 0 { runPass = true }
        }
        let runReconcile = _unlocked && (reconcileDue || ticks % 60 == 0)
        if runReconcile { reconcileDue = false }
        lock.unlock()
        store?.saveIfNeeded()
        if runPass { DispatchQueue.global().async { [weak self] in self?.replicator.pass() } }
        if runReconcile { DispatchQueue.global().async { [weak self] in self?.reconcile() } }
    }
}
