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
    /// The bucket version of the profile those links came from, or were uploaded as.
    var profileVersion: String?
    var profileDirty = false
    var profileGen = 0
    /// Links Shrug placed on this Mac (path -> target), so it only ever removes its own.
    var recorded: [String: String] = [:]
    /// Link paths you agreed to on this Mac (`shrug add`, or answering `shrug use`). A link
    /// another Mac added is only placed once you have. Nil in state saved before this existed:
    /// the links Shrug had placed (`recorded`) count as agreed to.
    var approved: Set<String>?
    /// Things worth telling you about, like a link waiting for you to choose.
    var notices: [String] = []
    var profileNames: [String] = []
    var macs: [String] = []
    /// Set after the first complete pass. Until then this Mac doesn't know what the bucket
    /// holds, so it must not touch links: a file here could look new and overwrite the real one.
    var everSynced = false
    /// Networks where this Mac stays unlocked when the screen locks (`shrug trust`). Never
    /// uploaded: each Mac decides for itself. Nil in state saved before this existed.
    var trusted: [TrustedNetwork]?
}

/// A network you trust on this Mac, known by its router.
struct TrustedNetwork: Codable, Equatable {
    var name: String
    /// The router's hardware address (see NetworkWatch).
    var router: String
    var addedAt: Date
}

/// What a pass over the bucket needs, valid until the next lock.
struct Session {
    let store: Store
    let storage: ObjectStorage
    let keys: VaultKeys
    let generation: Int
}

/// Unlocking needs the Shrug password: there's no Touch ID copy of the keys on this Mac.
public struct PasswordNeeded: Error, CustomStringConvertible {
    public var description: String { "Password needed" }
}

/// Owns the lock state and the rules around it.
///
/// Locked: no keys, no bucket credentials and no file names in memory, and no
/// contact with the storage. Shrug locks when the screen locks, the Mac sleeps or you switch
/// to another user. While locked, anything that needs a file asks Touch ID (or the Mac
/// password) to unlock.
///
/// The one exception: on a network you trust (`shrug trust`), a screen lock doesn't lock
/// Shrug. It stays unlocked until the Mac leaves that network, sleeps, or you switch users.
public final class Engine {
    public let paths: ShrugPaths
    let clock: Clock
    let touchID: TouchIDKeyStore
    let chip: ChipSeal
    let screen: ScreenWatch
    let network: NetworkWatch

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
    /// What the screen showed at the last look while unlocked (see `checkScreen`).
    private var lastScreen: ScreenState?
    /// The trusted network keeping Shrug unlocked while the screen is locked (see `screenLocked`).
    private var heldBy: String?
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

    /// Asks for the Shrug password when a program needs ~/Shrug and Touch ID can't unlock
    /// (you chose the password, no fingerprint in reach, Touch ID not set up). Gets what the
    /// program is doing; calls `done` once the question is closed, after unlocking if it was
    /// answered. The menu bar app shows a dialog; without it, access is refused quietly.
    public var askPassword: ((_ why: String, _ done: @escaping () -> Void) -> Void)?

    /// Seconds between passes over the bucket while unlocked (SHRUG_SYNC_SECONDS).
    let syncInterval: Int
    /// Quiet time after a change before it uploads, so one save is one upload (SHRUG_DEBOUNCE_SECONDS).
    let debounce: TimeInterval
    let denyCooldown: TimeInterval = 3
    /// A program waiting on ~/Shrug gives up after about 30 seconds (see Mounter.mount), so
    /// the prompt it caused closes first instead of unlocking for nobody.
    let accessPromptTimeout: TimeInterval = 25

    public init(paths: ShrugPaths, clock: Clock = .system, touchID: TouchIDKeyStore? = nil, chip: ChipSeal? = nil,
                screen: ScreenWatch = .system, network: NetworkWatch = .system) {
        self.paths = paths
        self.clock = clock
        self.touchID = touchID ?? TouchIDStore(url: paths.touchIDFile)
        self.chip = chip ?? SecureEnclaveSeal()
        self.screen = screen
        self.network = network
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
            self?.screenLocked()
        }))
        let workspace = NSWorkspace.shared.notificationCenter
        observers.append((workspace, workspace.addObserver(forName: NSWorkspace.willSleepNotification, object: nil,
                                                           queue: nil) { [weak self] _ in
            self?.lockNow("Mac went to sleep")
        }))
        observers.append((workspace, workspace.addObserver(forName: NSWorkspace.sessionDidResignActiveNotification,
                                                           object: nil, queue: nil) { [weak self] _ in
            self?.lockNow("switched to another user")
        }))

        // The slack lets macOS wake for this together with other timers, which saves battery.
        let t = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "shrug.timer"))
        t.schedule(deadline: .now() + 1, repeating: 1, leeway: .milliseconds(250))
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

    /// Something to tell you once. It stays in status and the menu until newer ones push it out.
    func notify(_ note: String) {
        updateState { st in
            if !st.notices.contains(note) { st.notices = Array((st.notices + [note]).suffix(20)) }
        }
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

    /// Changes the state and saves it before returning. The save happens under the lock, so
    /// what's on disk is always the newest state.
    func updateState(_ body: (inout LocalState) -> Void) {
        lock.lock()
        guard _unlocked, var s = _state, let key = _localKey else { return lock.unlock() }
        body(&s)
        _state = s
        do { try Engine.writeState(s, paths, key: key) } catch { log("saving state failed: \(error)") }
        lock.unlock()
        changed()
    }

    static func writeState(_ s: LocalState, _ paths: ShrugPaths, key: SymmetricKey) throws {
        try SealedFile.state.write(JSONFile.encode(s), paths, key: key)
    }

    static func readState(_ paths: ShrugPaths, key: SymmetricKey) throws -> LocalState {
        guard let plain = try SealedFile.state.read(paths, key: key) else { throw ShrugError("This Mac's Shrug settings are missing") }
        return try JSONFile.decode(LocalState.self, from: plain)
    }

    // MARK: - Unlocking

    public func unlock(password: String?) throws {
        guard paths.isSetUp else { throw ShrugError("Not set up yet: run ./setup") }
        if isUnlocked { return }
        guard let password else {
            guard touchID.isEnrolled else { throw PasswordNeeded() }
            promptLock.lock()
            defer { promptLock.unlock() }
            if isUnlocked { return }
            try unlockWithTouchID(reason: "unlock your vault")
            return
        }
        let keys = try loadKeys()
        let cache = KEKCache()
        let master = try keys.vault.open(password: password, cache: cache)
        let local = try keys.local.open(password: password, cache: cache)
        if !touchID.isEnrolled {
            do { try touchID.enroll(secret: master.rawData + local.rawData) } catch { log("Touch ID enroll: \(error)") }
        }
        try opened(master, local)
    }

    /// Throws PasswordNeeded when only the Shrug password can unlock now. A copy that can never
    /// open again is removed, so the next password unlock makes a new one.
    func unlockWithTouchID(reason: String, timeout: TimeInterval = 60) throws {
        let keys: Data
        do {
            keys = try touchID.unlock(reason: reason, timeout: timeout)
        } catch TouchIDError.invalidated {
            touchID.remove()
            log("the Touch ID copy of the keys no longer opens (fingerprints changed?): the password makes a new one")
            throw PasswordNeeded()
        } catch TouchIDError.usePassword {
            throw PasswordNeeded()
        }
        guard keys.count == 64 else {
            touchID.remove()
            throw PasswordNeeded()
        }
        try opened(SymmetricKey(data: keys.prefix(32)), SymmetricKey(data: keys.suffix(32)))
    }

    /// Everything an unlock does once the keys are known. This Mac's files are brought to the
    /// current format first; the vault follows in the first pass.
    func opened(_ master: SymmetricKey, _ local: SymmetricKey) throws {
        lock.lock()
        let already = _unlocked
        lock.unlock()
        if already { return }
        let vault = VaultKeys(master: master)
        try Migrations.upgradeLocal(paths, keys: vault, localKey: local, log: log)
        let state = try Engine.readState(paths, key: local)
        let store = try Store(paths: paths, keys: vault, localKey: local, clock: clock)
        if store.ignoredJournalBytes > 0 {
            log("the index journal ended in \(store.ignoredJournalBytes) bytes that don't belong to it (a crash while saving); they were left out")
        }
        let storage = try Storage.make(state.storage, state.credentials)
        let screenNow = screen.current()
        lock.lock()
        if _unlocked { return lock.unlock() }
        lastScreen = screenNow
        _keys = vault
        _localKey = local
        _state = state
        _store = store
        _storage = storage
        _unlocked = true
        generation += 1
        globalEpoch += 1 // a listing made while locked is out of date now
        deniedUntil = nil
        reconcileDue = true
        passDue = clock.now()
        lock.unlock()
        event("Unlocked")
        protectKeys()
    }

    // MARK: - keyring.json

    /// This Mac's keys, still wrapped with the Shrug password.
    func loadKeys() throws -> LocalKeys {
        switch try JSONFile.load(KeyringFile.self, from: paths.keyringFile) {
        case .plain(let keys):
            return keys
        case .chip(let sealed):
            guard chip.isAvailable, let plain = try? chip.open(sealed) else {
                throw ShrugError("This Mac's security chip can't open ~/.shrug/keyring.json (was ~/.shrug copied from another Mac?). Move ~/.shrug away and run ./setup to join your vault again; files in local/ don't come back.")
            }
            return try JSONFile.decode(LocalKeys.self, from: plain)
        }
    }

    /// Writes keyring.json, sealed by the security chip when this Mac has one.
    func saveKeys(_ keys: LocalKeys) throws {
        try JSONFile.save(sealedIfPossible(keys), to: paths.keyringFile)
    }

    /// If the chip fails, the password alone protects the keys, as on a Mac without one,
    /// until an unlock seals them (see `protectKeys`).
    private func sealedIfPossible(_ keys: LocalKeys) -> KeyringFile {
        guard chip.isAvailable else { return .plain(keys) }
        do {
            return .chip(try chip.seal(JSONFile.encode(keys)))
        } catch {
            log("the security chip couldn't seal keyring.json, so only the Shrug password protects it for now: \(error)")
            return .plain(keys)
        }
    }

    /// Seals a keyring.json that isn't sealed yet: one from before Shrug used the chip, or
    /// one written while the chip failed. Copies made before then (backups) stay as they were.
    func protectKeys() {
        guard chip.isAvailable, case .plain(let keys)? = try? JSONFile.load(KeyringFile.self, from: paths.keyringFile)
        else { return }
        let file = sealedIfPossible(keys)
        guard case .chip = file else { return }
        do {
            try JSONFile.save(file, to: paths.keyringFile)
            log("sealed keyring.json with this Mac's security chip")
        } catch {
            log("saving keyring.json failed: \(error)")
        }
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
        lastScreen = nil
        heldBy = nil
        lock.unlock()
        store?.close()
        fs.reset()
        replicator.forget()
        if wasOpen { event("Locked: \(reason)") }
    }

    /// For the virtual folder: unlock with Touch ID if possible, else with the Shrug password
    /// if the menu bar app can ask for it, else refuse quietly.
    /// The NFS request doesn't say which program sent it, so the prompt can't either:
    /// "Shrug is trying to unlock because a program is <doing> <path>."
    func unlockForAccess(_ doing: String, _ path: String) -> Bool {
        if isUnlocked { return true }
        guard !refusing, touchID.isEnrolled || askPassword != nil else { return false }
        promptLock.lock()
        defer { promptLock.unlock() }
        if isUnlocked { return true }
        // Waited behind a prompt that was just cancelled: don't ask again right away.
        if refusing { return false }
        // The program gives up after about 30 seconds, whichever way it's asked.
        let deadline = Date().addingTimeInterval(accessPromptTimeout)
        let why = "a program is \(doing) \(Engine.shown(path))"
        do {
            guard touchID.isEnrolled else { throw PasswordNeeded() }
            try unlockWithTouchID(reason: "unlock because \(why)", timeout: accessPromptTimeout)
            return true
        } catch is PasswordNeeded {
            if passwordUnlock(why, until: deadline) { return true }
        } catch {}
        lock.lock()
        deniedUntil = clock.now().addingTimeInterval(denyCooldown)
        lock.unlock()
        event("Stayed locked: \(why)", log: "stayed locked")
        return false
    }

    /// Asks for the Shrug password (see `askPassword`) and waits for the answer, but not past
    /// `deadline`. An answer that comes later still unlocks, for the program's next try.
    private func passwordUnlock(_ why: String, until deadline: Date) -> Bool {
        guard let ask = askPassword else { return false }
        let closed = DispatchSemaphore(value: 0)
        ask(why) { closed.signal() }
        _ = closed.wait(timeout: .now() + max(1, deadline.timeIntervalSinceNow))
        return isUnlocked
    }

    /// A path as it may appear in a system prompt. Names come from whatever program asked, so
    /// control and formatting characters (line breaks, right-to-left overrides) become "?",
    /// and long ones are shortened in the middle.
    static func shown(_ path: String, limit: Int = 80) -> String {
        var scalars = String.UnicodeScalarView()
        for s in path.unicodeScalars {
            switch s.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator, .privateUse, .surrogate, .unassigned:
                scalars.append("?")
            default:
                scalars.append(s)
            }
        }
        let clean = String(scalars)
        guard clean.count > limit else { return clean }
        return String(clean.prefix(limit / 2 - 1)) + "…" + String(clean.suffix(limit / 2))
    }

    private var refusing: Bool {
        lock.lock()
        defer { lock.unlock() }
        return deniedUntil.map { $0 > clock.now() } ?? false
    }

    /// For commands: immediate when unlocked, otherwise one Touch ID prompt. PasswordNeeded
    /// when only the Shrug password can unlock (the command line then asks for it).
    func requireUnlocked(_ reason: String) throws {
        if isUnlocked { return }
        guard touchID.isEnrolled else { throw PasswordNeeded() }
        promptLock.lock()
        defer { promptLock.unlock() }
        if isUnlocked { return }
        do {
            try unlockWithTouchID(reason: reason)
        } catch let e as PasswordNeeded {
            throw e
        } catch {
            throw ShrugError("Shrug stayed locked: \(error)")
        }
    }

    // MARK: - Previews

    /// Whether the program reading a file is Finder, Quick Look or Spotlight, which would
    /// otherwise download every remote/ file you browse past.
    func isPreviewer(reading path: String) -> Bool {
        lock.lock()
        if let (answer, at) = previewers[path], clock.now().timeIntervalSince(at) < 10 {
            lock.unlock()
            return answer
        }
        lock.unlock()
        let mountPath = (ShrugPaths.realpath(paths.mount.path) ?? paths.mount.path) + "/" + path
        let name = ProcessFinder.holder(of: mountPath) ?? ""
        let previewer = ["Finder", "QuickLook", "com.apple.quicklook", "quicklookd", "mds", "mdworker", "Thumbnail",
                         "iconservices"].contains { name.hasPrefix($0) }
        lock.lock()
        previewers[path] = (previewer, clock.now())
        lock.unlock()
        return previewer
    }

    // MARK: - Timers

    /// Something in ~/Shrug changed: upload it shortly.
    func localChange() {
        lock.lock()
        let soon = clock.now().addingTimeInterval(debounce + 0.5)
        if passDue.map({ $0 > soon }) ?? true { passDue = soon }
        lock.unlock()
    }

    func passSoon() {
        lock.lock()
        passDue = clock.now()
        lock.unlock()
    }

    func reconcileSoon() {
        lock.lock()
        reconcileDue = true
        lock.unlock()
    }

    /// Locks if the screen locked, or you switched to another user, since the last look. The
    /// notifications in `start` normally get there first; this catches one that never came.
    /// Only a change counts, so unlocking on purpose while the screen is locked (over SSH, say)
    /// still works, as before.
    func checkScreen() {
        lock.lock()
        let unlocked = _unlocked
        let gen = generation
        lock.unlock()
        guard unlocked, let now = screen.current() else { return }
        lock.lock()
        // Locked, or locked and unlocked again, while asking: that unlock has its own baseline.
        guard _unlocked, generation == gen else { return lock.unlock() }
        let before = lastScreen
        lastScreen = now
        lock.unlock()
        guard let before else { return }
        if before.ours && !now.ours {
            lockNow("switched to another user")
        } else if now.locked && !before.locked {
            // With someone else at the screen, a trusted network keeps nothing open.
            if now.ours { screenLocked() } else { lockNow("screen locked") }
        } else if before.locked && !now.locked {
            screenOpened()
        }
    }

    // MARK: - Trusted networks

    /// The trusted network this Mac is on, if any. Not knowing the network is not trusting it.
    func trustedNetwork(among trusted: [TrustedNetwork]) -> TrustedNetwork? {
        guard !trusted.isEmpty, let router = network.current() else { return nil }
        return trusted.first { $0.router == router }
    }

    /// The screen locked: Shrug locks too, unless this Mac is on a network you trust. Then it
    /// stays unlocked, and `checkNetwork` locks it the moment the Mac is anywhere else.
    func screenLocked() {
        lock.lock()
        let gen = generation
        let trusted = (_unlocked ? _state?.trusted : nil) ?? []
        lock.unlock()
        guard let here = trustedNetwork(among: trusted) else { return lockNow("screen locked") }
        lock.lock()
        // Locked, or locked and unlocked again, while asking: nothing to hold open.
        guard _unlocked, generation == gen else { return lock.unlock() }
        let already = heldBy != nil
        heldBy = here.name
        lock.unlock()
        // The notification and `checkScreen` can both get here for one screen lock.
        if !already { event("Screen locked: staying unlocked on \(here.name)", log: "screen locked: staying unlocked on a trusted network") }
    }

    /// You're back at the screen: the next screen lock decides again.
    private func screenOpened() {
        lock.lock()
        let was = heldBy
        heldBy = nil
        lock.unlock()
        if was != nil { changed() }
    }

    /// While a trusted network keeps Shrug unlocked behind a locked screen: lock as soon as the
    /// Mac isn't on one (it moved, the network dropped, or you stopped trusting it).
    func checkNetwork() {
        lock.lock()
        let gen = generation
        let held = _unlocked && heldBy != nil
        let trusted = _state?.trusted ?? []
        lock.unlock()
        guard held else { return }
        if let here = trustedNetwork(among: trusted) {
            lock.lock()
            if _unlocked, generation == gen, heldBy != nil { heldBy = here.name }
            lock.unlock()
            return
        }
        lock.lock()
        let still = _unlocked && generation == gen && heldBy != nil
        lock.unlock()
        if still { lockNow("left the trusted network while the screen was locked") }
    }

    /// The network holding Shrug unlocked behind a locked screen, for status.
    var heldOpenBy: String? {
        lock.lock()
        defer { lock.unlock() }
        return _unlocked ? heldBy : nil
    }

    func tick() {
        ticks += 1
        checkScreen()
        checkNetwork()
        lock.lock()
        let store = _unlocked ? _store : nil
        var runPass = false
        if _unlocked {
            if let due = passDue, due <= clock.now() { runPass = true; passDue = nil }
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
