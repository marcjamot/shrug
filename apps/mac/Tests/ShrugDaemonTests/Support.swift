import CryptoKit
import XCTest
@testable import ShrugCore
@testable import ShrugDaemon
import ShrugNFS

/// A clock that moves on a millisecond every time it's read, and jumps when told to. Every edit
/// gets its own time, in the order the test makes them, on every Mac that shares it.
final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var t: Date

    init(_ start: Date = Date().ms) { t = start }

    func advance(_ seconds: TimeInterval) {
        lock.lock()
        t += seconds
        lock.unlock()
    }

    var clock: Clock {
        Clock { [self] in
            lock.lock()
            defer { lock.unlock() }
            t += 0.001
            return t
        }
    }
}

/// One Mac: an engine with its own home folder, laid out like a real one (~/.shrug, ~/Shrug),
/// driven through the virtual folder directly (no mount).
final class Mac {
    let engine: Engine
    let paths: ShrugPaths
    /// The same chip after a restart: it's this Mac's hardware, not the app's.
    let chip: ChipSeal
    let ctx = NFSContext(uid: getuid(), gid: getgid())

    static func paths(_ root: URL, _ name: String) -> ShrugPaths {
        let home = root.appendingPathComponent(name)
        return ShrugPaths(state: home.appendingPathComponent(".shrug"), mount: home.appendingPathComponent("Shrug"),
                          home: home, socket: home.appendingPathComponent(".shrug/shrug.sock").path)
    }

    /// Unless a test passes its own `screen`, macOS is never asked about the real one. Every
    /// Mac has its own security chip, which tests stand in for.
    init(_ root: URL, _ name: String, clock: TestClock, touchID: TouchIDKeyStore? = nil, chip: ChipSeal = FakeChip(),
         screen: ScreenWatch = ScreenWatch { nil }) {
        paths = Mac.paths(root, name)
        self.chip = chip
        try? FileManager.default.createDirectory(at: paths.home, withIntermediateDirectories: true)
        engine = Engine(paths: paths, clock: clock.clock, touchID: touchID, chip: chip, screen: screen)
    }

    var fs: VaultFS { engine.fs }
    var store: Store { engine.store! }

    func lookup(_ path: String) throws -> UInt64 {
        var id = fs.rootID
        for part in path.split(separator: "/") { id = try fs.lookup(id, String(part)).get() }
        return id
    }

    func write(_ path: String, _ data: Data) throws {
        let dir = try lookup(Store.parent(path))
        let id: UInt64
        if case .success(let existing) = fs.lookup(dir, Store.name(path)) {
            id = existing
            var a = NFSSetAttrs()
            a.size = 0
            try fs.setattr(id, a, ctx).get()
        } else {
            id = try fs.create(dir, Store.name(path), mode: 0o600, exclusive: true, ctx).get()
        }
        try fs.write(id, offset: 0, data: data, ctx).get()
    }

    func mkdirs(_ path: String) throws {
        var dir = ""
        for part in path.split(separator: "/").map(String.init) {
            let parent = try lookup(dir)
            dir = dir.isEmpty ? part : dir + "/" + part
            if case .failure = fs.lookup(parent, part) { _ = try fs.mkdir(parent, part, mode: 0o700, ctx).get() }
        }
    }

    func read(_ path: String) throws -> Data {
        let id = try lookup(path)
        let size = try fs.getattr(id).get().size
        var out = Data()
        while out.count < Int(size) {
            let (chunk, eof) = try fs.read(id, offset: UInt64(out.count), count: 65536, ctx).get()
            out.append(chunk)
            if eof || chunk.isEmpty { break }
        }
        return out
    }

    func text(_ path: String) throws -> String { String(decoding: try read(path), as: UTF8.self) }

    func remove(_ path: String) throws {
        try fs.remove(try lookup(Store.parent(path)), Store.name(path), ctx).get()
    }

    func rename(_ from: String, _ to: String) throws {
        try fs.rename(try lookup(Store.parent(from)), Store.name(from), try lookup(Store.parent(to)), Store.name(to), ctx).get()
    }

    func names(_ dir: String) throws -> [String] { try fs.readdir(try lookup(dir)).get().map(\.name) }

    func home(_ rel: String) -> URL { paths.home.appendingPathComponent(rel) }

    /// A real file in this Mac's home folder.
    func putHome(_ rel: String, _ text: String) throws {
        let url = home(rel)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(text.utf8).write(to: url)
    }

    func sync() { engine.replicator.pass() }

    /// Makes the debounce wait of every pending change run out.
    func settle() {
        for (p, e) in store.pending() where e.changedAt != nil { store.update(p) { $0.changedAt = .distantPast } }
    }
}

/// Two or more Macs sharing a plain folder as the bucket.
class ShrugTestCase: XCTestCase {
    var root: URL!
    var bucket: URL!
    let time = TestClock()
    let password = "correct horse battery staple"

    override func setUpWithError() throws {
        setenv("SHRUG_TEST_KDF_ITERATIONS", "1000", 1)
        setenv("SHRUG_NO_TOUCHID", "1", 1)
        setenv("SHRUG_DEBOUNCE_SECONDS", "0", 1)
        root = FileManager.default.temporaryDirectory.appendingPathComponent("shrug-test-\(UUID().uuidString)")
        bucket = root.appendingPathComponent("bucket")
        try FileManager.default.createDirectory(at: bucket, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: root)
    }

    var storage: StorageConfig { StorageConfig(kind: "folder", path: bucket.path) }

    func mac(_ name: String, touchID: TouchIDKeyStore? = nil, chip: ChipSeal = FakeChip(),
             screen: ScreenWatch = ScreenWatch { nil }) -> Mac {
        Mac(root, name, clock: time, touchID: touchID, chip: chip, screen: screen)
    }

    /// Follows `profile` on `mac`, agreeing to every link it asks about (as answering "y" does).
    @discardableResult
    func follow(_ m: Mac, _ profile: String = "work", choices: [String: Choice] = [:]) throws -> Outcome {
        let first = try m.engine.use(profile, choices: choices)
        guard case .confirm(let links) = first else { return first }
        return try m.engine.use(profile, choices: choices, approve: Set(links.map(\.path)))
    }

    /// The first Mac creates the vault; the second joins it with the password.
    func twoMacs() throws -> (Mac, Mac) {
        let a = mac("a")
        _ = try a.engine.setup(storage, nil, password: password, deviceName: "a", create: true)
        let b = mac("b")
        _ = try b.engine.setup(storage, nil, password: password, deviceName: "b", create: false)
        return (a, b)
    }

    /// Both Macs follow `profile`, both up to date.
    func twoMacsFollowing(_ profile: String = "work") throws -> (Mac, Mac) {
        let (a, b) = try twoMacs()
        _ = try a.engine.use(profile, choices: [:])
        a.sync()
        _ = try b.engine.use(profile, choices: [:])
        b.sync()
        return (a, b)
    }

    func offline(_ body: () throws -> Void) rethrows {
        let away = root.appendingPathComponent("bucket-away")
        try? FileManager.default.moveItem(at: bucket, to: away)
        defer { try? FileManager.default.moveItem(at: away, to: bucket) }
        try body()
    }

    /// The bucket object holding a path.
    func object(_ mac: Mac, _ path: String) -> URL {
        bucket.appendingPathComponent(mac.store.objectKey(path))
    }

    /// Replaces an object's bytes the way a misbehaving storage would (a new version).
    func tamper(_ url: URL, _ data: Data) throws {
        try FileManager.default.removeItem(at: url)
        try data.write(to: url)
    }
}

func bytes(_ n: Int, seed: UInt8 = 7) -> Data {
    Data((0..<n).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ Int(seed)) })
}
