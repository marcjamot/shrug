import CryptoKit
import XCTest
@testable import ShrugCore
@testable import ShrugDaemon
import ShrugNFS

/// One Mac: an engine with its own ~/.shrug and home, driven through the virtual folder
/// directly (no mount).
final class Mac {
    let engine: Engine
    let paths: ShrugPaths
    let ctx = NFSContext(uid: getuid(), gid: getgid())

    init(_ root: URL, _ name: String) {
        let dir = root.appendingPathComponent(name)
        paths = ShrugPaths(state: dir.appendingPathComponent("state"), mount: dir.appendingPathComponent("mnt"),
                          home: dir.appendingPathComponent("home"), socket: dir.appendingPathComponent("s").path)
        try? FileManager.default.createDirectory(at: paths.home, withIntermediateDirectories: true)
        engine = Engine(paths: paths)
    }

    var fs: VaultFS { engine.fs }

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

    func names(_ dir: String) throws -> [String] { try fs.readdir(try lookup(dir)).get().map(\.name) }

    func sync() { engine.replicator.pass() }
}

final class EngineTests: XCTestCase {
    var root: URL!
    var bucket: URL!
    let password = "correct horse battery staple"

    override func setUpWithError() throws {
        setenv("SHRUG_TEST_KDF_ITERATIONS", "1000", 1)
        setenv("SHRUG_NO_TOUCHID", "1", 1)
        setenv("SHRUG_DEBOUNCE_SECONDS", "0", 1)
        root = FileManager.default.temporaryDirectory.appendingPathComponent("shrug-engine-\(UUID().uuidString)")
        bucket = root.appendingPathComponent("bucket")
        try FileManager.default.createDirectory(at: bucket, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: root)
    }

    var storage: StorageConfig { StorageConfig(kind: "folder", path: bucket.path) }

    /// The first Mac creates the vault; the second joins it with the password.
    func twoMacs() throws -> (Mac, Mac) {
        let a = Mac(root, "a")
        _ = try a.engine.setup(storage, nil, password: password, deviceName: "a", create: true)
        let b = Mac(root, "b")
        _ = try b.engine.setup(storage, nil, password: password, deviceName: "b", create: false)
        return (a, b)
    }

    func offline(_ body: () throws -> Void) rethrows {
        let away = root.appendingPathComponent("bucket-away")
        try? FileManager.default.moveItem(at: bucket, to: away)
        defer { try? FileManager.default.moveItem(at: away, to: bucket) }
        try body()
    }

    func testTopLevelIsFixed() throws {
        let (a, _) = try twoMacs()
        XCTAssertEqual(try a.names(""), [VaultFS.neverIndex, "local", "synced", "remote"])
        guard case .failure(.acces) = a.fs.create(a.fs.rootID, "stray.txt", mode: nil, exclusive: true, a.ctx) else {
            return XCTFail("nothing can be created next to the three folders")
        }
    }

    func testLockedHidesNamesAndContents() throws {
        let (a, _) = try twoMacs()
        try a.write("synced/client-x-contract.txt", Data("secret terms".utf8))
        try a.write("local/notes.txt", Data("local only".utf8))
        a.engine.store?.save()
        a.engine.lockNow("test")

        XCTAssertEqual(try a.names("synced"), [], "a locked folder looks empty")
        guard case .failure(.acces) = a.fs.lookup(3, "client-x-contract.txt") else {
            return XCTFail("opening by name asks to unlock, and is refused without Touch ID")
        }
        guard case .failure(.noent) = a.fs.lookup(3, ".DS_Store") else { return XCTFail("Finder's own names never prompt") }
        // Nothing on disk gives a name or content away.
        for rel in FileManager.default.enumerator(atPath: a.paths.state.path)!.allObjects as! [String] {
            XCTAssertFalse(rel.contains("client") || rel.contains("notes"), rel)
            if let data = try? Data(contentsOf: a.paths.state.appendingPathComponent(rel)) {
                XCTAssertNil(data.range(of: Data("client-x".utf8)), rel)
                XCTAssertNil(data.range(of: Data("secret terms".utf8)), rel)
            }
        }
        let bucketFiles = FileManager.default.enumerator(atPath: bucket.path)!.allObjects as! [String]
        XCTAssertFalse(bucketFiles.contains { $0.contains("client") })

        try a.engine.unlock(password: password)
        XCTAssertEqual(try a.read("synced/client-x-contract.txt"), Data("secret terms".utf8))
        XCTAssertEqual(try a.read("local/notes.txt"), Data("local only".utf8))
    }

    func testSyncedFilesReachTheOtherMac() throws {
        let (a, b) = try twoMacs()
        try a.mkdirs("synced/work")
        try a.write("synced/work/kubeconfig", Data("apiVersion: v1".utf8))
        try a.write("local/only-here.txt", Data("x".utf8))
        a.sync()
        b.sync()
        XCTAssertEqual(try b.read("synced/work/kubeconfig"), Data("apiVersion: v1".utf8))
        XCTAssertEqual(try b.names("local"), [], "local/ never leaves its Mac")
        XCTAssertEqual(b.engine.status().waiting, 0)
        a.sync()
        XCTAssertEqual(a.engine.status().macs, ["a", "b"])
    }

    func testLastEditWins() throws {
        let (a, b) = try twoMacs()
        try a.write("synced/f.txt", Data("one".utf8))
        a.sync()
        b.sync()
        // A edits while offline; B edits later, online.
        try offline {
            try a.write("synced/f.txt", Data("A, offline".utf8))
            a.sync()
        }
        usleep(5000)
        try b.write("synced/f.txt", Data("B, later".utf8))
        b.sync()
        a.sync() // A is back: B's edit is newer, so it wins
        XCTAssertEqual(try a.read("synced/f.txt"), Data("B, later".utf8))
        // And a newer edit on A beats B's.
        usleep(5000)
        try a.write("synced/f.txt", Data("A, newest".utf8))
        a.sync()
        b.sync()
        XCTAssertEqual(try b.read("synced/f.txt"), Data("A, newest".utf8))
    }

    func testDeletesAndRenamesReachTheOtherMac() throws {
        let (a, b) = try twoMacs()
        try a.write("synced/old.txt", Data("x".utf8))
        try a.write("synced/gone.txt", Data("y".utf8))
        a.sync()
        b.sync()
        try a.fs.rename(3, "old.txt", 3, "new.txt", a.ctx).get()
        try a.fs.remove(3, "gone.txt", a.ctx).get()
        a.sync()
        b.sync()
        XCTAssertEqual(try b.names("synced"), ["new.txt"])
        XCTAssertEqual(try b.read("synced/new.txt"), Data("x".utf8))
        guard case .failure(.xdev) = a.fs.rename(3, "new.txt", 4, "new.txt", a.ctx) else {
            return XCTFail("moving between folders is a copy, not a rename")
        }
    }

    func testRemoteFilesStreamAndAreNotKept() throws {
        let (a, b) = try twoMacs()
        let big = bytes(300_000)
        try a.write("remote/video.bin", big)
        a.sync()
        let key = String(a.engine.store!.objectKey("remote/video.bin").dropFirst(2))
        XCTAssertFalse(FileManager.default.fileExists(atPath: a.paths.objectStore.appendingPathComponent(key).path),
                       "after uploading, the local copy is gone")
        XCTAssertEqual(try a.read("remote/video.bin"), big, "but it still reads, from the bucket")
        b.sync()
        XCTAssertEqual(try b.names("remote"), ["video.bin"])
        XCTAssertEqual(try b.read("remote/video.bin"), big)
        // Editing brings it here, saving uploads it, and then it's gone again.
        try b.write("remote/video.bin", Data("short".utf8))
        b.sync()
        a.sync()
        XCTAssertEqual(try a.read("remote/video.bin"), Data("short".utf8))
    }

    func testOfflineSavesWaitAndThenUpload() throws {
        let (a, b) = try twoMacs()
        try offline {
            try a.write("remote/draft.txt", Data("written on a plane".utf8))
            try a.write("synced/todo.txt", Data("plane".utf8))
            a.sync()
            XCTAssertEqual(a.engine.status().online, false)
            XCTAssertEqual(a.engine.status().waiting, 2)
        }
        a.sync()
        XCTAssertEqual(a.engine.status().waiting, 0)
        b.sync()
        XCTAssertEqual(try b.read("remote/draft.txt"), Data("written on a plane".utf8))
        XCTAssertEqual(try b.read("synced/todo.txt"), Data("plane".utf8))
    }

    func testWrongPasswordDoesNotJoin() throws {
        let a = Mac(root, "a")
        _ = try a.engine.setup(storage, nil, password: password, deviceName: "a", create: true)
        let b = Mac(root, "b")
        XCTAssertThrowsError(try b.engine.setup(storage, nil, password: "not the password", deviceName: "b", create: false))
        XCTAssertFalse(b.paths.isSetUp)
        XCTAssertThrowsError(try a.engine.setup(storage, nil, password: password, deviceName: "a", create: true),
                             "setting up twice is refused")
    }

    func testProfilesPlaceLinksOnEveryMac() throws {
        let (a, b) = try twoMacs()
        guard case .done = try a.engine.use("work", choices: [:]) else { return XCTFail() }
        let key = a.paths.home.appendingPathComponent(".ssh/id_test")
        try FileManager.default.createDirectory(at: key.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("PRIVATE KEY".utf8).write(to: key)
        guard case .done = try a.engine.add(path: key.path, target: nil, cls: nil, choices: [:]) else { return XCTFail() }
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: key.path),
                       a.paths.mount.appendingPathComponent("synced/ssh/id_test").path)
        XCTAssertEqual(try a.read("synced/ssh/id_test"), Data("PRIVATE KEY".utf8))
        // A link to a file that doesn't exist yet creates it empty.
        let env = a.paths.home.appendingPathComponent("project/.env")
        _ = try a.engine.add(path: env.path, target: "synced/project/env", cls: nil, choices: [:])
        XCTAssertEqual(try a.read("synced/project/env"), Data())
        a.sync()

        // B already has its own ~/.ssh/id_test: following "work" asks which to keep.
        let bKey = b.paths.home.appendingPathComponent(".ssh/id_test")
        try FileManager.default.createDirectory(at: bKey.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("B's old key".utf8).write(to: bKey)
        b.sync()
        guard case .collisions(let paths) = try b.engine.use("work", choices: [:]) else { return XCTFail("should ask") }
        XCTAssertEqual(paths, ["~/.ssh/id_test"])
        XCTAssertEqual(b.engine.found(bKey, "synced/ssh/id_test"), .file, "asking changes nothing")
        guard case .done = try b.engine.use("work", choices: ["~/.ssh/id_test": .shrug]) else { return XCTFail() }
        XCTAssertEqual(b.engine.found(bKey, "synced/ssh/id_test"), .ourLink)
        XCTAssertEqual(try b.read("synced/ssh/id_test"), Data("PRIVATE KEY".utf8), "Shrug's key won")
        XCTAssertFalse(FileManager.default.fileExists(atPath: bKey.path + ".before-shrug"))
        XCTAssertEqual(b.engine.found(b.paths.home.appendingPathComponent("project/.env"), "synced/project/env"), .ourLink)

        // A link change on B reaches A: the last change wins.
        _ = try b.engine.remove(path: b.paths.home.appendingPathComponent("project/.env").path)
        b.sync()
        a.sync()
        a.engine.reconcile()
        XCTAssertEqual(a.engine.found(env, "synced/project/env"), .nothing, "the link is gone on A too")
        XCTAssertEqual(try a.read("synced/project/env"), Data(), "but the file stays in ~/Shrug")
    }

    func testAdjustingPullsBackReplacedLinksAndWaitsOnOthers() throws {
        let (a, b) = try twoMacs()
        _ = try a.engine.use("work", choices: [:])
        a.sync()
        _ = try b.engine.use("work", choices: [:])
        let cfg = a.paths.home.appendingPathComponent(".kube/config")
        _ = try a.engine.add(path: cfg.path, target: nil, cls: nil, choices: [:])
        // A tool saves by replacing the link with a real file.
        unlink(cfg.path)
        try Data("new context".utf8).write(to: cfg)
        a.engine.reconcile()
        XCTAssertEqual(a.engine.found(cfg, "synced/kube/config"), .ourLink)
        XCTAssertEqual(try a.read("synced/kube/config"), Data("new context".utf8))
        a.sync()

        // B follows "work" too, and has its own fresh ~/.kube/config. When the link arrives
        // nobody is there to ask, so B's file is left alone (never pulled in over Shrug's,
        // never deleted) and B is told once.
        let bCfg = b.paths.home.appendingPathComponent(".kube/config")
        try FileManager.default.createDirectory(at: bCfg.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("fresh default".utf8).write(to: bCfg)
        b.sync()
        b.engine.reconcile()
        b.engine.reconcile()
        XCTAssertEqual(b.engine.found(bCfg, "synced/kube/config"), .file)
        XCTAssertEqual(try Data(contentsOf: bCfg), Data("fresh default".utf8))
        XCTAssertEqual(try b.read("synced/kube/config"), Data("new context".utf8))
        XCTAssertEqual(b.engine.status().notices.count, 1, "told once, not every minute")

        // Following the profile again asks, and the version not chosen is deleted.
        guard case .collisions(let paths) = try b.engine.use("work", choices: [:]) else { return XCTFail("should ask") }
        XCTAssertEqual(paths, ["~/.kube/config"])
        guard case .done = try b.engine.use("work", choices: ["~/.kube/config": .shrug]) else { return XCTFail() }
        XCTAssertEqual(b.engine.found(bCfg, "synced/kube/config"), .ourLink)
        XCTAssertEqual(try b.read("synced/kube/config"), Data("new context".utf8))
        XCTAssertFalse(FileManager.default.fileExists(atPath: bCfg.path + ".before-shrug"))
    }

    func testUnlockAgainWithPassword() throws {
        let (a, _) = try twoMacs()
        try a.write("synced/x", Data("x".utf8))
        a.engine.lockNow("test")
        XCTAssertNil(a.engine.store)
        XCTAssertThrowsError(try a.engine.unlock(password: "wrong one"))
        try a.engine.unlock(password: password)
        XCTAssertEqual(try a.read("synced/x"), Data("x".utf8))
    }
}

func bytes(_ n: Int, seed: UInt8 = 7) -> Data {
    Data((0..<n).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ Int(seed)) })
}
