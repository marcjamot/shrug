import CryptoKit
import XCTest
@testable import ShrugCore
@testable import ShrugDaemon
import ShrugNFS

final class EngineTests: ShrugTestCase {
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
        a.sync()
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
        for rel in FileManager.default.enumerator(atPath: bucket.path)!.allObjects as! [String] {
            XCTAssertFalse(rel.contains("client"), rel)
            if let data = try? Data(contentsOf: bucket.appendingPathComponent(rel)) {
                XCTAssertNil(data.range(of: Data("secret terms".utf8)), rel)
            }
        }

        try a.engine.unlock(password: password)
        XCTAssertEqual(try a.text("synced/client-x-contract.txt"), "secret terms")
        XCTAssertEqual(try a.text("local/notes.txt"), "local only")
    }

    func testSyncedFilesReachTheOtherMac() throws {
        let (a, b) = try twoMacs()
        try a.mkdirs("synced/work")
        try a.write("synced/work/kubeconfig", Data("apiVersion: v1".utf8))
        try a.write("local/only-here.txt", Data("x".utf8))
        a.sync()
        b.sync()
        XCTAssertEqual(try b.text("synced/work/kubeconfig"), "apiVersion: v1")
        XCTAssertEqual(try b.names("local"), [], "local/ never leaves its Mac")
        XCTAssertEqual(b.engine.status().waiting, 0)
        a.sync()
        XCTAssertEqual(a.engine.status().macs, ["a", "b"])
    }

    func testTheNewestEditWinsWhicheverMacSyncsFirst() throws {
        for newerFirst in [true, false] {
            let (a, b) = try twoMacs()
            try a.write("synced/f.txt", Data("one".utf8))
            a.sync()
            b.sync()
            try offline {
                try a.write("synced/f.txt", Data("A, older".utf8))
                try b.write("synced/f.txt", Data("B, newer".utf8))
            }
            if newerFirst {
                b.sync()
                a.sync()
            } else {
                a.sync()
                b.sync()
                a.sync()
            }
            XCTAssertEqual(try a.text("synced/f.txt"), "B, newer")
            XCTAssertEqual(try b.text("synced/f.txt"), "B, newer")
            XCTAssertEqual(a.engine.status().waiting + b.engine.status().waiting, 0)
            try FileManager.default.removeItem(at: root)
            try FileManager.default.createDirectory(at: bucket, withIntermediateDirectories: true)
        }
    }

    func testDeletesAndRenamesReachTheOtherMac() throws {
        let (a, b) = try twoMacs()
        try a.write("synced/old.txt", Data("x".utf8))
        try a.write("synced/gone.txt", Data("y".utf8))
        a.sync()
        b.sync()
        try a.rename("synced/old.txt", "synced/new.txt")
        try a.remove("synced/gone.txt")
        a.sync()
        b.sync()
        XCTAssertEqual(try b.names("synced"), ["new.txt"])
        XCTAssertEqual(try b.text("synced/new.txt"), "x")
        guard case .failure(.xdev) = a.fs.rename(3, "new.txt", 4, "new.txt", a.ctx) else {
            return XCTFail("moving between folders is a copy, not a rename")
        }
    }

    func testDeleteMarkersStayForGood() throws {
        let (a, b) = try twoMacs()
        try a.write("synced/gone.txt", Data("y".utf8))
        a.sync()
        try a.remove("synced/gone.txt")
        a.sync()
        time.advance(400 * 86400)
        a.sync()
        b.sync()
        XCTAssertTrue(FileManager.default.fileExists(atPath: object(a, "synced/gone.txt").path),
                      "Shrug never removes an object, not even an old marker")
        XCTAssertEqual(try b.names("synced"), [])
    }

    func testEveryUploadHasItsOwnFileID() throws {
        let (a, _) = try twoMacs()
        var ids: Set<String> = []
        for version in ["one", "two", "two"] {
            try a.write("synced/token", Data(version.utf8))
            a.sync()
            let h = try ObjectFormat.verifiedHeader(of: object(a, "synced/token"), keys: a.store.keys,
                                                    objectKey: a.store.objectKey("synced/token"))
            ids.insert(try XCTUnwrap(h.fileID))
        }
        XCTAssertEqual(ids.count, 3, "no two versions of a file share a key")
    }

    func testRemoteFilesStreamAndAreNotKept() throws {
        let (a, b) = try twoMacs()
        let big = bytes(300_000)
        try a.write("remote/video.bin", big)
        a.sync()
        let key = String(a.store.objectKey("remote/video.bin").dropFirst(2))
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
        XCTAssertEqual(try a.text("remote/video.bin"), "short")
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
        XCTAssertEqual(try b.text("remote/draft.txt"), "written on a plane")
        XCTAssertEqual(try b.text("synced/todo.txt"), "plane")
    }

    func testWrongPasswordDoesNotJoin() throws {
        let a = mac("a")
        _ = try a.engine.setup(storage, nil, password: password, deviceName: "a", create: true)
        let b = mac("b")
        XCTAssertThrowsError(try b.engine.setup(storage, nil, password: "not the password", deviceName: "b", create: false))
        XCTAssertFalse(b.paths.isSetUp)
        XCTAssertThrowsError(try a.engine.setup(storage, nil, password: password, deviceName: "a", create: true),
                             "setting up twice is refused")
        let c = mac("c")
        XCTAssertThrowsError(try c.engine.setup(storage, nil, password: password, deviceName: "c", create: true),
                             "a second vault can't replace the first")
    }

    func testAnyPasswordIsYoursToChoose() throws {
        let a = mac("a")
        _ = try a.engine.setup(storage, nil, password: "x", deviceName: "a", create: true)
        a.engine.lockNow("test")
        try a.engine.unlock(password: "x")
        XCTAssertTrue(a.engine.isUnlocked)
    }

    func testProfilesPlaceLinksOnEveryMac() throws {
        let (a, b) = try twoMacs()
        guard case .done = try a.engine.use("work", choices: [:]) else { return XCTFail() }
        try a.putHome(".ssh/id_test", "PRIVATE KEY")
        guard case .done = try a.engine.add(path: a.home(".ssh/id_test").path, target: nil, cls: nil, choices: [:]) else {
            return XCTFail()
        }
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: a.home(".ssh/id_test").path),
                       a.paths.mount.appendingPathComponent("synced/ssh/id_test").path)
        XCTAssertEqual(try a.text("synced/ssh/id_test"), "PRIVATE KEY")
        // A link to a file that doesn't exist yet creates it empty.
        let env = a.home("project/.env")
        _ = try a.engine.add(path: env.path, target: "synced/project/env", cls: nil, choices: [:])
        XCTAssertEqual(try a.read("synced/project/env"), Data())
        a.sync()

        // Following "work" on B first asks to place A's links there at all.
        try b.putHome(".ssh/id_test", "B's old key")
        b.sync()
        guard case .confirm(let asked) = try b.engine.use("work", choices: [:]) else { return XCTFail("should ask") }
        XCTAssertEqual(asked.map(\.path), ["~/.ssh/id_test", "~/project/.env"])
        // B already has its own ~/.ssh/id_test: then it asks which to keep.
        guard case .collisions(let paths) = try follow(b) else { return XCTFail("should ask") }
        XCTAssertEqual(paths, ["~/.ssh/id_test"])
        XCTAssertEqual(b.engine.found(b.home(".ssh/id_test"), "synced/ssh/id_test"), .file, "asking changes nothing")
        guard case .done = try follow(b, choices: ["~/.ssh/id_test": .shrug]) else { return XCTFail() }
        XCTAssertEqual(b.engine.found(b.home(".ssh/id_test"), "synced/ssh/id_test"), .ourLink)
        XCTAssertEqual(try b.text("synced/ssh/id_test"), "PRIVATE KEY", "Shrug's key won")
        XCTAssertEqual(b.engine.found(b.home("project/.env"), "synced/project/env"), .ourLink)

        // A link change on B reaches A: the last change wins.
        _ = try b.engine.remove(path: b.home("project/.env").path)
        b.sync()
        a.sync()
        a.engine.reconcile()
        XCTAssertEqual(a.engine.found(env, "synced/project/env"), .nothing, "the link is gone on A too")
        XCTAssertEqual(try a.read("synced/project/env"), Data(), "but the file stays in ~/Shrug")
    }

    func testAdjustingPullsBackReplacedLinksAndWaitsOnOthers() throws {
        let (a, b) = try twoMacsFollowing()
        let cfg = a.home(".kube/config")
        _ = try a.engine.add(path: cfg.path, target: nil, cls: nil, choices: [:])
        // A tool saves by replacing the link with a real file.
        unlink(cfg.path)
        try Data("new context".utf8).write(to: cfg)
        a.engine.reconcile()
        XCTAssertEqual(a.engine.found(cfg, "synced/kube/config"), .ourLink)
        XCTAssertEqual(try a.text("synced/kube/config"), "new context")
        a.sync()

        // B has its own fresh ~/.kube/config. When the link arrives nobody is there to ask, so
        // B's file is left alone (never pulled in over Shrug's, never deleted) and B is told once.
        try b.putHome(".kube/config", "fresh default")
        b.sync()
        b.engine.reconcile()
        b.engine.reconcile()
        XCTAssertEqual(b.engine.found(b.home(".kube/config"), "synced/kube/config"), .file)
        XCTAssertEqual(try String(contentsOf: b.home(".kube/config"), encoding: .utf8), "fresh default")
        XCTAssertEqual(try b.text("synced/kube/config"), "new context")
        XCTAssertEqual(b.engine.status().notices.count, 1, "told once, not every minute")

        // Following the profile again asks, and the version not chosen is deleted.
        guard case .collisions(let paths) = try follow(b) else { return XCTFail("should ask") }
        XCTAssertEqual(paths, ["~/.kube/config"])
        guard case .done = try follow(b, choices: ["~/.kube/config": .shrug]) else { return XCTFail() }
        XCTAssertEqual(b.engine.found(b.home(".kube/config"), "synced/kube/config"), .ourLink)
        XCTAssertEqual(try b.text("synced/kube/config"), "new context")
    }

    func testDeletingALinkRemovesIt() throws {
        let (a, b) = try twoMacsFollowing()
        let cfg = a.home(".kube/config")
        _ = try a.engine.add(path: cfg.path, target: nil, cls: nil, choices: [:])
        try a.write("synced/kube/config", Data("context".utf8))
        a.sync()
        b.sync()
        try follow(b)
        let bCfg = b.home(".kube/config")
        XCTAssertEqual(b.engine.found(bCfg, "synced/kube/config"), .ourLink)

        // Deleting the link is a `shrug remove`: it isn't put back, and the file stays in Shrug.
        unlink(cfg.path)
        a.engine.reconcile()
        a.engine.reconcile()
        XCTAssertEqual(a.engine.found(cfg, "synced/kube/config"), .nothing)
        XCTAssertFalse(a.engine.status().links.contains { $0.path == "~/.kube/config" })
        XCTAssertEqual(try a.text("synced/kube/config"), "context")
        a.sync()
        b.sync()
        b.engine.reconcile()
        XCTAssertEqual(b.engine.found(bCfg, "synced/kube/config"), .nothing, "gone on B too")

        // Adding it again works, even when the delete wasn't noticed yet.
        _ = try a.engine.add(path: cfg.path, target: nil, cls: nil, choices: [:])
        unlink(cfg.path)
        _ = try a.engine.add(path: cfg.path, target: nil, cls: nil, choices: [:])
        XCTAssertEqual(a.engine.found(cfg, "synced/kube/config"), .ourLink)
        XCTAssertEqual(try a.text("synced/kube/config"), "context")
    }

    func testRenamingInShrugMovesTheLinkAndDeletingRemovesIt() throws {
        let (a, b) = try twoMacsFollowing()
        let cfg = a.home(".kube/config")
        _ = try a.engine.add(path: cfg.path, target: nil, cls: nil, choices: [:])
        try a.write("synced/kube/config", Data("context".utf8))
        a.sync()
        b.sync()
        try follow(b)
        let bCfg = b.home(".kube/config")

        // Renaming the file, or its folder, in ~/Shrug: the link follows, on both Macs.
        try a.rename("synced/kube/config", "synced/kube/work")
        try a.rename("synced/kube", "synced/k8s")
        a.engine.reconcile()
        XCTAssertEqual(a.engine.found(cfg, "synced/k8s/work"), .ourLink)
        XCTAssertEqual(try a.text("synced/k8s/work"), "context")
        a.sync()
        b.sync()
        b.engine.reconcile()
        XCTAssertEqual(b.engine.found(bCfg, "synced/k8s/work"), .ourLink)
        XCTAssertFalse(b.engine.status().notices.contains { $0.contains("replaced") }, "a move isn't a surprise")

        // Deleting the file in ~/Shrug: it's gone, and so is the link. Nothing comes back empty.
        try a.remove("synced/k8s/work")
        a.engine.reconcile()
        XCTAssertEqual(a.engine.found(cfg, "synced/k8s/work"), .nothing)
        XCTAssertFalse(a.engine.status().links.contains { $0.path == "~/.kube/config" })
        XCTAssertNil(a.store.entry("synced/k8s/work"))
        a.sync()
        b.sync()
        b.engine.reconcile()
        XCTAssertEqual(b.engine.found(bCfg, "synced/k8s/work"), .nothing)
        XCTAssertNil(b.store.entry("synced/k8s/work"))
    }

    func testUnlockAgainWithPassword() throws {
        let (a, _) = try twoMacs()
        try a.write("synced/x", Data("x".utf8))
        a.engine.lockNow("test")
        XCTAssertNil(a.engine.store)
        XCTAssertThrowsError(try a.engine.unlock(password: "wrong one"))
        try a.engine.unlock(password: password)
        XCTAssertEqual(try a.text("synced/x"), "x")
    }

    func testGrowingAFileFillsTheGapChunkByChunk() throws {
        let (a, _) = try twoMacs()
        try a.write("synced/f", Data("x".utf8))
        let id = try a.lookup("synced/f")
        var attrs = NFSSetAttrs()
        attrs.size = 3 << 20
        try a.fs.setattr(id, attrs, a.ctx).get()
        XCTAssertEqual(try a.read("synced/f").count, 3 << 20, "a gap of several chunks fills with zeros")
        XCTAssertEqual(try a.read("synced/f").prefix(1), Data("x".utf8))
    }
}
