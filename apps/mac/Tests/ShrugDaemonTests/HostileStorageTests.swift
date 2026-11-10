import CryptoKit
import XCTest
@testable import ShrugCore
@testable import ShrugDaemon

/// The storage, or anyone who can write to the bucket, changing objects behind Shrug's back.
final class HostileStorageTests: ShrugTestCase {
    func testAnotherFilesContentIsRefused() throws {
        let (a, b) = try twoMacs()
        try a.write("synced/aws-prod", Data("PROD-SECRET-AAAA".utf8))
        try a.write("synced/aws-test", Data("TEST-SECRET-BBBB".utf8))
        a.sync()
        b.sync()
        // Keep prod's sealed header, serve test's content.
        var prod = try Data(contentsOf: object(a, "synced/aws-prod"))
        let test = try Data(contentsOf: object(a, "synced/aws-test"))
        let start = Int(ObjectFormat.contentOffset)
        prod.replaceSubrange(start..<prod.count, with: test[start...])
        try tamper(object(a, "synced/aws-prod"), prod)

        b.sync()
        XCTAssertEqual(try b.text("synced/aws-prod"), "PROD-SECRET-AAAA", "B keeps what it had")
        XCTAssertTrue(b.engine.status().notices.contains { $0.contains("synced/aws-prod") })
        let c = mac("c")
        _ = try c.engine.setup(storage, nil, password: password, deviceName: "c", create: false)
        c.sync()
        XCTAssertEqual(try c.names("synced"), ["aws-test"], "a new Mac doesn't take it at all")
    }

    func testAnOlderVersionIsRefusedAndRepaired() throws {
        let (a, b) = try twoMacs()
        try a.write("synced/token", Data("v1-revoked".utf8))
        a.sync()
        let v1 = try Data(contentsOf: object(a, "synced/token"))
        try a.write("synced/token", Data("v2-current".utf8))
        a.sync()
        b.sync()
        try tamper(object(a, "synced/token"), v1)

        a.sync()
        b.sync()
        XCTAssertEqual(try a.text("synced/token"), "v2-current")
        XCTAssertEqual(try b.text("synced/token"), "v2-current")
        XCTAssertTrue(a.engine.status().notices.contains { $0.contains("older synced/token") })
        let c = mac("c")
        _ = try c.engine.setup(storage, nil, password: password, deviceName: "c", create: false)
        c.sync()
        XCTAssertEqual(try c.text("synced/token"), "v2-current", "the newer copy went back up")
    }

    func testCutContentIsRefused() throws {
        let (a, b) = try twoMacs()
        let data = bytes(200_000)
        try a.write("synced/big", data)
        a.sync()
        b.sync()
        try a.write("synced/big", bytes(200_000, seed: 9))
        a.sync()
        let full = try Data(contentsOf: object(a, "synced/big"))
        let cut = Int(ObjectFormat.contentOffset) + EncFormat.headerSize + 2 * EncFormat.recordSize
        try tamper(object(a, "synced/big"), full.prefix(cut))

        b.sync()
        XCTAssertEqual(try b.read("synced/big"), data, "B keeps its complete copy instead of a cut one")
    }

    func testAnOversizedObjectIsNeverDownloaded() throws {
        let (a, b) = try twoMacs()
        try a.write("synced/token", Data("v1".utf8))
        try a.write("remote/r", Data("remote".utf8))
        a.sync()
        b.sync()
        // Genuine objects with 8 MB after them: their sealed headers still open.
        for path in ["synced/token", "remote/r"] {
            let url = object(a, path)
            try tamper(url, Data(contentsOf: url) + Data(count: 8 << 20))
        }

        b.sync()
        XCTAssertEqual(try b.text("synced/token"), "v1")
        let notices = b.engine.status().notices
        for path in ["synced/token", "remote/r"] {
            // Not "kept this Mac's", which comes from checking a download: this one never started.
            XCTAssertTrue(notices.contains { $0.contains("copy of \(path) is damaged") && $0.hasSuffix("Shrug won't use it") },
                          path)
        }
    }

    func testChunksFromAnotherVersionDontFit() throws {
        let (a, b) = try twoMacs()
        try a.write("synced/big", bytes(140_000, seed: 1))
        a.sync()
        let v1 = try Data(contentsOf: object(a, "synced/big"))
        try a.write("synced/big", bytes(140_000, seed: 2))
        a.sync()
        b.sync()
        try a.write("synced/big", bytes(140_000, seed: 3))
        a.sync()
        // The newest header and content, with the first chunk of the first version.
        var spliced = try Data(contentsOf: object(a, "synced/big"))
        let first = Int(ObjectFormat.contentOffset) + EncFormat.headerSize
        spliced.replaceSubrange(first..<(first + EncFormat.recordSize), with: v1[first..<(first + EncFormat.recordSize)])
        try tamper(object(a, "synced/big"), spliced)

        b.sync()
        XCTAssertEqual(try b.read("synced/big"), bytes(140_000, seed: 2))
    }

    func testAReplayedDeleteMarkerIsRefused() throws {
        let (a, b) = try twoMacs()
        try a.write("synced/f", Data("one".utf8))
        a.sync()
        try a.remove("synced/f")
        a.sync()
        let marker = try Data(contentsOf: object(a, "synced/f"))
        try a.write("synced/f", Data("back again".utf8))
        a.sync()
        b.sync()
        try tamper(object(a, "synced/f"), marker)

        b.sync()
        a.sync()
        XCTAssertEqual(try b.text("synced/f"), "back again")
        XCTAssertEqual(try a.text("synced/f"), "back again")
    }

    func testRemovedObjectsComeBack() throws {
        let (a, b) = try twoMacs()
        try a.mkdirs("synced/dir")
        try a.write("synced/dir/keep", Data("important".utf8))
        try a.write("remote/only-there", Data("remote".utf8))
        a.sync()
        b.sync()
        for path in ["synced/dir", "synced/dir/keep", "remote/only-there"] {
            try FileManager.default.removeItem(at: object(a, path))
        }

        a.sync()
        b.sync()
        XCTAssertEqual(try a.text("synced/dir/keep"), "important")
        XCTAssertEqual(try b.text("synced/dir/keep"), "important")
        XCTAssertTrue(FileManager.default.fileExists(atPath: object(a, "synced/dir/keep").path), "it went back up")
        XCTAssertTrue(FileManager.default.fileExists(atPath: object(a, "synced/dir").path))
        XCTAssertTrue(a.engine.status().notices.contains { $0.contains("synced/dir/keep was missing") })
        XCTAssertEqual(try a.names("remote"), [], "only the storage had the remote file's content")
        XCTAssertTrue(a.engine.status().notices.contains { $0.contains("remote/only-there was removed") })
    }

    func testAnOlderRemoteFileIsNotRead() throws {
        let (a, b) = try twoMacs()
        try a.write("remote/r", Data("old".utf8))
        a.sync()
        let old = try Data(contentsOf: object(a, "remote/r"))
        try a.write("remote/r", Data("new".utf8))
        a.sync()
        b.sync()
        try tamper(object(a, "remote/r"), old)

        b.sync()
        guard case .failure = b.fs.read(try b.lookup("remote/r"), offset: 0, count: 100, b.ctx) else {
            return XCTFail("B must not show the older content")
        }
        XCTAssertTrue(b.engine.status().notices.contains { $0.contains("older remote/r") })
    }

    func testAnOlderProfileIsRefused() throws {
        let (a, b) = try twoMacsFollowing()
        let key = bucket.appendingPathComponent(a.store.keys.profileKey("work"))
        let empty = try Data(contentsOf: key)
        try a.putHome(".kube/config", "cfg")
        _ = try a.engine.add(path: a.home(".kube/config").path, target: nil, cls: nil, choices: [:])
        a.sync()
        b.sync()
        try tamper(key, empty)

        b.sync()
        a.sync()
        XCTAssertEqual(b.engine.stateCopy()?.links.map(\.path), ["~/.kube/config"])
        XCTAssertEqual(a.engine.stateCopy()?.links.map(\.path), ["~/.kube/config"])
        let restored = try a.store.keys.openMeta(Profile.self, Data(contentsOf: key), key: a.store.keys.profileKey("work"))
        XCTAssertEqual(restored.links.map(\.path), ["~/.kube/config"], "the newer profile went back up")
    }
}
