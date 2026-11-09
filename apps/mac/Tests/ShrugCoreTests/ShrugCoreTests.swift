import CryptoKit
import XCTest
@testable import ShrugCore

func bytes(_ n: Int, seed: UInt8 = 7) -> Data {
    Data((0..<n).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ Int(seed)) })
}

final class EncryptedFileTests: XCTestCase {
    var dir: URL!
    let key = SymmetricKey(size: .bits256)

    override func setUp() {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("shrug-tests-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: dir)
    }

    func write(_ data: Data, to url: URL, base: Int64 = 0) throws {
        FileManager.default.createFile(atPath: url.path, contents: Data(count: Int(base)))
        try EncryptedFile(url: url, master: key, writable: true, base: base).write(offset: 0, data: data)
    }

    func read(_ url: URL, base: Int64 = 0, key: SymmetricKey? = nil) throws -> Data {
        let f = try EncryptedFile(url: url, master: key ?? self.key, writable: false, base: base)
        return try f.read(offset: 0, count: Int(f.size))
    }

    func testRoundTripSizes() throws {
        for base in [Int64(0), ObjectFormat.contentOffset] {
            for size in [0, 1, 100, 65535, 65536, 65537, 200_001] {
                let url = dir.appendingPathComponent("f\(size)-\(base)")
                let data = bytes(size)
                try write(data, to: url, base: base)
                XCTAssertEqual(try read(url, base: base), data, "size \(size), base \(base)")
                let encSize = try FileManager.default.attributesOfItem(atPath: url.path)[.size] as! Int64
                XCTAssertEqual(EncFormat.plainSize(encryptedSize: encSize - base), Int64(size))
            }
        }
    }

    func testWrongKeyFails() throws {
        let url = dir.appendingPathComponent("f")
        try write(bytes(10), to: url)
        XCTAssertThrowsError(try read(url, key: SymmetricKey(size: .bits256)))
    }

    func testRandomAccessMatchesReference() throws {
        let url = dir.appendingPathComponent("r")
        FileManager.default.createFile(atPath: url.path, contents: Data(count: 100))
        var reference = Data()
        var rng = SystemRandomNumberGenerator()
        for step in 0..<200 {
            let f = try EncryptedFile(url: url, master: key, writable: true, base: 100)
            if Int.random(in: 0..<10, using: &rng) < 7 {
                let offset = Int.random(in: 0...(reference.count + 70_000), using: &rng)
                let len = Int.random(in: 1...150_000, using: &rng)
                let chunk = bytes(len, seed: UInt8(step % 251))
                try f.write(offset: Int64(offset), data: chunk)
                if offset > reference.count { reference.append(Data(count: offset - reference.count)) }
                let end = offset + len
                if end > reference.count { reference.append(Data(count: end - reference.count)) }
                reference.replaceSubrange(offset..<end, with: chunk)
            } else {
                let newSize = Int.random(in: 0...(reference.count + 10_000), using: &rng)
                try f.truncate(to: Int64(newSize))
                if newSize < reference.count { reference = reference.prefix(newSize) }
                else { reference.append(Data(count: newSize - reference.count)) }
            }
            XCTAssertEqual(f.size, Int64(reference.count), "size after step \(step)")
            let readOffset = Int.random(in: 0...max(0, reference.count), using: &rng)
            let got = try f.read(offset: Int64(readOffset), count: Int.random(in: 1...100_000, using: &rng))
            let expectEnd = min(reference.count, readOffset + got.count)
            XCTAssertEqual(got, readOffset < expectEnd ? Data(reference[readOffset..<expectEnd]) : Data())
        }
        XCTAssertEqual(try read(url, base: 100), reference)
        XCTAssertEqual(try Data(contentsOf: url).prefix(100), Data(count: 100), "the part before base is untouched")
    }

    func testRewritingSameContentKeepsFileIdentical() throws {
        let url = dir.appendingPathComponent("same")
        let data = bytes(150_000)
        try write(data, to: url)
        let before = try Data(contentsOf: url)
        try EncryptedFile(url: url, master: key, writable: true).write(offset: 0, data: data)
        XCTAssertEqual(try Data(contentsOf: url), before)
    }

    func testChunksOpenOnTheirOwn() throws {
        let url = dir.appendingPathComponent("stream")
        let data = bytes(200_000)
        try write(data, to: url)
        let raw = try Data(contentsOf: url)
        let id = try XCTUnwrap(EncFormat.fileID(fromHeader: raw))
        let second = raw.subdata(in: (28 + EncFormat.recordSize)..<(28 + 2 * EncFormat.recordSize))
        XCTAssertEqual(try EncFormat.openChunk(second, master: key, fileID: id, index: 1),
                       data.subdata(in: 65536..<131072))
        XCTAssertThrowsError(try EncFormat.openChunk(second, master: key, fileID: id, index: 2), "bound to its index")
    }

    func testKeyring() throws {
        setenv("SHRUG_TEST_KDF_ITERATIONS", "1000", 1)
        let (ring, key) = try Keyring.create(password: "correct horse battery")
        XCTAssertEqual(try ring.open(password: "correct horse battery").rawData, key.rawData)
        XCTAssertThrowsError(try ring.open(password: "wrong"))
    }
}

final class ObjectFormatTests: XCTestCase {
    let keys = VaultKeys(master: SymmetricKey(size: .bits256))

    func header(_ path: String) -> ObjectHeader {
        ObjectHeader(path: path, kind: .file, editedAt: .nowMs, mtime: .nowMs, size: 12, mode: 0o600, fileID: "ab")
    }

    func testHeaderRoundTripAndBinding() throws {
        let key = keys.objectKey("synced/ssh/id_ed25519")
        XCTAssertTrue(key.hasPrefix("f/"))
        XCTAssertFalse(key.contains("ssh"), "names never reach the bucket")
        XCTAssertEqual(key, keys.objectKey("synced/ssh/id_ed25519"), "the same on every Mac")
        XCTAssertNotEqual(key, keys.objectKey("remote/ssh/id_ed25519"))

        let h = header("synced/ssh/id_ed25519")
        let prefix = try ObjectFormat.prefix(h, keys: keys, objectKey: key)
        XCTAssertEqual(Int64(prefix.count), ObjectFormat.contentOffset, "fixed size: hides the path length")
        XCTAssertNil(prefix.range(of: Data("id_ed25519".utf8)))
        XCTAssertEqual(try ObjectFormat.decodeHeader(prefix, keys: keys, objectKey: key), h)
        XCTAssertThrowsError(try ObjectFormat.decodeHeader(prefix, keys: keys, objectKey: keys.objectKey("synced/x")),
                             "an object moved to another name doesn't open")
        XCTAssertThrowsError(try ObjectFormat.decodeHeader(prefix, keys: VaultKeys(master: SymmetricKey(size: .bits256)),
                                                           objectKey: key))
    }

    func testMetadataIsBoundToItsName() throws {
        let p = Profile(name: "work", links: [Link(path: "~/.kube/config", target: "synced/kube/config")], editedAt: Date())
        let key = keys.profileKey("work")
        let sealed = try keys.sealMeta(p, key: key)
        XCTAssertNil(sealed.range(of: Data("kube".utf8)))
        XCTAssertEqual(try keys.openMeta(Profile.self, sealed, key: key).links, p.links)
        XCTAssertThrowsError(try keys.openMeta(Profile.self, sealed, key: keys.profileKey("other")))
    }
}

final class StorageTests: XCTestCase {
    /// The worked example from AWS's Signature Version 4 documentation (GET with a range).
    func testSigV4MatchesAWSExample() {
        let signer = SigV4(accessID: "AKIAIOSFODNN7EXAMPLE", secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                           region: "us-east-1")
        let date = ISO8601.parse("2013-05-24T00:00:00Z")!
        let auth = signer.authorization(
            method: "GET", path: "/test.txt", query: [],
            headers: ["host": "examplebucket.s3.amazonaws.com", "range": "bytes=0-9",
                      "x-amz-content-sha256": SigV4.emptyHash, "x-amz-date": "20130524T000000Z"],
            payloadHash: SigV4.emptyHash, date: date)
        XCTAssertEqual(auth, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, "
            + "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, "
            + "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
    }

    func testQueryEncoding() {
        XCTAssertEqual(SigV4.canonicalQuery([("prefix", "f/"), ("marker", "a b")]), "marker=a%20b&prefix=f%2F")
    }

    func testListParsing() {
        let xml = """
        <?xml version="1.0"?><ListBucketResult><IsTruncated>true</IsTruncated><NextMarker>f/2</NextMarker>
        <Contents><Key>f/1</Key><Size>10</Size><ETag>"abc"</ETag></Contents>
        <Contents><Key>f/2</Key><Size>20</Size><ETag>"def"</ETag></Contents></ListBucketResult>
        """
        let page = ListParser.parse(Data(xml.utf8))
        XCTAssertEqual(page.objects.map(\.key), ["f/1", "f/2"])
        XCTAssertEqual(page.objects.map(\.etag), ["abc", "def"])
        XCTAssertTrue(page.truncated)
        XCTAssertEqual(page.nextMarker, "f/2")
    }

    func testFolderStorage() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("shrug-bucket-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let s = FolderStorage(root: root)
        XCTAssertThrowsError(try s.list(prefix: "")) { error in
            guard case StorageError.offline = error else { return XCTFail("a missing folder is offline") }
        }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let e1 = try s.put("f/a", data: Data("hello".utf8))
        XCTAssertEqual(try s.get("f/a", range: 1...3), Data("ell".utf8))
        XCTAssertEqual(try s.list(prefix: "f/").map(\.etag), [e1])
        let e2 = try s.put("f/a", data: Data("hello!".utf8))
        XCTAssertNotEqual(e1, e2, "a new version has a new etag")
        try s.delete("f/a")
        XCTAssertThrowsError(try s.get("f/a", range: nil)) { error in
            guard case StorageError.notFound = error else { return XCTFail() }
        }
    }

    func testHex() {
        XCTAssertEqual(Data([0, 255, 16]).hex, "00ff10")
        XCTAssertEqual(Data(hex: "00ff10"), Data([0, 255, 16]))
    }
}

final class PathsTests: XCTestCase {
    func testExpandAndContract() {
        let p = ShrugPaths(state: URL(fileURLWithPath: "/s"), mount: URL(fileURLWithPath: "/m"),
                          home: URL(fileURLWithPath: "/Users/me"), socket: "/s/sock")
        XCTAssertEqual(p.expand("~/.ssh/x").path, "/Users/me/.ssh/x")
        XCTAssertEqual(p.contract(URL(fileURLWithPath: "/Users/me/.ssh/x")), "~/.ssh/x")
        XCTAssertEqual(p.contract(URL(fileURLWithPath: "/usr/bin/env")), "/usr/bin/env")
    }
}
