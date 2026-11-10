import CryptoKit
import LocalAuthentication
import XCTest
@testable import ShrugCore

func bytes(_ n: Int, seed: UInt8 = 7) -> Data {
    Data((0..<n).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ Int(seed)) })
}

class TempDirTestCase: XCTestCase {
    var dir: URL!

    override func setUp() {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("shrug-tests-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: dir)
    }
}

final class EncryptedFileTests: TempDirTestCase {
    let key = SymmetricKey(size: .bits256)

    func write(_ data: Data, to url: URL, base: Int64 = 0) throws {
        FileManager.default.createFile(atPath: url.path, contents: Data(count: Int(base)))
        try EncryptedFile(url: url, master: key, writable: true, base: base).write(offset: 0, data: data)
    }

    func read(_ url: URL, base: Int64 = 0, key: SymmetricKey? = nil) throws -> Data {
        let f = try EncryptedFile(url: url, master: key ?? self.key, writable: false, base: base)
        return try f.read(offset: 0, count: Int(f.size))
    }

    func size(_ url: URL) throws -> Int64 {
        try FileManager.default.attributesOfItem(atPath: url.path)[.size] as! Int64
    }

    func testRoundTripSizes() throws {
        for base in [Int64(0), ObjectFormat.contentOffset] {
            for n in [0, 1, 100, 65535, 65536, 65537, 200_001] {
                let url = dir.appendingPathComponent("f\(n)-\(base)")
                let data = bytes(n)
                try write(data, to: url, base: base)
                XCTAssertEqual(try read(url, base: base), data, "size \(n), base \(base)")
                XCTAssertEqual(EncFormat.plainSize(encryptedSize: try size(url) - base), Int64(n))
                XCTAssertEqual(EncFormat.encryptedSize(plainSize: Int64(n)), try size(url) - base)
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
                let offset = Int.random(in: 0...(reference.count + 200_000), using: &rng)
                let len = Int.random(in: 1...150_000, using: &rng)
                let chunk = bytes(len, seed: UInt8(step % 251))
                try f.write(offset: Int64(offset), data: chunk)
                if offset > reference.count { reference.append(Data(count: offset - reference.count)) }
                let end = offset + len
                if end > reference.count { reference.append(Data(count: end - reference.count)) }
                reference.replaceSubrange(offset..<end, with: chunk)
            } else {
                let newSize = Int.random(in: 0...(reference.count + 200_000), using: &rng)
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

    func testEmptyContentHasNoHeader() throws {
        let url = dir.appendingPathComponent("empty")
        try write(bytes(1000), to: url)
        let f = try EncryptedFile(url: url, master: key, writable: true)
        try f.truncate(to: 0)
        XCTAssertNil(f.contentFileID)
        XCTAssertEqual(try size(url), 0)
        XCTAssertTrue(f.matches(fileID: nil, size: 0))
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

    func testReencryptingGivesAFreshFileIDAndTheSameContent() throws {
        let url = dir.appendingPathComponent("orig")
        try write(bytes(150_000), to: url)
        let original = try EncryptedFile(url: url, master: key, writable: false)
        let prefix = Data(repeating: 0xAB, count: 12)
        let copy = try original.reencrypt(to: dir.appendingPathComponent("copy"), prefix: prefix)
        XCTAssertNotEqual(copy.contentFileID, original.contentFileID)
        XCTAssertEqual(try copy.read(offset: 0, count: 200_000), bytes(150_000))
        XCTAssertEqual(try Data(contentsOf: copy.url).prefix(12), prefix)
        XCTAssertTrue(copy.matches(fileID: copy.contentFileID?.hex, size: 150_000))
    }

    func testMatchesSpotsCutsAndOtherIDs() throws {
        let url = dir.appendingPathComponent("m")
        try write(bytes(150_000), to: url)
        let f = try EncryptedFile(url: url, master: key, writable: false)
        let id = f.contentFileID?.hex
        XCTAssertTrue(f.matches(fileID: id, size: 150_000))
        XCTAssertFalse(f.matches(fileID: id, size: 149_999))
        XCTAssertFalse(f.matches(fileID: id, size: 200_000))
        XCTAssertFalse(f.matches(fileID: "00", size: 150_000))
        XCTAssertFalse(f.matches(fileID: nil, size: 150_000))
    }

    func testKeyring() throws {
        setenv("SHRUG_TEST_KDF_ITERATIONS", "1000", 1)
        let (ring, key) = try Keyring.create(password: "correct horse battery")
        XCTAssertEqual(try ring.open(password: "correct horse battery").rawData, key.rawData)
        XCTAssertThrowsError(try ring.open(password: "wrong"))
    }

    /// A keyring from the bucket can say anything: odd ones are refused before any work, instead
    /// of crashing (a negative count) or deriving for hours.
    func testOddKeyringsAreRefusedBeforeAnyWork() throws {
        setenv("SHRUG_TEST_KDF_ITERATIONS", "1000", 1)
        let (ring, _) = try Keyring.create(password: "correct horse battery")
        for iterations in [0, -1, Int.min, Int.max, ShrugCrypto.maxIterations + 1] {
            var odd = ring
            odd.iterations = iterations
            XCTAssertThrowsError(try odd.open(password: "correct horse battery"), "\(iterations) iterations")
        }
        var salt = ring
        salt.salt = Data(count: 4).base64EncodedString()
        XCTAssertThrowsError(try salt.open(password: "correct horse battery"))
        var kdf = ring
        kdf.kdf = "md5"
        XCTAssertThrowsError(try kdf.open(password: "correct horse battery"))
        var wrapped = ring
        wrapped.wrappedKey = "not base64!"
        XCTAssertThrowsError(try wrapped.open(password: "correct horse battery"))
    }
}

/// This Mac's real Secure Enclave (skipped where there's none, as on CI).
final class ChipSealTests: XCTestCase {
    func testTheSecureEnclaveOpensOnlyWhatItsOwnKeySealed() throws {
        let chip = SecureEnclaveSeal()
        try XCTSkipUnless(chip.isAvailable, "no Secure Enclave here")
        let secret = Data("this Mac's keys".utf8)
        let sealed = try chip.seal(secret)
        XCTAssertEqual(try chip.open(sealed), secret)

        var mixed = try chip.seal(secret)
        mixed.sealed = sealed.sealed
        XCTAssertThrowsError(try chip.open(mixed), "another chip key doesn't open it")
        var damaged = sealed
        damaged.key = Data(count: 64).base64EncodedString()
        XCTAssertThrowsError(try chip.open(damaged))
    }
}

final class TouchIDStoreTests: TempDirTestCase {
    func testOnlyCopiesMadeForFingerprintsOnlyCount() throws {
        let url = dir.appendingPathComponent("touchid.json")
        let store = TouchIDStore(url: url)
        XCTAssertFalse(store.hasCurrentCopy)
        // As made before the rule was recorded: the Mac password opened it too.
        let old = #"{"seKey":"AA==","ephemeral":"AA==","sealed":"AA==","created":"2026-01-01T00:00:00.000Z"}"#
        try Data(old.utf8).write(to: url)
        XCTAssertFalse(store.hasCurrentCopy, "an old copy is never used")
        let current = #"{"seKey":"AA==","ephemeral":"AA==","sealed":"AA==","created":"2026-01-01T00:00:00.000Z","policy":2}"#
        try Data(current.utf8).write(to: url)
        XCTAssertTrue(store.hasCurrentCopy)
    }

    func testTouchIDAnswersMapToWhatShrugDoesNext() {
        func kind(_ code: LAError.Code) -> String {
            switch TouchIDStore.classify(LAError(code)) {
            case .usePassword: return "password"
            case .cancelled: return "cancelled"
            case .invalidated: return "invalidated"
            case .timedOut: return "timedOut"
            }
        }
        XCTAssertEqual(kind(.userFallback), "password", "the Use Shrug Password… button")
        XCTAssertEqual(kind(.biometryLockout), "password", "too many tries never falls back to the Mac password")
        XCTAssertEqual(kind(.biometryNotAvailable), "password", "lid closed, no sensor in reach")
        XCTAssertEqual(kind(.authenticationFailed), "password")
        XCTAssertEqual(kind(.userCancel), "cancelled")
        XCTAssertEqual(kind(.systemCancel), "cancelled")
    }
}

final class ObjectFormatTests: TempDirTestCase {
    let keys = VaultKeys(master: SymmetricKey(size: .bits256))

    func header(_ path: String) -> ObjectHeader {
        ObjectHeader(path: path, kind: .file, editedAt: Date().ms, mtime: Date().ms, size: 12, mode: 0o600, fileID: "ab")
    }

    /// A complete object for `path` with `content`, as an upload makes it.
    func object(_ path: String, _ content: Data) throws -> URL {
        let plain = dir.appendingPathComponent(UUID().uuidString)
        FileManager.default.createFile(atPath: plain.path, contents: nil)
        try EncryptedFile(url: plain, master: keys.master, writable: true).write(offset: 0, data: content)
        let url = dir.appendingPathComponent(UUID().uuidString)
        let copy = try EncryptedFile(url: plain, master: keys.master, writable: false)
            .reencrypt(to: url, prefix: ObjectFormat.blankPrefix())
        let h = ObjectHeader(path: path, kind: .file, editedAt: Date().ms, mtime: Date().ms, size: Int64(content.count),
                             mode: 0o600, fileID: copy.contentFileID?.hex)
        try ObjectFormat.writeHeader(h, to: url, keys: keys, objectKey: keys.objectKey(path))
        return url
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

    func testVerifiedObjectsAreExactlyWhatTheirHeaderSays() throws {
        let path = "synced/a"
        let good = try object(path, bytes(140_000, seed: 1))
        XCTAssertEqual(try ObjectFormat.verifiedHeader(of: good, keys: keys, objectKey: keys.objectKey(path)).size, 140_000)
        let original = try Data(contentsOf: good)
        let start = Int(ObjectFormat.contentOffset)

        // Another file's content under this header.
        let other = try Data(contentsOf: try object("synced/b", bytes(140_000, seed: 2)))
        var swapped = original
        swapped.replaceSubrange(start..<swapped.count, with: other[start...])
        // Cut at a chunk boundary, or with a byte missing.
        let cut = original.prefix(start + EncFormat.headerSize + EncFormat.recordSize)
        let short = original.dropLast()
        // A chunk from another version of the same file.
        let older = try Data(contentsOf: try object(path, bytes(140_000, seed: 3)))
        var spliced = original
        let first = start + EncFormat.headerSize
        spliced.replaceSubrange(first..<(first + EncFormat.recordSize), with: older[first..<(first + EncFormat.recordSize)])

        for (name, data) in [("swapped", swapped), ("cut", Data(cut)), ("short", Data(short)), ("spliced", spliced)] {
            let url = dir.appendingPathComponent(name)
            try data.write(to: url)
            XCTAssertThrowsError(try ObjectFormat.verifiedHeader(of: url, keys: keys, objectKey: keys.objectKey(path)), name)
        }
        XCTAssertThrowsError(try ObjectFormat.verifiedHeader(of: good, keys: keys, objectKey: keys.objectKey("synced/b")),
                             "moved to another name")
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

final class StorageTests: TempDirTestCase {
    /// The worked example from AWS's Signature Version 4 documentation (GET with a range), which
    /// checks the algorithm itself; Google's version only changes the names.
    func testV4SigningMatchesAWSExample() {
        let amazon = V4Signer.Names(algorithm: "AWS4-HMAC-SHA256", keyPrefix: "AWS4", service: "s3",
                                    requestType: "aws4_request", headerPrefix: "x-amz")
        let signer = V4Signer(accessID: "AKIAIOSFODNN7EXAMPLE", secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                              region: "us-east-1", names: amazon)
        let date = ISO8601.parse("2013-05-24T00:00:00Z")!
        let auth = signer.authorization(
            method: "GET", path: "/test.txt", query: [],
            headers: ["host": "examplebucket.s3.amazonaws.com", "range": "bytes=0-9",
                      "x-amz-content-sha256": V4Signer.emptyHash, "x-amz-date": "20130524T000000Z"],
            payloadHash: V4Signer.emptyHash, date: date)
        XCTAssertEqual(auth, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, "
            + "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, "
            + "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
    }

    func testGoogleSigningUsesGooglesNames() {
        let signer = V4Signer(accessID: "GOOG1EXAMPLE", secret: "secret", region: "auto")
        let auth = signer.authorization(
            method: "GET", path: "/vault/m/keyring", query: [],
            headers: ["host": "storage.googleapis.com", "x-goog-date": "20261110T000000Z",
                      "x-goog-content-sha256": V4Signer.emptyHash, "x-goog-if-generation-match": "7"],
            payloadHash: V4Signer.emptyHash, date: ISO8601.parse("2026-11-10T00:00:00Z")!)
        XCTAssertTrue(auth.hasPrefix("GOOG4-HMAC-SHA256 Credential=GOOG1EXAMPLE/20261110/auto/storage/goog4_request, "
            + "SignedHeaders=host;x-goog-content-sha256;x-goog-date;x-goog-if-generation-match, Signature="), auth)
    }

    func testQueryEncoding() {
        XCTAssertEqual(V4Signer.canonicalQuery([("prefix", "f/"), ("marker", "a b")]), "marker=a%20b&prefix=f%2F")
    }

    func testFolderStorageWritesAreConditional() throws {
        let root = dir.appendingPathComponent("bucket")
        let s = FolderStorage(root: root)
        XCTAssertThrowsError(try s.list(prefix: "")) { error in
            guard case StorageError.offline = error else { return XCTFail("a missing folder is offline") }
        }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let v1 = try s.put("f/a", data: Data("hello".utf8), replacing: nil)
        XCTAssertEqual(try s.get("f/a", range: 1...3, version: v1), Data("ell".utf8))
        XCTAssertEqual(try s.list(prefix: "f/").map(\.version), [v1])
        XCTAssertThrowsError(try s.put("f/a", data: Data("again".utf8), replacing: nil), "it exists already") { error in
            guard case StorageError.conflict = error else { return XCTFail("\(error)") }
        }
        let v2 = try s.put("f/a", data: Data("hello!".utf8), replacing: v1)
        XCTAssertNotEqual(v1, v2, "a new version has a new version id")
        XCTAssertThrowsError(try s.put("f/a", data: Data("stale".utf8), replacing: v1), "v1 was replaced meanwhile")
        XCTAssertThrowsError(try s.get("f/a", range: nil, version: v1), "reading a version that's gone")
        XCTAssertEqual(try s.get("f/a"), Data("hello!".utf8))
        let dest = dir.appendingPathComponent("download")
        XCTAssertEqual(try s.download("f/a", to: dest, version: v2), v2)
        XCTAssertEqual(try Data(contentsOf: dest), Data("hello!".utf8))
        XCTAssertThrowsError(try s.download("f/a", to: dest, version: v1), "downloading a version that's gone") { error in
            guard case StorageError.conflict = error else { return XCTFail("\(error)") }
        }
        XCTAssertThrowsError(try s.get("f/b")) { error in
            guard case StorageError.notFound = error else { return XCTFail() }
        }
        XCTAssertEqual(try s.list(prefix: "").map(\.key), ["f/a"], "no lock or temporary files listed")
    }

    func testHex() {
        XCTAssertEqual(Data([0, 255, 16]).hex, "00ff10")
        XCTAssertEqual(Data(hex: "00ff10"), Data([0, 255, 16]))
    }
}

final class FileTests: TempDirTestCase {
    func testAtomicWritesAreOwnerOnlyAndLeaveNothingBehind() throws {
        let url = dir.appendingPathComponent("state.enc")
        try JSONFile.writeAtomically(Data("one".utf8), to: url)
        try JSONFile.writeAtomically(Data("two".utf8), to: url)
        XCTAssertEqual(try Data(contentsOf: url), Data("two".utf8))
        XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int, 0o600)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path), ["state.enc"])
    }

    func testSocketLinesHaveALimit() throws {
        var fds: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
        defer { fds.forEach { close($0) } }
        Descriptor.writeAll(fds[0], Data("short line\nignored".utf8))
        XCTAssertEqual(UnixSocket.readLine(fds[1], limit: 100), Data("short line".utf8))
        Descriptor.writeAll(fds[0], Data(repeating: 0x41, count: 300) + Data("\n".utf8))
        XCTAssertNil(UnixSocket.readLine(fds[1], limit: 100))
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
