import CryptoKit
import XCTest
@testable import ShrugCore
@testable import ShrugDaemon

/// Upgrading what older Shrugs left behind. Each fixture in Fixtures/ is a vault (a storage
/// folder) and one Mac's ~/.shrug exactly as that format's Shrug wrote them, with the password
/// "fixture password" (KDF at 1000 iterations), all holding the same things:
///   synced/ssh/id_fixture   "FIXTURE PRIVATE KEY\n", linked from ~/.ssh/id_fixture (profile "work")
///   synced/docs/note.txt    "a note\n"
///   synced/big.bin          bytes(140_000, seed: 1)
///   synced/rotated.txt      "token-version-2", after "token-version-1" went up
///   synced/gone.txt         deleted (a delete marker)
///   remote/archive.bin      bytes(70_000, seed: 2), only in the bucket
///   local/only-here.txt     "this Mac only\n"
///   synced/pending.txt      "not uploaded yet", still waiting to upload
///
/// format2 was made by Shrug e17cd90, the last format-2 version, and format3 by 49826da, the
/// last format-3 one. format3 also holds two of the ._ files macOS adds, which Shrug saved like
/// any other file until format 4: synced/docs/._note.txt and local/._only-here.txt.
///
/// Before changing a format, write a fixture of the current one with the current code:
///   FIXTURE_OUT=$PWD/Tests/ShrugDaemonTests/Fixtures/format<N> swift test --filter testWriteCurrentFormatFixture
final class MigrationTests: ShrugTestCase {
    let fixturePassword = "fixture password"

    /// Makes a fixture of the current format at `dest`.
    func writeFixture(to dest: URL) throws {
        let work = root.appendingPathComponent("fixture-work")
        let workBucket = work.appendingPathComponent("bucket")
        try FileManager.default.createDirectory(at: workBucket, withIntermediateDirectories: true)
        // No security chip: a fixture opens on any Mac, in this test and in later ones.
        let m = Mac(work, "mac", clock: time, chip: FakeChip(available: false))
        _ = try m.engine.setup(StorageConfig(kind: "folder", path: workBucket.path), nil, password: fixturePassword,
                               deviceName: "fixture-mac", create: true)
        _ = try m.engine.use("work", choices: [:])
        try m.putHome(".ssh/id_fixture", "FIXTURE PRIVATE KEY\n")
        _ = try m.engine.add(path: m.home(".ssh/id_fixture").path, target: nil, cls: nil, choices: [:])
        try m.mkdirs("synced/docs")
        try m.write("synced/docs/note.txt", Data("a note\n".utf8))
        try m.write("synced/big.bin", bytes(140_000, seed: 1))
        try m.write("synced/rotated.txt", Data("token-version-1".utf8))
        try m.write("synced/gone.txt", Data("deleted later".utf8))
        try m.write("remote/archive.bin", bytes(70_000, seed: 2))
        try m.write("local/only-here.txt", Data("this Mac only\n".utf8))
        // What macOS adds next to a file that has extended attributes (gone again by the lock below).
        try m.write("synced/docs/._note.txt", bytes(4096, seed: 3))
        try m.write("local/._only-here.txt", bytes(4096, seed: 4))
        m.sync()
        try m.write("synced/rotated.txt", Data("token-version-2".utf8))
        try m.remove("synced/gone.txt")
        m.sync()
        try m.write("synced/pending.txt", Data("not uploaded yet".utf8))
        XCTAssertEqual(m.engine.status().waiting, 1)
        m.engine.lockNow("fixture")

        try? FileManager.default.removeItem(at: dest)
        try FileManager.default.createDirectory(at: dest.appendingPathComponent("mac"), withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: workBucket, to: dest.appendingPathComponent("bucket"))
        try FileManager.default.copyItem(at: m.paths.state, to: dest.appendingPathComponent("mac/state"))
        for leftover in ["bucket/.lock", "mac/state/shrug.log"] {
            try? FileManager.default.removeItem(at: dest.appendingPathComponent(leftover))
        }
    }

    func testWriteCurrentFormatFixture() throws {
        guard let out = ProcessInfo.processInfo.environment["FIXTURE_OUT"] else { throw XCTSkip("Set FIXTURE_OUT to write a fixture") }
        try writeFixture(to: URL(fileURLWithPath: out))
    }

    func fixture(_ name: String) throws -> URL {
        try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: nil, subdirectory: "Fixtures"))
    }

    /// Puts a fixture's Mac in this test's folder, pointed at a copy of its bucket (copied once,
    /// so several Macs can share it), with its links in place as they were on that Mac.
    func install(_ source: URL, as name: String = "mac") throws -> Mac {
        if try FileManager.default.contentsOfDirectory(atPath: bucket.path).isEmpty {
            for item in try FileManager.default.contentsOfDirectory(atPath: source.appendingPathComponent("bucket").path) {
                try FileManager.default.copyItem(at: source.appendingPathComponent("bucket/\(item)"),
                                                 to: bucket.appendingPathComponent(item))
            }
        }
        let state = Mac.paths(root, name).state
        try FileManager.default.createDirectory(at: state.deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: source.appendingPathComponent("mac/state"), to: state)
        let m = mac(name)

        // The fixture's Mac used its own bucket folder; this one uses the copy.
        let keys = try JSONFile.load(LocalKeys.self, from: m.paths.keyringFile)
        let local = try keys.local.open(password: fixturePassword)
        var settings = try LocalUpgrade.object(XCTUnwrap(SealedFile.state.read(m.paths, key: local)))
        var storage = try XCTUnwrap(settings["storage"] as? [String: Any])
        storage["path"] = bucket.path
        settings["storage"] = storage
        try SealedFile.state.write(LocalUpgrade.data(settings), m.paths, key: local)

        let link = m.home(".ssh/id_fixture")
        try FileManager.default.createDirectory(at: link.deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: m.paths.mount.appendingPathComponent("synced/ssh/id_fixture"))
        return m
    }

    var vaultFormat: Int? {
        let record = try? LocalUpgrade.object(Data(contentsOf: bucket.appendingPathComponent(VaultKeys.keyringKey)))
        return record?["version"] as? Int
    }

    /// The content file ids of every file object in the bucket.
    func contentFileIDs() throws -> Set<String> {
        var ids: Set<String> = []
        for name in try FileManager.default.contentsOfDirectory(atPath: bucket.appendingPathComponent("f").path) {
            let data = try Data(contentsOf: bucket.appendingPathComponent("f/\(name)"))
            let start = Int(ObjectFormat.contentOffset)
            if data.count > start, let id = EncFormat.fileID(fromHeader: data.subdata(in: start..<data.count)) {
                ids.insert(id.hex)
            }
        }
        return ids
    }

    /// What this Mac has its own copy of.
    func assertLocalCopies(_ m: Mac, file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertEqual(try m.text("synced/ssh/id_fixture"), "FIXTURE PRIVATE KEY\n", file: file, line: line)
        XCTAssertEqual(try m.read("synced/big.bin"), bytes(140_000, seed: 1), file: file, line: line)
        XCTAssertEqual(try m.text("synced/pending.txt"), "not uploaded yet", file: file, line: line)
        XCTAssertEqual(try m.text("local/only-here.txt"), "this Mac only\n", file: file, line: line)
    }

    func assertFixtureContents(_ m: Mac, file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertEqual(try m.text("synced/ssh/id_fixture"), "FIXTURE PRIVATE KEY\n", file: file, line: line)
        XCTAssertEqual(try m.text("synced/docs/note.txt"), "a note\n", file: file, line: line)
        XCTAssertEqual(try m.read("synced/big.bin"), bytes(140_000, seed: 1), file: file, line: line)
        XCTAssertEqual(try m.text("synced/rotated.txt"), "token-version-2", file: file, line: line)
        XCTAssertEqual(try m.text("synced/pending.txt"), "not uploaded yet", file: file, line: line)
        XCTAssertEqual(try m.read("remote/archive.bin"), bytes(70_000, seed: 2), file: file, line: line)
        XCTAssertEqual(try m.names("synced"), ["big.bin", "docs", "pending.txt", "rotated.txt", "ssh"], file: file, line: line)
    }

    func testTheCurrentFormatNeedsNoUpgrade() throws {
        let made = root.appendingPathComponent("fixture")
        try writeFixture(to: made)
        let m = try install(made)
        let before = try FolderStorage(root: bucket).list(prefix: "f/").map(\.version)
        try m.engine.unlock(password: fixturePassword)
        m.sync()
        XCTAssertNil(m.engine.status().problem)
        XCTAssertEqual(try Migrations.localFormat(m.paths), Migrations.current)
        XCTAssertEqual(vaultFormat, Migrations.current)
        try assertFixtureContents(m)
        let objects = try FolderStorage(root: bucket).list(prefix: "f/")
        XCTAssertEqual(objects.count, before.count + 1, "only the waiting file went up")
    }

    func testFormat2Upgrades() throws {
        let m = try install(fixture("format2"))
        XCTAssertEqual(try Migrations.localFormat(m.paths), 2)
        XCTAssertEqual(vaultFormat, 2)
        let oldIDs = try contentFileIDs()

        try m.engine.unlock(password: fixturePassword)
        XCTAssertEqual(try Migrations.localFormat(m.paths), Migrations.current, "this Mac's files upgrade on unlock")
        guard case .chip = try JSONFile.load(KeyringFile.self, from: m.paths.keyringFile) else {
            return XCTFail("the keyring is sealed by the security chip on unlock")
        }
        XCTAssertEqual(try m.text("local/only-here.txt"), "this Mac only\n")
        m.sync()
        XCTAssertNil(m.engine.status().problem)
        XCTAssertEqual(vaultFormat, Migrations.current, "the vault upgrades in the first pass")
        try assertFixtureContents(m)
        XCTAssertEqual(m.engine.status().waiting, 0, "what was waiting went up")
        m.engine.reconcile()
        let status = m.engine.status()
        XCTAssertEqual(status.profile, "work")
        XCTAssertEqual(status.links.map(\.path), ["~/.ssh/id_fixture"])
        XCTAssertEqual(status.links.map(\.state), ["ok"])

        // Every file object is sealed again: a fresh file id that its header names.
        let newIDs = try contentFileIDs()
        XCTAssertTrue(newIDs.isDisjoint(with: oldIDs), "no file id from format 2 is left")
        for name in try FileManager.default.contentsOfDirectory(atPath: bucket.appendingPathComponent("f").path) {
            XCTAssertNoThrow(try ObjectFormat.verifiedHeader(of: bucket.appendingPathComponent("f/\(name)"),
                                                             keys: m.store.keys, objectKey: "f/\(name)"))
        }

        // A Mac that joins now sees all of it.
        let b = mac("b")
        _ = try b.engine.setup(storage, nil, password: fixturePassword, deviceName: "b", create: false)
        b.sync()
        try assertFixtureContents(b)
        XCTAssertEqual(try b.names("local"), [])
    }

    func testFormat3Upgrades() throws {
        let m = try install(fixture("format3"))
        XCTAssertEqual(try Migrations.localFormat(m.paths), 3)
        XCTAssertEqual(vaultFormat, 3)
        func copies(_ dir: URL) throws -> Int { try FileManager.default.contentsOfDirectory(atPath: dir.path).count }
        XCTAssertEqual(try copies(m.paths.objectStore), 6)
        XCTAssertEqual(try copies(m.paths.localStore), 2)

        try m.engine.unlock(password: fixturePassword)
        XCTAssertEqual(try Migrations.localFormat(m.paths), Migrations.current, "this Mac's files upgrade on unlock")
        XCTAssertTrue(FileManager.default.fileExists(atPath: m.paths.journalFile.path), "the index has its journal")
        try assertLocalCopies(m)
        XCTAssertEqual(try m.names("synced/docs"), ["note.txt"], "the ._ files macOS added are gone")
        XCTAssertEqual(try m.names("local"), ["only-here.txt"])
        XCTAssertEqual(try copies(m.paths.objectStore), 5, "and so is their content")
        XCTAssertEqual(try copies(m.paths.localStore), 1)
        XCTAssertEqual(m.engine.status().waiting, 1, "what was waiting to upload still is")

        m.sync()
        XCTAssertNil(m.engine.status().problem)
        XCTAssertEqual(vaultFormat, Migrations.current, "the vault upgrades in the first pass")
        try assertFixtureContents(m)
        XCTAssertEqual(m.engine.status().waiting, 0)
        m.engine.reconcile()
        XCTAssertEqual(m.engine.status().links.map(\.state), ["ok"])

        // Changes from here go to the journal, and are there after a lock.
        try m.write("synced/docs/new.txt", Data("after the upgrade".utf8))
        try m.remove("local/only-here.txt")
        m.engine.lockNow("test")
        try m.engine.unlock(password: fixturePassword)
        XCTAssertEqual(try m.text("synced/docs/new.txt"), "after the upgrade")
        XCTAssertEqual(try m.names("local"), [])
        try assertFixtureContents(m)

        // A Mac that joins now sees all of it.
        m.sync()
        let b = mac("b")
        _ = try b.engine.setup(storage, nil, password: fixturePassword, deviceName: "b", create: false)
        b.sync()
        try assertFixtureContents(b)
        XCTAssertEqual(try b.names("synced/docs"), ["new.txt", "note.txt"])
    }

    /// The upgrade stopped after the index was converted, before the format number went up:
    /// the step runs again on what it already converted.
    func testTheFormat4StepIsSafeToRepeat() throws {
        let m = try install(fixture("format3"))
        try m.engine.unlock(password: fixturePassword)
        m.engine.lockNow("test")
        try Migrations.setLocalFormat(3, m.paths)
        try FileManager.default.removeItem(at: m.paths.journalFile)

        try m.engine.unlock(password: fixturePassword)
        XCTAssertEqual(try Migrations.localFormat(m.paths), Migrations.current)
        try assertLocalCopies(m)
        XCTAssertEqual(try m.names("synced/docs"), ["note.txt"])
        m.sync()
        XCTAssertNil(m.engine.status().problem)
        try assertFixtureContents(m)
    }

    func testAnInterruptedUpgradeCarriesOn() throws {
        let m = try install(fixture("format2"))
        try offline {
            try m.engine.unlock(password: fixturePassword)
            m.sync()
        }
        XCTAssertEqual(try Migrations.localFormat(m.paths), Migrations.current)
        XCTAssertEqual(vaultFormat, 2, "offline, the vault waits")
        try assertLocalCopies(m)

        let objects = bucket.appendingPathComponent("f")
        chmod(objects.path, 0o500)
        m.sync()
        chmod(objects.path, 0o700)
        XCTAssertNotNil(m.engine.status().problem)
        XCTAssertEqual(vaultFormat, 2, "a failed upgrade leaves the vault as it was")
        try assertLocalCopies(m) // nothing syncs with a vault that isn't upgraded yet

        m.sync()
        XCTAssertNil(m.engine.status().problem)
        XCTAssertEqual(vaultFormat, Migrations.current)
        try assertFixtureContents(m)
    }

    func testAnotherOldMacUpgradesOnlyItsOwnFiles() throws {
        let first = try install(fixture("format2"), as: "first")
        try first.engine.unlock(password: fixturePassword)
        first.sync()
        XCTAssertEqual(vaultFormat, Migrations.current)
        let keyring = try FolderStorage(root: bucket).list(prefix: "m/keyring").first?.version
        let ids = try contentFileIDs()

        let second = try install(fixture("format2"), as: "second")
        try second.engine.unlock(password: fixturePassword)
        second.sync()
        XCTAssertNil(second.engine.status().problem)
        XCTAssertEqual(try Migrations.localFormat(second.paths), Migrations.current)
        try assertFixtureContents(second)
        XCTAssertEqual(try FolderStorage(root: bucket).list(prefix: "m/keyring").first?.version, keyring,
                       "the vault is upgraded once")
        XCTAssertLessThanOrEqual(ids.subtracting(try contentFileIDs()).count, 1,
                                 "nothing is sealed again but the file this Mac had waiting")
    }

    func testNewerFormatsAreRefused() throws {
        let (a, b) = try twoMacs()
        try a.write("synced/x", Data("x".utf8))
        a.sync()

        // This Mac's own files from a newer Shrug.
        a.engine.lockNow("test")
        try Migrations.setLocalFormat(Migrations.current + 1, a.paths)
        XCTAssertThrowsError(try a.engine.unlock(password: password)) { error in
            XCTAssertTrue("\(error)".contains("newer Shrug"), "\(error)")
        }

        // A vault from a newer Shrug: nothing is read or written.
        let keyring = bucket.appendingPathComponent(VaultKeys.keyringKey)
        var record = try LocalUpgrade.object(Data(contentsOf: keyring))
        record["version"] = Migrations.current + 1
        try tamper(keyring, LocalUpgrade.data(record))
        try b.write("synced/y", Data("y".utf8))
        b.sync()
        XCTAssertTrue(b.engine.status().problem?.contains("newer Shrug") == true)
        XCTAssertEqual(b.engine.status().waiting, 1)
        XCTAssertEqual(try b.names("synced"), ["y"], "nothing was taken from it either")

        let c = mac("c")
        XCTAssertThrowsError(try c.engine.setup(storage, nil, password: password, deviceName: "c", create: false))
    }

    func testStepsCountUpOneFormatAtATime() {
        XCTAssertEqual(Migrations.steps.map(\.format), Array((Migrations.oldest + 1)...Migrations.current))
    }
}
