import CryptoKit
import XCTest
@testable import ShrugCore
@testable import ShrugDaemon

/// Stands in for one Mac's security chip: only it opens what it sealed.
final class FakeChip: ChipSeal, @unchecked Sendable {
    private let key = SymmetricKey(size: .bits256)
    var isAvailable: Bool

    init(available: Bool = true) { isAvailable = available }

    func seal(_ data: Data) throws -> ChipSealed {
        ChipSealed(key: "", ephemeral: "", sealed: try ShrugCrypto.seal(data, key: key, aad: Data()).base64EncodedString())
    }

    func open(_ s: ChipSealed) throws -> Data {
        guard let sealed = Data(base64Encoded: s.sealed), let plain = try? ShrugCrypto.open(sealed, key: key, aad: Data())
        else { throw ShrugError("This Mac's security chip can't open it") }
        return plain
    }
}

/// ~/.shrug/keyring.json is sealed by the Mac's security chip on top of the Shrug password,
/// so a copy of it is no use for guessing the password anywhere else.
final class KeyringTests: ShrugTestCase {
    func testTheKeyringOpensOnlyOnTheMacThatMadeIt() throws {
        let a = mac("a")
        _ = try a.engine.setup(storage, nil, password: password, deviceName: "a", create: true)
        let file = try Data(contentsOf: a.paths.keyringFile)
        guard case .chip = try JSONFile.decode(KeyringFile.self, from: file) else { return XCTFail("not sealed") }
        XCTAssertFalse(String(decoding: file, as: UTF8.self).contains("wrappedKey"), "nothing to guess the password against")

        // This Mac's ~/.shrug on another Mac: a backup restored there, or a copied disk.
        let other = Mac.paths(root, "other")
        try FileManager.default.createDirectory(at: other.home, withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: a.paths.state, to: other.state)
        let b = mac("other")
        XCTAssertThrowsError(try b.engine.unlock(password: password)) {
            XCTAssertTrue("\($0)".contains("run ./setup"), "says what to do: \($0)")
        }
        XCTAssertFalse(b.engine.isUnlocked)

        // Here, it still takes the password.
        a.engine.lockNow("test")
        XCTAssertThrowsError(try a.engine.unlock(password: "not the password"))
        try a.engine.unlock(password: password)
        XCTAssertTrue(a.engine.isUnlocked)
    }

    func testAKeyringFromBeforeTheChipIsSealedAtTheNextUnlock() throws {
        let chip = FakeChip(available: false) // as an older Shrug left it
        let touch = FakeTouchID()
        let a = mac("a", touchID: touch, chip: chip)
        _ = try a.engine.setup(storage, nil, password: password, deviceName: "a", create: true)
        guard case .plain = try JSONFile.load(KeyringFile.self, from: a.paths.keyringFile) else { return XCTFail() }
        a.engine.lockNow("test")

        // A fingerprint unlock is enough: sealing doesn't need the password.
        chip.isAvailable = true
        try a.engine.unlock(password: nil)
        XCTAssertTrue(a.engine.isUnlocked)
        guard case .chip = try JSONFile.load(KeyringFile.self, from: a.paths.keyringFile) else { return XCTFail("not sealed") }

        a.engine.lockNow("test")
        try a.engine.unlock(password: password)
        XCTAssertTrue(a.engine.isUnlocked, "the sealed keyring opens with the password")
    }

    func testWithoutAChipThePasswordAloneProtectsTheKeyring() throws {
        let a = mac("a", chip: FakeChip(available: false))
        _ = try a.engine.setup(storage, nil, password: password, deviceName: "a", create: true)
        a.engine.lockNow("test")
        try a.engine.unlock(password: password)
        XCTAssertTrue(a.engine.isUnlocked)
        guard case .plain = try JSONFile.load(KeyringFile.self, from: a.paths.keyringFile) else { return XCTFail() }
    }
}
