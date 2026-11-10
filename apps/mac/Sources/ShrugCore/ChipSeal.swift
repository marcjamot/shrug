import CryptoKit
import Foundation
import Security

/// Data sealed by one Mac's security chip (see `ChipSeal`).
public struct ChipSealed: Codable, Equatable, Sendable {
    /// The chip's private key, in a form only the chip that made it can use.
    public var key: String
    public var ephemeral: String
    public var sealed: String

    public init(key: String, ephemeral: String, sealed: String) {
        self.key = key
        self.ephemeral = ephemeral
        self.sealed = sealed
    }
}

/// Seals data so that only this Mac's security chip can open it again, with no prompt.
/// ~/.shrug/keyring.json is sealed this way on top of the Shrug password, so a copy of it
/// taken off this Mac (a stolen disk, a backup) is no use for guessing the password elsewhere.
public protocol ChipSeal {
    var isAvailable: Bool { get }
    func seal(_ data: Data) throws -> ChipSealed
    /// Throws if this Mac's chip didn't seal it (it came from another Mac, or the chip was reset).
    func open(_ sealed: ChipSealed) throws -> Data
}

/// The Secure Enclave: its key never leaves the chip, so what it seals opens only on this Mac.
public struct SecureEnclaveSeal: ChipSeal {
    static let info = Data("shrug-keyring-chip-v1".utf8)

    public init() {}

    public var isAvailable: Bool { SecureEnclave.isAvailable }

    public func seal(_ data: Data) throws -> ChipSealed {
        var error: Unmanaged<CFError>?
        // No fingerprint or password: the Shrug password is still needed inside. After first
        // unlock, not when unlocked: unlocking over SSH while the screen is locked must work.
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &error)
        else { throw ShrugError("Cannot create the security chip's access control") }
        let chipKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let kek = try SecureEnclaveSeal.kek(ephemeral.sharedSecretFromKeyAgreement(with: chipKey.publicKey))
        return ChipSealed(
            key: chipKey.dataRepresentation.base64EncodedString(),
            ephemeral: ephemeral.publicKey.rawRepresentation.base64EncodedString(),
            sealed: try ShrugCrypto.seal(data, key: kek, aad: SecureEnclaveSeal.info).base64EncodedString())
    }

    public func open(_ s: ChipSealed) throws -> Data {
        guard let keyData = Data(base64Encoded: s.key), let ephData = Data(base64Encoded: s.ephemeral),
              let sealed = Data(base64Encoded: s.sealed)
        else { throw ShrugError("The security chip's seal is damaged") }
        do {
            let chipKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyData)
            let shared = try chipKey.sharedSecretFromKeyAgreement(
                with: P256.KeyAgreement.PublicKey(rawRepresentation: ephData))
            return try ShrugCrypto.open(sealed, key: SecureEnclaveSeal.kek(shared), aad: SecureEnclaveSeal.info)
        } catch {
            throw ShrugError("This Mac's security chip can't open it")
        }
    }

    static func kek(_ shared: SharedSecret) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: info, outputByteCount: 32)
    }
}
