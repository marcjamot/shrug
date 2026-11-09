import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Keeps a copy of the vault keys that only this Mac's Secure Enclave can open,
/// and only after Touch ID or the Mac password. Without the file, only the full
/// Shrug password works.
public struct TouchIDStore {
    struct Blob: Codable {
        var seKey: String
        var ephemeral: String
        var sealed: String
        var created: Date
    }

    public let url: URL
    static let info = Data("shrug-touchid-v1".utf8)

    public init(url: URL) { self.url = url }

    public static var available: Bool {
        SecureEnclave.isAvailable && ProcessInfo.processInfo.environment["SHRUG_NO_TOUCHID"] == nil
    }

    public var isEnrolled: Bool {
        TouchIDStore.available && FileManager.default.fileExists(atPath: url.path)
    }

    public func enroll(secret: Data) throws {
        guard TouchIDStore.available else { return }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], &error)
        else { throw ShrugError("Cannot create Touch ID access control") }
        let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: seKey.publicKey)
        let kek = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: Data(), sharedInfo: TouchIDStore.info, outputByteCount: 32)
        let sealed = try ShrugCrypto.seal(secret, key: kek, aad: TouchIDStore.info)
        let blob = Blob(
            seKey: seKey.dataRepresentation.base64EncodedString(),
            ephemeral: ephemeral.publicKey.rawRepresentation.base64EncodedString(),
            sealed: sealed.base64EncodedString(),
            created: Date())
        try JSONFile.save(blob, to: url)
    }

    /// Shows the system Touch ID / password prompt with `reason` ("Shrug is trying to <reason>").
    /// Blocks until answered, or cancels the prompt after `timeout` seconds.
    public func unlock(reason: String, timeout: TimeInterval = 60) throws -> Data {
        guard TouchIDStore.available else { throw ShrugError("Touch ID is not available") }
        let blob = try JSONFile.load(Blob.self, from: url)
        guard let seData = Data(base64Encoded: blob.seKey),
              let ephData = Data(base64Encoded: blob.ephemeral),
              let sealed = Data(base64Encoded: blob.sealed)
        else { throw ShrugError("Touch ID data is damaged") }
        let context = LAContext()
        context.localizedReason = reason
        let done = DispatchSemaphore(value: 0)
        var result: Result<Data, Error> = .failure(ShrugError("Touch ID was cancelled"))
        DispatchQueue.global(qos: .userInitiated).async {
            result = Result {
                let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                    dataRepresentation: seData, authenticationContext: context)
                let shared = try seKey.sharedSecretFromKeyAgreement(
                    with: P256.KeyAgreement.PublicKey(rawRepresentation: ephData))
                let kek = shared.hkdfDerivedSymmetricKey(
                    using: SHA256.self, salt: Data(), sharedInfo: TouchIDStore.info, outputByteCount: 32)
                return try ShrugCrypto.open(sealed, key: kek, aad: TouchIDStore.info)
            }
            done.signal()
        }
        if done.wait(timeout: .now() + timeout) == .timedOut {
            context.invalidate()
            _ = done.wait(timeout: .now() + 5)
            throw ShrugError("Touch ID prompt timed out")
        }
        return try result.get()
    }

    public func remove() {
        try? FileManager.default.removeItem(at: url)
    }
}
