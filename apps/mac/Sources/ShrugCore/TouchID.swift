import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Why Touch ID didn't hand over the keys.
public enum TouchIDError: Error, CustomStringConvertible {
    /// You chose "Use Shrug Password…", or Touch ID can't be used right now (no sensor in
    /// reach, too many failed tries): the Shrug password is the way in.
    case usePassword(String)
    /// This copy can never open again (the fingerprints changed since it was made, or it's
    /// damaged). The Shrug password makes a new one.
    case invalidated
    case cancelled
    case timedOut

    public var description: String {
        switch self {
        case .usePassword(let why): return "Touch ID can't unlock (\(why)): use the Shrug password"
        case .invalidated: return "Touch ID needs setting up again: use the Shrug password once"
        case .cancelled: return "Touch ID was cancelled"
        case .timedOut: return "Touch ID prompt timed out"
        }
    }
}

/// A copy of the vault keys that only a fingerprint can open.
public protocol TouchIDKeyStore {
    var isEnrolled: Bool { get }
    func enroll(secret: Data) throws
    /// Shows the Touch ID prompt with `reason` ("Shrug is trying to <reason>"). Blocks until
    /// answered, or cancels the prompt after `timeout` seconds. Throws a TouchIDError.
    func unlock(reason: String, timeout: TimeInterval) throws -> Data
    func remove()
}

/// Keeps a copy of the vault keys that only this Mac's Secure Enclave can open, and only
/// after a fingerprint enrolled when the copy was made. The Mac's own password never opens it:
/// without a fingerprint, only the full Shrug password works.
public struct TouchIDStore: TouchIDKeyStore {
    struct Blob: Codable {
        var seKey: String
        var ephemeral: String
        var sealed: String
        var created: Date
        /// Which rule guards the key (see `policy`). Copies from before it was recorded also
        /// opened with the Mac password, so they're never used.
        var policy: Int?
    }

    /// 2: the enrolled fingerprints only (biometryCurrentSet), no Mac password.
    static let policy = 2

    public let url: URL
    static let info = Data("shrug-touchid-v1".utf8)

    public init(url: URL) { self.url = url }

    public static var available: Bool {
        SecureEnclave.isAvailable && ProcessInfo.processInfo.environment["SHRUG_NO_TOUCHID"] == nil
    }

    /// Whether the file is a copy made under the current rule (it may still fail to open).
    public var hasCurrentCopy: Bool {
        (try? JSONFile.load(Blob.self, from: url))?.policy == TouchIDStore.policy
    }

    public var isEnrolled: Bool { TouchIDStore.available && hasCurrentCopy }

    public func enroll(secret: Data) throws {
        guard TouchIDStore.available else { return }
        var error: Unmanaged<CFError>?
        // biometryCurrentSet, not biometryAny: someone who knows the Mac password could add their
        // own finger in System Settings, and with biometryAny that finger would open the copy.
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &error)
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
            created: Date(),
            policy: TouchIDStore.policy)
        try JSONFile.save(blob, to: url)
    }

    public func unlock(reason: String, timeout: TimeInterval = 60) throws -> Data {
        guard TouchIDStore.available else { throw TouchIDError.usePassword("Touch ID is not available") }
        guard let blob = try? JSONFile.load(Blob.self, from: url), blob.policy == TouchIDStore.policy,
              let seData = Data(base64Encoded: blob.seKey),
              let ephData = Data(base64Encoded: blob.ephemeral),
              let sealed = Data(base64Encoded: blob.sealed)
        else { throw TouchIDError.invalidated }

        // Asking for the fingerprint first gives clear answers (fallback, cancel, lockout) and
        // offers the Shrug password instead of the Mac's. The Secure Enclave then accepts the
        // context that was just checked, without asking again.
        let context = LAContext()
        context.localizedFallbackTitle = "Use Shrug Password…"
        var unusable: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &unusable) else {
            throw TouchIDError.usePassword(unusable?.localizedDescription ?? "Touch ID can't be used right now")
        }
        let answer = Answer()
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { ok, error in
            answer.finish(ok ? nil : error ?? TouchIDError.cancelled)
        }
        guard let failure = answer.wait(timeout) else {
            context.invalidate()
            throw TouchIDError.timedOut
        }
        if let error = failure.error { throw TouchIDStore.classify(error) }
        do {
            let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: seData, authenticationContext: context)
            let shared = try seKey.sharedSecretFromKeyAgreement(
                with: P256.KeyAgreement.PublicKey(rawRepresentation: ephData))
            let kek = shared.hkdfDerivedSymmetricKey(
                using: SHA256.self, salt: Data(), sharedInfo: TouchIDStore.info, outputByteCount: 32)
            return try ShrugCrypto.open(sealed, key: kek, aad: TouchIDStore.info)
        } catch {
            // The fingerprint was fine, so the key itself is gone: the enrolled fingers changed.
            throw TouchIDError.invalidated
        }
    }

    static func classify(_ error: Error) -> TouchIDError {
        if let e = error as? TouchIDError { return e }
        guard let la = error as? LAError else { return .cancelled }
        switch la.code {
        case .userFallback: return .usePassword("you chose the Shrug password")
        case .authenticationFailed: return .usePassword("the fingerprint wasn't recognized")
        case .biometryLockout: return .usePassword("too many failed tries")
        case .biometryNotAvailable, .biometryNotEnrolled, .biometryNotPaired, .biometryDisconnected, .passcodeNotSet,
             .notInteractive:
            return .usePassword(la.localizedDescription)
        default: return .cancelled
        }
    }

    public func remove() {
        try? FileManager.default.removeItem(at: url)
    }
}

/// The answer from the Touch ID prompt, handed from its callback to the waiting thread.
private final class Answer: @unchecked Sendable {
    struct Failure { let error: Error? }
    private let lock = NSLock()
    private let done = DispatchSemaphore(value: 0)
    private var result: Failure?

    func finish(_ error: Error?) {
        lock.lock()
        result = Failure(error: error)
        lock.unlock()
        done.signal()
    }

    /// Nil on timeout; otherwise the error, if there was one.
    func wait(_ timeout: TimeInterval) -> Failure? {
        guard done.wait(timeout: .now() + timeout) == .success else { return nil }
        lock.lock()
        defer { lock.unlock() }
        return result
    }
}
