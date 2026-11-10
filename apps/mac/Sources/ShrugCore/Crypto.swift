import CommonCrypto
import CryptoKit
import Foundation
import Security

public struct ShrugError: Error, CustomStringConvertible {
    public let description: String
    public init(_ description: String) { self.description = description }
}

public enum ShrugCrypto {
    public static func random(_ count: Int) -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        precondition(status == errSecSuccess, "No randomness available")
        return data
    }

    /// PBKDF2-HMAC-SHA256. The keyring records the algorithm so it can be upgraded later.
    public static func pbkdf2(_ password: String, salt: Data, iterations: Int) -> SymmetricKey {
        var out = Data(count: 32)
        let status: Int32 = out.withUnsafeMutableBytes { outPtr in
            salt.withUnsafeBytes { saltPtr in
                password.withCString { pw in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        pw, password.utf8.count,
                        saltPtr.bindMemory(to: UInt8.self).baseAddress!, salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(iterations),
                        outPtr.bindMemory(to: UInt8.self).baseAddress!, 32)
                }
            }
        }
        precondition(status == kCCSuccess, "PBKDF2 failed")
        return SymmetricKey(data: out)
    }

    /// The most iterations a keyring may ask for. Far above what a second buys today (about
    /// 3 million on an M2), and every keyring Shrug makes stays under it.
    public static let maxIterations = 100_000_000

    /// Enough iterations for roughly one second on this machine, never fewer than 600k.
    public static func calibratedIterations() -> Int {
        #if DEBUG
        // Tests only. Release builds ignore it, so a stray variable can't weaken a real vault.
        if let forced = ProcessInfo.processInfo.environment["SHRUG_TEST_KDF_ITERATIONS"], let n = Int(forced) {
            return n
        }
        #endif
        let rounds = CCCalibratePBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2), 32, 16, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 32, 1000)
        return min(max(Int(rounds), 600_000), maxIterations)
    }

    /// AES-256-GCM, returns nonce | ciphertext | tag.
    public static func seal(_ plain: Data, key: SymmetricKey, aad: Data) throws -> Data {
        try AES.GCM.seal(plain, using: key, authenticating: aad).combined!
    }

    public static func open(_ combined: Data, key: SymmetricKey, aad: Data) throws -> Data {
        Data(try AES.GCM.open(AES.GCM.SealedBox(combined: combined), using: key, authenticating: aad))
    }
}

extension SymmetricKey {
    public var rawData: Data { withUnsafeBytes { Data($0) } }
}

extension Data {
    var b64: String { base64EncodedString() }
}

/// A random 256-bit key, wrapped by a key derived from the Shrug password.
public struct Keyring: Codable, Equatable, Sendable {
    public var kdf: String
    public var iterations: Int
    public var salt: String
    public var wrappedKey: String

    static let aad = Data("shrug-keyring-v1".utf8)

    /// A fresh random key wrapped with a fresh salt.
    public static func create(password: String) throws -> (Keyring, SymmetricKey) {
        let salt = ShrugCrypto.random(16)
        let iterations = ShrugCrypto.calibratedIterations()
        let kek = ShrugCrypto.pbkdf2(password, salt: salt, iterations: iterations)
        let key = SymmetricKey(size: .bits256)
        return (try wrap(key, salt: salt, iterations: iterations, kek: kek), key)
    }

    /// Wrap `key` with an already-derived password key (lets two keyrings share one slow derivation).
    public static func wrap(_ key: SymmetricKey, salt: Data, iterations: Int, kek: SymmetricKey) throws -> Keyring {
        let wrapped = try ShrugCrypto.seal(key.rawData, key: kek, aad: aad)
        return Keyring(kdf: "pbkdf2-sha256", iterations: iterations, salt: salt.b64, wrappedKey: wrapped.b64)
    }

    public var saltData: Data { Data(base64Encoded: salt) ?? Data() }

    /// A keyring from the bucket is checked before any work is done for it: an odd one could
    /// otherwise crash the derivation or keep it busy for hours.
    func validate() throws {
        guard kdf == "pbkdf2-sha256" else { throw ShrugError("Unknown key derivation '\(kdf)'") }
        guard (1...ShrugCrypto.maxIterations).contains(iterations) else {
            throw ShrugError("The keyring asks for \(iterations) iterations, which Shrug never makes: it's damaged")
        }
        guard saltData.count == 16, Data(base64Encoded: wrappedKey) != nil else {
            throw ShrugError("The keyring is damaged")
        }
    }

    public func open(password: String, cache: KEKCache? = nil) throws -> SymmetricKey {
        try validate()
        let kek = cache?.derive(password, salt: saltData, iterations: iterations)
            ?? ShrugCrypto.pbkdf2(password, salt: saltData, iterations: iterations)
        guard let wrapped = Data(base64Encoded: wrappedKey),
              let raw = try? ShrugCrypto.open(wrapped, key: kek, aad: Keyring.aad)
        else { throw ShrugError("Wrong password") }
        return SymmetricKey(data: raw)
    }
}

/// Remembers password-derived keys during one unlock so the slow KDF runs once per salt.
public final class KEKCache {
    private var keys: [String: SymmetricKey] = [:]
    public init() {}

    public func derive(_ password: String, salt: Data, iterations: Int) -> SymmetricKey {
        let id = "\(salt.b64):\(iterations)"
        if let k = keys[id] { return k }
        let k = ShrugCrypto.pbkdf2(password, salt: salt, iterations: iterations)
        keys[id] = k
        return k
    }
}

extension ShrugCrypto {
    /// A key for one purpose, derived from a master key.
    public static func subkey(_ master: SymmetricKey, _ purpose: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: master, info: Data(purpose.utf8), outputByteCount: 32)
    }

    /// Keyed hash of `text` as hex, for names that must look random but be the same on every Mac.
    public static func hmacHex(_ key: SymmetricKey, _ text: String, bytes: Int = 16) -> String {
        Data(HMAC<SHA256>.authenticationCode(for: Data(text.utf8), using: key)).prefix(bytes).hex
    }

    public static func randomHex(_ bytes: Int = 16) -> String { random(bytes).hex }
}

extension Data {
    public var hex: String { map { String(format: "%02x", $0) }.joined() }

    public init?(hex: String) {
        guard hex.count % 2 == 0 else { return nil }
        var out = Data(capacity: hex.count / 2)
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            guard let byte = UInt8(hex[i..<j], radix: 16) else { return nil }
            out.append(byte)
            i = j
        }
        self = out
    }
}
