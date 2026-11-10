import CryptoKit
import Foundation
import ShrugCore

/// The two files this Mac keeps sealed with its local key: its settings and its index of ~/Shrug.
enum SealedFile {
    case state, index

    private var label: String { self == .state ? "shrug-state-v1" : "shrug-index-v1" }

    func url(_ paths: ShrugPaths) -> URL { self == .state ? paths.stateFile : paths.indexFile }

    /// The plain contents, or nil if the file doesn't exist yet.
    func read(_ paths: ShrugPaths, key: SymmetricKey) throws -> Data? {
        let url = url(paths)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        guard let sealed = try? Data(contentsOf: url),
              let plain = try? ShrugCrypto.open(sealed, key: ShrugCrypto.subkey(key, label), aad: Data(label.utf8))
        else { throw ShrugError(self == .state ? "Can't open this Mac's Shrug settings" : "Can't decrypt this Mac's index of ~/Shrug") }
        return plain
    }

    func write(_ plain: Data, _ paths: ShrugPaths, key: SymmetricKey) throws {
        let sealed = try ShrugCrypto.seal(plain, key: ShrugCrypto.subkey(key, label), aad: Data(label.utf8))
        try JSONFile.writeAtomically(sealed, to: url(paths))
    }
}
