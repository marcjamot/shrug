import CryptoKit
import Foundation
import ShrugCore

extension Engine {
    /// Checks the storage and credentials. True if the bucket already holds a vault.
    func probe(_ config: StorageConfig, _ credentials: Credentials?) throws -> Bool {
        guard !paths.isSetUp else { throw ShrugError("This Mac is already set up") }
        let storage = try Storage.make(config, credentials)
        do {
            _ = try storage.get(VaultKeys.keyringKey, range: nil)
            return true
        } catch StorageError.notFound {
            _ = try storage.list(prefix: "m/") // proves the key can read the bucket at all
            return false
        }
    }

    /// Creates the vault (first Mac) or joins it with the Shrug password, then unlocks.
    /// Returns the profiles in the bucket.
    func setup(_ config: StorageConfig, _ credentials: Credentials?, password: String, deviceName: String,
               create: Bool) throws -> [String] {
        guard !paths.isSetUp else { throw ShrugError("This Mac is already set up") }
        guard !deviceName.isEmpty else { throw ShrugError("Give this Mac a name") }
        let storage = try Storage.make(config, credentials)
        let cache = KEKCache()
        let vaultRing: Keyring
        let master: SymmetricKey
        if create {
            guard password.count >= 12 else { throw ShrugError("Use a passphrase of at least 12 characters") }
            if (try? storage.get(VaultKeys.keyringKey, range: nil)) != nil {
                throw ShrugError("This storage already has a vault: run setup again to join it")
            }
            (vaultRing, master) = try Keyring.create(password: password)
            _ = try storage.put(VaultKeys.keyringKey, data: JSONFile.encode(VaultRecord(keyring: vaultRing)))
        } else {
            let record = try JSONFile.decode(VaultRecord.self, from: storage.get(VaultKeys.keyringKey, range: nil))
            master = try record.keyring.open(password: password, cache: cache)
            vaultRing = record.keyring
        }
        // This Mac's own key, wrapped with the same password (and the same slow derivation).
        let local = SymmetricKey(size: .bits256)
        let kek = cache.derive(password, salt: vaultRing.saltData, iterations: vaultRing.iterations)
        let localRing = try Keyring.wrap(local, salt: vaultRing.saltData, iterations: vaultRing.iterations, kek: kek)
        let state = LocalState(deviceID: ShrugCrypto.randomHex(8), deviceName: deviceName, storage: config,
                               credentials: credentials)
        try Engine.writeState(state, to: paths.stateFile, key: local)
        try JSONFile.save(LocalKeys(vault: vaultRing, local: localRing), to: paths.keyringFile)
        do { try touchID.enroll(secret: master.rawData + local.rawData) } catch { log("Touch ID enroll: \(error)") }
        try opened(master, local)
        if let login = LoginItem.enable() { event(login) }
        guard let s = session() else { return [] }
        let names = (try? replicator.profileNames(s)) ?? []
        updateState { $0.profileNames = names }
        return names
    }
}
