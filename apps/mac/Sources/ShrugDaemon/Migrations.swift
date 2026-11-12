import CryptoKit
import Darwin
import Foundation
import ShrugCore

/// Shrug's formats, and the steps that bring older ones up to date.
///
/// Two things have a format: this Mac's own files in ~/.shrug (its number is in
/// ~/.shrug/version) and the vault in the bucket (`version` in m/keyring). The rest of the code
/// only reads and writes the current format. Whatever an older Shrug left behind is converted
/// by these steps first: this Mac's files when it unlocks, the vault in the first pass that
/// reaches it. Steps run in order, and the number goes up right after each, so an interrupted
/// upgrade carries on where it stopped; a step that was interrupted runs again, so every step
/// must be safe to repeat. A format newer than this Shrug knows is refused.
///
/// Changing a format means: before touching the code, generate a fixture of the current format
/// with the current code; then add a step here, and a test that upgrades that fixture.
enum Migrations {
    struct Step {
        /// The format this step produces from the one before it.
        let format: Int
        let local: (LocalUpgrade) throws -> Void
        let vault: (VaultUpgrade) throws -> Void
    }

    /// The format of every Shrug before formats were numbered.
    static let oldest = 2

    static let steps: [Step] = [
        Step(format: 3, local: Format3.local, vault: Format3.vault),
        Step(format: 4, local: Format4.local, vault: Format4.vault),
    ]

    static var current: Int { steps.last?.format ?? oldest }

    private static let lock = NSLock()

    // MARK: - This Mac

    /// The format of this Mac's files. Installs from before the version file are the oldest format.
    static func localFormat(_ paths: ShrugPaths) throws -> Int {
        guard FileManager.default.fileExists(atPath: paths.versionFile.path) else { return oldest }
        guard let text = try? String(contentsOf: paths.versionFile, encoding: .utf8),
              let format = Int(text.trimmingCharacters(in: .whitespacesAndNewlines))
        else { throw ShrugError("~/.shrug/version is damaged") }
        return format
    }

    static func setLocalFormat(_ format: Int, _ paths: ShrugPaths) throws {
        try JSONFile.writeAtomically(Data("\(format)\n".utf8), to: paths.versionFile)
    }

    static func upgradeLocal(_ paths: ShrugPaths, keys: VaultKeys, localKey: SymmetricKey, log: (String) -> Void) throws {
        lock.lock()
        defer { lock.unlock() }
        let format = try localFormat(paths)
        guard format <= current else {
            throw ShrugError("This Mac's Shrug files come from a newer Shrug (format \(format)). Install the latest Shrug.")
        }
        let files = LocalUpgrade(paths: paths, keys: keys, localKey: localKey)
        for step in steps where step.format > format {
            try step.local(files)
            try setLocalFormat(step.format, paths)
            log("upgraded this Mac's files to format \(step.format)")
        }
    }

    // MARK: - The vault

    /// Brings the vault to the current format, given the listing of the bucket. Returns whether
    /// it changed anything, which makes that listing out of date.
    static func upgradeVault(_ storage: ObjectStorage, keys: VaultKeys, objects: [String: StoredObject],
                             scratch: URL, log: @escaping (String) -> Void) throws -> Bool {
        guard let keyring = objects[VaultKeys.keyringKey] else { throw ShrugError("The storage has no Shrug vault") }
        var record = try LocalUpgrade.object(storage.get(VaultKeys.keyringKey, version: keyring.version))
        guard let format = record["version"] as? Int else { throw ShrugError("The vault's keyring is damaged") }
        guard format <= current else {
            throw ShrugError("This vault was upgraded by a newer Shrug (format \(format)). Install the latest Shrug on this Mac.")
        }
        guard format < current else { return false }
        var version = keyring.version
        for step in steps where step.format > format {
            try step.vault(VaultUpgrade(storage: storage, keys: keys, scratch: scratch, log: log))
            record["version"] = step.format
            version = try storage.put(VaultKeys.keyringKey, data: LocalUpgrade.data(record), replacing: version)
            log("upgraded the vault to format \(step.format)")
        }
        return true
    }
}

/// This Mac's files during an upgrade, as plain JSON: the old layouts have no Swift types left.
struct LocalUpgrade {
    let paths: ShrugPaths
    let keys: VaultKeys
    let localKey: SymmetricKey

    func state() throws -> [String: Any] {
        guard let plain = try SealedFile.state.read(paths, key: localKey) else { throw ShrugError("This Mac's Shrug settings are missing") }
        return try LocalUpgrade.object(plain)
    }

    func writeState(_ state: [String: Any]) throws {
        try SealedFile.state.write(LocalUpgrade.data(state), paths, key: localKey)
    }

    /// Nil before anything was ever saved in ~/Shrug.
    func index() throws -> [String: Any]? {
        try SealedFile.index.read(paths, key: localKey).map(LocalUpgrade.object)
    }

    func writeIndex(_ index: [String: Any]) throws {
        try SealedFile.index.write(LocalUpgrade.data(index), paths, key: localKey)
    }

    static func object(_ data: Data) throws -> [String: Any] {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ShrugError("Not a JSON object")
        }
        return object
    }

    static func data(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
    }
}

/// The vault during an upgrade.
struct VaultUpgrade {
    let storage: ObjectStorage
    let keys: VaultKeys
    /// Where to keep downloads while working on them.
    let scratch: URL
    let log: (String) -> Void
}

/// Format 3: object versions are storage generations, which make writes conditional; delete
/// markers stay for good; every upload has its own file id.
enum Format3 {
    /// The old versions were ETags, which can't serve as generations. Without them every
    /// entry counts as not seen yet, and the next pass looks at each object once.
    static func local(_ files: LocalUpgrade) throws {
        var state = try files.state()
        state["profileETag"] = nil
        try files.writeState(state)
        guard var index = try files.index() else { return }
        index["version"] = nil
        if var entries = index["entries"] as? [String: [String: Any]] {
            for path in entries.keys { entries[path]?["etag"] = nil }
            index["entries"] = entries
        }
        try files.writeIndex(index)
    }

    /// The versions of a file shared one file id, so chunks of an older version still opened
    /// inside a newer one. Every file object is sealed again under a fresh id.
    static func vault(_ v: VaultUpgrade) throws {
        for obj in try v.storage.list(prefix: "f/") {
            let prefix = try v.storage.get(obj.key, range: 0...(ObjectFormat.contentOffset - 1), version: obj.version)
            guard let h = try? ObjectFormat.decodeHeader(prefix, keys: v.keys, objectKey: obj.key) else {
                v.log("skipped an object that doesn't open with this vault")
                continue
            }
            guard h.kind == .file else { continue }
            guard h.fitsSize(of: obj) else {
                v.log("skipped an object whose size doesn't match its header")
                continue
            }
            let old = v.scratch.appendingPathComponent(".tmp-\(UUID().uuidString)")
            let new = v.scratch.appendingPathComponent(".tmp-\(UUID().uuidString)")
            defer {
                unlink(old.path)
                unlink(new.path)
            }
            guard try v.storage.download(obj.key, to: old, version: obj.version) == obj.version else {
                throw StorageError.conflict
            }
            guard (try? ObjectFormat.verifiedHeader(of: old, keys: v.keys, objectKey: obj.key)) == h else {
                v.log("skipped an object that doesn't open with this vault")
                continue
            }
            let content = try EncryptedFile(url: old, master: v.keys.master, writable: false, base: ObjectFormat.contentOffset)
            let copy = try content.reencrypt(to: new, prefix: ObjectFormat.blankPrefix())
            var fresh = h
            fresh.fileID = copy.contentFileID?.hex
            try ObjectFormat.writeHeader(fresh, to: new, keys: v.keys, objectKey: obj.key)
            _ = try v.storage.upload(obj.key, from: new, replacing: obj.version)
        }
    }
}

/// Format 4: this Mac's index is written whole now and then, with a journal of the changes
/// since (see SavedIndex); the ._ files macOS adds are no longer saved; files can be larger
/// than 1 GiB.
enum Format4 {
    /// The index names its journal, and both start out together. The ._ files it listed go,
    /// with their content: a new one only lasts until Shrug locks (see `Store.isAppleDouble`).
    /// Any that reached the bucket stay: that never happened with Shrug's own uploads.
    static func local(_ files: LocalUpgrade) throws {
        guard var index = try files.index() else { return } // nothing saved yet: the store starts both
        var entries = index["entries"] as? [String: [String: Any]] ?? [:]
        for (path, e) in entries where Store.isAppleDouble(Store.name(path)) && e["version"] == nil {
            let kind = e["kind"] as? String
            guard kind == "file" || kind == "deleted" else { continue }
            if kind == "file" {
                let content = Store.fileClass(path) == .local
                    ? files.paths.localStore.appendingPathComponent(e["blob"] as? String ?? "missing")
                    : files.paths.objectStore.appendingPathComponent(String(files.keys.objectKey(path).dropFirst(2)))
                unlink(content.path)
            }
            entries[path] = nil
        }
        let journal = ShrugCrypto.random(16)
        index["entries"] = entries
        index["journal"] = journal.hex
        try files.writeIndex(index)
        try JSONFile.writeAtomically(SavedIndex.magic + journal, to: files.paths.journalFile)
    }

    /// Nothing to convert. The vault may hold files larger than 1 GiB from here on, which an
    /// older Shrug takes for damage: the new number has it ask for an update instead.
    static func vault(_ v: VaultUpgrade) throws {}
}
