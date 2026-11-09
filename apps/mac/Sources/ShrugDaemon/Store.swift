import CryptoKit
import Darwin
import Foundation
import ShrugCore

public enum FileClass: String, CaseIterable, Codable, Sendable {
    /// This Mac only, never uploaded.
    case local
    /// Kept on this Mac and in the bucket.
    case synced
    /// Kept in the bucket; on this Mac only while being edited or waiting to upload.
    case remote
}

/// One file or folder in ~/Shrug.
struct Entry: Codable {
    var kind: ObjectKind
    var size: Int64 = 0
    var mtime: Date
    var editedAt: Date
    var mode: UInt16 = 0o600
    /// local/ only: the backing file's random name.
    var blob: String?
    /// Needs uploading (synced/ and remote/ only).
    var dirty = false
    /// Bumped on every local change, so an upload can tell whether it's still current.
    var gen = 0
    /// The last local change, for the short wait before uploading.
    var changedAt: Date?
    /// The bucket version this entry matches, or that it was uploaded as.
    var etag: String?
    /// remote/ only: the content is on this Mac.
    var cached = false

    init(kind: ObjectKind, now: Date = .nowMs) {
        self.kind = kind
        mtime = now
        editedAt = now
        if kind == .dir { mode = 0o700 }
    }
}

struct IndexFile: Codable {
    var version = 1
    var entries: [String: Entry] = [:]
}

/// What's in ~/Shrug on this Mac. Lives in memory only while unlocked; on disk it's
/// sealed with the local key, so a locked Mac doesn't even reveal file names.
/// Paths look like "synced/ssh/id_ed25519".
final class Store {
    let paths: ShrugPaths
    let keys: VaultKeys
    let localKey: SymmetricKey
    private let indexKey: SymmetricKey
    private let lock = NSRecursiveLock()
    private var entries: [String: Entry] = [:]
    private var byObjectKey: [String: String] = [:]
    private var needsSave = false
    private var fileLocks: [String: NSLock] = [:]
    private(set) var closed = false

    static let indexAAD = Data("shrug-index-v1".utf8)

    init(paths: ShrugPaths, keys: VaultKeys, localKey: SymmetricKey) throws {
        self.paths = paths
        self.keys = keys
        self.localKey = localKey
        indexKey = ShrugCrypto.subkey(localKey, "shrug-index-v1")
        for dir in [paths.objectStore, paths.localStore] {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        }
        if let sealed = try? Data(contentsOf: paths.indexFile) {
            guard let plain = try? ShrugCrypto.open(sealed, key: indexKey, aad: Store.indexAAD) else {
                throw ShrugError("Can't decrypt this Mac's index of ~/Shrug")
            }
            entries = try JSONFile.decode(IndexFile.self, from: plain).entries
        }
        for p in entries.keys where Store.fileClass(p) != .local { byObjectKey[keys.objectKey(p)] = p }
    }

    // MARK: - Saving

    func save() {
        lock.lock()
        let snapshot = IndexFile(entries: entries)
        needsSave = false
        lock.unlock()
        do {
            let sealed = try ShrugCrypto.seal(JSONFile.encode(snapshot), key: indexKey, aad: Store.indexAAD)
            try JSONFile.writeAtomically(sealed, to: paths.indexFile)
        } catch {
            lock.lock()
            needsSave = true
            lock.unlock()
        }
    }

    func saveIfNeeded() {
        lock.lock()
        let due = needsSave
        lock.unlock()
        if due { save() }
    }

    /// Saves and forgets everything: called on lock.
    func close() {
        save()
        lock.lock()
        entries = [:]
        byObjectKey = [:]
        closed = true
        lock.unlock()
    }

    private func touched() { needsSave = true }

    // MARK: - Paths

    static func fileClass(_ path: String) -> FileClass? {
        FileClass(rawValue: String(path.split(separator: "/", maxSplits: 1).first ?? ""))
    }

    static func parent(_ path: String) -> String {
        guard let slash = path.lastIndex(of: "/") else { return "" }
        return String(path[..<slash])
    }

    static func name(_ path: String) -> String {
        guard let slash = path.lastIndex(of: "/") else { return path }
        return String(path[path.index(after: slash)...])
    }

    /// Files apps make while saving, or Finder's own: kept on this Mac, never uploaded.
    static func isScratch(_ name: String) -> Bool {
        name == ".DS_Store" || name.hasPrefix("._") || name.hasPrefix(".sb-") || name.hasPrefix("~$")
            || name.hasPrefix(".~lock.") || name.hasSuffix(".swp") || name.hasSuffix(".swx") || name.hasPrefix(".#")
    }

    func objectKey(_ path: String) -> String { keys.objectKey(path) }

    func path(forObjectKey key: String) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return byObjectKey[key]
    }

    /// The local file holding an entry's content.
    func backingURL(_ path: String, _ entry: Entry) -> URL {
        if Store.fileClass(path) == .local { return paths.localStore.appendingPathComponent(entry.blob ?? "missing") }
        return paths.objectStore.appendingPathComponent(String(objectKey(path).dropFirst(2)))
    }

    func backingURL(_ path: String) -> URL? {
        guard let e = entry(path) else { return nil }
        return backingURL(path, e)
    }

    // MARK: - Queries

    /// The entry, unless it's a delete marker.
    func entry(_ path: String) -> Entry? {
        lock.lock()
        defer { lock.unlock() }
        guard let e = entries[path], e.kind != .deleted else { return nil }
        return e
    }

    func rawEntry(_ path: String) -> Entry? {
        lock.lock()
        defer { lock.unlock() }
        return entries[path]
    }

    func isDirectory(_ path: String) -> Bool {
        if FileClass(rawValue: path) != nil { return true }
        lock.lock()
        defer { lock.unlock() }
        if let e = entries[path] { return e.kind == .dir }
        let prefix = path + "/"
        return entries.contains { $0.key.hasPrefix(prefix) && $0.value.kind != .deleted }
    }

    func exists(_ path: String) -> Bool { entry(path) != nil || isDirectory(path) }

    /// Names directly inside a folder, including folders that only exist because of what's in them.
    func children(_ dir: String) -> [String] {
        let prefix = dir + "/"
        lock.lock()
        defer { lock.unlock() }
        var names = Set<String>()
        for (p, e) in entries where e.kind != .deleted && p.hasPrefix(prefix) {
            let rest = p.dropFirst(prefix.count)
            names.insert(String(rest.split(separator: "/", maxSplits: 1).first ?? Substring(rest)))
        }
        return names.sorted()
    }

    func all() -> [(String, Entry)] {
        lock.lock()
        defer { lock.unlock() }
        return entries.map { ($0.key, $0.value) }
    }

    /// Changes waiting for the bucket.
    func pending() -> [(String, Entry)] {
        all().filter { $0.1.dirty }.sorted { $0.0 < $1.0 }
    }

    var waitingCount: Int {
        pending().filter { !Store.isScratch(Store.name($0.0)) }.count
    }

    // MARK: - Changing entries

    func update(_ path: String, _ body: (inout Entry) -> Void) {
        lock.lock()
        defer { lock.unlock() }
        guard var e = entries[path] else { return }
        body(&e)
        entries[path] = e
        touched()
    }

    func set(_ path: String, _ entry: Entry) {
        lock.lock()
        defer { lock.unlock() }
        entries[path] = entry
        if Store.fileClass(path) != .local { byObjectKey[objectKey(path)] = path }
        touched()
    }

    func drop(_ path: String) {
        lock.lock()
        defer { lock.unlock() }
        entries[path] = nil
        if Store.fileClass(path) != .local { byObjectKey[objectKey(path)] = nil }
        touched()
    }

    /// Records a local change: newest edit, and (outside local/) due for upload.
    func changed(_ path: String, size: Int64? = nil) {
        let now = Date.nowMs
        update(path) { e in
            if let size { e.size = size }
            e.mtime = now
            e.editedAt = now
            e.gen += 1
            e.changedAt = now
            if Store.fileClass(path) != .local { e.dirty = true }
        }
    }

    // MARK: - Content

    func fileLock(_ path: String) -> NSLock {
        lock.lock()
        defer { lock.unlock() }
        if let l = fileLocks[path] { return l }
        let l = NSLock()
        fileLocks[path] = l
        return l
    }

    /// Opens a file's local content. For remote/ files that aren't on this Mac, the caller
    /// fetches them first.
    func open(_ path: String, writable: Bool) throws -> EncryptedFile {
        guard let e = entry(path), e.kind == .file else { throw ShrugError("Not a file") }
        let local = Store.fileClass(path) == .local
        return try EncryptedFile(url: backingURL(path, e), master: local ? localKey : keys.master, writable: writable,
                                 base: local ? 0 : ObjectFormat.contentOffset)
    }

    /// A new, empty file (replacing a delete marker if there is one).
    func createFile(_ path: String, mode: UInt16 = 0o600) throws {
        guard let cls = Store.fileClass(path) else { throw ShrugError("Not in a Shrug folder") }
        var e = Entry(kind: .file)
        e.mode = mode & 0o700 == 0 ? 0o600 : (mode & 0o700) | 0o600
        e.etag = rawEntry(path)?.etag
        e.gen = (rawEntry(path)?.gen ?? 0) + 1
        e.changedAt = Date()
        if cls == .local {
            e.blob = ShrugCrypto.randomHex()
            guard FileManager.default.createFile(atPath: backingURL(path, e).path, contents: Data(),
                                                 attributes: [.posixPermissions: 0o600]) else {
                throw ShrugError("Cannot create a file in ~/.shrug")
            }
        } else {
            e.dirty = true
            e.cached = true
            guard FileManager.default.createFile(atPath: backingURL(path, e).path, contents: ObjectFormat.blankPrefix(),
                                                 attributes: [.posixPermissions: 0o600]) else {
                throw ShrugError("Cannot create a file in ~/.shrug")
            }
        }
        set(path, e)
    }

    func mkdir(_ path: String) {
        var e = Entry(kind: .dir)
        e.etag = rawEntry(path)?.etag
        e.dirty = Store.fileClass(path) != .local
        e.changedAt = Date()
        set(path, e)
    }

    /// Removes a file or folder entry. Outside local/ it becomes a delete marker for the bucket.
    func remove(_ path: String) {
        guard let e = entry(path) else { return }
        if e.kind == .file { unlink(backingURL(path, e).path) }
        if Store.fileClass(path) == .local {
            drop(path)
            return
        }
        var marker = Entry(kind: .deleted)
        marker.etag = e.etag
        marker.gen = e.gen + 1
        marker.dirty = true
        marker.changedAt = Date()
        set(path, marker)
    }

    /// Moves a file or folder (and everything in it) within one class.
    func rename(_ from: String, _ to: String) throws {
        let moving: [(String, Entry)] = all().filter {
            $0.1.kind != .deleted && ($0.0 == from || $0.0.hasPrefix(from + "/"))
        }
        guard !moving.isEmpty else { throw ShrugError("Nothing to move") }
        if let target = entry(to), target.kind == .file { remove(to) }
        let now = Date.nowMs
        for (old, e) in moving.sorted(by: { $0.0.count < $1.0.count }) {
            let new = to + old.dropFirst(from.count)
            var moved = e
            moved.etag = rawEntry(new)?.etag
            moved.gen = (rawEntry(new)?.gen ?? 0) + e.gen + 1
            moved.editedAt = now
            moved.changedAt = now
            if Store.fileClass(new) != .local {
                moved.dirty = true
                if e.kind == .file && (Store.fileClass(new) == .synced || e.cached) {
                    let src = backingURL(old, e)
                    let dst = backingURL(new, moved)
                    if Darwin.rename(src.path, dst.path) != 0 && Store.fileClass(new) == .synced {
                        throw ShrugError("Cannot move a local copy")
                    }
                }
            }
            if Store.fileClass(old) == .local {
                drop(old)
            } else {
                var marker = Entry(kind: .deleted)
                marker.etag = e.etag
                marker.gen = e.gen + 1
                marker.dirty = true
                marker.changedAt = now
                set(old, marker)
            }
            set(new, moved)
        }
    }

    /// Copies a real file's content in, as a new edit (creating the entry if needed).
    func importFile(from url: URL, to path: String) throws {
        if entry(path) == nil { try createFile(path) }
        var st = stat()
        let exec = stat(url.path, &st) == 0 && st.st_mode & 0o100 != 0
        let l = fileLock(path)
        l.lock()
        defer { l.unlock() }
        let file = try open(path, writable: true)
        try file.truncate(to: 0)
        guard let input = FileHandle(forReadingAtPath: url.path) else { throw ShrugError("Cannot read \(url.path)") }
        defer { try? input.close() }
        var offset: Int64 = 0
        while true {
            let chunk = input.readData(ofLength: 1 << 20)
            if chunk.isEmpty { break }
            try file.write(offset: offset, data: chunk)
            offset += Int64(chunk.count)
        }
        changed(path, size: file.size)
        if exec { update(path) { $0.mode = 0o700 } }
    }
}
