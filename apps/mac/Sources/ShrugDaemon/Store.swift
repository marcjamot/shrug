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
    /// The bucket version this entry matches, or was uploaded as. Nil: not known to be in the bucket.
    var version: String?
    /// remote/ only: the content is on this Mac.
    var cached = false

    init(kind: ObjectKind, at now: Date) {
        self.kind = kind
        mtime = now
        editedAt = now
        if kind == .dir { mode = 0o700 }
    }

    /// What a bucket object's header says about it.
    init(_ h: ObjectHeader, version: String) {
        kind = h.kind
        size = h.size
        mtime = h.mtime
        editedAt = h.editedAt
        mode = h.mode
        self.version = version
    }
}

struct IndexFile: Codable {
    var entries: [String: Entry]
}

/// What's in ~/Shrug on this Mac. Lives in memory only while unlocked; on disk it's
/// sealed with the local key, so a locked Mac doesn't even reveal file names.
/// Paths look like "synced/ssh/id_ed25519".
///
/// Changes to what exists (create, delete, rename) are saved before they return, and so is
/// the first content change after an upload; sizes and times follow within a second.
final class Store {
    let paths: ShrugPaths
    let keys: VaultKeys
    let localKey: SymmetricKey
    let clock: Clock
    private let lock = NSRecursiveLock()
    private let saveLock = NSLock()
    private var entries: [String: Entry] = [:]
    private var byObjectKey: [String: String] = [:]
    private var needsSave = false
    private var fileLocks: [String: NSLock] = [:]
    /// Set on lock; read under `lock`.
    private var closed = false

    init(paths: ShrugPaths, keys: VaultKeys, localKey: SymmetricKey, clock: Clock) throws {
        self.paths = paths
        self.keys = keys
        self.localKey = localKey
        self.clock = clock
        for dir in [paths.objectStore, paths.localStore] {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        }
        if let plain = try SealedFile.index.read(paths, key: localKey) {
            entries = try JSONFile.decode(IndexFile.self, from: plain).entries
        }
        for (p, e) in entries {
            if Store.fileClass(p) != .local { byObjectKey[keys.objectKey(p)] = p }
            // A local copy is the truth about its size: the index may be a write behind it after a crash.
            if e.kind == .file, hasLocalCopy(p, e), let size = plainSize(of: p, e) { entries[p]?.size = size }
        }
    }

    // MARK: - Saving

    /// Writes the index now. Saves run one at a time, each with the entries as they are then.
    func save() {
        saveLock.lock()
        defer { saveLock.unlock() }
        lock.lock()
        guard !closed else { return lock.unlock() }
        let snapshot = IndexFile(entries: entries)
        needsSave = false
        lock.unlock()
        do {
            try SealedFile.index.write(JSONFile.encode(snapshot), paths, key: localKey)
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

    /// Saves and forgets everything: called on lock. What's saved and the moment the store
    /// closes are one step, so every change recorded before it is on disk, and nothing can be
    /// recorded after it (see `willChange`).
    func close() {
        saveLock.lock()
        defer { saveLock.unlock() }
        lock.lock()
        let snapshot = closed ? nil : IndexFile(entries: entries)
        closed = true
        entries = [:]
        byObjectKey = [:]
        needsSave = false
        lock.unlock()
        if let snapshot { try? SealedFile.index.write(JSONFile.encode(snapshot), paths, key: localKey) }
    }

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

    /// Whether the file's content is on this Mac (always, except remote/ files not being edited).
    func hasLocalCopy(_ path: String, _ entry: Entry) -> Bool {
        Store.fileClass(path) != .remote || entry.cached
    }

    private func plainSize(of path: String, _ entry: Entry) -> Int64? {
        var st = stat()
        guard stat(backingURL(path, entry).path, &st) == 0 else { return nil }
        let base = Store.fileClass(path) == .local ? 0 : ObjectFormat.contentOffset
        return EncFormat.plainSize(encryptedSize: Int64(st.st_size) - base)
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
        if let e = entries[path], e.kind != .deleted { return e.kind == .dir }
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
        needsSave = true
    }

    func set(_ path: String, _ entry: Entry) {
        lock.lock()
        defer { lock.unlock() }
        guard !closed else { return } // a pass that outlived the lock
        entries[path] = entry
        if Store.fileClass(path) != .local { byObjectKey[objectKey(path)] = path }
        needsSave = true
    }

    func drop(_ path: String) {
        lock.lock()
        defer { lock.unlock() }
        entries[path] = nil
        if Store.fileClass(path) != .local { byObjectKey[objectKey(path)] = nil }
        needsSave = true
    }

    /// Records that a file's content is about to change: a new edit, due for upload outside
    /// local/. The first change after an upload is saved before the content changes, so a crash
    /// can't leave new content that never uploads.
    ///
    /// False once Shrug has locked (or the file is gone): the caller must not change the
    /// content then, because nothing would ever upload it.
    @discardableResult
    func willChange(_ path: String) -> Bool {
        let now = clock.nowMs
        lock.lock()
        guard !closed, var e = entries[path] else {
            lock.unlock()
            return false
        }
        let wasDirty = e.dirty
        e.mtime = now
        e.editedAt = now
        e.gen += 1
        e.changedAt = now
        if Store.fileClass(path) != .local { e.dirty = true }
        entries[path] = e
        needsSave = true
        lock.unlock()
        if e.dirty && !wasDirty { save() }
        return true
    }

    func didWrite(_ path: String, size: Int64) {
        update(path) { $0.size = size }
    }

    /// After uploading generation `gen` of a path as `version`. If nothing changed meanwhile the
    /// entry is clean, and the sealed copy that went up becomes the local copy (synced/), or the
    /// local copy goes away (remote/). Called with the file lock held.
    ///
    /// False if the sealed copy couldn't take the local copy's place. Nothing is lost then: the
    /// local copy has the same content, sealed under its earlier file id.
    @discardableResult
    func uploaded(_ path: String, gen: Int, version: String, sealedCopy: URL?) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !closed, var e = entries[path] else { return true }
        var placed = true
        e.version = version
        if e.gen == gen {
            e.dirty = false
            e.changedAt = nil
            if e.kind == .file, let sealedCopy {
                if Store.fileClass(path) == .remote {
                    unlink(backingURL(path, e).path)
                    e.cached = false
                } else {
                    placed = Darwin.rename(sealedCopy.path, backingURL(path, e).path) == 0
                }
            }
        }
        entries[path] = e
        needsSave = true
        return placed
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
        lock.lock()
        let isClosed = closed
        lock.unlock()
        guard !isClosed else { throw ShrugError("Shrug is locked") }
        let previous = rawEntry(path)
        var e = Entry(kind: .file, at: clock.nowMs)
        e.mode = mode & 0o100 != 0 ? 0o700 : 0o600
        e.version = previous?.version
        e.gen = (previous?.gen ?? 0) + 1
        e.changedAt = e.editedAt
        let contents: Data
        if cls == .local {
            e.blob = ShrugCrypto.randomHex()
            contents = Data()
        } else {
            e.dirty = true
            e.cached = true
            contents = ObjectFormat.blankPrefix()
        }
        guard FileManager.default.createFile(atPath: backingURL(path, e).path, contents: contents,
                                             attributes: [.posixPermissions: 0o600]) else {
            throw ShrugError("Cannot create a file in ~/.shrug")
        }
        set(path, e)
        save()
    }

    func mkdir(_ path: String) {
        let previous = rawEntry(path)
        var e = Entry(kind: .dir, at: clock.nowMs)
        e.version = previous?.version
        e.gen = (previous?.gen ?? 0) + 1
        e.dirty = Store.fileClass(path) != .local
        e.changedAt = e.editedAt
        set(path, e)
        save()
    }

    /// Removes a file or folder entry. Outside local/ it becomes a delete marker for the bucket.
    func remove(_ path: String) {
        guard let e = entry(path) else { return }
        removeEntry(path, e)
        save()
    }

    private func removeEntry(_ path: String, _ e: Entry) {
        if e.kind == .file && hasLocalCopy(path, e) { unlink(backingURL(path, e).path) }
        if Store.fileClass(path) == .local { return drop(path) }
        var marker = Entry(kind: .deleted, at: clock.nowMs)
        marker.version = e.version
        marker.gen = e.gen + 1
        marker.dirty = true
        marker.changedAt = marker.editedAt
        set(path, marker)
    }

    /// Moves a file or folder (and everything in it) within one class.
    func rename(_ from: String, _ to: String) throws {
        defer { save() }
        let moving: [(String, Entry)] = all().filter {
            $0.1.kind != .deleted && ($0.0 == from || $0.0.hasPrefix(from + "/"))
        }
        guard !moving.isEmpty else { throw ShrugError("Nothing to move") }
        if let target = entry(to), target.kind == .file { removeEntry(to, target) }
        let now = clock.nowMs
        for (old, e) in moving.sorted(by: { $0.0.count < $1.0.count }) {
            let new = to + old.dropFirst(from.count)
            var moved = e
            moved.version = rawEntry(new)?.version
            moved.gen = (rawEntry(new)?.gen ?? 0) + e.gen + 1
            moved.editedAt = now
            moved.changedAt = now
            if Store.fileClass(new) != .local {
                moved.dirty = true
                if e.kind == .file && hasLocalCopy(old, e) {
                    guard Darwin.rename(backingURL(old, e).path, backingURL(new, moved).path) == 0 else {
                        throw ShrugError("Cannot move a local copy")
                    }
                }
            }
            if Store.fileClass(old) == .local {
                drop(old)
            } else {
                var marker = Entry(kind: .deleted, at: now)
                marker.version = e.version
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
        guard let input = FileHandle(forReadingAtPath: url.path) else { throw ShrugError("Cannot read \(url.path)") }
        defer { try? input.close() }
        var st = stat()
        let exec = stat(url.path, &st) == 0 && st.st_mode & 0o100 != 0
        let l = fileLock(path)
        l.lock()
        defer { l.unlock() }
        let file = try open(path, writable: true)
        guard willChange(path) else { throw ShrugError("Shrug locked before the file was saved") }
        try file.truncate(to: 0)
        var offset: Int64 = 0
        while true {
            let chunk = input.readData(ofLength: 1 << 20)
            if chunk.isEmpty { break }
            try file.write(offset: offset, data: chunk)
            offset += Int64(chunk.count)
        }
        update(path) {
            $0.size = file.size
            if exec { $0.mode = 0o700 }
        }
        save()
    }
}
