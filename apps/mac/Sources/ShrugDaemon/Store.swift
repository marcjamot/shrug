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
    /// local/ and unsaved files: the backing file's random name.
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
    /// Only in memory, with its content in the scratch folder: gone when Shrug locks, never in
    /// the saved index, the bucket or a folder's listing (see `Store.isAppleDouble`).
    var unsaved = false

    private enum CodingKeys: String, CodingKey {
        case kind, size, mtime, editedAt, mode, blob, dirty, gen, changedAt, version, cached
    }

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

/// What's in ~/Shrug on this Mac. Lives in memory only while unlocked; on disk it's
/// sealed with the local key, so a locked Mac doesn't even reveal file names.
/// Paths look like "synced/ssh/id_ed25519".
///
/// Saving a change adds it to a journal (see SavedIndex), so it costs the same however much
/// is in ~/Shrug:
/// - Changes to what exists (create, delete, rename) are on the disk before they return, as
///   after an fsync. Sizes and times follow within a second, or when a program asks (`sync`).
/// - A change that makes this Mac's copy of a file differ from the one in the bucket is
///   flushed through the disk's own cache first, so not even a power cut can leave new
///   content that never uploads.
/// - Once a second, and on lock, everything is flushed that far.
final class Store {
    let paths: ShrugPaths
    let keys: VaultKeys
    let localKey: SymmetricKey
    let clock: Clock
    private let lock = NSRecursiveLock()
    private var entries: [String: Entry] = [:]
    private var byObjectKey: [String: String] = [:]
    /// The names in each folder that has any: its files and folders, and folders that only
    /// exist because of what's in them. Looking a name up or listing a folder never has to
    /// go through every entry.
    private var names: [String: Set<String>] = [:]
    /// The unsaved files in each folder that has any. They aren't listed, and don't make a
    /// folder exist.
    private var hidden: [String: Set<String>] = [:]
    /// When the names in a folder last changed since unlock, whoever changed them. A folder's
    /// time has to move then: it's how the system knows that a listing it kept, or a "no such
    /// file" it remembers, is out of date.
    private var namesChangedAt: [String: Date] = [:]
    /// Paths with a change waiting for the bucket.
    private var dirtyPaths: Set<String> = []
    /// Paths whose entry changed since the journal last heard of them.
    private var unrecorded: Set<String> = []
    /// A recorded change made this Mac's copy differ from the bucket's: the next save flushes.
    private var mustFlush = false
    private var fileLocks: [String: NSLock] = [:]
    /// Set on lock; read under `lock`.
    private var closed = false

    /// One save at a time. Guards the saved index and the two flags below.
    private let saveLock = NSLock()
    private let index: SavedIndex
    /// Everything in the journal is on the disk…
    private var onDisk = true
    /// …and through the disk's own cache, along with every file `sync` put on the disk.
    private var flushed = true
    /// Bytes at the end of the journal that didn't open when the index was read: what a crash
    /// while saving leaves.
    let ignoredJournalBytes: Int
    /// A journal shorter than this is never worth folding into the index.
    var shortJournal = 1 << 20

    init(paths: ShrugPaths, keys: VaultKeys, localKey: SymmetricKey, clock: Clock) throws {
        self.paths = paths
        self.keys = keys
        self.localKey = localKey
        self.clock = clock
        // What the scratch folder held belonged to the last unlock.
        try? FileManager.default.removeItem(at: paths.scratchStore)
        for dir in [paths.objectStore, paths.localStore, paths.scratchStore] {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        }
        index = SavedIndex(paths: paths, key: localKey)
        let saved = try index.load()
        ignoredJournalBytes = index.ignored
        for (p, e) in saved { put(p, e) }
        unrecorded = []
        mustFlush = false
        namesChangedAt = [:]
        for (p, e) in saved {
            // A local copy is the truth about its size: the index may be a write behind it after a crash.
            if e.kind == .file, hasLocalCopy(p, e), let size = plainSize(of: p, e) { entries[p]?.size = size }
        }
    }

    // MARK: - Saving

    /// Every change to an entry goes through here, with `lock` held, so the name lists, the
    /// upload list and the journal never miss one.
    private func put(_ path: String, _ new: Entry?) {
        let old = entries[path]
        entries[path] = new
        let wasListed = old.map { $0.kind != .deleted && !$0.unsaved } ?? false
        let isListed = new.map { $0.kind != .deleted && !$0.unsaved } ?? false
        if isListed && !wasListed { list(path) }
        if wasListed && !isListed { unlist(path) }
        if old?.unsaved != new?.unsaved, let slash = path.lastIndex(of: "/") {
            let dir = String(path[..<slash])
            let name = String(path[path.index(after: slash)...])
            if new?.unsaved == true {
                hidden[dir, default: []].insert(name)
            } else {
                hidden[dir]?.remove(name)
                if hidden[dir]?.isEmpty == true { hidden[dir] = nil }
            }
        }
        if (old == nil) != (new == nil), Store.fileClass(path) != .local {
            byObjectKey[objectKey(path)] = new == nil ? nil : path
        }
        // A folder's time was set outright, as tar does after filling one: that's its time now.
        if let old, let new, old.kind == .dir, new.kind == .dir, old.mtime != new.mtime { namesChangedAt[path] = nil }
        if new?.dirty == true { dirtyPaths.insert(path) } else { dirtyPaths.remove(path) }
        if old?.unsaved == false || new?.unsaved == false { unrecorded.insert(path) }
        // A file that matched the bucket's is about to stop matching it.
        if let old, old.kind == .file, !old.dirty, old.version != nil, new?.dirty != false { mustFlush = true }
    }

    /// Adds a path's name to its folder, and that folder's to the one above, as far as needed.
    private func list(_ path: String) {
        var p = Substring(path)
        while let slash = p.lastIndex(of: "/") {
            let dir = String(p[..<slash])
            guard names[dir, default: []].insert(String(p[p.index(after: slash)...])).inserted else { return }
            namesChanged(in: dir)
            p = p[..<slash]
        }
    }

    /// Takes a path's name out of its folder, and any folder left with nothing in it (that
    /// isn't an entry itself) out of the one above.
    private func unlist(_ path: String) {
        var p = Substring(path)
        while let slash = p.lastIndex(of: "/") {
            let here = String(p)
            if names[here] != nil { return }
            if let e = entries[here], e.kind != .deleted, !e.unsaved { return }
            let dir = String(p[..<slash])
            names[dir]?.remove(String(p[p.index(after: slash)...]))
            if names[dir]?.isEmpty == true { names[dir] = nil }
            namesChanged(in: dir)
            p = p[..<slash]
        }
    }

    /// Gives a folder a later time than it has had, even if the clock hasn't moved.
    private func namesChanged(in dir: String) {
        let now = clock.now()
        if let last = namesChangedAt[dir], last >= now {
            namesChangedAt[dir] = last.addingTimeInterval(0.000_001)
        } else {
            namesChangedAt[dir] = now
        }
    }

    /// What the journal should hear about `paths`. Called with `lock` held.
    private func changes(for paths: Set<String>) -> IndexChanges {
        var changes = IndexChanges()
        for p in paths {
            if let e = entries[p], !e.unsaved { changes.changed[p] = e } else { changes.removed.append(p) }
        }
        return changes
    }

    /// Saves every change so far: on the disk when this returns.
    func save() { record(flush: false) }

    /// Adds the changes since the last save to the journal and puts it on the disk; with
    /// `flush` (or after a change that needs it, see `put`), through the disk's own cache.
    /// False if it couldn't: the changes then wait for the next save.
    @discardableResult
    private func record(flush: Bool) -> Bool {
        saveLock.lock()
        defer { saveLock.unlock() }
        // After a failure that left no journal to add to, the whole index is written instead.
        guard index.isOpen else { return rewrite() }
        lock.lock()
        guard !closed else {
            lock.unlock()
            return false
        }
        let paths = unrecorded
        let changes = changes(for: paths)
        let flush = flush || mustFlush
        unrecorded = []
        mustFlush = false
        lock.unlock()
        do {
            if !changes.isEmpty {
                try index.append(changes)
                onDisk = false
                flushed = false
            }
            if flush && !flushed {
                try index.sync(flush: true)
                onDisk = true
                flushed = true
            } else if !onDisk {
                try index.sync(flush: false)
                onDisk = true
            }
            return true
        } catch {
            lock.lock()
            unrecorded.formUnion(paths)
            mustFlush = mustFlush || flush
            lock.unlock()
            return false
        }
    }

    /// Writes the whole index and starts a new journal. Called with `saveLock` held.
    @discardableResult
    private func rewrite() -> Bool {
        lock.lock()
        guard !closed else {
            lock.unlock()
            return false
        }
        let all = entries
        let paths = unrecorded
        unrecorded = []
        mustFlush = false
        lock.unlock()
        do {
            try index.rewrite(all.filter { !$0.value.unsaved })
            onDisk = true
            flushed = true
            return true
        } catch {
            lock.lock()
            unrecorded.formUnion(paths)
            mustFlush = true
            lock.unlock()
            return false
        }
    }

    /// Called every second: flushes what was saved since, and folds a journal that has grown
    /// long into the index.
    func saveIfNeeded() {
        record(flush: true)
        saveLock.lock()
        if index.journalIsLong(over: shortJournal) { rewrite() }
        saveLock.unlock()
    }

    /// What a program's fsync asks for: the file's content, and every change so far, on the disk.
    /// (An unsaved file is gone after a crash either way.)
    func sync(_ path: String) throws {
        if let e = entry(path), e.kind == .file, !e.unsaved, hasLocalCopy(path, e) {
            let fd = Darwin.open(backingURL(path, e).path, O_RDONLY)
            // Not there: an upload just took a remote/ file's copy away, and the bucket has it.
            if fd >= 0 {
                defer { Darwin.close(fd) }
                guard fsync(fd) == 0 else { throw ShrugError("Could not sync a file: \(String(cString: strerror(errno)))") }
                saveLock.lock()
                flushed = false
                saveLock.unlock()
            }
        }
        guard record(flush: false) else { throw ShrugError("Could not save this Mac's index") }
    }

    /// Saves and forgets everything: called on lock. What's saved and the moment the store
    /// closes are one step, so every change recorded before it is on disk, and nothing can be
    /// recorded after it (see `willChange`).
    func close() {
        saveLock.lock()
        defer { saveLock.unlock() }
        lock.lock()
        guard !closed else { return lock.unlock() }
        let all = entries
        let last = changes(for: unrecorded)
        closed = true
        entries = [:]
        byObjectKey = [:]
        names = [:]
        hidden = [:]
        namesChangedAt = [:]
        dirtyPaths = []
        unrecorded = []
        lock.unlock()
        do {
            if !last.isEmpty { try index.append(last) }
            try index.sync(flush: true)
        } catch {
            // No journal to add to: the whole index, then.
            try? index.rewrite(all.filter { !$0.value.unsaved })
        }
        index.close()
        try? FileManager.default.removeItem(at: paths.scratchStore)
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

    /// The ._ files macOS writes next to every file that has extended attributes, which is
    /// most files a program makes. A new one is `unsaved`: it costs the index nothing and
    /// lasts until Shrug locks. macOS finds it by name; a folder's listing leaves it out, so
    /// programs that go through a folder (git, tar, a copy) see the files you put there, as
    /// on the Mac's own disk.
    static func isAppleDouble(_ name: String) -> Bool { name.hasPrefix("._") }

    func objectKey(_ path: String) -> String { keys.objectKey(path) }

    func path(forObjectKey key: String) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return byObjectKey[key]
    }

    /// The local file holding an entry's content.
    func backingURL(_ path: String, _ entry: Entry) -> URL {
        if entry.unsaved { return paths.scratchStore.appendingPathComponent(entry.blob ?? "missing") }
        if Store.fileClass(path) == .local { return paths.localStore.appendingPathComponent(entry.blob ?? "missing") }
        return paths.objectStore.appendingPathComponent(String(objectKey(path).dropFirst(2)))
    }

    /// Whether the file's content is on this Mac (always, except remote/ files not being edited).
    func hasLocalCopy(_ path: String, _ entry: Entry) -> Bool {
        entry.unsaved || Store.fileClass(path) != .remote || entry.cached
    }

    /// Whether an entry's content is sealed with this Mac's key, on its own, rather than as
    /// the copy of a bucket object.
    private func isLocalOnly(_ path: String, _ entry: Entry) -> Bool {
        entry.unsaved || Store.fileClass(path) == .local
    }

    private func plainSize(of path: String, _ entry: Entry) -> Int64? {
        var st = stat()
        guard stat(backingURL(path, entry).path, &st) == 0 else { return nil }
        let base = isLocalOnly(path, entry) ? 0 : ObjectFormat.contentOffset
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
        return names[path] != nil
    }

    func exists(_ path: String) -> Bool { entry(path) != nil || isDirectory(path) }

    /// When a folder's names last changed, or else the time it was made with or given since;
    /// nil if neither is known.
    func folderTime(_ path: String) -> Date? {
        lock.lock()
        defer { lock.unlock() }
        return namesChangedAt[path] ?? entries[path].flatMap { $0.kind == .dir ? $0.mtime : nil }
    }

    /// Names directly inside a folder, including folders that only exist because of what's in
    /// them, without unsaved files.
    func children(_ dir: String) -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return names[dir]?.sorted() ?? []
    }

    /// The entry at a path and every entry below it, unsaved files included (no delete markers).
    func tree(_ path: String) -> [(String, Entry)] {
        lock.lock()
        defer { lock.unlock() }
        var found: [(String, Entry)] = []
        var left = [path]
        while let p = left.popLast() {
            if let e = entries[p], e.kind != .deleted { found.append((p, e)) }
            for name in names[p] ?? [] { left.append(p + "/" + name) }
            for name in hidden[p] ?? [] { left.append(p + "/" + name) }
        }
        return found
    }

    func all() -> [(String, Entry)] {
        lock.lock()
        defer { lock.unlock() }
        return entries.map { ($0.key, $0.value) }
    }

    /// Changes waiting for the bucket.
    func pending() -> [(String, Entry)] {
        lock.lock()
        defer { lock.unlock() }
        return dirtyPaths.sorted().compactMap { p in entries[p].map { (p, $0) } }
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
        put(path, e)
    }

    func set(_ path: String, _ entry: Entry) {
        lock.lock()
        defer { lock.unlock() }
        guard !closed else { return } // a pass that outlived the lock
        put(path, entry)
    }

    func drop(_ path: String) {
        lock.lock()
        defer { lock.unlock() }
        guard !closed else { return }
        put(path, nil)
    }

    /// Records that a file's content is about to change: a new edit, due for upload outside
    /// local/. The first change after an upload is saved, and flushed, before the content
    /// changes, so a crash can't leave new content that never uploads.
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
        if Store.fileClass(path) != .local && !e.unsaved { e.dirty = true }
        put(path, e)
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
        put(path, e)
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
        let local = isLocalOnly(path, e)
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
        e.cached = cls != .local
        // Where the index already knows the path, the new file takes its place there.
        e.unsaved = previous == nil && Store.isAppleDouble(Store.name(path))
        let contents: Data
        if isLocalOnly(path, e) {
            e.blob = ShrugCrypto.randomHex()
            contents = Data()
        } else {
            e.dirty = true
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
    /// The file's lock keeps a download of the same file from landing halfway through.
    func remove(_ path: String) {
        let l = fileLock(path)
        l.lock()
        defer { l.unlock() }
        guard let e = entry(path) else { return }
        var contents = [removeEntry(path, e)]
        // A folder's unsaved files go with it: nothing else would ever remove them.
        if e.kind == .dir {
            for (p, inside) in tree(path) where inside.unsaved && Store.parent(p) == path {
                contents.append(removeEntry(p, inside))
            }
        }
        save()
        for case let content? in contents { unlink(content.path) }
    }

    /// Takes an entry out of the index. Returns the file that held its content, for the caller
    /// to delete once that's saved: the saved index never names a file that's gone.
    private func removeEntry(_ path: String, _ e: Entry) -> URL? {
        let content = e.kind == .file && hasLocalCopy(path, e) ? backingURL(path, e) : nil
        if isLocalOnly(path, e) {
            drop(path)
        } else {
            var marker = Entry(kind: .deleted, at: clock.nowMs)
            marker.version = e.version
            marker.gen = e.gen + 1
            marker.dirty = true
            marker.changedAt = marker.editedAt
            set(path, marker)
        }
        return content
    }

    /// Whether a file can move to another name in its folder class. An unsaved file can only
    /// become another unsaved one: its content isn't kept the way a saved file's is. (Moving
    /// it anyway works as between folders: programs copy it instead.)
    func canRename(_ from: String, _ to: String) -> Bool {
        guard let e = entry(from), e.unsaved else { return true }
        return Store.isAppleDouble(Store.name(to)) && rawEntry(to)?.unsaved != false
    }

    /// Moves a file or folder (and everything in it) within one class.
    func rename(_ from: String, _ to: String) throws {
        var replaced: [URL] = []
        defer {
            save()
            for url in replaced { unlink(url.path) }
        }
        let moving = tree(from)
        guard !moving.isEmpty else { throw ShrugError("Nothing to move") }
        if let target = entry(to), target.kind == .file, let content = removeEntry(to, target) { replaced.append(content) }
        let now = clock.nowMs
        for (old, e) in moving.sorted(by: { $0.0.count < $1.0.count }) {
            let new = to + old.dropFirst(from.count)
            var moved = e
            moved.gen = (rawEntry(new)?.gen ?? 0) + e.gen + 1
            if e.unsaved {
                // Its content stays where it is, under its random name.
                drop(old)
                set(new, moved)
                continue
            }
            moved.version = rawEntry(new)?.version
            moved.editedAt = now
            moved.changedAt = now
            if Store.fileClass(new) != .local {
                moved.dirty = true
                if e.kind == .file && hasLocalCopy(old, e) {
                    let place = backingURL(new, moved)
                    guard Darwin.rename(backingURL(old, e).path, place.path) == 0 else {
                        throw ShrugError("Cannot move a local copy")
                    }
                    replaced.removeAll { $0.path == place.path }
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
