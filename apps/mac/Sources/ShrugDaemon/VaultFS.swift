import CryptoKit
import Darwin
import Foundation
import ShrugCore
import ShrugNFS

/// The virtual folder mounted at ~/Shrug. The top level is always exactly local/,
/// synced/ and remote/; nothing else can be created there. While Shrug is locked the
/// three folders look empty, and opening anything inside asks Touch ID to unlock.
/// Nothing decrypted is ever written to disk.
final class VaultFS: NFSFileSystem {
    unowned let engine: Engine
    private let lock = NSLock()
    private var byPath: [String: UInt64] = [:]
    private var byID: [UInt64: String] = [:]
    private var nextID: UInt64 = 100
    private let uid = getuid()
    private let gid = getgid()
    private let started = Date()
    /// ~/Shrug as you'd type it, for Touch ID prompts.
    private let shownMount: String
    let caseInsensitive = false
    /// The most a bucket takes in one object (5 TiB), less room for what encryption adds.
    static let maxFileSize: UInt64 = 1 << 42
    var maxFileSize: UInt64 { VaultFS.maxFileSize }
    /// Kept free on this Mac's disk: a write that would leave less is refused, so nothing a
    /// program does in ~/Shrug can fill the disk.
    var reserve: UInt64 = 1 << 29

    static let neverIndex = ".metadata_never_index"
    static let fixed: [String: UInt64] = ["": 1, "local": 2, "synced": 3, "remote": 4, neverIndex: 5]

    init(engine: Engine) {
        self.engine = engine
        shownMount = engine.paths.contract(engine.paths.mount)
        reset()
    }

    var rootID: UInt64 { 1 }

    /// Forgets every name below the three folders (on lock), so none stays in memory.
    func reset() {
        lock.lock()
        defer { lock.unlock() }
        byPath = [:]
        byID = [:]
        for (p, id) in VaultFS.fixed {
            byPath[p] = id
            byID[id] = p
        }
    }

    // MARK: - Paths and ids

    private func path(_ id: UInt64) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return byID[id]
    }

    private func id(for path: String) -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        if let id = byPath[path] { return id }
        let id = nextID
        nextID += 1
        byPath[path] = id
        byID[id] = path
        return id
    }

    /// Forgets a path's id; with `folder`, those of everything that was in it too.
    private func forget(_ path: String, folder: Bool) {
        lock.lock()
        defer { lock.unlock() }
        if let id = byPath.removeValue(forKey: path) { byID[id] = nil }
        guard folder else { return }
        for (p, id) in byPath where p.hasPrefix(path + "/") {
            byPath[p] = nil
            byID[id] = nil
        }
    }

    /// Ids follow a path to its new name; with `folder`, so does everything in it.
    private func moved(_ from: String, _ to: String, folder: Bool) {
        lock.lock()
        defer { lock.unlock() }
        if let old = byPath[to] { byID[old] = nil; byPath[to] = nil }
        guard folder else {
            if let id = byPath.removeValue(forKey: from) {
                byPath[to] = id
                byID[id] = to
            }
            return
        }
        for (p, id) in byPath where p == from || p.hasPrefix(from + "/") {
            let np = to + p.dropFirst(from.count)
            byPath[p] = nil
            byPath[np] = id
            byID[id] = np
        }
    }

    private static func join(_ dir: String, _ name: String) -> String { dir.isEmpty ? name : dir + "/" + name }

    /// Names the system looks up on its own (Finder, Spotlight, AppleDouble files): never worth a prompt.
    static func quiet(_ name: String) -> Bool {
        name.hasPrefix("._") || [".DS_Store", ".localized", "Icon\r", ".hidden", ".Spotlight-V100", ".Trashes",
                                 ".fseventsd", neverIndex, ".metadata_never_index_unless_rootfs", ".TemporaryItems",
                                 ".VolumeIcon.icns", ".git", ".svn", ".hg"].contains(name)
    }

    // MARK: - Attributes

    private func nfsTime(_ date: Date, epoch: UInt64 = 0) -> NFSTime {
        let t = date.timeIntervalSince1970
        let total = UInt64(max(0, (t - floor(t)) * 1_000_000_000)) + epoch
        return NFSTime(sec: UInt32(truncatingIfNeeded: Int(t) + Int(total / 1_000_000_000)),
                       nsec: UInt32(total % 1_000_000_000))
    }

    private func dirAttr(_ id: UInt64, mode: UInt32, mtime: Date? = nil) -> NFSAttr {
        let t = nfsTime(mtime ?? started, epoch: engine.epoch)
        return NFSAttr(type: .directory, mode: mode, nlink: 2, uid: uid, gid: gid, size: 4096, used: 4096,
                       fileid: id, atime: t, mtime: t, ctime: t)
    }

    func getattr(_ id: UInt64) -> Result<NFSAttr, NFSStat> {
        guard let path = path(id) else { return .failure(.stale) }
        if path.isEmpty { return .success(dirAttr(id, mode: 0o500)) }
        if path == VaultFS.neverIndex {
            let t = nfsTime(started)
            return .success(NFSAttr(type: .regular, mode: 0o400, nlink: 1, uid: uid, gid: gid, size: 0, used: 0,
                                    fileid: id, atime: t, mtime: t, ctime: t))
        }
        if FileClass(rawValue: path) != nil {
            return .success(dirAttr(id, mode: 0o700, mtime: engine.store?.folderTime(path)))
        }
        guard let store = engine.store else { return .failure(.stale) }
        if let e = store.entry(path), e.kind == .file {
            let t = nfsTime(e.mtime, epoch: engine.epoch)
            return .success(NFSAttr(type: .regular, mode: UInt32(e.mode & 0o700), nlink: 1, uid: uid, gid: gid,
                                    size: UInt64(e.size), used: UInt64(e.size), fileid: id, atime: t, mtime: t, ctime: t))
        }
        if store.isDirectory(path) { return .success(dirAttr(id, mode: 0o700, mtime: store.folderTime(path))) }
        return .failure(.stale)
    }

    func parent(_ id: UInt64) -> UInt64 {
        guard let p = path(id), !p.isEmpty else { return rootID }
        return self.id(for: Store.parent(p))
    }

    /// The store, unlocking first (with a Touch ID prompt) if needed. `doing` finishes
    /// "a program is …", like "opening".
    private func openStore(_ doing: String, _ path: String) -> Store? {
        if let s = engine.store { return s }
        guard engine.unlockForAccess(doing, shownMount + "/" + path) else { return nil }
        return engine.store
    }

    func lookup(_ dir: UInt64, _ name: String) -> Result<UInt64, NFSStat> {
        guard let dirPath = path(dir) else { return .failure(.stale) }
        if dirPath.isEmpty {
            guard !name.isEmpty, let id = VaultFS.fixed[name] else { return .failure(.noent) }
            return .success(id)
        }
        if dirPath == VaultFS.neverIndex { return .failure(.notdir) }
        let child = VaultFS.join(dirPath, name)
        if engine.store == nil && VaultFS.quiet(name) { return .failure(.noent) }
        guard let store = openStore("opening", child) else { return .failure(.acces) }
        return store.exists(child) ? .success(id(for: child)) : .failure(.noent)
    }

    func readdir(_ dir: UInt64) -> Result<[NFSDirEntry], NFSStat> {
        guard let dirPath = path(dir) else { return .failure(.stale) }
        if dirPath.isEmpty {
            return .success([NFSDirEntry(name: VaultFS.neverIndex, id: 5), NFSDirEntry(name: "local", id: 2),
                             NFSDirEntry(name: "synced", id: 3), NFSDirEntry(name: "remote", id: 4)])
        }
        guard let store = engine.store else {
            return FileClass(rawValue: dirPath) != nil ? .success([]) : .failure(.stale)
        }
        guard store.isDirectory(dirPath) else { return .failure(.notdir) }
        return .success(store.children(dirPath).map { NFSDirEntry(name: $0, id: id(for: VaultFS.join(dirPath, $0))) })
    }

    // MARK: - Contents

    private func file(_ id: UInt64, _ action: String) -> Result<(Store, String, Entry), NFSStat> {
        guard let path = path(id) else { return .failure(.stale) }
        if VaultFS.fixed[path] != nil { return .failure(.isdir) }
        guard let store = openStore(action, path) else { return .failure(.acces) }
        guard let e = store.entry(path) else { return .failure(.stale) }
        guard e.kind == .file else { return .failure(.isdir) }
        return .success((store, path, e))
    }

    func read(_ id: UInt64, offset: UInt64, count: UInt32, _ ctx: NFSContext) -> Result<(Data, Bool), NFSStat> {
        if path(id) == VaultFS.neverIndex { return .success((Data(), true)) }
        let target: (Store, String, Entry)
        switch file(id, "reading") {
        case .failure(let e): return .failure(e)
        case .success(let t): target = t
        }
        let (store, path, e) = target
        if Store.fileClass(path) == .remote && !e.cached {
            // Previews and indexing would quietly download everything you browse past.
            if engine.isPreviewer(reading: path) { return .failure(.acces) }
            return engine.replicator.readRemote(path, offset: Int64(offset), count: Int(count))
        }
        let l = store.fileLock(path)
        l.lock()
        defer { l.unlock() }
        do {
            let f = try store.open(path, writable: false)
            let data = try f.read(offset: Int64(offset), count: Int(count))
            return .success((data, Int64(offset) + Int64(data.count) >= f.size))
        } catch {
            engine.log("read failed: \(error)")
            return .failure(.io)
        }
    }

    /// Whether this Mac's disk can take `bytes` more and keep its reserve.
    private func hasRoom(for bytes: UInt64) -> Bool {
        var s = statfs()
        guard statfs(engine.paths.state.path, &s) == 0 else { return true }
        return UInt64(s.f_bavail) * UInt64(s.f_bsize) >= bytes + reserve
    }

    /// A remote/ file must be on this Mac before it can change.
    private func ensureLocal(_ store: Store, _ path: String) -> NFSStat? {
        guard Store.fileClass(path) == .remote, let e = store.entry(path), e.kind == .file, !e.cached else { return nil }
        do {
            try engine.replicator.fetchWhole(path)
            return nil
        } catch {
            engine.log("fetch failed: \(error)")
            return .io
        }
    }

    func write(_ id: UInt64, offset: UInt64, data: Data, _ ctx: NFSContext) -> Result<Void, NFSStat> {
        let target: (Store, String, Entry)
        switch file(id, "changing") {
        case .failure(let e): return .failure(e)
        case .success(let t): target = t
        }
        let (store, path, _) = target
        if let failure = ensureLocal(store, path) { return .failure(failure) }
        let l = store.fileLock(path)
        l.lock()
        defer { l.unlock() }
        do {
            let f = try store.open(path, writable: true)
            let end = offset + UInt64(data.count)
            if end > UInt64(f.size), !hasRoom(for: end - UInt64(f.size)) { return .failure(.nospc) }
            // Shrug locked after the file opened: writing now would leave an edit that never uploads.
            guard store.willChange(path) else { return .failure(.acces) }
            try f.write(offset: Int64(offset), data: data)
            store.didWrite(path, size: f.size)
            engine.localChange()
            return .success(())
        } catch {
            engine.log("write failed: \(error)")
            return .failure(.io)
        }
    }

    /// A program asked for what it wrote to be on the disk (fsync, or closing the file).
    func commit(_ id: UInt64, _ ctx: NFSContext) -> Result<Void, NFSStat> {
        guard let path = path(id) else { return .failure(.stale) }
        if VaultFS.fixed[path] != nil { return .success(()) }
        // Locking saved everything, and never asks to unlock for this.
        guard let store = engine.store else { return .failure(.stale) }
        do {
            try store.sync(path)
            return .success(())
        } catch {
            engine.log("sync failed: \(error)")
            return .failure(.io)
        }
    }

    // MARK: - Structure

    /// A folder inside one of the three, ready for changes.
    private func folder(_ dir: UInt64) -> Result<(Store, String), NFSStat> {
        guard let dirPath = path(dir) else { return .failure(.stale) }
        if dirPath.isEmpty || dirPath == VaultFS.neverIndex { return .failure(.acces) }
        guard let store = openStore("saving in", dirPath) else { return .failure(.acces) }
        guard store.isDirectory(dirPath) else { return .failure(.notdir) }
        return .success((store, dirPath))
    }

    func create(_ dir: UInt64, _ name: String, mode: UInt32?, exclusive: Bool, _ ctx: NFSContext) -> Result<UInt64, NFSStat> {
        switch folder(dir) {
        case .failure(let e): return .failure(e)
        case .success(let (store, dirPath)):
            let child = VaultFS.join(dirPath, name)
            if store.isDirectory(child) { return .failure(.isdir) }
            if store.entry(child) != nil {
                return exclusive ? .failure(.exist) : .success(id(for: child))
            }
            do {
                try store.createFile(child, mode: UInt16((mode ?? 0o600) & 0o777))
            } catch {
                engine.log("create failed: \(error)")
                return .failure(.io)
            }
            engine.localChange()
            return .success(id(for: child))
        }
    }

    func mkdir(_ dir: UInt64, _ name: String, mode: UInt32?, _ ctx: NFSContext) -> Result<UInt64, NFSStat> {
        switch folder(dir) {
        case .failure(let e): return .failure(e)
        case .success(let (store, dirPath)):
            let child = VaultFS.join(dirPath, name)
            if store.exists(child) { return .failure(.exist) }
            store.mkdir(child)
            engine.localChange()
            return .success(id(for: child))
        }
    }

    func remove(_ dir: UInt64, _ name: String, _ ctx: NFSContext) -> Result<Void, NFSStat> {
        switch folder(dir) {
        case .failure(let e): return .failure(e)
        case .success(let (store, dirPath)):
            let child = VaultFS.join(dirPath, name)
            guard let e = store.entry(child) else { return store.isDirectory(child) ? .failure(.isdir) : .failure(.noent) }
            guard e.kind == .file else { return .failure(.isdir) }
            store.remove(child)
            forget(child, folder: false)
            engine.localChange()
            return .success(())
        }
    }

    func rmdir(_ dir: UInt64, _ name: String, _ ctx: NFSContext) -> Result<Void, NFSStat> {
        switch folder(dir) {
        case .failure(let e): return .failure(e)
        case .success(let (store, dirPath)):
            let child = VaultFS.join(dirPath, name)
            guard store.isDirectory(child) else { return .failure(store.exists(child) ? .notdir : .noent) }
            // A folder holding only Finder's own files counts as empty.
            let names = store.children(child)
            guard names.allSatisfy(Store.isScratch) else { return .failure(.notempty) }
            for n in names { store.remove(VaultFS.join(child, n)) }
            store.remove(child)
            forget(child, folder: true)
            engine.localChange()
            return .success(())
        }
    }

    func rename(_ fromDir: UInt64, _ fromName: String, _ toDir: UInt64, _ toName: String, _ ctx: NFSContext) -> Result<Void, NFSStat> {
        guard case .success(let (store, fromPath)) = folder(fromDir) else { return .failure(.acces) }
        guard case .success(let (_, toPath)) = folder(toDir) else { return .failure(.acces) }
        let from = VaultFS.join(fromPath, fromName)
        let to = VaultFS.join(toPath, toName)
        guard Store.fileClass(from) == Store.fileClass(to) else { return .failure(.xdev) }
        guard store.exists(from) else { return .failure(.noent) }
        if to == from || to.hasPrefix(from + "/") { return .failure(.inval) }
        let folder = store.isDirectory(from)
        if store.isDirectory(to) && !store.children(to).isEmpty { return .failure(.notempty) }
        if folder != store.isDirectory(to) && store.exists(to) {
            return .failure(store.isDirectory(to) ? .isdir : .notdir)
        }
        guard store.canRename(from, to) else { return .failure(.xdev) }
        // Moving a remote/ file means re-uploading it, so its content has to be here.
        if Store.fileClass(from) == .remote {
            for (p, e) in store.tree(from) where e.kind == .file && !e.cached {
                if let failure = ensureLocal(store, p) { return .failure(failure) }
            }
        }
        do {
            try store.rename(from, to)
        } catch {
            engine.log("rename failed: \(error)")
            return .failure(.io)
        }
        moved(from, to, folder: folder)
        engine.renamed(from, to)
        engine.localChange()
        return .success(())
    }

    func setattr(_ id: UInt64, _ attrs: NFSSetAttrs, _ ctx: NFSContext) -> Result<Void, NFSStat> {
        guard let path = path(id) else { return .failure(.stale) }
        if VaultFS.fixed[path] != nil { return attrs.size == nil && attrs.mode == nil ? .success(()) : .failure(.acces) }
        guard let store = openStore("changing", path) else { return .failure(.acces) }
        guard store.exists(path) else { return .failure(.stale) }
        if let size = attrs.size {
            guard store.entry(path)?.kind == .file else { return .failure(.isdir) }
            if let failure = ensureLocal(store, path) { return .failure(failure) }
            let l = store.fileLock(path)
            l.lock()
            defer { l.unlock() }
            do {
                let f = try store.open(path, writable: true)
                if f.size != Int64(size) {
                    if size > UInt64(f.size), !hasRoom(for: size - UInt64(f.size)) { return .failure(.nospc) }
                    guard store.willChange(path) else { return .failure(.acces) }
                    try f.truncate(to: Int64(size))
                    store.didWrite(path, size: f.size)
                    engine.localChange()
                }
            } catch {
                engine.log("truncate failed: \(error)")
                return .failure(.io)
            }
        }
        if let mode = attrs.mode {
            store.update(path) { $0.mode = mode & 0o100 != 0 ? 0o700 : ($0.kind == .dir ? 0o700 : 0o600) }
        }
        switch attrs.mtime {
        case .unchanged: break
        case .serverTime: store.update(path) { $0.mtime = engine.clock.nowMs }
        case .client(let t):
            store.update(path) { $0.mtime = Date(timeIntervalSince1970: Double(t.sec) + Double(t.nsec) / 1e9).ms }
        }
        return .success(())
    }

    func fsstat() -> NFSFSStat {
        var s = statfs()
        guard statfs(engine.paths.state.path, &s) == 0 else {
            return NFSFSStat(totalBytes: 0, freeBytes: 0, totalFiles: 0, freeFiles: 0)
        }
        let bs = UInt64(s.f_bsize)
        let free = UInt64(s.f_bavail) * bs
        return NFSFSStat(totalBytes: UInt64(s.f_blocks) * bs, freeBytes: free > reserve ? free - reserve : 0,
                         totalFiles: UInt64(s.f_files), freeFiles: UInt64(s.f_ffree))
    }
}
