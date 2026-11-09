import CryptoKit
import Darwin
import Foundation
import ShrugCore
import ShrugNFS

/// Keeps ~/Shrug and the bucket in step, while unlocked and online.
///
/// - The newest edit of a file wins, using the edit time sealed inside each object.
/// - Deleting leaves a small sealed marker, so other Macs delete too; markers go after 30 days.
/// - synced/ files live on this Mac and in the bucket. remote/ files live in the bucket;
///   reading streams just the chunks needed, and changes stay here only until uploaded.
final class Replicator {
    unowned let engine: Engine
    private let passLock = NSLock()
    private let cacheLock = NSLock()
    private var chunks: [String: Data] = [:]
    private var chunkOrder: [String] = []
    private var fileIDs: [String: Data] = [:]
    private var macNames: [String: String] = [:]
    private var _online: Bool?
    private var _lastSync: Date?
    private var _problem: String?

    static let markerLifetime: TimeInterval = 30 * 86400
    static let maxCachedChunks = 512
    static let readAhead = 16

    init(engine: Engine) { self.engine = engine }

    var online: Bool? { cacheLock.lock(); defer { cacheLock.unlock() }; return _online }
    var lastSync: Date? { cacheLock.lock(); defer { cacheLock.unlock() }; return _lastSync }
    var problem: String? { cacheLock.lock(); defer { cacheLock.unlock() }; return _problem }

    private func report(online: Bool?, problem: String?, synced: Bool = false) {
        cacheLock.lock()
        _online = online
        _problem = problem
        if synced { _lastSync = Date() }
        cacheLock.unlock()
        engine.changed()
    }

    /// Drops everything decrypted from memory (on lock).
    func forget() {
        cacheLock.lock()
        chunks = [:]
        chunkOrder = []
        fileIDs = [:]
        macNames = [:]
        cacheLock.unlock()
    }

    // MARK: - A pass

    /// One pass over the bucket. With `wait`, waits for a running pass and then does its own,
    /// so the caller knows this Mac is up to date (if online).
    func pass(wait: Bool = false) {
        if wait {
            passLock.lock()
        } else if !passLock.try() {
            engine.passSoon()
            return
        }
        defer { passLock.unlock() }
        guard let s = engine.session() else { return }
        do {
            let objects = try s.storage.list(prefix: "")
            guard engine.isCurrent(s) else { return }
            var byKey: [String: StoredObject] = [:]
            for o in objects { byKey[o.key] = o }
            // A listing without the vault is a wrong bucket or a broken answer: never act on it.
            guard byKey[VaultKeys.keyringKey] != nil else { throw ShrugError("The storage has no Shrug vault") }
            try syncMacs(s, byKey)
            if try syncProfile(s, byKey) { engine.reconcileSoon() }
            try download(s, byKey)
            try upload(s, byKey)
            if engine.stateCopy()?.everSynced == false { engine.updateState { $0.everSynced = true } }
            report(online: true, problem: nil, synced: true)
        } catch let e as StorageError {
            switch e {
            case .offline: report(online: false, problem: nil)
            case .denied(let m): report(online: true, problem: "The storage refused this Mac's key (\(m))")
            default: report(online: true, problem: "\(e)")
            }
        } catch {
            report(online: true, problem: "\(error)")
        }
    }

    private func syncMacs(_ s: Session, _ byKey: [String: StoredObject]) throws {
        guard let st = engine.stateCopy() else { return }
        let mine = VaultKeys.deviceKey(st.deviceID)
        if byKey[mine] == nil {
            _ = try s.storage.put(mine, data: s.keys.sealMeta(DeviceRecord(name: st.deviceName, addedAt: Date()), key: mine))
        }
        var names: [String] = byKey[mine] == nil ? [st.deviceName] : []
        for o in byKey.values where o.key.hasPrefix("m/d/") {
            cacheLock.lock()
            let known = macNames[o.key + "@" + o.etag]
            cacheLock.unlock()
            if let known {
                names.append(known)
                continue
            }
            guard let rec = try? s.keys.openMeta(DeviceRecord.self, s.storage.get(o.key, range: nil), key: o.key) else { continue }
            cacheLock.lock()
            macNames[o.key + "@" + o.etag] = rec.name
            cacheLock.unlock()
            names.append(rec.name)
        }
        let sorted = names.sorted()
        if sorted != st.macs { engine.updateState { $0.macs = sorted } }
    }

    /// Returns whether this Mac's links changed.
    private func syncProfile(_ s: Session, _ byKey: [String: StoredObject]) throws -> Bool {
        guard let st = engine.stateCopy(), let name = st.profile else { return false }
        let key = s.keys.profileKey(name)
        var changed = false
        if let obj = byKey[key], obj.etag != st.profileETag {
            let p = try s.keys.openMeta(Profile.self, s.storage.get(key, range: nil), key: key)
            if !st.profileDirty || p.editedAt > (st.profileEditedAt ?? .distantPast) {
                changed = p.links != st.links
                engine.updateState {
                    $0.links = p.links
                    $0.profileEditedAt = p.editedAt
                    $0.profileETag = obj.etag
                    $0.profileDirty = false
                }
            } else {
                engine.updateState { $0.profileETag = obj.etag } // ours is newer: it replaces that one below
            }
        }
        guard let now = engine.stateCopy(), now.profileDirty, now.profile == name else { return changed }
        let p = Profile(name: name, links: now.links, editedAt: now.profileEditedAt ?? Date())
        let etag = try s.storage.put(key, data: s.keys.sealMeta(p, key: key))
        engine.updateState {
            if $0.profileGen == now.profileGen { $0.profileDirty = false }
            $0.profileETag = etag
        }
        return changed
    }

    private func download(_ s: Session, _ byKey: [String: StoredObject]) throws {
        let now = Date()
        for obj in byKey.values.sorted(by: { $0.key < $1.key }) where obj.key.hasPrefix("f/") {
            guard engine.isCurrent(s) else { return }
            if let p = s.store.path(forObjectKey: obj.key), s.store.rawEntry(p)?.etag == obj.etag { continue }
            let prefix = try s.storage.get(obj.key, range: 0...(ObjectFormat.contentOffset - 1))
            guard let h = try? ObjectFormat.decodeHeader(prefix, keys: s.keys, objectKey: obj.key),
                  s.keys.objectKey(h.path) == obj.key, let cls = Store.fileClass(h.path), cls != .local else {
                engine.log("skipped an object that doesn't open with this vault")
                continue
            }
            if h.kind == .deleted && now.timeIntervalSince(h.editedAt) > Replicator.markerLifetime {
                try s.storage.delete(obj.key)
                if s.store.rawEntry(h.path)?.kind == .deleted { s.store.drop(h.path) }
                continue
            }
            if let local = s.store.rawEntry(h.path), local.dirty, local.editedAt >= h.editedAt {
                s.store.update(h.path) { $0.etag = obj.etag } // ours is newer and will replace it
                continue
            }
            try apply(h, obj, s)
        }
        // Gone from the bucket (an old delete marker cleaned up, or removed by hand).
        let present = Set(byKey.keys)
        for (p, e) in s.store.all() where Store.fileClass(p) != .local && !e.dirty && e.etag != nil
            && !present.contains(s.store.objectKey(p)) {
            if e.kind == .file { unlink(s.store.backingURL(p, e).path) }
            s.store.drop(p)
        }
    }

    private func apply(_ h: ObjectHeader, _ obj: StoredObject, _ s: Session) throws {
        let previous = s.store.rawEntry(h.path)
        var e = Entry(kind: h.kind)
        e.mtime = h.mtime
        e.editedAt = h.editedAt
        e.mode = h.mode
        e.etag = obj.etag
        e.gen = (previous?.gen ?? 0) + 1
        switch h.kind {
        case .deleted, .dir:
            if let previous, previous.kind == .file { unlink(s.store.backingURL(h.path, previous).path) }
            s.store.set(h.path, e)
        case .file:
            e.size = h.size
            let backing = s.store.backingURL(h.path, e)
            if Store.fileClass(h.path) == .synced {
                let tmp = engine.paths.objectStore.appendingPathComponent(".tmp-\(UUID().uuidString)")
                defer { unlink(tmp.path) }
                e.etag = try s.storage.download(obj.key, to: tmp)
                // Only use it if it's still the version we looked at; otherwise next time.
                guard (try? ObjectFormat.readHeader(of: tmp, keys: s.keys, objectKey: obj.key)) == h else { return }
                chmod(tmp.path, 0o600)
                let l = s.store.fileLock(h.path)
                l.lock()
                defer { l.unlock() }
                guard Darwin.rename(tmp.path, backing.path) == 0 else { throw ShrugError("Cannot store a download") }
                s.store.set(h.path, e)
            } else {
                if previous?.cached == true { unlink(backing.path) }
                s.store.set(h.path, e)
            }
        }
    }

    private func upload(_ s: Session, _ byKey: [String: StoredObject]) throws {
        let now = Date()
        for (path, e) in s.store.pending() {
            guard engine.isCurrent(s) else { return }
            if let at = e.changedAt, now.timeIntervalSince(at) < engine.debounce {
                engine.localChange()
                continue
            }
            let key = s.store.objectKey(path)
            if Store.isScratch(Store.name(path)) {
                // Never uploaded; a delete marker for one has nothing to replace.
                if e.kind == .deleted && byKey[key] == nil { s.store.drop(path) }
                continue
            }
            if e.kind == .deleted && e.etag == nil && byKey[key] == nil {
                s.store.drop(path) // never reached the bucket
                continue
            }
            let etag: String
            if e.kind == .file {
                etag = try uploadFile(path, e, key, s)
            } else {
                let h = ObjectHeader(path: path, kind: e.kind, editedAt: e.editedAt, mtime: e.mtime, size: 0,
                                     mode: e.mode, fileID: nil)
                etag = try s.storage.put(key, data: ObjectFormat.prefix(h, keys: s.keys, objectKey: key))
            }
            let backing = s.store.backingURL(path, e)
            s.store.update(path) { x in
                x.etag = etag
                guard x.gen == e.gen else { return } // changed again meanwhile: upload again next time
                x.dirty = false
                x.changedAt = nil
                if Store.fileClass(path) == .remote && x.kind == .file {
                    unlink(backing.path)
                    x.cached = false
                }
            }
        }
    }

    private func uploadFile(_ path: String, _ e: Entry, _ key: String, _ s: Session) throws -> String {
        let url = s.store.backingURL(path, e)
        let l = s.store.fileLock(path)
        l.lock()
        defer { l.unlock() }
        let fileID = try EncryptedFile(url: url, master: s.keys.master, writable: false,
                                       base: ObjectFormat.contentOffset).contentFileID
        let h = ObjectHeader(path: path, kind: .file, editedAt: e.editedAt, mtime: e.mtime, size: e.size,
                             mode: e.mode, fileID: fileID?.hex)
        try ObjectFormat.writeHeader(h, to: url, keys: s.keys, objectKey: key)
        return try s.storage.upload(key, from: url)
    }

    // MARK: - remote/ files

    /// Reads part of a remote/ file straight from the bucket, a few chunks at a time.
    func readRemote(_ path: String, offset: Int64, count: Int) -> Result<(Data, Bool), NFSStat> {
        guard let s = engine.session(), let e = s.store.entry(path), e.kind == .file else { return .failure(.stale) }
        if e.size == 0 || offset >= e.size { return .success((Data(), true)) }
        guard let etag = e.etag else { return .failure(.io) }
        let key = s.store.objectKey(path)
        let cs = Int64(EncFormat.chunkSize)
        let end = min(e.size, offset + Int64(count))
        do {
            var out = Data()
            for index in Int(offset / cs)...Int((end - 1) / cs) {
                let chunk = try plainChunk(s, key: key, etag: etag, size: e.size, index: index)
                let start = Int64(index) * cs
                let from = Int(max(offset, start) - start)
                let to = Int(min(end, start + Int64(chunk.count)) - start)
                if from < to { out.append(chunk.subdata(in: from..<to)) }
            }
            return .success((out, offset + Int64(out.count) >= e.size))
        } catch {
            engine.log("streaming failed: \(error)")
            return .failure(.io)
        }
    }

    private func cached(_ id: String) -> Data? {
        cacheLock.lock()
        defer { cacheLock.unlock() }
        return chunks[id]
    }

    private func remember(_ id: String, _ data: Data) {
        cacheLock.lock()
        defer { cacheLock.unlock() }
        if chunks[id] == nil { chunkOrder.append(id) }
        chunks[id] = data
        while chunkOrder.count > Replicator.maxCachedChunks { chunks[chunkOrder.removeFirst()] = nil }
    }

    private func plainChunk(_ s: Session, key: String, etag: String, size: Int64, index: Int) throws -> Data {
        let id = "\(key)@\(etag)#\(index)"
        if let c = cached(id) { return c }
        let cs = Int64(EncFormat.chunkSize)
        let count = Int((size + cs - 1) / cs)
        let last = min(count - 1, index + Replicator.readAhead - 1)
        func plainLength(_ i: Int) -> Int { Int(min(cs, size - Int64(i) * cs)) }
        func recordStart(_ i: Int) -> Int64 {
            ObjectFormat.contentOffset + Int64(EncFormat.headerSize) + Int64(i) * Int64(EncFormat.recordSize)
        }
        let idKey = "\(key)@\(etag)"
        cacheLock.lock()
        var known = fileIDs[idKey]
        cacheLock.unlock()
        if known == nil {
            let header = try s.storage.get(key, range: ObjectFormat.contentOffset...(ObjectFormat.contentOffset
                + Int64(EncFormat.headerSize) - 1))
            guard let fid = EncFormat.fileID(fromHeader: Data(header)) else { throw ShrugError("Damaged content") }
            known = fid
            cacheLock.lock()
            fileIDs[idKey] = fid
            cacheLock.unlock()
        }
        let fileID = known!
        let hi = recordStart(last) + Int64(plainLength(last) + EncFormat.overhead) - 1
        let data = Data(try s.storage.get(key, range: recordStart(index)...hi))
        var cursor = 0
        for i in index...last {
            let length = plainLength(i) + EncFormat.overhead
            guard cursor + length <= data.count else { throw ShrugError("Short read from the storage") }
            let plain = try EncFormat.openChunk(data.subdata(in: cursor..<(cursor + length)), master: s.keys.master,
                                                fileID: fileID, index: i)
            remember("\(key)@\(etag)#\(i)", plain)
            cursor += length
        }
        guard let c = cached(id) else { throw ShrugError("Read failed") }
        return c
    }

    /// Brings a remote/ file's content onto this Mac, so it can be changed.
    func fetchWhole(_ path: String) throws {
        guard let s = engine.session(), let e = s.store.entry(path), e.kind == .file else { throw ShrugError("Locked") }
        if e.cached { return }
        let backing = s.store.backingURL(path, e)
        let key = s.store.objectKey(path)
        let tmp = engine.paths.objectStore.appendingPathComponent(".tmp-\(UUID().uuidString)")
        defer { unlink(tmp.path) }
        if e.etag == nil {
            FileManager.default.createFile(atPath: tmp.path, contents: ObjectFormat.blankPrefix())
        } else {
            _ = try s.storage.download(key, to: tmp)
            guard try ObjectFormat.readHeader(of: tmp, keys: s.keys, objectKey: key).path == path else {
                throw ShrugError("The storage returned another file")
            }
        }
        chmod(tmp.path, 0o600)
        let l = s.store.fileLock(path)
        l.lock()
        defer { l.unlock() }
        guard Darwin.rename(tmp.path, backing.path) == 0 else { throw ShrugError("Cannot store a download") }
        s.store.update(path) { $0.cached = true }
    }

    /// Names of the profiles in the bucket.
    func profileNames(_ s: Session) throws -> [String] {
        var names: [String] = []
        for o in try s.storage.list(prefix: "m/p/") {
            if let p = try? s.keys.openMeta(Profile.self, s.storage.get(o.key, range: nil), key: o.key) { names.append(p.name) }
        }
        return names.sorted()
    }
}
