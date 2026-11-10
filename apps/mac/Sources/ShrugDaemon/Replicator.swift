import CryptoKit
import Darwin
import Foundation
import ShrugCore
import ShrugNFS

/// Keeps ~/Shrug and the bucket in step, while unlocked and online.
///
/// - The newest edit of a file wins, using the edit time sealed inside each object. A Mac never
///   takes a version older than one it already has: if the bucket goes backwards, this Mac's
///   newer copy goes back up.
/// - Every write names the version it replaces, so a change another Mac made meanwhile is never
///   overwritten unseen: the write fails, and the next pass looks at that change first.
/// - A download is only used if its content is exactly what its sealed header describes.
/// - Deleting leaves a small sealed marker, so other Macs delete too. Shrug never removes
///   objects; one that disappears anyway is put back from this Mac's copy.
/// - synced/ files live on this Mac and in the bucket. remote/ files live in the bucket; reading
///   streams just the chunks needed, and changes stay here only until uploaded.
/// - A profile goes up only after the files its links point to, so other Macs never see a link
///   before its file.
final class Replicator {
    unowned let engine: Engine
    private let passLock = NSLock()
    private let cacheLock = NSLock()
    private var chunks: [String: Data] = [:]
    private var chunkOrder: [String] = []
    private var fileIDs: [String: Data] = [:]
    private var macNames: [String: String] = [:]
    /// The keyring version last found in the current format, so the check runs once per change.
    private var checkedKeyring: String?
    private var _online: Bool?
    private var _lastSync: Date?
    private var _problem: String?

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
        if synced { _lastSync = engine.clock.now() }
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
        checkedKeyring = nil
        cacheLock.unlock()
    }

    private var scratch: URL { engine.paths.objectStore.appendingPathComponent(".tmp-\(UUID().uuidString)") }

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
            var objects = try listing(s)
            guard engine.isCurrent(s) else { return }
            if try upgradeVault(s, objects) { objects = try listing(s) }
            try syncMacs(s, objects)
            let linksChanged = try downloadProfile(s, objects)
            try download(s, objects)
            try upload(s, objects)
            try uploadProfile(s)
            if linksChanged { engine.reconcileSoon() }
            if engine.stateCopy()?.everSynced == false { engine.updateState { $0.everSynced = true } }
            report(online: true, problem: nil, synced: true)
        } catch let e as StorageError {
            switch e {
            case .offline: report(online: false, problem: nil)
            case .conflict: engine.passSoon() // something changed under this pass: start over
            case .denied(let m): report(online: true, problem: "The storage refused this Mac's key (\(m))")
            default: report(online: true, problem: "\(e)")
            }
        } catch {
            report(online: true, problem: "\(error)")
        }
    }

    private func listing(_ s: Session) throws -> [String: StoredObject] {
        var byKey: [String: StoredObject] = [:]
        for o in try s.storage.list(prefix: "") { byKey[o.key] = o }
        // A listing without the vault is a wrong bucket or a broken answer: never act on it.
        guard byKey[VaultKeys.keyringKey] != nil else { throw ShrugError("The storage has no Shrug vault") }
        return byKey
    }

    /// Makes sure the vault is in this Shrug's format, upgrading it first if it's older.
    /// Returns whether it upgraded.
    private func upgradeVault(_ s: Session, _ objects: [String: StoredObject]) throws -> Bool {
        let keyring = objects[VaultKeys.keyringKey]?.version
        cacheLock.lock()
        let checked = checkedKeyring == keyring
        cacheLock.unlock()
        if checked { return false }
        let upgraded = try Migrations.upgradeVault(s.storage, keys: s.keys, objects: objects,
                                                   scratch: engine.paths.objectStore, log: engine.log)
        if !upgraded {
            cacheLock.lock()
            checkedKeyring = keyring
            cacheLock.unlock()
        }
        return upgraded
    }

    private func syncMacs(_ s: Session, _ objects: [String: StoredObject]) throws {
        guard let st = engine.stateCopy() else { return }
        let mine = VaultKeys.deviceKey(st.deviceID)
        if objects[mine] == nil {
            let record = DeviceRecord(name: st.deviceName, addedAt: engine.clock.nowMs)
            _ = try s.storage.put(mine, data: s.keys.sealMeta(record, key: mine), replacing: nil)
        }
        var names: [String] = objects[mine] == nil ? [st.deviceName] : []
        for o in objects.values where o.key.hasPrefix("m/d/") {
            cacheLock.lock()
            let known = macNames[o.key + "@" + o.version]
            cacheLock.unlock()
            if let known {
                names.append(known)
                continue
            }
            guard let rec = try? s.keys.openMeta(DeviceRecord.self, s.storage.get(o.key, version: o.version), key: o.key)
            else { continue }
            cacheLock.lock()
            macNames[o.key + "@" + o.version] = rec.name
            cacheLock.unlock()
            names.append(rec.name)
        }
        let sorted = names.sorted()
        if sorted != st.macs { engine.updateState { $0.macs = sorted } }
    }

    // MARK: - The profile

    /// Takes the profile from the bucket if it's newer than this Mac's. Returns whether the links changed.
    private func downloadProfile(_ s: Session, _ objects: [String: StoredObject]) throws -> Bool {
        guard let st = engine.stateCopy(), let name = st.profile else { return false }
        let key = s.keys.profileKey(name)
        guard let obj = objects[key], obj.version != st.profileVersion else { return false }
        let p = try s.keys.openMeta(Profile.self, s.storage.get(key, version: obj.version), key: key)
        if p.editedAt < st.profileEditedAt ?? .distantPast {
            // Older than this Mac's: ours replaces it (newer edits here, or the bucket went backwards).
            engine.updateState {
                $0.profileVersion = obj.version
                $0.profileDirty = true
            }
            return false
        }
        if st.profileDirty && p.editedAt == st.profileEditedAt {
            engine.updateState { $0.profileVersion = obj.version }
            return false
        }
        engine.updateState {
            $0.links = p.links
            $0.profileEditedAt = p.editedAt
            $0.profileVersion = obj.version
            $0.profileDirty = false
        }
        return p.links != st.links
    }

    private func uploadProfile(_ s: Session) throws {
        guard let st = engine.stateCopy(), st.profileDirty, let name = st.profile else { return }
        if st.links.contains(where: { s.store.rawEntry($0.target)?.dirty == true }) { return } // its files go first
        let key = s.keys.profileKey(name)
        let p = Profile(name: name, links: st.links, editedAt: st.profileEditedAt ?? engine.clock.nowMs)
        let version = try s.storage.put(key, data: s.keys.sealMeta(p, key: key), replacing: st.profileVersion)
        engine.updateState {
            if $0.profileGen == st.profileGen { $0.profileDirty = false }
            $0.profileVersion = version
        }
    }

    // MARK: - Files

    private func download(_ s: Session, _ objects: [String: StoredObject]) throws {
        for obj in objects.values.sorted(by: { $0.key < $1.key }) where obj.key.hasPrefix("f/") {
            guard engine.isCurrent(s) else { return }
            if let p = s.store.path(forObjectKey: obj.key), s.store.rawEntry(p)?.version == obj.version { continue }
            do {
                try take(obj, s)
            } catch StorageError.conflict {
                engine.passSoon() // replaced since the listing: the next pass sees the new one
            }
        }
        restoreMissing(s, objects)
    }

    /// Looks at one object this Mac hasn't seen, and uses it if it's newer than what's here.
    private func take(_ obj: StoredObject, _ s: Session) throws {
        let prefix = try s.storage.get(obj.key, range: 0...(ObjectFormat.contentOffset - 1), version: obj.version)
        guard let h = try? ObjectFormat.decodeHeader(prefix, keys: s.keys, objectKey: obj.key),
              s.keys.objectKey(h.path) == obj.key, let cls = Store.fileClass(h.path), cls != .local else {
            engine.log("skipped an object that doesn't open with this vault")
            return
        }
        if let local = s.store.rawEntry(h.path) {
            if local.dirty && local.editedAt >= h.editedAt {
                s.store.update(h.path) { $0.version = obj.version } // ours is newer and will replace it
                return
            }
            if local.editedAt > h.editedAt {
                // Older than what this Mac already has: the bucket went backwards.
                if local.kind == .file && !s.store.hasLocalCopy(h.path, local) {
                    engine.notify("The storage went back to an older \(h.path); Shrug won't use it")
                    return
                }
                s.store.update(h.path) {
                    $0.version = obj.version
                    $0.dirty = true
                }
                engine.notify("The storage went back to an older \(h.path); this Mac's newer copy went up again")
                return
            }
        }
        try apply(h, obj, s)
    }

    private func apply(_ h: ObjectHeader, _ obj: StoredObject, _ s: Session) throws {
        if h.kind == .file && !h.fitsSize(of: obj) {
            engine.notify("The storage's copy of \(h.path) is damaged or was changed outside Shrug; Shrug won't use it")
            return
        }
        let previous = s.store.rawEntry(h.path)
        var e = Entry(h, version: obj.version)
        e.gen = (previous?.gen ?? 0) + 1
        var download: URL?
        defer { download.map { _ = unlink($0.path) } }
        if h.kind == .file && Store.fileClass(h.path) == .synced {
            let tmp = scratch
            download = tmp
            guard try s.storage.download(obj.key, to: tmp, version: obj.version) == obj.version else {
                throw StorageError.conflict
            }
            guard let checked = try? ObjectFormat.verifiedHeader(of: tmp, keys: s.keys, objectKey: obj.key), checked == h else {
                engine.notify("The storage's copy of \(h.path) is damaged or was changed outside Shrug; kept this Mac's")
                return
            }
            chmod(tmp.path, 0o600)
        }
        let l = s.store.fileLock(h.path)
        l.lock()
        defer { l.unlock() }
        // Changed here while downloading: the next pass decides again.
        guard s.store.rawEntry(h.path)?.gen == previous?.gen else { return }
        if let download {
            guard Darwin.rename(download.path, s.store.backingURL(h.path, e).path) == 0 else {
                throw ShrugError("Cannot store a download")
            }
        } else if let previous, previous.kind == .file, s.store.hasLocalCopy(h.path, previous) {
            unlink(s.store.backingURL(h.path, previous).path)
        }
        s.store.set(h.path, e)
    }

    /// Shrug never deletes objects, so one missing from the listing was removed by something
    /// else: a person, a lifecycle rule, the provider. This Mac's copy goes back up; a remote/
    /// file whose content only the bucket had is gone.
    private func restoreMissing(_ s: Session, _ objects: [String: StoredObject]) {
        for (p, e) in s.store.all() where Store.fileClass(p) != .local && !e.dirty && e.version != nil
            && objects[s.store.objectKey(p)] == nil {
            if e.kind == .file && !s.store.hasLocalCopy(p, e) {
                s.store.drop(p)
                engine.notify("\(p) was removed from the storage outside Shrug, and only the storage had it")
                continue
            }
            s.store.update(p) {
                $0.dirty = true
                $0.version = nil
            }
            if e.kind == .file { engine.notify("\(p) was missing from the storage; this Mac's copy went back up") }
        }
    }

    private func upload(_ s: Session, _ objects: [String: StoredObject]) throws {
        let now = engine.clock.now()
        for (path, e) in s.store.pending() {
            guard engine.isCurrent(s) else { return }
            if let at = e.changedAt, now.timeIntervalSince(at) < engine.debounce {
                engine.localChange()
                continue
            }
            let key = s.store.objectKey(path)
            if Store.isScratch(Store.name(path)) {
                // Never uploaded; a delete marker for one has nothing to replace.
                if e.kind == .deleted && objects[key] == nil { s.store.drop(path) }
                continue
            }
            if e.kind == .deleted && e.version == nil && objects[key] == nil {
                s.store.drop(path) // never reached the bucket
                continue
            }
            do {
                if e.kind == .file {
                    try uploadFile(path, key, s)
                } else {
                    let h = ObjectHeader(path: path, kind: e.kind, editedAt: e.editedAt, mtime: e.mtime, size: 0,
                                         mode: e.mode, fileID: nil)
                    let version = try s.storage.put(key, data: ObjectFormat.prefix(h, keys: s.keys, objectKey: key),
                                                    replacing: e.version)
                    s.store.uploaded(path, gen: e.gen, version: version, sealedCopy: nil)
                }
            } catch StorageError.conflict {
                engine.passSoon() // changed in the bucket meanwhile: the next pass looks at it first
            }
        }
    }

    /// Seals a copy of the file under a fresh file id (holding its lock only for that), and
    /// uploads the copy.
    private func uploadFile(_ path: String, _ key: String, _ s: Session) throws {
        let l = s.store.fileLock(path)
        let sealed = scratch
        defer { unlink(sealed.path) }
        l.lock()
        guard let e = s.store.entry(path), e.kind == .file, e.dirty else { return l.unlock() }
        let copy: EncryptedFile
        do {
            copy = try s.store.open(path, writable: false).reencrypt(to: sealed, prefix: ObjectFormat.blankPrefix())
        } catch {
            l.unlock()
            throw error
        }
        l.unlock()
        let h = ObjectHeader(path: path, kind: .file, editedAt: e.editedAt, mtime: e.mtime, size: copy.size,
                             mode: e.mode, fileID: copy.contentFileID?.hex)
        try ObjectFormat.writeHeader(h, to: sealed, keys: s.keys, objectKey: key)
        let version = try s.storage.upload(key, from: sealed, replacing: e.version)
        l.lock()
        defer { l.unlock() }
        if !s.store.uploaded(path, gen: e.gen, version: version, sealedCopy: sealed) {
            engine.log("kept the earlier local copy after an upload: \(String(cString: strerror(errno)))")
        }
    }

    // MARK: - remote/ files

    /// Reads part of a remote/ file straight from the bucket, a few chunks at a time.
    func readRemote(_ path: String, offset: Int64, count: Int) -> Result<(Data, Bool), NFSStat> {
        guard let s = engine.session(), let e = s.store.entry(path), e.kind == .file else { return .failure(.stale) }
        if e.size == 0 || offset >= e.size { return .success((Data(), true)) }
        guard let version = e.version else { return .failure(.io) }
        let key = s.store.objectKey(path)
        let cs = Int64(EncFormat.chunkSize)
        let end = min(e.size, offset + Int64(count))
        do {
            var out = Data()
            for index in Int(offset / cs)...Int((end - 1) / cs) {
                let chunk = try plainChunk(s, path, e, key: key, version: version, index: index)
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

    /// The file id of the version this Mac took, read from the bucket once: the sealed header
    /// must be the one this Mac knows, and the content must carry the id that header names.
    private func remoteFileID(_ s: Session, _ path: String, _ e: Entry, key: String, version: String) throws -> Data {
        let id = "\(key)@\(version)"
        cacheLock.lock()
        let known = fileIDs[id]
        cacheLock.unlock()
        if let known { return known }
        let end = ObjectFormat.contentOffset + Int64(EncFormat.headerSize)
        let data = try s.storage.get(key, range: 0...(end - 1), version: version)
        guard data.count == Int(end), let h = try? ObjectFormat.decodeHeader(data, keys: s.keys, objectKey: key),
              h.path == path, h.kind == .file, h.editedAt == e.editedAt, h.size == e.size,
              let fileID = EncFormat.fileID(fromHeader: data.subdata(in: Int(ObjectFormat.contentOffset)..<Int(end))),
              fileID.hex == h.fileID
        else { throw ShrugError("The storage's copy of a remote file isn't the version this Mac knows") }
        cacheLock.lock()
        fileIDs[id] = fileID
        cacheLock.unlock()
        return fileID
    }

    private func plainChunk(_ s: Session, _ path: String, _ e: Entry, key: String, version: String, index: Int) throws -> Data {
        let id = "\(key)@\(version)#\(index)"
        if let c = cached(id) { return c }
        let fileID = try remoteFileID(s, path, e, key: key, version: version)
        let cs = Int64(EncFormat.chunkSize)
        let count = Int((e.size + cs - 1) / cs)
        let last = min(count - 1, index + Replicator.readAhead - 1)
        func plainLength(_ i: Int) -> Int { Int(min(cs, e.size - Int64(i) * cs)) }
        func recordStart(_ i: Int) -> Int64 {
            ObjectFormat.contentOffset + Int64(EncFormat.headerSize) + Int64(i) * Int64(EncFormat.recordSize)
        }
        let hi = recordStart(last) + Int64(plainLength(last) + EncFormat.overhead) - 1
        let data = try s.storage.get(key, range: recordStart(index)...hi, version: version)
        var cursor = data.startIndex
        for i in index...last {
            let length = plainLength(i) + EncFormat.overhead
            guard cursor + length <= data.endIndex else { throw ShrugError("Short read from the storage") }
            let plain = try EncFormat.openChunk(data.subdata(in: cursor..<(cursor + length)), master: s.keys.master,
                                                fileID: fileID, index: i)
            remember("\(key)@\(version)#\(i)", plain)
            cursor += length
        }
        guard let c = cached(id) else { throw ShrugError("Read failed") }
        return c
    }

    /// Brings a remote/ file's content onto this Mac, so it can be changed. Only the version this
    /// Mac took, whose size was checked then. Its errors go to the log, so they never name the file.
    func fetchWhole(_ path: String) throws {
        guard let s = engine.session(), let e = s.store.entry(path), e.kind == .file else { throw ShrugError("Locked") }
        if e.cached { return }
        guard let version = e.version else { throw ShrugError("The file hasn't been seen in the storage yet") }
        let key = s.store.objectKey(path)
        let tmp = scratch
        defer { unlink(tmp.path) }
        guard try s.storage.download(key, to: tmp, version: version) == version else { throw StorageError.conflict }
        let h = try ObjectFormat.verifiedHeader(of: tmp, keys: s.keys, objectKey: key)
        guard h.path == path, h.editedAt == e.editedAt else { throw ShrugError("The storage returned another version of the file") }
        chmod(tmp.path, 0o600)
        let l = s.store.fileLock(path)
        l.lock()
        defer { l.unlock() }
        guard Darwin.rename(tmp.path, s.store.backingURL(path, e).path) == 0 else { throw ShrugError("Cannot store a download") }
        s.store.update(path) { $0.cached = true }
    }

    /// Names of the profiles in the bucket.
    func profileNames(_ s: Session) throws -> [String] {
        var names: [String] = []
        for o in try s.storage.list(prefix: "m/p/") {
            if let p = try? s.keys.openMeta(Profile.self, s.storage.get(o.key, version: o.version), key: o.key) {
                names.append(p.name)
            }
        }
        return names.sorted()
    }
}

extension ObjectHeader {
    /// Whether a file object is exactly as big as this sealed header says, within the file size
    /// limit. One that isn't was changed outside Shrug and could be any size, so it's refused
    /// before anything downloads it.
    func fitsSize(of obj: StoredObject) -> Bool {
        (0...Int64(VaultFS.maxFileSize)).contains(size) && obj.size == ObjectFormat.objectSize(plainSize: size)
    }
}
