import Darwin
import Security
import Foundation

public enum NFSStat: UInt32, Error {
    case ok = 0, perm = 1, noent = 2, io = 5, acces = 13, exist = 17, xdev = 18, notdir = 20, isdir = 21
    case inval = 22, fbig = 27, nospc = 28, rofs = 30, nametoolong = 63, notempty = 66, stale = 70
    case badhandle = 10001, notsupp = 10004, serverfault = 10006
}

public struct NFSTime: Equatable, Sendable {
    public var sec: UInt32
    public var nsec: UInt32
    public init(sec: UInt32, nsec: UInt32) {
        self.sec = sec
        self.nsec = nsec
    }
}

public enum NFSFileType: UInt32, Sendable { case regular = 1, directory = 2 }

public struct NFSAttr: Sendable {
    public var type: NFSFileType
    public var mode: UInt32
    public var nlink: UInt32
    public var uid: UInt32
    public var gid: UInt32
    public var size: UInt64
    public var used: UInt64
    public var fileid: UInt64
    public var atime: NFSTime
    public var mtime: NFSTime
    public var ctime: NFSTime

    public init(type: NFSFileType, mode: UInt32, nlink: UInt32, uid: UInt32, gid: UInt32, size: UInt64,
                used: UInt64, fileid: UInt64, atime: NFSTime, mtime: NFSTime, ctime: NFSTime) {
        self.type = type
        self.mode = mode
        self.nlink = nlink
        self.uid = uid
        self.gid = gid
        self.size = size
        self.used = used
        self.fileid = fileid
        self.atime = atime
        self.mtime = mtime
        self.ctime = ctime
    }
}

public enum NFSTimeSet: Sendable { case unchanged, serverTime, client(NFSTime) }

public struct NFSSetAttrs: Sendable {
    public var mode: UInt32?
    public var size: UInt64?
    public var atime: NFSTimeSet = .unchanged
    public var mtime: NFSTimeSet = .unchanged
    public init() {}
}

public struct NFSContext: Sendable {
    public let uid: UInt32
    public let gid: UInt32
    public init(uid: UInt32, gid: UInt32) {
        self.uid = uid
        self.gid = gid
    }
}

public struct NFSDirEntry: Sendable {
    public let name: String
    public let id: UInt64
    public init(name: String, id: UInt64) {
        self.name = name
        self.id = id
    }
}

public struct NFSFSStat: Sendable {
    public var totalBytes: UInt64
    public var freeBytes: UInt64
    public var totalFiles: UInt64
    public var freeFiles: UInt64
    public init(totalBytes: UInt64, freeBytes: UInt64, totalFiles: UInt64, freeFiles: UInt64) {
        self.totalBytes = totalBytes
        self.freeBytes = freeBytes
        self.totalFiles = totalFiles
        self.freeFiles = freeFiles
    }
}

/// What the server needs from a file system. Ids are stable for the life of the mount.
public protocol NFSFileSystem: AnyObject {
    var rootID: UInt64 { get }
    func parent(_ id: UInt64) -> UInt64
    func getattr(_ id: UInt64) -> Result<NFSAttr, NFSStat>
    func lookup(_ dir: UInt64, _ name: String) -> Result<UInt64, NFSStat>
    func readdir(_ dir: UInt64) -> Result<[NFSDirEntry], NFSStat>
    func read(_ id: UInt64, offset: UInt64, count: UInt32, _ ctx: NFSContext) -> Result<(Data, Bool), NFSStat>
    func write(_ id: UInt64, offset: UInt64, data: Data, _ ctx: NFSContext) -> Result<Void, NFSStat>
    func create(_ dir: UInt64, _ name: String, mode: UInt32?, exclusive: Bool, _ ctx: NFSContext) -> Result<UInt64, NFSStat>
    func mkdir(_ dir: UInt64, _ name: String, mode: UInt32?, _ ctx: NFSContext) -> Result<UInt64, NFSStat>
    func remove(_ dir: UInt64, _ name: String, _ ctx: NFSContext) -> Result<Void, NFSStat>
    func rmdir(_ dir: UInt64, _ name: String, _ ctx: NFSContext) -> Result<Void, NFSStat>
    func rename(_ fromDir: UInt64, _ fromName: String, _ toDir: UInt64, _ toName: String, _ ctx: NFSContext) -> Result<Void, NFSStat>
    func setattr(_ id: UInt64, _ attrs: NFSSetAttrs, _ ctx: NFSContext) -> Result<Void, NFSStat>
    func fsstat() -> NFSFSStat
    var caseInsensitive: Bool { get }
}

/// MOUNT v3 and NFS v3 on one loopback TCP port.
public final class NFSServer {
    private let fs: NFSFileSystem
    private var rpc: RPCServer!
    private let writeVerifier = ShrugNFSRandom.bytes(8)
    /// Part of every file handle. Without it no request can name a file, and the only
    /// way to learn it is the MOUNT call, which is answered only while Shrug itself mounts.
    private let handleSecret = ShrugNFSRandom.bytes(16)
    private let gate = NSLock()
    private var mountWindow = false
    /// Users whose requests are served (this user and root).
    public var allowedUIDs: Set<UInt32> = [getuid(), 0]
    public var log: (String) -> Void = { _ in }

    /// Runs `body` (which runs mount_nfs) with the MOUNT call allowed.
    public func whileMounting<T>(_ body: () throws -> T) rethrows -> T {
        gate.lock(); mountWindow = true; gate.unlock()
        defer { gate.lock(); mountWindow = false; gate.unlock() }
        return try body()
    }

    public var port: UInt16 { rpc.port }

    public init(fs: NFSFileSystem, requireReservedPort: Bool = false) {
        self.fs = fs
        self.rpc = RPCServer(requireReservedPort: requireReservedPort) { [unowned self] call, out in
            self.dispatch(&call, &out)
        }
    }

    public func start() throws {
        rpc.log = { [weak self] in self?.log($0) }
        try rpc.start()
    }

    public func stop() { rpc.stop() }

    // MARK: - Dispatch

    private let trace = ProcessInfo.processInfo.environment["SHRUG_NFS_TRACE"] != nil

    private func dispatch(_ call: inout RPCCall, _ out: inout XDRWriter) -> AcceptStat {
        if trace { log("rpc prog=\(call.prog) vers=\(call.vers) proc=\(call.proc) uid=\(call.uid)") }
        do {
            switch (call.prog, call.vers) {
            case (100005, 3): return try mountProc(&call, &out)
            case (100003, 3): return try nfsProc(&call, &out)
            case (100005, _), (100003, _): return .progMismatch
            default: return .progUnavail
            }
        } catch {
            return .garbageArgs
        }
    }

    private func mountProc(_ call: inout RPCCall, _ out: inout XDRWriter) throws -> AcceptStat {
        switch call.proc {
        case 0: return .success
        case 1: // MNT
            _ = try call.args.string(max: 1024)
            gate.lock()
            let open = mountWindow
            gate.unlock()
            guard open else {
                log("refused MOUNT outside Shrug's own mount")
                out.u32(13) // MNT3ERR_ACCES
                return .success
            }
            out.u32(0)
            out.opaque(handle(fs.rootID))
            out.u32(1)
            out.u32(1) // AUTH_UNIX
            return .success
        case 2: // DUMP
            out.bool(false)
            return .success
        case 3, 4: // UMNT, UMNTALL
            return .success
        case 5: // EXPORT
            out.bool(true)
            out.string("/")
            out.bool(false)
            out.bool(false)
            return .success
        default: return .procUnavail
        }
    }

    private func nfsProc(_ call: inout RPCCall, _ out: inout XDRWriter) throws -> AcceptStat {
        let ctx = NFSContext(uid: call.uid, gid: call.gid)
        var a = call.args
        if call.proc != 0 && !allowedUIDs.contains(call.uid) {
            denied(call.proc, &out)
            return .success
        }
        switch call.proc {
        case 0: break
        case 1: getattr(&a, &out)
        case 2: try setattr(&a, &out, ctx)
        case 3: try lookup(&a, &out)
        case 4: try access(&a, &out)
        case 5: // READLINK
            _ = try a.opaque(max: 64)
            out.u32(NFSStat.notsupp.rawValue)
            out.bool(false)
        case 6: try read(&a, &out, ctx)
        case 7: try write(&a, &out, ctx)
        case 8: try create(&a, &out, ctx)
        case 9: try mkdir(&a, &out, ctx)
        case 10, 11: // SYMLINK, MKNOD
            out.u32(NFSStat.notsupp.rawValue)
            wccEmpty(&out)
        case 12, 13: try remove(&a, &out, ctx, directory: call.proc == 13)
        case 14: try rename(&a, &out, ctx)
        case 15: // LINK
            out.u32(NFSStat.notsupp.rawValue)
            out.bool(false)
            wccEmpty(&out)
        case 16: try readdir(&a, &out, plus: false)
        case 17: try readdir(&a, &out, plus: true)
        case 18: try fsstat(&a, &out)
        case 19: try fsinfo(&a, &out)
        case 20: try pathconf(&a, &out)
        case 21: try commit(&a, &out)
        default: return .procUnavail
        }
        return .success
    }

    /// "Permission denied" with the failure body each procedure expects.
    private func denied(_ proc: UInt32, _ out: inout XDRWriter) {
        out.u32(NFSStat.acces.rawValue)
        switch proc {
        case 1: break
        case 2, 7, 8, 9, 10, 11, 12, 13, 21: wccEmpty(&out)
        case 14: wccEmpty(&out); wccEmpty(&out)
        case 15: out.bool(false); wccEmpty(&out)
        default: out.bool(false)
        }
    }

    // MARK: - Encoding helpers

    private func handle(_ id: UInt64) -> Data {
        withUnsafeBytes(of: id.bigEndian) { Data($0) } + handleSecret
    }

    private func readHandle(_ a: inout XDRReader) throws -> UInt64? {
        let d = try a.opaque(max: 64)
        guard d.count == 24, d.suffix(16) == handleSecret else { return nil }
        return d.prefix(8).withUnsafeBytes { UInt64(bigEndian: $0.loadUnaligned(as: UInt64.self)) }
    }

    private func fattr(_ attr: NFSAttr, _ out: inout XDRWriter) {
        out.u32(attr.type.rawValue)
        out.u32(attr.mode)
        out.u32(attr.nlink)
        out.u32(attr.uid)
        out.u32(attr.gid)
        out.u64(attr.size)
        out.u64(attr.used)
        out.u32(0)
        out.u32(0) // rdev
        out.u64(1) // fsid
        out.u64(attr.fileid)
        for t in [attr.atime, attr.mtime, attr.ctime] {
            out.u32(t.sec)
            out.u32(t.nsec)
        }
    }

    private func postOpAttr(_ id: UInt64?, _ out: inout XDRWriter) {
        if let id, case .success(let attr) = fs.getattr(id) {
            out.bool(true)
            fattr(attr, &out)
        } else {
            out.bool(false)
        }
    }

    private func wcc(_ id: UInt64?, _ out: inout XDRWriter) {
        out.bool(false) // no pre-op attributes
        postOpAttr(id, &out)
    }

    private func wccEmpty(_ out: inout XDRWriter) {
        out.bool(false)
        out.bool(false)
    }

    private func readSattr(_ a: inout XDRReader) throws -> NFSSetAttrs {
        var s = NFSSetAttrs()
        if try a.bool() { s.mode = try a.u32() }
        if try a.bool() { _ = try a.u32() } // uid
        if try a.bool() { _ = try a.u32() } // gid
        if try a.bool() { s.size = try a.u64() }
        for i in 0..<2 {
            let how = try a.u32()
            var t = NFSTimeSet.unchanged
            if how == 1 { t = .serverTime }
            if how == 2 { t = .client(NFSTime(sec: try a.u32(), nsec: try a.u32())) }
            if i == 0 { s.atime = t } else { s.mtime = t }
        }
        return s
    }

    private func validName(_ name: String) -> NFSStat? {
        if name.isEmpty || name == "." || name == ".." || name.contains("/") || name.contains("\0") { return .inval }
        if name.utf8.count > 255 { return .nametoolong }
        return nil
    }

    // MARK: - Procedures

    private func getattr(_ a: inout XDRReader, _ out: inout XDRWriter) {
        guard let id = try? readHandle(&a) else {
            out.u32(NFSStat.badhandle.rawValue)
            return
        }
        switch fs.getattr(id) {
        case .success(let attr):
            out.u32(0)
            fattr(attr, &out)
        case .failure(let e):
            out.u32(e.rawValue)
        }
    }

    private func setattr(_ a: inout XDRReader, _ out: inout XDRWriter, _ ctx: NFSContext) throws {
        let id = try readHandle(&a)
        let s = try readSattr(&a)
        if try a.bool() { _ = try a.u32(); _ = try a.u32() } // guard ctime, ignored
        guard let id else {
            out.u32(NFSStat.badhandle.rawValue)
            wccEmpty(&out)
            return
        }
        let r = fs.setattr(id, s, ctx)
        if case .failure(let e) = r { out.u32(e.rawValue) } else { out.u32(0) }
        wcc(id, &out)
    }

    private func lookup(_ a: inout XDRReader, _ out: inout XDRWriter) throws {
        let dir = try readHandle(&a)
        let name = try a.string(max: 1024)
        guard let dir else {
            out.u32(NFSStat.badhandle.rawValue)
            out.bool(false)
            return
        }
        let result: Result<UInt64, NFSStat>
        if name == "." { result = .success(dir) }
        else if name == ".." { result = .success(fs.parent(dir)) }
        else { result = fs.lookup(dir, name) }
        switch result {
        case .success(let id):
            out.u32(0)
            out.opaque(handle(id))
            postOpAttr(id, &out)
            postOpAttr(dir, &out)
        case .failure(let e):
            out.u32(e.rawValue)
            postOpAttr(dir, &out)
        }
    }

    private func access(_ a: inout XDRReader, _ out: inout XDRWriter) throws {
        let id = try readHandle(&a)
        let wanted = try a.u32()
        guard let id, case .success(let attr) = fs.getattr(id) else {
            out.u32(NFSStat.stale.rawValue)
            out.bool(false)
            return
        }
        let owner = (attr.mode >> 6) & 7
        var granted: UInt32 = 0
        if owner & 4 != 0 { granted |= 0x01 | (attr.type == .directory ? 0x02 : 0) } // READ, LOOKUP
        if owner & 2 != 0 { granted |= 0x04 | 0x08 | 0x10 } // MODIFY, EXTEND, DELETE
        if owner & 1 != 0 { granted |= (attr.type == .directory ? 0x02 : 0x20) } // LOOKUP / EXECUTE
        out.u32(0)
        out.bool(true)
        fattr(attr, &out)
        out.u32(wanted & granted)
    }

    private func read(_ a: inout XDRReader, _ out: inout XDRWriter, _ ctx: NFSContext) throws {
        let id = try readHandle(&a)
        let offset = try a.u64()
        let count = try a.u32()
        guard let id else {
            out.u32(NFSStat.badhandle.rawValue)
            out.bool(false)
            return
        }
        switch fs.read(id, offset: offset, count: min(count, 1 << 20), ctx) {
        case .success(let (data, eof)):
            out.u32(0)
            postOpAttr(id, &out)
            out.u32(UInt32(data.count))
            out.bool(eof)
            out.opaque(data)
        case .failure(let e):
            out.u32(e.rawValue)
            postOpAttr(id, &out)
        }
    }

    private func write(_ a: inout XDRReader, _ out: inout XDRWriter, _ ctx: NFSContext) throws {
        let id = try readHandle(&a)
        let offset = try a.u64()
        _ = try a.u32() // count
        _ = try a.u32() // stable_how: we always write through
        let data = try a.opaque(max: 4 << 20)
        guard let id else {
            out.u32(NFSStat.badhandle.rawValue)
            wccEmpty(&out)
            return
        }
        switch fs.write(id, offset: offset, data: data, ctx) {
        case .success:
            out.u32(0)
            wcc(id, &out)
            out.u32(UInt32(data.count))
            out.u32(2) // FILE_SYNC
            out.fixed(writeVerifier)
        case .failure(let e):
            out.u32(e.rawValue)
            wcc(id, &out)
        }
    }

    private func create(_ a: inout XDRReader, _ out: inout XDRWriter, _ ctx: NFSContext) throws {
        let dir = try readHandle(&a)
        let name = try a.string(max: 1024)
        let how = try a.u32()
        var mode: UInt32?
        if how == 2 { _ = try a.fixed(8) } else { mode = try readSattr(&a).mode }
        guard let dir else {
            out.u32(NFSStat.badhandle.rawValue)
            wccEmpty(&out)
            return
        }
        if let bad = validName(name) {
            out.u32(bad.rawValue)
            wcc(dir, &out)
            return
        }
        newObject(fs.create(dir, name, mode: mode, exclusive: how != 0, ctx), dir: dir, &out)
    }

    private func mkdir(_ a: inout XDRReader, _ out: inout XDRWriter, _ ctx: NFSContext) throws {
        let dir = try readHandle(&a)
        let name = try a.string(max: 1024)
        let mode = try readSattr(&a).mode
        guard let dir else {
            out.u32(NFSStat.badhandle.rawValue)
            wccEmpty(&out)
            return
        }
        if let bad = validName(name) {
            out.u32(bad.rawValue)
            wcc(dir, &out)
            return
        }
        newObject(fs.mkdir(dir, name, mode: mode, ctx), dir: dir, &out)
    }

    private func newObject(_ r: Result<UInt64, NFSStat>, dir: UInt64, _ out: inout XDRWriter) {
        switch r {
        case .success(let id):
            out.u32(0)
            out.bool(true)
            out.opaque(handle(id))
            postOpAttr(id, &out)
            wcc(dir, &out)
        case .failure(let e):
            out.u32(e.rawValue)
            wcc(dir, &out)
        }
    }

    private func remove(_ a: inout XDRReader, _ out: inout XDRWriter, _ ctx: NFSContext, directory: Bool) throws {
        let dir = try readHandle(&a)
        let name = try a.string(max: 1024)
        guard let dir else {
            out.u32(NFSStat.badhandle.rawValue)
            wccEmpty(&out)
            return
        }
        let r = directory ? fs.rmdir(dir, name, ctx) : fs.remove(dir, name, ctx)
        if case .failure(let e) = r { out.u32(e.rawValue) } else { out.u32(0) }
        wcc(dir, &out)
    }

    private func rename(_ a: inout XDRReader, _ out: inout XDRWriter, _ ctx: NFSContext) throws {
        let from = try readHandle(&a)
        let fromName = try a.string(max: 1024)
        let to = try readHandle(&a)
        let toName = try a.string(max: 1024)
        guard let from, let to else {
            out.u32(NFSStat.badhandle.rawValue)
            wccEmpty(&out)
            wccEmpty(&out)
            return
        }
        let r: Result<Void, NFSStat> = validName(toName).map { .failure($0) } ?? fs.rename(from, fromName, to, toName, ctx)
        if case .failure(let e) = r { out.u32(e.rawValue) } else { out.u32(0) }
        wcc(from, &out)
        wcc(to, &out)
    }

    private func readdir(_ a: inout XDRReader, _ out: inout XDRWriter, plus: Bool) throws {
        let dir = try readHandle(&a)
        let cookie = try a.u64()
        _ = try a.fixed(8) // cookie verifier
        let limit: UInt32
        if plus {
            _ = try a.u32() // dircount
            limit = try a.u32()
        } else {
            limit = try a.u32()
        }
        guard let dir else {
            out.u32(NFSStat.badhandle.rawValue)
            out.bool(false)
            return
        }
        switch fs.readdir(dir) {
        case .failure(let e):
            out.u32(e.rawValue)
            postOpAttr(dir, &out)
        case .success(let listing):
            let all = [NFSDirEntry(name: ".", id: dir), NFSDirEntry(name: "..", id: fs.parent(dir))] + listing
            out.u32(0)
            postOpAttr(dir, &out)
            out.fixed(Data(count: 8))
            var budget = Int(limit) - 128
            var index = Int(cookie)
            var entries = XDRWriter()
            while index < all.count {
                let e = all[index]
                var one = XDRWriter()
                one.bool(true)
                one.u64(e.id)
                one.string(e.name)
                one.u64(UInt64(index + 1))
                if plus {
                    postOpAttr(e.id, &one)
                    one.bool(true)
                    one.opaque(handle(e.id))
                }
                if one.data.count > budget { break }
                budget -= one.data.count
                entries.append(one)
                index += 1
            }
            out.append(entries)
            out.bool(false)
            out.bool(index >= all.count)
        }
    }

    private func fsstat(_ a: inout XDRReader, _ out: inout XDRWriter) throws {
        let id = try readHandle(&a)
        let s = fs.fsstat()
        out.u32(0)
        postOpAttr(id, &out)
        out.u64(s.totalBytes)
        out.u64(s.freeBytes)
        out.u64(s.freeBytes)
        out.u64(s.totalFiles)
        out.u64(s.freeFiles)
        out.u64(s.freeFiles)
        out.u32(0)
    }

    private func fsinfo(_ a: inout XDRReader, _ out: inout XDRWriter) throws {
        let id = try readHandle(&a)
        out.u32(0)
        postOpAttr(id, &out)
        out.u32(1 << 20) // rtmax
        out.u32(65536) // rtpref
        out.u32(4096) // rtmult
        out.u32(1 << 20) // wtmax
        out.u32(65536) // wtpref
        out.u32(4096) // wtmult
        out.u32(65536) // dtpref
        out.u64(UInt64(Int64.max))
        out.u32(0)
        out.u32(1) // time_delta 1ns
        out.u32(0x08 | 0x10) // HOMOGENEOUS | CANSETTIME
    }

    private func pathconf(_ a: inout XDRReader, _ out: inout XDRWriter) throws {
        let id = try readHandle(&a)
        out.u32(0)
        postOpAttr(id, &out)
        out.u32(1) // linkmax
        out.u32(255) // name_max
        out.bool(true) // no_trunc
        out.bool(true) // chown_restricted
        out.bool(fs.caseInsensitive)
        out.bool(true) // case_preserving
    }

    private func commit(_ a: inout XDRReader, _ out: inout XDRWriter) throws {
        let id = try readHandle(&a)
        out.u32(0)
        wcc(id, &out)
        out.fixed(writeVerifier)
    }
}

enum ShrugNFSRandom {
    static func bytes(_ n: Int) -> Data {
        var d = Data(count: n)
        _ = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, n, $0.baseAddress!) }
        return d
    }
}
