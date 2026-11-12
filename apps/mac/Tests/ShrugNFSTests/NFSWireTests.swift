import Darwin
import XCTest
@testable import ShrugNFS

/// An in-memory file system with folders, so every procedure can be driven over the wire.
final class TreeFS: NFSFileSystem {
    private struct Node {
        var parent: UInt64
        var name: String
        var isDir: Bool
        var data = Data()
        var mode: UInt32
    }

    var rootID: UInt64 { 1 }
    let maxFileSize: UInt64 = 1 << 20
    let caseInsensitive = false
    private let lock = NSLock()
    private var nodes: [UInt64: Node] = [1: Node(parent: 1, name: "", isDir: true, mode: 0o700)]
    private var next: UInt64 = 2
    /// The files asked to be put on the disk, in order.
    private(set) var committed: [UInt64] = []
    var commitFails = false

    private func child(_ dir: UInt64, _ name: String) -> UInt64? {
        nodes.first { $0.key != 1 && $0.value.parent == dir && $0.value.name == name }?.key
    }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }

    func parent(_ id: UInt64) -> UInt64 { locked { nodes[id]?.parent ?? 1 } }

    func getattr(_ id: UInt64) -> Result<NFSAttr, NFSStat> {
        locked {
            guard let n = nodes[id] else { return .failure(.stale) }
            let t = NFSTime(sec: 1, nsec: 0)
            return .success(NFSAttr(type: n.isDir ? .directory : .regular, mode: n.mode, nlink: n.isDir ? 2 : 1,
                                    uid: getuid(), gid: getgid(), size: UInt64(n.data.count), used: UInt64(n.data.count),
                                    fileid: id, atime: t, mtime: t, ctime: t))
        }
    }

    func lookup(_ dir: UInt64, _ name: String) -> Result<UInt64, NFSStat> {
        locked {
            guard let d = nodes[dir] else { return .failure(.stale) }
            guard d.isDir else { return .failure(.notdir) }
            return child(dir, name).map { .success($0) } ?? .failure(.noent)
        }
    }

    func readdir(_ dir: UInt64) -> Result<[NFSDirEntry], NFSStat> {
        locked {
            guard let d = nodes[dir], d.isDir else { return .failure(.notdir) }
            return .success(nodes.filter { $0.key != 1 && $0.value.parent == dir }
                .map { NFSDirEntry(name: $0.value.name, id: $0.key) }.sorted { $0.name < $1.name })
        }
    }

    func read(_ id: UInt64, offset: UInt64, count: UInt32, _ ctx: NFSContext) -> Result<(Data, Bool), NFSStat> {
        locked {
            guard let n = nodes[id] else { return .failure(.stale) }
            guard !n.isDir else { return .failure(.isdir) }
            let start = min(Int(offset), n.data.count)
            let end = min(start + Int(count), n.data.count)
            return .success((n.data.subdata(in: start..<end), end == n.data.count))
        }
    }

    func write(_ id: UInt64, offset: UInt64, data: Data, _ ctx: NFSContext) -> Result<Void, NFSStat> {
        locked {
            guard var n = nodes[id] else { return .failure(.stale) }
            guard !n.isDir else { return .failure(.isdir) }
            let end = Int(offset) + data.count
            if n.data.count < end { n.data.append(Data(count: end - n.data.count)) }
            n.data.replaceSubrange(Int(offset)..<end, with: data)
            nodes[id] = n
            return .success(())
        }
    }

    func commit(_ id: UInt64, _ ctx: NFSContext) -> Result<Void, NFSStat> {
        locked {
            guard nodes[id] != nil else { return .failure(.stale) }
            if commitFails { return .failure(.io) }
            committed.append(id)
            return .success(())
        }
    }

    private func make(_ dir: UInt64, _ name: String, isDir: Bool, mode: UInt32?, exclusive: Bool) -> Result<UInt64, NFSStat> {
        locked {
            guard let d = nodes[dir] else { return .failure(.stale) }
            guard d.isDir else { return .failure(.notdir) }
            if let existing = child(dir, name) {
                return exclusive || isDir || nodes[existing]!.isDir ? .failure(.exist) : .success(existing)
            }
            let id = next
            next += 1
            nodes[id] = Node(parent: dir, name: name, isDir: isDir, mode: (mode ?? 0o600) & 0o777)
            return .success(id)
        }
    }

    func create(_ dir: UInt64, _ name: String, mode: UInt32?, exclusive: Bool, _ ctx: NFSContext) -> Result<UInt64, NFSStat> {
        make(dir, name, isDir: false, mode: mode, exclusive: exclusive)
    }

    func mkdir(_ dir: UInt64, _ name: String, mode: UInt32?, _ ctx: NFSContext) -> Result<UInt64, NFSStat> {
        make(dir, name, isDir: true, mode: mode ?? 0o700, exclusive: true)
    }

    func remove(_ dir: UInt64, _ name: String, _ ctx: NFSContext) -> Result<Void, NFSStat> {
        locked {
            guard let id = child(dir, name) else { return .failure(.noent) }
            guard !nodes[id]!.isDir else { return .failure(.isdir) }
            nodes[id] = nil
            return .success(())
        }
    }

    func rmdir(_ dir: UInt64, _ name: String, _ ctx: NFSContext) -> Result<Void, NFSStat> {
        locked {
            guard let id = child(dir, name) else { return .failure(.noent) }
            guard nodes[id]!.isDir else { return .failure(.notdir) }
            guard !nodes.contains(where: { $0.value.parent == id && $0.key != id }) else { return .failure(.notempty) }
            nodes[id] = nil
            return .success(())
        }
    }

    func rename(_ fromDir: UInt64, _ fromName: String, _ toDir: UInt64, _ toName: String,
                _ ctx: NFSContext) -> Result<Void, NFSStat> {
        locked {
            guard let id = child(fromDir, fromName) else { return .failure(.noent) }
            guard nodes[toDir]?.isDir == true else { return .failure(.notdir) }
            if let existing = child(toDir, toName), existing != id {
                guard !nodes[existing]!.isDir else { return .failure(.isdir) }
                nodes[existing] = nil
            }
            nodes[id]!.parent = toDir
            nodes[id]!.name = toName
            return .success(())
        }
    }

    func setattr(_ id: UInt64, _ attrs: NFSSetAttrs, _ ctx: NFSContext) -> Result<Void, NFSStat> {
        locked {
            guard var n = nodes[id] else { return .failure(.stale) }
            if let size = attrs.size {
                guard !n.isDir else { return .failure(.isdir) }
                if Int(size) < n.data.count { n.data = n.data.prefix(Int(size)) } else {
                    n.data.append(Data(count: Int(size) - n.data.count))
                }
            }
            if let mode = attrs.mode { n.mode = mode & 0o777 }
            nodes[id] = n
            return .success(())
        }
    }

    func fsstat() -> NFSFSStat { NFSFSStat(totalBytes: 1 << 30, freeBytes: 1 << 29, totalFiles: 1000, freeFiles: 900) }
}

/// Repeatable randomness for fuzzing (SplitMix64), so a failure can be replayed from its seed.
struct SeededRandom: RandomNumberGenerator {
    var state: UInt64
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

/// Reading replies exactly as RFC 1813 lays them out.
extension XDRReader {
    var atEnd: Bool { pos == data.count }

    /// fattr3, if present. Returns (type, mode, size).
    @discardableResult
    mutating func postOpAttr() throws -> (type: UInt32, mode: UInt32, size: UInt64)? {
        guard try bool() else { return nil }
        let type = try u32()
        let mode = try u32()
        _ = try u32() // nlink
        _ = try u32() // uid
        _ = try u32() // gid
        let size = try u64()
        _ = try u64() // used
        _ = try u64() // rdev
        _ = try u64() // fsid
        _ = try u64() // fileid
        for _ in 0..<3 { _ = try u64() } // atime, mtime, ctime
        return (type, mode, size)
    }

    mutating func wcc() throws {
        if try bool() { _ = try u64(); _ = try u64(); _ = try u64() } // pre-op size, mtime, ctime
        try postOpAttr()
    }
}

final class NFSWireTests: XCTestCase {
    var fs: TreeFS!
    var server: NFSServer!
    var c: RPCClient!
    var root = Data()

    override func setUpWithError() throws {
        fs = TreeFS()
        server = NFSServer(fs: fs)
        try server.start()
        c = try RPCClient(port: server.port)
        var handle: Data?
        try server.whileMounting {
            var r = try c.call(prog: 100005, proc: 1) { $0.string("/") }
            XCTAssertEqual(try r.u32(), 0)
            handle = try r.opaque()
        }
        root = try XCTUnwrap(handle)
    }

    override func tearDown() {
        server.stop()
    }

    func nfs(_ proc: UInt32, uid: UInt32 = getuid(), _ args: (inout XDRWriter) -> Void = { _ in }) throws -> XDRReader {
        try c.call(prog: 100003, proc: proc, uid: uid, args)
    }

    func sattr(mode: UInt32? = nil, size: UInt64? = nil, _ w: inout XDRWriter) {
        w.bool(mode != nil); if let mode { w.u32(mode) }
        w.bool(false) // uid
        w.bool(false) // gid
        w.bool(size != nil); if let size { w.u64(size) }
        w.u32(0) // atime: don't change
        w.u32(0) // mtime: don't change
    }

    /// CREATE (UNCHECKED): status, and the new handle.
    func create(_ dir: Data, _ name: String, mode: UInt32 = 0o600) throws -> (UInt32, Data?) {
        var r = try nfs(8) {
            $0.opaque(dir)
            $0.string(name)
            $0.u32(0)
            self.sattr(mode: mode, &$0)
        }
        let status = try r.u32()
        var handle: Data?
        if status == 0 {
            XCTAssertTrue(try r.bool())
            handle = try r.opaque()
            XCTAssertEqual(try r.postOpAttr()?.type, 1)
        }
        try r.wcc()
        XCTAssertTrue(r.atEnd, "CREATE reply has exactly its fields")
        return (status, handle)
    }

    func lookup(_ dir: Data, _ name: String) throws -> (UInt32, Data?) {
        var r = try nfs(3) {
            $0.opaque(dir)
            $0.string(name)
        }
        let status = try r.u32()
        var handle: Data?
        if status == 0 {
            handle = try r.opaque()
            try r.postOpAttr()
        }
        try r.postOpAttr()
        XCTAssertTrue(r.atEnd, "LOOKUP reply has exactly its fields")
        return (status, handle)
    }

    /// `stable` is what the kernel asks for: 0 (UNSTABLE: a COMMIT follows) or 2 (FILE_SYNC).
    func write(_ file: Data, _ offset: UInt64, _ data: Data, stable: UInt32 = 2) throws -> UInt32 {
        var r = try nfs(7) {
            $0.opaque(file)
            $0.u64(offset)
            $0.u32(UInt32(data.count))
            $0.u32(stable)
            $0.opaque(data)
        }
        let status = try r.u32()
        try r.wcc()
        if status == 0 {
            XCTAssertEqual(try r.u32(), UInt32(data.count))
            XCTAssertEqual(try r.u32(), stable == 0 ? 0 : 2, "committed only as far as asked")
            _ = try r.fixed(8)
        }
        XCTAssertTrue(r.atEnd, "WRITE reply has exactly its fields")
        return status
    }

    /// COMMIT; returns the status and the write verifier.
    func commit(_ file: Data) throws -> (UInt32, Data?) {
        var r = try nfs(21) {
            $0.opaque(file)
            $0.u64(0)
            $0.u32(0)
        }
        let status = try r.u32()
        try r.wcc()
        let verifier = status == 0 ? try r.fixed(8) : nil
        XCTAssertTrue(r.atEnd, "COMMIT reply has exactly its fields")
        return (status, verifier)
    }

    func read(_ file: Data, _ offset: UInt64 = 0, _ count: UInt32 = 1 << 16) throws -> (Data, Bool) {
        var r = try nfs(6) {
            $0.opaque(file)
            $0.u64(offset)
            $0.u32(count)
        }
        XCTAssertEqual(try r.u32(), 0)
        try r.postOpAttr()
        let n = try r.u32()
        let eof = try r.bool()
        let data = try r.opaque()
        XCTAssertEqual(Int(n), data.count)
        XCTAssertTrue(r.atEnd, "READ reply has exactly its fields")
        return (data, eof)
    }

    func size(_ handle: Data) throws -> UInt64 {
        var r = try nfs(1) { $0.opaque(handle) }
        XCTAssertEqual(try r.u32(), 0)
        _ = try r.u32() // type
        _ = try r.u32() // mode
        _ = try r.u32()
        _ = try r.u32()
        _ = try r.u32()
        return try r.u64()
    }

    /// Every entry of a folder, following cookies page by page with a small reply budget.
    func list(_ dir: Data, plus: Bool, count: UInt32) throws -> [(name: String, handle: Data?)] {
        var out: [(String, Data?)] = []
        var cookie: UInt64 = 0
        for _ in 0..<1000 {
            var r = try nfs(plus ? 17 : 16) {
                $0.opaque(dir)
                $0.u64(cookie)
                $0.fixed(Data(count: 8))
                $0.u32(count)
                if plus { $0.u32(count) }
            }
            XCTAssertEqual(try r.u32(), 0)
            try r.postOpAttr()
            _ = try r.fixed(8)
            var page = 0
            while try r.bool() {
                _ = try r.u64() // fileid
                let name = try r.string()
                cookie = try r.u64()
                var handle: Data?
                if plus {
                    try r.postOpAttr()
                    if try r.bool() { handle = try r.opaque() }
                }
                out.append((name, handle))
                page += 1
            }
            let eof = try r.bool()
            XCTAssertTrue(r.atEnd, "READDIR reply has exactly its fields")
            if eof { return out }
            if page == 0 { XCTFail("a page with nothing in it, and not the end"); return out }
        }
        XCTFail("never reached the end")
        return out
    }

    // MARK: - Tests

    func testCreateWriteReadTruncateRemove() throws {
        let (status, file) = try create(root, "id_ed25519")
        XCTAssertEqual(status, 0)
        let f = try XCTUnwrap(file)
        XCTAssertEqual(try write(f, 0, Data("PRIVATE KEY".utf8)), 0)
        XCTAssertEqual(try read(f).0, Data("PRIVATE KEY".utf8))
        let part = try read(f, 8, 2)
        XCTAssertEqual(part.0, Data("KE".utf8))
        XCTAssertFalse(part.1, "not the end yet")

        var r = try nfs(2) {
            $0.opaque(f)
            self.sattr(size: 7, &$0)
            $0.bool(false) // no ctime guard
        }
        XCTAssertEqual(try r.u32(), 0)
        try r.wcc()
        XCTAssertTrue(r.atEnd, "SETATTR reply has exactly its fields")
        XCTAssertEqual(try size(f), 7)
        let cut = try read(f)
        XCTAssertEqual(cut.0, Data("PRIVATE".utf8))
        XCTAssertTrue(cut.1)

        var gone = try nfs(12) {
            $0.opaque(self.root)
            $0.string("id_ed25519")
        }
        XCTAssertEqual(try gone.u32(), 0)
        try gone.wcc()
        XCTAssertTrue(gone.atEnd)
        XCTAssertEqual(try lookup(root, "id_ed25519").0, NFSStat.noent.rawValue)
    }

    func testExclusiveCreateAndBadNamesAreRefused() throws {
        XCTAssertEqual(try create(root, "f").0, 0)
        var r = try nfs(8) {
            $0.opaque(self.root)
            $0.string("f")
            $0.u32(2) // EXCLUSIVE
            $0.fixed(Data(count: 8))
        }
        XCTAssertEqual(try r.u32(), NFSStat.exist.rawValue)
        try r.wcc()
        XCTAssertTrue(r.atEnd)
        for bad in ["", ".", "..", "a/b", "nul\0byte"] {
            XCTAssertEqual(try create(root, bad).0, NFSStat.inval.rawValue, "'\(bad)'")
        }
        XCTAssertEqual(try create(root, String(repeating: "x", count: 256)).0, NFSStat.nametoolong.rawValue)
    }

    func testFoldersRenamesAndListingsWithAttributes() throws {
        var mk = try nfs(9) {
            $0.opaque(self.root)
            $0.string("ssh")
            self.sattr(mode: 0o700, &$0)
        }
        XCTAssertEqual(try mk.u32(), 0)
        XCTAssertTrue(try mk.bool())
        let ssh = try mk.opaque()
        XCTAssertEqual(try mk.postOpAttr()?.type, 2)
        try mk.wcc()
        XCTAssertTrue(mk.atEnd, "MKDIR reply has exactly its fields")

        let key = try XCTUnwrap(try create(ssh, "id").1)
        XCTAssertEqual(try write(key, 0, Data("k".utf8)), 0)

        // READDIRPLUS hands out handles that work.
        let listing = try list(root, plus: true, count: 512)
        XCTAssertEqual(listing.map(\.name), [".", "..", "ssh"])
        let fromListing = try XCTUnwrap(listing.last?.handle)
        XCTAssertEqual(try lookup(fromListing, "id").0, 0)

        // RENAME across folders, then the old name is gone and the new one reads.
        var mv = try nfs(14) {
            $0.opaque(ssh)
            $0.string("id")
            $0.opaque(self.root)
            $0.string("moved")
        }
        XCTAssertEqual(try mv.u32(), 0)
        try mv.wcc()
        try mv.wcc()
        XCTAssertTrue(mv.atEnd, "RENAME reply has exactly its fields")
        XCTAssertEqual(try lookup(ssh, "id").0, NFSStat.noent.rawValue)
        XCTAssertEqual(try read(try XCTUnwrap(try lookup(root, "moved").1)).0, Data("k".utf8))

        var rm = try nfs(13) {
            $0.opaque(self.root)
            $0.string("ssh")
        }
        XCTAssertEqual(try rm.u32(), 0)
        try rm.wcc()
        XCTAssertTrue(rm.atEnd)
        XCTAssertEqual(try lookup(root, "ssh").0, NFSStat.noent.rawValue)
    }

    func testListingsPageThroughEveryEntry() throws {
        let names = (0..<40).map { String(format: "file-%02d", $0) }
        for n in names { XCTAssertEqual(try create(root, n).0, 0) }
        XCTAssertEqual(try list(root, plus: false, count: 256).map(\.name), [".", ".."] + names)
        let plus = try list(root, plus: true, count: 600)
        XCTAssertEqual(plus.map(\.name), [".", ".."] + names)
        XCTAssertTrue(plus.allSatisfy { $0.handle != nil })
    }

    func testInfoProceduresAnswerInFull() throws {
        var access = try nfs(4) {
            $0.opaque(self.root)
            $0.u32(0x3F)
        }
        XCTAssertEqual(try access.u32(), 0)
        try access.postOpAttr()
        XCTAssertEqual(try access.u32(), 0x01 | 0x02 | 0x04 | 0x08 | 0x10, "a 700 folder: read, look up, change, delete")
        XCTAssertTrue(access.atEnd)

        var stat = try nfs(18) { $0.opaque(self.root) }
        XCTAssertEqual(try stat.u32(), 0)
        try stat.postOpAttr()
        XCTAssertEqual(try stat.u64(), 1 << 30)
        for _ in 0..<5 { _ = try stat.u64() }
        _ = try stat.u32()
        XCTAssertTrue(stat.atEnd, "FSSTAT")

        var info = try nfs(19) { $0.opaque(self.root) }
        XCTAssertEqual(try info.u32(), 0)
        try info.postOpAttr()
        XCTAssertEqual(try info.u32(), 1 << 20, "rtmax")
        for _ in 0..<6 { _ = try info.u32() }
        XCTAssertEqual(try info.u64(), fs.maxFileSize)
        for _ in 0..<3 { _ = try info.u32() }
        XCTAssertTrue(info.atEnd, "FSINFO")

        var conf = try nfs(20) { $0.opaque(self.root) }
        XCTAssertEqual(try conf.u32(), 0)
        try conf.postOpAttr()
        XCTAssertEqual(try conf.u32(), 1)
        XCTAssertEqual(try conf.u32(), 255)
        for _ in 0..<4 { _ = try conf.bool() }
        XCTAssertTrue(conf.atEnd, "PATHCONF")

        let f = try XCTUnwrap(try create(root, "f").1)
        XCTAssertEqual(try commit(f).0, 0)
    }

    func testWritesReachTheDiskWhenAsked() throws {
        let f = try XCTUnwrap(try create(root, "f").1)
        XCTAssertEqual(try write(f, 0, Data("one".utf8), stable: 0), 0)
        XCTAssertEqual(fs.committed, [], "an ordinary write isn't synced, and doesn't claim to be")
        XCTAssertEqual(try commit(f).0, 0)
        XCTAssertEqual(fs.committed.count, 1, "the program's fsync is")
        XCTAssertEqual(try write(f, 3, Data("two".utf8), stable: 2), 0)
        XCTAssertEqual(fs.committed.count, 2, "and so is a write that asks for it")
        XCTAssertEqual(try read(f).0, Data("onetwo".utf8))

        fs.commitFails = true
        XCTAssertEqual(try commit(f).0, NFSStat.io.rawValue, "a sync that fails is never called done")
        XCTAssertEqual(try write(f, 0, Data("x".utf8), stable: 2), NFSStat.io.rawValue)
        XCTAssertEqual(try write(f, 0, Data("x".utf8), stable: 0), 0)
    }

    func testInfoProceduresRefuseHandlesWithoutTheSecret() throws {
        let forged = Data(count: 24)
        for proc: UInt32 in [18, 19, 20, 21] {
            var r = try nfs(proc) {
                $0.opaque(forged)
                if proc == 21 {
                    $0.u64(0)
                    $0.u32(0)
                }
            }
            XCTAssertEqual(try r.u32(), NFSStat.badhandle.rawValue, "proc \(proc)")
            if proc == 21 { try r.wcc() } else { try r.postOpAttr() }
            XCTAssertTrue(r.atEnd, "proc \(proc) refusal has exactly its fields")
        }
    }

    /// Refusals carry the failure body RFC 1813 gives each procedure, or the kernel misreads them.
    func testRefusalsHaveTheShapeOfEachProcedure() throws {
        for proc: UInt32 in 1...21 {
            var r = try nfs(proc, uid: 4242)
            XCTAssertEqual(try r.u32(), NFSStat.acces.rawValue, "proc \(proc)")
            switch proc {
            case 1: break
            case 2, 7, 8, 9, 10, 11, 12, 13, 21: try r.wcc()
            case 14: try r.wcc(); try r.wcc()
            case 15: try r.postOpAttr(); try r.wcc()
            default: try r.postOpAttr()
            }
            XCTAssertTrue(r.atEnd, "proc \(proc) refusal has exactly its fields")
        }
    }

    func testUnsupportedProceduresSayNotSupported() throws {
        var link = try nfs(5) { $0.opaque(self.root) }
        XCTAssertEqual(try link.u32(), NFSStat.notsupp.rawValue)
        try link.postOpAttr()
        XCTAssertTrue(link.atEnd, "READLINK")
        for proc: UInt32 in [10, 11] {
            var r = try nfs(proc) { $0.opaque(self.root) }
            XCTAssertEqual(try r.u32(), NFSStat.notsupp.rawValue)
            try r.wcc()
            XCTAssertTrue(r.atEnd, "proc \(proc)")
        }
    }

    /// Well-framed calls with real handles and random arguments, so the randomness reaches the
    /// argument parsers and the file system behind them. Every call is answered, and the server
    /// keeps working.
    func testFramedFuzzReachesTheParsersAndNeverStopsTheServer() throws {
        let file = try XCTUnwrap(try create(root, "target").1)
        let handles = [root, file, Data(count: 24), Data(repeating: 0xFF, count: 64)]
        var rng = SeededRandom(state: 0x5368_7275_67) // "Shrug"
        for i in 0..<3000 {
            var w = XDRWriter()
            let xid = UInt32(i + 1_000_000)
            w.u32(xid)
            w.u32(0)
            w.u32(2)
            let prog: UInt32 = Int.random(in: 0..<10, using: &rng) == 0 ? 100005 : 100003
            w.u32(prog)
            w.u32(Int.random(in: 0..<20, using: &rng) == 0 ? 2 : 3)
            w.u32(UInt32.random(in: 0...23, using: &rng))
            var cred = XDRWriter()
            cred.u32(0)
            cred.string("fuzz")
            cred.u32(getuid())
            cred.u32(getgid())
            cred.u32(0)
            w.u32(1)
            w.opaque(cred.data)
            w.u32(0)
            w.opaque(Data())
            if Bool.random(using: &rng) { w.opaque(handles.randomElement(using: &rng)!) }
            let tail = (0..<Int.random(in: 0...96, using: &rng)).map { _ in
                // Mostly small numbers, so lengths and offsets are often in range.
                Bool.random(using: &rng) ? UInt8(0) : UInt8.random(in: 0...255, using: &rng)
            }
            w.fixed(Data(tail))
            c.send(w.data)
            guard let reply = c.receive() else { return XCTFail("no answer to fuzz call \(i)") }
            var r = XDRReader(reply)
            XCTAssertEqual(try r.u32(), xid, "answers come in order, each to its own call")
        }
        XCTAssertNoThrow(try nfs(0))
        XCTAssertEqual(try lookup(root, "target").0, 0, "and it still works")
    }

    func testStoppingClosesTheListenerAndEveryConnection() throws {
        XCTAssertNoThrow(try nfs(0))
        let port = server.port
        server.stop()
        XCTAssertNil(c.receive(), "the open connection ends")
        XCTAssertThrowsError(try RPCClient(port: port), "nothing listens any more")
    }

    func testHandleSecretsCompareWhole() {
        XCTAssertTrue(NFSServer.same(Data([1, 2, 3]), Data([1, 2, 3])))
        XCTAssertFalse(NFSServer.same(Data([1, 2, 3]), Data([1, 2, 4])))
        XCTAssertFalse(NFSServer.same(Data([1, 2, 3]), Data([1, 2])))
    }
}
