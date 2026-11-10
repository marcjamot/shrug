import Darwin
import XCTest
@testable import ShrugNFS

/// A tiny file system: the root (1) and one file (2).
final class MemoryFS: NFSFileSystem {
    var rootID: UInt64 { 1 }
    let maxFileSize: UInt64 = 1 << 20
    let caseInsensitive = false
    var content = Data("hello".utf8)

    private func attr(_ id: UInt64) -> NFSAttr {
        let t = NFSTime(sec: 0, nsec: 0)
        return id == 1
            ? NFSAttr(type: .directory, mode: 0o700, nlink: 2, uid: getuid(), gid: getgid(), size: 0, used: 0, fileid: 1,
                      atime: t, mtime: t, ctime: t)
            : NFSAttr(type: .regular, mode: 0o600, nlink: 1, uid: getuid(), gid: getgid(), size: UInt64(content.count),
                      used: 0, fileid: 2, atime: t, mtime: t, ctime: t)
    }

    func parent(_ id: UInt64) -> UInt64 { 1 }
    func getattr(_ id: UInt64) -> Result<NFSAttr, NFSStat> { id == 1 || id == 2 ? .success(attr(id)) : .failure(.stale) }
    func lookup(_ dir: UInt64, _ name: String) -> Result<UInt64, NFSStat> { name == "hello.txt" ? .success(2) : .failure(.noent) }
    func readdir(_ dir: UInt64) -> Result<[NFSDirEntry], NFSStat> { .success([NFSDirEntry(name: "hello.txt", id: 2)]) }
    func read(_ id: UInt64, offset: UInt64, count: UInt32, _ ctx: NFSContext) -> Result<(Data, Bool), NFSStat> {
        .success((content.dropFirst(Int(offset)).prefix(Int(count)), true))
    }
    func write(_ id: UInt64, offset: UInt64, data: Data, _ ctx: NFSContext) -> Result<Void, NFSStat> { .success(()) }
    func create(_ dir: UInt64, _ name: String, mode: UInt32?, exclusive: Bool, _ ctx: NFSContext) -> Result<UInt64, NFSStat> {
        .failure(.acces)
    }
    func mkdir(_ dir: UInt64, _ name: String, mode: UInt32?, _ ctx: NFSContext) -> Result<UInt64, NFSStat> { .failure(.acces) }
    func remove(_ dir: UInt64, _ name: String, _ ctx: NFSContext) -> Result<Void, NFSStat> { .failure(.acces) }
    func rmdir(_ dir: UInt64, _ name: String, _ ctx: NFSContext) -> Result<Void, NFSStat> { .failure(.acces) }
    func rename(_ fromDir: UInt64, _ fromName: String, _ toDir: UInt64, _ toName: String,
                _ ctx: NFSContext) -> Result<Void, NFSStat> { .failure(.acces) }
    func setattr(_ id: UInt64, _ attrs: NFSSetAttrs, _ ctx: NFSContext) -> Result<Void, NFSStat> { .success(()) }
    func fsstat() -> NFSFSStat { NFSFSStat(totalBytes: 0, freeBytes: 0, totalFiles: 0, freeFiles: 0) }
}

/// Speaks ONC RPC to the server like any program on this Mac could.
final class RPCClient {
    let fd: Int32
    private var xid: UInt32 = 1

    init(port: UInt16) throws {
        fd = socket(AF_INET, SOCK_STREAM, 0)
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        var tv = timeval(tv_sec: 5, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = port.bigEndian
        let r = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard r == 0 else { throw NFSServerError("connect failed") }
    }

    deinit { close(fd) }

    func send(_ record: Data) {
        var framed = XDRWriter()
        framed.u32(0x8000_0000 | UInt32(record.count))
        _ = (framed.data + record).withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
    }

    /// The next reply record, or nil once the server has closed the connection.
    func receive() -> Data? {
        func readFull(_ n: Int) -> Data? {
            var out = Data(count: n)
            var got = 0
            while got < n {
                let r = out.withUnsafeMutableBytes { read(fd, $0.baseAddress! + got, n - got) }
                if r <= 0 { return nil }
                got += r
            }
            return out
        }
        guard let mark = readFull(4) else { return nil }
        let len = Int(mark.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) } & 0x7FFF_FFFF)
        return readFull(len)
    }

    /// Calls a procedure; returns the reply body after the accept status (which must be success).
    func call(prog: UInt32, proc: UInt32, uid: UInt32 = getuid(), _ args: (inout XDRWriter) -> Void = { _ in }) throws -> XDRReader {
        var w = XDRWriter()
        w.u32(xid)
        xid += 1
        w.u32(0) // CALL
        w.u32(2)
        w.u32(prog)
        w.u32(3)
        w.u32(proc)
        var cred = XDRWriter()
        cred.u32(0)
        cred.string("test")
        cred.u32(uid)
        cred.u32(getgid())
        cred.u32(0)
        w.u32(1) // AUTH_UNIX
        w.opaque(cred.data)
        w.u32(0)
        w.opaque(Data())
        args(&w)
        send(w.data)
        guard let reply = receive() else { throw NFSServerError("connection closed") }
        var r = XDRReader(reply)
        _ = try r.u32() // xid
        _ = try r.u32() // REPLY
        _ = try r.u32() // accepted
        _ = try r.u32()
        _ = try r.opaque()
        guard try r.u32() == 0 else { throw NFSServerError("call not accepted") }
        return r
    }
}

final class NFSServerTests: XCTestCase {
    var fs: MemoryFS!
    var server: NFSServer!

    func start() throws -> RPCClient {
        fs = MemoryFS()
        server = NFSServer(fs: fs)
        try server.start()
        addTeardownBlock { [server] in server?.stop() }
        return try RPCClient(port: server.port)
    }

    /// MOUNT's answer: a status, then the root handle if it's 0.
    func mountCall(_ c: RPCClient) throws -> (UInt32, Data?) {
        var r = try c.call(prog: 100005, proc: 1) { $0.string("/") }
        let status = try r.u32()
        return (status, status == 0 ? try r.opaque() : nil)
    }

    /// The root handle, as Shrug's own mount gets it.
    func mount(_ c: RPCClient) throws -> Data {
        var handle: Data?
        try server.whileMounting { handle = try mountCall(c).1 }
        return try XCTUnwrap(handle)
    }

    func getattr(_ c: RPCClient, _ handle: Data, uid: UInt32 = getuid()) throws -> UInt32 {
        var r = try c.call(prog: 100003, proc: 1, uid: uid) { $0.opaque(handle) }
        return try r.u32()
    }

    func testTheRootHandleIsHandedOutOnceDuringShrugsOwnMount() throws {
        let c = try start()
        XCTAssertEqual(try mountCall(c).0, 13, "MNT3ERR_ACCES outside Shrug's mount")
        try server.whileMounting {
            XCTAssertEqual(try mountCall(c).1?.count, 24)
            XCTAssertEqual(try mountCall(c).0, 13, "and only once")
        }
        XCTAssertEqual(try mountCall(c).0, 13)
    }

    func testAHandleTakenFromAFailedMountIsWorthless() throws {
        let c = try start()
        var stolen: Data?
        struct MountFailed: Error {}
        XCTAssertThrowsError(try server.whileMounting {
            stolen = try mountCall(c).1 // something else answers first, so Shrug's mount fails
            throw MountFailed()
        })
        XCTAssertEqual(try getattr(c, try XCTUnwrap(stolen)), NFSStat.badhandle.rawValue)
        XCTAssertEqual(try getattr(c, try mount(c)), 0)
    }

    func testHandlesWithoutTheSecretAreRefused() throws {
        let c = try start()
        let root = try mount(c)
        XCTAssertEqual(try getattr(c, root), 0)
        var forged = root
        forged.replaceSubrange(8..<24, with: Data(count: 16))
        XCTAssertEqual(try getattr(c, forged), NFSStat.badhandle.rawValue)
    }

    func testOtherUsersAreRefused() throws {
        let c = try start()
        let root = try mount(c)
        XCTAssertEqual(try getattr(c, root, uid: 4242), NFSStat.acces.rawValue)
    }

    func testReaddirRefusesCookiesItNeverGave() throws {
        let c = try start()
        let root = try mount(c)
        var r = try c.call(prog: 100003, proc: 16) {
            $0.opaque(root)
            $0.u64(UInt64.max)
            $0.fixed(Data(count: 8))
            $0.u32(4096)
        }
        XCTAssertEqual(try r.u32(), NFSStat.badCookie.rawValue)
    }

    func testWritesPastTheLimitAreRefused() throws {
        let c = try start()
        let root = try mount(c)
        var look = try c.call(prog: 100003, proc: 3) {
            $0.opaque(root)
            $0.string("hello.txt")
        }
        XCTAssertEqual(try look.u32(), 0)
        let file = try look.opaque()
        var r = try c.call(prog: 100003, proc: 7) {
            $0.opaque(file)
            $0.u64(UInt64.max - 2)
            $0.u32(4)
            $0.u32(2)
            $0.opaque(Data("data".utf8))
        }
        XCTAssertEqual(try r.u32(), NFSStat.fbig.rawValue)
    }

    func testOversizedRecordsCloseTheConnection() throws {
        let c = try start()
        var mark = XDRWriter()
        mark.u32(UInt32(RPCServer.maxRecord + 1))
        _ = mark.data.withUnsafeBytes { write(c.fd, $0.baseAddress, $0.count) }
        XCTAssertNil(c.receive())
    }

    func testGarbageNeverStopsTheServer() throws {
        let c = try start()
        var rng = SystemRandomNumberGenerator()
        for _ in 0..<300 {
            c.send(Data((0..<Int.random(in: 0...200, using: &rng)).map { _ in UInt8.random(in: 0...255, using: &rng) }))
        }
        let fresh = try RPCClient(port: server.port)
        XCTAssertNoThrow(try fresh.call(prog: 100003, proc: 0))
    }

    func testConnectionsAreLimited() throws {
        let first = try start()
        var open = [first]
        for _ in 1..<RPCServer.maxConnections { open.append(try RPCClient(port: server.port)) }
        XCTAssertNoThrow(try open.last!.call(prog: 100003, proc: 0))
        let extra = try RPCClient(port: server.port)
        XCTAssertNil(extra.receive(), "one more than the limit is closed right away")
    }
}
