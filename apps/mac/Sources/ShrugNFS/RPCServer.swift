import Darwin
import Foundation

public struct RPCCall {
    public let xid: UInt32
    public let prog: UInt32
    public let vers: UInt32
    public let proc: UInt32
    public let uid: UInt32
    public let gid: UInt32
    var args: XDRReader
}

enum AcceptStat: UInt32 {
    case success = 0, progUnavail = 1, progMismatch = 2, procUnavail = 3, garbageArgs = 4
}

/// ONC RPC over TCP on 127.0.0.1 with record marking (RFC 5531).
/// Calls run concurrently so one request waiting for Touch ID never blocks others.
final class RPCServer {
    typealias Handler = (inout RPCCall, inout XDRWriter) -> AcceptStat

    /// A WRITE carries at most 1 MiB (see FSINFO), plus a little framing.
    static let maxRecord = (1 << 20) + (1 << 16)
    /// The kernel needs one or two; anything past this is someone else.
    static let maxConnections = 16

    /// One client connection. The descriptor closes when the last user lets go (the thread
    /// reading calls, or a call still being answered), so a late reply can never land on a
    /// descriptor number the system has given to someone else meanwhile.
    private final class Connection: @unchecked Sendable {
        let fd: Int32
        let writeLock = NSLock()
        private let inflightLock = NSLock()
        private var inflight: Set<UInt32> = []

        init(_ fd: Int32) { self.fd = fd }
        deinit { close(fd) }

        /// False if a call with this xid is still running (a retransmission).
        func begin(_ xid: UInt32) -> Bool {
            inflightLock.lock()
            defer { inflightLock.unlock() }
            return inflight.insert(xid).inserted
        }

        func end(_ xid: UInt32) {
            inflightLock.lock()
            inflight.remove(xid)
            inflightLock.unlock()
        }

        func send(_ data: Data) {
            writeLock.lock()
            defer { writeLock.unlock() }
            data.withUnsafeBytes { raw in
                var off = 0
                while off < raw.count {
                    let n = write(fd, raw.baseAddress! + off, raw.count - off)
                    if n <= 0 { break }
                    off += n
                }
            }
        }
    }

    private(set) var port: UInt16 = 0
    private var acceptor: AcceptLoop?
    private let handler: Handler
    private let queue = DispatchQueue(label: "shrug.nfs.calls", attributes: .concurrent)
    private let lock = NSLock()
    private var connections: [Int32: Connection] = [:]
    private var running = false
    var log: (String) -> Void = { _ in }

    init(handler: @escaping Handler) {
        self.handler = handler
    }

    func start() throws {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw NFSServerError("socket() failed") }
        var yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = 0
        let r = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard r == 0, listen(fd, 16) == 0 else {
            close(fd)
            throw NFSServerError("Cannot listen on loopback: \(String(cString: strerror(errno)))")
        }
        var bound = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &bound) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        port = UInt16(bigEndian: bound.sin_port)
        lock.lock()
        running = true
        lock.unlock()
        acceptor = try AcceptLoop(listening: fd, name: "shrug.nfs.accept") { [weak self] client in
            guard let self else { close(client); return }
            self.accepted(client)
        }
    }

    func stop() {
        lock.lock()
        running = false
        let open = Array(connections.values)
        connections.removeAll()
        lock.unlock()
        acceptor?.stop()
        // Wakes each connection's reader; the descriptor closes once nothing uses it.
        for c in open { shutdown(c.fd, SHUT_RDWR) }
    }

    private func accepted(_ fd: Int32) {
        lock.lock()
        let full = connections.count >= RPCServer.maxConnections
        let refuse = !running || full
        let connection = refuse ? nil : Connection(fd)
        if let connection { connections[fd] = connection }
        lock.unlock()
        guard let connection else {
            if full { log("refused an NFS connection: too many open") }
            close(fd)
            return
        }
        var one: Int32 = 1
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        let t = Thread { [weak self] in self?.serve(connection) }
        t.name = "shrug.nfs.conn"
        t.start()
    }

    private func readFull(_ fd: Int32, _ count: Int) -> Data? {
        var out = Data(count: count)
        var got = 0
        while got < count {
            let n = out.withUnsafeMutableBytes { read(fd, $0.baseAddress! + got, count - got) }
            if n <= 0 { return nil }
            got += n
        }
        return out
    }

    private func serve(_ connection: Connection) {
        let fd = connection.fd
        defer {
            lock.lock()
            if connections[fd] === connection { connections[fd] = nil }
            lock.unlock()
        }
        while true {
            var record = Data()
            var last = false
            while !last {
                guard let mark = readFull(fd, 4) else { return }
                let v = mark.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) }
                last = v & 0x8000_0000 != 0
                let len = Int(v & 0x7FFF_FFFF)
                guard record.count + len <= RPCServer.maxRecord, let frag = readFull(fd, len) else { return }
                record.append(frag)
            }
            guard var call = parseCall(record) else { continue }
            guard connection.begin(call.xid) else { continue } // a retransmission of something still running
            queue.async { [handler] in
                var body = XDRWriter()
                let stat = handler(&call, &body)
                var reply = XDRWriter()
                reply.u32(call.xid)
                reply.u32(1) // REPLY
                reply.u32(0) // MSG_ACCEPTED
                reply.u32(0) // verifier AUTH_NONE
                reply.u32(0)
                reply.u32(stat.rawValue)
                if stat == .progMismatch {
                    reply.u32(3)
                    reply.u32(3)
                } else if stat == .success {
                    reply.append(body)
                }
                var framed = XDRWriter()
                framed.u32(0x8000_0000 | UInt32(reply.data.count))
                framed.append(reply)
                connection.send(framed.data)
                connection.end(call.xid)
            }
        }
    }

    private func parseCall(_ record: Data) -> RPCCall? {
        var r = XDRReader(record)
        do {
            let xid = try r.u32()
            guard try r.u32() == 0, try r.u32() == 2 else { return nil } // CALL, RPC v2
            let prog = try r.u32()
            let vers = try r.u32()
            let proc = try r.u32()
            let flavor = try r.u32()
            let cred = try r.opaque(max: 400)
            _ = try r.u32() // verifier flavor
            _ = try r.opaque(max: 400)
            var uid: UInt32 = UInt32.max
            var gid: UInt32 = UInt32.max
            if flavor == 1 { // AUTH_UNIX
                var c = XDRReader(cred)
                _ = try c.u32()
                _ = try c.string(max: 255)
                uid = try c.u32()
                gid = try c.u32()
            }
            return RPCCall(xid: xid, prog: prog, vers: vers, proc: proc, uid: uid, gid: gid, args: r)
        } catch {
            return nil
        }
    }
}

public struct NFSServerError: Error, CustomStringConvertible {
    public let description: String
    init(_ d: String) { description = d }
}
