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

    private(set) var port: UInt16 = 0
    private var listenFD: Int32 = -1
    private let handler: Handler
    private let requireReservedPort: Bool
    private let queue = DispatchQueue(label: "shrug.nfs.calls", attributes: .concurrent)
    private let lock = NSLock()
    private var connections: Set<Int32> = []
    private var running = false
    var log: (String) -> Void = { _ in }

    init(requireReservedPort: Bool, handler: @escaping Handler) {
        self.requireReservedPort = requireReservedPort
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
        listenFD = fd
        running = true
        let t = Thread { [weak self] in self?.acceptLoop() }
        t.name = "shrug.nfs.accept"
        t.start()
    }

    func stop() {
        lock.lock()
        running = false
        let fds = connections
        connections.removeAll()
        lock.unlock()
        if listenFD >= 0 {
            shutdown(listenFD, SHUT_RDWR)
            close(listenFD)
            listenFD = -1
        }
        for fd in fds {
            shutdown(fd, SHUT_RDWR)
            close(fd)
        }
    }

    private func acceptLoop() {
        while true {
            var peer = sockaddr_in()
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let fd = withUnsafeMutablePointer(to: &peer) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { accept(listenFD, $0, &len) }
            }
            if fd < 0 {
                lock.lock()
                let stillRunning = running
                lock.unlock()
                if !stillRunning { return }
                continue
            }
            let peerPort = UInt16(bigEndian: peer.sin_port)
            // Only the kernel (root) can use ports below 1024, so this keeps other
            // local users from talking to the server directly.
            if requireReservedPort && peerPort >= 1024 {
                log("refused NFS connection from unprivileged port \(peerPort)")
                close(fd)
                continue
            }
            var one: Int32 = 1
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, socklen_t(MemoryLayout<Int32>.size))
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            lock.lock()
            connections.insert(fd)
            lock.unlock()
            let t = Thread { [weak self] in self?.serve(fd) }
            t.name = "shrug.nfs.conn"
            t.start()
        }
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

    private func serve(_ fd: Int32) {
        let writeLock = NSLock()
        let inflightLock = NSLock()
        var inflight: Set<UInt32> = []
        defer {
            lock.lock()
            let mine = connections.remove(fd) != nil
            lock.unlock()
            if mine { close(fd) }
        }
        while true {
            var record = Data()
            var last = false
            while !last {
                guard let mark = readFull(fd, 4) else { return }
                let v = mark.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) }
                last = v & 0x8000_0000 != 0
                let len = Int(v & 0x7FFF_FFFF)
                guard len <= 4 << 20, let frag = readFull(fd, len) else { return }
                record.append(frag)
            }
            guard var call = parseCall(record) else { continue }
            inflightLock.lock()
            let duplicate = !inflight.insert(call.xid).inserted
            inflightLock.unlock()
            if duplicate { continue } // a retransmission of something still running
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
                writeLock.lock()
                framed.data.withUnsafeBytes { raw in
                    var off = 0
                    while off < raw.count {
                        let n = write(fd, raw.baseAddress! + off, raw.count - off)
                        if n <= 0 { break }
                        off += n
                    }
                }
                writeLock.unlock()
                inflightLock.lock()
                inflight.remove(call.xid)
                inflightLock.unlock()
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
