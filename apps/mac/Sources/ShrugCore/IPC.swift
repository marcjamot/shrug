import Darwin
import Foundation

/// One JSON line each way over a Unix socket that only this user can open.
public struct IPCRequest: Codable, Sendable {
    public var cmd: String
    public var args: [String: String]

    public init(_ cmd: String, _ args: [String: String] = [:]) {
        self.cmd = cmd
        self.args = args
    }
}

public struct IPCResponse: Codable, Sendable {
    public var ok: Bool
    public var message: String
    /// Machine-readable outcome: "password-needed", "collisions", "has-vault", "empty".
    public var code: String?
    public var status: StatusInfo?
    /// Profile names, or the paths that collide.
    public var list: [String]?

    public init(ok: Bool, message: String, code: String? = nil, status: StatusInfo? = nil, list: [String]? = nil) {
        self.ok = ok
        self.message = message
        self.code = code
        self.status = status
        self.list = list
    }
}

public struct LinkInfo: Codable, Sendable {
    public var path: String
    public var target: String
    /// "ok", or what's wrong.
    public var state: String

    public init(path: String, target: String, state: String) {
        self.path = path
        self.target = target
        self.state = state
    }
}

/// While locked, only the first few fields are filled: names stay hidden.
public struct StatusInfo: Codable, Sendable {
    public var setUp: Bool
    public var unlocked: Bool
    public var touchID: Bool
    public var mounted: Bool
    public var mount: String
    public var device: String?
    public var macs: [String]
    public var profile: String?
    public var storage: String?
    /// nil before the first attempt.
    public var online: Bool?
    public var lastSync: Date?
    public var problem: String?
    public var waiting: Int
    public var links: [LinkInfo]
    public var notices: [String]
    public var lastEvent: String?

    public init(setUp: Bool, unlocked: Bool, touchID: Bool, mounted: Bool, mount: String, device: String? = nil,
                macs: [String] = [], profile: String? = nil, storage: String? = nil, online: Bool? = nil,
                lastSync: Date? = nil, problem: String? = nil, waiting: Int = 0, links: [LinkInfo] = [],
                notices: [String] = [], lastEvent: String? = nil) {
        self.setUp = setUp
        self.unlocked = unlocked
        self.touchID = touchID
        self.mounted = mounted
        self.mount = mount
        self.device = device
        self.macs = macs
        self.profile = profile
        self.storage = storage
        self.online = online
        self.lastSync = lastSync
        self.problem = problem
        self.waiting = waiting
        self.links = links
        self.notices = notices
        self.lastEvent = lastEvent
    }
}

public enum Descriptor {
    /// Writes everything, retrying short writes. False if the descriptor stopped taking data.
    @discardableResult
    public static func writeAll(_ fd: Int32, _ data: Data) -> Bool {
        data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let n = write(fd, raw.baseAddress! + offset, raw.count - offset)
                if n <= 0 { return false }
                offset += n
            }
            return true
        }
    }
}

public enum UnixSocket {
    static func address(_ path: String) throws -> sockaddr_un {
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        guard bytes.count < capacity else { throw ShrugError("Socket path too long: \(path)") }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: bytes)
            raw[bytes.count] = 0
        }
        return addr
    }

    /// A peer that hangs up early makes writes fail instead of killing the process with SIGPIPE.
    public static func ignoreHangups(_ fd: Int32) {
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
    }

    public static func connect(_ path: String) throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw ShrugError("socket() failed") }
        ignoreHangups(fd)
        var addr = try address(path)
        let r = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard r == 0 else {
            close(fd)
            throw ShrugError("Shrug is not running (open the Shrug app first)")
        }
        return fd
    }

    public static func listen(_ path: String) throws -> Int32 {
        if let probe = try? connect(path) {
            close(probe)
            throw ShrugError("Shrug is already running")
        }
        unlink(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw ShrugError("socket() failed") }
        var addr = try address(path)
        let old = umask(0o077)
        let r = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        umask(old)
        guard r == 0, Darwin.listen(fd, 16) == 0 else {
            close(fd)
            throw ShrugError("Cannot listen on \(path): \(String(cString: strerror(errno)))")
        }
        chmod(path, 0o600)
        return fd
    }

    /// One line (without its newline), at most `limit` bytes. Nil if the peer closed first or
    /// sent more than that. Anything after the newline is ignored: one request per connection.
    public static func readLine(_ fd: Int32, limit: Int) -> Data? {
        var line = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while line.count <= limit {
            let n = read(fd, &buffer, buffer.count)
            if n <= 0 { return nil }
            if let end = buffer[0..<n].firstIndex(of: 0x0A) {
                line.append(contentsOf: buffer[0..<end])
                return line.count <= limit ? line : nil
            }
            line.append(contentsOf: buffer[0..<n])
        }
        return nil
    }

    /// One JSON value on one line.
    public static func send<T: Encodable>(_ value: T, to fd: Int32) throws {
        var data = try JSONFile.encode(value)
        data.removeAll { $0 == 0x0A }
        data.append(0x0A)
        guard Descriptor.writeAll(fd, data) else { throw ShrugError("The connection to Shrug broke") }
    }
}

public enum IPCClient {
    /// Biggest answer the command line accepts (a status lists every link).
    static let answerLimit = 4 << 20

    public static func send(_ request: IPCRequest, socket path: String) throws -> IPCResponse {
        let fd = try UnixSocket.connect(path)
        defer { close(fd) }
        try UnixSocket.send(request, to: fd)
        guard let line = UnixSocket.readLine(fd, limit: answerLimit) else { throw ShrugError("No answer from Shrug") }
        return try JSONFile.decode(IPCResponse.self, from: line)
    }
}
