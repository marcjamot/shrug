import Darwin
import Foundation

public struct StoredObject: Sendable {
    public let key: String
    public let size: Int64
    /// This exact version of the object (a generation). It changes whenever the object is replaced.
    public let version: String

    public init(key: String, size: Int64, version: String) {
        self.key = key
        self.size = size
        self.version = version
    }
}

public enum StorageError: Error, CustomStringConvertible {
    case notFound
    /// No connection: try again later. Never treated as anything worse.
    case offline(String)
    /// The storage refused these credentials.
    case denied(String)
    /// The object isn't the version the request named: it was replaced meanwhile.
    case conflict
    case failed(String)

    public var description: String {
        switch self {
        case .notFound: return "not found"
        case .offline(let m): return "offline (\(m))"
        case .denied(let m): return "access denied (\(m))"
        case .conflict: return "changed meanwhile"
        case .failed(let m): return m
        }
    }
}

/// Dumb object storage. Everything Shrug hands it is already encrypted.
///
/// Every write names the version it replaces (nil: the object must not exist yet), so two Macs
/// never overwrite each other's changes unseen. Shrug never deletes objects.
public protocol ObjectStorage: AnyObject {
    func list(prefix: String) throws -> [StoredObject]
    /// The whole object, or the bytes in `range` (inclusive). With `version`, only from that version.
    func get(_ key: String, range: ClosedRange<Int64>?, version: String?) throws -> Data
    /// Downloads the object into `file`, returning its version. With `version`, only that version:
    /// a replaced object is never downloaded, so its size can't be a surprise.
    func download(_ key: String, to file: URL, version: String?) throws -> String
    /// Returns the new version.
    func put(_ key: String, data: Data, replacing version: String?) throws -> String
    /// Returns the new version.
    func upload(_ key: String, from file: URL, replacing version: String?) throws -> String
}

extension ObjectStorage {
    public func get(_ key: String, version: String? = nil) throws -> Data {
        try get(key, range: nil, version: version)
    }
}

/// Where this Mac's vault lives. Nothing secret in here; the credentials are separate.
public struct StorageConfig: Codable, Equatable, Sendable {
    /// "gcs" (Google Cloud Storage), or "folder" (a plain folder: for tests, or a mounted drive).
    public var kind: String
    public var bucket: String?
    public var path: String?
    public var endpoint: String?
    public var region: String?

    public init(kind: String, bucket: String? = nil, path: String? = nil, endpoint: String? = nil, region: String? = nil) {
        self.kind = kind
        self.bucket = bucket
        self.path = path
        self.endpoint = endpoint
        self.region = region
    }

    public var summary: String {
        kind == "gcs" ? "Google Cloud Storage bucket \(bucket ?? "?")" : "folder \(path ?? "?")"
    }
}

/// An HMAC key (access ID and secret) that can only reach the vault's bucket.
public struct Credentials: Codable, Sendable {
    public var accessID: String
    public var secret: String

    public init(accessID: String, secret: String) {
        self.accessID = accessID
        self.secret = secret
    }
}

public enum Storage {
    public static func make(_ config: StorageConfig, _ credentials: Credentials?) throws -> ObjectStorage {
        switch config.kind {
        case "gcs":
            guard let bucket = config.bucket, !bucket.isEmpty else { throw ShrugError("No bucket name") }
            guard let c = credentials, !c.accessID.isEmpty, !c.secret.isEmpty else { throw ShrugError("No credentials") }
            guard let endpoint = URL(string: config.endpoint ?? "https://storage.googleapis.com"), endpoint.scheme == "https"
            else { throw ShrugError("The storage address must start with https://") }
            return GCSStorage(endpoint: endpoint, bucket: bucket, region: config.region ?? "auto",
                              accessID: c.accessID, secret: c.secret)
        case "folder":
            guard let path = config.path, !path.isEmpty else { throw ShrugError("No folder given") }
            return FolderStorage(root: URL(fileURLWithPath: path))
        default:
            throw ShrugError("Unknown storage '\(config.kind)'")
        }
    }
}

/// A plain folder used as a bucket: each object is a file. If the folder is missing, the
/// storage counts as offline, which is how tests switch the network off. Writes take a lock
/// file, so several processes sharing the folder still get conditional writes.
public final class FolderStorage: ObjectStorage {
    public let root: URL

    public init(root: URL) { self.root = root }

    private func file(_ key: String) -> URL { root.appendingPathComponent(key) }

    private func checkOnline() throws {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: root.path, isDirectory: &isDir), isDir.boolValue else {
            throw StorageError.offline("\(root.path) is not there")
        }
    }

    /// A new inode, size or modification time means a new version.
    private func version(_ url: URL) -> String? {
        var st = stat()
        guard stat(url.path, &st) == 0, st.st_mode & S_IFMT == S_IFREG else { return nil }
        return "\(st.st_ino)-\(st.st_size)-\(st.st_mtimespec.tv_sec).\(st.st_mtimespec.tv_nsec)"
    }

    private func locked<T>(_ body: () throws -> T) throws -> T {
        let fd = open(root.appendingPathComponent(".lock").path, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else { throw StorageError.failed("Cannot lock \(root.path)") }
        defer { close(fd) }
        flock(fd, LOCK_EX)
        defer { flock(fd, LOCK_UN) }
        return try body()
    }

    public func list(prefix: String) throws -> [StoredObject] {
        try checkOnline()
        guard let walker = FileManager.default.enumerator(atPath: root.path) else { return [] }
        var out: [StoredObject] = []
        while let rel = walker.nextObject() as? String {
            guard rel.hasPrefix(prefix), !(rel as NSString).lastPathComponent.hasPrefix(".") else { continue }
            let url = file(rel)
            guard let v = version(url), let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize else { continue }
            out.append(StoredObject(key: rel, size: Int64(size), version: v))
        }
        return out.sorted { $0.key < $1.key }
    }

    public func get(_ key: String, range: ClosedRange<Int64>?, version expected: String?) throws -> Data {
        try checkOnline()
        let url = file(key)
        guard let current = version(url), let h = try? FileHandle(forReadingFrom: url) else { throw StorageError.notFound }
        defer { try? h.close() }
        if let expected, expected != current { throw StorageError.conflict }
        guard let range else { return h.readDataToEndOfFile() }
        try h.seek(toOffset: UInt64(range.lowerBound))
        return h.readData(ofLength: Int(range.upperBound - range.lowerBound + 1))
    }

    public func download(_ key: String, to dest: URL, version expected: String?) throws -> String {
        try checkOnline()
        let src = file(key)
        guard let v = version(src) else { throw StorageError.notFound }
        if let expected, expected != v { throw StorageError.conflict }
        try? FileManager.default.removeItem(at: dest)
        try FileManager.default.copyItem(at: src, to: dest)
        return v
    }

    private func place(_ key: String, replacing expected: String?, _ write: (URL) throws -> Void) throws -> String {
        try checkOnline()
        let dest = file(key)
        try FileManager.default.createDirectory(at: dest.deletingLastPathComponent(), withIntermediateDirectories: true)
        let tmp = dest.deletingLastPathComponent().appendingPathComponent(".tmp-\(UUID().uuidString)")
        defer { unlink(tmp.path) }
        try write(tmp)
        return try locked {
            guard version(dest) == expected else { throw StorageError.conflict }
            guard rename(tmp.path, dest.path) == 0, let v = version(dest) else { throw StorageError.failed("Cannot write \(key)") }
            return v
        }
    }

    public func put(_ key: String, data: Data, replacing version: String?) throws -> String {
        try place(key, replacing: version) { try data.write(to: $0) }
    }

    public func upload(_ key: String, from src: URL, replacing version: String?) throws -> String {
        try place(key, replacing: version) { try FileManager.default.copyItem(at: src, to: $0) }
    }
}
