import Darwin
import Foundation

public struct StoredObject: Sendable {
    public let key: String
    public let size: Int64
    /// Changes whenever the object is replaced.
    public let etag: String

    public init(key: String, size: Int64, etag: String) {
        self.key = key
        self.size = size
        self.etag = etag
    }
}

public enum StorageError: Error, CustomStringConvertible {
    case notFound
    /// No connection: try again later. Never treated as anything worse.
    case offline(String)
    /// The storage refused these credentials.
    case denied(String)
    case failed(String)

    public var description: String {
        switch self {
        case .notFound: return "not found"
        case .offline(let m): return "offline (\(m))"
        case .denied(let m): return "access denied (\(m))"
        case .failed(let m): return m
        }
    }
}

/// Dumb object storage. Everything Shrug hands it is already encrypted.
public protocol ObjectStorage: AnyObject {
    func list(prefix: String) throws -> [StoredObject]
    /// The whole object, or the bytes in `range` (inclusive).
    func get(_ key: String, range: ClosedRange<Int64>?) throws -> Data
    /// Downloads the object into `file`, returning its etag.
    func download(_ key: String, to file: URL) throws -> String
    func put(_ key: String, data: Data) throws -> String
    func upload(_ key: String, from file: URL) throws -> String
    func delete(_ key: String) throws
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
            let endpoint = URL(string: config.endpoint ?? "https://storage.googleapis.com")!
            return S3Storage(endpoint: endpoint, bucket: bucket, region: config.region ?? "auto",
                             accessID: c.accessID, secret: c.secret)
        case "folder":
            guard let path = config.path, !path.isEmpty else { throw ShrugError("No folder given") }
            return FolderStorage(root: URL(fileURLWithPath: path))
        default:
            throw ShrugError("Unknown storage '\(config.kind)'")
        }
    }
}

/// A plain folder used as a bucket: each object is a file. If the folder is missing,
/// the storage counts as offline, which is how tests switch the network off.
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

    private func etag(_ url: URL) throws -> String {
        var st = stat()
        guard stat(url.path, &st) == 0 else { throw StorageError.notFound }
        return "\(st.st_ino)-\(st.st_size)-\(st.st_mtimespec.tv_sec).\(st.st_mtimespec.tv_nsec)"
    }

    public func list(prefix: String) throws -> [StoredObject] {
        try checkOnline()
        guard let walker = FileManager.default.enumerator(atPath: root.path) else { return [] }
        var out: [StoredObject] = []
        while let rel = walker.nextObject() as? String {
            guard rel.hasPrefix(prefix), !(rel as NSString).lastPathComponent.hasPrefix(".tmp-") else { continue }
            let url = file(rel)
            var st = stat()
            guard stat(url.path, &st) == 0, st.st_mode & S_IFMT == S_IFREG else { continue }
            out.append(StoredObject(key: rel, size: Int64(st.st_size), etag: try etag(url)))
        }
        return out.sorted { $0.key < $1.key }
    }

    public func get(_ key: String, range: ClosedRange<Int64>?) throws -> Data {
        try checkOnline()
        guard let h = try? FileHandle(forReadingFrom: file(key)) else { throw StorageError.notFound }
        defer { try? h.close() }
        guard let range else { return h.readDataToEndOfFile() }
        try h.seek(toOffset: UInt64(range.lowerBound))
        return h.readData(ofLength: Int(range.upperBound - range.lowerBound + 1))
    }

    public func download(_ key: String, to dest: URL) throws -> String {
        try checkOnline()
        let src = file(key)
        guard FileManager.default.fileExists(atPath: src.path) else { throw StorageError.notFound }
        let tag = try etag(src)
        try? FileManager.default.removeItem(at: dest)
        try FileManager.default.copyItem(at: src, to: dest)
        return tag
    }

    private func place(_ key: String, _ write: (URL) throws -> Void) throws -> String {
        try checkOnline()
        let dest = file(key)
        try FileManager.default.createDirectory(at: dest.deletingLastPathComponent(), withIntermediateDirectories: true)
        let tmp = dest.deletingLastPathComponent().appendingPathComponent(".tmp-\(UUID().uuidString)")
        try write(tmp)
        guard rename(tmp.path, dest.path) == 0 else {
            unlink(tmp.path)
            throw StorageError.failed("Cannot write \(key)")
        }
        return try etag(dest)
    }

    public func put(_ key: String, data: Data) throws -> String {
        try place(key) { try data.write(to: $0) }
    }

    public func upload(_ key: String, from src: URL) throws -> String {
        try place(key) { try FileManager.default.copyItem(at: src, to: $0) }
    }

    public func delete(_ key: String) throws {
        try checkOnline()
        unlink(file(key).path)
    }
}
