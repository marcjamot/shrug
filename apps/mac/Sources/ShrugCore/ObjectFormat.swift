import CryptoKit
import Darwin
import Foundation

/// Every key Shrug uses for the bucket, derived from the vault key (shared by all Macs).
public struct VaultKeys: @unchecked Sendable {
    public let master: SymmetricKey
    let names: SymmetricKey
    let headers: SymmetricKey
    let meta: SymmetricKey

    public init(master: SymmetricKey) {
        self.master = master
        names = ShrugCrypto.subkey(master, "shrug-names-v1")
        headers = ShrugCrypto.subkey(master, "shrug-headers-v1")
        meta = ShrugCrypto.subkey(master, "shrug-meta-v1")
    }

    /// The bucket name for a file, like "synced/ssh/id_ed25519" -> "f/3fa1…". It looks random
    /// to the storage provider, but is the same on every Mac.
    public func objectKey(_ path: String) -> String { "f/" + ShrugCrypto.hmacHex(names, "file:" + path) }

    public func profileKey(_ name: String) -> String { "m/p/" + ShrugCrypto.hmacHex(names, "profile:" + name) }

    public static func deviceKey(_ id: String) -> String { "m/d/" + id }

    /// The password-wrapped vault key. The only object that isn't sealed with the vault key itself.
    public static let keyringKey = "m/keyring"

    /// Metadata (profiles, Macs): sealed JSON, bound to its bucket name.
    public func sealMeta<T: Encodable>(_ value: T, key: String) throws -> Data {
        try ShrugCrypto.seal(JSONFile.encode(value), key: meta, aad: Data("shrug-meta:\(key)".utf8))
    }

    public func openMeta<T: Decodable>(_ type: T.Type, _ data: Data, key: String) throws -> T {
        guard let plain = try? ShrugCrypto.open(data, key: meta, aad: Data("shrug-meta:\(key)".utf8)) else {
            throw ShrugError("Can't decrypt \(key) (wrong vault key or damaged)")
        }
        return try JSONFile.decode(T.self, from: plain)
    }
}

public enum ObjectKind: String, Codable, Sendable { case file, dir, deleted }

/// What a file object says about itself. Stored encrypted; the provider never sees it.
public struct ObjectHeader: Codable, Equatable, Sendable {
    public var path: String
    public var kind: ObjectKind
    /// When the content last really changed; the newest edit wins between Macs.
    public var editedAt: Date
    /// The modification time programs see.
    public var mtime: Date
    public var size: Int64
    public var mode: UInt16
    /// Hex of the content's file id (nil for empty content), which binds the content to this
    /// header: a download is only used if its content has exactly this id and size.
    public var fileID: String?

    public init(path: String, kind: ObjectKind, editedAt: Date, mtime: Date, size: Int64, mode: UInt16, fileID: String?) {
        self.path = path
        self.kind = kind
        self.editedAt = editedAt
        self.mtime = mtime
        self.size = size
        self.mode = mode
        self.fileID = fileID
    }
}

/// File objects in the bucket, and Shrug's local copies of them, byte for byte:
///
///     "SHRUGOB1" | slot size (u32 BE) | header slot | content
///
/// The slot holds the sealed header's length (u32 BE), the sealed header and zero
/// padding. It always has the same size, so the header can be rewritten in place and
/// never reveals how long the path is. The content is EncFormat from `contentOffset`.
public enum ObjectFormat {
    public static let magic = Data("SHRUGOB1".utf8)
    public static let slotSize = 4096
    public static let contentOffset = Int64(12 + slotSize)

    static func u32(_ v: Int) -> Data { withUnsafeBytes(of: UInt32(v).bigEndian) { Data($0) } }

    static func aad(_ objectKey: String) -> Data { Data("shrug-object:\(objectKey)".utf8) }

    /// The exact size of a complete file object whose content is `plainSize` bytes.
    public static func objectSize(plainSize: Int64) -> Int64 {
        contentOffset + EncFormat.encryptedSize(plainSize: plainSize)
    }

    /// The start of a new local copy, with an empty header slot.
    public static func blankPrefix() -> Data { magic + u32(slotSize) + Data(count: slotSize) }

    /// The full prefix (magic, slot size, sealed header slot).
    public static func prefix(_ header: ObjectHeader, keys: VaultKeys, objectKey: String) throws -> Data {
        let sealed = try ShrugCrypto.seal(JSONFile.encode(header), key: keys.headers, aad: aad(objectKey))
        guard sealed.count + 4 <= slotSize else { throw ShrugError("Path too long") }
        return magic + u32(slotSize) + u32(sealed.count) + sealed + Data(count: slotSize - 4 - sealed.count)
    }

    public static func decodeHeader(_ prefix: Data, keys: VaultKeys, objectKey: String) throws -> ObjectHeader {
        let p = Data(prefix)
        guard p.count >= 16, p.prefix(8) == magic else { throw ShrugError("Not a Shrug object") }
        let slot = Int(p.subdata(in: 8..<12).withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) })
        let length = Int(p.subdata(in: 12..<16).withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) })
        guard slot == slotSize, length > 0, 16 + length <= p.count, length + 4 <= slot else {
            throw ShrugError("Damaged Shrug object header")
        }
        guard let plain = try? ShrugCrypto.open(p.subdata(in: 16..<(16 + length)), key: keys.headers, aad: aad(objectKey)) else {
            throw ShrugError("Can't decrypt an object header (wrong vault key, or it was moved or changed)")
        }
        return try JSONFile.decode(ObjectHeader.self, from: plain)
    }

    /// Rewrites the header of a local copy in place.
    public static func writeHeader(_ header: ObjectHeader, to url: URL, keys: VaultKeys, objectKey: String) throws {
        let data = try prefix(header, keys: keys, objectKey: objectKey)
        let fd = Darwin.open(url.path, O_WRONLY)
        guard fd >= 0 else { throw ShrugError("Cannot open a local copy: \(String(cString: strerror(errno)))") }
        defer { Darwin.close(fd) }
        let n = data.withUnsafeBytes { pwrite(fd, $0.baseAddress, data.count, 0) }
        guard n == data.count else { throw ShrugError("Cannot write a local copy: \(String(cString: strerror(errno)))") }
    }

    /// Reads the header of a local copy.
    public static func readHeader(of url: URL, keys: VaultKeys, objectKey: String) throws -> ObjectHeader {
        let h = try FileHandle(forReadingFrom: url)
        defer { try? h.close() }
        return try decodeHeader(h.readData(ofLength: Int(contentOffset)), keys: keys, objectKey: objectKey)
    }

    /// Reads and checks a whole object, such as a download: its header must open under
    /// `objectKey` and name the path that key belongs to, and a file's content must be exactly
    /// the content that header describes, every chunk intact.
    public static func verifiedHeader(of url: URL, keys: VaultKeys, objectKey: String) throws -> ObjectHeader {
        let h = try readHeader(of: url, keys: keys, objectKey: objectKey)
        guard keys.objectKey(h.path) == objectKey else { throw ShrugError("An object claims another file's name") }
        guard h.kind == .file else { return h }
        let content = try EncryptedFile(url: url, master: keys.master, writable: false, base: contentOffset)
        guard content.matches(fileID: h.fileID, size: h.size) else {
            throw ShrugError("An object's content doesn't match its header (damaged, or changed by the storage)")
        }
        try content.verify()
        return h
    }
}
