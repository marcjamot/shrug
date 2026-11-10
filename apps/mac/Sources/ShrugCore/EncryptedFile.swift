import CryptoKit
import Darwin
import Foundation

/// The encrypted content format, used for every file Shrug stores:
///
///     header:  "SHRUGEN1" | fileID (16 random bytes) | chunkSize (u32 BE)
///     chunks:  nonce (12) | ciphertext (<= chunkSize) | tag (16)
///
/// Every file gets its own key: HKDF(master, salt: fileID). Each chunk is sealed with a fresh
/// random nonce and authenticated together with its index, so a program can read or write any
/// part of a large file without touching the rest, and a download can fetch just the chunks it
/// needs. Every upload is a fresh copy under a new file id, so chunks from different versions
/// of a file never fit together. Empty content has no header at all.
public enum EncFormat {
    public static let magic = Data("SHRUGEN1".utf8)
    public static let chunkSize = 65536
    public static let headerSize = 28
    public static let overhead = 28
    public static let recordSize = chunkSize + overhead

    /// Plain size from encrypted size alone.
    public static func plainSize(encryptedSize: Int64) -> Int64 {
        let body = encryptedSize - Int64(headerSize)
        if body <= 0 { return 0 }
        let rs = Int64(recordSize)
        let full = body / rs
        let rem = body % rs
        return full * Int64(chunkSize) + (rem > Int64(overhead) ? rem - Int64(overhead) : 0)
    }

    /// The exact encrypted size of complete content of `plainSize` bytes.
    public static func encryptedSize(plainSize: Int64) -> Int64 {
        guard plainSize > 0 else { return 0 }
        let cs = Int64(chunkSize)
        let rem = plainSize % cs
        return Int64(headerSize) + plainSize / cs * Int64(recordSize) + (rem > 0 ? rem + Int64(overhead) : 0)
    }

    public static func fileKey(master: SymmetricKey, fileID: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: master, salt: fileID, info: Data("shrug-file-v1".utf8), outputByteCount: 32)
    }

    public static func aad(fileID: Data, index: Int) -> Data {
        var d = fileID
        withUnsafeBytes(of: UInt64(index).bigEndian) { d.append(contentsOf: $0) }
        return d
    }

    static func header(fileID: Data) -> Data {
        var d = magic + fileID
        withUnsafeBytes(of: UInt32(chunkSize).bigEndian) { d.append(contentsOf: $0) }
        return d
    }

    /// The file id from a content header, or nil if `data` isn't one.
    public static func fileID(fromHeader data: Data) -> Data? {
        guard data.count >= headerSize, data.prefix(8) == magic else { return nil }
        return data.subdata(in: data.startIndex + 8..<data.startIndex + 24)
    }

    /// Opens one chunk record fetched on its own (for streaming from the bucket).
    public static func openChunk(_ record: Data, master: SymmetricKey, fileID: Data, index: Int) throws -> Data {
        try ShrugCrypto.open(record, key: fileKey(master: master, fileID: fileID), aad: aad(fileID: fileID, index: index))
    }
}

/// Random-access reads and writes on one encrypted file. The content may start at
/// `base`, after a header that isn't part of it (as in bucket objects).
public final class EncryptedFile {
    public let url: URL
    private let fd: Int32
    private let master: SymmetricKey
    private let base: Int64
    private var fileID: Data?
    private var key: SymmetricKey?

    public init(url: URL, master: SymmetricKey, writable: Bool, base: Int64 = 0) throws {
        self.url = url
        self.master = master
        self.base = base
        let fd = Darwin.open(url.path, writable ? O_RDWR : O_RDONLY)
        guard fd >= 0 else { throw ShrugError("Cannot open \(url.lastPathComponent): \(String(cString: strerror(errno)))") }
        self.fd = fd
        let size = encryptedSize
        if size == 0 { return } // no content yet: the header is written on first write
        guard size >= Int64(EncFormat.headerSize) else { throw ShrugError("\(url.lastPathComponent) is not a Shrug file") }
        var header = Data(count: EncFormat.headerSize)
        let n = header.withUnsafeMutableBytes { pread(fd, $0.baseAddress, EncFormat.headerSize, off_t(base)) }
        guard n == EncFormat.headerSize, let id = EncFormat.fileID(fromHeader: header) else {
            throw ShrugError("\(url.lastPathComponent) is not a Shrug file")
        }
        let chunk = header.subdata(in: 24..<28).withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) }
        guard chunk == UInt32(EncFormat.chunkSize) else { throw ShrugError("Unsupported chunk size in \(url.lastPathComponent)") }
        fileID = id
        key = EncFormat.fileKey(master: master, fileID: id)
    }

    deinit { Darwin.close(fd) }

    private var encryptedSize: Int64 {
        var st = stat()
        fstat(fd, &st)
        return max(0, Int64(st.st_size) - base)
    }

    public var size: Int64 { EncFormat.plainSize(encryptedSize: encryptedSize) }

    /// The random id that binds this content to its key (nil while empty).
    public var contentFileID: Data? { fileID }

    /// Whether this is exactly the content a header describes: the same file id, and complete.
    public func matches(fileID expected: String?, size expectedSize: Int64) -> Bool {
        fileID?.hex == expected && encryptedSize == EncFormat.encryptedSize(plainSize: expectedSize)
    }

    /// Decrypts every chunk, so damage shows up now rather than when a program reads it.
    public func verify() throws {
        for index in 0..<chunkCount { _ = try readChunk(index) }
    }

    /// Copies the content into a new file at `url`, after `prefix`, under a fresh file id.
    public func reencrypt(to url: URL, prefix: Data) throws -> EncryptedFile {
        guard FileManager.default.createFile(atPath: url.path, contents: prefix, attributes: [.posixPermissions: 0o600]) else {
            throw ShrugError("Cannot create \(url.lastPathComponent)")
        }
        let copy = try EncryptedFile(url: url, master: master, writable: true, base: Int64(prefix.count))
        for index in 0..<chunkCount { try copy.writeChunk(index, try readChunk(index)) }
        return copy
    }

    private var chunkCount: Int {
        let body = encryptedSize - Int64(EncFormat.headerSize)
        if body <= 0 { return 0 }
        return Int((body + Int64(EncFormat.recordSize) - 1) / Int64(EncFormat.recordSize))
    }

    private func recordOffset(_ index: Int) -> off_t {
        off_t(base + Int64(EncFormat.headerSize + index * EncFormat.recordSize))
    }

    private func ensureHeader() throws -> (Data, SymmetricKey) {
        if let fileID, let key { return (fileID, key) }
        let id = ShrugCrypto.random(16)
        let header = EncFormat.header(fileID: id)
        let n = header.withUnsafeBytes { pwrite(fd, $0.baseAddress, header.count, off_t(base)) }
        guard n == header.count else { throw ShrugError("Write failed: \(String(cString: strerror(errno)))") }
        let k = EncFormat.fileKey(master: master, fileID: id)
        fileID = id
        key = k
        return (id, k)
    }

    private func readChunk(_ index: Int) throws -> Data {
        guard let fileID, let key else { return Data() }
        var record = Data(count: EncFormat.recordSize)
        let n = record.withUnsafeMutableBytes { pread(fd, $0.baseAddress, EncFormat.recordSize, recordOffset(index)) }
        guard n > EncFormat.overhead else {
            if n == 0 { return Data() }
            throw ShrugError("Truncated chunk in \(url.lastPathComponent)")
        }
        record.count = n
        do {
            return try ShrugCrypto.open(record, key: key, aad: EncFormat.aad(fileID: fileID, index: index))
        } catch {
            throw ShrugError("Cannot decrypt \(url.lastPathComponent) (wrong key or damaged file)")
        }
    }

    private func writeChunk(_ index: Int, _ plain: Data) throws {
        let (fileID, key) = try ensureHeader()
        let record = try ShrugCrypto.seal(plain, key: key, aad: EncFormat.aad(fileID: fileID, index: index))
        let n = record.withUnsafeBytes { pwrite(fd, $0.baseAddress, record.count, recordOffset(index)) }
        guard n == record.count else { throw ShrugError("Write failed: \(String(cString: strerror(errno)))") }
    }

    public func read(offset: Int64, count: Int) throws -> Data {
        let size = self.size
        guard offset < size, count > 0 else { return Data() }
        let cs = Int64(EncFormat.chunkSize)
        let end = min(size, offset + Int64(count))
        var out = Data(capacity: Int(end - offset))
        for index in Int(offset / cs)...Int((end - 1) / cs) {
            let chunk = try readChunk(index)
            let start = Int64(index) * cs
            let from = Int(max(offset, start) - start)
            let to = Int(min(end, start + Int64(chunk.count)) - start)
            if from < to { out.append(chunk.subdata(in: from..<to)) }
        }
        return out
    }

    /// Writes `data` at `offset`, filling any gap after the current end with zeros.
    public func write(offset: Int64, data: Data) throws {
        guard !data.isEmpty else { return }
        try fill(from: min(offset, size), to: offset + Int64(data.count), with: data, at: offset)
    }

    public func truncate(to newSize: Int64) throws {
        let size = self.size
        if newSize >= size { return try fill(from: size, to: newSize, with: Data(), at: newSize) }
        if newSize == 0 {
            guard ftruncate(fd, off_t(base)) == 0 else { throw ShrugError("Truncate failed") }
            fileID = nil
            key = nil
            return
        }
        let cs = Int64(EncFormat.chunkSize)
        let keep = Int(newSize / cs)
        let rem = Int(newSize % cs)
        let last = rem > 0 ? try readChunk(keep) : Data()
        guard ftruncate(fd, recordOffset(keep)) == 0 else { throw ShrugError("Truncate failed") }
        if rem > 0 { try writeChunk(keep, last.prefix(rem)) }
    }

    /// Rewrites the chunks covering `start..<end`: existing bytes stay, `data` (which belongs at
    /// `dataOffset`) goes in where it overlaps, and the rest is zeros. One chunk at a time, so a
    /// large gap never sits in memory.
    private func fill(from start: Int64, to end: Int64, with data: Data, at dataOffset: Int64) throws {
        guard start < end else { return }
        let cs = Int64(EncFormat.chunkSize)
        let existingChunks = chunkCount
        let dataEnd = dataOffset + Int64(data.count)
        for index in Int(start / cs)...Int((end - 1) / cs) {
            let chunkStart = Int64(index) * cs
            let existing = index < existingChunks ? try readChunk(index) : Data()
            var buffer = existing
            let length = Int(min(cs, end - chunkStart))
            if buffer.count < length { buffer.append(Data(count: length - buffer.count)) }
            let from = max(dataOffset, chunkStart)
            let to = min(dataEnd, chunkStart + cs)
            if from < to {
                let slice = data.startIndex + Int(from - dataOffset)
                buffer.replaceSubrange(Int(from - chunkStart)..<Int(to - chunkStart),
                                       with: data[slice..<(slice + Int(to - from))])
            }
            if buffer != existing { try writeChunk(index, buffer) } // unchanged content stays byte-identical
        }
    }
}
