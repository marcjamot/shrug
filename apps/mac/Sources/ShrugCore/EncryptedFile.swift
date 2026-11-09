import CryptoKit
import Darwin
import Foundation

/// The encrypted content format, used for every file Shrug stores:
///
///     header:  "SHRUGEN1" | fileID (16 random bytes) | chunkSize (u32 BE)
///     chunks:  nonce (12) | ciphertext (<= chunkSize) | tag (16)
///
/// Every file gets its own key: HKDF(master, salt: fileID). Each chunk is sealed
/// with a fresh random nonce and authenticated together with its index, so a
/// program can read or write any part of a large file without touching the rest,
/// and a download can fetch just the chunks it needs.
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
        var fd = writable ? Darwin.open(url.path, O_RDWR) : -1
        if fd < 0 { fd = Darwin.open(url.path, O_RDONLY) }
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

    var encryptedSize: Int64 {
        var st = stat()
        fstat(fd, &st)
        return max(0, Int64(st.st_size) - base)
    }

    public var size: Int64 { EncFormat.plainSize(encryptedSize: encryptedSize) }

    /// The random id that binds this content to its key (nil while empty).
    public var contentFileID: Data? { fileID }

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

    public func write(offset: Int64, data: Data) throws {
        var offset = offset
        var data = Data(data)
        let size = self.size
        if offset > size {
            data = Data(count: Int(offset - size)) + data
            offset = size
        }
        guard !data.isEmpty else { return }
        let cs = Int64(EncFormat.chunkSize)
        let end = offset + Int64(data.count)
        let existingChunks = chunkCount
        for index in Int(offset / cs)...Int((end - 1) / cs) {
            let start = Int64(index) * cs
            let existing = index < existingChunks ? try readChunk(index) : Data()
            let newLength = max(existing.count, Int(min(cs, end - start)))
            var buffer = existing
            if buffer.count < newLength { buffer.append(Data(count: newLength - buffer.count)) }
            let from = max(offset, start)
            let to = min(end, start + cs)
            buffer.replaceSubrange(
                Int(from - start)..<Int(to - start),
                with: data.subdata(in: Int(from - offset)..<Int(to - offset)))
            if buffer == existing { continue } // unchanged content: keep the file byte-identical
            try writeChunk(index, buffer)
        }
    }

    public func truncate(to newSize: Int64) throws {
        let size = self.size
        if newSize == size { return }
        if newSize > size {
            try write(offset: size, data: Data(count: Int(newSize - size)))
            return
        }
        let cs = Int64(EncFormat.chunkSize)
        let keep = Int(newSize / cs)
        let rem = Int(newSize % cs)
        if rem > 0 {
            let chunk = try readChunk(keep)
            guard ftruncate(fd, recordOffset(keep)) == 0 else { throw ShrugError("Truncate failed") }
            try writeChunk(keep, chunk.prefix(rem))
        } else {
            guard ftruncate(fd, newSize == 0 && fileID == nil ? off_t(base) : recordOffset(keep)) == 0 else {
                throw ShrugError("Truncate failed")
            }
        }
    }
}
