import CryptoKit
import Darwin
import Foundation
import ShrugCore

/// The index as index.enc holds it.
struct IndexFile: Codable {
    /// The id of the journal that continues this index.
    var journal: String
    var entries: [String: Entry]
}

/// One journal record: entries as they are now, and paths that have none any more.
struct IndexChanges: Codable {
    var changed: [String: Entry] = [:]
    var removed: [String] = []

    var isEmpty: Bool { changed.isEmpty && removed.isEmpty }
}

/// This Mac's index of ~/Shrug on disk, sealed with the local key:
///
///     index.enc       every entry, as of the last time the whole index was written
///     index.journal   the changes since: "SHRUGIJ1" | id (16 random bytes) | records
///     record          length (u32 BE) | sealed JSON, padded so its length says little
///
/// A change adds one small record, so saving costs the same however much is in ~/Shrug. Once
/// the journal has grown as long as the index, the index is written whole again and a new
/// journal starts.
///
/// index.enc names the journal that continues it, so a journal left over from an earlier
/// index (a crash between writing the two) is never applied again. Every record is sealed to
/// its journal and its place in it. A record that a crash cut short doesn't open, and the
/// journal ends before it.
///
/// One caller at a time: the store saves its changes in order.
final class SavedIndex {
    static let magic = Data("SHRUGIJ1".utf8)
    static let headerSize = 24
    /// Records are padded to a multiple of this, so their lengths don't give path lengths away.
    static let padding = 256
    private let paths: ShrugPaths
    private let key: SymmetricKey
    private let recordKey: SymmetricKey
    private var fd: Int32 = -1
    private var id = Data()
    /// Records in the journal, and its length in bytes.
    private var count: UInt64 = 0
    private var size = 0
    private var snapshotBytes = 0
    /// Bytes at the end of the journal that weren't used when it was read (see `load`).
    private(set) var ignored = 0

    init(paths: ShrugPaths, key: SymmetricKey) {
        self.paths = paths
        self.key = key
        recordKey = ShrugCrypto.subkey(key, "shrug-index-journal-v1")
    }

    deinit { close() }

    /// False after a failure that left the journal unusable: only `rewrite` helps then.
    var isOpen: Bool { fd >= 0 }

    /// Whether it's time to write the index whole again: the journal has outgrown it, and
    /// isn't `short`.
    func journalIsLong(over short: Int) -> Bool { size - SavedIndex.headerSize > max(short, snapshotBytes) }

    func close() {
        if fd >= 0 { Darwin.close(fd) }
        fd = -1
    }

    // MARK: - Reading

    /// Reads the index: the last whole copy, then every change since. Leaves the journal open
    /// for the next change.
    func load() throws -> [String: Entry] {
        guard let plain = try SealedFile.index.read(paths, key: key) else {
            try rewrite([:]) // nothing was ever saved
            return [:]
        }
        let file = try JSONFile.decode(IndexFile.self, from: plain)
        guard let id = Data(hex: file.journal), id.count == 16 else {
            throw ShrugError("This Mac's index of ~/Shrug is damaged")
        }
        var entries = file.entries
        snapshotBytes = plain.count
        var journal = Data()
        if FileManager.default.fileExists(atPath: paths.journalFile.path) {
            journal = try Data(contentsOf: paths.journalFile)
        }
        guard journal.prefix(SavedIndex.headerSize) == SavedIndex.magic + id else {
            // Not this index's journal: left from before the index was last written whole, or
            // missing. Either way nothing changed since.
            ignored = max(0, journal.count - SavedIndex.headerSize)
            try start(id)
            return entries
        }
        self.id = id
        var end = SavedIndex.headerSize
        while let (changes, next) = record(in: journal, at: end) {
            for (path, entry) in changes.changed { entries[path] = entry }
            for path in changes.removed { entries[path] = nil }
            end = next
            count += 1
        }
        ignored = journal.count - end
        try open(at: end)
        return entries
    }

    /// The record at `offset` and where the next one starts, or nil where the journal ends.
    private func record(in journal: Data, at offset: Int) -> (IndexChanges, Int)? {
        guard offset + 4 <= journal.count else { return nil }
        let length = Int(journal.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
            UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self))
        })
        let end = offset + 4 + length
        guard length > 0, end <= journal.count,
              let plain = try? ShrugCrypto.open(journal.subdata(in: (offset + 4)..<end), key: recordKey, aad: aad(count)),
              let changes = try? JSONFile.decode(IndexChanges.self, from: plain)
        else { return nil }
        return (changes, end)
    }

    private func aad(_ position: UInt64) -> Data {
        var d = Data("shrug-index-journal-v1".utf8) + id
        withUnsafeBytes(of: position.bigEndian) { d.append(contentsOf: $0) }
        return d
    }

    // MARK: - Writing

    /// Opens the journal for adding records after its first `end` bytes.
    private func open(at end: Int) throws {
        let fd = Darwin.open(paths.journalFile.path, O_WRONLY | O_APPEND)
        guard fd >= 0, ftruncate(fd, off_t(end)) == 0 else {
            let why = String(cString: strerror(errno))
            if fd >= 0 { Darwin.close(fd) }
            throw ShrugError("Cannot open this Mac's index journal: \(why)")
        }
        self.fd = fd
        size = end
    }

    /// Starts an empty journal for the index that names `id`.
    private func start(_ id: Data) throws {
        close()
        try JSONFile.writeAtomically(SavedIndex.magic + id, to: paths.journalFile)
        self.id = id
        count = 0
        try open(at: SavedIndex.headerSize)
    }

    /// Writes the whole index, and starts a new journal for it. Both are on the disk for good
    /// when this returns.
    func rewrite(_ entries: [String: Entry]) throws {
        let id = ShrugCrypto.random(16)
        let plain = try JSONFile.encodeCompact(IndexFile(journal: id.hex, entries: entries))
        try SealedFile.index.write(plain, paths, key: key)
        // The old journal belongs to no index now: nothing more may be added to it.
        close()
        snapshotBytes = plain.count
        try start(id)
    }

    /// Adds one record. It's in the system's hands when this returns, so it survives Shrug
    /// crashing; `sync` puts it on the disk.
    func append(_ changes: IndexChanges) throws {
        guard isOpen else { throw ShrugError("This Mac's index journal isn't open") }
        var plain = try JSONFile.encodeCompact(changes)
        let unit = SavedIndex.padding
        plain.append(Data(repeating: 0x20, count: (unit - plain.count % unit) % unit))
        let sealed = try ShrugCrypto.seal(plain, key: recordKey, aad: aad(count))
        let record = withUnsafeBytes(of: UInt32(sealed.count).bigEndian) { Data($0) } + sealed
        guard Descriptor.writeAll(fd, record) else {
            let why = String(cString: strerror(errno))
            // Half a record would hide every record after it: cut it off, or give the journal up.
            if ftruncate(fd, off_t(size)) != 0 { close() }
            throw ShrugError("Could not save a change to this Mac's index: \(why)")
        }
        size += record.count
        count += 1
    }

    /// Puts every record on the disk, as fsync does. With `flush`, through the disk's own
    /// cache too, so not even a power cut loses them.
    func sync(flush: Bool) throws {
        guard isOpen else { throw ShrugError("This Mac's index journal isn't open") }
        guard (flush ? fcntl(fd, F_FULLFSYNC) : fsync(fd)) == 0 else {
            throw ShrugError("Could not save this Mac's index: \(String(cString: strerror(errno)))")
        }
    }
}
