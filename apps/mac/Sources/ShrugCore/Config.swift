import Darwin
import Foundation

public enum JSONFile {
    static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        e.dateEncodingStrategy = .custom { date, encoder in
            var c = encoder.singleValueContainer()
            try c.encode(ISO8601.format(date))
        }
        return e
    }()

    /// The same, on one line: for what only Shrug reads, and writes often.
    static let compactEncoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.withoutEscapingSlashes]
        e.dateEncodingStrategy = encoder.dateEncodingStrategy
        return e
    }()

    static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .custom { decoder in
            let c = try decoder.singleValueContainer()
            let s = try c.decode(String.self)
            guard let date = ISO8601.parse(s) else {
                throw DecodingError.dataCorruptedError(in: c, debugDescription: "Bad date \(s)")
            }
            return date
        }
        return d
    }()

    public static func load<T: Decodable>(_ type: T.Type, from url: URL) throws -> T {
        try decoder.decode(T.self, from: Data(contentsOf: url))
    }

    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        try decoder.decode(T.self, from: data)
    }

    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        try encoder.encode(value)
    }

    public static func encodeCompact<T: Encodable>(_ value: T) throws -> Data {
        try compactEncoder.encode(value)
    }

    public static func save<T: Encodable>(_ value: T, to url: URL) throws {
        var data = try encoder.encode(value)
        data.append(0x0A)
        try writeAtomically(data, to: url)
    }

    /// Replaces `url` with `data` in one step, owner-only. The data reaches the disk before the
    /// rename, so after a crash the file is either the old version or the new one, never a mix.
    public static func writeAtomically(_ data: Data, to url: URL) throws {
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let tmp = dir.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
        let fd = open(tmp.path, O_WRONLY | O_CREAT | O_EXCL, 0o600)
        guard fd >= 0 else { throw ShrugError("Could not write \(url.lastPathComponent): \(String(cString: strerror(errno)))") }
        var written = Descriptor.writeAll(fd, data) && fcntl(fd, F_FULLFSYNC) == 0
        close(fd)
        if written { written = rename(tmp.path, url.path) == 0 }
        guard written else {
            unlink(tmp.path)
            throw ShrugError("Could not replace \(url.lastPathComponent): \(String(cString: strerror(errno)))")
        }
    }
}

public enum ISO8601 {
    private static let plain: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    private static let fractional: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    public static func format(_ date: Date) -> String { fractional.string(from: date) }
    public static func parse(_ s: String) -> Date? { fractional.date(from: s) ?? plain.date(from: s) }
}

/// Where Shrug gets the time, so tests can control it.
public struct Clock: Sendable {
    public let now: @Sendable () -> Date

    public init(_ now: @escaping @Sendable () -> Date) { self.now = now }

    public static let system = Clock { Date() }

    /// Rounded to what JSON keeps (milliseconds), so a time survives a round trip unchanged.
    public var nowMs: Date { now().ms }
}

extension Date {
    public var ms: Date { Date(timeIntervalSince1970: (timeIntervalSince1970 * 1000).rounded(.down) / 1000) }
}

/// One link: a path on this Mac that shows a file from ~/Shrug.
public struct Link: Codable, Equatable, Sendable {
    /// Where the link goes, with ~ for the home folder: "~/.ssh/id_ed25519".
    public var path: String
    /// The file it shows, relative to ~/Shrug: "synced/ssh/id_ed25519".
    public var target: String

    public init(path: String, target: String) {
        self.path = path
        self.target = target
    }
}

/// A named set of links, kept in the bucket. Several Macs can follow one; the last change wins.
public struct Profile: Codable, Sendable {
    public var name: String
    public var links: [Link]
    public var editedAt: Date

    public init(name: String, links: [Link], editedAt: Date) {
        self.name = name
        self.links = links
        self.editedAt = editedAt
    }
}

/// One Mac, as listed in the bucket.
public struct DeviceRecord: Codable, Sendable {
    public var name: String
    public var addedAt: Date

    public init(name: String, addedAt: Date) {
        self.name = name
        self.addedAt = addedAt
    }
}

/// The bucket's `m/keyring`: the vault key, wrapped with the Shrug password.
public struct VaultRecord: Codable, Sendable {
    /// The vault's format (see Migrations).
    public var version: Int
    public var keyring: Keyring

    public init(version: Int, keyring: Keyring) {
        self.version = version
        self.keyring = keyring
    }
}

/// This Mac's copy of the vault keyring (so the password works offline) and its own local
/// key, both wrapped with the Shrug password.
public struct LocalKeys: Codable, Sendable {
    public var vault: Keyring
    public var local: Keyring

    public init(vault: Keyring, local: Keyring) {
        self.vault = vault
        self.local = local
    }
}

/// `~/.shrug/keyring.json`: the LocalKeys, sealed by this Mac's security chip as well
/// (`{"chip": …}`) when it has one, or as they are (Macs without one, and installs from
/// before the chip was used, until their next unlock).
public enum KeyringFile: Codable, Sendable {
    case plain(LocalKeys)
    case chip(ChipSealed)

    private enum CodingKeys: String, CodingKey { case chip }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        if let sealed = try c.decodeIfPresent(ChipSealed.self, forKey: .chip) {
            self = .chip(sealed)
        } else {
            self = .plain(try LocalKeys(from: decoder))
        }
    }

    public func encode(to encoder: Encoder) throws {
        switch self {
        case .plain(let keys):
            try keys.encode(to: encoder)
        case .chip(let sealed):
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(sealed, forKey: .chip)
        }
    }
}
