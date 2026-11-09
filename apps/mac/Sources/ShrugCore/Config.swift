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

    /// Atomic write with owner-only permissions.
    public static func save<T: Encodable>(_ value: T, to url: URL, mode: Int = 0o600) throws {
        var data = try encoder.encode(value)
        data.append(0x0A)
        try writeAtomically(data, to: url, mode: mode)
    }

    public static func writeAtomically(_ data: Data, to url: URL, mode: Int = 0o600) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let tmp = url.deletingLastPathComponent().appendingPathComponent(".\(url.lastPathComponent).tmp")
        guard FileManager.default.createFile(atPath: tmp.path, contents: data, attributes: [.posixPermissions: mode]) else {
            throw ShrugError("Could not write \(url.lastPathComponent)")
        }
        guard rename(tmp.path, url.path) == 0 else { throw ShrugError("Could not replace \(url.lastPathComponent)") }
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
    public var version: Int
    public var keyring: Keyring

    public init(version: Int = 2, keyring: Keyring) {
        self.version = version
        self.keyring = keyring
    }
}

/// `~/.shrug/keyring.json`: this Mac's copy of the vault keyring (so the password works
/// offline) and its own local key, both wrapped with the Shrug password.
public struct LocalKeys: Codable, Sendable {
    public var vault: Keyring
    public var local: Keyring

    public init(vault: Keyring, local: Keyring) {
        self.vault = vault
        self.local = local
    }
}

extension Date {
    /// Rounded to what JSON keeps (milliseconds), so a time survives a round trip unchanged.
    public var ms: Date { Date(timeIntervalSince1970: (timeIntervalSince1970 * 1000).rounded(.down) / 1000) }

    public static var nowMs: Date { Date().ms }
}
