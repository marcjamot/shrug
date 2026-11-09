import Foundation

struct XDRError: Error {}

/// Big-endian XDR decoding (RFC 4506), just the parts NFSv3 needs.
public struct XDRReader {
    let data: Data
    var pos: Int

    public init(_ data: Data) {
        self.data = Data(data)
        self.pos = 0
    }

    mutating func u32() throws -> UInt32 {
        guard pos + 4 <= data.count else { throw XDRError() }
        let v = data.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(fromByteOffset: pos, as: UInt32.self)) }
        pos += 4
        return v
    }

    mutating func u64() throws -> UInt64 {
        let hi = UInt64(try u32())
        let lo = UInt64(try u32())
        return hi << 32 | lo
    }

    mutating func bool() throws -> Bool { try u32() != 0 }

    mutating func fixed(_ n: Int) throws -> Data {
        guard pos + n <= data.count else { throw XDRError() }
        let d = data.subdata(in: pos..<(pos + n))
        pos += (n + 3) & ~3
        return d
    }

    mutating func opaque(max: Int = 1 << 24) throws -> Data {
        let n = Int(try u32())
        guard n <= max else { throw XDRError() }
        return try fixed(n)
    }

    mutating func string(max: Int = 4096) throws -> String {
        String(decoding: try opaque(max: max), as: UTF8.self)
    }
}

public struct XDRWriter {
    public private(set) var data = Data()

    public init() {}

    mutating func u32(_ v: UInt32) {
        withUnsafeBytes(of: v.bigEndian) { data.append(contentsOf: $0) }
    }

    mutating func u64(_ v: UInt64) {
        u32(UInt32(truncatingIfNeeded: v >> 32))
        u32(UInt32(truncatingIfNeeded: v))
    }

    mutating func bool(_ v: Bool) { u32(v ? 1 : 0) }

    mutating func fixed(_ d: Data) {
        data.append(d)
        let pad = (4 - d.count % 4) % 4
        if pad > 0 { data.append(Data(count: pad)) }
    }

    mutating func opaque(_ d: Data) {
        u32(UInt32(d.count))
        fixed(d)
    }

    mutating func string(_ s: String) { opaque(Data(s.utf8)) }

    mutating func append(_ other: XDRWriter) { data.append(other.data) }
}
