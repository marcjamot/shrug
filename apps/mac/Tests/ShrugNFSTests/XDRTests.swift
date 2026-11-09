import XCTest
@testable import ShrugNFS

final class XDRTests: XCTestCase {
    func testRoundTrip() throws {
        var w = XDRWriter()
        w.u32(7)
        w.u64(0x1122_3344_5566_7788)
        w.bool(true)
        w.string("héllo")
        w.opaque(Data([1, 2, 3]))
        XCTAssertEqual(w.data.count % 4, 0)

        var r = XDRReader(w.data)
        XCTAssertEqual(try r.u32(), 7)
        XCTAssertEqual(try r.u64(), 0x1122_3344_5566_7788)
        XCTAssertEqual(try r.bool(), true)
        XCTAssertEqual(try r.string(), "héllo")
        XCTAssertEqual(try r.opaque(), Data([1, 2, 3]))
        XCTAssertThrowsError(try r.u32())
    }

    func testOversizedOpaqueIsRejected() {
        var w = XDRWriter()
        w.u32(1000)
        var r = XDRReader(w.data)
        XCTAssertThrowsError(try r.opaque(max: 10))
    }
}
