import XCTest
@testable import ShrugCore

/// Answers GCSStorage's requests in place of Google.
final class StubHTTP: URLProtocol {
    struct Reply {
        var status = 200
        var headers: [String: String] = [:]
        var body = Data()
        var error: URLError?
    }

    private static let lock = NSLock()
    nonisolated(unsafe) private static var handler: (URLRequest) -> Reply = { _ in Reply() }
    nonisolated(unsafe) private static var seen: [URLRequest] = []

    static func answer(_ handler: @escaping (URLRequest) -> Reply) {
        lock.lock()
        self.handler = handler
        seen = []
        lock.unlock()
    }

    static var requests: [URLRequest] {
        lock.lock()
        defer { lock.unlock() }
        return seen
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}

    override func startLoading() {
        StubHTTP.lock.lock()
        StubHTTP.seen.append(request)
        let reply = StubHTTP.handler(request)
        StubHTTP.lock.unlock()
        if let error = reply.error { return client!.urlProtocol(self, didFailWithError: error) }
        let response = HTTPURLResponse(url: request.url!, statusCode: reply.status, httpVersion: "HTTP/1.1",
                                       headerFields: reply.headers)!
        client!.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client!.urlProtocol(self, didLoad: reply.body)
        client!.urlProtocolDidFinishLoading(self)
    }
}

final class GCSStorageTests: XCTestCase {
    var storage: GCSStorage!

    override func setUp() {
        let config = GCSStorage.sessionConfiguration()
        config.protocolClasses = [StubHTTP.self]
        storage = GCSStorage(endpoint: URL(string: "https://storage.test")!, bucket: "vault", region: "auto",
                             accessID: "GOOG1EXAMPLE", secret: "secret", configuration: config)
    }

    func listing(_ objects: [(String, String?)], truncated: Bool = false) -> Data {
        let contents = objects.map { key, generation in
            "<Contents><Key>\(key)</Key>" + (generation.map { "<Generation>\($0)</Generation>" } ?? "")
                + "<Size>10</Size><ETag>\"abc\"</ETag></Contents>"
        }.joined()
        return Data("""
        <?xml version="1.0"?><ListBucketResult><IsTruncated>\(truncated)</IsTruncated>\(contents)</ListBucketResult>
        """.utf8)
    }

    func testListsEveryPageWithGenerations() throws {
        StubHTTP.answer { request in
            let query = request.url?.query ?? ""
            return query.contains("marker=")
                ? StubHTTP.Reply(body: self.listing([("f/3", "300")]))
                : StubHTTP.Reply(body: self.listing([("f/1", "100"), ("f/2", "200")], truncated: true))
        }
        let objects = try storage.list(prefix: "f/")
        XCTAssertEqual(objects.map(\.key), ["f/1", "f/2", "f/3"])
        XCTAssertEqual(objects.map(\.version), ["100", "200", "300"])
        XCTAssertEqual(StubHTTP.requests.count, 2)
        XCTAssertEqual(StubHTTP.requests[1].url?.query, "marker=f%2F2&prefix=f%2F", "the next page starts after the last key")
    }

    func testAListingWithoutGenerationsIsRefused() {
        StubHTTP.answer { _ in StubHTTP.Reply(body: self.listing([("f/1", nil)])) }
        XCTAssertThrowsError(try storage.list(prefix: ""))
    }

    func testWritesAreConditionalAndSigned() throws {
        StubHTTP.answer { _ in StubHTTP.Reply(headers: ["x-goog-generation": "42"]) }
        XCTAssertEqual(try storage.put("f/a", data: Data("x".utf8), replacing: nil), "42")
        XCTAssertEqual(try storage.put("f/a", data: Data("y".utf8), replacing: "41"), "42")
        let requests = StubHTTP.requests
        XCTAssertEqual(requests.map { $0.value(forHTTPHeaderField: "x-goog-if-generation-match") }, ["0", "41"],
                       "a new object must not exist yet; a replacement names what it replaces")
        let auth = requests[0].value(forHTTPHeaderField: "Authorization") ?? ""
        XCTAssertTrue(auth.hasPrefix("GOOG4-HMAC-SHA256 "), auth)
        XCTAssertTrue(auth.contains("x-goog-if-generation-match"), "Google requires every x-goog header to be signed")
        let names = (requests[0].allHTTPHeaderFields ?? [:]).keys.map { $0.lowercased() }
        XCTAssertTrue(names.contains("x-goog-date") && names.contains("x-goog-content-sha256"))
        XCTAssertFalse(names.contains { $0.hasPrefix("x-amz-") }, "Google refuses x-amz and x-goog headers together")
        XCTAssertEqual(requests[0].httpMethod, "PUT")
        XCTAssertEqual(requests[0].url?.path, "/vault/f/a")
    }

    func testRangedReadsNameTheirVersion() throws {
        StubHTTP.answer { _ in StubHTTP.Reply(body: Data("0123456789".utf8)) }
        XCTAssertEqual(try storage.get("f/a", range: 0...9, version: "7"), Data("0123456789".utf8))
        let request = try XCTUnwrap(StubHTTP.requests.first)
        XCTAssertEqual(request.value(forHTTPHeaderField: "range"), "bytes=0-9")
        XCTAssertEqual(request.value(forHTTPHeaderField: "x-goog-if-generation-match"), "7")
    }

    func testAnswersBecomeStorageErrors() {
        let cases: [(StubHTTP.Reply, String)] = [
            (StubHTTP.Reply(status: 404), "notFound"),
            (StubHTTP.Reply(status: 403, body: Data("<Error><Code>AccessDenied</Code></Error>".utf8)), "denied"),
            (StubHTTP.Reply(status: 412), "conflict"),
            (StubHTTP.Reply(status: 503), "offline"),
            (StubHTTP.Reply(status: 429), "offline"),
            (StubHTTP.Reply(error: URLError(.notConnectedToInternet)), "offline"),
            (StubHTTP.Reply(error: URLError(.serverCertificateUntrusted)), "failed"), // a problem, not "offline"
            (StubHTTP.Reply(error: URLError(.serverCertificateHasUnknownRoot)), "failed"),
            (StubHTTP.Reply(status: 400), "failed"),
        ]
        for (reply, expected) in cases {
            StubHTTP.answer { _ in reply }
            XCTAssertThrowsError(try storage.get("f/a")) { error in
                let kind: String
                switch error as? StorageError {
                case .notFound: kind = "notFound"
                case .denied: kind = "denied"
                case .conflict: kind = "conflict"
                case .offline: kind = "offline"
                case .failed: kind = "failed"
                case nil: kind = "\(error)"
                }
                XCTAssertEqual(kind, expected, "HTTP \(reply.status)")
            }
        }
    }

    func testDownloadsLandInTheirFileWithTheirGeneration() throws {
        let dest = FileManager.default.temporaryDirectory.appendingPathComponent("shrug-dl-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dest) }
        StubHTTP.answer { _ in StubHTTP.Reply(headers: ["x-goog-generation": "9"], body: Data("content".utf8)) }
        XCTAssertEqual(try storage.download("f/a", to: dest, version: nil), "9")
        XCTAssertEqual(try Data(contentsOf: dest), Data("content".utf8))
        XCTAssertNil(StubHTTP.requests.first?.value(forHTTPHeaderField: "x-goog-if-generation-match"))

        StubHTTP.answer { _ in StubHTTP.Reply(body: Data("content".utf8)) }
        XCTAssertThrowsError(try storage.download("f/a", to: dest, version: nil), "an answer without a generation can't be trusted")

        let nowhere = URL(fileURLWithPath: "/nonexistent-\(UUID().uuidString)/file")
        StubHTTP.answer { _ in StubHTTP.Reply(headers: ["x-goog-generation": "9"], body: Data("content".utf8)) }
        XCTAssertThrowsError(try storage.download("f/a", to: nowhere, version: nil), "a download that can't be saved is a failure")
    }

    func testDownloadsOfOneVersionNameIt() throws {
        let dest = FileManager.default.temporaryDirectory.appendingPathComponent("shrug-dl-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dest) }
        StubHTTP.answer { _ in StubHTTP.Reply(headers: ["x-goog-generation": "8"], body: Data("content".utf8)) }
        XCTAssertEqual(try storage.download("f/a", to: dest, version: "8"), "8")
        XCTAssertEqual(StubHTTP.requests.first?.value(forHTTPHeaderField: "x-goog-if-generation-match"), "8")

        StubHTTP.answer { _ in StubHTTP.Reply(status: 412) }
        XCTAssertThrowsError(try storage.download("f/a", to: dest, version: "8"), "replaced since") { error in
            guard case StorageError.conflict = error else { return XCTFail("\(error)") }
        }
    }
}
