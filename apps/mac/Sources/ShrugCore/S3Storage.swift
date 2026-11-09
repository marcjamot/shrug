import CryptoKit
import Foundation

/// AWS Signature Version 4, which Google Cloud Storage accepts with HMAC keys.
public struct SigV4: Sendable {
    public let accessID: String
    public let secret: String
    public let region: String
    public let service = "s3"

    public init(accessID: String, secret: String, region: String) {
        self.accessID = accessID
        self.secret = secret
        self.region = region
    }

    public static let emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    public static func amzDate(_ date: Date) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        return f.string(from: date)
    }

    /// RFC 3986 encoding as AWS wants it: everything but A-Z a-z 0-9 - _ . ~ (and "/" in paths).
    static let unreserved = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~".utf8)

    public static func encode(_ s: String, keepSlash: Bool) -> String {
        var out = ""
        for byte in s.utf8 {
            if unreserved.contains(byte) || (keepSlash && byte == UInt8(ascii: "/")) {
                out.append(Character(UnicodeScalar(byte)))
            } else {
                out += String(format: "%%%02X", byte)
            }
        }
        return out
    }

    public static func canonicalQuery(_ query: [(String, String)]) -> String {
        var pairs: [(String, String)] = []
        for (k, v) in query { pairs.append((encode(k, keepSlash: false), encode(v, keepSlash: false))) }
        pairs.sort { (a: (String, String), b: (String, String)) -> Bool in a.0 == b.0 ? a.1 < b.1 : a.0 < b.0 }
        return pairs.map { "\($0.0)=\($0.1)" }.joined(separator: "&")
    }

    private static func hmac(_ key: Data, _ text: String) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data(text.utf8), using: SymmetricKey(data: key)))
    }

    /// The Authorization header value. `headers` must include host, x-amz-date and
    /// x-amz-content-sha256, and are all signed.
    public func authorization(method: String, path: String, query: [(String, String)], headers: [String: String],
                              payloadHash: String, date: Date) -> String {
        let amz = SigV4.amzDate(date)
        let day = String(amz.prefix(8))
        let names = headers.keys.map { $0.lowercased() }.sorted()
        let lower = Dictionary(uniqueKeysWithValues: headers.map { ($0.key.lowercased(), $0.value) })
        let canonicalHeaders = names.map { "\($0):\(lower[$0]!.trimmingCharacters(in: .whitespaces))\n" }.joined()
        let signedHeaders = names.joined(separator: ";")
        let canonical = [method, SigV4.encode(path, keepSlash: true), SigV4.canonicalQuery(query),
                         canonicalHeaders, signedHeaders, payloadHash].joined(separator: "\n")
        let scope = "\(day)/\(region)/\(service)/aws4_request"
        let toSign = ["AWS4-HMAC-SHA256", amz, scope, Data(SHA256.hash(data: Data(canonical.utf8))).hex]
            .joined(separator: "\n")
        var k = SigV4.hmac(Data("AWS4\(secret)".utf8), day)
        k = SigV4.hmac(k, region)
        k = SigV4.hmac(k, service)
        k = SigV4.hmac(k, "aws4_request")
        let signature = SigV4.hmac(k, toSign).hex
        return "AWS4-HMAC-SHA256 Credential=\(accessID)/\(scope), SignedHeaders=\(signedHeaders), Signature=\(signature)"
    }
}

/// An S3-compatible bucket over HTTPS (Google Cloud Storage's XML API, path style).
public final class S3Storage: ObjectStorage {
    let endpoint: URL
    let bucket: String
    let signer: SigV4
    let session: URLSession

    public init(endpoint: URL, bucket: String, region: String, accessID: String, secret: String) {
        self.endpoint = endpoint
        self.bucket = bucket
        signer = SigV4(accessID: accessID, secret: secret, region: region)
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 6 * 3600
        config.waitsForConnectivity = false
        config.httpCookieStorage = nil
        config.urlCache = nil
        session = URLSession(configuration: config)
    }

    enum Body {
        case none, data(Data), file(URL)
    }

    struct Response {
        let status: Int
        let headers: [String: String]
        let body: Data
    }

    /// One signed request. `saveTo` streams the response body into a file instead.
    private func send(_ method: String, key: String?, query: [(String, String)] = [], extra: [String: String] = [:],
                      body: Body = .none, saveTo: URL? = nil) throws -> Response {
        let path = "/" + bucket + (key.map { "/" + $0 } ?? "")
        var components = URLComponents()
        components.scheme = endpoint.scheme
        components.host = endpoint.host
        components.port = endpoint.port
        components.percentEncodedPath = SigV4.encode(path, keepSlash: true)
        let q = SigV4.canonicalQuery(query)
        if !q.isEmpty { components.percentEncodedQuery = q }
        guard let url = components.url, let host = endpoint.host else { throw StorageError.failed("Bad storage URL") }

        let payload: String
        switch body {
        case .none: payload = SigV4.emptyHash
        case .data(let d): payload = Data(SHA256.hash(data: d)).hex
        case .file: payload = "UNSIGNED-PAYLOAD"
        }
        let now = Date()
        var headers = ["host": endpoint.port.map { "\(host):\($0)" } ?? host,
                       "x-amz-date": SigV4.amzDate(now), "x-amz-content-sha256": payload]
        for (k, v) in extra { headers[k.lowercased()] = v }
        var request = URLRequest(url: url)
        request.httpMethod = method
        for (k, v) in headers where k != "host" { request.setValue(v, forHTTPHeaderField: k) }
        request.setValue(signer.authorization(method: method, path: path, query: query, headers: headers,
                                              payloadHash: payload, date: now), forHTTPHeaderField: "Authorization")
        if case .data(let d) = body {
            request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
            request.httpBody = d
        }
        if case .file = body { request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type") }

        let done = DispatchSemaphore(value: 0)
        var result: Result<Response, Error> = .failure(StorageError.offline("no answer"))
        func finish(_ data: Data?, _ response: URLResponse?, _ error: Error?) {
            if let error {
                result = .failure(S3Storage.classify(error))
            } else if let http = response as? HTTPURLResponse {
                var h: [String: String] = [:]
                for (k, v) in http.allHeaderFields { h[String(describing: k).lowercased()] = String(describing: v) }
                result = .success(Response(status: http.statusCode, headers: h, body: data ?? Data()))
            }
            done.signal()
        }
        let task: URLSessionTask
        if let saveTo {
            task = session.downloadTask(with: request) { tmp, response, error in
                var data: Data?
                if let tmp, let http = response as? HTTPURLResponse {
                    if (200..<300).contains(http.statusCode) {
                        try? FileManager.default.removeItem(at: saveTo)
                        do { try FileManager.default.moveItem(at: tmp, to: saveTo) } catch { data = nil }
                    } else {
                        data = try? Data(contentsOf: tmp)
                    }
                }
                finish(data, response, error)
            }
        } else if case .file(let file) = body {
            task = session.uploadTask(with: request, fromFile: file) { finish($0, $1, $2) }
        } else {
            task = session.dataTask(with: request) { finish($0, $1, $2) }
        }
        task.resume()
        done.wait()
        let response = try result.get()
        if (200..<300).contains(response.status) { return response }
        throw S3Storage.failure(response)
    }

    static func classify(_ error: Error) -> StorageError {
        let offline: Set<URLError.Code> = [
            .notConnectedToInternet, .networkConnectionLost, .timedOut, .cannotFindHost, .cannotConnectToHost,
            .dnsLookupFailed, .internationalRoamingOff, .dataNotAllowed, .secureConnectionFailed,
            .serverCertificateUntrusted, .serverCertificateHasBadDate, .serverCertificateNotYetValid,
            .cannotLoadFromNetwork, .callIsActive,
        ]
        if let u = error as? URLError, offline.contains(u.code) { return .offline(u.localizedDescription) }
        return .failed(error.localizedDescription)
    }

    static func failure(_ r: Response) -> StorageError {
        let parsed = XMLValues(r.body, ["Code", "Message"])
        let detail = [parsed["Code"].first, parsed["Message"].first].compactMap { $0 }.joined(separator: ": ")
        let text = detail.isEmpty ? "HTTP \(r.status)" : detail
        switch r.status {
        case 404: return .notFound
        case 401, 403: return .denied(text)
        case 500...599, 408, 429: return .offline(text) // the service is having trouble: just retry later
        default: return .failed(text)
        }
    }

    static func etag(_ r: Response) -> String {
        (r.headers["etag"] ?? "").trimmingCharacters(in: CharacterSet(charactersIn: "\""))
    }

    public func list(prefix: String) throws -> [StoredObject] {
        var out: [StoredObject] = []
        var marker = ""
        while true {
            var query = [("prefix", prefix)]
            if !marker.isEmpty { query.append(("marker", marker)) }
            let r = try send("GET", key: nil, query: query)
            let page = ListParser.parse(r.body)
            out += page.objects
            guard page.truncated, let last = page.nextMarker ?? page.objects.last?.key, last != marker else { break }
            marker = last
        }
        return out
    }

    public func get(_ key: String, range: ClosedRange<Int64>?) throws -> Data {
        var extra: [String: String] = [:]
        if let range { extra["range"] = "bytes=\(range.lowerBound)-\(range.upperBound)" }
        return try send("GET", key: key, extra: extra).body
    }

    public func download(_ key: String, to file: URL) throws -> String {
        S3Storage.etag(try send("GET", key: key, saveTo: file))
    }

    public func put(_ key: String, data: Data) throws -> String {
        S3Storage.etag(try send("PUT", key: key, body: .data(data)))
    }

    public func upload(_ key: String, from file: URL) throws -> String {
        S3Storage.etag(try send("PUT", key: key, body: .file(file)))
    }

    public func delete(_ key: String) throws {
        do {
            _ = try send("DELETE", key: key)
        } catch StorageError.notFound {}
    }
}

/// Collects the text of the named elements in an XML answer.
struct XMLValues {
    private var values: [String: [String]] = [:]

    init(_ data: Data, _ names: Set<String>) {
        let parser = XMLParser(data: data)
        let delegate = Delegate(names)
        parser.delegate = delegate
        parser.parse()
        values = delegate.values
    }

    subscript(name: String) -> [String] { values[name] ?? [] }

    final class Delegate: NSObject, XMLParserDelegate {
        let names: Set<String>
        var values: [String: [String]] = [:]
        var text: String?
        init(_ names: Set<String>) { self.names = names }
        func parser(_ p: XMLParser, didStartElement e: String, namespaceURI: String?, qualifiedName: String?,
                    attributes: [String: String] = [:]) {
            text = names.contains(e) ? "" : nil
        }
        func parser(_ p: XMLParser, foundCharacters s: String) { text? += s }
        func parser(_ p: XMLParser, didEndElement e: String, namespaceURI: String?, qualifiedName: String?) {
            if names.contains(e), let t = text { values[e, default: []].append(t) }
            text = nil
        }
    }
}

/// A ListBucketResult page.
enum ListParser {
    struct Page {
        var objects: [StoredObject] = []
        var truncated = false
        var nextMarker: String?
    }

    static func parse(_ data: Data) -> Page {
        let parser = XMLParser(data: data)
        let d = Delegate()
        parser.delegate = d
        parser.parse()
        return d.page
    }

    final class Delegate: NSObject, XMLParserDelegate {
        var page = Page()
        var inContents = false
        var text = ""
        var key = "", size: Int64 = 0, etag = ""
        func parser(_ p: XMLParser, didStartElement e: String, namespaceURI: String?, qualifiedName: String?,
                    attributes: [String: String] = [:]) {
            if e == "Contents" { inContents = true; key = ""; size = 0; etag = "" }
            text = ""
        }
        func parser(_ p: XMLParser, foundCharacters s: String) { text += s }
        func parser(_ p: XMLParser, didEndElement e: String, namespaceURI: String?, qualifiedName: String?) {
            switch e {
            case "Key" where inContents: key = text
            case "Size" where inContents: size = Int64(text) ?? 0
            case "ETag" where inContents: etag = text.trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            case "Contents":
                inContents = false
                page.objects.append(StoredObject(key: key, size: size, etag: etag))
            case "IsTruncated": page.truncated = text == "true"
            case "NextMarker": page.nextMarker = text.isEmpty ? nil : text
            default: break
            }
            text = ""
        }
    }
}
