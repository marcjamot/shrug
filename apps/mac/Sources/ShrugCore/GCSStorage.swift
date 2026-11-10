import CryptoKit
import Foundation

/// Signature Version 4 with an HMAC key, under Google's names (GOOG4-HMAC-SHA256). Google only
/// accepts x-goog-* headers, which preconditions need, with its own names.
public struct V4Signer: Sendable {
    /// What one provider calls the parts of the algorithm.
    public struct Names: Sendable {
        public let algorithm: String
        public let keyPrefix: String
        public let service: String
        public let requestType: String
        /// "x-goog" for x-goog-date and x-goog-content-sha256.
        public let headerPrefix: String

        public init(algorithm: String, keyPrefix: String, service: String, requestType: String, headerPrefix: String) {
            self.algorithm = algorithm
            self.keyPrefix = keyPrefix
            self.service = service
            self.requestType = requestType
            self.headerPrefix = headerPrefix
        }

        public static let google = Names(algorithm: "GOOG4-HMAC-SHA256", keyPrefix: "GOOG4", service: "storage",
                                         requestType: "goog4_request", headerPrefix: "x-goog")

        public var dateHeader: String { headerPrefix + "-date" }
        public var payloadHeader: String { headerPrefix + "-content-sha256" }
    }

    public let accessID: String
    public let secret: String
    public let region: String
    public let names: Names

    public init(accessID: String, secret: String, region: String, names: Names = .google) {
        self.accessID = accessID
        self.secret = secret
        self.region = region
        self.names = names
    }

    public static let emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    private static let dateFormat: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        return f
    }()

    public static func timestamp(_ date: Date) -> String { dateFormat.string(from: date) }

    /// RFC 3986 encoding as V4 wants it: everything but A-Z a-z 0-9 - _ . ~ (and "/" in paths).
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
        let pairs: [(String, String)] = query.map { (encode($0.0, keepSlash: false), encode($0.1, keepSlash: false)) }
        let sorted = pairs.sorted { (a: (String, String), b: (String, String)) -> Bool in a.0 == b.0 ? a.1 < b.1 : a.0 < b.0 }
        return sorted.map { "\($0.0)=\($0.1)" }.joined(separator: "&")
    }

    private static func hmac(_ key: Data, _ text: String) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data(text.utf8), using: SymmetricKey(data: key)))
    }

    /// The Authorization header value. `headers` must include host and the date and payload-hash
    /// headers (see Names), and are all signed: Google requires every x-goog-* header to be.
    public func authorization(method: String, path: String, query: [(String, String)], headers: [String: String],
                              payloadHash: String, date: Date) -> String {
        let stamp = V4Signer.timestamp(date)
        let day = String(stamp.prefix(8))
        let lower = Dictionary(uniqueKeysWithValues: headers.map { ($0.key.lowercased(), $0.value) })
        let headerNames = lower.keys.sorted()
        let canonicalHeaders = headerNames.map { "\($0):\(lower[$0]!.trimmingCharacters(in: .whitespaces))\n" }.joined()
        let signedHeaders = headerNames.joined(separator: ";")
        let canonical = [method, V4Signer.encode(path, keepSlash: true), V4Signer.canonicalQuery(query),
                         canonicalHeaders, signedHeaders, payloadHash].joined(separator: "\n")
        let scope = "\(day)/\(region)/\(names.service)/\(names.requestType)"
        let toSign = [names.algorithm, stamp, scope, Data(SHA256.hash(data: Data(canonical.utf8))).hex]
            .joined(separator: "\n")
        var k = V4Signer.hmac(Data("\(names.keyPrefix)\(secret)".utf8), day)
        k = V4Signer.hmac(k, region)
        k = V4Signer.hmac(k, names.service)
        k = V4Signer.hmac(k, names.requestType)
        let signature = V4Signer.hmac(k, toSign).hex
        return "\(names.algorithm) Credential=\(accessID)/\(scope), SignedHeaders=\(signedHeaders), Signature=\(signature)"
    }
}

/// A Google Cloud Storage bucket over its XML API (path style, signed with an HMAC key).
/// Object versions are GCS generations, and every write is conditional on one.
public final class GCSStorage: ObjectStorage {
    let endpoint: URL
    let bucket: String
    let signer: V4Signer
    let session: URLSession

    public static func sessionConfiguration() -> URLSessionConfiguration {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 6 * 3600
        config.waitsForConnectivity = false
        config.httpCookieStorage = nil
        config.urlCache = nil
        return config
    }

    public init(endpoint: URL, bucket: String, region: String, accessID: String, secret: String,
                configuration: URLSessionConfiguration = GCSStorage.sessionConfiguration()) {
        self.endpoint = endpoint
        self.bucket = bucket
        signer = V4Signer(accessID: accessID, secret: secret, region: region)
        session = URLSession(configuration: configuration)
    }

    enum Body {
        case none, data(Data), file(URL)
    }

    struct Response {
        let status: Int
        let headers: [String: String]
        let body: Data
    }

    static let precondition = "x-goog-if-generation-match"

    /// One signed request. `saveTo` streams the response body into a file instead.
    private func send(_ method: String, key: String?, query: [(String, String)] = [], extra: [String: String] = [:],
                      body: Body = .none, saveTo: URL? = nil) throws -> Response {
        let path = "/" + bucket + (key.map { "/" + $0 } ?? "")
        var components = URLComponents()
        components.scheme = endpoint.scheme
        components.host = endpoint.host
        components.port = endpoint.port
        components.percentEncodedPath = V4Signer.encode(path, keepSlash: true)
        let q = V4Signer.canonicalQuery(query)
        if !q.isEmpty { components.percentEncodedQuery = q }
        guard let url = components.url, let host = endpoint.host else { throw StorageError.failed("Bad storage URL") }

        let payload: String
        switch body {
        case .none: payload = V4Signer.emptyHash
        case .data(let d): payload = Data(SHA256.hash(data: d)).hex
        case .file: payload = "UNSIGNED-PAYLOAD"
        }
        let now = Date()
        var headers = ["host": endpoint.port.map { "\(host):\($0)" } ?? host,
                       signer.names.dateHeader: V4Signer.timestamp(now), signer.names.payloadHeader: payload]
        for (k, v) in extra { headers[k.lowercased()] = v }
        var request = URLRequest(url: url)
        request.httpMethod = method
        for (k, v) in headers where k != "host" { request.setValue(v, forHTTPHeaderField: k) }
        request.setValue(signer.authorization(method: method, path: path, query: query, headers: headers,
                                              payloadHash: payload, date: now), forHTTPHeaderField: "Authorization")
        switch body {
        case .none: break
        case .data(let d):
            request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
            request.httpBody = d
        case .file:
            request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        }

        let done = DispatchSemaphore(value: 0)
        var result: Result<Response, Error> = .failure(StorageError.offline("no answer"))
        func finish(_ data: Data?, _ response: URLResponse?, _ error: Error?) {
            if let error {
                result = .failure(GCSStorage.classify(error))
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
                guard error == nil, let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                    return finish(tmp.flatMap { try? Data(contentsOf: $0) }, response, error)
                }
                do {
                    guard let tmp else { throw StorageError.failed("nothing arrived") }
                    try? FileManager.default.removeItem(at: saveTo)
                    try FileManager.default.moveItem(at: tmp, to: saveTo)
                    finish(nil, response, nil)
                } catch {
                    finish(nil, nil, StorageError.failed("Cannot save a download: \(error)"))
                }
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
        throw GCSStorage.failure(response)
    }

    static func classify(_ error: Error) -> StorageError {
        if let e = error as? StorageError { return e }
        let offline: Set<URLError.Code> = [
            .notConnectedToInternet, .networkConnectionLost, .timedOut, .cannotFindHost, .cannotConnectToHost,
            .dnsLookupFailed, .internationalRoamingOff, .dataNotAllowed, .secureConnectionFailed,
            .cannotLoadFromNetwork, .callIsActive,
        ]
        // Not "offline": someone may be intercepting the connection (or it's a captive portal),
        // and that should show as a problem.
        let untrusted: Set<URLError.Code> = [
            .serverCertificateUntrusted, .serverCertificateHasBadDate, .serverCertificateNotYetValid,
            .serverCertificateHasUnknownRoot, .clientCertificateRejected, .clientCertificateRequired,
        ]
        if let u = error as? URLError, offline.contains(u.code) { return .offline(u.localizedDescription) }
        if let u = error as? URLError, untrusted.contains(u.code) {
            return .failed("The storage's certificate isn't trusted, so nothing was sent (\(u.localizedDescription))")
        }
        return .failed(error.localizedDescription)
    }

    static func failure(_ r: Response) -> StorageError {
        let parsed = XMLValues(r.body, ["Code", "Message"])
        let detail = [parsed["Code"].first, parsed["Message"].first].compactMap { $0 }.joined(separator: ": ")
        let text = detail.isEmpty ? "HTTP \(r.status)" : detail
        switch r.status {
        case 404: return .notFound
        case 401, 403: return .denied(text)
        case 412: return .conflict
        case 500...599, 408, 429: return .offline(text) // the service is having trouble: just retry later
        default: return .failed(text)
        }
    }

    static func generation(_ r: Response) throws -> String {
        guard let g = r.headers["x-goog-generation"], !g.isEmpty else {
            throw StorageError.failed("The storage didn't say which version it stored")
        }
        return g
    }

    public func list(prefix: String) throws -> [StoredObject] {
        var out: [StoredObject] = []
        var marker = ""
        while true {
            var query = [("prefix", prefix)]
            if !marker.isEmpty { query.append(("marker", marker)) }
            let page = try ListParser.parse(try send("GET", key: nil, query: query).body)
            out += page.objects
            guard page.truncated, let last = page.nextMarker ?? page.objects.last?.key, last != marker else { break }
            marker = last
        }
        return out
    }

    public func get(_ key: String, range: ClosedRange<Int64>?, version: String?) throws -> Data {
        var extra: [String: String] = [:]
        if let range { extra["range"] = "bytes=\(range.lowerBound)-\(range.upperBound)" }
        if let version { extra[GCSStorage.precondition] = version }
        return try send("GET", key: key, extra: extra).body
    }

    /// With `version`, Google sends nothing unless the object is still that generation.
    public func download(_ key: String, to file: URL, version: String?) throws -> String {
        var extra: [String: String] = [:]
        if let version { extra[GCSStorage.precondition] = version }
        return try GCSStorage.generation(send("GET", key: key, extra: extra, saveTo: file))
    }

    /// Version nil becomes generation 0: Google's way of saying "only if it doesn't exist yet".
    public func put(_ key: String, data: Data, replacing version: String?) throws -> String {
        try GCSStorage.generation(send("PUT", key: key, extra: [GCSStorage.precondition: version ?? "0"], body: .data(data)))
    }

    public func upload(_ key: String, from file: URL, replacing version: String?) throws -> String {
        try GCSStorage.generation(send("PUT", key: key, extra: [GCSStorage.precondition: version ?? "0"], body: .file(file)))
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

    static func parse(_ data: Data) throws -> Page {
        let parser = XMLParser(data: data)
        let d = Delegate()
        parser.delegate = d
        guard parser.parse() else { throw StorageError.failed("The storage sent a listing that doesn't parse") }
        guard !d.missingGeneration else { throw StorageError.failed("The storage listing has no object generations") }
        return d.page
    }

    final class Delegate: NSObject, XMLParserDelegate {
        var page = Page()
        var missingGeneration = false
        var inContents = false
        var text = ""
        var key = "", size: Int64 = 0, generation = ""
        func parser(_ p: XMLParser, didStartElement e: String, namespaceURI: String?, qualifiedName: String?,
                    attributes: [String: String] = [:]) {
            if e == "Contents" { inContents = true; key = ""; size = 0; generation = "" }
            text = ""
        }
        func parser(_ p: XMLParser, foundCharacters s: String) { text += s }
        func parser(_ p: XMLParser, didEndElement e: String, namespaceURI: String?, qualifiedName: String?) {
            switch e {
            case "Key" where inContents: key = text
            case "Size" where inContents: size = Int64(text) ?? 0
            case "Generation" where inContents: generation = text
            case "Contents":
                inContents = false
                if generation.isEmpty { missingGeneration = true }
                page.objects.append(StoredObject(key: key, size: size, version: generation))
            case "IsTruncated": page.truncated = text == "true"
            case "NextMarker": page.nextMarker = text.isEmpty ? nil : text
            default: break
            }
            text = ""
        }
    }
}
