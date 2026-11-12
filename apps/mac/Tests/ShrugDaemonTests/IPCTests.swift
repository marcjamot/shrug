import Darwin
import XCTest
@testable import ShrugCore
@testable import ShrugDaemon

/// The command line's socket.
final class IPCTests: ShrugTestCase {
    func withServer(_ engine: Engine, _ body: (String) throws -> Void) throws {
        let socket = "/tmp/shrug-test-\(UUID().uuidString.prefix(8)).sock"
        let server = IPCServer(socket: socket, engine: engine)
        try server.start()
        defer { server.stop() }
        try body(socket)
    }

    /// Sends raw bytes and returns the answer, or nil if the connection closed without one.
    func raw(_ socket: String, _ bytes: Data) throws -> IPCResponse? {
        let fd = try UnixSocket.connect(socket)
        defer { close(fd) }
        Descriptor.writeAll(fd, bytes)
        shutdown(fd, SHUT_WR)
        return UnixSocket.readLine(fd, limit: 1 << 20).flatMap { try? JSONFile.decode(IPCResponse.self, from: $0) }
    }

    func testStatusWhileLockedNamesNothing() throws {
        let (a, _) = try twoMacsFollowing()
        try a.putHome(".kube/config", "x")
        _ = try a.engine.add(path: a.home(".kube/config").path, target: nil, cls: nil, choices: [:])
        a.engine.lockNow("test")
        try withServer(a.engine) { socket in
            let r = try IPCClient.send(IPCRequest("status"), socket: socket)
            XCTAssertEqual(r.status?.unlocked, false)
            XCTAssertNil(r.status?.profile)
            XCTAssertEqual(r.status?.links.count, 0)
            XCTAssertFalse(String(decoding: try JSONFile.encode(r), as: UTF8.self).contains("kube"))
        }
    }

    func testLinksListsEveryLinkAndWhatIsWrongWithIt() throws {
        let (a, _) = try twoMacsFollowing()
        try withServer(a.engine) { socket in
            XCTAssertEqual(try IPCClient.send(IPCRequest("links"), socket: socket).message,
                           "No links yet: 'shrug add <path>' makes one.")
            for name in [".kube/config", ".npmrc"] {
                try a.putHome(name, "x")
                _ = try a.engine.add(path: a.home(name).path, target: nil, cls: nil, choices: [:])
            }
            // A folder takes one link's place.
            unlink(a.home(".npmrc").path)
            try FileManager.default.createDirectory(at: a.home(".npmrc"), withIntermediateDirectories: false)
            let r = try IPCClient.send(IPCRequest("links"), socket: socket)
            XCTAssertTrue(r.ok, r.message)
            XCTAssertEqual(r.message, """
            ok  ~/.kube/config -> synced/kube/config
            !!  ~/.npmrc -> synced/npmrc: a folder is in the way
            """)
            // Locked, it names nothing: the command line asks for the password first.
            a.engine.lockNow("test")
            let locked = try IPCClient.send(IPCRequest("links"), socket: socket)
            XCTAssertEqual(locked.code, "password-needed")
            XCTAssertFalse(locked.message.contains("kube"))
        }
    }

    func testUnlockWithoutTouchIDAsksForThePassword() throws {
        let (a, _) = try twoMacs()
        a.engine.lockNow("test")
        try withServer(a.engine) { socket in
            XCTAssertEqual(try IPCClient.send(IPCRequest("unlock"), socket: socket).code, "password-needed")
            XCTAssertFalse(try IPCClient.send(IPCRequest("unlock", ["password": "wrong"]), socket: socket).ok)
            XCTAssertTrue(try IPCClient.send(IPCRequest("unlock", ["password": password]), socket: socket).ok)
            XCTAssertTrue(a.engine.isUnlocked)
        }
    }

    func testLinksFromAnotherMacAreAgreedToOverTheSocket() throws {
        let (a, b) = try twoMacsFollowing()
        try a.putHome(".kube/config", "context")
        _ = try a.engine.add(path: a.home(".kube/config").path, target: nil, cls: nil, choices: [:])
        a.sync()
        b.sync()
        try withServer(b.engine) { socket in
            let asked = try IPCClient.send(IPCRequest("use", ["name": "work"]), socket: socket)
            XCTAssertEqual(asked.code, "confirm-links")
            XCTAssertEqual(asked.list, ["~/.kube/config"])
            XCTAssertEqual(asked.message, "~/.kube/config -> synced/kube/config")
            let agreed = try IPCClient.send(IPCRequest("use", ["name": "work", "approve": #"["~/.kube/config"]"#]),
                                            socket: socket)
            XCTAssertTrue(agreed.ok, agreed.message)
        }
        XCTAssertEqual(b.engine.found(b.home(".kube/config"), "synced/kube/config"), .ourLink)
    }

    func testStoppingReleasesTheSocketForTheNextStart() throws {
        let (a, _) = try twoMacs()
        let socket = "/tmp/shrug-test-\(UUID().uuidString.prefix(8)).sock"
        for _ in 0..<3 {
            let server = IPCServer(socket: socket, engine: a.engine)
            try server.start() // refuses while an earlier server's socket still answers
            XCTAssertTrue(try IPCClient.send(IPCRequest("status"), socket: socket).ok)
            server.stop()
            XCTAssertThrowsError(try UnixSocket.connect(socket), "closed by the time stop returns")
        }
    }

    func testBadRequestsAreAnsweredOrDropped() throws {
        let (a, _) = try twoMacs()
        try withServer(a.engine) { socket in
            XCTAssertEqual(try raw(socket, Data("not json\n".utf8))?.message, "Bad request")
            XCTAssertEqual(try IPCClient.send(IPCRequest("explode"), socket: socket).message, "Unknown command 'explode'")
            XCTAssertNil(try raw(socket, Data(repeating: 0x41, count: IPCServer.requestLimit + 10)), "too long: dropped")
            XCTAssertTrue(try IPCClient.send(IPCRequest("status"), socket: socket).ok, "and still answering")
        }
    }
}
