import Darwin
import Foundation
import ShrugCore
import ShrugNFS

/// Answers `shrug` over the Unix socket.
final class IPCServer {
    /// Requests are one short JSON line.
    static let requestLimit = 1 << 16
    static let maxConnections = 8

    let socketPath: String
    unowned let engine: Engine
    private var acceptor: AcceptLoop?
    private let lock = NSLock()
    private var open = 0

    init(socket: String, engine: Engine) {
        socketPath = socket
        self.engine = engine
    }

    func start() throws {
        let fd = try UnixSocket.listen(socketPath)
        acceptor = try AcceptLoop(listening: fd, name: "shrug.ipc") { [weak self] client in
            guard let self else { close(client); return }
            self.accepted(client)
        }
    }

    func stop() {
        acceptor?.stop()
        acceptor = nil
        unlink(socketPath)
    }

    private func accepted(_ client: Int32) {
        // Only this user may talk to Shrug, a few commands at a time.
        var uid: uid_t = 0
        var gid: gid_t = 0
        lock.lock()
        let full = open >= IPCServer.maxConnections
        if !full { open += 1 }
        lock.unlock()
        guard !full else { close(client); return }
        guard getpeereid(client, &uid, &gid) == 0, uid == getuid() else {
            close(client)
            lock.lock()
            open -= 1
            lock.unlock()
            return
        }
        UnixSocket.ignoreHangups(client)
        Thread { [weak self] in
            defer { close(client) }
            guard let self else { return }
            defer {
                self.lock.lock()
                self.open -= 1
                self.lock.unlock()
            }
            guard let line = UnixSocket.readLine(client, limit: IPCServer.requestLimit) else { return }
            let response: IPCResponse
            if let request = try? JSONFile.decode(IPCRequest.self, from: line) {
                response = self.engine.handle(request)
            } else {
                response = IPCResponse(ok: false, message: "Bad request")
            }
            try? UnixSocket.send(response, to: client)
        }.start()
    }
}

extension Engine {
    public func handle(_ r: IPCRequest) -> IPCResponse {
        func ok(_ message: String) -> IPCResponse { IPCResponse(ok: true, message: message) }
        func outcome(_ o: Outcome) -> IPCResponse {
            switch o {
            case .done(let m): return ok(m)
            case .collisions(let paths):
                return IPCResponse(ok: false, message: "Both this Mac and Shrug have a file there", code: "collisions",
                                   list: paths)
            case .confirm(let links):
                return IPCResponse(ok: false, message: links.map { "\($0.path) -> \($0.target)" }.joined(separator: "\n"),
                                   code: "confirm-links", list: links.map(\.path))
            }
        }
        let a = r.args
        do {
            switch r.cmd {
            case "status":
                return IPCResponse(ok: true, message: "", status: status())
            case "unlock":
                try unlock(password: a["password"])
                disk.settle() // so ~/ShrugDisk is there when the command returns
                return ok("Unlocked")
            case "lock":
                lockNow("locked from the command line")
                return ok("Locked")
            case "probe":
                let (config, creds) = try Engine.storageArgs(a)
                return IPCResponse(ok: true, message: "", code: try probe(config, creds) ? "has-vault" : "empty")
            case "setup":
                let (config, creds) = try Engine.storageArgs(a)
                let names = try setup(config, creds, password: a["password"] ?? "", deviceName: a["device"] ?? "",
                                      create: a["create"] == "1")
                disk.settle()
                return IPCResponse(ok: true, message: "Set up and unlocked", list: names)
            case "use":
                return outcome(try use(a["name"], choices: Engine.choices(a), approve: Engine.approvals(a)))
            case "add":
                let cls = a["class"].flatMap(FileClass.init(rawValue:))
                return outcome(try add(path: a["path"] ?? "", target: a["target"], cls: cls, choices: Engine.choices(a)))
            case "remove":
                return ok(try remove(path: a["path"] ?? ""))
            case "trust":
                return ok(try trust(name: a["name"], password: a["password"]))
            case "untrust":
                return ok(try untrust(name: a["name"]))
            default:
                return IPCResponse(ok: false, message: "Unknown command '\(r.cmd)'")
            }
        } catch let e as PasswordNeeded {
            // Touch ID can't unlock for this (or isn't set up): the command line asks for the
            // Shrug password, unlocks with it and tries again.
            return IPCResponse(ok: false, message: e.description, code: "password-needed")
        } catch {
            return IPCResponse(ok: false, message: "\(error)")
        }
    }

    /// "approve" is JSON: ["~/.ssh/config"], the links you agreed to place on this Mac. Missing
    /// means you haven't been asked yet; an empty list means you said no for now.
    static func approvals(_ a: [String: String]) -> Set<String>? {
        guard let json = a["approve"], let paths = try? JSONFile.decode([String].self, from: Data(json.utf8)) else {
            return nil
        }
        return Set(paths)
    }

    static func storageArgs(_ a: [String: String]) throws -> (StorageConfig, Credentials?) {
        guard let json = a["storage"], let config = try? JSONFile.decode(StorageConfig.self, from: Data(json.utf8)) else {
            throw ShrugError("No storage given")
        }
        var creds: Credentials?
        if let id = a["access-id"], let secret = a["secret"], !id.isEmpty { creds = Credentials(accessID: id, secret: secret) }
        return (config, creds)
    }

    /// "choices" is JSON: {"~/.ssh/config": "mine"}.
    static func choices(_ a: [String: String]) -> [String: Choice] {
        guard let json = a["choices"], let raw = try? JSONFile.decode([String: String].self, from: Data(json.utf8)) else {
            return [:]
        }
        return raw.compactMapValues(Choice.init(rawValue:))
    }

    /// While locked, nothing that could name a file.
    public func status() -> StatusInfo {
        var base = StatusInfo(setUp: paths.isSetUp, unlocked: isUnlocked, touchID: touchID.isEnrolled, mounted: mounted,
                              mount: paths.mount.path)
        base.disk = disk.status(unlocked: false)
        guard let st = stateCopy(), let store = store else { return base }
        var info = base
        info.device = st.deviceName
        info.macs = st.macs
        info.profile = st.profile
        info.storage = st.storage.summary
        info.online = replicator.online
        info.lastSync = replicator.lastSync
        info.problem = replicator.problem
        info.waiting = store.waitingCount + (st.profileDirty ? 1 : 0)
        info.links = linkInfos()
        info.notices = st.notices
        let trusted = st.trusted ?? []
        info.trusted = trusted.map(\.name)
        info.trustedHere = trustedNetwork(among: trusted)?.name
        info.held = heldOpenBy
        info.disk = disk.status(unlocked: true)
        lock.lock()
        info.lastEvent = lastEventText
        lock.unlock()
        return info
    }
}
