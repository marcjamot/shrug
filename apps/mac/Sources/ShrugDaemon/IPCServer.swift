import Darwin
import Foundation
import ShrugCore

/// Answers `shrug` over the Unix socket.
final class IPCServer {
    let socketPath: String
    unowned let engine: Engine
    private var fd: Int32 = -1

    init(socket: String, engine: Engine) {
        socketPath = socket
        self.engine = engine
    }

    func start() throws {
        fd = try UnixSocket.listen(socketPath)
        let t = Thread { [weak self] in self?.acceptLoop() }
        t.name = "shrug.ipc"
        t.start()
    }

    func stop() {
        if fd >= 0 {
            shutdown(fd, SHUT_RDWR)
            close(fd)
            fd = -1
        }
        unlink(socketPath)
    }

    private func acceptLoop() {
        while fd >= 0 {
            let client = accept(fd, nil, nil)
            if client < 0 {
                if fd < 0 { return }
                continue
            }
            // Only this user may talk to Shrug.
            var uid: uid_t = 0
            var gid: gid_t = 0
            if getpeereid(client, &uid, &gid) != 0 || uid != getuid() {
                close(client)
                continue
            }
            Thread { [weak self] in
                defer { close(client) }
                guard let self, let line = UnixSocket.readLine(client) else { return }
                let response: IPCResponse
                if let request = try? JSONFile.decode(IPCRequest.self, from: line) {
                    response = self.engine.handle(request)
                } else {
                    response = IPCResponse(ok: false, message: "Bad request")
                }
                var data = (try? JSONFile.encode(response)) ?? Data()
                data.removeAll { $0 == 0x0A }
                data.append(0x0A)
                UnixSocket.writeAll(client, data)
            }.start()
        }
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
            }
        }
        let a = r.args
        do {
            switch r.cmd {
            case "status":
                return IPCResponse(ok: true, message: "", status: status())
            case "unlock":
                do {
                    try unlock(password: a["password"])
                } catch let e as ShrugError where e.description == "password-needed" {
                    return IPCResponse(ok: false, message: "Password needed", code: "password-needed")
                }
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
                return IPCResponse(ok: true, message: "Set up and unlocked", list: names)
            case "use":
                return outcome(try use(a["name"], choices: Engine.choices(a)))
            case "add":
                let cls = a["class"].flatMap(FileClass.init(rawValue:))
                return outcome(try add(path: a["path"] ?? "", target: a["target"], cls: cls, choices: Engine.choices(a)))
            case "remove":
                return ok(try remove(path: a["path"] ?? ""))
            default:
                return IPCResponse(ok: false, message: "Unknown command '\(r.cmd)'")
            }
        } catch {
            return IPCResponse(ok: false, message: "\(error)")
        }
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
        let base = StatusInfo(setUp: paths.isSetUp, unlocked: isUnlocked, touchID: touchID.isEnrolled, mounted: mounted,
                              mount: paths.mount.path)
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
        lock.lock()
        info.lastEvent = lastEventText
        lock.unlock()
        return info
    }
}
