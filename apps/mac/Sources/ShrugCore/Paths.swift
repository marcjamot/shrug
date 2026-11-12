import Darwin
import Foundation

/// Every location Shrug reads or writes on a Mac.
///
///     ~/Shrug       the virtual folder: local/, synced/, remote/
///     ~/ShrugDisk   the encrypted disk for working data, attached while Shrug is unlocked
///     ~/.shrug      Shrug's own state: keys, encrypted copies, the disk's image, settings, log
///
/// Environment overrides let everything run in a throwaway folder for testing:
/// SHRUG_STATE_DIR, SHRUG_MOUNT_DIR, SHRUG_DISK_DIR, SHRUG_HOME_DIR, SHRUG_SOCKET.
public struct ShrugPaths: Sendable {
    public let state: URL
    public let mount: URL
    /// Where the disk is attached (~/ShrugDisk).
    public let disk: URL
    /// What `~` expands to in links.
    public let home: URL
    /// Unix socket the command line uses to talk to the app.
    public let socket: String

    public init(state: URL, mount: URL, home: URL, socket: String, disk: URL? = nil) {
        self.state = state
        self.mount = mount
        self.home = home
        self.socket = socket
        self.disk = disk ?? home.appendingPathComponent("ShrugDisk")
    }

    public static func current() -> ShrugPaths {
        let env = ProcessInfo.processInfo.environment
        let realHome = FileManager.default.homeDirectoryForCurrentUser
        let home = env["SHRUG_HOME_DIR"].map { URL(fileURLWithPath: $0) } ?? realHome
        let state = env["SHRUG_STATE_DIR"].map { URL(fileURLWithPath: $0) } ?? realHome.appendingPathComponent(".shrug")
        let mount = env["SHRUG_MOUNT_DIR"].map { URL(fileURLWithPath: $0) } ?? home.appendingPathComponent("Shrug")
        let socket = env["SHRUG_SOCKET"] ?? state.appendingPathComponent("shrug.sock").path
        let disk = env["SHRUG_DISK_DIR"].map { URL(fileURLWithPath: $0) }
        return ShrugPaths(state: state, mount: mount, home: home, socket: socket, disk: disk)
    }

    /// The format of everything in here (see Migrations).
    public var versionFile: URL { state.appendingPathComponent("version") }
    /// The vault keyring copy and this Mac's local key, both password-wrapped, and sealed by
    /// the security chip when there is one.
    public var keyringFile: URL { state.appendingPathComponent("keyring.json") }
    public var touchIDFile: URL { state.appendingPathComponent("touchid.json") }
    /// Settings, credentials, profile and links: encrypted with the local key.
    public var stateFile: URL { state.appendingPathComponent("state.enc") }
    /// What's in ~/Shrug: encrypted with the local key.
    public var indexFile: URL { state.appendingPathComponent("index.enc") }
    /// The changes to the index since it was last written whole: encrypted with the local key.
    public var journalFile: URL { state.appendingPathComponent("index.journal") }
    /// Local copies of synced/ and remote/ files, named by their (random-looking) bucket key.
    public var objectStore: URL { state.appendingPathComponent("store/objects") }
    /// local/ files, named by random ids.
    public var localStore: URL { state.appendingPathComponent("store/local") }
    /// Files that only last until Shrug locks (see Store), named by random ids.
    public var scratchStore: URL { state.appendingPathComponent("store/scratch") }
    /// The disk attached at ~/ShrugDisk: an encrypted image that this Mac's local key opens.
    public var diskImage: URL { state.appendingPathComponent("disk.sparsebundle") }
    public var logFile: URL { state.appendingPathComponent("shrug.log") }

    public var isSetUp: Bool { FileManager.default.fileExists(atPath: keyringFile.path) }

    /// `~/x` -> absolute URL under `home`.
    public func expand(_ path: String) -> URL {
        if path == "~" { return home }
        if path.hasPrefix("~/") { return home.appendingPathComponent(String(path.dropFirst(2))) }
        return URL(fileURLWithPath: path)
    }

    /// Absolute URL -> `~/x` when it lives under `home`.
    public func contract(_ url: URL) -> String {
        let p = canonical(url)
        let h = ShrugPaths.realpath(home.path) ?? home.standardizedFileURL.path
        if p == h { return "~" }
        if p.hasPrefix(h + "/") { return "~/" + p.dropFirst(h.count + 1) }
        return p
    }

    /// One spelling per location, for comparing paths: the deepest folder that exists, with
    /// symlinks resolved (so /tmp and /private/tmp agree), plus the rest as is. The last
    /// component may itself be a link, so it's never followed.
    public func canonical(_ url: URL) -> String {
        var tail = [url.lastPathComponent]
        var parent = url.deletingLastPathComponent().standardizedFileURL
        while true {
            if let real = ShrugPaths.realpath(parent.path) {
                return (real == "/" ? "" : real) + "/" + tail.reversed().joined(separator: "/")
            }
            if parent.path == "/" || parent.path.isEmpty { return url.standardizedFileURL.path }
            tail.append(parent.lastPathComponent)
            parent = parent.deletingLastPathComponent()
        }
    }

    public func canonical(_ path: String) -> String { canonical(expand(path)) }

    public static func realpath(_ path: String) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        guard Darwin.realpath(path, &buffer) != nil else { return nil }
        return String(cString: buffer)
    }
}
