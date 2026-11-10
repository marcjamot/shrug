import CoreGraphics
import Darwin
import Foundation
import ServiceManagement
import ShrugCore

/// What the screen shows, as far as Shrug's lock goes.
public struct ScreenState: Equatable, Sendable {
    /// The lock screen (or the login window) is up.
    public var locked: Bool
    /// This user is the one at the screen (false after switching to another user).
    public var ours: Bool

    public init(locked: Bool, ours: Bool) {
        self.locked = locked
        self.ours = ours
    }
}

/// Where the engine asks what the screen shows, so tests can answer instead of macOS.
public struct ScreenWatch: Sendable {
    /// Nil when macOS doesn't say (outside a login session).
    public let current: @Sendable () -> ScreenState?

    public init(_ current: @escaping @Sendable () -> ScreenState?) { self.current = current }

    /// Asks the window server: one quick call. The console key is documented; the locked key
    /// isn't, but it's what the lock screen sets. Either one changing is enough to lock.
    public static let system = ScreenWatch {
        guard let info = CGSessionCopyCurrentDictionary() as? [String: Any] else { return nil }
        return ScreenState(locked: info["CGSSessionScreenIsLocked"] as? Bool ?? false,
                           ours: info[kCGSessionOnConsoleKey] as? Bool ?? true)
    }
}

/// Mounting the virtual folder with the system NFS client.
enum Mounter {
    static func isMounted(_ url: URL) -> Bool {
        var s = statfs()
        guard statfs(url.path, &s) == 0 else { return false }
        let type = withUnsafeBytes(of: &s.f_fstypename) { String(cString: $0.bindMemory(to: CChar.self).baseAddress!) }
        let on = withUnsafeBytes(of: &s.f_mntonname) { String(cString: $0.bindMemory(to: CChar.self).baseAddress!) }
        return type == "nfs" && on == url.resolvingSymlinksInPath().path
    }

    static func mount(port: UInt16, at url: URL) throws {
        unmount(url) // clean up after a crash
        // Never hide someone's files: only mount over an empty folder.
        if let existing = try? FileManager.default.contentsOfDirectory(atPath: url.path),
           !existing.filter({ $0 != ".DS_Store" && $0 != ".localized" }).isEmpty {
            throw ShrugError("\(url.path) already has files in it. Move them somewhere else, then start Shrug again.")
        }
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o500])
        seal(url)
        let options = [
            "vers=3", "tcp", "port=\(port)", "mountport=\(port)",
            // Locks stay local; nothing to coordinate with a remote host.
            "locallocks",
            // Revalidate on every open, so a lock takes effect even for cached files.
            "noac", "nonegnamecache",
            // Fail instead of hanging forever if Shrug stops, but wait out a Touch ID prompt.
            // Without dumbtimer, macOS ignores timeo and estimates it from loopback round
            // trips, giving up after about half a second. Either way, a soft mount never
            // waits much more than 30 seconds (Engine.accessPromptTimeout stays under that).
            "soft", "dumbtimer", "timeo=300", "retrans=2",
            "rsize=65536", "wsize=65536", "noquota", "nobrowse",
        ].joined(separator: ",")
        let r = try run("/sbin/mount_nfs", ["-o", options, "127.0.0.1:/", url.path])
        guard r.code == 0 else { throw ShrugError("Could not mount \(url.path): \(r.output)") }
    }

    /// Without Shrug running, the mount point is an empty folder nobody can write into, so
    /// nothing lands on disk unencrypted by mistake (not even through a link).
    static func seal(_ url: URL) {
        guard !isMounted(url) else { return }
        chmod(url.path, 0o500)
    }

    static func unmount(_ url: URL) {
        // diskutil goes through DiskArbitration, which can unmount user NFS mounts
        // even where a plain umount is refused.
        if (try? run("/sbin/umount", [url.path]))?.code == 0 { return }
        if (try? run("/usr/sbin/diskutil", ["unmount", url.path]))?.code == 0 { return }
        _ = try? run("/usr/sbin/diskutil", ["unmount", "force", url.path])
    }

    static func run(_ tool: String, _ args: [String]) throws -> (code: Int32, output: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        try p.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
    }
}

/// Finds which program has a file open.
enum ProcessFinder {
    /// Who has `path` open, so the preview filter can tell Finder and Quick Look from other
    /// programs. (The Touch ID prompt can't use it: a program looks a file up before opening it.)
    static func holder(of path: String) -> String? {
        let me = getpid()
        for pid in allPIDs() where pid != me {
            for fd in descriptors(of: pid) where fd.proc_fdtype == UInt32(PROX_FDTYPE_VNODE) {
                var info = vnode_fdinfowithpath()
                let r = proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDVNODEPATHINFO, &info,
                                       Int32(MemoryLayout<vnode_fdinfowithpath>.size))
                guard r > 0 else { continue }
                let p = withUnsafeBytes(of: &info.pvip.vip_path) { String(cString: $0.bindMemory(to: CChar.self).baseAddress!) }
                if p == path { return name(of: pid) }
            }
        }
        return nil
    }

    private static func allPIDs() -> [pid_t] {
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(count) + 32)
        let got = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size))
        return got > 0 ? pids.prefix(Int(got)).filter { $0 > 0 } : []
    }

    private static func descriptors(of pid: pid_t) -> [proc_fdinfo] {
        let size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard size > 0 else { return [] }
        var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(size) / MemoryLayout<proc_fdinfo>.stride)
        let filled = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, size)
        return filled > 0 ? Array(fds.prefix(Int(filled) / MemoryLayout<proc_fdinfo>.stride)) : []
    }

    static func name(of pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: 256)
        guard proc_name(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
        return String(cString: buffer)
    }
}

/// Opens Shrug at login. Only for the installed app, not for test builds.
enum LoginItem {
    static func enable() -> String? {
        guard Bundle.main.bundleIdentifier == "app.shrug.Shrug", SMAppService.mainApp.status != .enabled else { return nil }
        do {
            try SMAppService.mainApp.register()
            return "Shrug opens at login."
        } catch {
            return "Couldn't make Shrug open at login (\(error.localizedDescription)); use Open at Login in its menu."
        }
    }
}
