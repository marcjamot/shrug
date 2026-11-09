import Darwin
import Foundation
import ServiceManagement

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
            throw ShrugErrorD("\(url.path) already has files in it. Move them somewhere else, then start Shrug again.")
        }
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o500])
        seal(url)
        let options = [
            "vers=3", "tcp", "port=\(port)", "mountport=\(port)",
            // Locks stay local; nothing to coordinate with a remote host.
            "locallocks",
            // Revalidate on every open, so a lock takes effect even for cached files.
            "noac", "nonegnamecache",
            // Fail instead of hanging forever if Shrug stops; long enough for a Touch ID prompt.
            "soft", "timeo=600", "retrans=2",
            "rsize=65536", "wsize=65536", "noquota", "nobrowse",
        ].joined(separator: ",")
        let r = try run("/sbin/mount_nfs", ["-o", options, "127.0.0.1:/", url.path])
        guard r.code == 0 else { throw ShrugErrorD("Could not mount \(url.path): \(r.output)") }
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

struct ShrugErrorD: Error, CustomStringConvertible {
    let description: String
    init(_ d: String) { description = d }
}

/// Finds which program has a file open, so the Touch ID prompt can say who is asking.
enum ProcessFinder {
    static func holder(of path: String) -> String? {
        let me = getpid()
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return nil }
        var pids = [pid_t](repeating: 0, count: Int(count) + 32)
        let got = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size))
        guard got > 0 else { return nil }
        for pid in pids.prefix(Int(got)) where pid > 0 && pid != me {
            let size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
            guard size > 0 else { continue }
            let n = Int(size) / MemoryLayout<proc_fdinfo>.stride
            var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: n)
            let filled = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, size)
            guard filled > 0 else { continue }
            for fd in fds.prefix(Int(filled) / MemoryLayout<proc_fdinfo>.stride)
            where fd.proc_fdtype == UInt32(PROX_FDTYPE_VNODE) {
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
