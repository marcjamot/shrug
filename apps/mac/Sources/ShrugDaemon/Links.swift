import Darwin
import Foundation
import ShrugCore

/// When this Mac and Shrug both have a file for a path.
public enum Choice: String, Sendable {
    /// This Mac's file replaces Shrug's.
    case mine
    /// Shrug's file wins; this Mac's is deleted.
    case shrug
}

/// The result of a command that may need answers first.
enum Outcome {
    case done(String)
    case collisions([String])
}

/// Links are what profiles describe: paths on this Mac that show files in ~/Shrug.
/// Shrug keeps three views and moves what is towards what should be:
///   desired   the profile's links
///   recorded  the links Shrug itself placed here (it only ever removes those)
///   actual    what's on disk
/// It only deletes a real file you chose against: one in the way is pulled into Shrug, or
/// left alone until you choose.
extension Engine {
    enum Found: Equatable { case nothing, ourLink, otherLink, file, folder }

    func mountURL(_ target: String) -> URL { paths.mount.appendingPathComponent(target) }

    func found(_ url: URL, _ target: String) -> Found {
        var st = stat()
        guard lstat(url.path, &st) == 0 else { return .nothing }
        switch st.st_mode & S_IFMT {
        case S_IFLNK:
            guard let dest = try? FileManager.default.destinationOfSymbolicLink(atPath: url.path) else { return .otherLink }
            let ours = mountURL(target).path
            return dest == ours || paths.canonical(URL(fileURLWithPath: dest)) == paths.canonical(URL(fileURLWithPath: ours))
                ? .ourLink : .otherLink
        case S_IFREG: return .file
        default: return .folder
        }
    }

    /// Paths where this Mac has its own file and Shrug has one too: someone has to choose.
    func collisions(_ links: [Link], _ store: Store, _ recorded: [String: String]) -> [String] {
        links.filter {
            found(paths.expand($0.path), $0.target) == .file && recorded[$0.path] != $0.target
                && store.entry($0.target)?.kind == .file
        }.map(\.path)
    }

    private func place(_ url: URL, _ target: String) throws {
        let parent = url.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: parent.path) {
            try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        }
        guard symlink(mountURL(target).path, url.path) == 0 else {
            throw ShrugError("can't create the link: \(String(cString: strerror(errno)))")
        }
    }

    /// Makes the links on disk match the profile. Returns what it did, for the command line.
    @discardableResult
    func reconcile(choices: [String: Choice] = [:]) -> [String] {
        reconcileLock.lock()
        defer { reconcileLock.unlock() }
        guard let store = store, let st = stateCopy(), st.everSynced else { return [] }
        var recorded = st.recorded
        var notes: [String] = []
        var notices: [String] = []
        var imported = false
        for link in st.links {
            let url = paths.expand(link.path)
            do {
                switch found(url, link.target) {
                case .ourLink:
                    if store.entry(link.target) == nil && !store.isDirectory(link.target) {
                        try store.createFile(link.target)
                        imported = true
                    }
                    recorded[link.path] = link.target
                case .nothing:
                    if store.entry(link.target) == nil {
                        guard !store.isDirectory(link.target) else { throw ShrugError("\(link.target) is a folder") }
                        try store.createFile(link.target)
                        imported = true
                    }
                    try place(url, link.target)
                    recorded[link.path] = link.target
                    notes.append("linked    \(link.path) -> \(link.target)")
                case .file:
                    let replaced = recorded[link.path] == link.target
                    let inSync = store.entry(link.target)?.kind == .file
                    if replaced || !inSync || choices[link.path] == .mine {
                        try store.importFile(from: url, to: link.target)
                        imported = true
                        unlink(url.path)
                        try place(url, link.target)
                        recorded[link.path] = link.target
                        notes.append(replaced ? "restored  \(link.path) (a program had replaced the link; its file is in Shrug now)"
                                     : inSync ? "linked    \(link.path) (kept this Mac's version)"
                                     : "moved     \(link.path) into Shrug")
                    } else if choices[link.path] == .shrug {
                        unlink(url.path)
                        try place(url, link.target)
                        recorded[link.path] = link.target
                        notes.append("linked    \(link.path) (kept Shrug's version, deleted this Mac's)")
                    } else {
                        // Nobody chose (the link came from another Mac): leave this Mac's file
                        // alone and unrecorded, so the next `shrug use` asks.
                        let note = "waiting   \(link.path): this Mac has its own file there. "
                            + "Run 'shrug use \(st.profile ?? "<profile>")' to choose which to keep"
                        notes.append(note)
                        notices.append(note)
                    }
                case .otherLink:
                    unlink(url.path)
                    try place(url, link.target)
                    recorded[link.path] = link.target
                    let note = "replaced  the link that was at \(link.path)"
                    notes.append(note)
                    notices.append(note)
                case .folder:
                    let note = "skipped   \(link.path): a folder is in the way"
                    notes.append(note)
                    notices.append(note)
                }
            } catch {
                let note = "failed    \(link.path): \(error)"
                notes.append(note)
                notices.append(note)
            }
        }
        let wanted = Set(st.links.map(\.path))
        for (path, target) in recorded where !wanted.contains(path) {
            let url = paths.expand(path)
            if found(url, target) == .ourLink {
                unlink(url.path)
                notes.append("unlinked  \(path)")
            }
            recorded[path] = nil
        }
        // Reconciling runs every minute: a problem that's still there is noticed once.
        let fresh = notices.filter { !st.notices.contains($0) }
        if recorded != st.recorded || !fresh.isEmpty {
            updateState {
                $0.recorded = recorded
                $0.notices = Array(($0.notices + fresh).suffix(20))
            }
        }
        if imported { localChange() }
        return notes
    }

    /// Where `add` puts a file by default: its path, minus the dot that hides the first
    /// folder, so Finder shows it. ~/.kube/config -> synced/kube/config.
    func defaultTarget(_ tilde: String, _ cls: FileClass) -> String {
        var parts = (tilde.hasPrefix("~/") ? String(tilde.dropFirst(2)) : tilde)
            .split(separator: "/").map(String.init)
        if let first = parts.first, first.count > 1, first.hasPrefix(".") { parts[0] = String(first.dropFirst()) }
        return cls.rawValue + "/" + parts.joined(separator: "/")
    }

    static func validTarget(_ t: String) -> Bool {
        let parts = t.split(separator: "/", omittingEmptySubsequences: false)
        return parts.count >= 2 && FileClass(rawValue: String(parts[0])) != nil
            && parts.allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }
    }

    private func editProfile(_ body: (inout [Link]) -> Void) {
        updateState {
            body(&$0.links)
            $0.links.sort { $0.path < $1.path }
            $0.profileDirty = true
            $0.profileGen += 1
            $0.profileEditedAt = .nowMs
        }
        passSoon()
    }

    /// Catches up with the bucket first: links must never be judged against an old picture.
    private func catchUp() throws {
        replicator.pass(wait: true)
        guard stateCopy()?.everSynced == true else {
            throw ShrugError("Can't reach the storage yet. On a new Mac, Shrug needs one complete sync before it places links.")
        }
    }

    func add(path: String, target: String?, cls: FileClass?, choices: [String: Choice]) throws -> Outcome {
        try requireUnlocked("unlock to add a link")
        try catchUp()
        guard let store = store, let st = stateCopy() else { throw ShrugError("Shrug is locked") }
        guard st.profile != nil else { throw ShrugError("Pick a profile first: shrug use <name>") }
        let url = paths.expand(path)
        let mount = paths.canonical(paths.mount)
        guard !paths.canonical(url).hasPrefix(mount + "/"), paths.canonical(url) != mount else {
            throw ShrugError("That's inside ~/Shrug already")
        }
        let tilde = paths.contract(url)
        let t = target ?? defaultTarget(tilde, cls ?? .synced)
        guard Engine.validTarget(t) else { throw ShrugError("'\(t)' should look like synced/<name>, local/<name> or remote/<name>") }
        guard found(url, t) != .folder else { throw ShrugError("\(tilde) is a folder: Shrug links single files") }
        let link = Link(path: tilde, target: t)
        let open = collisions([link], store, st.recorded).filter { choices[$0] == nil }
        if !open.isEmpty { return .collisions(open) }
        editProfile { links in
            links.removeAll { $0.path == tilde }
            links.append(link)
        }
        let notes = reconcile(choices: choices)
        return .done((notes.isEmpty ? ["linked    \(tilde) -> \(t)"] : notes).joined(separator: "\n"))
    }

    func remove(path: String) throws -> String {
        try requireUnlocked("unlock to remove a link")
        guard let st = stateCopy() else { throw ShrugError("Shrug is locked") }
        let tilde = paths.contract(paths.expand(path))
        guard let link = st.links.first(where: { $0.path == tilde }) else { throw ShrugError("\(tilde) isn't a Shrug link") }
        editProfile { $0.removeAll { $0.path == tilde } }
        reconcile()
        return "Removed the link at \(tilde). The file stays in ~/Shrug/\(link.target)."
    }

    /// Lists the profiles (no name), or makes this Mac follow one (created if new).
    func use(_ name: String?, choices: [String: Choice]) throws -> Outcome {
        try requireUnlocked("unlock to choose a profile")
        if name != nil { try catchUp() }
        guard let s = session(), let st = stateCopy() else { throw ShrugError("Shrug is locked") }
        guard let name, !name.isEmpty else {
            let names: [String]
            do {
                names = try replicator.profileNames(s)
                updateState { $0.profileNames = names }
            } catch StorageError.offline {
                names = st.profileNames
            }
            let list = names.map { $0 == st.profile ? "\($0)  (this Mac)" : $0 }
            return .done(list.isEmpty ? "No profiles yet: 'shrug use <name>' makes one." : list.joined(separator: "\n"))
        }
        var profile: Profile
        var isNew = false
        if name == st.profile {
            profile = Profile(name: name, links: st.links, editedAt: st.profileEditedAt ?? .nowMs)
        } else {
            let key = s.keys.profileKey(name)
            do {
                profile = try s.keys.openMeta(Profile.self, s.storage.get(key, range: nil), key: key)
            } catch StorageError.notFound {
                profile = Profile(name: name, links: [], editedAt: .nowMs)
                isNew = true
            } catch StorageError.offline {
                throw ShrugError("Can't reach the storage to load '\(name)'. Try again when online.")
            }
        }
        let open = collisions(profile.links, s.store, st.recorded).filter { choices[$0] == nil }
        if !open.isEmpty { return .collisions(open) }
        let switching = name != st.profile
        updateState {
            $0.profile = name
            $0.links = profile.links
            $0.profileEditedAt = profile.editedAt
            if switching { $0.profileETag = nil }
            $0.profileDirty = isNew || (!switching && $0.profileDirty)
            $0.profileGen += 1
            if !$0.profileNames.contains(name) { $0.profileNames = ($0.profileNames + [name]).sorted() }
        }
        passSoon()
        let notes = reconcile(choices: choices)
        let head = isNew ? "Created profile '\(name)'; this Mac follows it." : "This Mac follows '\(name)'."
        return .done(([head] + notes).joined(separator: "\n"))
    }

    func linkInfos() -> [LinkInfo] {
        guard let st = stateCopy(), let store = store else { return [] }
        return st.links.map { link in
            let state: String
            switch found(paths.expand(link.path), link.target) {
            case .ourLink: state = store.entry(link.target) == nil ? "the file is missing in ~/Shrug" : "ok"
            case .nothing: state = "not placed yet"
            case .file: state = "a real file is in the way"
            case .otherLink: state = "another link is in the way"
            case .folder: state = "a folder is in the way"
            }
            return LinkInfo(path: link.path, target: link.target, state: state)
        }
    }
}
