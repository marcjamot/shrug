import Darwin
import Foundation
import ShrugCore

/// When this Mac has its own file (or link) where Shrug's link should go.
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
    /// Links from the profile that wait for you to agree to them on this Mac.
    case confirm([Link])
}

/// Links are what profiles describe: paths on this Mac that show files in ~/Shrug.
/// Shrug keeps three views and moves what is towards what should be:
///   desired   the profile's links
///   recorded  the links Shrug itself placed here (it only ever removes those)
///   actual    what's on disk
///
/// Profiles come from the bucket, so a link is checked before anything is done for it, and
/// placing links never creates or takes in content for synced/ or remote/: a link whose file
/// hasn't arrived yet waits for it. A link is only placed at a path you agreed to on this Mac
/// (`shrug add`, or answering `shrug use`), so whoever can change a profile can't put a link
/// at, say, ~/.zshenv on every Mac that follows it. Only `shrug add` moves a file into Shrug,
/// and an existing file or link is only replaced when you choose. Deleting one of Shrug's
/// links yourself is a `shrug remove`. Deleting a linked file in ~/Shrug removes its link;
/// renaming it there moves the link along.
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

    /// A file in one of the three folders, like synced/ssh/id_ed25519, that can sync.
    static func isValidTarget(_ t: String) -> Bool {
        let parts = t.split(separator: "/", omittingEmptySubsequences: false)
        return parts.count >= 2 && FileClass(rawValue: String(parts[0])) != nil
            && parts.allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." } && !Store.isScratch(String(parts.last!))
    }

    /// Why a link mustn't be placed on this Mac, or nil if it's fine.
    func problem(_ link: Link) -> String? {
        guard Engine.isValidTarget(link.target) else { return "'\(link.target)' isn't a file Shrug can keep" }
        guard link.path.hasPrefix("~/") else { return "Shrug only links files in your home folder" }
        let parts = link.path.dropFirst(2).split(separator: "/", omittingEmptySubsequences: false)
        guard !parts.isEmpty, parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else { return "not a plain path" }
        // Compared as the Mac's disk compares names, ignoring case: ~/library/launchagents is
        // ~/Library/LaunchAgents, even while that folder doesn't exist yet.
        let real = Engine.folded(paths.canonical(link.path))
        let forbidden = [
            (paths.mount, "it's inside ~/Shrug"),
            (paths.state, "it's inside Shrug's own folder"),
            (paths.home.appendingPathComponent("Library/LaunchAgents"), "programs there start by themselves"),
        ]
        for (place, why) in forbidden {
            let p = Engine.folded(paths.canonical(place))
            if real == p || real.hasPrefix(p + "/") { return why }
        }
        return nil
    }

    /// One spelling per name on a disk that ignores case and Unicode normalization.
    static func folded(_ path: String) -> String {
        path.folding(options: .caseInsensitive, locale: nil).precomposedStringWithCanonicalMapping
    }

    /// Whether you agreed to a link at this path on this Mac. A link Shrug placed counts.
    func isApproved(_ path: String, _ st: LocalState) -> Bool {
        st.recorded[path] != nil || st.approved?.contains(path) == true
    }

    /// Links still waiting for you to agree to them. One that already points at its file in
    /// ~/Shrug changes nothing on disk, so it doesn't ask.
    func unapproved(_ links: [Link], _ st: LocalState) -> [Link] {
        links.filter {
            problem($0) == nil && !isApproved($0.path, st) && found(paths.expand($0.path), $0.target) != .ourLink
        }
    }

    /// Whether Shrug has the link's file here to show (a local/ file is made when missing).
    private func available(_ target: String, _ store: Store) -> Bool {
        store.entry(target)?.kind == .file || Store.fileClass(target) == .local && !store.isDirectory(target)
    }

    /// Paths where this Mac has its own file or link and Shrug's file is here too: someone has to choose.
    func collisions(_ links: [Link], _ store: Store, _ recorded: [String: String]) -> [String] {
        links.filter { link in
            guard problem(link) == nil, available(link.target, store), recorded[link.path] != link.target else { return false }
            switch found(paths.expand(link.path), link.target) {
            case .file: return true
            case .otherLink: return !isRetargeted(link, recorded)
            default: return false
            }
        }.map(\.path)
    }

    /// A link Shrug placed for this path that now points at the old place of a moved file.
    private func isRetargeted(_ link: Link, _ recorded: [String: String]) -> Bool {
        recorded[link.path].map { found(paths.expand(link.path), $0) == .ourLink } ?? false
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
        var deleted: [Link] = []
        var filesChanged = false
        func notice(_ note: String) {
            notes.append(note)
            notices.append(note)
        }
        for link in st.links {
            if let problem = problem(link) {
                notice("skipped   \(link.path): \(problem)")
                continue
            }
            let url = paths.expand(link.path)
            if !isApproved(link.path, st) && found(url, link.target) != .ourLink {
                notice("waiting   \(link.path): linked on another Mac. "
                       + "Run 'shrug use \(st.profile ?? "<profile>")' to place it here")
                continue
            }
            let have = available(link.target, store)
            do {
                switch found(url, link.target) {
                case .ourLink:
                    if store.entry(link.target) == nil && !store.isDirectory(link.target) {
                        if recorded[link.path] == link.target {
                            deleted.append(link)
                            recorded[link.path] = nil
                            unlink(url.path)
                            notice("unlinked  \(link.path) (its file in ~/Shrug was deleted)")
                            break
                        }
                        guard have else { break } // its file hasn't arrived yet
                        try store.createFile(link.target)
                        filesChanged = true
                    }
                    recorded[link.path] = link.target
                case .nothing:
                    if recorded[link.path] == link.target {
                        deleted.append(link)
                        recorded[link.path] = nil
                        notice("unlinked  \(link.path) (deleted on this Mac; the file stays in ~/Shrug/\(link.target))")
                        break
                    }
                    guard have else { break }
                    if store.entry(link.target) == nil {
                        try store.createFile(link.target)
                        filesChanged = true
                    }
                    try place(url, link.target)
                    recorded[link.path] = link.target
                    notes.append("linked    \(link.path) -> \(link.target)")
                case .file where recorded[link.path] == link.target:
                    // A program saved by replacing Shrug's link with a real file: that's an edit.
                    try store.importFile(from: url, to: link.target)
                    filesChanged = true
                    unlink(url.path)
                    try place(url, link.target)
                    notes.append("restored  \(link.path) (a program had replaced the link; its file is in Shrug now)")
                case .otherLink where isRetargeted(link, recorded):
                    unlink(url.path)
                    try place(url, link.target)
                    recorded[link.path] = link.target
                    notes.append("relinked  \(link.path) -> \(link.target)")
                case .file, .otherLink:
                    guard have else { break } // asked once Shrug's file is here
                    switch choices[link.path] {
                    case .mine:
                        try store.importFile(from: url, to: link.target)
                        filesChanged = true
                        unlink(url.path)
                        try place(url, link.target)
                        recorded[link.path] = link.target
                        notes.append("linked    \(link.path) (kept this Mac's version)")
                    case .shrug:
                        if store.entry(link.target) == nil {
                            try store.createFile(link.target)
                            filesChanged = true
                        }
                        unlink(url.path)
                        try place(url, link.target)
                        recorded[link.path] = link.target
                        notes.append("linked    \(link.path) (kept Shrug's version, deleted this Mac's)")
                    case nil:
                        // Nobody chose (the link came from another Mac): leave this Mac's file
                        // alone and unrecorded, so the next `shrug use` asks.
                        notice("waiting   \(link.path): this Mac has its own file there. "
                               + "Run 'shrug use \(st.profile ?? "<profile>")' to choose which to keep")
                    }
                case .folder:
                    notice("skipped   \(link.path): a folder is in the way")
                }
            } catch {
                notice("failed    \(link.path): \(error)")
            }
        }
        if !deleted.isEmpty { editProfile { links in links.removeAll { deleted.contains($0) } } }
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
        // Agreeing is for a path while it's in the profile: if it leaves and comes back, ask again.
        let stale = st.approved.map { !$0.isSubset(of: wanted) } ?? false
        if recorded != st.recorded || !fresh.isEmpty || stale {
            updateState {
                $0.recorded = recorded
                $0.notices = Array(($0.notices + fresh).suffix(20))
                if let agreed = $0.approved { $0.approved = agreed.intersection($0.links.map(\.path)) }
            }
        }
        if filesChanged { localChange() }
        return notes
    }

    /// Where `add` puts a file by default: its path, minus the dot that hides the first
    /// folder, so Finder shows it. ~/.kube/config -> synced/kube/config.
    func defaultTarget(_ tilde: String, _ cls: FileClass) -> String {
        var parts = String(tilde.dropFirst(2)).split(separator: "/").map(String.init)
        if let first = parts.first, first.count > 1, first.hasPrefix(".") { parts[0] = String(first.dropFirst()) }
        return cls.rawValue + "/" + parts.joined(separator: "/")
    }

    private func editProfile(_ body: (inout [Link]) -> Void) {
        let now = clock.nowMs
        updateState {
            body(&$0.links)
            $0.links.sort { $0.path < $1.path }
            $0.profileDirty = true
            $0.profileGen += 1
            $0.profileEditedAt = now
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

    /// Links `path` to `target` (by default its own path in synced/). When Shrug has no file
    /// there yet, this Mac's file moves in, or an empty one is made.
    func add(path: String, target: String?, cls: FileClass?, choices: [String: Choice]) throws -> Outcome {
        try requireUnlocked("unlock to add a link")
        try catchUp()
        guard let store = store, let st = stateCopy() else { throw ShrugError("Shrug is locked") }
        guard st.profile != nil else { throw ShrugError("Pick a profile first: shrug use <name>") }
        let url = paths.expand(path)
        let tilde = paths.contract(url)
        guard tilde.hasPrefix("~/") else { throw ShrugError("Shrug only links files in your home folder") }
        let link = Link(path: tilde, target: target ?? defaultTarget(tilde, cls ?? .synced))
        if let problem = problem(link) { throw ShrugError("Can't link \(tilde): \(problem)") }
        let here = found(url, link.target)
        guard here != .folder else { throw ShrugError("\(tilde) is a folder: Shrug links single files") }
        if store.entry(link.target) == nil {
            guard !store.isDirectory(link.target) else { throw ShrugError("\(link.target) is a folder") }
            if here == .file || here == .otherLink {
                try store.importFile(from: url, to: link.target)
                unlink(url.path)
            } else {
                try store.createFile(link.target)
            }
        } else {
            let open = collisions([link], store, st.recorded).filter { choices[$0] == nil }
            if !open.isEmpty { return .collisions(open) }
        }
        let nothingThere = found(url, link.target) == .nothing
        updateState {
            if nothingThere { $0.recorded[tilde] = nil }
            $0.approved = ($0.approved ?? []).union([tilde]) // added here, so agreed to here
        }
        editProfile { links in
            links.removeAll { $0.path == tilde }
            links.append(link)
        }
        let notes = reconcile(choices: choices)
        return .done((notes.isEmpty ? ["linked    \(tilde) -> \(link.target)"] : notes).joined(separator: "\n"))
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

    /// After a rename in ~/Shrug: links to what moved follow it.
    func renamed(_ from: String, _ to: String) {
        func moved(_ target: String) -> String? {
            target == from ? to : target.hasPrefix(from + "/") ? to + target.dropFirst(from.count) : nil
        }
        guard stateCopy()?.links.contains(where: { moved($0.target) != nil }) == true else { return }
        editProfile { links in
            for i in links.indices {
                if let t = moved(links[i].target) { links[i].target = t }
            }
        }
        reconcileSoon()
    }

    /// Lists the profiles (no name), or makes this Mac follow one (created if new).
    ///
    /// First asks which of the profile's links you agree to place on this Mac (`approve`: nil
    /// until asked; the paths you agreed to, possibly none), then whose file to keep where both
    /// have one. Links you didn't agree to wait, and the next `shrug use` asks again.
    func use(_ name: String?, choices: [String: Choice], approve: Set<String>? = nil) throws -> Outcome {
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
        var version: String?
        var isNew = false
        if name == st.profile {
            profile = Profile(name: name, links: st.links, editedAt: st.profileEditedAt ?? clock.nowMs)
            version = st.profileVersion
        } else {
            let key = s.keys.profileKey(name)
            let found = try s.storage.list(prefix: key).first { $0.key == key }
            if let found {
                profile = try s.keys.openMeta(Profile.self, s.storage.get(key, version: found.version), key: key)
                version = found.version
            } else {
                profile = Profile(name: name, links: [], editedAt: clock.nowMs)
                isNew = true
            }
        }
        let pending = unapproved(profile.links, st)
        if approve == nil && !pending.isEmpty { return .confirm(pending) }
        let agreed = Set(pending.map(\.path)).intersection(approve ?? [])
        var view = st
        view.approved = (st.approved ?? []).union(agreed)
        let placing = profile.links.filter { isApproved($0.path, view) }
        let open = collisions(placing, s.store, st.recorded).filter { choices[$0] == nil }
        if !open.isEmpty { return .collisions(open) }
        let switching = name != st.profile
        updateState {
            $0.profile = name
            $0.links = profile.links
            $0.profileEditedAt = profile.editedAt
            $0.profileVersion = version
            $0.profileDirty = isNew || (!switching && $0.profileDirty)
            $0.profileGen += 1
            if !$0.profileNames.contains(name) { $0.profileNames = ($0.profileNames + [name]).sorted() }
            if !agreed.isEmpty { $0.approved = ($0.approved ?? []).union(agreed) }
        }
        passSoon()
        let notes = reconcile(choices: choices)
        let head = isNew ? "Created profile '\(name)'; this Mac follows it." : "This Mac follows '\(name)'."
        return .done(([head] + notes).joined(separator: "\n"))
    }

    /// Every link in the profile, one per line, with what's wrong with those that don't work.
    func links() throws -> String {
        try requireUnlocked("unlock to list the links")
        let lines = linkInfos().map { l in
            l.state == "ok" ? "ok  \(l.path) -> \(l.target)" : "!!  \(l.path) -> \(l.target): \(l.state)"
        }
        return lines.isEmpty ? "No links yet: 'shrug add <path>' makes one." : lines.joined(separator: "\n")
    }

    func linkInfos() -> [LinkInfo] {
        guard let st = stateCopy(), let store = store else { return [] }
        return st.links.map { link in
            let state: String
            if let problem = problem(link) {
                state = "not placed: \(problem)"
            } else if !isApproved(link.path, st) && found(paths.expand(link.path), link.target) != .ourLink {
                state = "added on another Mac: 'shrug use \(st.profile ?? "<profile>")' to place it"
            } else {
                switch found(paths.expand(link.path), link.target) {
                case .ourLink: state = store.entry(link.target) == nil ? "waiting for its file to arrive" : "ok"
                case .nothing: state = available(link.target, store) ? "not placed yet" : "waiting for its file to arrive"
                case .file: state = "a real file is in the way"
                case .otherLink: state = "another link is in the way"
                case .folder: state = "a folder is in the way"
                }
            }
            return LinkInfo(path: link.path, target: link.target, state: state)
        }
    }
}
