import Darwin
import Foundation
import ShrugCore

// shrug: the command line for Shrug. Every command is answered by the running Shrug app.

let usage = """
Usage: shrug <command>

  setup                    Set up this Mac (./setup runs this)
  unlock                   Unlock (Touch ID, or the Shrug password)
  lock                     Lock now
  add <path> [<where>]     Make <path> (in your home folder) come from Shrug. A file already
                           there moves into Shrug; a missing one is created empty. <where> is
                           the place in ~/Shrug (default synced/<path>); --local or --remote
                           picks another folder
  remove <path>            Stop that link. The file stays in ~/Shrug
  use [<profile>]          Follow a profile (a new name creates one). Without a name, list them
  status                   Lock state, profile, storage, links

Answers can also be piped in, one per line, in the order they're asked.
"""

var args = Array(CommandLine.arguments.dropFirst())
guard let command = args.first, !["-h", "--help", "help"].contains(command) else {
    print(usage)
    exit(args.isEmpty ? 1 : 0)
}
args.removeFirst()

func flag(_ name: String) -> Bool {
    if let i = args.firstIndex(of: name) {
        args.remove(at: i)
        return true
    }
    return false
}

func option(_ name: String) -> String? {
    if let i = args.firstIndex(of: name), i + 1 < args.count {
        let v = args[i + 1]
        args.removeSubrange(i...(i + 1))
        return v
    }
    return nil
}

func die(_ message: String) -> Never {
    fputs("shrug: \(message)\n", stderr)
    exit(1)
}

let interactive = isatty(0) == 1

/// One answer: typed (hidden for secrets) or read from a pipe.
func ask(_ prompt: String, secret: Bool = false, default fallback: String? = nil) -> String {
    let shown = fallback.map { "\(prompt) [\($0)]: " } ?? "\(prompt): "
    var answer: String
    if interactive && secret {
        var buffer = [CChar](repeating: 0, count: 1024)
        guard let p = readpassphrase(shown, &buffer, buffer.count, RPP_REQUIRE_TTY) else { die("Cannot read input") }
        answer = String(cString: p)
        memset(&buffer, 0, buffer.count)
    } else {
        print(shown, terminator: "")
        fflush(stdout)
        guard let line = readLine(strippingNewline: true) else { die("No answer given") }
        answer = line
        if !interactive { print(secret ? "" : line) }
    }
    answer = answer.trimmingCharacters(in: .whitespaces)
    if answer.isEmpty, let fallback { return fallback }
    return answer
}

func absolute(_ path: String) -> String {
    let expanded = (path as NSString).expandingTildeInPath
    return URL(fileURLWithPath: expanded, relativeTo: URL(fileURLWithPath: FileManager.default.currentDirectoryPath))
        .standardizedFileURL.path
}

let paths = ShrugPaths.current()

func rawSend(_ cmd: String, _ a: [String: String] = [:]) -> IPCResponse {
    do {
        return try IPCClient.send(IPCRequest(cmd, a), socket: paths.socket)
    } catch {
        die("\(error)")
    }
}

/// Sends a command. If Shrug is locked and only the Shrug password can unlock it (no
/// fingerprint, or you chose the password), asks for it, unlocks and sends the command again.
func send(_ cmd: String, _ a: [String: String] = [:]) -> IPCResponse {
    let r = rawSend(cmd, a)
    guard r.code == "password-needed", cmd != "unlock" else { return r }
    let unlocked = rawSend("unlock", ["password": ask("Shrug password", secret: true)])
    guard unlocked.ok else { die(unlocked.message) }
    return rawSend(cmd, a)
}

func run(_ cmd: String, _ a: [String: String] = [:]) -> Never {
    let r = send(cmd, a)
    if r.ok {
        if !r.message.isEmpty { print(r.message) }
        exit(0)
    }
    die(r.message)
}

func defaultDeviceName() -> String {
    let host = ProcessInfo.processInfo.hostName
    return host.hasSuffix(".local") ? String(host.dropLast(6)) : host
}

/// Runs a command that may first need answers: which links from another Mac to place here,
/// then, for each path, whose file to keep.
func runChoosing(_ cmd: String, _ a: [String: String]) -> Never {
    var choices: [String: String] = [:]
    var forAll: String?
    var approved: [String]?
    while true {
        var request = a
        if !choices.isEmpty, let json = try? JSONFile.encode(choices) { request["choices"] = String(decoding: json, as: UTF8.self) }
        if let approved, let json = try? JSONFile.encode(approved) { request["approve"] = String(decoding: json, as: UTF8.self) }
        let r = send(cmd, request)
        if r.code == "confirm-links", approved == nil {
            print("The profile links these on this Mac, and they aren't here yet:")
            for line in r.message.split(separator: "\n") { print("  \(line)") }
            while approved == nil {
                switch ask("Place them? (y/n)") {
                case "y", "Y", "yes": approved = r.list ?? []
                case "n", "N", "no":
                    approved = []
                    print("They'll wait until you run 'shrug use' again.")
                default: print("Type y or n.")
                }
            }
            continue
        }
        guard r.code == "collisions", let paths = r.list, !paths.isEmpty else {
            if r.ok {
                if !r.message.isEmpty { print(r.message) }
                exit(0)
            }
            die(r.message)
        }
        for p in paths where choices[p] == nil {
            if let forAll {
                choices[p] = forAll
                continue
            }
            print("""
            \(p): this Mac has its own file or link there, and Shrug has one too.
              [m] keep this Mac's version (it replaces Shrug's)
              [s] keep Shrug's version (this Mac's is deleted)
              [M] this Mac's for this and all following
              [S] Shrug's for this and all following
              [a] abort
            """)
            while choices[p] == nil {
                switch ask("Choice") {
                case "m": choices[p] = "mine"
                case "s": choices[p] = "shrug"
                case "M": choices[p] = "mine"; forAll = "mine"
                case "S": choices[p] = "shrug"; forAll = "shrug"
                case "a": die("Aborted. Nothing changed.")
                default: print("Type m, s, M, S or a.")
                }
            }
        }
    }
}

func ago(_ d: Date) -> String {
    let s = Int(Date().timeIntervalSince(d))
    if s < 60 { return "just now" }
    if s < 3600 { return "\(s / 60) min ago" }
    if s < 86400 { return "\(s / 3600) h ago" }
    return "\(s / 86400) days ago"
}

func printStatus(_ s: StatusInfo) {
    guard s.setUp else {
        print("Not set up. Run ./setup in the repo folder.")
        return
    }
    let tilde = s.mount.hasPrefix(paths.home.path + "/") ? "~/" + s.mount.dropFirst(paths.home.path.count + 1) : s.mount
    print("Shrug:     \(s.unlocked ? "unlocked" : "locked")\(s.touchID ? "  [Touch ID on]" : "")")
    print("Folder:    \(tilde)\(s.mounted ? "" : "  (NOT mounted)")")
    guard s.unlocked else {
        print("Unlock to see more.")
        return
    }
    let others = s.macs.count > 1 ? "  (all Macs: \(s.macs.joined(separator: ", ")))" : ""
    print("Mac:       \(s.device ?? "-")\(others)")
    print("Profile:   \(s.profile ?? "none yet (shrug use <name>)")")
    let waiting = s.waiting == 1 ? "1 change waiting" : "\(s.waiting) changes waiting"
    let state: String
    if let problem = s.problem {
        state = "problem: \(problem)"
    } else if s.online == false {
        state = "offline" + (s.waiting > 0 ? ", \(waiting)" : "")
    } else if s.online == nil {
        state = "not checked yet"
    } else if s.waiting > 0 {
        state = waiting
    } else {
        state = "up to date" + (s.lastSync.map { " (checked \(ago($0)))" } ?? "")
    }
    print("Storage:   \(s.storage ?? "-"): \(state)")
    if !s.links.isEmpty {
        print("Links:")
        for l in s.links { print("  \(l.state == "ok" ? "ok" : "!!")  \(l.path) -> \(l.target)\(l.state == "ok" ? "" : ": \(l.state)")") }
    }
    if !s.notices.isEmpty {
        print("Notices:")
        for n in s.notices { print("  \(n)") }
    }
    if let e = s.lastEvent { print("Last:      \(e)") }
}

switch command {
case "status":
    let r = send("status")
    guard r.ok, let s = r.status else { die(r.message) }
    printStatus(s)

case "unlock":
    if flag("--password") {
        run("unlock", ["password": ask("Shrug password", secret: true)])
    }
    let r = send("unlock")
    if r.ok { print(r.message); exit(0) }
    guard r.code == "password-needed" else { die(r.message) }
    run("unlock", ["password": ask("Shrug password", secret: true)])

case "lock":
    run("lock")

case "setup":
    var a: [String: String] = [:]
    let kind = option("--storage") ?? ask("Storage (gcs, or folder)", default: "gcs")
    var config: StorageConfig
    switch kind {
    case "gcs":
        let bucket = option("--bucket") ?? ask("Bucket name")
        print("Shrug needs an HMAC key for a service account that can only use this bucket")
        print("(Cloud Storage > Settings > Interoperability).")
        a["access-id"] = ask("Access ID")
        a["secret"] = ask("Secret", secret: true)
        config = StorageConfig(kind: "gcs", bucket: bucket)
    case "folder":
        config = StorageConfig(kind: "folder", path: absolute(option("--path") ?? ask("Folder")))
    default:
        die("Unknown storage '\(kind)': use gcs or folder")
    }
    // Google accepts "auto"; pass the bucket's location if it ever asks for one.
    if let region = option("--region") { config.region = region }
    guard let json = try? JSONFile.encode(config) else { die("Bad storage settings") }
    a["storage"] = String(decoding: json, as: UTF8.self)
    a["device"] = option("--device") ?? defaultDeviceName()
    let wantedProfile = option("--profile")

    let probe = send("probe", a)
    guard probe.ok else { die(probe.message) }
    if probe.code == "empty" {
        print("There's no vault there yet, so this is your first Mac. Choose a Shrug password")
        print("and keep it in your password manager.")
        let p1 = ask("New Shrug password", secret: true)
        if interactive {
            guard p1 == ask("Repeat it", secret: true) else { die("Passwords do not match") }
        }
        a["password"] = p1
        a["create"] = "1"
    } else {
        a["password"] = ask("Shrug password", secret: true)
    }
    let r = send("setup", a)
    guard r.ok else { die(r.message) }
    print("\(a["device"]!) is set up and unlocked.")
    let names = r.list ?? []
    let profile: String
    if let wantedProfile {
        profile = wantedProfile
    } else if names.isEmpty {
        profile = ask("Name a profile for this Mac's links", default: "default")
    } else {
        print("Profiles: \(names.joined(separator: ", "))")
        profile = ask("Profile to follow (a new name creates one)", default: names[0])
    }
    runChoosing("use", ["name": profile])

case "add":
    let cls = flag("--local") ? "local" : flag("--remote") ? "remote" : nil
    guard let path = args.first else { die("add needs a path") }
    var a = ["path": absolute(path)]
    if args.count > 1 { a["target"] = args[1] }
    if let cls { a["class"] = cls }
    runChoosing("add", a)

case "remove":
    guard let path = args.first else { die("remove needs a path") }
    run("remove", ["path": absolute(path)])

case "use":
    if let name = args.first { runChoosing("use", ["name": name]) }
    run("use")

default:
    print(usage)
    exit(1)
}
