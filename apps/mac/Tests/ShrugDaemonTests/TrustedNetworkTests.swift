import XCTest
@testable import ShrugCore
@testable import ShrugDaemon

/// Stands in for macOS: the test says which router the Mac sees.
final class FakeNetwork: @unchecked Sendable {
    private let lock = NSLock()
    private var router: String?

    init(_ router: String? = nil) { self.router = router }

    func join(_ router: String?) {
        lock.lock()
        self.router = router
        lock.unlock()
    }

    var watch: NetworkWatch {
        NetworkWatch { [self] in
            lock.lock()
            defer { lock.unlock() }
            return router
        }
    }
}

/// On a network you trust, a screen lock doesn't lock Shrug; anything else still does.
/// (`checkScreen` and `checkNetwork` run every second; the tests call them directly.)
final class TrustedNetworkTests: ShrugTestCase {
    static let home = "a4:5e:60:01:02:03"
    static let cafe = "00:11:22:33:44:55"

    /// A set-up, unlocked Mac at home with a file, its screen and its network.
    func macAtHome(trusting: Bool = true, touchID: TouchIDKeyStore? = nil) throws -> (Mac, FakeScreen, FakeNetwork) {
        let screen = FakeScreen()
        let network = FakeNetwork(TrustedNetworkTests.home)
        let a = mac("a", touchID: touchID, screen: screen.watch, network: network.watch)
        _ = try a.engine.setup(storage, nil, password: password, deviceName: "a", create: true)
        try a.write("synced/key", Data("secret".utf8))
        if trusting { _ = try a.engine.trust(name: "home", password: password) }
        a.engine.checkScreen()
        return (a, screen, network)
    }

    func lockScreen(_ a: Mac, _ screen: FakeScreen) {
        screen.show(ScreenLockTests.locked)
        a.engine.checkScreen()
        a.engine.checkNetwork()
    }

    func testTheScreenLockingOnATrustedNetworkStaysUnlocked() throws {
        let (a, screen, _) = try macAtHome()
        lockScreen(a, screen)
        XCTAssertTrue(a.engine.isUnlocked)
        XCTAssertEqual(try a.text("synced/key"), "secret", "files stay readable behind the locked screen")
        XCTAssertEqual(a.engine.status().held, "home")

        a.engine.screenLocked() // the notification for the same screen lock, arriving late
        XCTAssertTrue(a.engine.isUnlocked)

        screen.show(ScreenLockTests.open)
        a.engine.checkScreen()
        XCTAssertTrue(a.engine.isUnlocked)
        XCTAssertNil(a.engine.status().held, "back at the screen: nothing is being held open")
    }

    func testTheNotificationAloneStaysUnlockedToo() throws {
        let (a, _, _) = try macAtHome()
        a.engine.screenLocked()
        XCTAssertTrue(a.engine.isUnlocked)
        XCTAssertEqual(a.engine.status().held, "home")
    }

    func testWithoutTrustTheScreenLockLocks() throws {
        let (a, screen, _) = try macAtHome(trusting: false)
        lockScreen(a, screen)
        XCTAssertFalse(a.engine.isUnlocked)
    }

    func testOnAnotherNetworkTheScreenLockLocks() throws {
        let (a, screen, network) = try macAtHome()
        network.join(TrustedNetworkTests.cafe)
        lockScreen(a, screen)
        XCTAssertFalse(a.engine.isUnlocked)
    }

    func testNotKnowingTheNetworkLocks() throws {
        let (a, screen, network) = try macAtHome()
        network.join(nil)
        lockScreen(a, screen)
        XCTAssertFalse(a.engine.isUnlocked, "no router to recognize is not a trusted network")
    }

    func testLeavingTheNetworkBehindALockedScreenLocks() throws {
        let (a, screen, network) = try macAtHome()
        lockScreen(a, screen)
        XCTAssertTrue(a.engine.isUnlocked)

        network.join(TrustedNetworkTests.cafe)
        a.engine.checkNetwork()
        XCTAssertFalse(a.engine.isUnlocked, "the Mac is somewhere else now")
        XCTAssertEqual(try a.names("synced"), [], "and names are hidden again")

        // Coming back doesn't unlock by itself.
        network.join(TrustedNetworkTests.home)
        a.engine.checkNetwork()
        XCTAssertFalse(a.engine.isUnlocked)
    }

    func testTheNetworkDroppingBehindALockedScreenLocks() throws {
        let (a, screen, network) = try macAtHome()
        lockScreen(a, screen)
        network.join(nil)
        a.engine.checkNetwork()
        XCTAssertFalse(a.engine.isUnlocked)
    }

    func testLeavingTheNetworkAtAnOpenScreenDoesntLock() throws {
        let (a, screen, network) = try macAtHome()
        network.join(TrustedNetworkTests.cafe)
        a.engine.checkNetwork()
        XCTAssertTrue(a.engine.isUnlocked, "you're at the screen: the network doesn't matter")

        // Held open once, then back at the screen: still doesn't matter.
        network.join(TrustedNetworkTests.home)
        lockScreen(a, screen)
        screen.show(ScreenLockTests.open)
        a.engine.checkScreen()
        network.join(TrustedNetworkTests.cafe)
        a.engine.checkNetwork()
        XCTAssertTrue(a.engine.isUnlocked)

        lockScreen(a, screen)
        XCTAssertFalse(a.engine.isUnlocked, "but the screen locking there locks")
    }

    func testSleepUserSwitchAndLockNowStillLock() throws {
        let (a, screen, _) = try macAtHome()
        lockScreen(a, screen)
        a.engine.lockNow("Mac went to sleep") // what the sleep notification does
        XCTAssertFalse(a.engine.isUnlocked)

        screen.show(ScreenLockTests.open)
        try a.engine.unlock(password: password)
        a.engine.checkScreen()
        screen.show(ScreenLockTests.otherUser)
        a.engine.checkScreen()
        XCTAssertFalse(a.engine.isUnlocked, "someone else at the screen locks, trusted network or not")

        screen.show(ScreenLockTests.open)
        try a.engine.unlock(password: password)
        a.engine.checkScreen()
        screen.show(ScreenState(locked: true, ours: false))
        a.engine.checkScreen()
        XCTAssertFalse(a.engine.isUnlocked, "switching user and the screen locking at once locks")
    }

    func testUntrustingWhileHeldOpenLocks() throws {
        let (a, screen, _) = try macAtHome()
        lockScreen(a, screen)
        XCTAssertEqual(try a.engine.untrust(name: nil), "No longer trusting 'home'")
        XCTAssertFalse(a.engine.isUnlocked)
    }

    func testUnlockingBehindALockedScreenElsewhereHolds() throws {
        let (a, screen, network) = try macAtHome()
        network.join(TrustedNetworkTests.cafe)
        lockScreen(a, screen)
        XCTAssertFalse(a.engine.isUnlocked)

        // Unlocked on purpose (over SSH, say): not held by a network, so the network isn't asked.
        try a.engine.unlock(password: password)
        a.engine.checkScreen()
        a.engine.checkNetwork()
        XCTAssertTrue(a.engine.isUnlocked)
    }

    func testTrustSurvivesALockAndIsntShownWhileLocked() throws {
        let (a, screen, _) = try macAtHome()
        a.engine.lockNow("test")
        XCTAssertNil(a.engine.status().trusted, "a locked Shrug says nothing about its networks")

        try a.engine.unlock(password: password)
        XCTAssertEqual(a.engine.status().trusted, ["home"])
        XCTAssertEqual(a.engine.status().trustedHere, "home")
        a.engine.checkScreen()
        lockScreen(a, screen)
        XCTAssertTrue(a.engine.isUnlocked)
    }

    // MARK: - Trusting

    func testTrustingNeedsThePasswordWithoutTouchID() throws {
        let (a, _, _) = try macAtHome(trusting: false)
        XCTAssertThrowsError(try a.engine.trust(name: "home", password: nil)) { XCTAssertTrue($0 is PasswordNeeded) }
        XCTAssertThrowsError(try a.engine.trust(name: "home", password: "wrong"), "unlocked or not, the password is checked")
        XCTAssertEqual(a.engine.status().trusted, [])
        _ = try a.engine.trust(name: "home", password: password)
        XCTAssertEqual(a.engine.status().trusted, ["home"])
    }

    func testTrustingAsksForAFingerprintEvenWhenUnlocked() throws {
        let touch = FakeTouchID()
        let (a, screen, _) = try macAtHome(trusting: false, touchID: touch)
        XCTAssertTrue(a.engine.isUnlocked)

        touch.answering { throw TouchIDError.cancelled }
        XCTAssertThrowsError(try a.engine.trust(name: nil, password: nil))
        XCTAssertEqual(a.engine.status().trusted, [], "no fingerprint, no trust")

        touch.answering {}
        _ = try a.engine.trust(name: nil, password: nil)
        XCTAssertEqual(touch.prompts.last, "trust the network this Mac is on")
        XCTAssertEqual(a.engine.status().trusted, ["home"], "unnamed, it's called home")

        touch.answering { throw TouchIDError.usePassword("test") }
        XCTAssertThrowsError(try a.engine.trust(name: "den", password: nil)) { XCTAssertTrue($0 is PasswordNeeded) }

        lockScreen(a, screen)
        XCTAssertTrue(a.engine.isUnlocked)
    }

    func testTrustingWhileLockedUnlocks() throws {
        let touch = FakeTouchID()
        let (a, _, _) = try macAtHome(trusting: false, touchID: touch)
        a.engine.lockNow("test")
        _ = try a.engine.trust(name: "home", password: nil)
        XCTAssertTrue(a.engine.isUnlocked)
        XCTAssertEqual(a.engine.status().trusted, ["home"])
    }

    func testNamesAndSeveralNetworks() throws {
        let (a, _, network) = try macAtHome()
        _ = try a.engine.trust(name: "den", password: password)
        XCTAssertEqual(a.engine.status().trusted, ["den"], "trusting the same network again renames it")

        network.join(TrustedNetworkTests.cafe)
        XCTAssertNil(a.engine.status().trustedHere)
        XCTAssertThrowsError(try a.engine.trust(name: "den", password: password), "a name means one network")
        _ = try a.engine.trust(name: "office", password: password)
        XCTAssertEqual(a.engine.status().trusted, ["den", "office"])
        XCTAssertEqual(a.engine.status().trustedHere, "office")

        network.join("0a:0b:0c:0d:0e:0f")
        XCTAssertThrowsError(try a.engine.untrust(name: nil), "not on one, and there are two: which?")
        XCTAssertThrowsError(try a.engine.untrust(name: "nope"))
        _ = try a.engine.untrust(name: "den")
        XCTAssertEqual(a.engine.status().trusted, ["office"])
        _ = try a.engine.untrust(name: nil)
        XCTAssertEqual(a.engine.status().trusted, [])
        XCTAssertThrowsError(try a.engine.untrust(name: nil))
    }

    func testNoNetworkIsNothingToTrust() throws {
        let (a, _, network) = try macAtHome(trusting: false)
        network.join(nil)
        XCTAssertThrowsError(try a.engine.trust(name: "home", password: password))
        XCTAssertEqual(a.engine.status().trusted, [])
    }

    func testTrustIsntUploaded() throws {
        let (a, _, _) = try macAtHome()
        a.sync()
        let b = mac("b", network: FakeNetwork(TrustedNetworkTests.home).watch)
        _ = try b.engine.setup(storage, nil, password: password, deviceName: "b", create: false)
        b.sync()
        XCTAssertEqual(b.engine.status().trusted, [], "each Mac decides for itself")
    }

    func testStateFromBeforeTrustedNetworksStillOpens() throws {
        let old = #"{"deviceID":"d","deviceName":"a","storage":{"kind":"folder","path":"/x"},"links":[],"profileDirty":false,"profileGen":0,"recorded":{},"notices":[],"profileNames":[],"macs":[],"everSynced":true}"#
        XCTAssertNil(try JSONFile.decode(LocalState.self, from: Data(old.utf8)).trusted)
    }

    // MARK: - What macOS says

    func testTheRouterAddressAsMacOSReportsIt() {
        func address(_ ip: String?, _ mac: String?) -> String? {
            var service: [String: Any] = [:]
            service["ARPResolvedIPAddress"] = ip
            service["ARPResolvedHardwareAddress"] = mac
            return Router.address(router: "192.168.1.1", service: service)
        }
        XCTAssertEqual(address("192.168.1.1", "A2:12:26:8D:16:99"), "a2:12:26:8d:16:99")
        XCTAssertEqual(address("192.168.1.1", "a2:1:26:8d:16:9"), "a2:01:26:8d:16:09", "one spelling per address")
        XCTAssertNil(address("192.168.1.254", "a2:12:26:8d:16:99"), "that's some other device's address")
        XCTAssertNil(address("192.168.1.1", nil))
        XCTAssertNil(address("192.168.1.1", "00:00:00:00:00:00"))
        XCTAssertNil(address("192.168.1.1", "ff:ff:ff:ff:ff:ff"))
        XCTAssertNil(address("192.168.1.1", "a2:12:26:8d:16"))
        XCTAssertNil(address("192.168.1.1", "a2:12:26:8d:16:zz"))
    }
}
