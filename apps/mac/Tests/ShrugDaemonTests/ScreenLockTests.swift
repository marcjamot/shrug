import XCTest
@testable import ShrugCore
@testable import ShrugDaemon

/// Stands in for macOS: the test says what the screen shows.
final class FakeScreen: @unchecked Sendable {
    private let lock = NSLock()
    private var state: ScreenState? = ScreenState(locked: false, ours: true)

    func show(_ s: ScreenState?) {
        lock.lock()
        state = s
        lock.unlock()
    }

    var watch: ScreenWatch {
        ScreenWatch { [self] in
            lock.lock()
            defer { lock.unlock() }
            return state
        }
    }
}

/// Shrug locks when the screen does, even if the notification for it never arrives.
/// (`checkScreen` runs every second; the tests call it directly.)
final class ScreenLockTests: ShrugTestCase {
    static let open = ScreenState(locked: false, ours: true)
    static let locked = ScreenState(locked: true, ours: true)
    static let otherUser = ScreenState(locked: false, ours: false)

    /// A set-up, unlocked Mac with a file, and the screen it looks at.
    func unlockedMac() throws -> (Mac, FakeScreen) {
        let screen = FakeScreen()
        let a = mac("a", screen: screen.watch)
        _ = try a.engine.setup(storage, nil, password: password, deviceName: "a", create: true)
        try a.write("synced/key", Data("secret".utf8))
        XCTAssertTrue(a.engine.isUnlocked)
        return (a, screen)
    }

    func testAMissedScreenLockIsCaught() throws {
        let (a, screen) = try unlockedMac()
        a.engine.checkScreen()
        XCTAssertTrue(a.engine.isUnlocked, "nothing changed: stays unlocked")

        screen.show(nil)
        a.engine.checkScreen()
        XCTAssertTrue(a.engine.isUnlocked, "macOS not saying anything is not a reason to lock")

        screen.show(ScreenLockTests.locked)
        a.engine.checkScreen()
        XCTAssertFalse(a.engine.isUnlocked, "the screen locked without a notification: the next look locks")
        XCTAssertEqual(try a.names("synced"), [], "and names are hidden again")
    }

    func testSwitchingToAnotherUserLocks() throws {
        let (a, screen) = try unlockedMac()
        a.engine.checkScreen()
        screen.show(ScreenLockTests.otherUser)
        a.engine.checkScreen()
        XCTAssertFalse(a.engine.isUnlocked)
    }

    func testUnlockingWhileTheScreenIsLockedHolds() throws {
        let (a, screen) = try unlockedMac()
        screen.show(ScreenLockTests.locked)
        a.engine.lockNow("screen locked") // the notification, on time

        // Unlocking on purpose while the screen stays locked (over SSH, say) holds.
        try a.engine.unlock(password: password)
        a.engine.checkScreen()
        XCTAssertTrue(a.engine.isUnlocked, "the screen was already locked when you unlocked")

        screen.show(ScreenLockTests.open)
        a.engine.checkScreen()
        XCTAssertTrue(a.engine.isUnlocked, "the screen opening doesn't lock")

        screen.show(ScreenLockTests.locked)
        a.engine.checkScreen()
        XCTAssertFalse(a.engine.isUnlocked, "but the next time it locks, Shrug does too")
    }

    func testALockedShrugDoesntAskAboutTheScreen() throws {
        let (a, screen) = try unlockedMac()
        a.engine.lockNow("test")
        screen.show(ScreenLockTests.locked)
        a.engine.checkScreen()
        screen.show(ScreenLockTests.open)
        try a.engine.unlock(password: password)
        a.engine.checkScreen()
        XCTAssertTrue(a.engine.isUnlocked, "what the screen did while locked doesn't count after unlocking")
    }
}
