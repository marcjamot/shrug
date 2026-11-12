import XCTest
@testable import ShrugCore
@testable import ShrugDaemon

/// ~/ShrugDisk follows Shrug's lock, and comes back with one prompt when you return to the
/// Mac. (The disk here is a stand-in; `SparseDiskTests` and the end-to-end script use a real one.)
final class DiskTests: ShrugTestCase {
    static let open = ScreenState(locked: false, ours: true)
    static let locked = ScreenState(locked: true, ours: true)
    static let otherUser = ScreenState(locked: false, ours: false)

    /// A set-up, unlocked Mac with its disk attached, the screen it looks at and its Touch ID.
    func unlockedMac(files: [String] = ["project"]) throws -> (Mac, FakeScreen, FakeTouchID) {
        let screen = FakeScreen()
        let touch = FakeTouchID()
        let a = mac("a", touchID: touch, screen: screen.watch)
        _ = try a.engine.setup(storage, nil, password: password, deviceName: "a", create: true)
        a.engine.disk.settle()
        a.disk.files = files
        XCTAssertTrue(a.disk.isAttached)
        return (a, screen, touch)
    }

    /// Waits for something another thread does (a prompt is asked off the caller's thread).
    func eventually(_ what: String, _ condition: () -> Bool, file: StaticString = #filePath, line: UInt = #line) {
        let deadline = Date().addingTimeInterval(3)
        while !condition(), Date() < deadline { usleep(5000) }
        XCTAssertTrue(condition(), what, file: file, line: line)
    }

    /// Gives a prompt that shouldn't come the time to come anyway.
    func never(_ what: String, _ condition: () -> Bool, file: StaticString = #filePath, line: UInt = #line) {
        usleep(150_000)
        XCTAssertFalse(condition(), what, file: file, line: line)
    }

    // MARK: - Following the lock

    func testTheDiskIsMadeOnceAndFollowsTheLock() throws {
        let a = mac("a")
        _ = try a.engine.setup(storage, nil, password: password, deviceName: "a", create: true)
        a.engine.disk.settle()
        XCTAssertEqual(a.disk.asked, ["create", "attach"], "setting up makes the disk and attaches it")
        XCTAssertEqual(a.engine.status().disk?.open, true)

        a.engine.lockNow("test")
        XCTAssertFalse(a.disk.isAttached, "it's ejected by the time the lock returns")
        XCTAssertNil(a.engine.status().disk, "and a locked Shrug says nothing about it")

        try a.engine.unlock(password: password)
        a.engine.disk.settle()
        XCTAssertEqual(a.disk.asked, ["create", "attach", "eject", "attach"], "the same disk comes back")
    }

    func testAMacFromBeforeTheDiskGetsOneAtItsNextUnlock() throws {
        let a = mac("a")
        _ = try a.engine.setup(storage, nil, password: password, deviceName: "a", create: true)
        a.engine.lockNow("test")
        // The same Mac started again, with no disk image in ~/.shrug: as an older Shrug left it.
        let again = Mac(root, "a", clock: time, chip: a.chip)
        try again.engine.unlock(password: password)
        again.engine.disk.settle()
        XCTAssertEqual(again.disk.asked, ["create", "attach"])
    }

    func testTheSameKeyOpensItAfterARestartAndNoOtherMacsDoes() throws {
        let a = mac("a")
        _ = try a.engine.setup(storage, nil, password: password, deviceName: "a", create: true)
        a.engine.disk.settle()
        a.engine.lockNow("test")

        let again = Mac(root, "a", clock: time, chip: a.chip, disk: a.disk)
        try again.engine.unlock(password: password)
        again.engine.disk.settle()
        XCTAssertTrue(a.disk.isAttached, "the key comes from this Mac's local key, so it's the same every time")
        again.engine.lockNow("test")

        // Another Mac in the same vault has another local key: this disk stays shut for it.
        let b = mac("b", disk: a.disk)
        _ = try b.engine.setup(storage, nil, password: password, deviceName: "b", create: false)
        b.engine.disk.settle()
        XCTAssertFalse(a.disk.isAttached)
        XCTAssertNotNil(b.engine.status().disk?.problem)
    }

    func testALockDuringAnAttachStillEndsEjected() throws {
        let a = mac("a")
        _ = try a.engine.setup(storage, nil, password: password, deviceName: "a", create: true)
        a.engine.disk.settle()
        a.engine.lockNow("test")

        let gate = DispatchSemaphore(value: 0)
        a.disk.holdAttach = gate
        try a.engine.unlock(password: password)
        let locked = expectation(description: "locked")
        DispatchQueue.global().async {
            a.engine.lockNow("test")
            locked.fulfill()
        }
        usleep(50000)
        gate.signal() // the attach finishes after the lock began
        wait(for: [locked], timeout: 5)
        XCTAssertFalse(a.disk.isAttached)
        XCTAssertFalse(a.engine.isUnlocked)
    }

    func testADiskThatWontOpenSaysWhy() throws {
        let a = mac("a")
        a.disk.attachFails = ShrugError("no room")
        _ = try a.engine.setup(storage, nil, password: password, deviceName: "a", create: true)
        a.engine.disk.settle()
        XCTAssertTrue(a.engine.isUnlocked, "Shrug itself unlocks all the same")
        XCTAssertEqual(a.engine.status().disk?.problem, "not open: no room")

        a.disk.attachFails = nil
        a.engine.lockNow("test")
        try a.engine.unlock(password: password)
        a.engine.disk.settle()
        XCTAssertEqual(a.engine.status().disk?.open, true, "and tries again at the next unlock")
    }

    func testADiskThatWontEjectIsTriedAgain() throws {
        let (a, _, _) = try unlockedMac()
        a.disk.ejectFails = ShrugError("busy")
        a.engine.lockNow("test")
        XCTAssertTrue(a.disk.isAttached)
        XCTAssertFalse(a.engine.isUnlocked, "Shrug itself is locked")
        XCTAssertTrue(a.engine.status().disk?.problem?.hasPrefix("STILL OPEN") ?? false, "and says so, even locked")

        a.disk.ejectFails = nil
        a.engine.disk.retry() // every second
        a.engine.disk.settle()
        XCTAssertFalse(a.disk.isAttached)
        XCTAssertNil(a.engine.status().disk)
    }

    func testSpaceIsGivenBackWhenMostOfTheImageIsUnused() throws {
        let (a, _, _) = try unlockedMac()
        a.disk.usedBytes = 1 << 30
        a.disk.imageBytes = 2 << 30 // twice what its files take, but that's only 1 GiB to gain
        a.engine.lockNow("test")
        try a.engine.unlock(password: password)
        a.engine.disk.settle()
        XCTAssertFalse(a.disk.asked.contains("reclaim"))

        a.disk.imageBytes = 5 << 30
        a.engine.lockNow("test")
        try a.engine.unlock(password: password)
        a.engine.disk.settle()
        XCTAssertEqual(Array(a.disk.asked.suffix(3)), ["eject", "reclaim", "attach"], "before it's attached again")

        a.disk.usedBytes = 40 << 30
        a.disk.imageBytes = 60 << 30 // 20 GiB to gain, but 40 GiB of files to move for it
        a.engine.lockNow("test")
        try a.engine.unlock(password: password)
        a.engine.disk.settle()
        XCTAssertEqual(a.disk.asked.filter { $0 == "reclaim" }.count, 1)
    }

    // MARK: - Back at the screen

    func testLeavingWithFilesOnTheDiskAsksOnceWhenYoureBack() throws {
        let (a, screen, touch) = try unlockedMac()
        screen.show(DiskTests.locked)
        a.engine.screenLocked()
        XCTAssertFalse(a.engine.isUnlocked)
        XCTAssertFalse(a.disk.isAttached)

        a.engine.checkReopen()
        never("nothing is asked while the screen is locked") { !touch.prompts.isEmpty }

        screen.show(DiskTests.open)
        a.engine.checkReopen()
        eventually("one fingerprint brings Shrug and the disk back") { a.engine.isUnlocked }
        a.engine.disk.settle()
        XCTAssertTrue(a.disk.isAttached)
        XCTAssertEqual(touch.prompts, ["unlock and open ~/ShrugDisk again"])
    }

    func testAnEmptyDiskAsksNothing() throws {
        let (a, screen, touch) = try unlockedMac(files: [])
        screen.show(DiskTests.locked)
        a.engine.screenLocked()
        a.engine.checkReopen()
        screen.show(DiskTests.open)
        a.engine.checkReopen()
        a.engine.screenUnlocked()
        never("a Mac that doesn't use the disk is never asked") { !touch.prompts.isEmpty }
        XCTAssertFalse(a.engine.isUnlocked)
    }

    func testAskingForTheLockAsksNothingLater() throws {
        let (a, screen, touch) = try unlockedMac()
        a.engine.lockNow("locked from the menu")
        screen.show(DiskTests.locked)
        a.engine.checkReopen()
        screen.show(DiskTests.open)
        a.engine.checkReopen()
        a.engine.screenUnlocked()
        never("you locked it yourself") { !touch.prompts.isEmpty }

        // And it takes back a question that was waiting.
        try a.engine.unlock(password: password)
        a.engine.disk.settle()
        screen.show(DiskTests.locked)
        a.engine.screenLocked()
        a.engine.lockNow("locked from the command line")
        screen.show(DiskTests.open)
        a.engine.checkReopen()
        a.engine.screenUnlocked()
        never("locked on purpose after the screen locked") { !touch.prompts.isEmpty }
    }

    func testACancelledPromptStaysLockedAndIsntRepeated() throws {
        let (a, screen, touch) = try unlockedMac()
        screen.show(DiskTests.locked)
        a.engine.screenLocked()
        a.engine.checkReopen()
        touch.answering { throw TouchIDError.cancelled }
        screen.show(DiskTests.open)
        a.engine.checkReopen()
        eventually("asked once") { touch.prompts.count == 1 }
        eventually("and told why nothing opened") {
            a.engine.lock.lock()
            defer { a.engine.lock.unlock() }
            return a.engine.lastEventText?.hasPrefix("Stayed locked") ?? false
        }
        XCTAssertFalse(a.engine.isUnlocked)

        a.engine.checkReopen()
        a.engine.screenUnlocked()
        never("not asked again") { touch.prompts.count > 1 }
        XCTAssertFalse(a.disk.isAttached)
    }

    func testTheNoticeThatTheScreenUnlockedAsksAtOnce() throws {
        let (a, screen, touch) = try unlockedMac()
        screen.show(DiskTests.locked)
        a.engine.screenLocked()
        // No look at the screen in between: the notice alone is enough.
        a.engine.screenUnlocked()
        eventually("unlocked") { a.engine.isUnlocked }
        XCTAssertEqual(touch.prompts.count, 1)
    }

    func testAScreenThatNeverLookedLockedAsksNothingByItself() throws {
        let (a, _, touch) = try unlockedMac()
        // The notice that the screen locked came, but macOS never showed it as locked.
        a.engine.screenLocked()
        a.engine.checkReopen()
        a.engine.checkReopen()
        never("no telling whether you're there: no prompt behind the lock screen") { !touch.prompts.isEmpty }
    }

    func testAfterSleepItWaitsForTheLockScreenToGo() throws {
        let (a, screen, touch) = try unlockedMac()
        a.engine.lockNow("Mac went to sleep", away: .asleep)
        a.engine.checkReopen()
        never("asleep") { !touch.prompts.isEmpty }

        a.engine.woke()
        screen.show(DiskTests.locked)
        a.engine.checkReopen()
        time.advance(60)
        a.engine.checkReopen()
        never("the lock screen is up, however long") { !touch.prompts.isEmpty }

        screen.show(DiskTests.open)
        a.engine.checkReopen()
        eventually("unlocked") { a.engine.isUnlocked }
    }

    func testAMacThatWakesWithoutALockScreenAsksAMomentLater() throws {
        let (a, _, touch) = try unlockedMac()
        a.engine.lockNow("Mac went to sleep", away: .asleep)
        a.engine.woke()
        a.engine.checkReopen()
        never("not the instant it wakes: the lock screen may still be coming") { !touch.prompts.isEmpty }
        time.advance(a.engine.wakeGrace)
        a.engine.checkReopen()
        eventually("unlocked") { a.engine.isUnlocked }
    }

    func testComingBackFromAnotherUserAsksToo() throws {
        let (a, screen, touch) = try unlockedMac()
        a.engine.checkScreen()
        screen.show(DiskTests.otherUser)
        a.engine.checkScreen()
        XCTAssertFalse(a.engine.isUnlocked)
        a.engine.checkReopen()
        never("someone else is at the screen") { !touch.prompts.isEmpty }
        screen.show(DiskTests.open)
        a.engine.checkReopen()
        eventually("unlocked") { a.engine.isUnlocked }
    }

    func testUnlockingAnotherWayTakesTheQuestionBack() throws {
        let (a, screen, touch) = try unlockedMac()
        screen.show(DiskTests.locked)
        a.engine.screenLocked()
        try a.engine.unlock(password: password) // over SSH, say
        a.engine.disk.settle()
        a.engine.lockNow("test")
        screen.show(DiskTests.open)
        a.engine.checkReopen()
        a.engine.screenUnlocked()
        never("that question was answered by the unlock") { !touch.prompts.isEmpty }
    }

    func testWithoutTouchIDItAsksForThePassword() throws {
        let screen = FakeScreen()
        let a = mac("a", screen: screen.watch)
        _ = try a.engine.setup(storage, nil, password: password, deviceName: "a", create: true)
        a.engine.disk.settle()
        a.disk.files = ["project"]
        let asked = expectation(description: "asked")
        a.engine.askPassword = { [password] why, done in
            XCTAssertEqual(why, "~/ShrugDisk was open when you left")
            try? a.engine.unlock(password: password)
            done()
            asked.fulfill()
        }
        screen.show(DiskTests.locked)
        a.engine.screenLocked()
        a.engine.checkReopen()
        screen.show(DiskTests.open)
        a.engine.checkReopen()
        wait(for: [asked], timeout: 5)
        eventually("unlocked") { a.engine.isUnlocked }
    }

    func testOnATrustedNetworkTheDiskStaysWithShrug() throws {
        let screen = FakeScreen()
        let touch = FakeTouchID()
        let a = mac("a", touchID: touch, screen: screen.watch, network: NetworkWatch { "a4:5e:60:01:02:03" })
        _ = try a.engine.setup(storage, nil, password: password, deviceName: "a", create: true)
        a.engine.disk.settle()
        a.disk.files = ["project"]
        _ = try a.engine.trust(name: "home", password: password)

        screen.show(DiskTests.locked)
        a.engine.screenLocked()
        XCTAssertTrue(a.engine.isUnlocked)
        XCTAssertTrue(a.disk.isAttached, "Shrug stays unlocked here, and so does the disk")

        a.engine.lockNow("Mac went to sleep", away: .asleep)
        XCTAssertFalse(a.disk.isAttached, "sleep locks everywhere")
    }
}

/// The real disk: an encrypted image made, attached and ejected by macOS, in a throwaway folder.
final class SparseDiskTests: XCTestCase {
    func testARealDiskIsMadeAttachedAndEjected() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("shrug-disk-\(UUID().uuidString)")
        let paths = ShrugPaths(state: root.appendingPathComponent(".shrug"), mount: root.appendingPathComponent("Shrug"),
                               home: root, socket: "")
        try FileManager.default.createDirectory(at: paths.state, withIntermediateDirectories: true)
        let disk = SparseDisk(paths: paths)
        defer {
            try? disk.eject()
            try? FileManager.default.removeItem(at: root)
        }
        func mode(_ url: URL) -> Int {
            (try? FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int) ?? -1
        }
        let note = paths.disk.appendingPathComponent("note.txt")
        let secret = "only on the disk \(UUID().uuidString)"

        XCTAssertFalse(disk.exists)
        try disk.create(key: "the right key")
        XCTAssertTrue(disk.exists)
        XCTAssertFalse(disk.isAttached)

        try disk.attach(key: "the right key")
        XCTAssertTrue(disk.isAttached)
        XCTAssertEqual(mode(paths.disk), 0o700, "only this user gets in")
        XCTAssertFalse(disk.holdsFiles, "what macOS puts on a new disk doesn't count")
        try Data(secret.utf8).write(to: note)
        XCTAssertTrue(disk.holdsFiles)
        XCTAssertGreaterThan(disk.used ?? 0, 0)

        // Ejected with a file open: the program holding it loses it.
        let fd = open(note.path, O_RDONLY)
        XCTAssertGreaterThanOrEqual(fd, 0)
        try disk.eject()
        XCTAssertFalse(disk.isAttached)
        var byte: UInt8 = 0
        XCTAssertLessThan(pread(fd, &byte, 1, 0), 1, "a file that was open can't be read any more")
        close(fd)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: paths.disk.path), [], "the folder is empty…")
        XCTAssertEqual(mode(paths.disk), 0o500, "…and nothing can be put in it")
        XCTAssertThrowsError(try Data("x".utf8).write(to: note))

        // Nothing readable in the image.
        let bands = paths.diskImage.appendingPathComponent("bands")
        for name in try FileManager.default.contentsOfDirectory(atPath: bands.path) {
            let band = try Data(contentsOf: bands.appendingPathComponent(name))
            XCTAssertNil(band.range(of: Data(secret.utf8)))
            XCTAssertNil(band.range(of: Data("note.txt".utf8)))
        }

        XCTAssertThrowsError(try disk.attach(key: "another key"))
        XCTAssertFalse(disk.isAttached)

        // Giving space back leaves the files and the disk's size as they were.
        try disk.reclaim(key: "the right key")
        try disk.attach(key: "the right key")
        XCTAssertEqual(try String(contentsOf: note, encoding: .utf8), secret)
        var s = statfs()
        XCTAssertEqual(statfs(paths.disk.path, &s), 0)
        XCTAssertGreaterThan(UInt64(s.f_blocks) * UInt64(s.f_bsize), 15 << 30, "as large as this Mac's disk, not the minimum")
        try disk.eject()
    }
}
