import XCTest
@testable import ShrugCore
@testable import ShrugDaemon

/// Stands in for Touch ID: the test decides what each prompt answers.
final class FakeTouchID: TouchIDKeyStore, @unchecked Sendable {
    private let lock = NSLock()
    private var secret: Data?
    private var reasons: [String] = []
    private var answer: () throws -> Void = {}
    private var hold: DispatchSemaphore?

    /// What every prompt from now on does: return normally (a fingerprint) or throw.
    func answering(_ body: @escaping () throws -> Void) {
        lock.lock()
        answer = body
        lock.unlock()
    }

    /// Keeps each prompt open until `gate` is signalled.
    func holding(_ gate: DispatchSemaphore) {
        lock.lock()
        hold = gate
        lock.unlock()
    }

    var prompts: [String] {
        lock.lock()
        defer { lock.unlock() }
        return reasons
    }

    var isEnrolled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return secret != nil
    }

    func enroll(secret: Data) throws {
        lock.lock()
        self.secret = secret
        lock.unlock()
    }

    func unlock(reason: String, timeout: TimeInterval) throws -> Data {
        lock.lock()
        reasons.append(reason)
        let (answer, hold, secret) = (self.answer, self.hold, self.secret)
        lock.unlock()
        _ = hold?.wait(timeout: .now() + 5)
        try answer()
        guard let secret else { throw TouchIDError.invalidated }
        return secret
    }

    func remove() {
        lock.lock()
        secret = nil
        lock.unlock()
    }
}

/// Unlocking takes a fingerprint or the Shrug password, never the Mac's password.
final class TouchIDTests: ShrugTestCase {
    /// A set-up Mac (so it has a Touch ID copy) with a file, locked.
    func lockedMac() throws -> (Mac, FakeTouchID) {
        let touch = FakeTouchID()
        let a = mac("a", touchID: touch)
        _ = try a.engine.setup(storage, nil, password: password, deviceName: "a", create: true)
        try a.write("synced/key", Data("secret".utf8))
        a.engine.lockNow("test")
        return (a, touch)
    }

    func isPasswordNeeded(_ error: Error) -> Bool { error is PasswordNeeded }

    func testAFingerprintUnlocks() throws {
        let (a, touch) = try lockedMac()
        XCTAssertTrue(touch.isEnrolled, "setting up with the password made the Touch ID copy")
        try a.engine.unlock(password: nil)
        XCTAssertTrue(a.engine.isUnlocked)
        XCTAssertEqual(touch.prompts, ["unlock your vault"])
        XCTAssertEqual(try a.text("synced/key"), "secret")
    }

    func testChoosingTheShrugPasswordAsksForIt() throws {
        let (a, touch) = try lockedMac()
        touch.answering { throw TouchIDError.usePassword("you chose the Shrug password") }
        XCTAssertThrowsError(try a.engine.unlock(password: nil)) { XCTAssertTrue(self.isPasswordNeeded($0)) }
        XCTAssertThrowsError(try a.engine.requireUnlocked("unlock to add a link")) { XCTAssertTrue(self.isPasswordNeeded($0)) }
        XCTAssertEqual(a.engine.handle(IPCRequest("remove", ["path": "/x"])).code, "password-needed",
                       "any command tells the command line to ask for the Shrug password")
        XCTAssertTrue(touch.isEnrolled, "the copy still works next time")
        try a.engine.unlock(password: password)
        XCTAssertTrue(a.engine.isUnlocked)
    }

    func testChangedFingerprintsNeedThePasswordOnceThenTouchIDWorksAgain() throws {
        let (a, touch) = try lockedMac()
        touch.answering { throw TouchIDError.invalidated }
        XCTAssertThrowsError(try a.engine.unlock(password: nil)) { XCTAssertTrue(self.isPasswordNeeded($0)) }
        XCTAssertFalse(touch.isEnrolled, "the copy that can't open is removed")
        try a.engine.unlock(password: password)
        XCTAssertTrue(touch.isEnrolled, "the password made a new one")
        a.engine.lockNow("test")
        touch.answering {}
        try a.engine.unlock(password: nil)
        XCTAssertTrue(a.engine.isUnlocked)
    }

    func testACancelledPromptStaysLockedAndDoesntAskAgainRightAway() throws {
        let (a, touch) = try lockedMac()
        touch.answering { throw TouchIDError.cancelled }
        guard case .failure(.acces) = a.fs.lookup(3, "key") else { return XCTFail("refused") }
        guard case .failure(.acces) = a.fs.lookup(3, "key") else { return XCTFail("refused") }
        XCTAssertEqual(touch.prompts.count, 1, "no second prompt right after a refusal")
        XCTAssertTrue(touch.isEnrolled, "cancelling isn't a reason to drop the copy")
        time.advance(4)
        touch.answering {}
        guard case .success = a.fs.lookup(3, "key") else { return XCTFail("unlocks once asked again") }
        XCTAssertEqual(touch.prompts.count, 2)
    }

    func testProgramsWaitForOnePromptInsteadOfEachOpeningOne() throws {
        let (a, touch) = try lockedMac()
        let gate = DispatchSemaphore(value: 0)
        touch.holding(gate)
        let group = DispatchGroup()
        let results = NSLock()
        var unlocked = 0
        for _ in 0..<5 {
            DispatchQueue.global().async(group: group) {
                if case .success = a.fs.lookup(3, "key") {
                    results.lock()
                    unlocked += 1
                    results.unlock()
                }
            }
        }
        let shown = Date().addingTimeInterval(5)
        while touch.prompts.isEmpty && Date() < shown { usleep(1000) }
        usleep(100_000) // the others are waiting behind it by now
        gate.signal()
        group.wait()
        XCTAssertEqual(touch.prompts.count, 1)
        XCTAssertEqual(unlocked, 5)
    }

    func testWithoutAFingerprintAProgramWaitsForTheShrugPassword() throws {
        let (a, touch) = try lockedMac()
        touch.answering { throw TouchIDError.usePassword("no fingerprint in reach") }
        var asked: [String] = []
        a.engine.askPassword = { [password] why, done in
            asked.append(why)
            DispatchQueue.global().async {
                try? a.engine.unlock(password: password) // as the menu bar app does with your answer
                done()
            }
        }
        guard case .success = a.fs.lookup(3, "key") else { return XCTFail("unlocked while the program waited") }
        XCTAssertEqual(asked, ["a program is opening \(a.paths.contract(a.paths.mount))/synced/key"])
        XCTAssertEqual(touch.prompts.count, 1, "Touch ID was tried first")
    }

    func testCancellingThePasswordDialogStaysLocked() throws {
        let (a, touch) = try lockedMac()
        touch.remove() // no Touch ID copy at all: straight to the password
        a.engine.askPassword = { _, done in done() }
        guard case .failure(.acces) = a.fs.lookup(3, "key") else { return XCTFail("refused") }
        XCTAssertFalse(a.engine.isUnlocked)
        XCTAssertEqual(touch.prompts, [])
    }

    func testPromptsShowFileNamesSafely() throws {
        let (a, touch) = try lockedMac()
        touch.answering { throw TouchIDError.cancelled }
        _ = a.fs.lookup(3, "report\u{202E}fdp.exe\nClick Allow to install the update")
        let reason = try XCTUnwrap(touch.prompts.first)
        XCTAssertFalse(reason.unicodeScalars.contains { [.control, .format].contains($0.properties.generalCategory) },
                       "no line breaks or right-to-left overrides from a program's file name")
        XCTAssertTrue(reason.hasSuffix("report?fdp.exe?Click Allow to install the update"))
        let long = Engine.shown("~/Shrug/synced/" + String(repeating: "a", count: 300) + "/id_ed25519")
        XCTAssertEqual(long.count, 80)
        XCTAssertTrue(long.hasPrefix("~/Shrug/synced/") && long.hasSuffix("/id_ed25519") && long.contains("…"))
    }
}
