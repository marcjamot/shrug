import XCTest
@testable import ShrugCore
@testable import ShrugDaemon

/// Crashes, and many things happening at once.
final class RobustnessTests: ShrugTestCase {
    func testChangesSurviveACrash() throws {
        let (a, b) = try twoMacs()
        try a.write("synced/f", Data("one".utf8))
        a.sync()
        b.sync()
        try a.write("synced/f", Data("two, then the Mac crashed".utf8))
        try a.write("synced/new", Data("made just before".utf8))

        // No lock and no save: a new engine starts from whatever reached the disk.
        let restarted = Mac(root, "a", clock: time, chip: a.chip)
        try restarted.engine.unlock(password: password)
        XCTAssertEqual(try restarted.text("synced/f"), "two, then the Mac crashed")
        XCTAssertEqual(try restarted.text("synced/new"), "made just before")
        XCTAssertEqual(restarted.engine.status().waiting, 2, "both changes are still due for upload")
        restarted.sync()
        b.sync()
        XCTAssertEqual(try b.text("synced/f"), "two, then the Mac crashed")
        XCTAssertEqual(try b.text("synced/new"), "made just before")
    }

    func testLockingWhileProgramsWriteAndSync() throws {
        let (a, b) = try twoMacs()
        try a.write("synced/f", Data("start".utf8))
        let done = NSLock()
        var finished = false
        func running() -> Bool {
            done.lock()
            defer { done.unlock() }
            return !finished
        }
        let group = DispatchGroup()
        DispatchQueue.global().async(group: group) {
            var n = 0
            while running() {
                try? a.write("synced/f", Data("version \(n)".utf8))
                n += 1
            }
        }
        DispatchQueue.global().async(group: group) {
            while running() { a.sync() }
        }
        for _ in 0..<20 {
            a.engine.lockNow("test")
            try a.engine.unlock(password: password)
        }
        done.lock()
        finished = true
        done.unlock()
        group.wait()

        // Whatever the last write that landed was, it reaches B: none was kept and forgotten.
        a.sync()
        b.sync()
        XCTAssertEqual(a.engine.status().waiting, 0)
        XCTAssertEqual(try b.text("synced/f"), try a.text("synced/f"))
        try a.write("synced/f", Data("final".utf8))
        a.sync()
        b.sync()
        XCTAssertEqual(try b.text("synced/f"), "final")
        XCTAssertNil(a.engine.status().problem)
    }

    /// The steps of a program's write (open the file, record the edit, change the content) with
    /// the lock landing between the first two: the edit must be refused, not written and forgotten.
    func testAWriteThatMeetsTheLockIsRefused() throws {
        let (a, b) = try twoMacs()
        try a.write("synced/token", Data("v1".utf8))
        a.sync()
        b.sync()
        let store = a.store
        _ = try store.open("synced/token", writable: true)
        a.engine.lockNow("screen locked")
        XCTAssertFalse(store.willChange("synced/token"), "too late to record it, so the write doesn't happen")
        XCTAssertThrowsError(try store.createFile("synced/new"))

        try a.engine.unlock(password: password)
        XCTAssertEqual(try a.text("synced/token"), "v1")
        XCTAssertEqual(a.engine.status().waiting, 0)
    }

    /// …and with the lock landing just after the edit was recorded: the content still changes,
    /// and that change uploads after the next unlock.
    func testAWriteRecordedJustBeforeTheLockStillUploads() throws {
        let (a, b) = try twoMacs()
        try a.write("synced/token", Data("v1".utf8))
        a.sync()
        b.sync()
        let store = a.store
        let f = try store.open("synced/token", writable: true)
        XCTAssertTrue(store.willChange("synced/token"))
        a.engine.lockNow("screen locked")
        try f.truncate(to: 0)
        try f.write(offset: 0, data: Data("v2, saved as the screen locked".utf8))

        try a.engine.unlock(password: password)
        XCTAssertEqual(try a.text("synced/token"), "v2, saved as the screen locked")
        XCTAssertEqual(a.engine.status().waiting, 1, "still due for upload")
        a.sync()
        b.sync()
        XCTAssertEqual(try b.text("synced/token"), "v2, saved as the screen locked")
    }

    func testTwoMacsSyncingAtOnceKeepTheNewestEdit() throws {
        let (a, b) = try twoMacs()
        try a.write("synced/f", Data("start".utf8))
        a.sync()
        b.sync()
        DispatchQueue.concurrentPerform(iterations: 4) { i in
            let m = i % 2 == 0 ? a : b
            for n in 0..<15 {
                if i < 2 { try? m.write("synced/f", Data("\(i)-\(n)".utf8)) }
                m.sync()
            }
        }
        try a.write("synced/f", Data("A, older".utf8))
        try b.write("synced/f", Data("B, newest".utf8))
        DispatchQueue.concurrentPerform(iterations: 6) { i in (i % 2 == 0 ? a : b).sync() }
        for _ in 0..<3 {
            a.sync()
            b.sync()
        }
        XCTAssertEqual(try a.text("synced/f"), "B, newest")
        XCTAssertEqual(try b.text("synced/f"), "B, newest")
        XCTAssertEqual(a.engine.status().waiting + b.engine.status().waiting, 0)
        XCTAssertNil(a.engine.status().problem)
        XCTAssertNil(b.engine.status().problem)
    }
}
