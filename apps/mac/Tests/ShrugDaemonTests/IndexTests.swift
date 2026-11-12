import XCTest
@testable import ShrugCore
@testable import ShrugDaemon
import ShrugNFS

/// How this Mac's index of ~/Shrug is saved (a journal of changes), found again after a crash,
/// and looked things up in.
final class IndexTests: ShrugTestCase {
    func oneMac() throws -> Mac {
        let a = mac("a")
        _ = try a.engine.setup(storage, nil, password: password, deviceName: "a", create: true)
        return a
    }

    /// The same Mac after a crash: no lock and no save, so only what reached the disk is there.
    func restarted(_ m: Mac) throws -> Mac {
        let again = Mac(root, "a", clock: time, chip: m.chip)
        try again.engine.unlock(password: password)
        return again
    }

    func size(_ url: URL) -> Int {
        (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int) ?? -1
    }

    // MARK: - The journal

    func testAChangeAddsToTheJournalAndLeavesTheIndexAlone() throws {
        let a = try oneMac()
        let index = try Data(contentsOf: a.paths.indexFile)
        var journal = size(a.paths.journalFile)
        for i in 0..<50 {
            try a.write("local/file\(i)", Data("content \(i)".utf8))
            let now = size(a.paths.journalFile)
            XCTAssertGreaterThan(now, journal, "each new file is saved before it returns")
            XCTAssertEqual((now - journal - 4) % SavedIndex.padding, 28, "in a record whose length says little")
            journal = now
        }
        XCTAssertEqual(try Data(contentsOf: a.paths.indexFile), index, "the index itself isn't written again")

        let b = try restarted(a)
        XCTAssertEqual(try b.names("local").count, 50)
        XCTAssertEqual(try b.text("local/file49"), "content 49")
    }

    func testEveryKindOfChangeSurvivesACrash() throws {
        let a = try oneMac()
        try a.mkdirs("synced/project/src")
        try a.write("synced/project/src/main.c", Data("int main".utf8))
        try a.write("synced/project/notes.txt", Data("notes".utf8))
        try a.write("local/key", Data("local".utf8))
        a.sync()
        try a.rename("synced/project/src", "synced/project/source")
        try a.remove("synced/project/notes.txt")
        try a.rename("local/key", "local/key2")
        try a.write("synced/project/source/main.c", Data("int main(void)".utf8))

        let b = try restarted(a)
        XCTAssertEqual(try b.names("synced/project"), ["source"])
        XCTAssertEqual(try b.text("synced/project/source/main.c"), "int main(void)")
        XCTAssertEqual(try b.text("local/key2"), "local")
        XCTAssertEqual(try b.names("local"), ["key2"])
        XCTAssertEqual(b.store.ignoredJournalBytes, 0)
        b.sync()
        XCTAssertEqual(b.engine.status().waiting, 0)
        XCTAssertNil(b.engine.status().problem)
    }

    func testAJournalCutShortEndsBeforeTheDamage() throws {
        let a = try oneMac()
        try a.write("local/one", Data("1".utf8))
        try a.write("local/two", Data("2".utf8))
        let whole = try Data(contentsOf: a.paths.journalFile)
        try a.write("local/three", Data("3".utf8))

        // A crash halfway through saving the last change.
        let cut = try Data(contentsOf: a.paths.journalFile)
        try cut.prefix(whole.count + (cut.count - whole.count) / 2).write(to: a.paths.journalFile)
        let b = try restarted(a)
        XCTAssertEqual(try b.names("local"), ["one", "two"], "what was saved whole is there")
        XCTAssertGreaterThan(b.store.ignoredJournalBytes, 0)

        // The next change follows the last good record, not the damage.
        try b.write("local/four", Data("4".utf8))
        let c = try restarted(b)
        XCTAssertEqual(try c.names("local"), ["four", "one", "two"])
        XCTAssertEqual(c.store.ignoredJournalBytes, 0)

        // Bytes that were never a record.
        let handle = try FileHandle(forWritingTo: c.paths.journalFile)
        try handle.seekToEnd()
        try handle.write(contentsOf: Data(repeating: 0, count: 500))
        try handle.close()
        let d = try restarted(c)
        XCTAssertEqual(try d.names("local"), ["four", "one", "two"])
        XCTAssertEqual(d.store.ignoredJournalBytes, 500)
    }

    func testALongJournalIsFoldedIntoTheIndex() throws {
        let a = try oneMac()
        a.store.shortJournal = 0
        for i in 0..<20 { try a.write("local/file\(i)", Data("content \(i)".utf8)) }
        try a.write("local/._file0", bytes(100))
        let index = size(a.paths.indexFile)
        a.store.saveIfNeeded()
        XCTAssertEqual(size(a.paths.journalFile), SavedIndex.headerSize, "a new journal starts")
        XCTAssertGreaterThan(size(a.paths.indexFile), index, "from an index that has it all")

        try a.remove("local/file0")
        let b = try restarted(a)
        XCTAssertEqual(try b.names("local").count, 19, "and changes go on from there")
        XCTAssertEqual(try b.text("local/file19"), "content 19")
    }

    /// A crash after the index was written whole, before its new journal started: the journal
    /// still there is the old one, whose changes the index already has.
    func testAJournalFromAnEarlierIndexIsNotAppliedAgain() throws {
        let a = try oneMac()
        a.store.shortJournal = 0
        try a.write("local/keep", Data("k".utf8))
        try a.write("local/gone", Data("g".utf8))
        let earlier = try Data(contentsOf: a.paths.journalFile)
        try a.remove("local/gone")
        a.store.saveIfNeeded()
        XCTAssertEqual(size(a.paths.journalFile), SavedIndex.headerSize)

        try earlier.write(to: a.paths.journalFile)
        let b = try restarted(a)
        XCTAssertEqual(try b.names("local"), ["keep"], "the file deleted since doesn't come back")
        XCTAssertGreaterThan(b.store.ignoredJournalBytes, 0)
        try b.write("local/new", Data("n".utf8))
        XCTAssertEqual(try restarted(b).names("local"), ["keep", "new"])
    }

    func testLockingSavesWhatWasStillWaiting() throws {
        let a = try oneMac()
        try a.write("local/f", Data("x".utf8))
        let id = try a.lookup("local/f")
        var attrs = NFSSetAttrs()
        attrs.mtime = .client(NFSTime(sec: 1_000_000, nsec: 0))
        try a.fs.setattr(id, attrs, a.ctx).get() // times are saved a moment later, not at once
        a.engine.lockNow("test")
        try a.engine.unlock(password: password)
        XCTAssertEqual(try a.fs.getattr(a.lookup("local/f")).get().mtime.sec, 1_000_000)
    }

    func testAProgramsSyncSavesAtOnce() throws {
        let a = try oneMac()
        try a.write("synced/f", Data("x".utf8))
        let id = try a.lookup("synced/f")
        var attrs = NFSSetAttrs()
        attrs.mtime = .client(NFSTime(sec: 1_000_000, nsec: 0))
        try a.fs.setattr(id, attrs, a.ctx).get()
        try a.fs.commit(id, a.ctx).get()
        try a.fs.commit(a.lookup("synced"), a.ctx).get()

        let b = try restarted(a)
        XCTAssertEqual(try b.fs.getattr(b.lookup("synced/f")).get().mtime.sec, 1_000_000)
        XCTAssertEqual(try b.text("synced/f"), "x")

        // A remote/ file that went up has no copy here to sync.
        try b.write("remote/r", Data("r".utf8))
        b.sync()
        try b.fs.commit(b.lookup("remote/r"), b.ctx).get()

        // Locking saved everything; afterwards nothing is asked of a locked Shrug.
        let file = try b.lookup("synced/f")
        b.engine.lockNow("test")
        guard case .failure(.stale) = b.fs.commit(file, b.ctx) else { return XCTFail("no sync while locked") }
    }

    // MARK: - Names

    func testFoldersExistByWhatIsInThem() throws {
        let a = try oneMac()
        // As a download leaves it: a file deep down, and no entry for the folders above.
        try a.store.createFile("synced/a/b/c.txt")
        XCTAssertEqual(try a.names("synced"), ["a"])
        XCTAssertEqual(try a.names("synced/a"), ["b"])
        XCTAssertEqual(try a.names("synced/a/b"), ["c.txt"])
        XCTAssertTrue(a.store.isDirectory("synced/a/b"))
        XCTAssertFalse(a.store.isDirectory("synced/a/b/c.txt"))
        XCTAssertFalse(a.store.exists("synced/a/x"))

        try a.store.createFile("synced/a/d.txt")
        try a.remove("synced/a/b/c.txt")
        XCTAssertEqual(try a.names("synced/a"), ["d.txt"], "an emptied folder that was never made goes")
        try a.remove("synced/a/d.txt")
        XCTAssertEqual(try a.names("synced"), [])

        // A folder that was made stays when it empties, and when it loses its own entry while full.
        try a.mkdirs("synced/made")
        try a.write("synced/made/f", Data("x".utf8))
        a.store.drop("synced/made")
        XCTAssertEqual(try a.names("synced"), ["made"])
        try a.remove("synced/made/f")
        XCTAssertEqual(try a.names("synced"), [])

        let b = try restarted(a)
        XCTAssertEqual(try b.names("synced"), [])
    }

    /// The system keeps a folder's listing until the folder's time moves, so the time has to
    /// move with the names, whoever changes them, and with every lock and unlock.
    func testAFoldersTimeMovesWhenItsNamesChange() throws {
        let a = try oneMac()
        try a.mkdirs("synced/docs")
        func time(_ path: String) throws -> String {
            let t = try a.fs.getattr(a.lookup(path)).get().mtime
            return "\(t.sec).\(t.nsec)"
        }
        var docs = [try time("synced/docs")]
        var top = [try time("synced")]

        try a.write("synced/docs/a.txt", Data("a".utf8)) // a program
        docs.append(try time("synced/docs"))
        try a.store.createFile("synced/docs/b.txt") // Shrug itself, as a download does
        docs.append(try time("synced/docs"))
        try a.rename("synced/docs/a.txt", "synced/docs/c.txt")
        docs.append(try time("synced/docs"))
        try a.remove("synced/docs/b.txt")
        docs.append(try time("synced/docs"))
        XCTAssertEqual(Set(docs).count, docs.count, "a different time after each change: \(docs)")
        XCTAssertEqual(try time("synced"), top[0], "the folder above lists the same names as before")

        // A time set outright, as tar does after filling a folder, stays until the names change again.
        var given = NFSSetAttrs()
        given.mtime = .client(NFSTime(sec: 1_000_000_000, nsec: 0))
        try a.fs.setattr(a.lookup("synced/docs"), given, a.ctx).get()
        XCTAssertTrue(try time("synced/docs").hasPrefix("1000000000."))
        try a.write("synced/docs/d.txt", Data("d".utf8))
        XCTAssertFalse(try time("synced/docs").hasPrefix("1000000000."))

        try a.store.createFile("synced/new.txt")
        top.append(try time("synced"))
        a.engine.lockNow("test")
        top.append(try time("synced"))
        try a.engine.unlock(password: password)
        top.append(try time("synced"))
        XCTAssertEqual(Set(top).count, top.count, "and after a lock and an unlock: \(top)")
    }

    /// The name lists against the slow way of finding the same answer, after a few hundred
    /// changes of every kind.
    func testNameListsAlwaysMatchTheEntries() throws {
        let a = try oneMac()
        let store = a.store
        var seed: UInt64 = 42
        func random(_ n: Int) -> Int {
            seed = seed &* 6364136223846793005 &+ 1442695040888963407
            return Int((seed >> 33) % UInt64(n))
        }
        func path() -> String {
            var p = ["local", "synced"][random(2)]
            for _ in 0...random(3) { p += "/" + ["a", "b", "c", "._d"][random(4)] }
            return p
        }
        func check(_ step: Int) {
            let all = store.all().filter { $0.1.kind != .deleted }
            // Unsaved files aren't listed, and don't make the folders above them exist.
            let live = all.filter { !$0.1.unsaved }.map(\.0)
            var folders: Set<String> = ["local", "synced"]
            for p in live {
                var dir = Store.parent(p)
                while !dir.isEmpty {
                    folders.insert(dir)
                    dir = Store.parent(dir)
                }
            }
            for dir in folders {
                let expected = Set(live.filter { $0.hasPrefix(dir + "/") }.map {
                    String($0.dropFirst(dir.count + 1).split(separator: "/")[0])
                })
                XCTAssertEqual(Set(store.children(dir)), expected, "step \(step): \(dir)")
            }
            for p in ["local", "local/a", "synced/b/c", "synced/a/b/c/a", "local/._d"] {
                let folder = store.entry(p).map { $0.kind == .dir } ?? (p == "local" || live.contains { $0.hasPrefix(p + "/") })
                XCTAssertEqual(store.isDirectory(p), folder, "step \(step): \(p)")
                // Everything at and below it, with the unsaved files of whatever is there.
                let below = all.filter { path, e in
                    (path == p || path.hasPrefix(p + "/"))
                        && (!e.unsaved || path == p || Store.parent(path) == p || store.exists(Store.parent(path)))
                }
                XCTAssertEqual(Set(store.tree(p).map(\.0)), Set(below.map(\.0)), "step \(step): \(p)")
            }
            XCTAssertEqual(store.pending().map(\.0), store.all().filter { $0.1.dirty }.map(\.0).sorted(), "step \(step)")
        }
        for step in 0..<400 {
            let p = path()
            switch random(6) {
            case 0, 1: if !store.exists(p) && store.entry(Store.parent(p))?.kind != .file { try store.createFile(p) }
            case 2: if !store.exists(p) && store.entry(Store.parent(p))?.kind != .file { store.mkdir(p) }
            case 3: store.remove(p)
            case 4:
                let to = path()
                if store.exists(p), !store.exists(to), Store.fileClass(p) == Store.fileClass(to), !to.hasPrefix(p + "/"),
                   store.entry(Store.parent(to))?.kind != .file, store.canRename(p, to) {
                    try store.rename(p, to)
                }
            default: store.drop(p)
            }
            check(step)
        }

        // The same lists come back from the journal.
        store.save()
        let before = Dictionary(uniqueKeysWithValues: ["local", "synced", "synced/a", "local/b"].map { ($0, store.children($0)) })
        let b = try restarted(a)
        for (dir, names) in before {
            XCTAssertEqual(b.store.children(dir), names.filter { n in
                // What was only in memory is gone, and so are folders that held nothing else.
                b.store.exists(dir + "/" + n)
            }, dir)
        }
    }

    func testManySmallFilesStayQuick() throws {
        let a = try oneMac()
        // A few thousand files already there: what each change costs must not depend on them.
        for i in 0..<3000 {
            a.store.set("synced/old/dir\(i % 50)/file\(i).txt", Entry(kind: .file, at: time.clock.nowMs))
        }
        a.store.save()
        let index = try Data(contentsOf: a.paths.indexFile)

        let start = Date()
        for i in 0..<500 {
            let dir = "local/project/mod\(i % 20)"
            if i < 20 { try a.mkdirs(dir) }
            try a.write("\(dir)/file\(i).c", Data("int f\(i)(void) { return \(i); }\n".utf8))
            try a.write("\(dir)/._file\(i).c", bytes(4096)) // as macOS adds for extended attributes
            guard case .failure(.noent) = a.fs.lookup(try a.lookup(dir), "missing\(i)") else { return XCTFail() }
        }
        XCTAssertEqual(try a.names("local/project/mod7").count, 25, "the files, without what macOS added")
        for i in 0..<500 { XCTAssertEqual(try a.fs.getattr(a.lookup("synced/old/dir\(i % 50)")).get().type, .directory) }
        let elapsed = Date().timeIntervalSince(start)
        // A hundredth of what rewriting the index for every change took.
        XCTAssertLessThan(elapsed, 5, "1,000 new files among 3,000")
        XCTAssertEqual(try Data(contentsOf: a.paths.indexFile), index)
    }

    // MARK: - ._ files

    func testAppleDoubleFilesLastUntilLock() throws {
        let (a, b) = try twoMacs()
        try a.mkdirs("synced/docs")
        try a.write("synced/docs/note.txt", Data("a note".utf8))
        try a.mkdirs("local/tmp")
        let journal = size(a.paths.journalFile)
        try a.write("synced/docs/._note.txt", bytes(4096))
        try a.write("remote/._r", bytes(70_000))
        try a.write("local/tmp/._junk", bytes(10))
        XCTAssertEqual(size(a.paths.journalFile), journal, "they cost the index nothing")
        XCTAssertEqual(try a.read("synced/docs/._note.txt"), bytes(4096), "macOS finds them by name")
        XCTAssertEqual(try a.read("remote/._r"), bytes(70_000))
        XCTAssertEqual(try a.names("synced/docs"), ["note.txt"], "but a listing shows the files you put there")
        XCTAssertEqual(try a.names("remote"), [])
        XCTAssertEqual(a.engine.status().waiting, 2, "the folder and the note")
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: a.paths.scratchStore.path).count, 3)

        // They follow their file, and their folder.
        try a.rename("synced/docs/._note.txt", "synced/docs/._memo.txt")
        try a.rename("synced/docs", "synced/papers")
        XCTAssertEqual(try a.read("synced/papers/._memo.txt"), bytes(4096))
        // But can't turn into a file Shrug keeps: programs copy instead, as between folders.
        let papers = try a.lookup("synced/papers")
        guard case .failure(.xdev) = a.fs.rename(papers, "._memo.txt", papers, "memo.txt", a.ctx) else {
            return XCTFail("an unsaved file stays unsaved")
        }
        // A folder holding nothing else is empty, and they go when it does.
        try a.fs.rmdir(a.lookup("local"), "tmp", a.ctx).get()
        XCTAssertEqual(try a.names("local"), [])
        try a.mkdirs("local/tmp")
        guard case .failure(.noent) = a.fs.lookup(try a.lookup("local/tmp"), "._junk") else {
            return XCTFail("a new folder of the same name starts without them")
        }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: a.paths.scratchStore.path).count, 2)

        a.sync()
        b.sync()
        XCTAssertEqual(try b.names("synced/papers"), ["note.txt"], "they never reach the bucket")
        XCTAssertEqual(a.engine.status().waiting, 0)

        a.engine.lockNow("test")
        XCTAssertFalse(FileManager.default.fileExists(atPath: a.paths.scratchStore.path), "locking deletes them")
        try a.engine.unlock(password: password)
        XCTAssertEqual(try a.names("synced/papers"), ["note.txt"])
        XCTAssertEqual(try a.names("remote"), [])
        XCTAssertEqual(try a.text("synced/papers/note.txt"), "a note")
    }

    // MARK: - Limits

    func testFilesCanBeLargerThanOneGigabyte() throws {
        let a = try oneMac()
        XCTAssertGreaterThan(a.fs.maxFileSize, 1 << 40)
        let size: Int64 = 3 << 30
        let h = ObjectHeader(path: "synced/big", kind: .file, editedAt: time.clock.nowMs, mtime: time.clock.nowMs,
                             size: size, mode: 0o600, fileID: nil)
        XCTAssertTrue(h.fitsSize(of: StoredObject(key: "f/x", size: ObjectFormat.objectSize(plainSize: size), version: "1")))
        XCTAssertFalse(h.fitsSize(of: StoredObject(key: "f/x", size: ObjectFormat.objectSize(plainSize: size) + 1, version: "1")))
    }

    func testAWriteThatWouldFillTheDiskIsRefused() throws {
        let a = try oneMac()
        try a.write("local/f", Data("start".utf8))
        let id = try a.lookup("local/f")
        a.fs.reserve = .max / 2 // as if the disk were all but full
        guard case .failure(.nospc) = a.fs.write(id, offset: 5, data: Data("more".utf8), a.ctx) else {
            return XCTFail("a file can't grow into the reserve")
        }
        var attrs = NFSSetAttrs()
        attrs.size = 1 << 20
        guard case .failure(.nospc) = a.fs.setattr(id, attrs, a.ctx) else { return XCTFail("nor by being stretched") }
        XCTAssertEqual(try a.text("local/f"), "start")
        XCTAssertEqual(a.fs.fsstat().freeBytes, 0, "programs are told there's no room")

        // Changing what's there, or making it smaller, needs no room.
        try a.fs.write(id, offset: 0, data: Data("S".utf8), a.ctx).get()
        attrs.size = 3
        try a.fs.setattr(id, attrs, a.ctx).get()
        XCTAssertEqual(try a.text("local/f"), "Sta")
    }
}
