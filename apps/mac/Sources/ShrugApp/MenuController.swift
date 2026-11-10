import AppKit
import ServiceManagement
import ShrugCore
import ShrugDaemon

/// The menu bar icon: lock state, whether the bucket is up to date, links needing attention.
final class MenuController: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let engine: Engine
    var item: NSStatusItem!
    /// The password dialog is showing (main thread only): never more than one.
    var askingPassword = false

    init(engine: Engine) {
        self.engine = engine
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.mainMenu = MenuController.editingMenu()
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        let menu = NSMenu()
        menu.delegate = self
        item.menu = menu
        engine.onChange = { [weak self] in self?.refreshIcon() }
        // A program needs ~/Shrug and Touch ID can't unlock: ask for the Shrug password.
        engine.askPassword = { [weak self] why, done in
            DispatchQueue.main.async {
                guard let self else { return done() }
                self.askPassword(why: why, done: done)
            }
        }
        refreshIcon()
        Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in self?.refreshIcon() }
    }

    func applicationWillTerminate(_ notification: Notification) {
        engine.stop()
    }

    /// Shrug has no menu bar of its own, so nothing would turn ⌘V into Paste in its dialogs, and
    /// a password from a password manager couldn't be pasted. This menu is never shown; it only
    /// supplies the usual editing keys.
    static func editingMenu() -> NSMenu {
        let edit = NSMenu(title: "Edit")
        edit.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        let editItem = NSMenuItem(title: "Edit", action: nil, keyEquivalent: "")
        editItem.submenu = edit
        let main = NSMenu()
        main.addItem(NSMenuItem(title: "Shrug", action: nil, keyEquivalent: "")) // the app menu's place
        main.addItem(editItem)
        return main
    }

    // MARK: - Icon

    func refreshIcon() {
        let s = engine.status()
        let symbol = s.unlocked ? "lock.open.fill" : "lock.fill"
        let image = NSImage(systemSymbolName: symbol, accessibilityDescription: s.unlocked ? "Shrug unlocked" : "Shrug locked")
        image?.isTemplate = true
        item.button?.image = image
        let attention = s.waiting + s.links.filter { $0.state != "ok" }.count
        item.button?.title = attention > 0 ? " \(attention)" : ""
        item.button?.imagePosition = .imageLeading
        item.button?.toolTip = headline(s)
    }

    func headline(_ s: StatusInfo) -> String {
        if !s.setUp { return "Shrug: not set up" }
        return s.unlocked ? "Shrug: unlocked" : "Shrug: locked"
    }

    func storageLine(_ s: StatusInfo) -> String {
        if let p = s.problem { return p }
        if s.online == false { return s.waiting > 0 ? "Offline, \(s.waiting) waiting to upload" : "Offline" }
        if s.waiting > 0 { return "\(s.waiting) waiting to upload" }
        return s.online == nil ? "Not checked yet" : "Up to date"
    }

    // MARK: - Menu

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        let s = engine.status()
        menu.addItem(disabled(headline(s)))
        if !s.mounted { menu.addItem(disabled("The Shrug folder isn't mounted")) }
        if s.unlocked {
            menu.addItem(disabled(storageLine(s)))
            if let p = s.profile { menu.addItem(disabled("Profile: \(p)")) }
            if let here = s.trustedHere { menu.addItem(disabled("Trusted network: \(here)")) }
            let broken = s.links.filter { $0.state != "ok" }
            if !broken.isEmpty {
                menu.addItem(.separator())
                menu.addItem(disabled("Links needing attention:"))
                for l in broken.prefix(8) { menu.addItem(disabled("  \(l.path): \(l.state)")) }
            }
            for n in s.notices.suffix(3) { menu.addItem(disabled(n)) }
        }
        menu.addItem(.separator())
        if s.setUp {
            if s.unlocked {
                menu.addItem(action("Lock Now", #selector(lockNow)))
                if let here = s.trustedHere {
                    menu.addItem(action("Stop Trusting \(here)", #selector(untrustNetwork)))
                } else {
                    menu.addItem(action("Trust This Network…", #selector(trustNetwork)))
                }
            } else {
                menu.addItem(action("Unlock" + (s.touchID ? "" : "…"), #selector(unlockTouchID)))
                if s.touchID { menu.addItem(action("Unlock with Password…", #selector(unlockPassword))) }
            }
            menu.addItem(action("Open Shrug Folder", #selector(openFolder)))
        } else {
            menu.addItem(disabled("Run ./setup in the repo folder"))
        }
        menu.addItem(.separator())
        let login = action("Open at Login", #selector(toggleLogin))
        login.state = SMAppService.mainApp.status == .enabled ? .on : .off
        menu.addItem(login)
        menu.addItem(action("Quit Shrug", #selector(quit)))
    }

    func disabled(_ title: String) -> NSMenuItem {
        let i = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        i.isEnabled = false
        return i
    }

    func action(_ title: String, _ sel: Selector) -> NSMenuItem {
        let i = NSMenuItem(title: title, action: sel, keyEquivalent: "")
        i.target = self
        return i
    }

    // MARK: - Actions

    /// Runs `work` off the main thread, shows its error if it fails, then calls `then`.
    func background(_ work: @escaping () throws -> Void, then: (() -> Void)? = nil) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try work()
            } catch {
                DispatchQueue.main.async { self.alert("\(error)") }
            }
            then?()
            DispatchQueue.main.async { self.refreshIcon() }
        }
    }

    @objc func unlockTouchID() { unlock(forcePassword: false) }
    @objc func unlockPassword() { unlock(forcePassword: true) }

    func unlock(forcePassword: Bool) {
        if engine.status().touchID && !forcePassword {
            background {
                do {
                    try self.engine.unlock(password: nil)
                } catch is PasswordNeeded {
                    DispatchQueue.main.async { self.askPassword() }
                }
            }
        } else {
            askPassword()
        }
    }

    /// The Shrug password dialog. `why` says what a program was doing when it asked; `done` runs
    /// once the dialog is closed (after unlocking, if a password was given).
    func askPassword(why: String? = nil, done: (() -> Void)? = nil) {
        guard !askingPassword else { done?(); return }
        askingPassword = true
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Unlock Shrug"
        alert.informativeText = why.map { "Shrug is locked and \($0).\n\nEnter your Shrug password to unlock." }
            ?? "Enter your Shrug password."
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
        alert.accessoryView = field
        alert.addButton(withTitle: "Unlock")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = field
        let answered = alert.runModal() == .alertFirstButtonReturn
        askingPassword = false
        guard answered else { done?(); return }
        let password = field.stringValue
        background({ try self.engine.unlock(password: password) }, then: done)
    }

    @objc func lockNow() {
        engine.lockNow("locked from the menu")
        refreshIcon()
    }

    /// Asks what to call the network, then for a fingerprint (or the Shrug password).
    @objc func trustNetwork() {
        guard let name = ask("Trust This Network",
                             "On this network, Shrug stays unlocked when the screen locks. It locks when the Mac "
                                 + "leaves the network, sleeps, or you switch to another user.\n\n"
                                 + "Anyone who gets past the Mac's lock screen here can then read your files.",
                             button: "Trust", value: "home")
        else { return }
        background {
            do {
                _ = try self.engine.trust(name: name, password: nil)
            } catch is PasswordNeeded {
                DispatchQueue.main.async {
                    guard let password = self.ask("Trust This Network", "Enter your Shrug password to confirm.",
                                                  button: "Trust", secret: true)
                    else { return }
                    self.background { _ = try self.engine.trust(name: name, password: password) }
                }
            }
        }
    }

    @objc func untrustNetwork() {
        background { _ = try self.engine.untrust(name: nil) }
    }

    /// A dialog with one field. Nil if cancelled.
    func ask(_ title: String, _ text: String, button: String, secret: Bool = false, value: String = "") -> String? {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = text
        let frame = NSRect(x: 0, y: 0, width: 260, height: 24)
        let field = secret ? NSSecureTextField(frame: frame) : NSTextField(frame: frame)
        field.stringValue = value
        alert.accessoryView = field
        alert.addButton(withTitle: button)
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = field
        return alert.runModal() == .alertFirstButtonReturn ? field.stringValue : nil
    }

    @objc func openFolder() {
        NSWorkspace.shared.open(engine.paths.mount)
    }

    @objc func toggleLogin() {
        do {
            if SMAppService.mainApp.status == .enabled {
                try SMAppService.mainApp.unregister()
            } else {
                try SMAppService.mainApp.register()
            }
        } catch {
            alert("Could not change login item: \(error.localizedDescription)")
        }
    }

    @objc func quit() { NSApp.terminate(nil) }

    func alert(_ message: String) {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.messageText = "Shrug"
        a.informativeText = message
        a.runModal()
    }
}
