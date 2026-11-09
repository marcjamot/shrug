import AppKit
import ServiceManagement
import ShrugCore
import ShrugDaemon

/// The menu bar icon: lock state, whether the bucket is up to date, links needing attention.
final class MenuController: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let engine: Engine
    var item: NSStatusItem!

    init(engine: Engine) {
        self.engine = engine
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        let menu = NSMenu()
        menu.delegate = self
        item.menu = menu
        engine.onChange = { [weak self] in self?.refreshIcon() }
        refreshIcon()
        Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in self?.refreshIcon() }
    }

    func applicationWillTerminate(_ notification: Notification) {
        engine.stop()
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

    func background(_ work: @escaping () throws -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try work()
            } catch {
                DispatchQueue.main.async { self.alert("\(error)") }
            }
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
                } catch let e as ShrugError where e.description == "password-needed" {
                    DispatchQueue.main.async { self.askPassword() }
                }
            }
        } else {
            askPassword()
        }
    }

    func askPassword() {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Unlock Shrug"
        alert.informativeText = "Enter your Shrug password."
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
        alert.accessoryView = field
        alert.addButton(withTitle: "Unlock")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = field
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let password = field.stringValue
        background { try self.engine.unlock(password: password) }
    }

    @objc func lockNow() {
        engine.lockNow("locked from the menu")
        refreshIcon()
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
