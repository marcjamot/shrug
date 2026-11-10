import Foundation
import ShrugCore

/// Trusted networks: where a screen lock doesn't lock Shrug (see `Engine.screenLocked`).
extension Engine {
    static let trustedLimit = 20

    /// Trusts the network this Mac is on now. It makes Shrug less strict, so it takes a
    /// fingerprint, or the Shrug password, even when Shrug is unlocked.
    public func trust(name: String?, password: String?) throws -> String {
        guard paths.isSetUp else { throw ShrugError("Not set up yet: run ./setup") }
        guard network.current() != nil else { throw Engine.noNetwork }
        try confirm("trust the network this Mac is on", password: password)
        // Asked again: the answer may have taken a while, and it's this network you agreed to.
        guard let router = network.current() else { throw Engine.noNetwork }
        let wanted = Engine.shown((name ?? "").trimmingCharacters(in: .whitespaces), limit: 40)
        var result = ""
        var failure: ShrugError?
        updateState { st in
            var trusted = st.trusted ?? []
            if let i = trusted.firstIndex(where: { $0.router == router }) {
                if !wanted.isEmpty, wanted != trusted[i].name {
                    guard !trusted.contains(where: { $0.name == wanted }) else {
                        failure = ShrugError("Another trusted network is already called '\(wanted)'")
                        return
                    }
                    trusted[i].name = wanted
                }
                result = "Trusting this network as '\(trusted[i].name)'"
            } else {
                let name = wanted.isEmpty ? Engine.freeName(trusted) : wanted
                guard !trusted.contains(where: { $0.name == name }) else {
                    failure = ShrugError("Another trusted network is already called '\(name)': pick another name, or 'shrug untrust \(name)' first")
                    return
                }
                guard trusted.count < Engine.trustedLimit else {
                    failure = ShrugError("That's \(Engine.trustedLimit) trusted networks already: untrust one first")
                    return
                }
                trusted.append(TrustedNetwork(name: name, router: router, addedAt: clock.nowMs))
                result = "Trusting this network as '\(name)': Shrug stays unlocked here when the screen locks"
            }
            st.trusted = trusted
        }
        if let failure { throw failure }
        guard !result.isEmpty else { throw ShrugError("Shrug locked before the network was trusted") }
        log("trusted a network")
        return result
    }

    /// Stops trusting a network: the one named, else the one this Mac is on, else the only one.
    public func untrust(name: String?) throws -> String {
        try requireUnlocked("unlock to stop trusting a network")
        let trusted = stateCopy()?.trusted ?? []
        guard !trusted.isEmpty else { throw ShrugError("No network is trusted") }
        let gone: TrustedNetwork
        if let name, !name.isEmpty {
            guard let found = trusted.first(where: { $0.name == name }) else {
                throw ShrugError("No trusted network is called '\(name)' (trusted: \(Engine.names(trusted)))")
            }
            gone = found
        } else if let here = trustedNetwork(among: trusted) {
            gone = here
        } else if trusted.count == 1 {
            gone = trusted[0]
        } else {
            throw ShrugError("This Mac isn't on a trusted network. Say which to stop trusting: \(Engine.names(trusted))")
        }
        updateState { st in st.trusted = (st.trusted ?? []).filter { $0 != gone } }
        log("stopped trusting a network")
        // If that network was keeping Shrug unlocked behind a locked screen, it locks now.
        checkNetwork()
        return "No longer trusting '\(gone.name)'"
    }

    private static var noNetwork: ShrugError {
        ShrugError("Can't tell which network this Mac is on (no router found), so there's nothing to trust")
    }

    private static func names(_ trusted: [TrustedNetwork]) -> String {
        trusted.map(\.name).joined(separator: ", ")
    }

    /// "home", then "home 2", "home 3"…
    private static func freeName(_ trusted: [TrustedNetwork]) -> String {
        let taken = Set(trusted.map(\.name))
        if !taken.contains("home") { return "home" }
        return (2...).lazy.map { "home \($0)" }.first { !taken.contains($0) }!
    }

    /// Makes sure it's you, even when Shrug is already unlocked: a fingerprint, or the Shrug
    /// password if one is given. Unlocks too. PasswordNeeded when only the password will do.
    func confirm(_ reason: String, password: String?) throws {
        if let password {
            _ = try loadKeys().vault.open(password: password, cache: KEKCache())
            try unlock(password: password)
            return
        }
        guard touchID.isEnrolled else { throw PasswordNeeded() }
        promptLock.lock()
        defer { promptLock.unlock() }
        do {
            if isUnlocked {
                do {
                    _ = try touchID.unlock(reason: reason, timeout: 60)
                } catch TouchIDError.usePassword {
                    throw PasswordNeeded()
                } catch TouchIDError.invalidated {
                    throw PasswordNeeded()
                }
            } else {
                try unlockWithTouchID(reason: reason)
            }
        } catch let e as PasswordNeeded {
            throw e
        } catch {
            throw ShrugError("Not confirmed: \(error)")
        }
    }
}
