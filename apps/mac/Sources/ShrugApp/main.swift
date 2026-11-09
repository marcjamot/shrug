import AppKit
import Foundation
import ShrugCore
import ShrugDaemon

// Shrug.app: hosts the engine and shows the menu bar icon.
// `ShrugApp --headless` runs the same engine without UI (used for testing).

let engine = Engine(paths: .current())
do {
    try engine.start()
} catch {
    fputs("Shrug could not start: \(error)\n", stderr)
    exit(1)
}

func installSignalHandlers(_ onSignal: @escaping () -> Void) -> [DispatchSourceSignal] {
    [SIGINT, SIGTERM, SIGHUP].map { sig in
        signal(sig, SIG_IGN)
        let s = DispatchSource.makeSignalSource(signal: sig, queue: .main)
        s.setEventHandler(handler: onSignal)
        s.resume()
        return s
    }
}

if CommandLine.arguments.contains("--headless") {
    let sources = installSignalHandlers {
        engine.stop()
        exit(0)
    }
    _ = sources
    RunLoop.main.run()
} else {
    let app = NSApplication.shared
    let delegate = MenuController(engine: engine)
    app.delegate = delegate
    app.setActivationPolicy(.accessory)
    let sources = installSignalHandlers {
        engine.stop()
        exit(0)
    }
    _ = sources
    app.run()
}
