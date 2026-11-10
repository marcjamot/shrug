// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "Shrug",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "ShrugApp", targets: ["ShrugApp"]),
        .executable(name: "shrug", targets: ["shrug"]),
    ],
    targets: [
        // Shared building blocks: crypto, file and object formats, storage, config, IPC.
        .target(name: "ShrugCore"),
        // A minimal loopback NFSv3 server. Knows nothing about Shrug.
        .target(name: "ShrugNFS"),
        // The engine: lock rules, virtual folder, links and profiles, bucket sync.
        .target(name: "ShrugDaemon", dependencies: ["ShrugCore", "ShrugNFS"]),
        // Menu bar app that hosts the engine (or runs it headless with --headless).
        .executableTarget(name: "ShrugApp", dependencies: ["ShrugDaemon"]),
        // Command line client that talks to the running app.
        .executableTarget(name: "shrug", dependencies: ["ShrugCore"]),
        .testTarget(name: "ShrugCoreTests", dependencies: ["ShrugCore"]),
        .testTarget(name: "ShrugNFSTests", dependencies: ["ShrugNFS"]),
        // Fixtures: data in older formats, for the migration tests.
        .testTarget(name: "ShrugDaemonTests", dependencies: ["ShrugDaemon", "ShrugCore", "ShrugNFS"],
                    resources: [.copy("Fixtures")]),
    ]
)
