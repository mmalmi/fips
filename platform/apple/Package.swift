// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "FipsBle",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
    ],
    products: [
        .library(name: "FipsBle", targets: ["FipsBle"]),
    ],
    targets: [
        .target(
            name: "FipsBle",
            linkerSettings: [.linkedFramework("CoreBluetooth")]
        ),
        .testTarget(name: "FipsBleTests", dependencies: ["FipsBle"]),
    ],
    swiftLanguageVersions: [.v5]
)
