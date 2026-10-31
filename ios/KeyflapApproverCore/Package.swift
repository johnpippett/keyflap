// swift-tools-version: 6.0
//
// Platform-independent core of the Keyflap iOS approver: statement encoding (byte-for-byte
// the broker signer's canonical form), pairing links, the broker API models and client,
// and display formatting. Foundation only, so it builds and tests on Linux too.
// swift-crypto is used only by the tests (to check signatures against the TypeScript
// side's fixtures and to produce the fixture the TypeScript tests verify).

import PackageDescription

let package = Package(
    name: "KeyflapApproverCore",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "KeyflapApproverCore", targets: ["KeyflapApproverCore"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
    ],
    targets: [
        .target(name: "KeyflapApproverCore"),
        .testTarget(
            name: "KeyflapApproverCoreTests",
            dependencies: [
                "KeyflapApproverCore",
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
    ]
)
