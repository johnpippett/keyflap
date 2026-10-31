// swift-tools-version: 6.0
//
// The Keyflap approver iOS app, laid out for xtool (https://github.com/xtool-org/xtool):
// exactly one library product, which xtool links into the app bundle described by
// xtool.yml. CI builds the same sources through an XcodeGen project (project.yml).
// Platform-independent logic lives in KeyflapApproverCore (tests run on Linux too).

import PackageDescription

let package = Package(
    name: "KeyflapApprover",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "KeyflapApprover", targets: ["KeyflapApprover"]),
    ],
    dependencies: [
        .package(path: "KeyflapApproverCore"),
    ],
    targets: [
        .target(
            name: "KeyflapApprover",
            dependencies: [.product(name: "KeyflapApproverCore", package: "KeyflapApproverCore")],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
