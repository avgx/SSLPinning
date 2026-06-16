// swift-tools-version: 6.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SSLPinning",
    defaultLocalization: "en",
    platforms: [
        .iOS(.v15),
        .tvOS(.v15),
        .macOS(.v13),
        .watchOS(.v9),
        .visionOS(.v1)
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SSLPinning",
            targets: ["SSLPinning"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.7.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.19.1")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SSLPinning",
            dependencies: [
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "X509", package: "swift-certificates"),
            ],
            resources: [.process("Resources")]
        ),
        .testTarget(
            name: "SSLPinningTests",
            dependencies: ["SSLPinning"]
        ),
    ]
)
