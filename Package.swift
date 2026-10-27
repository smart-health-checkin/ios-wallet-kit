// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "SMARTHealthCheckin",
    platforms: [
        .iOS(.v26),
        .macOS(.v26),
        .visionOS(.v26)
    ],
    products: [
        .library(name: "SMARTHealthCheckin", type: .dynamic, targets: ["SMARTHealthCheckin"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.0.0")
    ],
    targets: [
        .target(
            name: "SMARTHealthCheckin",
            dependencies: [
                .product(name: "X509", package: "swift-certificates")
            ],
            path: "Sources"
        ),
        .testTarget(
            name: "SMARTHealthCheckinTests",
            dependencies: ["SMARTHealthCheckin"],
            path: "Tests"
        )
    ]
)
