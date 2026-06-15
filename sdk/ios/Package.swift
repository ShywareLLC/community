// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ShywareSDK",
    platforms: [
        .iOS(.v17),   // iOS 26 SDK ships as 17 in swift-tools; update to .v26 when toolchain lands
        .macOS(.v14),
    ],
    products: [
        .library(name: "ShywareSDK", targets: ["ShywareSDK"]),
    ],
    targets: [
        .target(
            name: "ShywareSDK",
            path: "Sources/ShywareSDK"
        ),
        .testTarget(
            name: "ShywareSDKTests",
            dependencies: ["ShywareSDK"],
            path: "Tests/ShywareSDKTests"
        ),
    ]
)
