// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "pam_totp",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "pam_totp",
            type: .dynamic,
            targets: ["pam_totp"]
        ),
        .executable(
            name: "pam_totp-setup",
            targets: ["Setup"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "CPAMBridge",
            path: "src/pam_bridge",
            publicHeadersPath: "include"
        ),
        .target(
            name: "pam_totp",
            dependencies: [
                "PAMShared",
                "CPAMBridge"
            ],
            path: "src/pam_module",
            linkerSettings: [
                .linkedLibrary("pam")
            ]
        ),
        .target(
            name: "PAMShared",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto")
            ],
            path: "src/shared"
        ),
        .executableTarget(
            name: "Setup",
            dependencies: [
                "PAMShared"
            ],
            path: "src/setup"
        ),
        .testTarget(
            name: "pam_totpTests",
            dependencies: ["PAMShared"],
            path: "tests"
        )
    ]
)
