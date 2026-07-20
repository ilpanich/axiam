// swift-tools-version:5.9
// Standalone SwiftPM package for the Swift SDK bench. Depends on the real SDK
// (AxiamSDK, product of package "axiam-swift-sdk") via a local path dependency
// on the sibling `axiam-swift-sdk` checkout, mirroring the go/rust/csharp
// benches' relative sibling-path convention (../../../../axiam-<lang>-sdk) —
// the tagged SwiftPM release may not be resolvable from this sandbox, and a
// path dependency lets the bench track the exact SDK under test.
//
// For a reproducible, published build once the package is tagged/available,
// swap the dependency for the git reference the SDK's own README documents:
//   .package(url: "https://github.com/ilpanich/axiam-swift-sdk.git", from: "1.0.0-alpha12")
import PackageDescription

let package = Package(
    name: "axiam-sdk-bench",
    platforms: [
        .macOS(.v13),
    ],
    dependencies: [
        .package(path: "../../../../axiam-swift-sdk"),
    ],
    targets: [
        .executableTarget(
            name: "axiam-bench",
            dependencies: [
                // "axiam-swift-sdk" is the dependency's package identity (its
                // repo/directory name); "AxiamSDK" is the library product name
                // — exactly as documented in axiam-swift-sdk/README.md's own
                // Installation snippet.
                .product(name: "AxiamSDK", package: "axiam-swift-sdk"),
            ]
        ),
    ]
)
