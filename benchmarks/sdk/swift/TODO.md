# Swift SDK benchmark — now wired

The Swift SDK bench glue is wired to the real SDK (`ilpanich/axiam-swift-sdk`, library
product `AxiamSDK`). It times the four canonical CONTRACT.md §1 ops (`login`, `refresh`,
`checkAccess`, `batchCheck`) and emits one `axiam.sdk-bench/v1` JSON object to stdout
(see `../HARNESS-SPEC.md`).

## Layout
- `Package.swift` depends on the SDK via a local path dependency on the sibling checkout
  (`../../../../axiam-swift-sdk`), mirroring the go/rust/csharp benches' relative
  sibling-path convention, because the tagged release (`1.0.0-alpha12`) may not be
  resolvable from this sandbox. Swap it for the git reference in the SDK's README once
  published:
  `.package(url: "https://github.com/ilpanich/axiam-swift-sdk.git", from: "1.0.0-alpha12")`.
- `Sources/axiam-bench/main.swift` is the entrypoint (executable target `axiam-bench`, run
  with `swift run -c release axiam-bench`).
- `run.sh` builds in release config and `exec`s `swift run -c release axiam-bench`; it falls
  back to `emit_pending swift` when the `swift` toolchain is missing OR the release build
  fails (e.g. the sibling checkout isn't present).

## mTLS / custom CA
Swift is one of the SDKs that shipped a §6.1 client-certificate mTLS option
(`AxiamConfig(..., clientCertificate: .pem(certificate:privateKey:))`), so the bench reads
`BENCH_CA_CERT` / `BENCH_CLIENT_CERT` / `BENCH_CLIENT_KEY` (file paths, per
`../../docs/security-profiles.md`) and threads them into `AxiamConfig` when present. This is
ahead of `../HARNESS-SPEC.md`'s current "no SDK exposes mTLS" note, which predates the
Swift/Kotlin/C/C++ SDKs' addition of §6.1 — update that note when the other language benches
catch up.

## Running
- `cd benchmarks && just sdk=swift sdk-bench`

## Before running for real
- Requires a Swift toolchain (`swift build`/`swift run`) — **not installed in this sandbox**,
  so this bench is written-but-unverified here: it has not been compiled or run against a
  live AXIAM target. Verify on a machine with Swift 5.9+ installed and the sibling
  `axiam-swift-sdk` checkout present at `../../../../axiam-swift-sdk`.
