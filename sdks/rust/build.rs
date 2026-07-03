//! Build-time gRPC codegen shim.
//!
//! When the `grpc` feature is enabled, compiles the AXIAM protobuf service
//! definitions into `src/gen/` via `tonic-prost-build`. This is the local
//! codegen fallback to the repository's `buf generate` pipeline (D-09,
//! `sdks/buf.gen.yaml` targets the same `rust/src/gen` output directory);
//! plan 16-03 wires the generated module into the crate, and plan 16-06's
//! publish job swaps in the buf-bundled stubs for the published crate.
//!
//! When the `grpc` feature is off, this build script is a no-op.

use std::path::Path;

fn main() {
    // Only run codegen when the `grpc` feature is requested. Cargo sets
    // `CARGO_FEATURE_<NAME>` env vars (uppercased, `-` -> `_`) for every
    // enabled feature of the crate being built.
    if std::env::var("CARGO_FEATURE_GRPC").is_err() {
        return;
    }

    let proto_dir = Path::new("../../proto/axiam/v1");
    let protos = [
        proto_dir.join("authorization.proto"),
        proto_dir.join("token.proto"),
        proto_dir.join("user.proto"),
    ];

    // Guard against missing proto inputs: warn (do not fail) so a partial
    // checkout or non-monorepo build of this crate does not hard-fail just
    // because the `grpc` feature was requested. The buf-bundled stubs
    // (D-09) are the publish-time fallback for exactly this situation.
    let missing: Vec<&Path> = protos
        .iter()
        .map(|p| p.as_path())
        .filter(|p| !p.exists())
        .collect();
    if !missing.is_empty() {
        for p in &missing {
            println!(
                "cargo:warning=axiam-sdk build.rs: proto file not found, skipping gRPC codegen: {}",
                p.display()
            );
        }
        return;
    }

    let out_dir = Path::new("src/gen");
    if let Err(e) = std::fs::create_dir_all(out_dir) {
        println!(
            "cargo:warning=axiam-sdk build.rs: could not create {}: {e}",
            out_dir.display()
        );
        return;
    }

    let proto_paths: Vec<&Path> = protos.iter().map(|p| p.as_path()).collect();
    if let Err(e) = tonic_prost_build::configure()
        .out_dir(out_dir)
        .compile_protos(&proto_paths, &[proto_dir])
    {
        println!("cargo:warning=axiam-sdk build.rs: gRPC codegen failed: {e}");
    }

    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }
}
