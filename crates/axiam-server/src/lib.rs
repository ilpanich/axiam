//! AXIAM Server — library crate.
//!
//! `axiam-server` is primarily a binary (`main.rs`), but a handful of its
//! internal modules need to be reachable from integration tests under
//! `tests/` — Rust integration test binaries can only link against a
//! package's *library* crate, not its `main.rs` binary. This crate exists
//! solely to expose those modules: `cleanup`, whose `run_erasure_pipeline`
//! free function is a test seam for the GDPR erasure durability negative test
//! (SECHRD-06), and `tls`, whose `build_rustls_server_config` is unit-tested
//! for its fail-fast validation of the optional direct-TLS config (F-04).
//!
//! `main.rs` depends on this crate automatically (a package's binary target
//! always links its own library target when both are present).

pub mod cleanup;
pub mod tls;
