//! AXIAM Server — library crate.
//!
//! `axiam-server` is primarily a binary (`main.rs`), but a handful of its
//! internal modules need to be reachable from integration tests under
//! `tests/` — Rust integration test binaries can only link against a
//! package's *library* crate, not its `main.rs` binary. This crate exists
//! solely to expose those modules: `cleanup`, whose `run_erasure_pipeline`
//! free function is a test seam for the GDPR erasure durability negative test
//! (SECHRD-06), and `tls`, whose `build_rustls_server_config` is unit-tested
//! for its fail-fast validation of the optional direct-TLS config (F-04), and
//! `legacy_env`, whose secret-variable warning is a pure function over an
//! environment predicate so it can be tested without `set_var`.
//!
//! `main.rs` depends on this crate automatically (a package's binary target
//! always links its own library target when both are present).

pub mod cleanup;
pub mod job_health;
pub mod legacy_env;
pub mod mds_job;
pub mod mtls_anchors;
pub mod tls;
