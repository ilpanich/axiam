//! AXIAM SDK for Rust
//!
//! This crate provides the official Rust client SDK for AXIAM
//! (Access eXtended Identity and Authorization Management).
//!
//! See `../CONTRACT.md §1-§10` for the cross-language behavioral contract.
//! Implementation follows in Phase 16 (Rust reference implementation).
//!
//! This SDK conforms to CONTRACT.md §1–§10.

#![forbid(unsafe_code)]

mod error;
mod sensitive;
// X-2: shared TLS-scheme guard for transport URLs (REST/gRPC/AMQP). Always
// compiled (transport modules below are feature-gated but all reuse this).
mod url_guard;

pub use error::AxiamError;
pub use sensitive::Sensitive;

// Single owner of all Phase 16 module declarations (this file is final
// after plan 16-01; downstream plans 16-02..16-05 only fill in module
// bodies, never edit this file, to avoid parallel-execution merge
// conflicts).
pub mod client;
pub mod token;

#[cfg(feature = "rest")]
pub mod rest;

#[cfg(feature = "grpc")]
pub mod grpc;

#[cfg(feature = "amqp")]
pub mod amqp;

#[cfg(feature = "actix")]
pub mod middleware;
