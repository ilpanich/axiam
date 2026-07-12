//! AXIAM SDK for Rust
//!
//! This crate provides the official Rust client SDK for AXIAM
//! (Access eXtended Identity and Authorization Management), a multi-tenant
//! IAM solution. It conforms to the cross-language SDK behavioral contract
//! in `../CONTRACT.md` §1–§10, and offers three interchangeable transports
//! behind Cargo features:
//!
//! - `rest` — [`client::AxiamClient`], built on `reqwest`; cookie-based
//!   sessions with CSRF double-submit protection (§3/§4).
//! - `grpc` — [`grpc::AuthzGrpcClient`], for low-latency authorization
//!   checks from a service mesh.
//! - `amqp` — [`amqp`], a closure-handler consumer for HMAC-signed,
//!   replay-protected authorization/audit messages (§8).
//!
//! An additional `actix` feature provides [`middleware::AxiamUser`], an
//! Actix-Web extractor that verifies sessions locally against a cached JWKS
//! (§10). All access/refresh tokens are wrapped in [`Sensitive`] so they are
//! never accidentally logged or displayed.
//!
//! # Example: login then check access (REST transport)
//!
//! ```no_run
//! use axiam_sdk::client::AxiamClient;
//!
//! # async fn run() -> Result<(), axiam_sdk::AxiamError> {
//! let client = AxiamClient::builder()
//!     .base_url("https://axiam.example.com")?
//!     .tenant_slug("acme")
//!     .build()?;
//!
//! client.login("user@example.com", "hunter2").await?;
//!
//! let allowed = client
//!     .can("read", "resource-uuid".parse().unwrap(), None)
//!     .await?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

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
