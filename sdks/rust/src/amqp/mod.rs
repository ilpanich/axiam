//! AMQP transport (owned by 16-04): HMAC sign/verify, closure-handler
//! consumer, `AuthzRequest`/`AuditEventMessage` DTOs.
//!
//! This module is a **mirror, never an import**, of the server's
//! `crates/axiam-amqp/src/messages.rs` wire format: the HMAC-SHA256
//! sign/verify functions and the `AuthzRequest`/`AuditEventMessage` structs
//! reproduce the server's algorithm and serde shape byte-for-byte using only
//! external crates (`hmac`, `sha2`, `hex`, `serde`, `uuid`, `serde_json`,
//! `lapin`) — this crate never depends on any `axiam-*` workspace crate.
//!
//! See `sdks/CONTRACT.md` §8 for the full HMAC verification protocol this
//! module implements.

pub mod hmac;
pub mod messages;

pub use hmac::{sign_payload, verify_payload};
pub use messages::{AuditEventMessage, AuthzRequest};

// `consumer` (the closure-handler `consume(...)` API, D-07) is added by this
// plan's Task 2, which depends on the `hmac`/`messages` primitives above.
