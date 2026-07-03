//! HMAC-SHA256 sign/verify for AMQP message payloads (CONTRACT.md §8).
//!
//! **Mirror, never import.** This module reproduces the algorithm in
//! `crates/axiam-amqp/src/messages.rs:35-50` byte-for-byte using only
//! external crates (`hmac`, `sha2`, `hex`) so that the SDK's HMAC output is
//! wire-compatible with the AXIAM server for the same key + canonical JSON
//! payload bytes. This crate does NOT depend on the `axiam-amqp` crate.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 of the JSON-serialized message payload.
///
/// The `hmac_signature` field must be set to `None` (or omitted) before
/// serializing `payload_json` — otherwise the signature is computed over a
/// message that includes a placeholder signature, making verification
/// impossible. This matches the server's `sign_payload` doc comment
/// (`crates/axiam-amqp/src/messages.rs:31-34`).
pub fn sign_payload(key: &[u8], payload_json: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(payload_json);
    hex::encode(mac.finalize().into_bytes())
}

/// Verify an HMAC-SHA256 signature over the canonical payload bytes.
///
/// Returns `true` if the signature matches. Uses constant-time comparison
/// internally (via the `hmac` crate's `verify_slice`).
pub fn verify_payload(key: &[u8], payload_json: &[u8], signature_hex: &str) -> bool {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(payload_json);
    let expected = hex::decode(signature_hex).unwrap_or_default();
    mac.verify_slice(&expected).is_ok()
}
