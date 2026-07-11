//! AMQP message DTOs mirroring the server's wire format (CONTRACT.md §8).
//!
//! **Mirror, never import.** These structs reproduce field declaration
//! order and `#[serde(...)]` attributes byte-for-byte from
//! `crates/axiam-amqp/src/messages.rs:166-245` so that
//! `serde_json::to_vec`/`to_string` produces canonical JSON byte-identical
//! to what the server signs/verifies against. This crate does NOT depend on
//! the `axiam-amqp` or `axiam-core` crates — these are standalone plain
//! structs built only on `serde`, `uuid`, `chrono`, and `serde_json`.
//!
//! Before computing or verifying the HMAC over either struct, the caller
//! MUST set `hmac_signature` to `None` (or remove the key entirely from the
//! serialized JSON object) — otherwise the signature would be computed over
//! a payload that includes a placeholder signature value, making
//! verification impossible. This matches the server's `sign_payload` doc
//! comment (`crates/axiam-amqp/src/messages.rs:31-34`).
//!
//! NEW-4 (v2, `key_version = 2`, BREAKING/hard cutover): the signed body now
//! carries two additional mandatory fields, `nonce` and `issued_at`, used for
//! replay protection (CONTRACT.md §8 "v2 — Replay Protection"). Both fields
//! are ALWAYS emitted (no `skip_serializing_if`) so they sit inside the HMAC
//! coverage. See `crates/axiam-amqp/tests/fixtures/v2_reference_vectors.json`
//! for server-generated canonical bytes + expected HMAC this SDK must
//! reproduce byte-for-byte.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Authorization check request received from `axiam.authz.request`.
///
/// Field declaration order matches the server's `AuthzRequest`
/// (`crates/axiam-amqp/src/messages.rs:166-197`) exactly: `correlation_id`,
/// `tenant_id`, `subject_id`, `action`, `resource_id`, `scope`,
/// `key_version`, `nonce`, `issued_at`, `hmac_signature`.
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthzRequest {
    /// Caller-provided ID to correlate request with response.
    pub correlation_id: Uuid,
    pub tenant_id: Uuid,
    pub subject_id: Uuid,
    pub action: String,
    pub resource_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// HKDF master-key rotation version (NEW-4). The consumer rejects any
    /// message with `key_version < 2` — v1 (pre-replay-protection) messages
    /// are not accepted (hard cutover, no grace path).
    pub key_version: u8,
    /// Per-message unique value for replay protection (NEW-4). ALWAYS
    /// emitted (no `skip_serializing_if`) so it sits inside the signed HMAC
    /// body. The consumer rejects a `nonce` it has already seen within the
    /// freshness window as a replay.
    pub nonce: Uuid,
    /// Producer-side send time for the freshness gate (NEW-4). ALWAYS
    /// emitted (no `skip_serializing_if`) so it sits inside the signed HMAC
    /// body. The consumer rejects the message when this lies outside ±skew
    /// of its own clock.
    pub issued_at: DateTime<Utc>,
    /// HMAC-SHA256 of the JSON-serialized message body (this field set to
    /// `None`/omitted before signing). Computed with the per-tenant AMQP
    /// signing key (CONTRACT.md §8). The consumer MUST verify this before
    /// processing; a missing signature is rejected in strict mode (the
    /// default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac_signature: Option<String>,
}

/// Audit event received from external services via `axiam.audit.events`.
///
/// Field declaration order matches the server's `AuditEventMessage`
/// (`crates/axiam-amqp/src/messages.rs:211-245`) exactly: `tenant_id`,
/// `actor_id`, `actor_type`, `action`, `resource_id`, `outcome`,
/// `ip_address`, `metadata`, `key_version`, `nonce`, `issued_at`,
/// `hmac_signature`.
#[derive(Debug, Deserialize, Serialize)]
pub struct AuditEventMessage {
    pub tenant_id: Uuid,
    pub actor_id: Uuid,
    pub actor_type: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<Uuid>,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// HKDF master-key rotation version (NEW-4). The consumer rejects any
    /// message with `key_version < 2` — v1 (pre-replay-protection) messages
    /// are not accepted (hard cutover, no grace path).
    pub key_version: u8,
    /// Per-message unique value for replay protection (NEW-4). ALWAYS
    /// emitted (no `skip_serializing_if`) so it sits inside the signed HMAC
    /// body. The consumer rejects a `nonce` it has already seen within the
    /// freshness window as a replay.
    pub nonce: Uuid,
    /// Producer-side send time for the freshness gate (NEW-4). ALWAYS
    /// emitted (no `skip_serializing_if`) so it sits inside the signed HMAC
    /// body. The consumer rejects the message when this lies outside ±skew
    /// of its own clock.
    pub issued_at: DateTime<Utc>,
    /// HMAC-SHA256 of the JSON-serialized message body (CONTRACT.md §8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac_signature: Option<String>,
}
