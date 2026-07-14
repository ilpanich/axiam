//! AMQP message types for serialization/deserialization.
//!
//! `MailType` and `OutboundMailMessage` are defined in `axiam-core::models::mail`
//! so that crates which cannot depend on `axiam-amqp` (e.g. `axiam-audit`) can
//! still build outbound mail messages.  They are re-exported here for convenience.
//!
//! SEC-022/055: `AuthzRequest` and `AuditEventMessage` carry an HMAC-SHA256
//! signature over the serialized payload body. Publishers set it; consumers
//! verify it. The signing key is a per-tenant AMQP signing secret.
//!
//! SEC-055: The `to_address` field in `OutboundMailMessage` is treated as
//! advisory; the actual recipient is always resolved server-side from
//! `user_id` + `tenant_id` to prevent recipient hijacking.

use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

pub use axiam_core::models::mail::{MailType, OutboundMailMessage};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// HKDF per-tenant key derivation (SECHRD-08 / D-05a/b)
// ---------------------------------------------------------------------------

/// Fixed application-level salt for HKDF tenant-key derivation. HKDF salts
/// are not secret; domain separation comes from the `info` parameter below.
const APP_SALT: &[u8] = b"axiam-amqp-hkdf-salt-v1";

/// Fixed domain-separation tag mixed into HKDF's `info` parameter so a
/// derived AMQP signing subkey can never collide with a subkey derived for
/// any other purpose from the same master key.
const DOMAIN_TAG: &[u8] = b"axiam-amqp-v1";

/// Current message envelope key version (SECHRD-08 / D-05b, NEW-4). Bump this
/// when rotating the master signing key OR when changing the signed envelope
/// shape; `key_version` travels on the wire so a verifier always derives the
/// subkey the publisher actually used.
///
/// NEW-4 (v2): the signed body now MUST carry a `nonce` + `issued_at` for
/// replay protection. Consumers **reject** (nack, requeue:false) any message
/// with `key_version < 2` — this is a hard cutover, there is no v1 grace path.
pub const CURRENT_KEY_VERSION: u8 = 2;

/// Minimum accepted envelope key version (NEW-4 hard cutover). Any message
/// with `key_version` below this is rejected outright — it predates the
/// mandatory `nonce`/`issued_at` replay-protection fields.
pub const MIN_ACCEPTED_KEY_VERSION: u8 = 2;

/// Default freshness skew for the `issued_at` acceptance window (NEW-4).
/// A message is accepted only when its `issued_at` lies within ±5 minutes of
/// the consumer's current clock. This bounds both clock drift and how long a
/// captured message stays replay-eligible before the freshness gate rejects it.
pub const DEFAULT_FRESHNESS_SKEW_SECS: i64 = 300;

fn default_key_version() -> u8 {
    CURRENT_KEY_VERSION
}

/// Serde default for `nonce` (NEW-4). A v1 message lacks this field; it
/// deserializes to the nil UUID and is then rejected by the `key_version < 2`
/// gate before the nonce is ever consulted, so the concrete value is inert.
fn default_nonce() -> Uuid {
    Uuid::nil()
}

/// Serde default for `issued_at` (NEW-4). A v1 message lacks this field; it
/// deserializes to the Unix epoch — far outside any freshness window — so a
/// message that somehow bypassed the `key_version` gate would still fail the
/// freshness check. `from_timestamp(0, 0)` is infallible for a constant.
fn default_issued_at() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(0, 0).expect("epoch is a valid timestamp")
}

/// Return `true` when `issued_at` lies within `±skew` of `now` (NEW-4).
///
/// This is the freshness gate for AMQP replay protection: a captured message
/// can only be replayed successfully inside this window, and the durable
/// nonce store rejects duplicates within it. `skew` bounds legitimate clock
/// drift between producer and consumer; [`DEFAULT_FRESHNESS_SKEW_SECS`] is the
/// default.
pub fn is_fresh(issued_at: DateTime<Utc>, now: DateTime<Utc>, skew: chrono::Duration) -> bool {
    now.signed_duration_since(issued_at).abs() <= skew
}

/// Derive a per-tenant AMQP signing subkey from the shared master key
/// (SECHRD-08 / D-05a/b, T-25-19).
///
/// Uses HKDF-SHA256 (`hkdf::Hkdf<Sha256>`) — never hand-rolled concatenation
/// hashing. The `info` parameter is domain-separated (fixed tag) and
/// versioned (`key_version`) then tenant-scoped (`tenant_id`), so:
/// - A signature produced with tenant A's subkey never verifies under
///   tenant B's subkey, even though both derive from the same master key.
/// - Bumping `key_version` (master key rotation) yields an entirely
///   different subkey for the same tenant, without breaking in-flight
///   messages signed under the prior version (D-05b).
pub fn derive_tenant_key(master: &[u8], tenant_id: Uuid, key_version: u8) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(APP_SALT), master);
    let mut info = Vec::with_capacity(DOMAIN_TAG.len() + 1 + 16);
    info.extend_from_slice(DOMAIN_TAG);
    info.push(key_version);
    info.extend_from_slice(tenant_id.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

// ---------------------------------------------------------------------------
// HMAC helpers (SEC-022)
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA256 of the JSON-serialized message payload.
///
/// The `hmac_signature` field must be set to `None` (or absent) before
/// serializing `payload_json` — otherwise the signature is over a message
/// that includes a placeholder signature, making verification impossible.
/// Use [`sign_payload`] to produce the canonical JSON before signing.
pub fn sign_payload(key: &[u8], payload_json: &[u8]) -> String {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(payload_json);
    hex::encode(mac.finalize().into_bytes())
}

/// Verify an HMAC-SHA256 signature over the canonical payload bytes.
///
/// Returns `true` if the signature matches. Uses constant-time comparison
/// internally (via the `hmac` crate's `verify_slice`).
pub fn verify_payload(key: &[u8], payload_json: &[u8], signature_hex: &str) -> bool {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(payload_json);
    let expected = hex::decode(signature_hex).unwrap_or_default();
    mac.verify_slice(&expected).is_ok()
}

/// Verify a signed AMQP envelope against its per-tenant derived subkey
/// (SECHRD-08 / D-05a/b/c).
///
/// Derives the tenant's subkey from `master_key` + `tenant_id` +
/// `key_version`, then verifies `signature` over `canonical_bytes`.
///
/// Returns `false` when `signature` is `None` (unsigned) OR the signature
/// does not verify — there is no accept-when-absent code path. Consumers
/// MUST reject (nack, never process) whenever this returns `false`
/// (T-25-20).
pub fn verify_tenant_signature(
    master_key: &[u8],
    tenant_id: Uuid,
    key_version: u8,
    canonical_bytes: &[u8],
    signature: Option<&str>,
) -> bool {
    let subkey = derive_tenant_key(master_key, tenant_id, key_version);
    signature.is_some_and(|sig| verify_payload(&subkey, canonical_bytes, sig))
}

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// Authorization check request received from `axiam.authz.request`.
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
    /// HKDF master-key rotation version (SECHRD-08 / D-05b). Selects which
    /// per-tenant subkey derivation the signature was produced with.
    #[serde(default = "default_key_version")]
    pub key_version: u8,
    /// Per-message unique nonce for replay protection (NEW-4). ALWAYS emitted
    /// (no `skip_serializing_if`) so it is inside the signed HMAC body. The
    /// consumer records it in the durable `amqp_nonce_replay` store; a
    /// duplicate within the freshness window is a replay and is rejected.
    #[serde(default = "default_nonce")]
    pub nonce: Uuid,
    /// Producer-side send time for the freshness gate (NEW-4). ALWAYS emitted
    /// (no `skip_serializing_if`) so it is inside the signed HMAC body. The
    /// consumer rejects the message if this lies outside ±skew of its clock.
    #[serde(default = "default_issued_at")]
    pub issued_at: DateTime<Utc>,
    /// HMAC-SHA256 of the JSON-serialized message body (this field set to null).
    /// Computed with the per-tenant subkey derived via [`derive_tenant_key`]
    /// (SECHRD-08 / D-05a/b). Mandatory — the consumer rejects both unsigned
    /// and invalid-signature messages; there is no fail-open path (D-05c).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac_signature: Option<String>,
}

/// Authorization decision published to `axiam.authz.response`.
#[derive(Debug, Serialize)]
pub struct AuthzResponse {
    pub correlation_id: Uuid,
    pub allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Audit event received from external services via `axiam.audit.events`.
///
/// Maps directly to `CreateAuditLogEntry` from `axiam-core`.
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
    /// HKDF master-key rotation version (SECHRD-08 / D-05b). Selects which
    /// per-tenant subkey derivation the signature was produced with.
    #[serde(default = "default_key_version")]
    pub key_version: u8,
    /// Per-message unique nonce for replay protection (NEW-4). ALWAYS emitted
    /// (no `skip_serializing_if`) so it is inside the signed HMAC body. The
    /// consumer records it in the durable `amqp_nonce_replay` store; a
    /// duplicate within the freshness window is a replay and is rejected.
    #[serde(default = "default_nonce")]
    pub nonce: Uuid,
    /// Producer-side send time for the freshness gate (NEW-4). ALWAYS emitted
    /// (no `skip_serializing_if`) so it is inside the signed HMAC body. The
    /// consumer rejects the message if this lies outside ±skew of its clock.
    #[serde(default = "default_issued_at")]
    pub issued_at: DateTime<Utc>,
    /// HMAC-SHA256 of the JSON-serialized message body (SEC-022/055).
    /// Computed with the per-tenant subkey derived via [`derive_tenant_key`]
    /// (SECHRD-08 / D-05a/b). Mandatory — the consumer rejects both unsigned
    /// and invalid-signature messages; there is no fail-open path (D-05c).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac_signature: Option<String>,
}

/// Notification event published to `axiam.notifications`.
///
/// Carries event type, tenant context, and event-specific payload.
#[derive(Debug, Clone, Serialize)]
pub struct NotificationEvent {
    pub event_type: String,
    pub tenant_id: Uuid,
    pub actor_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<Uuid>,
    pub timestamp: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Webhook delivery message carried on the `axiam.webhook` /
/// `axiam.webhook.retry` queues (CORR-03/D-07).
///
/// Produced by `WebhookDeliveryService::emit` (`axiam-api-rest`), consumed
/// by the webhook AMQP consumer (wired in 26-07) which drives
/// `WebhookDeliveryService::deliver_once` per (re)delivery. `attempt` is
/// incremented by the consumer on each republish to the retry queue and
/// checked against `AXIAM__WEBHOOK__MAX_ATTEMPTS` before a terminal nack
/// routes the message to `WEBHOOK_DLQ` (D-07).
///
/// `tenant_id` is not in the plan's original DTO sketch, but is required
/// for `deliver_once` to resolve the webhook via the tenant-scoped
/// `WebhookRepository::get_by_id` without a cross-tenant lookup — AXIAM's
/// multi-tenant data-isolation model requires every domain-entity lookup to
/// be tenant-scoped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookMessage {
    pub webhook_id: Uuid,
    pub delivery_id: Uuid,
    pub tenant_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub attempt: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample_message(mail_type: MailType) -> OutboundMailMessage {
        OutboundMailMessage {
            mail_type,
            tenant_id: Uuid::nil(),
            org_id: Uuid::nil(),
            user_id: Uuid::nil(),
            to_address: "user@example.com".to_string(),
            template_context: serde_json::json!({"key": "value"}),
            attempt_count: 0,
            enqueued_at: Utc.with_ymd_and_hms(2026, 6, 2, 0, 0, 0).unwrap(),
        }
    }

    #[test]
    fn outbound_mail_message_serde_round_trip() {
        let variants = [
            MailType::PasswordReset,
            MailType::EmailVerification,
            MailType::Notification,
            MailType::DeletionCancel,
            MailType::ExportReady,
        ];

        for variant in variants {
            let msg = sample_message(variant);
            let json = serde_json::to_string(&msg).expect("serialize");
            let decoded: OutboundMailMessage = serde_json::from_str(&json).expect("deserialize");

            // Verify structural fields survive round-trip
            assert_eq!(decoded.to_address, "user@example.com");
            assert_eq!(decoded.attempt_count, 0);
            assert_eq!(decoded.tenant_id, Uuid::nil());
        }
    }

    #[test]
    fn mail_type_snake_case_serialization() {
        assert_eq!(
            serde_json::to_string(&MailType::PasswordReset).unwrap(),
            r#""password_reset""#
        );
        assert_eq!(
            serde_json::to_string(&MailType::EmailVerification).unwrap(),
            r#""email_verification""#
        );
        assert_eq!(
            serde_json::to_string(&MailType::Notification).unwrap(),
            r#""notification""#
        );
        assert_eq!(
            serde_json::to_string(&MailType::DeletionCancel).unwrap(),
            r#""deletion_cancel""#
        );
        assert_eq!(
            serde_json::to_string(&MailType::ExportReady).unwrap(),
            r#""export_ready""#
        );
    }

    // SEC-022: HMAC sign/verify round-trip
    #[test]
    fn amqp_hmac_sign_verify_round_trip() {
        let key = b"test-amqp-signing-key";
        let payload = b"{\"tenant_id\":\"...\",\"action\":\"read\"}";
        let sig = sign_payload(key, payload);
        assert!(!sig.is_empty());
        assert!(
            verify_payload(key, payload, &sig),
            "valid signature must verify"
        );
    }

    #[test]
    fn amqp_hmac_wrong_key_fails_verify() {
        let key1 = b"key-one";
        let key2 = b"key-two";
        let payload = b"some-payload";
        let sig = sign_payload(key1, payload);
        assert!(
            !verify_payload(key2, payload, &sig),
            "wrong key must not verify"
        );
    }

    #[test]
    fn amqp_hmac_tampered_payload_fails_verify() {
        let key = b"hmac-key";
        let payload = b"original-payload";
        let tampered = b"tampered-payload";
        let sig = sign_payload(key, payload);
        assert!(
            !verify_payload(key, tampered, &sig),
            "tampered payload must not verify"
        );
    }

    // SEC-022: AuthzRequest carries hmac_signature field
    #[test]
    fn authz_request_hmac_signature_serializes_when_present() {
        let req = AuthzRequest {
            correlation_id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            subject_id: Uuid::nil(),
            action: "read".into(),
            resource_id: Uuid::nil(),
            scope: None,
            key_version: CURRENT_KEY_VERSION,
            nonce: Uuid::nil(),
            issued_at: Utc.with_ymd_and_hms(2026, 7, 10, 0, 0, 0).unwrap(),
            hmac_signature: Some("abc123".into()),
        };
        let json = serde_json::to_string(&req).expect("serialize");
        assert!(
            json.contains("hmac_signature"),
            "hmac_signature must be in JSON when Some"
        );
        // NEW-4: nonce + issued_at are always emitted (inside the signed body).
        assert!(json.contains("nonce"), "nonce must always be serialized");
        assert!(
            json.contains("issued_at"),
            "issued_at must always be serialized"
        );
    }

    #[test]
    fn authz_request_hmac_signature_omitted_when_none() {
        let req = AuthzRequest {
            correlation_id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            subject_id: Uuid::nil(),
            action: "read".into(),
            resource_id: Uuid::nil(),
            scope: None,
            key_version: CURRENT_KEY_VERSION,
            nonce: Uuid::nil(),
            issued_at: Utc.with_ymd_and_hms(2026, 7, 10, 0, 0, 0).unwrap(),
            hmac_signature: None,
        };
        let json = serde_json::to_string(&req).expect("serialize");
        assert!(
            !json.contains("hmac_signature"),
            "hmac_signature must be omitted when None"
        );
    }

    // NEW-4: field/wire order of the signed AuthzRequest body is
    // correlation_id, tenant_id, subject_id, action, resource_id,
    // scope?, key_version, nonce, issued_at, hmac_signature? — this order is
    // load-bearing (the HMAC is computed over these bytes) and the SDKs
    // reproduce it byte-for-byte.
    #[test]
    fn authz_request_canonical_field_order() {
        let req = AuthzRequest {
            correlation_id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            subject_id: Uuid::nil(),
            action: "read".into(),
            resource_id: Uuid::nil(),
            scope: Some("s".into()),
            key_version: CURRENT_KEY_VERSION,
            nonce: Uuid::nil(),
            issued_at: Utc.with_ymd_and_hms(2026, 7, 10, 0, 0, 0).unwrap(),
            hmac_signature: None,
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let expected = [
            "correlation_id",
            "tenant_id",
            "subject_id",
            "action",
            "resource_id",
            "scope",
            "key_version",
            "nonce",
            "issued_at",
        ];
        let positions: Vec<usize> = expected
            .iter()
            .map(|f| json.find(&format!("\"{f}\"")).expect("field present"))
            .collect();
        let mut sorted = positions.clone();
        sorted.sort_unstable();
        assert_eq!(
            positions, sorted,
            "AuthzRequest fields must serialize in declaration order (NEW-4 wire order)"
        );
    }

    #[test]
    fn is_fresh_accepts_within_and_rejects_outside_skew() {
        let now = Utc.with_ymd_and_hms(2026, 7, 10, 12, 0, 0).unwrap();
        let skew = chrono::Duration::seconds(DEFAULT_FRESHNESS_SKEW_SECS);
        assert!(is_fresh(now, now, skew), "exact-now must be fresh");
        assert!(
            is_fresh(now - chrono::Duration::seconds(299), now, skew),
            "within skew (past) must be fresh"
        );
        assert!(
            is_fresh(now + chrono::Duration::seconds(299), now, skew),
            "within skew (future clock drift) must be fresh"
        );
        assert!(
            !is_fresh(now - chrono::Duration::seconds(301), now, skew),
            "stale past must be rejected"
        );
        assert!(
            !is_fresh(now + chrono::Duration::seconds(301), now, skew),
            "too-far-future must be rejected"
        );
    }

    // SECHRD-08 / D-05a/b: HKDF per-tenant key derivation.
    #[test]
    fn derive_tenant_key_is_deterministic_and_versioned() {
        let master = b"shared-amqp-master-key";
        let tenant = Uuid::new_v4();

        let k1 = derive_tenant_key(master, tenant, 1);
        let k2 = derive_tenant_key(master, tenant, 1);
        assert_eq!(k1, k2, "same inputs must derive the same key");

        let k_v2 = derive_tenant_key(master, tenant, 2);
        assert_ne!(
            k1, k_v2,
            "a different key_version must derive a different key"
        );
    }

    // SECHRD-08 / T-25-19 (SC #5a): a tenant-A signature must not validate
    // under tenant-B's derived subkey, even from the same master key.
    #[test]
    fn per_tenant_signature_cross_tenant_rejected() {
        let master = b"shared-amqp-master-key";
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();
        let key_version = 1;

        let subkey_a = derive_tenant_key(master, tenant_a, key_version);
        let subkey_b = derive_tenant_key(master, tenant_b, key_version);
        assert_ne!(
            subkey_a, subkey_b,
            "different tenants must derive different subkeys"
        );

        let payload = b"{\"tenant_id\":\"a\",\"action\":\"read\"}";
        let sig = sign_payload(&subkey_a, payload);

        assert!(
            verify_payload(&subkey_a, payload, &sig),
            "tenant A's own signature must verify under tenant A's subkey"
        );
        assert!(
            !verify_payload(&subkey_b, payload, &sig),
            "tenant A's signature must NOT verify under tenant B's subkey (T-25-19)"
        );

        // Exercise via the consumer-facing wrapper too.
        assert!(verify_tenant_signature(
            master,
            tenant_a,
            key_version,
            payload,
            Some(&sig)
        ));
        assert!(!verify_tenant_signature(
            master,
            tenant_b,
            key_version,
            payload,
            Some(&sig)
        ));
    }

    // SECHRD-08 / T-25-20: unsigned messages must be rejected — no fail-open
    // "accept when absent" branch.
    #[test]
    fn verify_tenant_signature_rejects_unsigned_message() {
        let master = b"shared-amqp-master-key";
        let tenant = Uuid::new_v4();
        let payload = b"unsigned-audit-event";

        assert!(
            !verify_tenant_signature(master, tenant, CURRENT_KEY_VERSION, payload, None),
            "absent signature must be rejected — no fail-open path (SECHRD-08 / T-25-20)"
        );
    }

    #[test]
    fn verify_tenant_signature_rejects_tampered_payload() {
        let master = b"shared-amqp-master-key";
        let tenant = Uuid::new_v4();
        let payload = b"original-authz-request";
        let tampered = b"tampered-authz-request";
        let subkey = derive_tenant_key(master, tenant, CURRENT_KEY_VERSION);
        let sig = sign_payload(&subkey, payload);

        assert!(
            !verify_tenant_signature(master, tenant, CURRENT_KEY_VERSION, tampered, Some(&sig)),
            "tampered payload must not verify"
        );
    }

    #[test]
    fn verify_tenant_signature_rejects_invalid_hex_signature() {
        let master = b"shared-amqp-master-key";
        let tenant = Uuid::new_v4();
        let payload = b"some-audit-event";

        assert!(
            !verify_tenant_signature(
                master,
                tenant,
                CURRENT_KEY_VERSION,
                payload,
                Some("not-valid-hex!!")
            ),
            "malformed signature hex must not verify"
        );
    }
}
