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
use hmac::{Hmac, Mac};
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

/// Current message envelope key version (SECHRD-08 / D-05b). Bump this when
/// rotating the master signing key; `key_version` travels on the wire so a
/// verifier always derives the subkey the publisher actually used.
pub const CURRENT_KEY_VERSION: u8 = 1;

fn default_key_version() -> u8 {
    CURRENT_KEY_VERSION
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
            hmac_signature: Some("abc123".into()),
        };
        let json = serde_json::to_string(&req).expect("serialize");
        assert!(
            json.contains("hmac_signature"),
            "hmac_signature must be in JSON when Some"
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
            hmac_signature: None,
        };
        let json = serde_json::to_string(&req).expect("serialize");
        assert!(
            !json.contains("hmac_signature"),
            "hmac_signature must be omitted when None"
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
