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
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

pub use axiam_core::models::mail::{MailType, OutboundMailMessage};

type HmacSha256 = Hmac<Sha256>;

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
    /// HMAC-SHA256 of the JSON-serialized message body (this field set to null).
    /// Computed with the per-tenant AMQP signing key (SEC-022).
    /// Consumer MUST verify this before processing. Missing signature is
    /// acceptable during a rolling deployment but should be rejected in strict mode.
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
    /// HMAC-SHA256 of the JSON-serialized message body (SEC-022/055).
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
            hmac_signature: None,
        };
        let json = serde_json::to_string(&req).expect("serialize");
        assert!(
            !json.contains("hmac_signature"),
            "hmac_signature must be omitted when None"
        );
    }
}
