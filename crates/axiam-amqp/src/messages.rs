//! AMQP message types for serialization/deserialization.
//!
//! `MailType` and `OutboundMailMessage` are defined in `axiam-core::models::mail`
//! so that crates which cannot depend on `axiam-amqp` (e.g. `axiam-audit`) can
//! still build outbound mail messages.  They are re-exported here for convenience.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use axiam_core::models::mail::{MailType, OutboundMailMessage};

/// Authorization check request received from `axiam.authz.request`.
#[derive(Debug, Deserialize)]
pub struct AuthzRequest {
    /// Caller-provided ID to correlate request with response.
    pub correlation_id: Uuid,
    pub tenant_id: Uuid,
    pub subject_id: Uuid,
    pub action: String,
    pub resource_id: Uuid,
    #[serde(default)]
    pub scope: Option<String>,
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
#[derive(Debug, Deserialize)]
pub struct AuditEventMessage {
    pub tenant_id: Uuid,
    pub actor_id: Uuid,
    pub actor_type: String,
    pub action: String,
    #[serde(default)]
    pub resource_id: Option<Uuid>,
    pub outcome: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
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
}
