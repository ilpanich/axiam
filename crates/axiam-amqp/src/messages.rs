//! AMQP message types for serialization/deserialization.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

/// Mail type variants for async outbound delivery (D-14).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailType {
    PasswordReset,
    EmailVerification,
    Notification,
    DeletionCancel,
    ExportReady,
}

/// Outbound mail message published to `axiam.mail.outbound` (D-14).
///
/// All fields except `to_address` are safe to include in audit metadata.
/// `to_address` is present for delivery only — **MUST NOT** be logged in
/// audit events (D-16). Consumers MUST exclude it from any audit records
/// they produce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundMailMessage {
    pub mail_type: MailType,
    pub tenant_id: Uuid,
    pub org_id: Uuid,
    pub user_id: Uuid,
    /// Delivery address — present for SMTP delivery only.
    /// **MUST NOT** appear in audit log metadata (D-16).
    pub to_address: String,
    pub template_context: serde_json::Value,
    pub attempt_count: u32,
    pub enqueued_at: DateTime<Utc>,
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
