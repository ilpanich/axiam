//! Outbound mail message types for async delivery (D-14).
//!
//! These types are defined in `axiam-core` so that both `axiam-audit`
//! (which cannot depend on `axiam-amqp` due to the circular-dep constraint)
//! and `axiam-api-rest` can build outbound mail messages without coupling to
//! the AMQP infrastructure layer.  `axiam-amqp` re-exports these types and
//! provides the concrete AMQP publishing implementation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
/// audit events (D-16).  Consumers MUST exclude it from any audit records
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
