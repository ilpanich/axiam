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
