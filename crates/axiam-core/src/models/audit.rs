//! Audit log domain model.
//!
//! Audit logs are append-only — no UPDATE or DELETE operations are permitted.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub enum ActorType {
    User,
    ServiceAccount,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub enum AuditOutcome {
    Success,
    Failure,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub actor_id: Uuid,
    pub actor_type: ActorType,
    pub action: String,
    pub resource_id: Option<Uuid>,
    pub outcome: AuditOutcome,
    pub ip_address: Option<String>,
    pub metadata: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAuditLogEntry {
    pub tenant_id: Uuid,
    pub actor_id: Uuid,
    pub actor_type: ActorType,
    pub action: String,
    pub resource_id: Option<Uuid>,
    pub outcome: AuditOutcome,
    pub ip_address: Option<String>,
    pub metadata: Option<serde_json::Value>,
}
