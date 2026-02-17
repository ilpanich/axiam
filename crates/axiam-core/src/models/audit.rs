//! Audit log domain model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActorType {
    User,
    ServiceAccount,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditOutcome {
    Success,
    Failure,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub actor_id: Uuid,
    pub actor_type: ActorType,
    pub action: String,
    pub resource_id: Option<Uuid>,
    pub outcome: AuditOutcome,
    pub ip_address: Option<String>,
    pub metadata: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}
