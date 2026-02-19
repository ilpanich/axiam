//! Resource domain model.
//!
//! Resources are organized hierarchically via `parent_id`.
//! Role assignments on parent resources cascade to children unless overridden.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    /// The type of resource (e.g., `project`, `service`, `endpoint`).
    pub resource_type: String,
    /// Parent resource ID for hierarchical organization. `None` for root resources.
    pub parent_id: Option<Uuid>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateResource {
    pub tenant_id: Uuid,
    pub name: String,
    pub resource_type: String,
    pub parent_id: Option<Uuid>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateResource {
    pub name: Option<String>,
    pub resource_type: Option<String>,
    pub parent_id: Option<Option<Uuid>>,
    pub metadata: Option<serde_json::Value>,
}
