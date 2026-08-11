//! Resource domain model.
//!
//! Resources are organized hierarchically via `parent_id`.
//! Role assignments on parent resources cascade to children unless overridden.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Resource {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    /// The type of resource (e.g., `project`, `service`, `endpoint`).
    pub resource_type: String,
    /// Parent resource ID for hierarchical organization. `None` for root resources.
    pub parent_id: Option<Uuid>,
    pub metadata: serde_json::Value,
    /// The `client_id` that registered this resource through the UMA
    /// Protection API (X2), or `None` for a resource created any other way.
    ///
    /// Read-only from every ordinary path: [`UpdateResource`] cannot set it and
    /// [`CreateResource`] cannot either, so the only writer is the
    /// resource-registration handler. That is deliberate — the field backs a
    /// provenance badge in the admin UI, and a provenance marker anyone can
    /// write is decoration that reads like evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uma_registered_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateResource {
    pub tenant_id: Uuid,
    pub name: String,
    pub resource_type: String,
    pub parent_id: Option<Uuid>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct UpdateResource {
    pub name: Option<String>,
    pub resource_type: Option<String>,
    pub parent_id: Option<Option<Uuid>>,
    pub metadata: Option<serde_json::Value>,
}
