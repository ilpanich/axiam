//! Role domain model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: String,
    /// Global roles grant permissions across all resources.
    pub is_global: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRole {
    pub tenant_id: Uuid,
    pub name: String,
    pub description: String,
    pub is_global: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateRole {
    pub name: Option<String>,
    pub description: Option<String>,
    pub is_global: Option<bool>,
}

/// A role together with its assignment context (the resource it is scoped to).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleAssignment {
    pub role: Role,
    /// `None` means the role was assigned globally (no resource scope).
    pub resource_id: Option<Uuid>,
}
