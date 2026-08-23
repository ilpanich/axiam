//! Role domain model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
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

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateRole {
    pub tenant_id: Uuid,
    pub name: String,
    pub description: String,
    pub is_global: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct UpdateRole {
    pub name: Option<String>,
    pub description: Option<String>,
    pub is_global: Option<bool>,
}

/// A role together with its assignment context (the resource it is scoped to).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RoleAssignment {
    pub role: Role,
    /// `None` means the role was assigned globally (no resource scope).
    pub resource_id: Option<Uuid>,
}

/// One `has_role` edge seen from the *role's* side: which subject holds the
/// assignment, and the resource it is scoped to.
///
/// `has_role` carries a `UNIQUE(in, out)` index, so a subject holds a given
/// role at most once — this is one row per subject, same as listing subject
/// ids. What it adds is `resource_id`, and that field is not decoration: an
/// unassign that does not name it deletes the edge whose `resource_id` is
/// `NONE`, so revoking a resource-scoped grant without it silently deletes
/// nothing.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RoleSubjectAssignment {
    /// The user or group holding the assignment.
    pub subject_id: Uuid,
    /// `None` means the role was assigned globally (no resource scope).
    pub resource_id: Option<Uuid>,
}
