//! Group domain model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A group of users that can access resources based on their roles
/// and permissions. Groups simplify role management by allowing roles
/// to be assigned to a group rather than individual users.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Group {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: String,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateGroup {
    pub tenant_id: Uuid,
    pub name: String,
    pub description: String,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct UpdateGroup {
    pub name: Option<String>,
    pub description: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// How [`GroupRepository::add_directory_member`] left a (user, group) pair.
///
/// [`GroupRepository::add_directory_member`]: crate::repository::GroupRepository::add_directory_member
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryMembershipWrite {
    /// No edge existed; a directory-sourced one was written.
    Created,
    /// A directory-sourced edge already existed; nothing was written.
    AlreadyDirectory,
    /// An edge an administrator made by hand already exists. It was **not**
    /// changed and no second edge was written: the membership stays manual,
    /// and the directory will never remove it.
    AlreadyManual,
}
