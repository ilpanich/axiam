//! Scope domain model.
//!
//! Scopes define fine-grained sub-resource permissions within a resource.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// The resource this scope belongs to.
    pub resource_id: Uuid,
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScope {
    pub tenant_id: Uuid,
    pub resource_id: Uuid,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateScope {
    pub name: Option<String>,
    pub description: Option<String>,
}
