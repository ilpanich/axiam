//! Permission domain model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// The action this permission represents (e.g., `read`, `write`, `delete`).
    pub action: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePermission {
    pub tenant_id: Uuid,
    pub action: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdatePermission {
    pub action: Option<String>,
    pub description: Option<String>,
}
