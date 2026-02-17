//! Role domain model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub is_global: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
