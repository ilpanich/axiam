//! Resource domain model.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub id: Uuid,
    pub name: String,
    pub resource_type: String,
    pub parent_id: Option<Uuid>,
    pub metadata: serde_json::Value,
}
