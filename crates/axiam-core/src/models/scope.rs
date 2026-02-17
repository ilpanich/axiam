//! Scope domain model.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    pub id: Uuid,
    pub resource_id: Uuid,
    pub name: String,
    pub description: String,
}
