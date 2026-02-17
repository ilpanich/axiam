//! Service account domain model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::user::UserStatus;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccount {
    pub id: Uuid,
    pub name: String,
    pub client_id: String,
    pub client_secret_hash: String,
    pub status: UserStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
