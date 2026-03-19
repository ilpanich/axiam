//! Password history model for reuse prevention.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A stored password hash entry for history-based reuse detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordHistoryEntry {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
}

/// Input for creating a new password history entry.
#[derive(Debug, Clone)]
pub struct CreatePasswordHistoryEntry {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub password_hash: String,
}
