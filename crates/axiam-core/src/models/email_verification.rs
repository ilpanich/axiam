//! Email verification token model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A hashed email verification token stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailVerificationToken {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    /// SHA-256 hash of the raw token (raw token is never stored).
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Input for creating a new verification token.
#[derive(Debug, Clone)]
pub struct CreateEmailVerificationToken {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
}
