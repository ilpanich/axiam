//! User domain model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum UserStatus {
    Active,
    Inactive,
    Locked,
    PendingVerification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub status: UserStatus,
    pub mfa_enabled: bool,
    /// AES-256-GCM encrypted TOTP secret (if MFA is enrolled).
    pub mfa_secret: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUser {
    pub tenant_id: Uuid,
    pub username: String,
    pub email: String,
    /// Raw password (will be hashed with Argon2id before storage).
    pub password: String,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateUser {
    pub username: Option<String>,
    pub email: Option<String>,
    pub status: Option<UserStatus>,
    pub metadata: Option<serde_json::Value>,
    pub mfa_enabled: Option<bool>,
    /// `Some(Some(val))` = set, `Some(None)` = clear, `None` = no change.
    pub mfa_secret: Option<Option<String>>,
}
