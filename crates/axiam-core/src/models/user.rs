//! User domain model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub enum UserStatus {
    Active,
    Inactive,
    Locked,
    PendingVerification,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
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
    pub failed_login_attempts: u32,
    pub last_failed_login_at: Option<DateTime<Utc>>,
    pub locked_until: Option<DateTime<Utc>>,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateUser {
    pub tenant_id: Uuid,
    pub username: String,
    pub email: String,
    /// Raw password (will be hashed with Argon2id before storage).
    pub password: String,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct UpdateUser {
    pub username: Option<String>,
    pub email: Option<String>,
    /// Internal-only field set programmatically after Argon2id hashing.
    /// Never accepted from or exposed to API consumers.
    #[serde(skip)]
    #[schema(ignore = true)]
    pub password_hash: Option<String>,
    pub status: Option<UserStatus>,
    pub metadata: Option<serde_json::Value>,
    pub mfa_enabled: Option<bool>,
    /// `Some(Some(val))` = set, `Some(None)` = clear, `None` = no change.
    pub mfa_secret: Option<Option<String>>,
    pub failed_login_attempts: Option<u32>,
    pub last_failed_login_at: Option<Option<DateTime<Utc>>>,
    pub locked_until: Option<Option<DateTime<Utc>>>,
    /// `Some(Some(val))` = set, `Some(None)` = clear, `None` = no change.
    pub email_verified_at: Option<Option<DateTime<Utc>>>,
}
