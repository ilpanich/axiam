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
    /// User has been anonymized in-place following Art. 17 erasure (D-05).
    Anonymized,
    /// Removed by an administrator through `DELETE /api/v1/users/{id}`.
    ///
    /// An anonymised tombstone, not a row deletion. The audit trail is
    /// append-only and references actors by id, so hard-deleting the row would
    /// leave every entry the user ever produced pointing at nothing — and an
    /// audit log you cannot resolve to a person is not an audit log.
    ///
    /// What the row keeps is its id. `username` and `email` are overwritten
    /// with values derived from that id, `metadata` is emptied, and every
    /// credential is cleared, so the tombstone holds no personal data: keeping
    /// someone's address on it indefinitely would be retention with the UI
    /// hidden, not erasure. Overwriting rather than hiding is also what frees
    /// the identifiers from their unique indexes, so the person can register
    /// again — which erasure has to leave them able to do.
    ///
    /// Distinct from [`Self::Inactive`], the reversible "suspended" state an
    /// administrator sets from the edit dialog. Reusing that for deletion is
    /// what made `DELETE` look like it did nothing: the user stayed in the
    /// list, in their groups, holding their roles, with live sessions.
    ///
    /// Distinct from [`Self::Anonymized`] in evidence rather than in effect.
    /// That is the scheduled Art. 17 pipeline, which does everything this does
    /// AND pseudonymises the audit log's actor references with a keyed HMAC
    /// before writing a signed erasure proof. This is the immediate operational
    /// removal an administrator performs; that is the certified one a data
    /// subject requests.
    Deleted,
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
    /// The TOTP time-step counter value last successfully verified.
    ///
    /// Used to prevent replay attacks: a code whose step ≤ this value is
    /// rejected even if the HMAC is correct (SEC-008).
    pub totp_last_used_step: Option<u64>,
    pub failed_login_attempts: u32,
    pub last_failed_login_at: Option<DateTime<Utc>>,
    pub locked_until: Option<DateTime<Utc>>,
    pub email_verified_at: Option<DateTime<Utc>>,
    /// GDPR Art. 17 — set when user requests account deletion (D-08).
    pub deletion_pending: bool,
    /// Scheduled purge date when `deletion_pending` is true (D-08).
    pub scheduled_purge_at: Option<DateTime<Utc>>,
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
    /// `Some(Some(val))` = set, `Some(None)` = clear, `None` = no change.
    pub totp_last_used_step: Option<Option<u64>>,
    pub failed_login_attempts: Option<u32>,
    pub last_failed_login_at: Option<Option<DateTime<Utc>>>,
    pub locked_until: Option<Option<DateTime<Utc>>>,
    /// `Some(Some(val))` = set, `Some(None)` = clear, `None` = no change.
    pub email_verified_at: Option<Option<DateTime<Utc>>>,
}
