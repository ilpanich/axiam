//! SurrealDB implementation of [`UserRepository`].
//!
//! Password hashing is delegated entirely to `axiam_auth::password::hash_password`
//! (Argon2id, OWASP-recommended parameters). An optional pepper (server-side
//! secret) can be provided at construction time via `with_pepper`.

use axiam_auth::password;
use axiam_core::error::AxiamResult;
use axiam_core::models::user::{CreateUser, UpdateUser, User, UserStatus};
use axiam_core::repository::{PaginatedResult, Pagination, UserRepository};
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

/// DB-side row struct for queries where the UUID is already known.
#[derive(Debug, SurrealValue)]
struct UserRow {
    tenant_id: String,
    username: String,
    email: String,
    password_hash: String,
    status: String,
    mfa_enabled: bool,
    mfa_secret: Option<String>,
    /// Last TOTP step that was successfully verified (SEC-008/REQ-14 AC-5).
    totp_last_used_step: Option<u64>,
    failed_login_attempts: u32,
    last_failed_login_at: Option<DateTime<Utc>>,
    locked_until: Option<DateTime<Utc>>,
    email_verified_at: Option<DateTime<Utc>>,
    /// GDPR Art. 17 — set when user requests account deletion (D-08).
    deletion_pending: Option<bool>,
    /// Scheduled purge date when deletion_pending is true (D-08).
    scheduled_purge_at: Option<DateTime<Utc>>,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// DB-side row struct that includes the record ID via `meta::id(id)`.
#[derive(Debug, SurrealValue)]
struct UserRowWithId {
    record_id: String,
    tenant_id: String,
    username: String,
    email: String,
    password_hash: String,
    status: String,
    mfa_enabled: bool,
    mfa_secret: Option<String>,
    /// Last TOTP step that was successfully verified (SEC-008/REQ-14 AC-5).
    totp_last_used_step: Option<u64>,
    failed_login_attempts: u32,
    last_failed_login_at: Option<DateTime<Utc>>,
    locked_until: Option<DateTime<Utc>>,
    email_verified_at: Option<DateTime<Utc>>,
    /// GDPR Art. 17 — set when user requests account deletion (D-08).
    deletion_pending: Option<bool>,
    /// Scheduled purge date when deletion_pending is true (D-08).
    scheduled_purge_at: Option<DateTime<Utc>>,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

fn parse_status(s: &str) -> Result<UserStatus, DbError> {
    match s {
        "Active" => Ok(UserStatus::Active),
        "Inactive" => Ok(UserStatus::Inactive),
        "Locked" => Ok(UserStatus::Locked),
        "PendingVerification" => Ok(UserStatus::PendingVerification),
        "Anonymized" => Ok(UserStatus::Anonymized),
        other => Err(DbError::Migration(format!("unknown user status: {other}"))),
    }
}

fn status_to_string(s: &UserStatus) -> &'static str {
    match s {
        UserStatus::Active => "Active",
        UserStatus::Inactive => "Inactive",
        UserStatus::Locked => "Locked",
        UserStatus::PendingVerification => "PendingVerification",
        UserStatus::Anonymized => "Anonymized",
    }
}

impl UserRow {
    fn into_user(self, id: Uuid) -> Result<User, DbError> {
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        Ok(User {
            id,
            tenant_id,
            username: self.username,
            email: self.email,
            password_hash: self.password_hash,
            status: parse_status(&self.status)?,
            mfa_enabled: self.mfa_enabled,
            mfa_secret: self.mfa_secret,
            totp_last_used_step: self.totp_last_used_step,
            failed_login_attempts: self.failed_login_attempts,
            last_failed_login_at: self.last_failed_login_at,
            locked_until: self.locked_until,
            email_verified_at: self.email_verified_at,
            deletion_pending: self.deletion_pending.unwrap_or(false),
            scheduled_purge_at: self.scheduled_purge_at,
            metadata: self.metadata,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

impl UserRowWithId {
    fn try_into_user(self) -> Result<User, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        Ok(User {
            id,
            tenant_id,
            username: self.username,
            email: self.email,
            password_hash: self.password_hash,
            status: parse_status(&self.status)?,
            mfa_enabled: self.mfa_enabled,
            mfa_secret: self.mfa_secret,
            totp_last_used_step: self.totp_last_used_step,
            failed_login_attempts: self.failed_login_attempts,
            last_failed_login_at: self.last_failed_login_at,
            locked_until: self.locked_until,
            email_verified_at: self.email_verified_at,
            deletion_pending: self.deletion_pending.unwrap_or(false),
            scheduled_purge_at: self.scheduled_purge_at,
            metadata: self.metadata,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Row struct for count queries.
#[derive(Debug, SurrealValue)]
struct CountRow {
    total: u64,
}

/// SurrealDB implementation of the User repository.
pub struct SurrealUserRepository<C: Connection> {
    db: Surreal<C>,
    /// Optional server-side pepper for password hashing.
    pepper: Option<String>,
}

impl<C: Connection> Clone for SurrealUserRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            pepper: self.pepper.clone(),
        }
    }
}

impl<C: Connection> SurrealUserRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db, pepper: None }
    }

    pub fn with_pepper(db: Surreal<C>, pepper: String) -> Self {
        Self {
            db,
            pepper: Some(pepper),
        }
    }
}

impl<C: Connection> UserRepository for SurrealUserRepository<C> {
    async fn create(&self, input: CreateUser) -> AxiamResult<User> {
        let id = Uuid::new_v4();
        let id_str = id.to_string();
        let tenant_id_str = input.tenant_id.to_string();

        let password_hash = password::hash_password(&input.password, self.pepper.as_deref())
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let metadata = input
            .metadata
            .unwrap_or(serde_json::Value::Object(Default::default()));

        let result = self
            .db
            .query(
                "CREATE type::record('user', $id) SET \
                 tenant_id = $tenant_id, \
                 username = $username, email = $email, \
                 password_hash = $password_hash, \
                 status = $status, \
                 mfa_enabled = false, \
                 failed_login_attempts = 0, \
                 last_failed_login_at = NONE, \
                 locked_until = NONE, \
                 email_verified_at = NONE, \
                 metadata = $metadata",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str))
            .bind(("username", input.username))
            .bind(("email", input.email))
            .bind(("password_hash", password_hash))
            .bind(("status", "PendingVerification".to_string()))
            .bind(("metadata", metadata))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<UserRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "user".into(),
            id: id_str,
        })?;

        Ok(row.into_user(id)?)
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<User> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let mut result = self
            .db
            .query(
                "SELECT * FROM type::record('user', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<UserRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "user".into(),
            id: id_str,
        })?;

        Ok(row.into_user(id)?)
    }

    async fn get_by_username(&self, tenant_id: Uuid, username: &str) -> AxiamResult<User> {
        let tenant_id_str = tenant_id.to_string();

        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM user \
                 WHERE tenant_id = $tenant_id AND username = $username",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("username", username.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<UserRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "user".into(),
            id: format!("username={username}"),
        })?;

        Ok(row.try_into_user()?)
    }

    async fn get_by_email(&self, tenant_id: Uuid, email: &str) -> AxiamResult<User> {
        let tenant_id_str = tenant_id.to_string();

        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM user \
                 WHERE tenant_id = $tenant_id AND email = $email",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("email", email.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<UserRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "user".into(),
            id: format!("email={email}"),
        })?;

        Ok(row.try_into_user()?)
    }

    async fn update(&self, tenant_id: Uuid, id: Uuid, input: UpdateUser) -> AxiamResult<User> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let mut sets = Vec::new();
        if input.username.is_some() {
            sets.push("username = $username");
        }
        if input.email.is_some() {
            sets.push("email = $email");
        }
        if input.password_hash.is_some() {
            sets.push("password_hash = $password_hash");
        }
        if input.status.is_some() {
            sets.push("status = $status");
        }
        if input.metadata.is_some() {
            sets.push("metadata = $metadata");
        }
        if input.mfa_enabled.is_some() {
            sets.push("mfa_enabled = $mfa_enabled");
        }
        if input.mfa_secret.is_some() {
            sets.push("mfa_secret = $mfa_secret");
        }
        if input.totp_last_used_step.is_some() {
            sets.push("totp_last_used_step = $totp_last_used_step");
        }
        if input.failed_login_attempts.is_some() {
            sets.push("failed_login_attempts = $failed_login_attempts");
        }
        if input.last_failed_login_at.is_some() {
            sets.push("last_failed_login_at = $last_failed_login_at");
        }
        if input.locked_until.is_some() {
            sets.push("locked_until = $locked_until");
        }
        if input.email_verified_at.is_some() {
            sets.push("email_verified_at = $email_verified_at");
        }
        sets.push("updated_at = time::now()");

        let query = format!(
            "UPDATE type::record('user', $id) SET {} \
             WHERE tenant_id = $tenant_id",
            sets.join(", ")
        );

        let mut builder = self
            .db
            .query(&query)
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str));

        if let Some(username) = input.username {
            builder = builder.bind(("username", username));
        }
        if let Some(email) = input.email {
            builder = builder.bind(("email", email));
        }
        if let Some(password_hash) = input.password_hash {
            builder = builder.bind(("password_hash", password_hash));
        }
        if let Some(ref status) = input.status {
            builder = builder.bind(("status", status_to_string(status).to_string()));
        }
        if let Some(metadata) = input.metadata {
            builder = builder.bind(("metadata", metadata));
        }
        if let Some(mfa_enabled) = input.mfa_enabled {
            builder = builder.bind(("mfa_enabled", mfa_enabled));
        }
        if let Some(mfa_secret) = input.mfa_secret {
            // mfa_secret is Option<Option<String>>: Some(Some(v)) = set, Some(None) = clear
            builder = builder.bind(("mfa_secret", mfa_secret));
        }
        if let Some(totp_last_used_step) = input.totp_last_used_step {
            // totp_last_used_step is Option<Option<u64>>: Some(Some(v)) = set, Some(None) = clear
            builder = builder.bind(("totp_last_used_step", totp_last_used_step));
        }
        if let Some(failed_login_attempts) = input.failed_login_attempts {
            builder = builder.bind(("failed_login_attempts", failed_login_attempts));
        }
        if let Some(last_failed_login_at) = input.last_failed_login_at {
            builder = builder.bind(("last_failed_login_at", last_failed_login_at));
        }
        if let Some(locked_until) = input.locked_until {
            builder = builder.bind(("locked_until", locked_until));
        }
        if let Some(email_verified_at) = input.email_verified_at {
            builder = builder.bind(("email_verified_at", email_verified_at));
        }

        let result = builder.await.map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<UserRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "user".into(),
            id: id_str,
        })?;

        Ok(row.into_user(id)?)
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        // Soft-delete: set status to Inactive.
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        self.db
            .query(
                "UPDATE type::record('user', $id) SET \
                 status = 'Inactive', updated_at = time::now() \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id_str))
            .bind(("tenant_id", tenant_id_str))
            .await
            .map_err(DbError::from)?;

        Ok(())
    }

    async fn update_totp_step(&self, tenant_id: Uuid, id: Uuid, step: u64) -> AxiamResult<()> {
        self.db
            .query(
                "UPDATE type::record('user', $id) SET \
                 totp_last_used_step = $step, updated_at = time::now() \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("step", step))
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    async fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<User>> {
        let tenant_id_str = tenant_id.to_string();

        let mut count_result = self
            .db
            .query(
                "SELECT count() AS total FROM user \
                 WHERE tenant_id = $tenant_id GROUP ALL",
            )
            .bind(("tenant_id", tenant_id_str.clone()))
            .await
            .map_err(DbError::from)?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;
        let total = count_rows.first().map(|r| r.total).unwrap_or(0);

        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM user \
                 WHERE tenant_id = $tenant_id \
                 ORDER BY created_at ASC \
                 LIMIT $limit START $offset",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<UserRowWithId> = result.take(0).map_err(DbError::from)?;

        let items = rows
            .into_iter()
            .map(|row| row.try_into_user())
            .collect::<Result<Vec<_>, DbError>>()?;

        Ok(PaginatedResult {
            items,
            total,
            offset: pagination.offset,
            limit: pagination.limit,
        })
    }
}

// ---------------------------------------------------------------------------
// GDPR deletion / anonymization methods (D-05, D-08)
// ---------------------------------------------------------------------------

impl<C: Connection> SurrealUserRepository<C> {
    /// Atomically create a user together with its `terms_of_service` consent
    /// row (REQ-8 / GDPR Art. 7 proof-of-consent).
    ///
    /// Both inserts run inside a single SurrealDB `BEGIN..COMMIT` transaction:
    /// if the consent insert fails, the user insert is rolled back. This makes
    /// the invariant *"a user never exists without proof-of-consent"* hold even
    /// on a partial DB failure (threat T-5-consent-gap). AXIAM never physically
    /// deletes user rows (anonymize-in-place preserves FK integrity), so a
    /// compensating delete could not satisfy this invariant — the transaction
    /// is required.
    pub async fn create_with_consent(
        &self,
        input: CreateUser,
        consent_type: &str,
        consent_version: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AxiamResult<User> {
        let id = Uuid::new_v4();
        let id_str = id.to_string();
        let consent_id = Uuid::new_v4().to_string();
        let tenant_id_str = input.tenant_id.to_string();

        let password_hash = password::hash_password(&input.password, self.pepper.as_deref())
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let metadata = input
            .metadata
            .unwrap_or(serde_json::Value::Object(Default::default()));

        // Result slots: BEGIN=0, CREATE user=1, CREATE consent=2, COMMIT=3.
        let result = self
            .db
            .query(
                "BEGIN TRANSACTION; \
                 CREATE type::record('user', $id) SET \
                 tenant_id = $tenant_id, \
                 username = $username, email = $email, \
                 password_hash = $password_hash, \
                 status = $status, \
                 mfa_enabled = false, \
                 failed_login_attempts = 0, \
                 last_failed_login_at = NONE, \
                 locked_until = NONE, \
                 email_verified_at = NONE, \
                 metadata = $metadata; \
                 CREATE type::record('consent', $consent_id) SET \
                 tenant_id = $tenant_id, \
                 user_id = $id, \
                 consent_type = $consent_type, \
                 version = $consent_version, \
                 accepted_at = time::now(), \
                 ip_address = $ip_address, \
                 user_agent = $user_agent; \
                 COMMIT TRANSACTION",
            )
            .bind(("id", id_str.clone()))
            .bind(("consent_id", consent_id))
            .bind(("tenant_id", tenant_id_str))
            .bind(("username", input.username))
            .bind(("email", input.email))
            .bind(("password_hash", password_hash))
            .bind(("status", "PendingVerification".to_string()))
            .bind(("metadata", metadata))
            .bind(("consent_type", consent_type.to_string()))
            .bind(("consent_version", consent_version.to_string()))
            .bind(("ip_address", ip_address))
            .bind(("user_agent", user_agent))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        // The user CREATE result is at index 1 (BEGIN occupies slot 0).
        let rows: Vec<UserRow> = result.take(1).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "user".into(),
            id: id_str,
        })?;

        Ok(row.into_user(id)?)
    }

    /// Mark a user as deletion-pending and set the scheduled purge date (D-08).
    ///
    /// The user account is immediately disabled (status Inactive) so that
    /// login is blocked during the grace period.
    pub async fn mark_deletion_pending(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        scheduled_purge_at: DateTime<Utc>,
    ) -> AxiamResult<()> {
        self.db
            .query(
                "UPDATE type::record('user', $id) SET \
                 deletion_pending = true, \
                 scheduled_purge_at = $purge_at, \
                 status = 'Inactive', \
                 updated_at = time::now() \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", user_id.to_string()))
            .bind(("purge_at", scheduled_purge_at))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(())
    }

    /// Anonymize a user row in-place (D-05).
    ///
    /// Scrubs every PII column:
    /// - email → `email_hash` (SHA-256 hex of original email, passed by caller)
    /// - username → `pseudonym` (DELETED_USER_<hmac>)
    /// - password_hash → NULL (login permanently blocked)
    /// - mfa_secret → NULL
    /// - metadata → `{}`
    /// - locked_until / last_failed_login_at → NULL
    /// - status → `Anonymized`
    ///
    /// The row and its `id` are kept to preserve referential integrity for
    /// `created_by`/owner foreign-key references.
    pub async fn anonymize_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        email_hash: &str,
        pseudonym: &str,
    ) -> AxiamResult<()> {
        // password_hash is TYPE string (not nullable) — use empty string as
        // tombstone value. Argon2 output is never empty, so login is permanently
        // blocked without needing to make the column nullable.
        self.db
            .query(
                "UPDATE type::record('user', $id) SET \
                 email = $email_hash, \
                 username = $pseudonym, \
                 password_hash = '', \
                 mfa_secret = NONE, \
                 mfa_enabled = false, \
                 metadata = {}, \
                 locked_until = NONE, \
                 last_failed_login_at = NONE, \
                 deletion_pending = false, \
                 scheduled_purge_at = NONE, \
                 status = 'Anonymized', \
                 updated_at = time::now() \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", user_id.to_string()))
            .bind(("email_hash", email_hash.to_string()))
            .bind(("pseudonym", pseudonym.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(())
    }

    /// Clear deletion-pending state and re-enable a user (D-09 cancel path).
    ///
    /// Called when the user clicks the emailed cancel link within the grace
    /// window.  Resets `deletion_pending`, `scheduled_purge_at`, and sets
    /// status back to `Active`.
    pub async fn clear_deletion_pending(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<()> {
        self.db
            .query(
                "UPDATE type::record('user', $id) SET \
                 deletion_pending = false, \
                 scheduled_purge_at = NONE, \
                 status = 'Active', \
                 updated_at = time::now() \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", user_id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(())
    }

    /// Find users whose scheduled purge date has passed (D-08).
    ///
    /// Used by the `CleanupTask` sweep to run the purge pipeline.
    pub async fn find_due_for_purge(&self, now: DateTime<Utc>) -> AxiamResult<Vec<User>> {
        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM user \
                 WHERE deletion_pending = true \
                 AND scheduled_purge_at <= $now",
            )
            .bind(("now", now))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<UserRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|r| r.try_into_user().map_err(Into::into))
            .collect()
    }
}

/// Verify a password against an Argon2id hash.
///
/// Public for use by the auth layer.
pub fn verify_password(password: &str, hash: &str, pepper: Option<&str>) -> Result<bool, DbError> {
    use argon2::{Argon2, PasswordVerifier};

    let peppered: String;
    let input = match pepper {
        Some(p) => {
            peppered = format!("{p}{password}");
            peppered.as_bytes()
        }
        None => password.as_bytes(),
    };

    let parsed_hash = argon2::PasswordHash::new(hash)
        .map_err(|e| DbError::Migration(format!("invalid hash format: {e}")))?;

    let argon2 = Argon2::default();
    match argon2.verify_password(input, &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(DbError::Migration(format!("verify error: {e}"))),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::user::CreateUser;
    use surrealdb::Surreal;
    use surrealdb::engine::local::Mem;

    async fn setup_db() -> Surreal<surrealdb::engine::local::Db> {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        crate::schema::run_migrations(&db).await.unwrap();
        db
    }

    #[tokio::test]
    async fn mark_deletion_pending_and_anonymize() {
        let db = setup_db().await;
        let repo = SurrealUserRepository::new(db);
        let tenant_id = Uuid::new_v4();

        // Create a user.
        let user = repo
            .create(CreateUser {
                tenant_id,
                username: "alice".into(),
                email: "alice@example.com".into(),
                password: "correct-horse".into(),
                metadata: None,
            })
            .await
            .unwrap();

        // Mark deletion pending.
        let purge_at = Utc::now() + chrono::Duration::days(30);
        repo.mark_deletion_pending(tenant_id, user.id, purge_at)
            .await
            .unwrap();

        let updated = repo.get_by_id(tenant_id, user.id).await.unwrap();
        assert!(updated.deletion_pending, "deletion_pending must be true");
        assert_eq!(updated.status, UserStatus::Inactive);

        // find_due_for_purge should find it when purge_at is in the past.
        let past = Utc::now() + chrono::Duration::days(31);
        let due = repo.find_due_for_purge(past).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, user.id);

        // Not found when querying in the present (purge_at is 30 days away).
        let now = Utc::now();
        let not_due = repo.find_due_for_purge(now).await.unwrap();
        assert!(not_due.is_empty());

        // Anonymize.
        repo.anonymize_user(
            tenant_id,
            user.id,
            "sha256_of_alice_at_example_com",
            "DELETED_USER_deadbeef01234567",
        )
        .await
        .unwrap();

        let anon = repo.get_by_id(tenant_id, user.id).await.unwrap();
        assert_eq!(anon.status, UserStatus::Anonymized);
        assert_eq!(anon.email, "sha256_of_alice_at_example_com");
        assert_eq!(anon.username, "DELETED_USER_deadbeef01234567");
        // password_hash schema is TYPE string (not nullable); tombstone = empty string
        assert_eq!(
            anon.password_hash, "",
            "password_hash must be empty (tombstone) after anonymization"
        );
        assert!(anon.mfa_secret.is_none(), "mfa_secret must be scrubbed");
        assert!(
            !anon.deletion_pending,
            "deletion_pending cleared after anonymization"
        );
    }
}
