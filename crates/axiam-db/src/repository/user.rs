//! SurrealDB implementation of [`UserRepository`].
//!
//! Password hashing uses Argon2id with OWASP-recommended parameters
//! (memory: 19 MiB, iterations: 2, parallelism: 1). Salt is randomly
//! generated per hash. An optional pepper (server-side secret) can be
//! provided at construction time.

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
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
    failed_login_attempts: u32,
    last_failed_login_at: Option<DateTime<Utc>>,
    locked_until: Option<DateTime<Utc>>,
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
    failed_login_attempts: u32,
    last_failed_login_at: Option<DateTime<Utc>>,
    locked_until: Option<DateTime<Utc>>,
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
        other => Err(DbError::Migration(format!("unknown user status: {other}"))),
    }
}

fn status_to_string(s: &UserStatus) -> &'static str {
    match s {
        UserStatus::Active => "Active",
        UserStatus::Inactive => "Inactive",
        UserStatus::Locked => "Locked",
        UserStatus::PendingVerification => "PendingVerification",
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
            failed_login_attempts: self.failed_login_attempts,
            last_failed_login_at: self.last_failed_login_at,
            locked_until: self.locked_until,
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
            failed_login_attempts: self.failed_login_attempts,
            last_failed_login_at: self.last_failed_login_at,
            locked_until: self.locked_until,
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

/// Hash a password with Argon2id using OWASP-recommended parameters.
///
/// If a pepper is provided, it is prepended to the password before
/// hashing. The salt is randomly generated for each call.
fn hash_password(password: &str, pepper: Option<&str>) -> Result<String, DbError> {
    // OWASP ASVS recommended: m=19456 (19 MiB), t=2, p=1
    let params = argon2::Params::new(19456, 2, 1, None)
        .map_err(|e| DbError::Migration(format!("argon2 params error: {e}")))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let peppered: String;
    let input = match pepper {
        Some(p) => {
            peppered = format!("{p}{password}");
            peppered.as_bytes()
        }
        None => password.as_bytes(),
    };

    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let hash = argon2
        .hash_password(input, &salt)
        .map_err(|e| DbError::Migration(format!("password hash error: {e}")))?;

    Ok(hash.to_string())
}

/// SurrealDB implementation of the User repository.
#[derive(Clone)]
pub struct SurrealUserRepository<C: Connection> {
    db: Surreal<C>,
    /// Optional server-side pepper for password hashing.
    pepper: Option<String>,
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

        let password_hash = hash_password(&input.password, self.pepper.as_deref())?;

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
        if input.failed_login_attempts.is_some() {
            sets.push("failed_login_attempts = $failed_login_attempts");
        }
        if input.last_failed_login_at.is_some() {
            sets.push("last_failed_login_at = $last_failed_login_at");
        }
        if input.locked_until.is_some() {
            sets.push("locked_until = $locked_until");
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
        if let Some(failed_login_attempts) = input.failed_login_attempts {
            builder = builder.bind(("failed_login_attempts", failed_login_attempts));
        }
        if let Some(last_failed_login_at) = input.last_failed_login_at {
            builder = builder.bind(("last_failed_login_at", last_failed_login_at));
        }
        if let Some(locked_until) = input.locked_until {
            builder = builder.bind(("locked_until", locked_until));
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

/// Verify a password against an Argon2id hash.
///
/// Public for use by the auth layer.
pub fn verify_password(password: &str, hash: &str, pepper: Option<&str>) -> Result<bool, DbError> {
    use argon2::PasswordVerifier;

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
