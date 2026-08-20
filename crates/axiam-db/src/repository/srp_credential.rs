//! SurrealDB implementation of [`SrpCredentialRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::models::srp::{CreateSrpCredential, SrpCredential, SrpGroup, SrpKdf, SrpKdfParams};
use axiam_core::repository::SrpCredentialRepository;
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{CountRow, take_first_or_not_found};

#[derive(Debug, SurrealValue)]
struct CredentialRow {
    record_id: String,
    tenant_id: String,
    user_id: String,
    identity: String,
    srp_group: String,
    kdf: String,
    kdf_memory_kib: Option<u32>,
    kdf_iterations: u32,
    kdf_parallelism: Option<u32>,
    salt: String,
    verifier: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl CredentialRow {
    fn try_into_credential(self) -> Result<SrpCredential, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let user_id = Uuid::parse_str(&self.user_id)
            .map_err(|e| DbError::Migration(format!("invalid user UUID: {e}")))?;
        let group: SrpGroup = self.srp_group.parse().map_err(DbError::Migration)?;
        let kdf: SrpKdf = self.kdf.parse().map_err(DbError::Migration)?;

        // A row whose KDF column and cost columns disagree is corrupt, not
        // merely odd: silently defaulting the missing cost would change `x`
        // and lock the user out with an "invalid credentials" that no operator
        // could explain. Fail loudly instead.
        let kdf_params = match kdf {
            SrpKdf::Argon2id => SrpKdfParams::Argon2id {
                memory_kib: self.kdf_memory_kib.ok_or_else(|| {
                    DbError::Migration("argon2id SRP credential has no memory cost".into())
                })?,
                iterations: self.kdf_iterations,
                parallelism: self.kdf_parallelism.ok_or_else(|| {
                    DbError::Migration("argon2id SRP credential has no parallelism".into())
                })?,
            },
            SrpKdf::Pbkdf2Sha256 => SrpKdfParams::Pbkdf2Sha256 {
                iterations: self.kdf_iterations,
            },
        };

        Ok(SrpCredential {
            id,
            tenant_id,
            user_id,
            identity: self.identity,
            group,
            kdf_params,
            salt: self.salt,
            verifier: self.verifier,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// SurrealDB implementation of the SRP credential repository.
pub struct SurrealSrpCredentialRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> Clone for SurrealSrpCredentialRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealSrpCredentialRepository<C> {
    /// Build a repository over `db`.
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }
}

impl<C: Connection> SrpCredentialRepository for SurrealSrpCredentialRepository<C> {
    async fn upsert(&self, input: CreateSrpCredential) -> AxiamResult<SrpCredential> {
        let (memory_kib, iterations, parallelism) = match input.kdf_params {
            SrpKdfParams::Argon2id {
                memory_kib,
                iterations,
                parallelism,
            } => (Some(memory_kib), iterations, Some(parallelism)),
            SrpKdfParams::Pbkdf2Sha256 { iterations } => (None, iterations, None),
        };
        let kdf = input.kdf_params.kdf().to_string();

        // UPDATE-then-CREATE rather than a blind CREATE: the `(tenant_id,
        // user_id)` index is UNIQUE, so a second password change for the same
        // user must replace the row, not collide with it. The UPDATE is
        // filtered by the same pair the index covers, so it touches at most
        // one row.
        let result = self
            .db
            .current()
            .query(
                "UPDATE srp_credential SET \
                 identity = $identity, \
                 srp_group = $srp_group, \
                 kdf = $kdf, \
                 kdf_memory_kib = $kdf_memory_kib, \
                 kdf_iterations = $kdf_iterations, \
                 kdf_parallelism = $kdf_parallelism, \
                 salt = $salt, \
                 verifier = $verifier, \
                 updated_at = time::now() \
                 WHERE tenant_id = $tenant_id AND user_id = $user_id \
                 RETURN meta::id(id) AS record_id, *",
            )
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("user_id", input.user_id.to_string()))
            .bind(("identity", input.identity.clone()))
            .bind(("srp_group", input.group.to_string()))
            .bind(("kdf", kdf.clone()))
            .bind(("kdf_memory_kib", memory_kib))
            .bind(("kdf_iterations", iterations))
            .bind(("kdf_parallelism", parallelism))
            .bind(("salt", input.salt.clone()))
            .bind(("verifier", input.verifier.clone()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let updated: Vec<CredentialRow> = result.take(0).map_err(DbError::from)?;
        if let Some(row) = updated.into_iter().next() {
            return Ok(row.try_into_credential()?);
        }

        let id = new_id();
        let id_str = id.to_string();
        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('srp_credential', $id) SET \
                 tenant_id = $tenant_id, \
                 user_id = $user_id, \
                 identity = $identity, \
                 srp_group = $srp_group, \
                 kdf = $kdf, \
                 kdf_memory_kib = $kdf_memory_kib, \
                 kdf_iterations = $kdf_iterations, \
                 kdf_parallelism = $kdf_parallelism, \
                 salt = $salt, \
                 verifier = $verifier \
                 RETURN meta::id(id) AS record_id, *",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("user_id", input.user_id.to_string()))
            .bind(("identity", input.identity))
            .bind(("srp_group", input.group.to_string()))
            .bind(("kdf", kdf))
            .bind(("kdf_memory_kib", memory_kib))
            .bind(("kdf_iterations", iterations))
            .bind(("kdf_parallelism", parallelism))
            .bind(("salt", input.salt))
            .bind(("verifier", input.verifier))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<CredentialRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "srp_credential", &id_str)?;
        Ok(row.try_into_credential()?)
    }

    async fn get_by_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<SrpCredential> {
        let result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM srp_credential \
                 WHERE tenant_id = $tenant_id AND user_id = $user_id",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<CredentialRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "srp_credential", &user_id.to_string())?;
        Ok(row.try_into_credential()?)
    }

    async fn delete_for_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<bool> {
        let result = self
            .db
            .current()
            .query(
                "DELETE FROM srp_credential \
                 WHERE tenant_id = $tenant_id AND user_id = $user_id \
                 RETURN BEFORE",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<CredentialRow> = result.take(0).map_err(DbError::from)?;
        Ok(!rows.is_empty())
    }

    async fn count_for_tenant(&self, tenant_id: Uuid) -> AxiamResult<u64> {
        let result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM srp_credential \
                 WHERE tenant_id = $tenant_id GROUP ALL",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.first().map(|r| r.total).unwrap_or(0))
    }
}
