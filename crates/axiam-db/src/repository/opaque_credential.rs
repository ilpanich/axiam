//! SurrealDB implementation of [`OpaqueCredentialRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::models::opaque::{
    CreateOpaqueCredential, OpaqueCredential, OpaqueKsf, OpaqueKsfParams, OpaqueSuite,
};
use axiam_core::repository::OpaqueCredentialRepository;
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
    credential_identifier: String,
    suite: String,
    ksf: String,
    ksf_memory_kib: Option<u32>,
    ksf_iterations: Option<u32>,
    ksf_parallelism: Option<u32>,
    ksf_log_n: Option<u8>,
    ksf_r: Option<u32>,
    ksf_p: Option<u32>,
    record: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl CredentialRow {
    fn try_into_credential(self) -> Result<OpaqueCredential, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let user_id = Uuid::parse_str(&self.user_id)
            .map_err(|e| DbError::Migration(format!("invalid user UUID: {e}")))?;
        let suite: OpaqueSuite = self.suite.parse().map_err(DbError::Migration)?;
        let ksf: OpaqueKsf = self.ksf.parse().map_err(DbError::Migration)?;

        // A row whose KSF column and cost columns disagree is corrupt, not
        // merely odd: silently defaulting a missing cost would make the client
        // stretch differently, so it would fail to open an envelope that is
        // perfectly good and the user would be told their correct password is
        // wrong. Fail loudly instead.
        let missing =
            |field: &str| DbError::Migration(format!("{ksf} OPAQUE credential has no {field}"));
        let ksf_params = match ksf {
            OpaqueKsf::Argon2id => OpaqueKsfParams::Argon2id {
                memory_kib: self.ksf_memory_kib.ok_or_else(|| missing("memory cost"))?,
                iterations: self.ksf_iterations.ok_or_else(|| missing("time cost"))?,
                parallelism: self.ksf_parallelism.ok_or_else(|| missing("parallelism"))?,
            },
            OpaqueKsf::Scrypt => OpaqueKsfParams::Scrypt {
                log_n: self.ksf_log_n.ok_or_else(|| missing("log_n"))?,
                r: self.ksf_r.ok_or_else(|| missing("r"))?,
                p: self.ksf_p.ok_or_else(|| missing("p"))?,
            },
        };

        Ok(OpaqueCredential {
            id,
            tenant_id,
            user_id,
            credential_identifier: self.credential_identifier,
            suite,
            ksf_params,
            record: self.record,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Flatten KSF parameters into the six nullable columns the table carries.
///
/// Returned in column order: `(memory_kib, iterations, parallelism, log_n, r, p)`.
type KsfColumns = (
    Option<u32>,
    Option<u32>,
    Option<u32>,
    Option<u8>,
    Option<u32>,
    Option<u32>,
);

fn ksf_columns(params: OpaqueKsfParams) -> KsfColumns {
    match params {
        OpaqueKsfParams::Argon2id {
            memory_kib,
            iterations,
            parallelism,
        } => (
            Some(memory_kib),
            Some(iterations),
            Some(parallelism),
            None,
            None,
            None,
        ),
        OpaqueKsfParams::Scrypt { log_n, r, p } => {
            (None, None, None, Some(log_n), Some(r), Some(p))
        }
    }
}

/// SurrealDB implementation of the OPAQUE credential repository.
pub struct SurrealOpaqueCredentialRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> Clone for SurrealOpaqueCredentialRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealOpaqueCredentialRepository<C> {
    /// Build a repository over `db`.
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }
}

impl<C: Connection> OpaqueCredentialRepository for SurrealOpaqueCredentialRepository<C> {
    async fn upsert(&self, input: CreateOpaqueCredential) -> AxiamResult<OpaqueCredential> {
        let (memory_kib, iterations, parallelism, log_n, r, p) = ksf_columns(input.ksf_params);
        let ksf = input.ksf_params.ksf().to_string();

        // UPDATE-then-CREATE rather than a blind CREATE: the `(tenant_id,
        // user_id)` index is UNIQUE, so a second password change for the same
        // user must replace the row, not collide with it. The UPDATE is
        // filtered by the same pair the index covers, so it touches at most
        // one row.
        //
        // Note that `credential_identifier` is rewritten too. A password
        // change mints a fresh identifier, so the new record is unlinkable
        // from the old one even to somebody holding both database dumps.
        let result = self
            .db
            .current()
            .query(
                "UPDATE opaque_credential SET \
                 credential_identifier = $credential_identifier, \
                 suite = $suite, \
                 ksf = $ksf, \
                 ksf_memory_kib = $ksf_memory_kib, \
                 ksf_iterations = $ksf_iterations, \
                 ksf_parallelism = $ksf_parallelism, \
                 ksf_log_n = $ksf_log_n, \
                 ksf_r = $ksf_r, \
                 ksf_p = $ksf_p, \
                 record = $record, \
                 updated_at = time::now() \
                 WHERE tenant_id = $tenant_id AND user_id = $user_id \
                 RETURN meta::id(id) AS record_id, *",
            )
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("user_id", input.user_id.to_string()))
            .bind(("credential_identifier", input.credential_identifier.clone()))
            .bind(("suite", input.suite.to_string()))
            .bind(("ksf", ksf.clone()))
            .bind(("ksf_memory_kib", memory_kib))
            .bind(("ksf_iterations", iterations))
            .bind(("ksf_parallelism", parallelism))
            .bind(("ksf_log_n", log_n))
            .bind(("ksf_r", r))
            .bind(("ksf_p", p))
            .bind(("record", input.record.clone()))
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
                "CREATE type::record('opaque_credential', $id) SET \
                 tenant_id = $tenant_id, \
                 user_id = $user_id, \
                 credential_identifier = $credential_identifier, \
                 suite = $suite, \
                 ksf = $ksf, \
                 ksf_memory_kib = $ksf_memory_kib, \
                 ksf_iterations = $ksf_iterations, \
                 ksf_parallelism = $ksf_parallelism, \
                 ksf_log_n = $ksf_log_n, \
                 ksf_r = $ksf_r, \
                 ksf_p = $ksf_p, \
                 record = $record \
                 RETURN meta::id(id) AS record_id, *",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("user_id", input.user_id.to_string()))
            .bind(("credential_identifier", input.credential_identifier))
            .bind(("suite", input.suite.to_string()))
            .bind(("ksf", ksf))
            .bind(("ksf_memory_kib", memory_kib))
            .bind(("ksf_iterations", iterations))
            .bind(("ksf_parallelism", parallelism))
            .bind(("ksf_log_n", log_n))
            .bind(("ksf_r", r))
            .bind(("ksf_p", p))
            .bind(("record", input.record))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<CredentialRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "opaque_credential", &id_str)?;
        Ok(row.try_into_credential()?)
    }

    async fn get_by_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<OpaqueCredential> {
        let result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM opaque_credential \
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
        let row = take_first_or_not_found(rows, "opaque_credential", &user_id.to_string())?;
        Ok(row.try_into_credential()?)
    }

    async fn delete_for_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<bool> {
        let result = self
            .db
            .current()
            .query(
                "DELETE FROM opaque_credential \
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

    async fn count_active_users_without_credential(&self, tenant_id: Uuid) -> AxiamResult<u64> {
        // `LET` first so the planner sees a constant on the right-hand side of
        // the `NOT INSIDE`, the same reason `get_user_role_assignments` hoists
        // its membership sub-select: written inline it walks every
        // `opaque_credential` row in the database per user.
        let result = self
            .db
            .current()
            .query(
                "LET $enrolled = (\
                     SELECT VALUE user_id FROM opaque_credential \
                     WHERE tenant_id = $tenant_id\
                 ); \
                 SELECT count() AS total FROM user \
                 WHERE tenant_id = $tenant_id \
                 AND status = 'Active' \
                 AND meta::id(id) NOT INSIDE $enrolled \
                 GROUP ALL",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        // Statement 0 is the LET; the count is statement 1.
        let rows: Vec<CountRow> = result.take(1).map_err(DbError::from)?;
        Ok(rows.first().map(|r| r.total).unwrap_or(0))
    }

    async fn count_for_tenant(&self, tenant_id: Uuid) -> AxiamResult<u64> {
        let result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM opaque_credential \
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
