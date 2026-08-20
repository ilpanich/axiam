//! SurrealDB implementation of [`OpaqueServerSetupRepository`].
//!
//! One row per `(tenant, suite)`, holding the tenant's OPAQUE server key
//! material encrypted at rest.
//!
//! # Why there is no update and no delete
//!
//! The stored `ServerSetup` carries the OPRF seed every one of the tenant's
//! registration records was sealed against. Replacing it invalidates all of
//! them at once; removing it locks the tenant out. Both are recoverable only
//! by a tenant-wide password reset, which is not an operation that should be
//! one repository call away. An operator who genuinely needs it reaches for
//! the database directly, having read the runbook.

use axiam_core::error::AxiamResult;
use axiam_core::models::opaque::{OpaqueServerSetup, OpaqueSuite};
use axiam_core::repository::OpaqueServerSetupRepository;
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::take_first_or_not_found;

#[derive(Debug, SurrealValue)]
struct SetupRow {
    tenant_id: String,
    suite: String,
    sealed_setup: String,
    sealed_decoy_key: String,
    created_at: DateTime<Utc>,
}

impl SetupRow {
    fn try_into_setup(self) -> Result<OpaqueServerSetup, DbError> {
        Ok(OpaqueServerSetup {
            tenant_id: Uuid::parse_str(&self.tenant_id)
                .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?,
            suite: self.suite.parse().map_err(DbError::Migration)?,
            sealed_setup: self.sealed_setup,
            sealed_decoy_key: self.sealed_decoy_key,
            created_at: self.created_at,
        })
    }
}

/// SurrealDB implementation of the OPAQUE server setup repository.
pub struct SurrealOpaqueServerSetupRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> Clone for SurrealOpaqueServerSetupRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealOpaqueServerSetupRepository<C> {
    /// Build a repository over `db`.
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }

    async fn select(&self, tenant_id: Uuid, suite: OpaqueSuite) -> AxiamResult<Vec<SetupRow>> {
        let result = self
            .db
            .current()
            .query(
                "SELECT * FROM opaque_server_setup \
                 WHERE tenant_id = $tenant_id AND suite = $suite",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("suite", suite.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(result.take(0).map_err(DbError::from)?)
    }
}

impl<C: Connection> OpaqueServerSetupRepository for SurrealOpaqueServerSetupRepository<C> {
    async fn get(&self, tenant_id: Uuid, suite: OpaqueSuite) -> AxiamResult<OpaqueServerSetup> {
        let rows = self.select(tenant_id, suite).await?;
        let row = take_first_or_not_found(rows, "opaque_server_setup", &tenant_id.to_string())?;
        Ok(row.try_into_setup()?)
    }

    async fn get_or_create(&self, input: OpaqueServerSetup) -> AxiamResult<OpaqueServerSetup> {
        // Read first, so the common path — every login after the first — does
        // no write at all.
        if let Some(row) = self
            .select(input.tenant_id, input.suite)
            .await?
            .into_iter()
            .next()
        {
            return Ok(row.try_into_setup()?);
        }

        // The record id is derived from `(tenant, suite)` rather than random,
        // which is what makes this idempotent: two concurrent first logins
        // address the same row, so the loser of the race gets a uniqueness
        // failure instead of writing a second seed. A tenant whose seed
        // depended on which request won would have records that only
        // sometimes open — the kind of defect that presents as an
        // intermittent wrong password and takes weeks to find.
        let row_id = format!("{}:{}", input.tenant_id, input.suite);
        let created = self
            .db
            .current()
            .query(
                "CREATE type::record('opaque_server_setup', $id) SET \
                 tenant_id = $tenant_id, \
                 suite = $suite, \
                 sealed_setup = $sealed_setup, \
                 sealed_decoy_key = $sealed_decoy_key \
                 RETURN *",
            )
            .bind(("id", row_id))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("suite", input.suite.to_string()))
            .bind(("sealed_setup", input.sealed_setup.clone()))
            .bind(("sealed_decoy_key", input.sealed_decoy_key.clone()))
            .await;

        match created {
            Ok(response) => match response.check() {
                Ok(mut checked) => {
                    let rows: Vec<SetupRow> = checked.take(0).map_err(DbError::from)?;
                    if let Some(row) = rows.into_iter().next() {
                        return Ok(row.try_into_setup()?);
                    }
                    // CREATE returned nothing: somebody else won. Re-read.
                    self.get(input.tenant_id, input.suite).await
                }
                // A uniqueness violation means the race was lost, which is a
                // success for this method's contract — the caller wanted key
                // material to exist, and it does.
                Err(_) => self.get(input.tenant_id, input.suite).await,
            },
            Err(_) => self.get(input.tenant_id, input.suite).await,
        }
    }
}
