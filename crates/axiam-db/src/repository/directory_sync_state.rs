//! SurrealDB implementation of [`DirectorySyncStateRepository`] (G-3, T23.3.5,
//! D-31): what the directory sync job remembers about a tenant between runs.
//!
//! One row per tenant, and the record id **is** the tenant id, so "one row per
//! tenant" is a property of the key rather than of the application. The row
//! holds a watermark, the identity of the server the watermark belongs to,
//! timestamps, the last result and a bounded list of account ids — no secret
//! and no personal data. It is deleted with its tenant (`SurrealTenantRepository`).

use axiam_core::error::AxiamResult;
use axiam_core::models::directory_sync::{
    DirectorySyncResult, DirectorySyncState, REPORTED_USER_IDS_MAX,
};
use axiam_core::repository::DirectorySyncStateRepository;
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{classify_write_error, parse_uuid};

/// A stored row.
#[derive(Debug, SurrealValue)]
struct StateRow {
    tenant_id: String,
    watermark: Option<String>,
    server_identity: Option<String>,
    full_required: bool,
    last_attempt_at: Option<DateTime<Utc>>,
    last_full_run_at: Option<DateTime<Utc>>,
    last_result: Option<String>,
    reported_user_ids: Vec<String>,
    updated_at: DateTime<Utc>,
}

impl StateRow {
    fn into_domain(self) -> Result<DirectorySyncState, DbError> {
        let last_result = match self.last_result.as_deref() {
            None => None,
            Some(raw) => Some(DirectorySyncResult::from_wire(raw).ok_or_else(|| {
                DbError::Serialization("directory_sync_state row has an unknown last_result".into())
            })?),
        };
        Ok(DirectorySyncState {
            tenant_id: parse_uuid(&self.tenant_id, "tenant")?,
            watermark: self.watermark,
            server_identity: self.server_identity,
            full_required: self.full_required,
            last_attempt_at: self.last_attempt_at,
            last_full_run_at: self.last_full_run_at,
            last_result,
            reported_user_ids: self
                .reported_user_ids
                .iter()
                .map(|raw| parse_uuid(raw, "user"))
                .collect::<Result<Vec<_>, _>>()?,
            updated_at: self.updated_at,
        })
    }
}

/// SurrealDB implementation of [`DirectorySyncStateRepository`].
pub struct SurrealDirectorySyncStateRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> Clone for SurrealDirectorySyncStateRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealDirectorySyncStateRepository<C> {
    /// Build the repository.
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }
}

impl<C: Connection> DirectorySyncStateRepository for SurrealDirectorySyncStateRepository<C> {
    async fn get(&self, tenant_id: Uuid) -> AxiamResult<Option<DirectorySyncState>> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT tenant_id, watermark, server_identity, full_required, \
                        last_attempt_at, last_full_run_at, last_result, \
                        reported_user_ids, updated_at \
                 FROM directory_sync_state WHERE tenant_id = $tenant_id",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<StateRow> = result.take(0).map_err(DbError::from)?;
        match rows.into_iter().next() {
            Some(row) => Ok(Some(row.into_domain()?)),
            None => Ok(None),
        }
    }

    async fn save(&self, state: &DirectorySyncState) -> AxiamResult<()> {
        // The cap is the repository's rule as well as the schema's, so a caller
        // that exceeds it gets the oldest ids dropped rather than a refused
        // write that would lose the whole run's state.
        let skip = state
            .reported_user_ids
            .len()
            .saturating_sub(REPORTED_USER_IDS_MAX);
        let reported: Vec<String> = state
            .reported_user_ids
            .iter()
            .skip(skip)
            .map(Uuid::to_string)
            .collect();
        self.db
            .current()
            .query(
                "UPSERT type::record('directory_sync_state', $tenant_id) SET \
                 tenant_id = $tenant_id, watermark = $watermark, \
                 server_identity = $server_identity, full_required = $full_required, \
                 last_attempt_at = $last_attempt_at, last_full_run_at = $last_full_run_at, \
                 last_result = $last_result, reported_user_ids = $reported, \
                 updated_at = time::now()",
            )
            .bind(("tenant_id", state.tenant_id.to_string()))
            .bind(("watermark", state.watermark.clone()))
            .bind(("server_identity", state.server_identity.clone()))
            .bind(("full_required", state.full_required))
            .bind(("last_attempt_at", state.last_attempt_at))
            .bind(("last_full_run_at", state.last_full_run_at))
            .bind((
                "last_result",
                state.last_result.map(|r| r.as_str().to_string()),
            ))
            .bind(("reported", reported))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| classify_write_error(e.to_string(), "directory_sync_state"))?;
        Ok(())
    }

    async fn delete(&self, tenant_id: Uuid) -> AxiamResult<()> {
        self.db
            .current()
            .query("DELETE directory_sync_state WHERE tenant_id = $tenant_id")
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(DbError::from)?;
        Ok(())
    }
}
