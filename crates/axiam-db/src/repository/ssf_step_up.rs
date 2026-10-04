//! SurrealDB implementation of [`SsfStepUpRepository`] (G-5, T23.5.3, D-53 (1),
//! schema v78's `ssf_step_up`).
//!
//! One row per `(tenant, user)` — the record id is derived from the pair and a
//! unique index backs it — so the latest step-up replaces the earlier one, and
//! a row lives [`STEP_UP_RECORD_TTL_MINUTES`] minutes. `take` deletes in the
//! same statement that returns the row, so a record is consumed exactly once
//! however many return legs race for it.
//!
//! The row holds ids and one `acr` URN: no credential, no address.

use axiam_core::error::AxiamResult;
use axiam_core::models::ssf::{STEP_UP_RECORD_TTL_MINUTES, SsfStepUp};
use axiam_core::repository::SsfStepUpRepository;
use chrono::{DateTime, Duration, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{CountRow, classify_write_error};

const ENTITY: &str = "ssf_step_up";

#[derive(SurrealValue)]
struct StepUpRow {
    previous_session_id: String,
    previous_acr: String,
    expires_at: DateTime<Utc>,
}

#[derive(SurrealValue)]
struct RemovedRow {
    #[allow(dead_code)] // counted, never read
    record_id: String,
}

/// SurrealDB implementation of [`SsfStepUpRepository`].
pub struct SurrealSsfStepUpRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> Clone for SurrealSsfStepUpRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> std::fmt::Debug for SurrealSsfStepUpRepository<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SurrealSsfStepUpRepository")
            .finish_non_exhaustive()
    }
}

impl<C: Connection> SurrealSsfStepUpRepository<C> {
    /// Build the repository.
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }

    /// The record id of a `(tenant, user)` pair.
    fn record_id(tenant_id: Uuid, user_id: Uuid) -> String {
        format!("{}_{}", tenant_id.simple(), user_id.simple())
    }
}

impl<C: Connection> SsfStepUpRepository for SurrealSsfStepUpRepository<C> {
    async fn put(&self, record: &SsfStepUp, now: DateTime<Utc>) -> AxiamResult<()> {
        self.db
            .current()
            .query(
                "UPSERT type::record('ssf_step_up', $record_id) SET \
                 tenant_id = $tenant_id, user_id = $user_id, \
                 previous_session_id = $previous_session_id, \
                 previous_acr = $previous_acr, created_at = $now, \
                 expires_at = $expires_at",
            )
            .bind((
                "record_id",
                Self::record_id(record.tenant_id, record.user_id),
            ))
            .bind(("tenant_id", record.tenant_id.to_string()))
            .bind(("user_id", record.user_id.to_string()))
            .bind((
                "previous_session_id",
                record.previous_session_id.to_string(),
            ))
            .bind(("previous_acr", record.previous_acr.clone()))
            .bind(("now", now))
            .bind((
                "expires_at",
                now + Duration::minutes(STEP_UP_RECORD_TTL_MINUTES),
            ))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| classify_write_error(e.to_string(), ENTITY))?;
        Ok(())
    }

    async fn take(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        now: DateTime<Utc>,
    ) -> AxiamResult<Option<SsfStepUp>> {
        let mut result = self
            .db
            .current()
            .query(
                "DELETE ssf_step_up WHERE tenant_id = $tenant_id AND user_id = $user_id \
                 RETURN BEFORE",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<StepUpRow> = result.take(0).map_err(DbError::from)?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        // Consumed either way; only an unexpired record is a record.
        if row.expires_at <= now {
            return Ok(None);
        }
        let Ok(previous_session_id) = Uuid::parse_str(&row.previous_session_id) else {
            return Ok(None);
        };
        Ok(Some(SsfStepUp {
            tenant_id,
            user_id,
            previous_session_id,
            previous_acr: row.previous_acr,
        }))
    }

    async fn count_for_tenant(&self, tenant_id: Uuid) -> AxiamResult<u64> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM ssf_step_up \
                 WHERE tenant_id = $tenant_id GROUP ALL",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.first().map(|r| r.total).unwrap_or(0))
    }

    async fn delete_expired(&self, now: DateTime<Utc>) -> AxiamResult<u64> {
        let mut result = self
            .db
            .current()
            .query(
                "LET $removed = (DELETE ssf_step_up WHERE expires_at <= $now RETURN BEFORE); \
                 SELECT meta::id(id) AS record_id FROM $removed",
            )
            .bind(("now", now))
            .await
            .map_err(DbError::from)?;
        let removed: Vec<RemovedRow> = result.take(1).map_err(DbError::from)?;
        Ok(removed.len() as u64)
    }
}
