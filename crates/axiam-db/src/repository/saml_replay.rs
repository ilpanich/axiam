//! SurrealDB implementation of [`AssertionReplayRepository`].
//!
//! Provides insert-or-conflict semantics for SAML assertion IDs. Inserting a
//! `(tenant_id, assertion_id)` pair that already exists returns
//! `Err(AxiamError::ReplayDetected)` so the SAML ACS handler can reject
//! replayed assertions (D-09).

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::repository::AssertionReplayRepository;
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct CountRow {
    total: u64,
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

/// SurrealDB implementation of the SAML assertion replay repository.
#[derive(Clone)]
pub struct SurrealAssertionReplayRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealAssertionReplayRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> AssertionReplayRepository for SurrealAssertionReplayRepository<C> {
    async fn insert_assertion(
        &self,
        tenant_id: Uuid,
        assertion_id: &str,
        expires_at: DateTime<Utc>,
    ) -> AxiamResult<()> {
        let row_id = Uuid::new_v4().to_string();
        let assertion_id_owned = assertion_id.to_string();

        let result = self
            .db
            .query(
                "CREATE type::record('saml_assertion_replay', $row_id) SET \
                 tenant_id = $tenant_id, \
                 assertion_id = $assertion_id, \
                 expires_at = $expires_at",
            )
            .bind(("row_id", row_id))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("assertion_id", assertion_id_owned))
            .bind(("expires_at", expires_at))
            .await
            .map_err(DbError::from)?;

        result
            .check()
            .map_err(|e| {
                let msg = e.to_string();
                // SurrealDB v3 UNIQUE index violation message contains
                // "already contains" (e.g. "Database index `idx_replay_uniq`
                // already contains [...]"). Also match "already exists" and
                // "unique" as fallback patterns.
                if msg.contains("already contains")
                    || msg.contains("already exists")
                    || msg.contains("unique")
                {
                    AxiamError::ReplayDetected
                } else {
                    AxiamError::Database(msg)
                }
            })
            .map(|_| ())
    }

    async fn cleanup_expired(&self) -> AxiamResult<u64> {
        // Count expired rows first, then delete.
        let mut count_result = self
            .db
            .query(
                "SELECT count() AS total FROM saml_assertion_replay \
                 WHERE expires_at < time::now() GROUP ALL",
            )
            .await
            .map_err(DbError::from)?;

        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;
        let total = count_rows.first().map(|r| r.total).unwrap_or(0);

        self.db
            .query("DELETE saml_assertion_replay WHERE expires_at < time::now()")
            .await
            .map_err(DbError::from)?;

        Ok(total)
    }
}
