//! SurrealDB implementation of [`AmqpNonceRepository`] (NEW-4).
//!
//! Provides insert-or-conflict semantics for AMQP message nonces. Inserting a
//! `(tenant_id, nonce)` pair that already exists returns
//! `Err(AxiamError::ReplayDetected)` so the authz/audit AMQP consumers can
//! reject replayed messages (NEW-4). Mirrors [`super::saml_replay`].

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::repository::AmqpNonceRepository;
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use uuid::Uuid;

use crate::error::DbError;
use crate::helpers::CountRow;

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

/// SurrealDB implementation of the AMQP nonce replay repository (NEW-4).
pub struct SurrealAmqpNonceRepository<C: Connection> {
    db: Surreal<C>,
}

// Manual Clone impl (not derive): avoids the spurious `C: Clone` bound that
// blocks cloning under generic `C: Connection` callers. Matches
// SurrealAssertionReplayRepository.
impl<C: Connection> Clone for SurrealAmqpNonceRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealAmqpNonceRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> AmqpNonceRepository for SurrealAmqpNonceRepository<C> {
    async fn insert_nonce(
        &self,
        tenant_id: Uuid,
        nonce: Uuid,
        expires_at: DateTime<Utc>,
    ) -> AxiamResult<()> {
        let row_id = Uuid::new_v4().to_string();

        let result = self
            .db
            .query(
                "CREATE type::record('amqp_nonce_replay', $row_id) SET \
                 tenant_id = $tenant_id, \
                 nonce = $nonce, \
                 expires_at = $expires_at",
            )
            .bind(("row_id", row_id))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("nonce", nonce.to_string()))
            .bind(("expires_at", expires_at))
            .await
            .map_err(DbError::from)?;

        result
            .check()
            .map_err(|e| {
                let msg = e.to_string();
                // SurrealDB v3 UNIQUE index violation message contains
                // "already contains" (e.g. "Database index
                // `idx_amqp_nonce_uniq` already contains [...]"). Also match
                // "already exists" and "unique" as fallback patterns.
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
                "SELECT count() AS total FROM amqp_nonce_replay \
                 WHERE expires_at < time::now() GROUP ALL",
            )
            .await
            .map_err(DbError::from)?;

        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;
        let total = count_rows.first().map(|r| r.total).unwrap_or(0);

        self.db
            .query("DELETE amqp_nonce_replay WHERE expires_at < time::now()")
            .await
            .map_err(DbError::from)?;

        Ok(total)
    }
}
