//! SurrealDB implementation of [`AmqpNonceRepository`] (NEW-4).
//!
//! Provides insert-or-conflict semantics for AMQP message nonces. Inserting a
//! `(tenant_id, nonce)` pair that already exists returns
//! `Err(AxiamError::ReplayDetected)` so the authz/audit AMQP consumers can
//! reject replayed messages (NEW-4). Mirrors [`super::saml_replay`].

use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::repository::AmqpNonceRepository;
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{classify_replay_write_error, cleanup_expired_rows};

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

/// SurrealDB implementation of the AMQP nonce replay repository (NEW-4).
pub struct SurrealAmqpNonceRepository<C: Connection> {
    db: DbHandle<C>,
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
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        let db = db.into();
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
        let row_id = new_id().to_string();

        let result = self
            .db
            .current()
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

        // The UNIQUE violation IS the answer: this nonce has been seen, so the
        // message is a replay. What counts as one is decided in exactly one
        // place (D-09) -- see `helpers::is_unique_violation`.
        result
            .check()
            .map_err(classify_replay_write_error)
            .map(|_| ())
    }

    async fn cleanup_expired(&self) -> AxiamResult<u64> {
        cleanup_expired_rows(&self.db, "amqp_nonce_replay").await
    }
}
