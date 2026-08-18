//! SurrealDB implementation of [`AssertionReplayRepository`].
//!
//! Provides insert-or-conflict semantics for SAML assertion IDs. Inserting a
//! `(tenant_id, assertion_id)` pair that already exists returns
//! `Err(AxiamError::ReplayDetected)` so the SAML ACS handler can reject
//! replayed assertions (D-09).

use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::repository::AssertionReplayRepository;
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{classify_replay_write_error, cleanup_expired_rows};

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

/// SurrealDB implementation of the SAML assertion replay repository.
pub struct SurrealAssertionReplayRepository<C: Connection> {
    db: DbHandle<C>,
}

// Manual Clone impl (not derive): avoids the spurious `C: Clone` bound that
// blocks cloning under generic `C: Connection` callers. Matches SurrealUserRepository.
impl<C: Connection> Clone for SurrealAssertionReplayRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealAssertionReplayRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        let db = db.into();
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
        let row_id = new_id().to_string();
        let assertion_id_owned = assertion_id.to_string();

        let result = self
            .db
            .current()
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

        // The UNIQUE violation IS the answer: this assertion ID has been seen.
        // What counts as one is decided in exactly one place (D-09) so the
        // three replay guards cannot drift apart -- see
        // `helpers::is_unique_violation`.
        result
            .check()
            .map_err(classify_replay_write_error)
            .map(|_| ())
    }

    async fn cleanup_expired(&self) -> AxiamResult<u64> {
        cleanup_expired_rows(&self.db, "saml_assertion_replay").await
    }
}
