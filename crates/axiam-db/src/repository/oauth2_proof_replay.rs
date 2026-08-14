//! SurrealDB implementation of [`ProofReplayRepository`] (X5.1).
//!
//! Insert-or-conflict semantics for the `jti` values of RFC 7523 client
//! assertions and RFC 9449 DPoP proofs. This is the same mechanism
//! [`saml_replay`](super::saml_replay) and
//! [`amqp_nonce_replay`](super::amqp_nonce_replay) use, deliberately: `CREATE`
//! against a table with a `UNIQUE` index, and the index violation **is** the
//! "already seen" answer.
//!
//! There is no `SELECT` in this file, and that absence is the design. A
//! read-then-write replay check leaves a window between the read and the write
//! in which two concurrent copies of the same proof both see "not seen" — the
//! exact race X6 (#316) and #318 closed for authorization codes. A
//! proof-of-possession credential that survives one concurrent replay is not a
//! proof of possession.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::id::new_id;
use axiam_core::repository::{ProofKind, ProofReplayRepository};
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::CountRow;

/// SurrealDB implementation of the OAuth2 proof-replay repository.
pub struct SurrealProofReplayRepository<C: Connection> {
    db: DbHandle<C>,
}

// Manual Clone impl (not derive): avoids the spurious `C: Clone` bound that
// blocks cloning under generic `C: Connection` callers. Matches
// SurrealAssertionReplayRepository.
impl<C: Connection> Clone for SurrealProofReplayRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealProofReplayRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }
}

impl<C: Connection> ProofReplayRepository for SurrealProofReplayRepository<C> {
    async fn insert_proof_jti(
        &self,
        tenant_id: Uuid,
        kind: ProofKind,
        scope: &str,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> AxiamResult<()> {
        let row_id = new_id().to_string();

        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('oauth2_proof_replay', $row_id) SET \
                 tenant_id = $tenant_id, \
                 kind = $kind, \
                 scope = $scope, \
                 jti = $jti, \
                 expires_at = $expires_at",
            )
            .bind(("row_id", row_id))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("kind", kind.as_str().to_owned()))
            .bind(("scope", scope.to_owned()))
            .bind(("jti", jti.to_owned()))
            .bind(("expires_at", expires_at))
            .await
            .map_err(DbError::from)?;

        result
            .check()
            .map_err(|e| {
                let msg = e.to_string();
                // SurrealDB v3 reports a UNIQUE index violation as "Database
                // index `idx_proof_replay_uniq` already contains [...]". The
                // other two patterns are the same fallbacks
                // `saml_replay::insert_assertion` carries, kept identical so
                // the three replay guards cannot drift into disagreeing about
                // what a conflict looks like.
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

    async fn cleanup_expired_proofs(&self) -> AxiamResult<u64> {
        let mut count_result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM oauth2_proof_replay \
                 WHERE expires_at < time::now() GROUP ALL",
            )
            .await
            .map_err(DbError::from)?;

        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;
        let total = count_rows.first().map(|r| r.total).unwrap_or(0);

        self.db
            .current()
            .query("DELETE oauth2_proof_replay WHERE expires_at < time::now()")
            .await
            .map_err(DbError::from)?;

        Ok(total)
    }
}
