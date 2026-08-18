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

use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::repository::{ProofKind, ProofReplayRepository};
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{classify_replay_write_error, cleanup_expired_rows};

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

        // The UNIQUE violation IS the answer: this `jti` has been presented
        // before. The three replay guards used to carry a hand-copied marker
        // set each, kept identical by hand so they "cannot drift into
        // disagreeing about what a conflict looks like" -- the right worry,
        // and a mechanism that would have let a security fix land in two of
        // three files. They now share one definition (D-09).
        result
            .check()
            .map_err(classify_replay_write_error)
            .map(|_| ())
    }

    async fn cleanup_expired_proofs(&self) -> AxiamResult<u64> {
        cleanup_expired_rows(&self.db, "oauth2_proof_replay").await
    }
}
