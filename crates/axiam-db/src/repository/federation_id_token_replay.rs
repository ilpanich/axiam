//! SurrealDB implementation of [`ProviderIdTokenReplayRepository`] (G-A,
//! #816, D-N10).
//!
//! The provider-issued ID tokens a native sign-in consumed, by hash. The same
//! mechanism as [`saml_replay`](super::saml_replay) and
//! [`oauth2_proof_replay`](super::oauth2_proof_replay): `CREATE` against a
//! table with a `UNIQUE` index, and the index violation **is** the "already
//! seen" answer. No `SELECT` in the path, so two concurrent presentations of
//! one token cannot both see "not seen".

use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::repository::ProviderIdTokenReplayRepository;
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use uuid::Uuid;

use crate::handle::DbHandle;
use crate::helpers::{classify_replay_write_error, cleanup_expired_rows, is_transaction_conflict};

/// SurrealDB implementation of the provider ID-token replay repository.
pub struct SurrealProviderIdTokenReplayRepository<C: Connection> {
    db: DbHandle<C>,
}

// Manual Clone impl (not derive): avoids the spurious `C: Clone` bound, as
// the other replay repositories do.
impl<C: Connection> Clone for SurrealProviderIdTokenReplayRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealProviderIdTokenReplayRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }

    /// One `CREATE`; the error is the engine's, unclassified.
    async fn try_insert(
        &self,
        tenant_id: Uuid,
        provider_id: Uuid,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), surrealdb::Error> {
        self.db
            .current()
            .query(
                "CREATE type::record('federation_id_token_replay', $row_id) SET \
                 tenant_id = $tenant_id, \
                 provider_id = $provider_id, \
                 token_hash = $token_hash, \
                 expires_at = $expires_at",
            )
            .bind(("row_id", new_id().to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("provider_id", provider_id.to_string()))
            .bind(("token_hash", token_hash.to_owned()))
            .bind(("expires_at", expires_at))
            .await?
            .check()
            .map(|_| ())
    }
}

impl<C: Connection> ProviderIdTokenReplayRepository for SurrealProviderIdTokenReplayRepository<C> {
    async fn insert_id_token(
        &self,
        tenant_id: Uuid,
        provider_id: Uuid,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> AxiamResult<()> {
        // On the engine production runs (`surrealkv`), concurrent `CREATE`s
        // under one UNIQUE index can abort with a retryable write conflict
        // instead of the violation. An aborted `CREATE` wrote nothing, so it is
        // tried again: the retry either records the token or meets the
        // winner's row as the violation, i.e. `ReplayDetected`. Bounded, and a
        // conflict that outlasts the bound is a `Database` error — which the
        // caller treats as "cannot record", and refuses.
        const ATTEMPTS: usize = 4;
        let mut attempt = 1;
        loop {
            match self
                .try_insert(tenant_id, provider_id, token_hash, expires_at)
                .await
            {
                Err(e) if attempt < ATTEMPTS && is_transaction_conflict(&e) => attempt += 1,
                // The UNIQUE violation is the answer, classified by the one
                // shared definition every replay guard uses (D-09).
                other => return other.map_err(classify_replay_write_error),
            }
        }
    }

    async fn cleanup_expired(&self) -> AxiamResult<u64> {
        cleanup_expired_rows(&self.db, "federation_id_token_replay").await
    }
}
