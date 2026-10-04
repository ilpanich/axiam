//! SurrealDB implementation of [`PendingSamlRequestRepository`] (G-2, T23.2.3,
//! schema v73).
//!
//! A SAML `AuthnRequest` the SSO endpoint has accepted and is holding across
//! the login hop; see [`axiam_core::models::saml_authn_request`].
//!
//! # The two unique indexes
//!
//! * `(tenant_id, replay_key)` — `replay_key` is `{sp_id}:{request_id}` for an
//!   SP-initiated request and `idp:{row id}` for an IdP-initiated one (which
//!   answers no request and so can replay nothing). A second `AuthnRequest`
//!   with an `ID` the SP already used is a unique violation, which is the
//!   replay answer (`AxiamError::ReplayDetected`, through the one classifier
//!   every replay guard shares). Consumed rows are **kept** until they expire,
//!   so the guard spans the row's whole life rather than ending at its use.
//! * `handle_hash` — the digest of the opaque handle; a collision is 256 bits of
//!   chance and is classified as a replay rather than swallowed.
//!
//! # Consumption — the X6 two-layer arbiter
//!
//! Exactly the shape `device_grant::redeem` uses (see its comments and
//! `helpers::is_transaction_conflict`): a guarded `UPDATE … WHERE status =
//! 'pending'` inside an explicit transaction, so the deployed engine aborts the
//! loser of a race; then, in a **separate** query after the commit, a read-back
//! of the per-attempt nonce, so a racer whose write landed but was overwritten
//! learns it lost.

use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::models::saml_authn_request::{NewPendingSamlRequest, PendingSamlRequest};
use axiam_core::repository::PendingSamlRequestRepository;
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{classify_replay_write_error, cleanup_expired_rows, is_transaction_conflict};

const SELECT_FIELDS: &str = "meta::id(id) AS record_id, tenant_id, sp_id, request_id, \
     acs_url, relay_state, force_authn, is_passive, binding_hash, created_at, expires_at";

#[derive(Debug, SurrealValue)]
struct PendingRow {
    record_id: String,
    tenant_id: String,
    sp_id: String,
    request_id: Option<String>,
    acs_url: String,
    relay_state: Option<String>,
    force_authn: bool,
    is_passive: bool,
    binding_hash: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl PendingRow {
    fn try_into_request(self) -> Result<PendingSamlRequest, DbError> {
        let parse = |raw: &str, what: &str| {
            Uuid::parse_str(raw)
                .map_err(|_| DbError::Migration(format!("invalid {what} in saml_authn_request")))
        };
        Ok(PendingSamlRequest {
            id: parse(&self.record_id, "id")?,
            tenant_id: parse(&self.tenant_id, "tenant_id")?,
            sp_id: parse(&self.sp_id, "sp_id")?,
            request_id: self.request_id,
            acs_url: self.acs_url,
            relay_state: self.relay_state,
            force_authn: self.force_authn,
            is_passive: self.is_passive,
            binding_hash: self.binding_hash,
            created_at: self.created_at,
            expires_at: self.expires_at,
        })
    }
}

/// SurrealDB implementation of the pending SAML `AuthnRequest` repository.
pub struct SurrealPendingSamlRequestRepository<C: Connection> {
    db: DbHandle<C>,
}

// Manual Clone: no spurious `C: Clone` bound (the `saml_replay` pattern).
impl<C: Connection> Clone for SurrealPendingSamlRequestRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealPendingSamlRequestRepository<C> {
    /// Construct a repository over a database handle.
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }
}

impl<C: Connection> PendingSamlRequestRepository for SurrealPendingSamlRequestRepository<C> {
    async fn create(&self, input: NewPendingSamlRequest) -> AxiamResult<()> {
        let row_id = new_id().to_string();
        let replay_key = match input.request_id.as_deref() {
            Some(request_id) => format!("{}:{request_id}", input.sp_id),
            None => format!("idp:{row_id}"),
        };
        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('saml_authn_request', $id) SET \
                 tenant_id = $tenant_id, \
                 sp_id = $sp_id, \
                 request_id = $request_id, \
                 replay_key = $replay_key, \
                 acs_url = $acs_url, \
                 relay_state = $relay_state, \
                 force_authn = $force_authn, \
                 is_passive = $is_passive, \
                 handle_hash = $handle_hash, \
                 binding_hash = $binding_hash, \
                 status = 'pending', \
                 consumption_id = NONE, \
                 created_at = $created_at, \
                 expires_at = $expires_at",
            )
            .bind(("id", row_id))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("sp_id", input.sp_id.to_string()))
            .bind(("request_id", input.request_id))
            .bind(("replay_key", replay_key))
            .bind(("acs_url", input.acs_url))
            .bind(("relay_state", input.relay_state))
            .bind(("force_authn", input.force_authn))
            .bind(("is_passive", input.is_passive))
            .bind(("handle_hash", input.handle_hash))
            .bind(("binding_hash", input.binding_hash))
            .bind(("created_at", input.created_at))
            .bind(("expires_at", input.expires_at))
            .await
            .map_err(DbError::from)?;

        // The UNIQUE violation IS the answer: this request id was already used
        // with this SP (or, never in practice, the handle collided).
        result
            .check()
            .map_err(classify_replay_write_error)
            .map(|_| ())
    }

    async fn get_pending(
        &self,
        tenant_id: Uuid,
        handle_hash: &str,
    ) -> AxiamResult<Option<PendingSamlRequest>> {
        if handle_hash.is_empty() {
            return Ok(None);
        }
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {SELECT_FIELDS} FROM saml_authn_request \
                 WHERE tenant_id = $tenant_id AND handle_hash = $hash \
                 AND status = 'pending' AND expires_at > time::now() LIMIT 1"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("hash", handle_hash.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<PendingRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(PendingRow::try_into_request)
            .transpose()
            .map_err(Into::into)
    }

    async fn consume(
        &self,
        tenant_id: Uuid,
        handle_hash: &str,
    ) -> AxiamResult<Option<PendingSamlRequest>> {
        if handle_hash.is_empty() {
            return Ok(None);
        }
        // Layer 1: the guarded transition inside an explicit transaction.
        let nonce = new_id().to_string();
        let result = self
            .db
            .current()
            .query(format!(
                "BEGIN TRANSACTION; \
                 LET $before = (UPDATE saml_authn_request \
                     SET status = 'consumed', consumption_id = $nonce \
                     WHERE tenant_id = $tenant_id AND handle_hash = $hash \
                     AND status = 'pending' AND expires_at > time::now() \
                     RETURN BEFORE); \
                 SELECT {SELECT_FIELDS} FROM $before; \
                 COMMIT TRANSACTION"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("hash", handle_hash.to_string()))
            .bind(("nonce", nonce.clone()))
            .await;
        let mut result = match result {
            Ok(r) => r,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };
        // BEGIN=0, LET=1, SELECT=2, COMMIT=3.
        let rows: Vec<PendingRow> = match result.take::<Vec<PendingRow>>(2) {
            Ok(rows) => rows,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };
        if rows.is_empty() {
            return Ok(None);
        }

        // Layer 2: outside, and after, the transaction above.
        let stored = self
            .db
            .current()
            .query(
                "SELECT VALUE consumption_id FROM saml_authn_request \
                 WHERE tenant_id = $tenant_id AND handle_hash = $hash LIMIT 1",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("hash", handle_hash.to_string()))
            .await;
        let mut stored = match stored {
            Ok(r) => r,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };
        let stored: Vec<Option<String>> = match stored.take::<Vec<Option<String>>>(0) {
            Ok(v) => v,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };
        if stored.into_iter().flatten().next().as_deref() != Some(nonce.as_str()) {
            return Ok(None);
        }

        rows.into_iter()
            .next()
            .map(PendingRow::try_into_request)
            .transpose()
            .map_err(Into::into)
    }

    async fn cleanup_expired(&self) -> AxiamResult<u64> {
        cleanup_expired_rows(&self.db, "saml_authn_request").await
    }
}
