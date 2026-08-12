//! SurrealDB implementation of [`PushedAuthRequestRepository`] (RFC 9126 / B5).
//!
//! # Why `consume` is one statement
//!
//! Same reason as the device grant's `redeem` and refresh-token rotation: a
//! `request_uri` is single-use by RFC 9126 §2.2, and a read-then-write would
//! let two concurrent authorize requests both spend one pushed request. The
//! precondition — unconsumed, unexpired, right tenant — lives in the `WHERE`
//! clause so the datastore serialises the racers and exactly one sees the
//! before-image.
//!
//! Expiry is part of that same clause rather than a check in the service, so a
//! request cannot be consumed in the window between the service reading it and
//! writing it back.

use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::models::oauth2_client::{
    CreatePushedAuthRequest, PushedAuthParams, PushedAuthRequest,
};
use axiam_core::repository::PushedAuthRequestRepository;
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::is_transaction_conflict;

/// Projected explicitly rather than `SELECT *` so that `meta::id(id)` lands in
/// `record_id`; a bare `*` yields SurrealDB's `Thing`, which does not
/// deserialize into a `String`.
const SELECT_FIELDS: &str = "meta::id(id) AS record_id, tenant_id, client_id, \
     request_uri_hash, params, consumed, expires_at, created_at";

#[derive(Debug, SurrealValue)]
struct PushedAuthRequestRow {
    record_id: String,
    tenant_id: String,
    client_id: String,
    request_uri_hash: String,
    params: PushedAuthParamsRow,
    consumed: bool,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

/// The stored parameter object.
///
/// A row of its own rather than reusing [`PushedAuthParams`] directly because
/// the domain type is `serde`-shaped and this one is `SurrealValue`-shaped;
/// keeping them separate is the same split every other repository here uses.
#[derive(Debug, SurrealValue)]
struct PushedAuthParamsRow {
    response_type: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
}

impl From<PushedAuthParams> for PushedAuthParamsRow {
    fn from(p: PushedAuthParams) -> Self {
        Self {
            response_type: p.response_type,
            redirect_uri: p.redirect_uri,
            scope: p.scope,
            state: p.state,
            code_challenge: p.code_challenge,
            code_challenge_method: p.code_challenge_method,
            nonce: p.nonce,
        }
    }
}

impl From<PushedAuthParamsRow> for PushedAuthParams {
    fn from(p: PushedAuthParamsRow) -> Self {
        Self {
            response_type: p.response_type,
            redirect_uri: p.redirect_uri,
            scope: p.scope,
            state: p.state,
            code_challenge: p.code_challenge,
            code_challenge_method: p.code_challenge_method,
            nonce: p.nonce,
        }
    }
}

impl PushedAuthRequestRow {
    fn try_into_request(self) -> Result<PushedAuthRequest, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid pushed request UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        Ok(PushedAuthRequest {
            id,
            tenant_id,
            client_id: self.client_id,
            request_uri_hash: self.request_uri_hash,
            params: self.params.into(),
            consumed: self.consumed,
            expires_at: self.expires_at,
            created_at: self.created_at,
        })
    }
}

/// SurrealDB implementation of the pushed-authorization-request repository.
#[derive(Clone)]
pub struct SurrealPushedAuthRequestRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> SurrealPushedAuthRequestRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }
}

impl<C: Connection> PushedAuthRequestRepository for SurrealPushedAuthRequestRepository<C> {
    async fn create(&self, input: CreatePushedAuthRequest) -> AxiamResult<PushedAuthRequest> {
        let id = new_id();
        let params: PushedAuthParamsRow = input.params.into();

        let mut result = self
            .db
            .current()
            .query(format!(
                "LET $created = (CREATE type::record('pushed_auth_request', $id) SET \
                     tenant_id = $tenant_id, \
                     client_id = $client_id, \
                     request_uri_hash = $hash, \
                     params = $params, \
                     consumed = false, \
                     expires_at = $expires_at); \
                 SELECT {SELECT_FIELDS} FROM $created"
            ))
            .bind(("id", id.to_string()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("client_id", input.client_id))
            .bind(("hash", input.request_uri_hash))
            .bind(("params", params))
            .bind(("expires_at", input.expires_at))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<PushedAuthRequestRow> = result.take(1).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .ok_or_else(|| DbError::Migration("pushed_auth_request insert returned no row".into()))?
            .try_into_request()
            .map_err(Into::into)
    }

    async fn consume(
        &self,
        tenant_id: Uuid,
        request_uri_hash: &str,
    ) -> AxiamResult<Option<PushedAuthRequest>> {
        // `RETURN BEFORE` yields the pre-transition row. Marking `consumed`
        // rather than deleting keeps "already used" distinguishable from
        // "never existed" in an audit trail, even though both answer
        // `invalid_request` on the wire.
        //
        // The `consumed = false` guard is what makes a later, non-concurrent
        // authorize request match nothing. It does not decide a *concurrent*
        // one. The `BEGIN`/`COMMIT` this used to rely on was measured not to
        // either — but on `kv-mem`, the engine this crate's tests opened and
        // one AXIAM does not deploy. Re-measured in 2026-08
        // (`tools/surreal-race-probe`), `surrealkv` and `rocksdb` both admit
        // exactly one winner in every contended round; `kv-mem` does not. The
        // addendum in `SCHEMA_V31` has the table.
        //
        // RFC 9126 §2.2 makes `request_uri` one-time-use precisely because a
        // replayable one is a replayable authorization request, which is why
        // the nonce stays even now that the engine looks sufficient on its own.
        //
        // So the race is decided here as well: each attempt stamps a nonce, the
        // last write persists, and the third statement reads back to see whose
        // it was. See `SCHEMA_V31` for the measurements and for what the engine
        // rather than this code contributes.
        //
        // Deliberately **not** in a transaction: inside one the read-back would
        // see this caller's own write under snapshot isolation and every racer
        // would believe it won.
        let nonce = new_id().to_string();
        let result = self
            .db
            .current()
            .query(format!(
                "LET $before = (UPDATE pushed_auth_request \
                     SET consumed = true, redemption_id = $nonce \
                     WHERE tenant_id = $tenant_id AND request_uri_hash = $hash \
                     AND consumed = false AND expires_at > time::now() \
                     RETURN BEFORE); \
                 SELECT {SELECT_FIELDS} FROM $before; \
                 SELECT VALUE redemption_id FROM pushed_auth_request \
                     WHERE tenant_id = $tenant_id AND request_uri_hash = $hash LIMIT 1"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("hash", request_uri_hash.to_string()))
            .bind(("nonce", nonce.clone()))
            .await;

        // Each statement is its own transaction, so a conflict is still
        // possible. A loser's conflict is this method's "someone else consumed
        // it" answer, not a server fault.
        let mut result = match result {
            Ok(r) => r,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };

        // LET=0, SELECT rows=1, SELECT nonce=2.
        let rows: Vec<PushedAuthRequestRow> = match result.take::<Vec<PushedAuthRequestRow>>(1) {
            Ok(rows) => rows,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };
        if rows.is_empty() {
            // Unknown, already consumed, or expired. Nothing was written.
            return Ok(None);
        }

        let stored: Vec<Option<String>> = match result.take::<Vec<Option<String>>>(2) {
            Ok(v) => v,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };
        if stored.into_iter().flatten().next().as_deref() != Some(nonce.as_str()) {
            // Our write landed but another authorize request's landed after it.
            // That one holds the consumption; this one must not replay it.
            return Ok(None);
        }

        rows.into_iter()
            .next()
            .map(PushedAuthRequestRow::try_into_request)
            .transpose()
            .map_err(Into::into)
    }

    async fn cleanup_expired(&self, tenant_id: Uuid) -> AxiamResult<u64> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT count() AS c FROM (DELETE pushed_auth_request \
                 WHERE tenant_id = $tenant_id AND expires_at <= time::now() \
                 RETURN BEFORE) GROUP ALL",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        #[derive(Debug, SurrealValue)]
        struct CountRow {
            c: i64,
        }
        let rows: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.first().map(|r| r.c.max(0) as u64).unwrap_or(0))
    }
}
