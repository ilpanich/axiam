//! SurrealDB implementation of [`PushedAuthRequestRepository`] (RFC 9126 / B5).
//!
//! # Why `consume` layers a transaction under a nonce
//!
//! Same reason as the device grant's `redeem` and refresh-token rotation: a
//! `request_uri` is single-use by RFC 9126 §2.2, and a read-then-write would
//! let two concurrent authorize requests both spend one pushed request. The
//! precondition — unconsumed, unexpired, right tenant — lives in the `WHERE`
//! clause, which is what makes a later, non-concurrent replay match nothing.
//!
//! Expiry is part of that same clause rather than a check in the service, so a
//! request cannot be consumed in the window between the service reading it and
//! writing it back.
//!
//! Single-use is a **guarantee, conditional on an attested persistent storage
//! engine** (X6, #302), carried by the same two layers as
//! `permission_ticket.consume` and `device_grant.redeem`:
//!
//!   1. The guarded `UPDATE` runs inside an explicit `BEGIN`/`COMMIT`, so two
//!      concurrent authorize requests conflict on one key and the deployed
//!      engine aborts the loser — 0 double consumes in 5000 rounds of 8 racers
//!      on `surrealkv` and 0 in 1200 on `rocksdb` (`tools/surreal-race-probe`),
//!      against 23 in 1200 on `kv-mem`, which arbitrates at the same 54% rate
//!      and then silently misses.
//!   2. A per-attempt nonce is read back **after** the commit, in a query of
//!      its own; only the caller whose nonce survived reports a consume. It
//!      asks the engine for nothing, so it catches a conflict the engine
//!      missed, and it must stay outside the transaction — inside one, every
//!      racer sees its own write and believes it won (`SCHEMA_V31`).
//!
//! RFC 9126 §2.2 makes `request_uri` one-time-use precisely because a
//! replayable one is a replayable authorization request. On `kv-mem` the
//! guarantee does not hold and is not claimed; `axiam-server` attests the
//! engine at startup (`axiam_db::engine_attestation`).

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
        // Two layers, in two queries (X6/#302 — see the module header).
        //
        // Layer 1, here: the guarded `UPDATE` inside an explicit transaction,
        // so two concurrent authorize requests conflict on one key and the
        // deployed engine aborts the loser. `consumed = false` stays in the
        // clause — it is what makes a later, non-concurrent replay match
        // nothing.
        //
        // Layer 2, in the SEPARATE query below: the per-attempt nonce read back
        // after this transaction has committed, never folded into it (inside a
        // transaction every racer sees its own write and believes it won —
        // `SCHEMA_V31`).
        let nonce = new_id().to_string();
        let result = self
            .db
            .current()
            .query(format!(
                "BEGIN TRANSACTION; \
                 LET $before = (UPDATE pushed_auth_request \
                     SET consumed = true, redemption_id = $nonce \
                     WHERE tenant_id = $tenant_id AND request_uri_hash = $hash \
                     AND consumed = false AND expires_at > time::now() \
                     RETURN BEFORE); \
                 SELECT {SELECT_FIELDS} FROM $before; \
                 COMMIT TRANSACTION"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("hash", request_uri_hash.to_string()))
            .bind(("nonce", nonce.clone()))
            .await;

        // A loser's abort is this method's "someone else consumed it" answer,
        // not a server fault.
        let mut result = match result {
            Ok(r) => r,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };

        // BEGIN=0, LET=1, SELECT=2, COMMIT=3.
        let rows: Vec<PushedAuthRequestRow> = match result.take::<Vec<PushedAuthRequestRow>>(2) {
            Ok(rows) => rows,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };
        if rows.is_empty() {
            // Unknown, already consumed, or expired. Nothing was written.
            return Ok(None);
        }

        // Layer 2: outside, and after, the transaction above.
        let stored = self
            .db
            .current()
            .query(
                "SELECT VALUE redemption_id FROM pushed_auth_request \
                 WHERE tenant_id = $tenant_id AND request_uri_hash = $hash LIMIT 1",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("hash", request_uri_hash.to_string()))
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
