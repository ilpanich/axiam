//! SurrealDB implementation of [`PermissionTicketRepository`] (UMA 2.0 / X2).
//!
//! # Why `consume` layers a transaction under a nonce
//!
//! UMA 2.0 §3.3 makes a permission ticket single-use, so a read-then-write
//! would let two concurrent redemptions both spend one ticket. Putting the
//! precondition — unconsumed, unexpired, right tenant, right client — in the
//! `WHERE` clause of a single `UPDATE` is necessary but **not sufficient**: on
//! its own, without an explicit transaction around it, eight concurrent
//! redemptions of one ticket all succeed.
//!
//! Single-use **is** guaranteed here, conditional on running an attested
//! persistent storage engine (X6, #302). It is not one mechanism but two, and
//! a double redemption needs both to fail on the same ticket:
//!
//!   1. **The engine arbitrates.** The guarded `UPDATE` runs inside an explicit
//!      `BEGIN`/`COMMIT`, so two concurrent redemptions are a write-write
//!      conflict on one key and the loser is aborted. Measured with
//!      `tools/surreal-race-probe` on the engines AXIAM deploys: 0 double
//!      redemptions in 5000 rounds of 8 racers on `surrealkv` (what compose and
//!      the k8s StatefulSet run) and 0 in 1200 on `rocksdb`, with the engine
//!      aborting 54% of contended attempts. `kv-mem` aborts at the same rate
//!      and then silently misses 23 times in 1200 — which is what "conditional
//!      on a persistent engine" means, and why `axiam-server` attests the
//!      engine at startup (`axiam_db::engine_attestation`).
//!   2. **The nonce audits it.** Each attempt stamps its own `redemption_id`,
//!      and after the transaction commits a separate query reads the row back;
//!      only the caller whose nonce survived reports a redemption. This asks
//!      the engine for nothing, so a conflict the engine misses is caught here
//!      **unless the two commits interleave around the read-back** — if A
//!      commits, A reads back and sees its own nonce, and only then B's
//!      concurrent transaction commits, B's later read-back sees B's nonce and
//!      both callers report a redemption (SEC-105). So what this layer buys is
//!      precisely what §X6.2 promises and no more: a double redemption needs
//!      **two independent failures**, not one. It is not "the nonce catches
//!      any conflict the engine misses" — the project's own measurement agrees,
//!      recording the nonce-with-read-back shape at 1/640 on `kv-mem`
//!      (`claude_dev/extra-B-track-features.md` §X6.1).
//!
//! The read-back **must** stay outside the transaction, in a query of its own
//! after the commit. Inside it, snapshot isolation shows every racer its own
//! write and every racer believes it won — the occasional double redemption
//! becomes a guaranteed one. `SCHEMA_V31` records that trap and the layering.
//!
//! On `kv-mem` single-use is explicitly **not** guaranteed: the nonce leaks
//! there too (6 rounds in 1200). Running it is now an operator's deliberate,
//! logged choice rather than an accident — see `ALLOW_MEMORY_ENGINE_ENV`.
//!
//! Neither is a uniqueness constraint an alternative: a claim keyed on a record
//! ID is far worse (30/1200), and a `UNIQUE` index tripled the failure rate in
//! this path (3/320 against 1/320) because the extra write lengthens the window
//! without reliably being enforced. `SCHEMA_V31` carries the full comparison,
//! and #302 records why no fifth query-layer mechanism was sought.
//!
//! `concurrent_redemptions_yield_exactly_one_winner` is the regression test. It
//! runs on `surrealkv` and over many rounds as of 2026-08; before that it ran
//! one unsynchronised round against `kv-mem`, which is why the residual it was
//! meant to guard went unobserved in CI for as long as it did. The test that
//! fails the OLD mechanism reliably — #302's acceptance bar — is the probe
//! itself, `surreal-race-probe mem tx 1200 8`; see its README.
//!
//! # Why `client_id` is in that clause and not checked afterwards
//!
//! A ticket is bound to the resource server that minted it. If the binding
//! were checked on the returned row, a ticket leaked to another client would
//! be *burned* by that client's failed attempt — the rightful holder's ticket
//! destroyed by someone who was never entitled to it. Matching it in the
//! statement means a wrong-client redemption changes nothing.

use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::models::uma::{CreatePermissionTicket, PermissionTicket, RequestedPermission};
use axiam_core::repository::PermissionTicketRepository;
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
     ticket_hash, permissions, consumed, expires_at, created_at";

#[derive(Debug, SurrealValue)]
struct PermissionTicketRow {
    record_id: String,
    tenant_id: String,
    client_id: String,
    ticket_hash: String,
    permissions: Vec<RequestedPermissionRow>,
    consumed: bool,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

/// One stored `(resource, scopes)` tuple.
///
/// A row type of its own rather than reusing [`RequestedPermission`] directly
/// because the domain type is `serde`-shaped and this one is
/// `SurrealValue`-shaped — the same split every other repository here uses.
/// `resource_id` is stored as a string for the same reason `tenant_id` is.
#[derive(Debug, SurrealValue)]
struct RequestedPermissionRow {
    resource_id: String,
    resource_scopes: Vec<String>,
}

impl From<RequestedPermission> for RequestedPermissionRow {
    fn from(p: RequestedPermission) -> Self {
        Self {
            resource_id: p.resource_id.to_string(),
            resource_scopes: p.resource_scopes,
        }
    }
}

impl RequestedPermissionRow {
    fn try_into_permission(self) -> Result<RequestedPermission, DbError> {
        Ok(RequestedPermission {
            resource_id: Uuid::parse_str(&self.resource_id)
                .map_err(|e| DbError::Migration(format!("invalid resource UUID: {e}")))?,
            resource_scopes: self.resource_scopes,
        })
    }
}

impl PermissionTicketRow {
    fn try_into_ticket(self) -> Result<PermissionTicket, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid permission ticket UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let permissions = self
            .permissions
            .into_iter()
            .map(RequestedPermissionRow::try_into_permission)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PermissionTicket {
            id,
            tenant_id,
            ticket_hash: self.ticket_hash,
            client_id: self.client_id,
            permissions,
            consumed: self.consumed,
            expires_at: self.expires_at,
            created_at: self.created_at,
        })
    }
}

/// SurrealDB implementation of the permission-ticket repository.
#[derive(Clone)]
pub struct SurrealPermissionTicketRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> SurrealPermissionTicketRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }
}

impl<C: Connection> PermissionTicketRepository for SurrealPermissionTicketRepository<C> {
    async fn create(&self, input: CreatePermissionTicket) -> AxiamResult<PermissionTicket> {
        let id = new_id();
        let permissions: Vec<RequestedPermissionRow> = input
            .permissions
            .into_iter()
            .map(RequestedPermissionRow::from)
            .collect();

        let mut result = self
            .db
            .current()
            .query(format!(
                "LET $created = (CREATE type::record('permission_ticket', $id) SET \
                     tenant_id = $tenant_id, \
                     client_id = $client_id, \
                     ticket_hash = $hash, \
                     permissions = $permissions, \
                     consumed = false, \
                     expires_at = $expires_at); \
                 SELECT {SELECT_FIELDS} FROM $created"
            ))
            .bind(("id", id.to_string()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("client_id", input.client_id))
            .bind(("hash", input.ticket_hash))
            .bind(("permissions", permissions))
            .bind(("expires_at", input.expires_at))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<PermissionTicketRow> = result.take(1).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .ok_or_else(|| DbError::Migration("permission_ticket insert returned no row".into()))?
            .try_into_ticket()
            .map_err(Into::into)
    }

    async fn consume(
        &self,
        tenant_id: Uuid,
        ticket_hash: &str,
        client_id: &str,
    ) -> AxiamResult<Option<PermissionTicket>> {
        // `RETURN BEFORE` yields the pre-transition row. Marking `consumed`
        // rather than deleting keeps "already used" distinguishable from
        // "never existed" for the audit trail, even though both answer
        // `invalid_grant` on the wire.
        //
        // Two layers, in two queries (X6/#302 — see the module header).
        //
        // Layer 1, here: the guarded `UPDATE` inside an explicit transaction,
        // so two concurrent redemptions conflict on one key and the deployed
        // engine aborts the loser. `WHERE consumed = false` is still required
        // — it is what makes a later, non-concurrent replay match nothing and
        // leave the first winner's nonce undisturbed.
        //
        // Layer 2, in the SEPARATE query below: read the nonce back after this
        // transaction has committed. It must not be folded into the statements
        // here. Under snapshot isolation a racer inside the transaction sees
        // its own write, so every racer would read back its own nonce and
        // believe it won — an occasional double redemption would become a
        // certain one (`SCHEMA_V31`).
        let nonce = new_id().to_string();
        let result = self
            .db
            .current()
            .query(format!(
                "BEGIN TRANSACTION; \
                 LET $before = (UPDATE permission_ticket \
                     SET consumed = true, redemption_id = $nonce \
                     WHERE tenant_id = $tenant_id AND ticket_hash = $hash \
                     AND client_id = $client_id \
                     AND consumed = false AND expires_at > time::now() \
                     RETURN BEFORE); \
                 SELECT {SELECT_FIELDS} FROM $before; \
                 COMMIT TRANSACTION"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("hash", ticket_hash.to_string()))
            .bind(("client_id", client_id.to_string()))
            .bind(("nonce", nonce.clone()))
            .await;

        // A loser's abort is this method's "someone else redeemed first"
        // answer, not a server fault; propagating it would turn a
        // correctly-refused replay into a 500.
        let mut result = match result {
            Ok(r) => r,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };

        // BEGIN=0, LET=1, SELECT=2, COMMIT=3.
        let rows: Vec<PermissionTicketRow> = match result.take::<Vec<PermissionTicketRow>>(2) {
            Ok(rows) => rows,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };
        if rows.is_empty() {
            // Nothing matched: unknown, already consumed, expired, or the
            // wrong client. No write happened, so nothing was burned.
            return Ok(None);
        }

        // Layer 2: outside, and after, the transaction above.
        let stored = self
            .db
            .current()
            .query(
                "SELECT VALUE redemption_id FROM permission_ticket \
                 WHERE tenant_id = $tenant_id AND ticket_hash = $hash LIMIT 1",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("hash", ticket_hash.to_string()))
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
            // Our write landed but someone else's landed after it. They hold
            // the redemption; this caller must not also report one. The ticket
            // is spent either way, so `consumed` staying true is correct.
            return Ok(None);
        }

        rows.into_iter()
            .next()
            .map(PermissionTicketRow::try_into_ticket)
            .transpose()
            .map_err(Into::into)
    }

    async fn find_by_hash(
        &self,
        tenant_id: Uuid,
        ticket_hash: &str,
    ) -> AxiamResult<Option<PermissionTicket>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {SELECT_FIELDS} FROM permission_ticket \
                 WHERE tenant_id = $tenant_id AND ticket_hash = $hash LIMIT 1"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("hash", ticket_hash.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<PermissionTicketRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(PermissionTicketRow::try_into_ticket)
            .transpose()
            .map_err(Into::into)
    }

    async fn cleanup_expired(&self, tenant_id: Uuid) -> AxiamResult<u64> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT count() AS c FROM (DELETE permission_ticket \
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
        Ok(rows.into_iter().next().map(|r| r.c as u64).unwrap_or(0))
    }
}
