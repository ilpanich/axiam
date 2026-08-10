//! SurrealDB implementation of [`PermissionTicketRepository`] (UMA 2.0 / X2).
//!
//! # Why `consume` is a transaction and not a bare statement
//!
//! UMA 2.0 §3.3 makes a permission ticket single-use, so a read-then-write
//! would let two concurrent redemptions both spend one ticket. Putting the
//! precondition — unconsumed, unexpired, right tenant, right client — in the
//! `WHERE` clause of a single `UPDATE` is necessary but **not sufficient**:
//! measured against SurrealDB, eight concurrent redemptions of one ticket all
//! succeed without an explicit transaction around it. The conflict is simply
//! not detected.
//!
//! Wrapping it in `BEGIN`/`COMMIT` makes the datastore detect the write-write
//! conflict and abort every loser, which is then translated to `None` — see
//! `is_transaction_conflict`. `concurrent_redemptions_yield_exactly_one_winner`
//! is the regression test, and it fails with 4 winners out of 8 if the
//! transaction is removed.
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

/// Whether a SurrealDB error is a write-write transaction conflict.
///
/// Matched on the message because the driver surfaces it as an opaque `Db`
/// error rather than a typed variant. Narrow by design: only a conflict is
/// swallowed, and only into "someone else won the race" — every other failure
/// still propagates.
fn is_transaction_conflict(e: &surrealdb::Error) -> bool {
    let msg = e.to_string();
    msg.contains("failed transaction") || msg.contains("Failed to commit transaction")
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
        // `RETURN BEFORE` yields the pre-transition row, so exactly one
        // concurrent redemption sees a non-empty result and any other sees
        // nothing. Marking `consumed` rather than deleting keeps "already
        // used" distinguishable from "never existed" for the audit trail,
        // even though both answer `invalid_grant` on the wire.
        let result = self
            .db
            .current()
            .query(format!(
                "BEGIN TRANSACTION; \
                 LET $before = (UPDATE permission_ticket SET consumed = true \
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
            .await;

        // A concurrent redemption of the same ticket aborts this transaction
        // with a write-write conflict. That is not a server fault — it is the
        // datastore reporting that someone else redeemed first, which is
        // exactly the answer this method exists to give. Translating it to
        // `None` is what makes single-use hold under load; propagating it
        // would turn a correctly-refused replay into a 500.
        //
        // Without the surrounding transaction the conflict is not detected at
        // all and every concurrent caller "succeeds" — see
        // `concurrent_redemptions_yield_exactly_one_winner`, which fails with
        // 4 winners out of 8 if the BEGIN/COMMIT is removed.
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
