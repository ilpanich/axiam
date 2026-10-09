//! SurrealDB implementation of [`NotificationWindowRepository`] (#551, T-117,
//! schema v85's `notification_window`).
//!
//! One row per `(tenant, rule, event)`, its record id derived from the triple,
//! so the first claims of a window on two replicas write the same record and
//! the datastore orders them. A claim is one `UPSERT` whose every assignment is
//! conditional on the window having expired — the precondition of the write,
//! as `claim_failure_notification` (D-73) makes the hour its precondition — and
//! it is retried on a write conflict like the other hot rows: of two
//! concurrent claimants one commits and the other re-reads the winner's window.
//!
//! The row holds ids, an event name and two counts: no address, no request.

use axiam_core::error::AxiamResult;
use axiam_core::models::notification_rule::NotificationWindowClaim;
use axiam_core::repository::NotificationWindowRepository;
use chrono::{DateTime, Duration, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{classify_write_error, retry_hot_row};

const ENTITY: &str = "notification_window";

#[derive(SurrealValue)]
struct WindowRow {
    opened_by: String,
    carried: i64,
}

/// SurrealDB implementation of [`NotificationWindowRepository`].
pub struct SurrealNotificationWindowRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> Clone for SurrealNotificationWindowRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> std::fmt::Debug for SurrealNotificationWindowRepository<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SurrealNotificationWindowRepository")
            .finish_non_exhaustive()
    }
}

impl<C: Connection> SurrealNotificationWindowRepository<C> {
    /// Build the repository.
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }

    /// The record id of a `(tenant, rule, event)` triple. Event names are
    /// `snake_case` identifiers, so the id needs no escaping beyond what
    /// `type::record` does.
    fn record_id(tenant_id: Uuid, rule_id: Uuid, event: &str) -> String {
        format!("{}_{}_{event}", tenant_id.simple(), rule_id.simple())
    }
}

impl<C: Connection> NotificationWindowRepository for SurrealNotificationWindowRepository<C> {
    async fn claim(
        &self,
        tenant_id: Uuid,
        rule_id: Uuid,
        event: &str,
        now: DateTime<Utc>,
        window_secs: i64,
    ) -> AxiamResult<NotificationWindowClaim> {
        let cutoff = now - Duration::seconds(window_secs);
        let record_id = Self::record_id(tenant_id, rule_id, event);
        // Every assignment reads the row as it was before this statement:
        // `opened_at` is written last, and each condition reads it, so the
        // statement means the same whether SET is applied at once or in order.
        // An expired (or absent) window is reopened by this claimant — its
        // `opened_by` — with the old count carried for the mail; an open one
        // counts the event and keeps its claimant. The claimant compares the
        // `opened_by` it gets back with its own id.
        let claimant = Uuid::new_v4().to_string();
        let row = retry_hot_row(|| async {
            let mut result = self
                .db
                .current()
                .query(
                    "UPSERT type::record('notification_window', $id) SET \
                       tenant_id = $tenant_id, rule_id = $rule_id, event = $event, \
                       carried = IF opened_at = NONE OR opened_at <= $cutoff \
                         THEN suppressed ?? 0 ELSE carried END, \
                       suppressed = IF opened_at = NONE OR opened_at <= $cutoff \
                         THEN 0 ELSE suppressed + 1 END, \
                       opened_by = IF opened_at = NONE OR opened_at <= $cutoff \
                         THEN $claimant ELSE opened_by END, \
                       opened_at = IF opened_at = NONE OR opened_at <= $cutoff \
                         THEN $now ELSE opened_at END \
                     RETURN opened_by, carried",
                )
                .bind(("id", record_id.clone()))
                .bind(("tenant_id", tenant_id.to_string()))
                .bind(("rule_id", rule_id.to_string()))
                .bind(("event", event.to_string()))
                .bind(("claimant", claimant.clone()))
                .bind(("now", now))
                .bind(("cutoff", cutoff))
                .await
                .map_err(DbError::from)?
                .check()
                .map_err(|e| classify_write_error(e, ENTITY))?;
            let rows: Vec<WindowRow> = result.take(0).map_err(DbError::from)?;
            rows.into_iter().next().ok_or_else(|| {
                DbError::Migration("notification window claim returned no row".into())
            })
        })
        .await?;

        Ok(if row.opened_by == claimant {
            NotificationWindowClaim::Opened {
                suppressed: u64::try_from(row.carried).unwrap_or(0),
            }
        } else {
            NotificationWindowClaim::Counted
        })
    }
}
