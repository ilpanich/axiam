//! The revocation feed's read and prune side (T-39, T-143).
//!
//! The write side lives on [`crate::repository::SurrealSessionRepository`],
//! because a revocation is published by the same call that performs it and a
//! second repository in that path would be a second thing to forget.
//!
//! What is here is what the public handler and the background sweep need: the
//! live entries, and a way to drop the dead ones. Both are deliberately
//! tenant-**less**. The feed is a deployment-wide document served without
//! authentication, and scoping it by tenant would mean either asking the caller
//! which tenant it is interested in — turning the feed into the enumeration
//! oracle T-244 spent an entire design avoiding — or storing a tenant id on
//! rows whose whole property is that they identify nothing.

use axiam_core::error::AxiamResult;
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;

use crate::error::DbError;
use crate::handle::DbHandle;

#[derive(Debug, SurrealValue)]
struct RevokedSessionRow {
    sid_hash: String,
    /// Selected because the `ORDER BY` needs it, decoded because
    /// `SurrealValue` is exhaustive, and used by nothing: the document
    /// publishes hashes and a single deployment-wide `ttl`, never a per-entry
    /// expiry. A per-entry expiry would say *when* each session was revoked,
    /// which is one more thing an unauthenticated document would disclose.
    #[allow(dead_code)]
    expires_at: DateTime<Utc>,
}

/// Reads and prunes `revoked_session`.
pub struct SurrealRevokedSessionRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> Clone for SurrealRevokedSessionRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealRevokedSessionRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }

    /// Every entry that has not yet expired, as of `now`.
    ///
    /// Filtered on read rather than relying on the sweep, because the two
    /// answer different questions: the sweep keeps the table small, this keeps
    /// the **document** truthful. A deployment whose sweep is late must not
    /// publish an entry for a session whose tokens have all expired — that is
    /// a guard rejecting nothing, at the cost of disclosing one more
    /// revocation than it needed to.
    ///
    /// Ordered by `expires_at` so the document is stable between polls that see
    /// the same set, which is what lets an `ETag` mean anything.
    pub async fn list_live(&self, now: DateTime<Utc>) -> AxiamResult<Vec<String>> {
        let mut result = self
            .db
            .current()
            .query(
                // `expires_at` is in the projection because SurrealDB
                // requires an `ORDER BY` idiom to be selected; the row struct
                // reads only `sid_hash`, so nothing else escapes.
                "SELECT sid_hash, expires_at FROM revoked_session \
                 WHERE expires_at > $now \
                 ORDER BY expires_at ASC",
            )
            .bind(("now", now))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<RevokedSessionRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.into_iter().map(|r| r.sid_hash).collect())
    }

    /// Delete every entry whose expiry has passed. Returns how many went.
    ///
    /// Called by the background sweep. This is the only deletion path on the
    /// table, and unlike the audit log's it needs no ceremony: an expired
    /// revocation entry is not a record of anything — every token it described
    /// has expired on its own `exp` — and keeping it would be disclosure with
    /// no remaining purpose.
    pub async fn prune_expired(&self, now: DateTime<Utc>) -> AxiamResult<u64> {
        let mut counted = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM revoked_session WHERE expires_at <= $now GROUP ALL",
            )
            .bind(("now", now))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let counts: Vec<crate::helpers::CountRow> = counted.take(0).map_err(DbError::from)?;
        let count = counts.first().map_or(0, |c| c.total);

        self.db
            .current()
            .query("DELETE revoked_session WHERE expires_at <= $now")
            .bind(("now", now))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        Ok(count)
    }
}
