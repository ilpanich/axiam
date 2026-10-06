//! The minimal profile's singleton lease (T23.8.1, G-8, D-59).
//!
//! With `AXIAM__AMQP__ENABLED=false` there is no broker to carry a cache
//! invalidation or an authorization decision to a second instance, so the
//! profile is **single-instance by definition**. Nothing in a process's
//! configuration can prove it is the only one; a row in the datastore both
//! instances share can. This is that row: `minimal_profile_lease:instance`.
//!
//! * **Claim** — `CREATE` the row; if it exists, a conditional `UPDATE ... WHERE
//!   holder = $me OR expires_at <= $now` takes it over when it has expired (or
//!   is already ours). Both are single-record writes: of two simultaneous
//!   claimants exactly one is acknowledged, and a write that loses the race to
//!   the datastore's optimistic concurrency is retried and then sees the
//!   winner's row.
//! * **Renew** — `UPDATE ... WHERE holder = $me`. An empty result means the row
//!   is no longer ours: another instance took it over, or it was removed.
//! * **Release** — `DELETE ... WHERE holder = $me`, on an orderly stop, so a
//!   successor (a rolling update's next pod) does not wait out the TTL.
//!
//! The caller passes `now` and the TTL, so the whole protocol is testable
//! without sleeping, and the production constants live with the caller
//! (`axiam-server`'s profile module). Times are the caller's clock: the
//! protocol assumes the clocks of two instances sharing a datastore agree to
//! well within the TTL (30 s in production), which any NTP-disciplined host
//! does.

use axiam_core::error::AxiamResult;
use chrono::{DateTime, Duration, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{is_unique_violation, retry_on_write_conflict};

/// The row's fixed record id.
const LEASE_ID: &str = "instance";

#[derive(Debug, SurrealValue)]
struct LeaseRow {
    holder: String,
    acquired_at: DateTime<Utc>,
    renewed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// What the lease row says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRecord {
    /// The instance id that holds the lease.
    pub holder: String,
    /// When the current holder first took it.
    pub acquired_at: DateTime<Utc>,
    /// When the holder last renewed it.
    pub renewed_at: DateTime<Utc>,
    /// After this instant the lease may be taken over.
    pub expires_at: DateTime<Utc>,
}

impl From<LeaseRow> for LeaseRecord {
    fn from(row: LeaseRow) -> Self {
        Self {
            holder: row.holder,
            acquired_at: row.acquired_at,
            renewed_at: row.renewed_at,
            expires_at: row.expires_at,
        }
    }
}

/// The result of [`SurrealMinimalProfileLeaseRepository::claim`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseClaim {
    /// The caller holds the lease now (created, taken over after expiry, or
    /// already its own).
    Acquired,
    /// Another instance holds a live lease.
    Held {
        /// That instance's id.
        holder: String,
        /// When its lease expires unless renewed.
        expires_at: DateTime<Utc>,
    },
}

/// SurrealDB repository for the singleton lease. Not generic over a port: the
/// only consumer is the composition root's profile guard.
pub struct SurrealMinimalProfileLeaseRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> Clone for SurrealMinimalProfileLeaseRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealMinimalProfileLeaseRepository<C> {
    /// Bind to a datastore handle.
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }

    /// The row as it stands, if there is one.
    pub async fn current(&self) -> AxiamResult<Option<LeaseRecord>> {
        let mut result = self
            .db
            .current()
            .query("SELECT holder, acquired_at, renewed_at, expires_at FROM type::record('minimal_profile_lease', $id)")
            .bind(("id", LEASE_ID.to_owned()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<LeaseRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.into_iter().next().map(Into::into))
    }

    /// Try to take the lease for `holder` until `now + ttl`.
    pub async fn claim(
        &self,
        holder: &str,
        now: DateTime<Utc>,
        ttl: Duration,
    ) -> AxiamResult<LeaseClaim> {
        retry_on_write_conflict(|| self.claim_once(holder, now, ttl)).await
    }

    async fn claim_once(
        &self,
        holder: &str,
        now: DateTime<Utc>,
        ttl: Duration,
    ) -> AxiamResult<LeaseClaim> {
        let expires_at = now + ttl;

        // 1. First claim ever (or after a release): create the row. A second
        //    simultaneous creator hits the existing record.
        let created = self
            .db
            .current()
            .query(
                "CREATE type::record('minimal_profile_lease', $id) SET \
                 holder = $holder, acquired_at = $now, renewed_at = $now, \
                 expires_at = $expires_at",
            )
            .bind(("id", LEASE_ID.to_owned()))
            .bind(("holder", holder.to_owned()))
            .bind(("now", now))
            .bind(("expires_at", expires_at))
            .await
            .map_err(DbError::from)?
            .check();
        match created {
            Ok(_) => return Ok(LeaseClaim::Acquired),
            Err(e) if is_unique_violation(&e.to_string()) => {}
            Err(e) => return Err(DbError::Migration(e.to_string()).into()),
        }

        // 2. The row exists: take it over if it is ours or has expired. The
        //    WHERE makes it a conditional write; an empty result is "not yours".
        let mut taken = self
            .db
            .current()
            .query(
                "UPDATE type::record('minimal_profile_lease', $id) SET \
                 holder = $holder, acquired_at = $now, renewed_at = $now, \
                 expires_at = $expires_at \
                 WHERE holder = $holder OR expires_at <= $now \
                 RETURN holder, acquired_at, renewed_at, expires_at",
            )
            .bind(("id", LEASE_ID.to_owned()))
            .bind(("holder", holder.to_owned()))
            .bind(("now", now))
            .bind(("expires_at", expires_at))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<LeaseRow> = taken.take(0).map_err(DbError::from)?;
        if !rows.is_empty() {
            return Ok(LeaseClaim::Acquired);
        }

        // 3. Someone else holds a live lease. Report who and until when.
        match self.current().await? {
            Some(record) => Ok(LeaseClaim::Held {
                holder: record.holder,
                expires_at: record.expires_at,
            }),
            // Released between the two statements: the next attempt creates it.
            None => Err(DbError::Conflict("the lease was released during the claim".into()).into()),
        }
    }

    /// Extend `holder`'s lease to `now + ttl`. `Ok(false)` means the row is not
    /// `holder`'s any more — taken over by another instance, or gone.
    pub async fn renew(
        &self,
        holder: &str,
        now: DateTime<Utc>,
        ttl: Duration,
    ) -> AxiamResult<bool> {
        retry_on_write_conflict(|| async {
            let mut result = self
                .db
                .current()
                .query(
                    "UPDATE type::record('minimal_profile_lease', $id) SET \
                     renewed_at = $now, expires_at = $expires_at \
                     WHERE holder = $holder \
                     RETURN holder, acquired_at, renewed_at, expires_at",
                )
                .bind(("id", LEASE_ID.to_owned()))
                .bind(("holder", holder.to_owned()))
                .bind(("now", now))
                .bind(("expires_at", now + ttl))
                .await
                .map_err(DbError::from)?
                .check()
                .map_err(|e| DbError::Migration(e.to_string()))?;
            let rows: Vec<LeaseRow> = result.take(0).map_err(DbError::from)?;
            Ok::<bool, axiam_core::error::AxiamError>(!rows.is_empty())
        })
        .await
    }

    /// Give the lease up, if `holder` still holds it. Idempotent.
    pub async fn release(&self, holder: &str) -> AxiamResult<()> {
        retry_on_write_conflict(|| async {
            self.db
                .current()
                .query(
                    "DELETE type::record('minimal_profile_lease', $id) \
                     WHERE holder = $holder",
                )
                .bind(("id", LEASE_ID.to_owned()))
                .bind(("holder", holder.to_owned()))
                .await
                .map_err(DbError::from)?
                .check()
                .map_err(|e| DbError::Migration(e.to_string()))?;
            Ok::<(), axiam_core::error::AxiamError>(())
        })
        .await
    }
}
