//! SurrealDB implementation of [`DeviceGrantRepository`] (RFC 8628 / B2).
//!
//! # Why the state transitions live in the statements
//!
//! Every transition here — approve, deny, redeem — is expressed as a single
//! statement whose `WHERE` clause carries the precondition, rather than as a
//! read, a check in Rust, and a write.
//!
//! That is not stylistic. A device grant is polled in a loop by construction:
//! RFC 8628 §3.4 has the device hitting the token endpoint every few seconds
//! until something changes. So the moment a user approves, there is very
//! likely a poll already in flight, and a read-then-write redeem would let two
//! polls both observe `approved` and both mint a token set from one approval.
//! Putting the precondition in the statement makes the datastore serialise
//! them, and exactly one sees the before-image.

use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::models::oauth2_client::{CreateDeviceGrant, DeviceGrant, DeviceGrantStatus};
use axiam_core::repository::DeviceGrantRepository;
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::is_transaction_conflict;

/// Ceiling on the poll interval `slow_down` may raise a grant to.
///
/// Without a ceiling, a device stuck in a tight retry loop would be pushed to
/// an interval longer than the grant's own lifetime, turning a "slow down"
/// into a silent "never succeed". 60 s is comfortably above any sane polling
/// cadence and comfortably below the shortest sensible grant lifetime.
const MAX_INTERVAL_SECS: u64 = 60;

#[derive(Debug, SurrealValue)]
struct DeviceGrantRow {
    record_id: String,
    tenant_id: String,
    client_id: String,
    device_code_hash: String,
    user_code: String,
    scopes: Vec<String>,
    status: String,
    user_id: Option<String>,
    expires_at: DateTime<Utc>,
    interval_secs: i64,
    last_polled_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl DeviceGrantRow {
    fn try_into_grant(self) -> Result<DeviceGrant, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid device grant UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let user_id = match self.user_id.as_deref() {
            None | Some("") => None,
            Some(raw) => Some(
                Uuid::parse_str(raw)
                    .map_err(|e| DbError::Migration(format!("invalid user UUID: {e}")))?,
            ),
        };
        // An unrecognised status must NOT default to anything: the states
        // differ by whether they grant access, so guessing is the one
        // unacceptable answer.
        let status = DeviceGrantStatus::from_wire(&self.status).ok_or_else(|| {
            DbError::Migration(format!("unrecognised device grant status: {}", self.status))
        })?;

        Ok(DeviceGrant {
            id,
            tenant_id,
            client_id: self.client_id,
            device_code_hash: self.device_code_hash,
            user_code: self.user_code,
            scopes: self.scopes,
            status,
            user_id,
            expires_at: self.expires_at,
            interval_secs: self.interval_secs.max(1) as u64,
            last_polled_at: self.last_polled_at,
            created_at: self.created_at,
        })
    }
}

/// Projection shared by every read below.
const SELECT_FIELDS: &str = "meta::id(id) AS record_id, tenant_id, client_id, \
     device_code_hash, user_code, scopes, status, user_id, expires_at, \
     interval_secs, last_polled_at, created_at";

/// SurrealDB implementation of the device-grant repository.
pub struct SurrealDeviceGrantRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> Clone for SurrealDeviceGrantRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealDeviceGrantRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }
}

impl<C: Connection> DeviceGrantRepository for SurrealDeviceGrantRepository<C> {
    async fn create(&self, input: CreateDeviceGrant) -> AxiamResult<DeviceGrant> {
        let id = new_id();

        let mut result = self
            .db
            .current()
            .query(format!(
                "CREATE type::record('device_grant', $id) SET \
                 tenant_id = $tenant_id, \
                 client_id = $client_id, \
                 device_code_hash = $device_code_hash, \
                 user_code = $user_code, \
                 scopes = $scopes, \
                 status = 'pending', \
                 user_id = NONE, \
                 expires_at = $expires_at, \
                 interval_secs = $interval_secs, \
                 last_polled_at = NONE \
                 RETURN {SELECT_FIELDS}"
            ))
            .bind(("id", id.to_string()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("client_id", input.client_id))
            .bind(("device_code_hash", input.device_code_hash))
            .bind(("user_code", input.user_code))
            .bind(("scopes", input.scopes))
            .bind(("expires_at", input.expires_at))
            .bind(("interval_secs", input.interval_secs as i64))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<DeviceGrantRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .ok_or_else(|| DbError::Migration("device grant not returned after create".into()))?
            .try_into_grant()
            .map_err(Into::into)
    }

    async fn get_by_user_code(
        &self,
        tenant_id: Uuid,
        user_code: &str,
    ) -> AxiamResult<Option<DeviceGrant>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {SELECT_FIELDS} FROM device_grant \
                 WHERE tenant_id = $tenant_id AND user_code = $user_code"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_code", user_code.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<DeviceGrantRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(DeviceGrantRow::try_into_grant)
            .transpose()
            .map_err(Into::into)
    }

    async fn get_by_device_code_hash(
        &self,
        tenant_id: Uuid,
        device_code_hash: &str,
    ) -> AxiamResult<Option<DeviceGrant>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {SELECT_FIELDS} FROM device_grant \
                 WHERE tenant_id = $tenant_id AND device_code_hash = $hash"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("hash", device_code_hash.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<DeviceGrantRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(DeviceGrantRow::try_into_grant)
            .transpose()
            .map_err(Into::into)
    }

    async fn decide(
        &self,
        tenant_id: Uuid,
        user_code: &str,
        approved: bool,
        user_id: Uuid,
    ) -> AxiamResult<bool> {
        // `status = 'pending'` in the WHERE clause is the precondition: a
        // grant that was already decided (or already redeemed) must not be
        // re-decided, and the loser of a race gets `false` rather than
        // silently overwriting the earlier decision.
        let mut result = self
            .db
            .current()
            .query(
                "UPDATE device_grant SET status = $status, user_id = $user_id \
                 WHERE tenant_id = $tenant_id AND user_code = $user_code \
                 AND status = 'pending' AND expires_at > time::now() \
                 RETURN meta::id(id) AS record_id",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_code", user_code.to_string()))
            .bind((
                "status",
                if approved { "approved" } else { "denied" }.to_string(),
            ))
            .bind(("user_id", user_id.to_string()))
            .await
            .map_err(DbError::from)?;

        #[derive(SurrealValue)]
        struct IdRow {
            record_id: String,
        }
        let rows: Vec<IdRow> = result.take(0).map_err(DbError::from)?;
        Ok(!rows.is_empty())
    }

    async fn redeem(
        &self,
        tenant_id: Uuid,
        device_code_hash: &str,
    ) -> AxiamResult<Option<DeviceGrant>> {
        // Single-use. `RETURN BEFORE` yields the pre-transition row, and the
        // `status = 'approved'` guard is what makes a later, non-concurrent
        // poll match nothing.
        //
        // The guard does not decide a *concurrent* race, and neither does the
        // `BEGIN`/`COMMIT` this used to rely on. SurrealDB 3.2.3 does not
        // reliably detect the write-write conflict — measured on the
        // permission-ticket consume, which is this same shape, two transactions
        // both commit with zero errors and both return the pre-transition row.
        // Here that is one user approval minting two token sets, and a device
        // polling on a short interval and retrying is the normal shape of
        // RFC 8628 §3.4, not an exotic case.
        //
        // So the race is decided here instead: each attempt stamps a nonce, the
        // last write persists, and the third statement reads back to see whose
        // it was. Exactly one nonce can be the stored one. See `SCHEMA_V31` for
        // the measurements, including two repairs that proved worse than the
        // defect, and for why this is a narrower window rather than a guarantee.
        //
        // Deliberately **not** in a transaction: inside one the read-back would
        // see this caller's own write under snapshot isolation and every racer
        // would believe it won.
        let nonce = new_id().to_string();
        let result = self
            .db
            .current()
            .query(format!(
                "LET $before = (UPDATE device_grant \
                     SET status = 'redeemed', redemption_id = $nonce \
                     WHERE tenant_id = $tenant_id AND device_code_hash = $hash \
                     AND status = 'approved' AND expires_at > time::now() \
                     RETURN BEFORE); \
                 SELECT {SELECT_FIELDS} FROM $before; \
                 SELECT VALUE redemption_id FROM device_grant \
                     WHERE tenant_id = $tenant_id AND device_code_hash = $hash LIMIT 1"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("hash", device_code_hash.to_string()))
            .bind(("nonce", nonce.clone()))
            .await;

        // Each statement is its own transaction, so a conflict is still
        // possible. A loser's conflict is this method's "already redeemed"
        // answer, not a server fault.
        let mut result = match result {
            Ok(r) => r,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };

        // LET=0, SELECT rows=1, SELECT nonce=2.
        let rows: Vec<DeviceGrantRow> = match result.take::<Vec<DeviceGrantRow>>(1) {
            Ok(rows) => rows,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };
        if rows.is_empty() {
            // Unknown, not approved, already redeemed, or expired. Nothing was
            // written, so nothing was burned.
            return Ok(None);
        }

        let stored: Vec<Option<String>> = match result.take::<Vec<Option<String>>>(2) {
            Ok(v) => v,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };
        if stored.into_iter().flatten().next().as_deref() != Some(nonce.as_str()) {
            // Our write landed but another poll's landed after it. That poll
            // holds the redemption; this one must not also mint a token set.
            return Ok(None);
        }

        rows.into_iter()
            .next()
            .map(DeviceGrantRow::try_into_grant)
            .transpose()
            .map_err(Into::into)
    }

    async fn record_poll(
        &self,
        tenant_id: Uuid,
        device_code_hash: &str,
    ) -> AxiamResult<(u64, bool)> {
        let Some(grant) = self
            .get_by_device_code_hash(tenant_id, device_code_hash)
            .await?
        else {
            // Nothing to slow down; the caller will reject the unknown code.
            return Ok((0, false));
        };

        let now = Utc::now();
        let too_fast = grant.last_polled_at.is_some_and(|last| {
            (now - last).num_milliseconds() < (grant.interval_secs as i64) * 1000
        });

        // Capped: an uncapped `slow_down` would eventually push the interval
        // past the grant's own lifetime, turning "slow down" into "never
        // succeed" without ever saying so.
        let next_interval = if too_fast {
            (grant.interval_secs + 5).min(MAX_INTERVAL_SECS)
        } else {
            grant.interval_secs
        };

        self.db
            .current()
            .query(
                "UPDATE device_grant SET last_polled_at = $now, interval_secs = $interval \
                 WHERE tenant_id = $tenant_id AND device_code_hash = $hash",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("hash", device_code_hash.to_string()))
            .bind(("now", now))
            .bind(("interval", next_interval as i64))
            .await
            .map_err(DbError::from)?;

        Ok((next_interval, too_fast))
    }

    async fn cleanup_expired(&self, tenant_id: Uuid) -> AxiamResult<u64> {
        let mut result = self
            .db
            .current()
            .query(
                "LET $removed = (DELETE device_grant WHERE tenant_id = $tenant_id \
                     AND expires_at <= time::now() RETURN BEFORE); \
                 SELECT meta::id(id) AS record_id FROM $removed",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        // `RETURN BEFORE` yields the removed rows, so their count IS the
        // number deleted — no second query, and no window in which a
        // concurrent insert could inflate a follow-up `count()`.
        //
        // The before-images carry `id` as a record link rather than the
        // `record_id` string the row struct expects, so they are projected by
        // a second statement in the same query. Deserializing into the full
        // row type instead would fail on that one field and — because the
        // count is the only thing wanted here — fail *silently*, reporting
        // zero deletions for a cleanup that worked.
        #[derive(SurrealValue)]
        struct IdOnly {
            #[allow(dead_code)]
            record_id: String,
        }
        let deleted: Vec<IdOnly> = result.take(1).unwrap_or_default();
        Ok(deleted.len() as u64)
    }
}
