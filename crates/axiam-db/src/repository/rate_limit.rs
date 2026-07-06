//! SurrealDB-backed shared rate-limit bucket counter (SECHRD-03 / D-01a).
//!
//! Backs the REST shared-store rate-limit pre-check middleware
//! (`axiam-api-rest::middleware::rate_limit_shared`), which runs BEFORE the
//! existing per-replica in-memory `Governor`/`GovernorLayer` and closes the
//! multi-replica HPA gap (per-replica buckets otherwise multiply the
//! effective limit by the replica count).
//!
//! `key` MUST already encode the endpoint (e.g. `"{endpoint}:{ip}"`) so
//! per-endpoint limits are preserved — this repository has no notion of
//! "endpoint" itself and never collapses distinct endpoints into one
//! global bucket.

use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;

use crate::error::DbError;

/// Row shape returned by the windowed-CAS `UPSERT ... RETURN AFTER` query —
/// only `count` is needed by the caller.
#[derive(Debug, SurrealValue)]
struct RateLimitBucketRow {
    count: u64,
}

/// SurrealDB-backed shared rate-limit bucket counter.
#[derive(Clone)]
pub struct SurrealRateLimitBucketRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealRateLimitBucketRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }

    /// Increments the shared bucket identified by `key` for the fixed
    /// window starting at `window_start`, returning the POST-update count.
    ///
    /// Windowed compare-and-set semantics (follows `increment_failed_logins`'s
    /// read-before-write-in-one-statement pattern, `user.rs` — the RHS
    /// `count`/`window_start` refer to the PRE-update document):
    ///
    /// - First hit on a fresh key: `count` is unset (`NONE`) — sets
    ///   `count = 1`, `window_start = $window_start`.
    /// - A hit whose `window_start` matches (or is older than requested but
    ///   the stored value is not older than `$window_start`) the current
    ///   window: `count = count + 1` (the SAME window — increments).
    /// - A hit whose stored `window_start` is OLDER than `$window_start`
    ///   (a NEW window has begun): resets `count = 1` and advances
    ///   `window_start = $window_start`.
    ///
    /// All error paths `?`-propagate `DbError` — no `.unwrap()`/`.expect()`
    /// on this counter path.
    pub async fn increment(&self, key: &str, window_start: DateTime<Utc>) -> Result<u64, DbError> {
        let result = self
            .db
            .query(
                "UPSERT type::record('rate_limit_bucket', $key) SET \
                 count = IF window_start = NONE OR window_start < $window_start \
                          THEN 1 ELSE count + 1 END, \
                 window_start = IF window_start = NONE OR window_start < $window_start \
                          THEN $window_start ELSE window_start END, \
                 updated_at = time::now() \
                 RETURN AFTER",
            )
            .bind(("key", key.to_string()))
            .bind(("window_start", window_start))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<RateLimitBucketRow> = result.take(0).map_err(DbError::from)?;
        let row = rows
            .into_iter()
            .next()
            .ok_or_else(|| DbError::Migration("rate_limit_bucket UPSERT returned no row".into()))?;

        Ok(row.count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use surrealdb::Surreal;
    use surrealdb::engine::local::Mem;

    #[tokio::test]
    async fn rate_limit_bucket_increment_sequence_and_window_reset() {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        crate::schema::run_migrations(&db).await.unwrap();

        let repo = SurrealRateLimitBucketRepository::new(db);

        let key = "login:203.0.113.5";
        let window1 = Utc::now();

        // First hit in a fresh window sets count = 1.
        assert_eq!(repo.increment(key, window1).await.unwrap(), 1);

        // Subsequent hits in the SAME window increment.
        assert_eq!(repo.increment(key, window1).await.unwrap(), 2);
        assert_eq!(repo.increment(key, window1).await.unwrap(), 3);

        // A hit with a NEWER window_start resets count to 1 (new window).
        let window2 = window1 + Duration::minutes(1);
        assert_eq!(repo.increment(key, window2).await.unwrap(), 1);

        // Per-endpoint granularity: a DIFFERENT key starts its own bucket at
        // 1, independent of `key`'s already-advanced count.
        let other_key = "mfa_verify:203.0.113.5";
        assert_eq!(repo.increment(other_key, window2).await.unwrap(), 1);

        // The original key's bucket is untouched by the other key's
        // increment — no cross-endpoint bucket collapsing.
        assert_eq!(repo.increment(key, window2).await.unwrap(), 2);
    }
}
