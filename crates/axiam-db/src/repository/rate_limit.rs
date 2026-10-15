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
use surrealdb::Connection;
use surrealdb_types::SurrealValue;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{classify_write_error, retry_on_write_conflict};

/// Row shape returned by the windowed-CAS `UPSERT ... RETURN AFTER` query —
/// only `count` is needed by the caller.
#[derive(Debug, SurrealValue)]
struct RateLimitBucketRow {
    count: u64,
}

/// Row shape of [`SurrealRateLimitBucketRepository::peek_bucket`].
#[derive(Debug, SurrealValue)]
struct RateLimitBucketPeek {
    count: u64,
    window_start: DateTime<Utc>,
}

/// One row [`SurrealRateLimitBucketRepository::delete_stale`] removed.
#[derive(Debug, SurrealValue)]
struct RemovedBucket {
    #[allow(dead_code)] // counted, never read
    record_id: String,
}

/// SurrealDB-backed shared rate-limit bucket counter.
#[derive(Clone)]
pub struct SurrealRateLimitBucketRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> SurrealRateLimitBucketRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        let db = db.into();
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
    ///
    /// Thin delegation to [`Self::increment_by`] with `delta = 1`; the two
    /// share one UPSERT statement so the windowed-CAS semantics can never
    /// drift between the single-hit and batched-delta callers.
    pub async fn increment(&self, key: &str, window_start: DateTime<Utc>) -> Result<u64, DbError> {
        self.increment_by(key, window_start, 1).await
    }

    /// Adds `delta` to the shared bucket identified by `key` for the fixed
    /// window starting at `window_start`, returning the POST-update count.
    ///
    /// This is the batched generalization of [`Self::increment`] and the
    /// write primitive used by
    /// [`crate::rate_limit_counter::SharedRateLimitCounter`]'s write-behind
    /// flusher: instead of one UPSERT per request, the flusher accumulates
    /// `delta` local increments in memory and issues ONE UPSERT per
    /// `(key, window)` per sync interval. That is what removes the
    /// per-request synchronous datastore round-trip that capped the six
    /// hottest endpoints at ~20 ops/s (see the module docs of
    /// [`crate::rate_limit_counter`] for the measurements).
    ///
    /// Windowed compare-and-set semantics are identical to
    /// [`Self::increment`], with `1` generalized to `$delta`:
    ///
    /// - First hit on a fresh key (`count` is `NONE`): `count = $delta`.
    /// - Same window: `count = count + $delta`.
    /// - Stored `window_start` OLDER than `$window_start` (a new window
    ///   began): `count = $delta`, `window_start = $window_start`.
    ///
    /// A `delta` of `0` is a legal no-op write (it still refreshes
    /// `updated_at` and returns the current count), but the flusher never
    /// issues one — it skips buckets with nothing pending.
    pub async fn increment_by(
        &self,
        key: &str,
        window_start: DateTime<Utc>,
        delta: u64,
    ) -> Result<u64, DbError> {
        let result = self
            .db
            .current()
            .query(
                "UPSERT type::record('rate_limit_bucket', $key) SET \
                 count = IF window_start = NONE OR window_start < $window_start \
                          THEN $delta ELSE count + $delta END, \
                 window_start = IF window_start = NONE OR window_start < $window_start \
                          THEN $window_start ELSE window_start END, \
                 updated_at = time::now() \
                 RETURN AFTER",
            )
            .bind(("key", key.to_string()))
            .bind(("window_start", window_start))
            .bind(("delta", delta))
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

    /// Reads the count of the bucket `key` for the fixed window starting at
    /// `window_start`, writing nothing.
    ///
    /// Answers what [`Self::increment_by`] would return for a `delta` of `0`:
    /// `0` when no row exists or its stored `window_start` is older than
    /// `window_start` (an upsert would have started the new window at `0`),
    /// the stored `count` otherwise. A plain `SELECT`: it creates no row, so
    /// asking after a key nobody has written leaves the table as it was.
    pub async fn peek_count(&self, key: &str, window_start: DateTime<Utc>) -> Result<u64, DbError> {
        Ok(self
            .peek_bucket(key)
            .await?
            .filter(|(stored, _)| *stored >= window_start)
            .map_or(0, |(_, count)| count))
    }

    /// Reads the bucket `key` as it is stored, writing nothing: the start of
    /// the window its count belongs to and the count, or `None` when no
    /// bucket exists for `key`.
    ///
    /// Unlike [`Self::peek_count`] this tells a bucket that has moved on to a
    /// newer window from one still holding the window asked about, which is
    /// what the CIBA hint cap needs to notice a call that has been overtaken
    /// by the next window (`axiam_oauth2::ciba::CibaHintCap`).
    pub async fn peek_bucket(&self, key: &str) -> Result<Option<(DateTime<Utc>, u64)>, DbError> {
        let mut result = self
            .db
            .current()
            .query("SELECT count, window_start FROM type::record('rate_limit_bucket', $key)")
            .bind(("key", key.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<RateLimitBucketPeek> = result.take(0).map_err(DbError::from)?;
        Ok(rows
            .into_iter()
            .next()
            .map(|row| (row.window_start, row.count)))
    }

    /// Takes one back from the bucket `key`, in one conditional statement: the
    /// count drops by one only while the bucket still holds the window
    /// starting at `window_start` and the count is above zero. Otherwise —
    /// no bucket, a bucket that has moved on to another window, a count of
    /// zero — nothing is written (in particular, no row is created). Returns
    /// whether one was taken back.
    ///
    /// The undo of one [`Self::increment_by`] of `1` for the same window, for
    /// a caller that counts first and decides afterwards (the CIBA hint cap
    /// takes back the count of a call it refused). The read of `count` and the
    /// write are one statement on one record, so it cannot lose an increment
    /// made concurrently.
    pub async fn decrement(&self, key: &str, window_start: DateTime<Utc>) -> Result<bool, DbError> {
        let mut result = self
            .db
            .current()
            .query(
                "UPDATE type::record('rate_limit_bucket', $key) SET count = count - 1 \
                 WHERE window_start = $window_start AND count > 0 \
                 RETURN AFTER",
            )
            .bind(("key", key.to_string()))
            .bind(("window_start", window_start))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<RateLimitBucketRow> = result.take(0).map_err(DbError::from)?;
        Ok(!rows.is_empty())
    }

    /// Deletes, at most `limit` at a time, the buckets whose `updated_at` is
    /// before `cutoff`; returns how many were removed.
    ///
    /// The `WHERE` is evaluated again by the `DELETE` itself, per record, so a
    /// bucket a limiter wrote between the selection and the deletion is kept,
    /// and two replicas sweeping at once cannot remove a row twice or remove
    /// a row the other has just refreshed: each row goes once, or stays. The
    /// count is of rows this call removed (`RETURN BEFORE`), not of rows it
    /// selected. When two sweepers contend for the same rows the datastore
    /// aborts the loser's transaction: that is retried, and if it keeps
    /// losing it reports `0` (the winner removed the rows). Which `cutoff` is safe to pass is the caller's to establish;
    /// the server's sweep derives it from the windows in use.
    pub async fn delete_stale(&self, cutoff: DateTime<Utc>, limit: u32) -> Result<u64, DbError> {
        match retry_on_write_conflict(|| self.delete_stale_once(cutoff, limit)).await {
            // Two sweepers selected the same rows and this one lost the
            // commit: the winner removed them, which is what was wanted. Not
            // an error; whatever is left is the next pass's.
            Err(DbError::Conflict(_)) => Ok(0),
            outcome => outcome,
        }
    }

    async fn delete_stale_once(&self, cutoff: DateTime<Utc>, limit: u32) -> Result<u64, DbError> {
        let entity = "rate_limit_bucket";
        let mut result = self
            .db
            .current()
            .query(
                "LET $ids = (SELECT VALUE id FROM rate_limit_bucket \
                     WHERE updated_at < $cutoff LIMIT $limit); \
                 LET $removed = (DELETE $ids WHERE updated_at < $cutoff RETURN BEFORE); \
                 SELECT meta::id(id) AS record_id FROM $removed",
            )
            .bind(("cutoff", cutoff))
            .bind(("limit", i64::from(limit)))
            .await
            .map_err(|e| classify_write_error(e, entity))?
            .check()
            .map_err(|e| classify_write_error(e, entity))?;
        let removed: Vec<RemovedBucket> = result.take(2).map_err(DbError::from)?;
        Ok(removed.len() as u64)
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

    /// `increment_by` is the write primitive behind the write-behind flusher
    /// (`crate::rate_limit_counter`): a batched delta must land exactly as
    /// `delta` single increments would have, including the window reset.
    #[tokio::test]
    async fn rate_limit_bucket_increment_by_batches_deltas_and_resets_on_new_window() {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        crate::schema::run_migrations(&db).await.unwrap();

        let repo = SurrealRateLimitBucketRepository::new(db);

        let key = "authz_check:203.0.113.7";
        let window1 = Utc::now();

        // First flush on a fresh key sets count = delta (not 1).
        assert_eq!(repo.increment_by(key, window1, 7).await.unwrap(), 7);

        // A second flush in the SAME window ADDS the delta.
        assert_eq!(repo.increment_by(key, window1, 5).await.unwrap(), 12);

        // A single increment interleaves correctly with batched deltas.
        assert_eq!(repo.increment(key, window1).await.unwrap(), 13);

        // A NEWER window resets to exactly the delta (not delta + old count).
        let window2 = window1 + Duration::minutes(1);
        assert_eq!(repo.increment_by(key, window2, 4).await.unwrap(), 4);

        // delta = 0 is a legal no-op that returns the unchanged count.
        assert_eq!(repo.increment_by(key, window2, 0).await.unwrap(), 4);

        // Per-key isolation holds for batched deltas too.
        let other = "login:203.0.113.7";
        assert_eq!(repo.increment_by(other, window2, 2).await.unwrap(), 2);
        assert_eq!(repo.increment_by(key, window2, 1).await.unwrap(), 5);
    }
    async fn repo() -> (
        SurrealRateLimitBucketRepository<surrealdb::engine::local::Db>,
        Surreal<surrealdb::engine::local::Db>,
    ) {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        crate::schema::run_migrations(&db).await.unwrap();
        (SurrealRateLimitBucketRepository::new(db.clone()), db)
    }

    async fn rows(db: &Surreal<surrealdb::engine::local::Db>) -> usize {
        let mut r = db
            .query("SELECT count() AS total FROM rate_limit_bucket GROUP ALL")
            .await
            .unwrap();
        let n: Vec<crate::helpers::CountRow> = r.take(0).unwrap();
        n.first().map_or(0, |c| c.total as usize)
    }

    /// `peek_count` answers what a zero-delta `increment_by` would, and
    /// writes nothing (#638): no row for a key nobody wrote, none changed
    /// for one left from an older window.
    #[tokio::test]
    async fn peek_count_reads_without_writing() {
        let (repo, db) = repo().await;
        let w1 = Utc::now();
        let w2 = w1 + Duration::minutes(10);

        // Unknown key: zero, and still no row.
        assert_eq!(repo.peek_count("k", w1).await.unwrap(), 0);
        assert_eq!(rows(&db).await, 0, "a read created a row");

        repo.increment_by("k", w1, 2).await.unwrap();
        assert_eq!(repo.peek_count("k", w1).await.unwrap(), 2);
        // Asked about a newer window than the stored one: the upsert would
        // have reset it to zero; the read says zero and leaves the row alone.
        assert_eq!(repo.peek_count("k", w2).await.unwrap(), 0);
        assert_eq!(
            repo.peek_count("k", w1).await.unwrap(),
            2,
            "the row was rewritten"
        );
        assert_eq!(rows(&db).await, 1);
    }

    /// `peek_bucket` reports the stored window and count as they are, a newer
    /// window included, and writes nothing (#639).
    #[tokio::test]
    async fn peek_bucket_reports_the_stored_window() {
        let (repo, db) = repo().await;
        let w1 = Utc::now();
        let w2 = w1 + Duration::minutes(10);
        assert_eq!(repo.peek_bucket("k").await.unwrap(), None);
        assert_eq!(rows(&db).await, 0, "a read created a row");
        repo.increment_by("k", w1, 2).await.unwrap();
        let (stored, count) = repo.peek_bucket("k").await.unwrap().unwrap();
        assert_eq!((stored.timestamp(), count), (w1.timestamp(), 2));
        repo.increment_by("k", w2, 1).await.unwrap();
        let (stored, count) = repo.peek_bucket("k").await.unwrap().unwrap();
        assert_eq!((stored.timestamp(), count), (w2.timestamp(), 1));
        assert_eq!(rows(&db).await, 1);
    }

    /// `decrement` takes one back only from the window it names and never
    /// below zero, and creates no row (#639).
    #[tokio::test]
    async fn decrement_takes_one_back_from_its_own_window_only() {
        let (repo, db) = repo().await;
        let w1 = Utc::now();
        let w2 = w1 + Duration::minutes(10);
        assert!(!repo.decrement("k", w1).await.unwrap(), "no row");
        assert_eq!(rows(&db).await, 0, "a decrement created a row");

        repo.increment_by("k", w1, 2).await.unwrap();
        assert!(repo.decrement("k", w1).await.unwrap());
        assert_eq!(repo.peek_count("k", w1).await.unwrap(), 1);
        // Another window's: the bucket holds w1, so nothing is taken.
        assert!(!repo.decrement("k", w2).await.unwrap());
        assert_eq!(repo.peek_count("k", w1).await.unwrap(), 1);
        assert!(repo.decrement("k", w1).await.unwrap());
        assert!(!repo.decrement("k", w1).await.unwrap(), "never below zero");
        assert_eq!(repo.peek_count("k", w1).await.unwrap(), 0);

        // A bucket that has moved on to a newer window is not touched by
        // the older window's undo.
        repo.increment_by("k", w2, 1).await.unwrap();
        assert!(!repo.decrement("k", w1).await.unwrap());
        assert_eq!(repo.peek_count("k", w2).await.unwrap(), 1);
        assert_eq!(rows(&db).await, 1);
    }

    /// `delete_stale` removes rows whose `updated_at` is before the cutoff,
    /// keeps the others, and honours its batch size.
    #[tokio::test]
    async fn delete_stale_removes_old_rows_in_batches_and_keeps_current_ones() {
        let (repo, db) = repo().await;
        let w = Utc::now();
        for k in ["old1", "old2", "old3", "fresh"] {
            repo.increment_by(k, w, 1).await.unwrap();
        }
        db.query("UPDATE rate_limit_bucket SET updated_at = d'2000-01-01T00:00:00Z' WHERE meta::id(id) IN ['old1','old2','old3']")
            .await
            .unwrap()
            .check()
            .unwrap();
        let cutoff = w - Duration::hours(1);

        assert_eq!(repo.delete_stale(cutoff, 2).await.unwrap(), 2, "one batch");
        assert_eq!(rows(&db).await, 2);
        assert_eq!(repo.delete_stale(cutoff, 2).await.unwrap(), 1);
        assert_eq!(repo.delete_stale(cutoff, 2).await.unwrap(), 0);
        assert_eq!(rows(&db).await, 1);
        assert_eq!(repo.peek_count("fresh", w).await.unwrap(), 1);
    }
}
