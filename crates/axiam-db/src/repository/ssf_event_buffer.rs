//! SurrealDB implementation of [`SsfEventBufferRepository`] (G-5, T23.5.3,
//! schema v77's `ssf_event_buffer`).
//!
//! One row per `(tenant, stream, jti)` — the datastore's unique index decides —
//! holding an **unsigned** [`SsfPendingEvent`] as JSON. At most
//! [`POLL_BUFFER_MAX_EVENTS`] rows per stream, **oldest dropped** to admit the
//! newest (D-48; SSF 1.0 §8.1.2 permits a transmitter to drop held events and
//! the newest state is the one a receiver can act on), each for at most
//! [`POLL_BUFFER_RETENTION_DAYS`] days (`expires_at`, swept by
//! [`SsfEventBufferRepository::delete_expired`], a job on `/health/jobs`).
//!
//! # What the row holds, and what it must not
//!
//! The row is an event waiting for a receiver: `jti`, `iat`, the event URI and
//! object, the subject member (an address only on an `email` stream for an
//! address something vouched for) and the `txn`. Never a signed token and never
//! a credential. `pending_json` is read back only through
//! [`SsfPendingEvent`], whose `Debug` omits the subject.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::ssf::{
    POLL_BUFFER_MAX_EVENTS, POLL_BUFFER_RETENTION_DAYS, SsfPendingEvent,
};
use axiam_core::repository::SsfEventBufferRepository;
use chrono::{DateTime, Duration, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::CountRow;

const ENTITY: &str = "ssf_event_buffer";

#[derive(SurrealValue)]
struct EventRow {
    pending_json: String,
}

#[derive(SurrealValue)]
struct JtiRow {
    jti: String,
}

#[derive(SurrealValue)]
struct RemovedRow {
    #[allow(dead_code)] // counted, never read
    record_id: String,
}

/// SurrealDB implementation of [`SsfEventBufferRepository`].
pub struct SurrealSsfEventBufferRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> Clone for SurrealSsfEventBufferRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> std::fmt::Debug for SurrealSsfEventBufferRepository<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SurrealSsfEventBufferRepository")
            .finish_non_exhaustive()
    }
}

impl<C: Connection> SurrealSsfEventBufferRepository<C> {
    /// Build the repository.
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }

    /// Drop the oldest rows of the stream beyond the bound.
    async fn trim(&self, tenant_id: Uuid, stream_id: Uuid) -> AxiamResult<()> {
        let held = self.count(tenant_id, stream_id).await? as usize;
        if held <= POLL_BUFFER_MAX_EVENTS {
            return Ok(());
        }
        let excess = (held - POLL_BUFFER_MAX_EVENTS) as i64;
        let mut result = self
            .db
            .current()
            .query(
                "SELECT jti, created_at FROM ssf_event_buffer \
                 WHERE tenant_id = $tenant_id AND stream_id = $stream_id \
                 ORDER BY created_at ASC LIMIT $excess",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("stream_id", stream_id.to_string()))
            .bind(("excess", excess))
            .await
            .map_err(DbError::from)?;
        let oldest: Vec<JtiRow> = result.take(0).map_err(DbError::from)?;
        let jtis: Vec<String> = oldest.into_iter().map(|r| r.jti).collect();
        self.delete_by_jti(tenant_id, stream_id, &jtis).await?;
        Ok(())
    }
}

impl<C: Connection> SsfEventBufferRepository for SurrealSsfEventBufferRepository<C> {
    async fn push(
        &self,
        tenant_id: Uuid,
        stream_id: Uuid,
        event: &SsfPendingEvent,
        now: DateTime<Utc>,
    ) -> AxiamResult<()> {
        let pending_json = serde_json::to_string(event).map_err(|_| {
            AxiamError::Internal("an SSF event could not be encoded for the buffer".into())
        })?;
        let result = self
            .db
            .current()
            .query(
                "CREATE ssf_event_buffer SET tenant_id = $tenant_id, stream_id = $stream_id, \
                 jti = $jti, event_uri = $event_uri, pending_json = $pending_json, \
                 created_at = $now, expires_at = $expires_at",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("stream_id", stream_id.to_string()))
            .bind(("jti", event.jti.clone()))
            .bind(("event_uri", event.event_uri.clone()))
            .bind(("pending_json", pending_json))
            .bind(("now", now))
            .bind((
                "expires_at",
                now + Duration::days(POLL_BUFFER_RETENTION_DAYS),
            ))
            .await
            .map_err(DbError::from)?;
        match result
            .check()
            .map_err(|e| AxiamError::from(crate::helpers::classify_write_error(e, ENTITY)))
        {
            Ok(_) => {}
            // One row per jti: an event already buffered is buffered.
            Err(AxiamError::AlreadyExists { .. }) => return Ok(()),
            Err(other) => return Err(other),
        }
        self.trim(tenant_id, stream_id).await
    }

    async fn list_oldest(
        &self,
        tenant_id: Uuid,
        stream_id: Uuid,
        limit: usize,
        now: DateTime<Utc>,
    ) -> AxiamResult<Vec<SsfPendingEvent>> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT pending_json, created_at FROM ssf_event_buffer \
                 WHERE tenant_id = $tenant_id AND stream_id = $stream_id \
                   AND expires_at > $now \
                 ORDER BY created_at ASC LIMIT $limit",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("stream_id", stream_id.to_string()))
            .bind(("now", now))
            .bind(("limit", limit as i64))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<EventRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|row| {
                serde_json::from_str::<SsfPendingEvent>(&row.pending_json).map_err(|_| {
                    AxiamError::Internal("a buffered SSF event could not be decoded".into())
                })
            })
            .collect()
    }

    async fn delete_by_jti(
        &self,
        tenant_id: Uuid,
        stream_id: Uuid,
        jtis: &[String],
    ) -> AxiamResult<u64> {
        if jtis.is_empty() {
            return Ok(0);
        }
        let mut result = self
            .db
            .current()
            .query(
                "LET $removed = (DELETE ssf_event_buffer \
                     WHERE tenant_id = $tenant_id AND stream_id = $stream_id \
                       AND jti IN $jtis RETURN BEFORE); \
                 SELECT meta::id(id) AS record_id FROM $removed",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("stream_id", stream_id.to_string()))
            .bind(("jtis", jtis.to_vec()))
            .await
            .map_err(DbError::from)?;
        let removed: Vec<RemovedRow> = result.take(1).map_err(DbError::from)?;
        Ok(removed.len() as u64)
    }

    async fn count(&self, tenant_id: Uuid, stream_id: Uuid) -> AxiamResult<u64> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM ssf_event_buffer \
                 WHERE tenant_id = $tenant_id AND stream_id = $stream_id GROUP ALL",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("stream_id", stream_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.first().map(|r| r.total).unwrap_or(0))
    }

    async fn delete_expired(&self, now: DateTime<Utc>) -> AxiamResult<u64> {
        let mut result = self
            .db
            .current()
            .query(
                "LET $removed = (DELETE ssf_event_buffer WHERE expires_at <= $now \
                     RETURN BEFORE); \
                 SELECT meta::id(id) AS record_id FROM $removed",
            )
            .bind(("now", now))
            .await
            .map_err(DbError::from)?;
        let removed: Vec<RemovedRow> = result.take(1).map_err(DbError::from)?;
        Ok(removed.len() as u64)
    }
}
