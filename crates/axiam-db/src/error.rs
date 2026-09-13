//! Database-specific error types and conversions.

use axiam_core::error::AxiamError;

/// Database-layer error type.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("SurrealDB error: {0}")]
    Surreal(#[from] surrealdb::Error),

    /// Authentication is expired/unrecoverable (root token expiry or a
    /// genuinely revoked/invalid credential — CORR-02/D-05). Distinct from
    /// [`DbError::Surreal`] so a readiness probe can alarm on this
    /// specifically rather than treating it as an ordinary, possibly
    /// transient query error.
    #[error("SurrealDB authentication unhealthy: {0}")]
    Unhealthy(String),

    #[error("Migration failed: {0}")]
    Migration(String),

    #[error("Record not found: {entity} with id {id}")]
    NotFound { entity: String, id: String },

    #[error("Record already exists: {entity}")]
    AlreadyExists { entity: String },

    /// A value read back from SurrealDB could not be deserialized/parsed into
    /// its expected Rust type (e.g. a corrupt UUID column). Distinct from
    /// [`DbError::Migration`] so this class of error is never mislabeled as a
    /// schema-migration failure (QUAL-03/D-10). Falls through the same
    /// `other => AxiamError::Database` catch-all below, so the observable
    /// HTTP status is unchanged (still 5xx) — this is a log-clarity fix only.
    #[error("Data serialization error: {0}")]
    Serialization(String),

    /// An optimistic-concurrency write conflict that survived every retry
    /// [`crate::helpers::retry_on_write_conflict`] was willing to spend on it.
    ///
    /// Distinct from [`DbError::Migration`] for the same reason
    /// [`DbError::Serialization`] is (QUAL-03/D-10): a contended write is not a
    /// schema-migration failure, and reporting it as one sent an operator
    /// looking for a broken migration when the datastore had merely said "this
    /// transaction can be retried". Reaching this variant means contention is
    /// sustained rather than incidental — the retries are exhausted, not
    /// skipped — which is a capacity signal worth being able to grep for.
    ///
    /// Maps to [`AxiamError::WriteContention`] — `503 Service Unavailable`
    /// with `Retry-After: 1` over REST, `UNAVAILABLE` over gRPC. That was the
    /// separate decision this variant's introduction deferred, taken on
    /// 2026-09-12 (R-4): the answer is a statement about the server, and a
    /// `500` tells a client to stop when the correct advice is to come back in
    /// a moment. The message stays **here**, for the log; the client-facing
    /// error carries no payload at all.
    #[error("Write conflict: {0}")]
    Conflict(String),
}

impl From<DbError> for AxiamError {
    fn from(err: DbError) -> Self {
        match err {
            DbError::NotFound { entity, id } => AxiamError::NotFound { entity, id },
            DbError::AlreadyExists { entity } => AxiamError::AlreadyExists { entity },
            // T-262 / R-4. Note the ordering this relies on:
            // `classify_write_error` checks the UNIQUE-violation marker BEFORE
            // the conflict markers, so a constraint violation — a statement
            // about the request, which retrying only reproduces — is already
            // an `AlreadyExists` by the time it reaches here and keeps its
            // `409`.
            DbError::Conflict(_) => AxiamError::WriteContention,
            other => AxiamError::Database(other.to_string()),
        }
    }
}
