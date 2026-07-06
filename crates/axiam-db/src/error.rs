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
}

impl From<DbError> for AxiamError {
    fn from(err: DbError) -> Self {
        match err {
            DbError::NotFound { entity, id } => AxiamError::NotFound { entity, id },
            DbError::AlreadyExists { entity } => AxiamError::AlreadyExists { entity },
            other => AxiamError::Database(other.to_string()),
        }
    }
}
