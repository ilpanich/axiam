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
