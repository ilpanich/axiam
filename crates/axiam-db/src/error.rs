//! Database-specific error types and conversions.

use axiam_core::error::AxiamError;

/// Database-layer error type.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("SurrealDB error: {0}")]
    Surreal(#[from] surrealdb::Error),

    #[error("Migration failed: {0}")]
    Migration(String),

    #[error("Record not found: {entity} with id {id}")]
    NotFound { entity: String, id: String },

    #[error("Record already exists: {entity}")]
    AlreadyExists { entity: String },

    #[error(
        "SurrealDB session points to wrong namespace/database: \
         expected ns={expected_ns} db={expected_db}, \
         got ns={actual_ns:?} db={actual_db:?}"
    )]
    SessionMismatch {
        expected_ns: String,
        expected_db: String,
        actual_ns: Option<String>,
        actual_db: Option<String>,
    },
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
