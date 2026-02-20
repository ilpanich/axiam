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
}

impl From<DbError> for AxiamError {
    fn from(err: DbError) -> Self {
        match err {
            DbError::NotFound { entity, id } => AxiamError::NotFound { entity, id },
            other => AxiamError::Database(other.to_string()),
        }
    }
}
