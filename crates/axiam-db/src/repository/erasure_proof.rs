//! SurrealDB implementation of [`ErasureProofRepository`].
//!
//! Erasure proofs are INSERT-only records proving that a GDPR Art. 17
//! erasure occurred. They contain no PII — only a pseudonym and timestamp.

use axiam_core::error::AxiamResult;
use axiam_core::models::gdpr::{CreateErasureProof, ErasureProof};
use axiam_core::repository::ErasureProofRepository;
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct ErasureProofRow {
    pseudonym: String,
    tenant_id: String,
    user_id: String,
    erased_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

pub struct SurrealErasureProofRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> Clone for SurrealErasureProofRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealErasureProofRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> ErasureProofRepository for SurrealErasureProofRepository<C> {
    async fn create(&self, input: CreateErasureProof) -> AxiamResult<ErasureProof> {
        let id = Uuid::new_v4();
        let result = self
            .db
            .query(
                "CREATE type::record('erasure_proof', $id) SET \
                 pseudonym = $pseudonym, \
                 tenant_id = $tenant_id, \
                 user_id = $user_id, \
                 erased_at = $erased_at",
            )
            .bind(("id", id.to_string()))
            .bind(("pseudonym", input.pseudonym.clone()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("user_id", input.user_id.to_string()))
            .bind(("erased_at", input.erased_at))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<ErasureProofRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "erasure_proof".into(),
            id: id.to_string(),
        })?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let user_id = Uuid::parse_str(&row.user_id)
            .map_err(|e| DbError::Migration(format!("invalid user UUID: {e}")))?;

        Ok(ErasureProof {
            id,
            pseudonym: row.pseudonym,
            tenant_id,
            user_id,
            erased_at: row.erased_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use surrealdb::Surreal;
    use surrealdb::engine::local::Mem;

    async fn setup_db() -> Surreal<surrealdb::engine::local::Db> {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        crate::schema::run_migrations(&db).await.unwrap();
        db
    }

    #[tokio::test]
    async fn erasure_proof_insert_only() {
        let db = setup_db().await;
        let repo = SurrealErasureProofRepository::new(db);
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let proof = repo
            .create(CreateErasureProof {
                pseudonym: "DELETED_USER_deadbeef01234567".into(),
                tenant_id,
                user_id,
                erased_at: Utc::now(),
            })
            .await
            .unwrap();

        assert_eq!(proof.pseudonym, "DELETED_USER_deadbeef01234567");
        assert_eq!(proof.tenant_id, tenant_id);
        assert_eq!(proof.user_id, user_id);
        assert!(!proof.id.is_nil());
    }

    /// A duplicate erasure proof CREATE for the same (tenant_id, user_id)
    /// must fail idempotently at the schema level (D-03b/SECHRD-06) — the DB
    /// UNIQUE index is the enforcement mechanism a retried erasure relies on.
    #[tokio::test]
    async fn erasure_proof_duplicate_user_rejected_by_unique_index() {
        let db = setup_db().await;
        let repo = SurrealErasureProofRepository::new(db);
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        repo.create(CreateErasureProof {
            pseudonym: "DELETED_USER_first0123456789ab".into(),
            tenant_id,
            user_id,
            erased_at: Utc::now(),
        })
        .await
        .unwrap();

        let duplicate = repo
            .create(CreateErasureProof {
                pseudonym: "DELETED_USER_second123456789a".into(),
                tenant_id,
                user_id,
                erased_at: Utc::now(),
            })
            .await;

        assert!(
            duplicate.is_err(),
            "a second erasure proof for the same (tenant_id, user_id) must be rejected by the UNIQUE index"
        );
    }
}
