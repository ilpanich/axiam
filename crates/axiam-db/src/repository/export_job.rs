//! SurrealDB implementation of [`ExportJobRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::gdpr::{CreateExportJob, ExportJob, ExportJobStatus};
use axiam_core::repository::ExportJobRepository;
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::helpers::parse_uuid;

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct ExportJobRow {
    tenant_id: String,
    user_id: String,
    status: String,
    encrypted_blob: Option<String>,
    file_path: Option<String>,
    blob_nonce: Option<String>,
    download_token_hash: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct ExportJobRowWithId {
    record_id: String,
    tenant_id: String,
    user_id: String,
    status: String,
    encrypted_blob: Option<String>,
    file_path: Option<String>,
    blob_nonce: Option<String>,
    download_token_hash: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

fn parse_status(s: &str) -> Result<ExportJobStatus, DbError> {
    match s {
        "queued" => Ok(ExportJobStatus::Queued),
        "ready" => Ok(ExportJobStatus::Ready),
        "downloaded" => Ok(ExportJobStatus::Downloaded),
        "expired" => Ok(ExportJobStatus::Expired),
        "failed" => Ok(ExportJobStatus::Failed),
        other => Err(DbError::Migration(format!(
            "unknown export_job status: {other}"
        ))),
    }
}

impl ExportJobRowWithId {
    fn try_into_domain(self) -> Result<ExportJob, DbError> {
        let id = parse_uuid(&self.record_id, "record_id")?;
        let tenant_id = parse_uuid(&self.tenant_id, "tenant_id")?;
        let user_id = parse_uuid(&self.user_id, "user_id")?;
        Ok(ExportJob {
            id,
            tenant_id,
            user_id,
            status: parse_status(&self.status)?,
            encrypted_blob: self.encrypted_blob,
            file_path: self.file_path,
            blob_nonce: self.blob_nonce,
            download_token_hash: self.download_token_hash,
            expires_at: self.expires_at,
            created_at: self.created_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

pub struct SurrealExportJobRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> Clone for SurrealExportJobRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealExportJobRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }

    /// Return true if the user already has a queued or in-flight export job
    /// (status = 'queued').  Used by the GDPR handler to prevent duplicate
    /// concurrent export requests (CQ-B39).
    pub async fn has_pending_for_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<bool> {
        let mut result = self
            .db
            .query(
                "SELECT count() AS total FROM export_job \
                 WHERE tenant_id = $tenant_id AND user_id = $user_id \
                 AND status IN ['queued'] \
                 GROUP ALL",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        #[derive(Debug, surrealdb_types::SurrealValue)]
        struct CountRow {
            total: u64,
        }

        let rows: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
        let count = rows.into_iter().next().map(|r| r.total).unwrap_or(0);
        Ok(count > 0)
    }
}

impl<C: Connection> ExportJobRepository for SurrealExportJobRepository<C> {
    async fn create(&self, input: CreateExportJob) -> AxiamResult<ExportJob> {
        let id = Uuid::new_v4();
        let result = self
            .db
            .query(
                "CREATE type::record('export_job', $id) SET \
                 tenant_id = $tenant_id, \
                 user_id = $user_id, \
                 status = 'queued', \
                 encrypted_blob = NONE, \
                 file_path = NONE, \
                 blob_nonce = NONE, \
                 download_token_hash = NONE, \
                 expires_at = NONE, \
                 created_at = time::now()",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("user_id", input.user_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<ExportJobRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "export_job".into(),
            id: id.to_string(),
        })?;

        Ok(ExportJob {
            id,
            tenant_id: input.tenant_id,
            user_id: input.user_id,
            status: parse_status(&row.status)?,
            encrypted_blob: row.encrypted_blob,
            file_path: row.file_path,
            blob_nonce: row.blob_nonce,
            download_token_hash: row.download_token_hash,
            expires_at: row.expires_at,
            created_at: row.created_at,
        })
    }

    async fn find_queued(&self) -> AxiamResult<Vec<ExportJob>> {
        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM export_job \
                 WHERE status = 'queued' ORDER BY created_at ASC",
            )
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<ExportJobRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|r| r.try_into_domain().map_err(Into::into))
            .collect()
    }

    async fn set_ready(
        &self,
        id: Uuid,
        download_token_hash: String,
        encrypted_blob: Option<String>,
        file_path: Option<String>,
        blob_nonce: Option<String>,
        expires_at: DateTime<Utc>,
    ) -> AxiamResult<()> {
        self.db
            .query(
                "UPDATE type::record('export_job', $id) SET \
                 status = 'ready', \
                 download_token_hash = $token_hash, \
                 encrypted_blob = $encrypted_blob, \
                 file_path = $file_path, \
                 blob_nonce = $blob_nonce, \
                 expires_at = $expires_at",
            )
            .bind(("id", id.to_string()))
            .bind(("token_hash", download_token_hash))
            .bind(("encrypted_blob", encrypted_blob))
            .bind(("file_path", file_path))
            .bind(("blob_nonce", blob_nonce))
            .bind(("expires_at", expires_at))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(())
    }

    async fn find_by_download_token_hash(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> AxiamResult<Option<ExportJob>> {
        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM export_job \
                 WHERE tenant_id = $tenant_id AND download_token_hash = $hash",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("hash", token_hash.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<ExportJobRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(|r| r.try_into_domain().map_err(Into::into))
            .transpose()
    }

    async fn mark_downloaded(&self, id: Uuid) -> AxiamResult<()> {
        self.db
            .query("UPDATE type::record('export_job', $id) SET status = 'downloaded'")
            .bind(("id", id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(())
    }

    async fn consume_ready_and_delete(&self, id: Uuid) -> AxiamResult<bool> {
        // Atomically mark as downloaded only if currently 'ready' (CQ-B38).
        // The WHERE clause prevents the TOCTTOU race on the two-step
        // mark_downloaded + delete sequence.
        let mut result = self
            .db
            .query(
                "UPDATE type::record('export_job', $id) \
                 SET status = 'downloaded' \
                 WHERE status = 'ready'",
            )
            .bind(("id", id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let updated: Vec<ExportJobRow> = result.take(0).map_err(DbError::from)?;
        if updated.is_empty() {
            // Status was not 'ready' — already consumed or in wrong state.
            return Ok(false);
        }

        // Delete the row now that it is marked downloaded.
        self.db
            .query("DELETE type::record('export_job', $id)")
            .bind(("id", id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        Ok(true)
    }

    async fn mark_failed(&self, id: Uuid) -> AxiamResult<()> {
        self.db
            .query("UPDATE type::record('export_job', $id) SET status = 'failed'")
            .bind(("id", id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(())
    }

    async fn delete(&self, id: Uuid) -> AxiamResult<()> {
        self.db
            .query("DELETE type::record('export_job', $id)")
            .bind(("id", id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use surrealdb::Surreal;
    use surrealdb::engine::local::Mem;

    async fn setup_db() -> Surreal<surrealdb::engine::local::Db> {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        crate::schema::run_migrations(&db).await.unwrap();
        db
    }

    #[tokio::test]
    async fn export_job_lifecycle() {
        let db = setup_db().await;
        let repo = SurrealExportJobRepository::new(db);
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let job = repo
            .create(CreateExportJob { tenant_id, user_id })
            .await
            .unwrap();
        assert_eq!(job.status, ExportJobStatus::Queued);
        assert!(job.download_token_hash.is_none(), "no token until ready");

        let queued = repo.find_queued().await.unwrap();
        assert_eq!(queued.len(), 1);

        let expires = Utc::now() + Duration::hours(24);
        repo.set_ready(
            job.id,
            "download-token-hash".into(),
            Some("blob".into()),
            None,
            Some("nonce".into()),
            expires,
        )
        .await
        .unwrap();

        let found = repo
            .find_by_download_token_hash(tenant_id, "download-token-hash")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.status, ExportJobStatus::Ready);
        assert_eq!(
            found.download_token_hash.as_deref(),
            Some("download-token-hash")
        );

        repo.mark_downloaded(found.id).await.unwrap();
    }
}
