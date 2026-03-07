//! SurrealDB implementation of [`CertificateRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::certificate::{
    Certificate, CertificateStatus, CertificateType, KeyAlgorithm, StoreCertificate,
};
use axiam_core::repository::{CertificateRepository, PaginatedResult, Pagination};
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct CertificateRow {
    tenant_id: String,
    issuer_ca_id: String,
    subject: String,
    public_cert_pem: String,
    fingerprint: String,
    cert_type: String,
    key_algorithm: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    status: String,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct CertificateRowWithId {
    record_id: String,
    tenant_id: String,
    issuer_ca_id: String,
    subject: String,
    public_cert_pem: String,
    fingerprint: String,
    cert_type: String,
    key_algorithm: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    status: String,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct CountRow {
    total: u64,
}

#[derive(Debug, SurrealValue)]
struct BoundTargetRow {
    sa_id: String,
}

// ---------------------------------------------------------------------------
// Enum helpers
// ---------------------------------------------------------------------------

fn parse_status(s: &str) -> Result<CertificateStatus, DbError> {
    match s {
        "Active" => Ok(CertificateStatus::Active),
        "Revoked" => Ok(CertificateStatus::Revoked),
        "Expired" => Ok(CertificateStatus::Expired),
        other => Err(DbError::Migration(format!(
            "unknown certificate status: {other}"
        ))),
    }
}

fn status_str(s: &CertificateStatus) -> &'static str {
    match s {
        CertificateStatus::Active => "Active",
        CertificateStatus::Revoked => "Revoked",
        CertificateStatus::Expired => "Expired",
    }
}

fn parse_key_algorithm(s: &str) -> Result<KeyAlgorithm, DbError> {
    match s {
        "Rsa4096" => Ok(KeyAlgorithm::Rsa4096),
        "Ed25519" => Ok(KeyAlgorithm::Ed25519),
        other => Err(DbError::Migration(format!(
            "unknown key algorithm: {other}"
        ))),
    }
}

fn key_algorithm_str(k: &KeyAlgorithm) -> &'static str {
    match k {
        KeyAlgorithm::Rsa4096 => "Rsa4096",
        KeyAlgorithm::Ed25519 => "Ed25519",
    }
}

fn parse_cert_type(s: &str) -> Result<CertificateType, DbError> {
    match s {
        "User" => Ok(CertificateType::User),
        "Service" => Ok(CertificateType::Service),
        "Device" => Ok(CertificateType::Device),
        other => Err(DbError::Migration(format!(
            "unknown certificate type: {other}"
        ))),
    }
}

fn cert_type_str(t: &CertificateType) -> &'static str {
    match t {
        CertificateType::User => "User",
        CertificateType::Service => "Service",
        CertificateType::Device => "Device",
    }
}

// ---------------------------------------------------------------------------
// Row → domain conversion
// ---------------------------------------------------------------------------

impl CertificateRow {
    fn into_entry(self, id: Uuid) -> Result<Certificate, DbError> {
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let issuer_ca_id = Uuid::parse_str(&self.issuer_ca_id)
            .map_err(|e| DbError::Migration(format!("invalid issuer CA UUID: {e}")))?;
        Ok(Certificate {
            id,
            tenant_id,
            issuer_ca_id,
            subject: self.subject,
            public_cert_pem: self.public_cert_pem,
            fingerprint: self.fingerprint,
            cert_type: parse_cert_type(&self.cert_type)?,
            key_algorithm: parse_key_algorithm(&self.key_algorithm)?,
            not_before: self.not_before,
            not_after: self.not_after,
            status: parse_status(&self.status)?,
            metadata: self.metadata,
            created_at: self.created_at,
        })
    }
}

impl CertificateRowWithId {
    fn try_into_entry(self) -> Result<Certificate, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let issuer_ca_id = Uuid::parse_str(&self.issuer_ca_id)
            .map_err(|e| DbError::Migration(format!("invalid issuer CA UUID: {e}")))?;
        Ok(Certificate {
            id,
            tenant_id,
            issuer_ca_id,
            subject: self.subject,
            public_cert_pem: self.public_cert_pem,
            fingerprint: self.fingerprint,
            cert_type: parse_cert_type(&self.cert_type)?,
            key_algorithm: parse_key_algorithm(&self.key_algorithm)?,
            not_before: self.not_before,
            not_after: self.not_after,
            status: parse_status(&self.status)?,
            metadata: self.metadata,
            created_at: self.created_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct SurrealCertificateRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealCertificateRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> CertificateRepository for SurrealCertificateRepository<C> {
    async fn create(&self, input: StoreCertificate) -> AxiamResult<Certificate> {
        let id = Uuid::new_v4();
        let id_str = id.to_string();

        let result = self
            .db
            .query(
                "CREATE type::record('certificate', $id) SET \
                 tenant_id = $tenant_id, \
                 issuer_ca_id = $issuer_ca_id, \
                 subject = $subject, \
                 public_cert_pem = $public_cert_pem, \
                 fingerprint = $fingerprint, \
                 cert_type = $cert_type, \
                 key_algorithm = $key_algorithm, \
                 not_before = $not_before, \
                 not_after = $not_after, \
                 status = $status, \
                 metadata = $metadata",
            )
            .bind(("id", id_str))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("issuer_ca_id", input.issuer_ca_id.to_string()))
            .bind(("subject", input.subject))
            .bind(("public_cert_pem", input.public_cert_pem))
            .bind(("fingerprint", input.fingerprint))
            .bind(("cert_type", cert_type_str(&input.cert_type)))
            .bind(("key_algorithm", key_algorithm_str(&input.key_algorithm)))
            .bind(("not_before", input.not_before))
            .bind(("not_after", input.not_after))
            .bind(("status", status_str(&CertificateStatus::Active)))
            .bind(("metadata", input.metadata))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let row: Option<CertificateRow> = result.take(0).map_err(DbError::from)?;
        let row = row.ok_or_else(|| DbError::NotFound {
            entity: "certificate".into(),
            id: id.to_string(),
        })?;

        // Create the signed_by edge (RELATE doesn't accept type::record()).
        let relate_sql = format!(
            "RELATE certificate:`{}`->signed_by->ca_certificate:`{}`",
            id, input.issuer_ca_id,
        );
        self.db.query(&relate_sql).await.map_err(DbError::from)?;

        Ok(row.into_entry(id)?)
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Certificate> {
        let result = self
            .db
            .query(
                "SELECT * FROM type::record('certificate', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let row: Option<CertificateRow> = result.take(0).map_err(DbError::from)?;
        let row = row.ok_or_else(|| DbError::NotFound {
            entity: "certificate".into(),
            id: id.to_string(),
        })?;

        Ok(row.into_entry(id)?)
    }

    async fn get_by_fingerprint(
        &self,
        tenant_id: Uuid,
        fingerprint: &str,
    ) -> AxiamResult<Certificate> {
        let result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM certificate \
                 WHERE tenant_id = $tenant_id AND fingerprint = $fingerprint",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("fingerprint", fingerprint.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<CertificateRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "certificate".into(),
            id: fingerprint.to_string(),
        })?;

        row.try_into_entry().map_err(Into::into)
    }

    async fn revoke(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        let result = self
            .db
            .query(
                "UPDATE type::record('certificate', $id) SET \
                 status = $status \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("status", status_str(&CertificateStatus::Revoked)))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let row: Option<CertificateRow> = result.take(0).map_err(DbError::from)?;
        if row.is_none() {
            return Err(DbError::NotFound {
                entity: "certificate".into(),
                id: id.to_string(),
            }
            .into());
        }

        Ok(())
    }

    async fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<Certificate>> {
        let tenant_id_str = tenant_id.to_string();

        let count_sql = "SELECT count() AS total FROM certificate \
                         WHERE tenant_id = $tenant_id GROUP ALL";
        let count_result = self
            .db
            .query(count_sql)
            .bind(("tenant_id", tenant_id_str.clone()))
            .await
            .map_err(DbError::from)?;
        let mut count_result = count_result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;
        let total = count_rows.first().map(|r| r.total).unwrap_or(0);

        let data_sql = "SELECT meta::id(id) AS record_id, * FROM certificate \
                        WHERE tenant_id = $tenant_id \
                        ORDER BY created_at DESC \
                        LIMIT $limit START $offset";
        let data_result = self
            .db
            .query(data_sql)
            .bind(("tenant_id", tenant_id_str))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;
        let mut data_result = data_result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<CertificateRowWithId> = data_result.take(0).map_err(DbError::from)?;

        let items: Vec<Certificate> = rows
            .into_iter()
            .map(|r| r.try_into_entry())
            .collect::<Result<_, _>>()?;

        Ok(PaginatedResult {
            items,
            total,
            offset: pagination.offset,
            limit: pagination.limit,
        })
    }

    async fn get_by_fingerprint_global(&self, fingerprint: &str) -> AxiamResult<Certificate> {
        let result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM certificate \
                 WHERE fingerprint = $fingerprint",
            )
            .bind(("fingerprint", fingerprint.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<CertificateRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "certificate".into(),
            id: fingerprint.to_string(),
        })?;

        row.try_into_entry().map_err(Into::into)
    }

    async fn bind_to_service_account(
        &self,
        _tenant_id: Uuid,
        cert_id: Uuid,
        sa_id: Uuid,
    ) -> AxiamResult<()> {
        let relate_sql = format!(
            "RELATE certificate:`{}`->cert_bound_to->service_account:`{}`",
            cert_id, sa_id,
        );
        self.db
            .query(&relate_sql)
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(())
    }

    async fn get_bound_service_account(&self, cert_id: Uuid) -> AxiamResult<Option<Uuid>> {
        // Use a subquery to extract the service_account ID as a string
        let sql = format!(
            "SELECT meta::id(out) AS sa_id FROM cert_bound_to \
             WHERE in = certificate:`{}`",
            cert_id,
        );
        let result = self.db.query(&sql).await.map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<BoundTargetRow> = result.take(0).map_err(DbError::from)?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };

        let sa_id = Uuid::parse_str(&row.sa_id)
            .map_err(|e| DbError::Migration(format!("invalid service account UUID: {e}")))?;
        Ok(Some(sa_id))
    }
}
