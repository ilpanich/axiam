//! SurrealDB implementation of [`CaCertificateRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::certificate::{
    CaCertificate, CertificateStatus, KeyAlgorithm, StoreCaCertificate,
};
use axiam_core::repository::{CaCertificateRepository, PaginatedResult, Pagination};
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct CaCertificateRow {
    organization_id: String,
    subject: String,
    public_cert_pem: String,
    fingerprint: String,
    key_algorithm: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    status: String,
    encrypted_private_key: Option<surrealdb_types::Bytes>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct CaCertificateRowWithId {
    record_id: String,
    organization_id: String,
    subject: String,
    public_cert_pem: String,
    fingerprint: String,
    key_algorithm: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    status: String,
    encrypted_private_key: Option<surrealdb_types::Bytes>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct CountRow {
    total: u64,
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

// ---------------------------------------------------------------------------
// Row → domain conversion
// ---------------------------------------------------------------------------

impl CaCertificateRow {
    fn into_entry(self, id: Uuid) -> Result<CaCertificate, DbError> {
        let organization_id = Uuid::parse_str(&self.organization_id)
            .map_err(|e| DbError::Migration(format!("invalid org UUID: {e}")))?;
        Ok(CaCertificate {
            id,
            organization_id,
            subject: self.subject,
            public_cert_pem: self.public_cert_pem,
            fingerprint: self.fingerprint,
            key_algorithm: parse_key_algorithm(&self.key_algorithm)?,
            not_before: self.not_before,
            not_after: self.not_after,
            status: parse_status(&self.status)?,
            encrypted_private_key: self.encrypted_private_key.map(|b| b.into_inner().to_vec()),
            created_at: self.created_at,
        })
    }
}

impl CaCertificateRowWithId {
    fn try_into_entry(self) -> Result<CaCertificate, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let organization_id = Uuid::parse_str(&self.organization_id)
            .map_err(|e| DbError::Migration(format!("invalid org UUID: {e}")))?;
        Ok(CaCertificate {
            id,
            organization_id,
            subject: self.subject,
            public_cert_pem: self.public_cert_pem,
            fingerprint: self.fingerprint,
            key_algorithm: parse_key_algorithm(&self.key_algorithm)?,
            not_before: self.not_before,
            not_after: self.not_after,
            status: parse_status(&self.status)?,
            encrypted_private_key: self.encrypted_private_key.map(|b| b.into_inner().to_vec()),
            created_at: self.created_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct SurrealCaCertificateRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealCaCertificateRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> CaCertificateRepository for SurrealCaCertificateRepository<C> {
    async fn create(&self, input: StoreCaCertificate) -> AxiamResult<CaCertificate> {
        let id = Uuid::new_v4();
        let id_str = id.to_string();

        let result = self
            .db
            .query(
                "CREATE type::record('ca_certificate', $id) SET \
                 organization_id = $org_id, \
                 subject = $subject, \
                 public_cert_pem = $public_cert_pem, \
                 fingerprint = $fingerprint, \
                 key_algorithm = $key_algorithm, \
                 not_before = $not_before, \
                 not_after = $not_after, \
                 status = $status, \
                 encrypted_private_key = $encrypted_private_key",
            )
            .bind(("id", id_str))
            .bind(("org_id", input.organization_id.to_string()))
            .bind(("subject", input.subject))
            .bind(("public_cert_pem", input.public_cert_pem))
            .bind(("fingerprint", input.fingerprint))
            .bind(("key_algorithm", key_algorithm_str(&input.key_algorithm)))
            .bind(("not_before", input.not_before))
            .bind(("not_after", input.not_after))
            .bind(("status", status_str(&CertificateStatus::Active)))
            .bind((
                "encrypted_private_key",
                input
                    .encrypted_private_key
                    .map(surrealdb_types::Bytes::from),
            ))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let row: Option<CaCertificateRow> = result.take(0).map_err(DbError::from)?;
        let row = row.ok_or_else(|| DbError::NotFound {
            entity: "ca_certificate".into(),
            id: id.to_string(),
        })?;

        Ok(row.into_entry(id)?)
    }

    async fn get_by_id(&self, organization_id: Uuid, id: Uuid) -> AxiamResult<CaCertificate> {
        let result = self
            .db
            .query(
                "SELECT * FROM type::record('ca_certificate', $id) \
                 WHERE organization_id = $org_id",
            )
            .bind(("id", id.to_string()))
            .bind(("org_id", organization_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let row: Option<CaCertificateRow> = result.take(0).map_err(DbError::from)?;
        let row = row.ok_or_else(|| DbError::NotFound {
            entity: "ca_certificate".into(),
            id: id.to_string(),
        })?;

        Ok(row.into_entry(id)?)
    }

    async fn revoke(&self, organization_id: Uuid, id: Uuid) -> AxiamResult<()> {
        let result = self
            .db
            .query(
                "UPDATE type::record('ca_certificate', $id) SET \
                 status = $status \
                 WHERE organization_id = $org_id",
            )
            .bind(("id", id.to_string()))
            .bind(("org_id", organization_id.to_string()))
            .bind(("status", status_str(&CertificateStatus::Revoked)))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let row: Option<CaCertificateRow> = result.take(0).map_err(DbError::from)?;
        if row.is_none() {
            return Err(DbError::NotFound {
                entity: "ca_certificate".into(),
                id: id.to_string(),
            }
            .into());
        }

        Ok(())
    }

    async fn list_by_organization(
        &self,
        organization_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<CaCertificate>> {
        let org_id_str = organization_id.to_string();

        // Count query.
        let count_sql = "SELECT count() AS total FROM ca_certificate \
                         WHERE organization_id = $org_id GROUP ALL";
        let count_result = self
            .db
            .query(count_sql)
            .bind(("org_id", org_id_str.clone()))
            .await
            .map_err(DbError::from)?;
        let mut count_result = count_result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;
        let total = count_rows.first().map(|r| r.total).unwrap_or(0);

        // Data query.
        let data_sql = "SELECT meta::id(id) AS record_id, * FROM ca_certificate \
                        WHERE organization_id = $org_id \
                        ORDER BY created_at DESC \
                        LIMIT $limit START $offset";
        let data_result = self
            .db
            .query(data_sql)
            .bind(("org_id", org_id_str))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;
        let mut data_result = data_result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<CaCertificateRowWithId> = data_result.take(0).map_err(DbError::from)?;

        let items: Vec<CaCertificate> = rows
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
}
