//! SurrealDB implementation of [`PgpKeyRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::pgp_key::{
    PgpKey, PgpKeyAlgorithm, PgpKeyPurpose, PgpKeyStatus, StorePgpKey,
};
use axiam_core::repository::{PaginatedResult, Pagination, PgpKeyRepository};
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct PgpKeyRow {
    tenant_id: String,
    name: String,
    purpose: String,
    public_key_armored: String,
    fingerprint: String,
    algorithm: String,
    status: String,
    encrypted_private_key: Option<surrealdb_types::Bytes>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct PgpKeyRowWithId {
    record_id: String,
    tenant_id: String,
    name: String,
    purpose: String,
    public_key_armored: String,
    fingerprint: String,
    algorithm: String,
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

fn parse_purpose(s: &str) -> Result<PgpKeyPurpose, DbError> {
    match s {
        "AuditSigning" => Ok(PgpKeyPurpose::AuditSigning),
        "Export" => Ok(PgpKeyPurpose::Export),
        other => Err(DbError::Migration(format!(
            "unknown pgp key purpose: {other}"
        ))),
    }
}

fn purpose_str(p: &PgpKeyPurpose) -> &'static str {
    match p {
        PgpKeyPurpose::AuditSigning => "AuditSigning",
        PgpKeyPurpose::Export => "Export",
    }
}

fn parse_status(s: &str) -> Result<PgpKeyStatus, DbError> {
    match s {
        "Active" => Ok(PgpKeyStatus::Active),
        "Revoked" => Ok(PgpKeyStatus::Revoked),
        other => Err(DbError::Migration(format!(
            "unknown pgp key status: {other}"
        ))),
    }
}

fn status_str(s: &PgpKeyStatus) -> &'static str {
    match s {
        PgpKeyStatus::Active => "Active",
        PgpKeyStatus::Revoked => "Revoked",
    }
}

fn parse_algorithm(s: &str) -> Result<PgpKeyAlgorithm, DbError> {
    match s {
        "Rsa4096" => Ok(PgpKeyAlgorithm::Rsa4096),
        "Ed25519" => Ok(PgpKeyAlgorithm::Ed25519),
        other => Err(DbError::Migration(format!(
            "unknown pgp key algorithm: {other}"
        ))),
    }
}

fn algorithm_str(a: &PgpKeyAlgorithm) -> &'static str {
    match a {
        PgpKeyAlgorithm::Rsa4096 => "Rsa4096",
        PgpKeyAlgorithm::Ed25519 => "Ed25519",
    }
}

// ---------------------------------------------------------------------------
// Row → Domain conversions
// ---------------------------------------------------------------------------

impl PgpKeyRow {
    fn try_into_entry(self, id: Uuid) -> Result<PgpKey, DbError> {
        Ok(PgpKey {
            id,
            tenant_id: Uuid::parse_str(&self.tenant_id)
                .map_err(|e| DbError::Migration(e.to_string()))?,
            name: self.name,
            purpose: parse_purpose(&self.purpose)?,
            public_key_armored: self.public_key_armored,
            fingerprint: self.fingerprint,
            algorithm: parse_algorithm(&self.algorithm)?,
            status: parse_status(&self.status)?,
            encrypted_private_key: self.encrypted_private_key.map(|b| b.into_inner().to_vec()),
            created_at: self.created_at,
        })
    }
}

impl PgpKeyRowWithId {
    fn try_into_entry(self) -> Result<PgpKey, DbError> {
        let id = Uuid::parse_str(&self.record_id).map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(PgpKey {
            id,
            tenant_id: Uuid::parse_str(&self.tenant_id)
                .map_err(|e| DbError::Migration(e.to_string()))?,
            name: self.name,
            purpose: parse_purpose(&self.purpose)?,
            public_key_armored: self.public_key_armored,
            fingerprint: self.fingerprint,
            algorithm: parse_algorithm(&self.algorithm)?,
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
pub struct SurrealPgpKeyRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealPgpKeyRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> PgpKeyRepository for SurrealPgpKeyRepository<C> {
    async fn create(&self, input: StorePgpKey) -> AxiamResult<PgpKey> {
        let id = Uuid::new_v4();
        let result = self
            .db
            .query(
                "CREATE type::record('pgp_key', $id) SET \
                 tenant_id = $tenant_id, \
                 name = $name, \
                 purpose = $purpose, \
                 public_key_armored = $public_key_armored, \
                 fingerprint = $fingerprint, \
                 algorithm = $algorithm, \
                 status = $status, \
                 encrypted_private_key = $encrypted_private_key",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("name", input.name.clone()))
            .bind(("purpose", purpose_str(&input.purpose)))
            .bind(("public_key_armored", input.public_key_armored.clone()))
            .bind(("fingerprint", input.fingerprint.clone()))
            .bind(("algorithm", algorithm_str(&input.algorithm)))
            .bind(("status", status_str(&PgpKeyStatus::Active)))
            .bind((
                "encrypted_private_key",
                input
                    .encrypted_private_key
                    .clone()
                    .map(surrealdb_types::Bytes::from),
            ))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<PgpKeyRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "pgp_key".into(),
            id: id.to_string(),
        })?;
        row.try_into_entry(id).map_err(Into::into)
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<PgpKey> {
        let result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM pgp_key \
                 WHERE meta::id(id) = $id AND tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<PgpKeyRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "pgp_key".into(),
            id: id.to_string(),
        })?;

        row.try_into_entry().map_err(Into::into)
    }

    async fn get_signing_key(&self, tenant_id: Uuid) -> AxiamResult<PgpKey> {
        let result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM pgp_key \
                 WHERE tenant_id = $tenant_id \
                 AND purpose = 'AuditSigning' \
                 AND status = 'Active' \
                 LIMIT 1",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<PgpKeyRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "pgp_key (AuditSigning)".into(),
            id: tenant_id.to_string(),
        })?;

        row.try_into_entry().map_err(Into::into)
    }

    async fn revoke(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        let result = self
            .db
            .query(
                "UPDATE type::record('pgp_key', $id) SET \
                 status = $status \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("status", status_str(&PgpKeyStatus::Revoked)))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let row: Option<PgpKeyRow> = result.take(0).map_err(DbError::from)?;
        if row.is_none() {
            return Err(DbError::NotFound {
                entity: "pgp_key".into(),
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
    ) -> AxiamResult<PaginatedResult<PgpKey>> {
        let tenant_id_str = tenant_id.to_string();

        let count_sql = "SELECT count() AS total FROM pgp_key \
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

        let data_sql = "SELECT meta::id(id) AS record_id, * FROM pgp_key \
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
        let rows: Vec<PgpKeyRowWithId> = data_result.take(0).map_err(DbError::from)?;

        let items: Vec<PgpKey> = rows
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
