//! SurrealDB implementation of [`ServiceAccountRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::service_account::{
    CreateServiceAccount, ServiceAccount, UpdateServiceAccount,
};
use axiam_core::models::user::UserStatus;
use axiam_core::repository::{PaginatedResult, Pagination, ServiceAccountRepository};
use chrono::{DateTime, Utc};
use rand::Rng;
use sha2::{Digest, Sha256};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

/// Generate a random client ID with the `sa_` prefix (32 hex chars).
fn generate_client_id() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 16] = rng.random();
    format!("sa_{}", hex::encode(bytes))
}

/// Generate a random client secret (64 hex chars = 32 bytes of entropy).
fn generate_client_secret() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rng.random();
    hex::encode(bytes)
}

/// Hash a client secret using SHA-256.
pub fn hash_client_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hex::encode(hasher.finalize())
}

fn parse_status(s: &str) -> Result<UserStatus, DbError> {
    match s {
        "Active" => Ok(UserStatus::Active),
        "Inactive" => Ok(UserStatus::Inactive),
        "Locked" => Ok(UserStatus::Locked),
        "PendingVerification" => Ok(UserStatus::PendingVerification),
        other => Err(DbError::Migration(format!("unknown status: {other}"))),
    }
}

fn status_to_str(s: &UserStatus) -> &'static str {
    match s {
        UserStatus::Active => "Active",
        UserStatus::Inactive => "Inactive",
        UserStatus::Locked => "Locked",
        UserStatus::PendingVerification => "PendingVerification",
    }
}

#[derive(Debug, SurrealValue)]
struct ServiceAccountRow {
    tenant_id: String,
    name: String,
    client_id: String,
    client_secret_hash: String,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct ServiceAccountRowWithId {
    record_id: String,
    tenant_id: String,
    name: String,
    client_id: String,
    client_secret_hash: String,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl ServiceAccountRowWithId {
    fn try_into_service_account(self) -> Result<ServiceAccount, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        Ok(ServiceAccount {
            id,
            tenant_id,
            name: self.name,
            client_id: self.client_id,
            client_secret_hash: self.client_secret_hash,
            status: parse_status(&self.status)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(Debug, SurrealValue)]
struct CountRow {
    total: u64,
}

/// SurrealDB implementation of the ServiceAccount repository.
#[derive(Clone)]
pub struct SurrealServiceAccountRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealServiceAccountRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> ServiceAccountRepository for SurrealServiceAccountRepository<C> {
    async fn create(&self, input: CreateServiceAccount) -> AxiamResult<(ServiceAccount, String)> {
        let id = Uuid::new_v4();
        let id_str = id.to_string();
        let tenant_id_str = input.tenant_id.to_string();

        let client_id = generate_client_id();
        let raw_secret = generate_client_secret();
        let secret_hash = hash_client_secret(&raw_secret);

        let result = self
            .db
            .query(
                "CREATE type::record('service_account', $id) SET \
                 tenant_id = $tenant_id, \
                 name = $name, \
                 client_id = $client_id, \
                 client_secret_hash = $secret_hash, \
                 status = 'Active'",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str))
            .bind(("name", input.name))
            .bind(("client_id", client_id))
            .bind(("secret_hash", secret_hash))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<ServiceAccountRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "service_account".into(),
            id: id_str,
        })?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;

        let sa = ServiceAccount {
            id,
            tenant_id,
            name: row.name,
            client_id: row.client_id,
            client_secret_hash: row.client_secret_hash,
            status: parse_status(&row.status)?,
            created_at: row.created_at,
            updated_at: row.updated_at,
        };

        Ok((sa, raw_secret))
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<ServiceAccount> {
        let id_str = id.to_string();

        let mut result = self
            .db
            .query(
                "SELECT * FROM type::record('service_account', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<ServiceAccountRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "service_account".into(),
            id: id_str,
        })?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;

        Ok(ServiceAccount {
            id,
            tenant_id,
            name: row.name,
            client_id: row.client_id,
            client_secret_hash: row.client_secret_hash,
            status: parse_status(&row.status)?,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn get_by_client_id(
        &self,
        tenant_id: Uuid,
        client_id: &str,
    ) -> AxiamResult<ServiceAccount> {
        let client_id_owned = client_id.to_string();

        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM service_account \
                 WHERE tenant_id = $tenant_id AND client_id = $client_id",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("client_id", client_id_owned.clone()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<ServiceAccountRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "service_account".into(),
            id: format!("client_id={client_id_owned}"),
        })?;

        row.try_into_service_account().map_err(Into::into)
    }

    async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateServiceAccount,
    ) -> AxiamResult<ServiceAccount> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let mut sets = Vec::new();
        if input.name.is_some() {
            sets.push("name = $name");
        }
        if input.status.is_some() {
            sets.push("status = $status");
        }
        sets.push("updated_at = time::now()");

        let query = format!(
            "UPDATE type::record('service_account', $id) SET {} \
             WHERE tenant_id = $tenant_id",
            sets.join(", ")
        );

        let mut builder = self
            .db
            .query(&query)
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str));

        if let Some(name) = input.name {
            builder = builder.bind(("name", name));
        }
        if let Some(status) = input.status {
            builder = builder.bind(("status", status_to_str(&status).to_string()));
        }

        let result = builder.await.map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<ServiceAccountRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "service_account".into(),
            id: id_str,
        })?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;

        Ok(ServiceAccount {
            id,
            tenant_id,
            name: row.name,
            client_id: row.client_id,
            client_secret_hash: row.client_secret_hash,
            status: parse_status(&row.status)?,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        let id_str = id.to_string();

        let query = format!(
            "DELETE has_role WHERE in = service_account:`{id_str}`; \
             DELETE type::record('service_account', $id) \
             WHERE tenant_id = $tenant_id;"
        );

        self.db
            .query(query)
            .bind(("id", id_str))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        Ok(())
    }

    async fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<ServiceAccount>> {
        let tenant_id_str = tenant_id.to_string();

        let mut count_result = self
            .db
            .query(
                "SELECT count() AS total FROM service_account \
                 WHERE tenant_id = $tenant_id GROUP ALL",
            )
            .bind(("tenant_id", tenant_id_str.clone()))
            .await
            .map_err(DbError::from)?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;
        let total = count_rows.first().map(|r| r.total).unwrap_or(0);

        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM service_account \
                 WHERE tenant_id = $tenant_id \
                 ORDER BY created_at ASC \
                 LIMIT $limit START $offset",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<ServiceAccountRowWithId> = result.take(0).map_err(DbError::from)?;

        let items = rows
            .into_iter()
            .map(|row| row.try_into_service_account())
            .collect::<Result<Vec<_>, DbError>>()?;

        Ok(PaginatedResult {
            items,
            total,
            offset: pagination.offset,
            limit: pagination.limit,
        })
    }

    async fn rotate_secret(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<String> {
        let id_str = id.to_string();

        let raw_secret = generate_client_secret();
        let secret_hash = hash_client_secret(&raw_secret);

        let result = self
            .db
            .query(
                "UPDATE type::record('service_account', $id) SET \
                 client_secret_hash = $secret_hash, \
                 updated_at = time::now() \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id_str.clone()))
            .bind(("secret_hash", secret_hash))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<ServiceAccountRow> = result.take(0).map_err(DbError::from)?;
        if rows.is_empty() {
            return Err(DbError::NotFound {
                entity: "service_account".into(),
                id: id_str,
            }
            .into());
        }

        Ok(raw_secret)
    }
}
