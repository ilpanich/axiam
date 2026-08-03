//! SurrealDB implementation of [`ServiceAccountRepository`].

use axiam_auth::client_secret;
use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::models::service_account::{
    CreateServiceAccount, ServiceAccount, UpdateServiceAccount,
};
use axiam_core::models::user::UserStatus;
use axiam_core::repository::{PaginatedResult, Pagination, ServiceAccountRepository};
use chrono::{DateTime, Utc};
use rand::RngExt;
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{CountRow, paginate, take_first_or_not_found};

/// Generate a random client ID with the `sa_` prefix (32 hex chars).
fn generate_client_id() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 16] = rng.random();
    format!("sa_{}", hex::encode(bytes))
}

/// Generate a random client secret (64 hex chars = 32 bytes of entropy).
///
/// Every client secret in AXIAM originates here or in the equivalent function
/// in [`super::oauth2_client`] — there is no operator-supplied-secret path.
/// The stored hash is nevertheless **keyed** (see
/// [`axiam_auth::client_secret`]) so the security of the at-rest
/// representation no longer rests on that property alone (OBS-1).
fn generate_client_secret() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rng.random();
    hex::encode(bytes)
}

/// Hash a client secret for storage, in the current (v2) scheme.
///
/// Resolves the process-wide keyed hasher, so this **fails closed** when no
/// pepper is configured in a release build rather than degrading to an unkeyed
/// digest (OBS-1). See [`axiam_auth::client_secret::install_from_config`] for
/// the startup gate.
fn hash_client_secret(secret: &str) -> AxiamResult<String> {
    Ok(client_secret::global()?.hash(secret))
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
        UserStatus::Anonymized => "Anonymized",
    }
}

#[derive(Debug, SurrealValue)]
struct ServiceAccountRow {
    tenant_id: String,
    name: String,
    description: Option<String>,
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
    description: Option<String>,
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
            description: self.description,
            client_id: self.client_id,
            client_secret_hash: self.client_secret_hash,
            status: parse_status(&self.status)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// SurrealDB implementation of the ServiceAccount repository.
#[derive(Clone)]
pub struct SurrealServiceAccountRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> SurrealServiceAccountRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        let db = db.into();
        Self { db }
    }
}

impl<C: Connection> ServiceAccountRepository for SurrealServiceAccountRepository<C> {
    async fn create(&self, input: CreateServiceAccount) -> AxiamResult<(ServiceAccount, String)> {
        let id = new_id();
        let id_str = id.to_string();
        let tenant_id_str = input.tenant_id.to_string();

        let client_id = generate_client_id();
        let raw_secret = generate_client_secret();
        let secret_hash = hash_client_secret(&raw_secret)?;

        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('service_account', $id) SET \
                 tenant_id = $tenant_id, \
                 name = $name, \
                 description = $description, \
                 client_id = $client_id, \
                 client_secret_hash = $secret_hash, \
                 status = 'Active'",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str))
            .bind(("name", input.name))
            .bind(("description", input.description))
            .bind(("client_id", client_id))
            .bind(("secret_hash", secret_hash))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<ServiceAccountRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "service_account", &id_str)?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;

        let sa = ServiceAccount {
            id,
            tenant_id,
            name: row.name,
            description: row.description,
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
            .current()
            .query(
                "SELECT * FROM type::record('service_account', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<ServiceAccountRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "service_account", &id_str)?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;

        Ok(ServiceAccount {
            id,
            tenant_id,
            name: row.name,
            description: row.description,
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
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM service_account \
                 WHERE tenant_id = $tenant_id AND client_id = $client_id",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("client_id", client_id_owned.clone()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<ServiceAccountRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(
            rows,
            "service_account",
            &format!("client_id={client_id_owned}"),
        )?;

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
        if input.description.is_some() {
            sets.push("description = $description");
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

        let db = self.db.current();
        let mut builder = db
            .query(&query)
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str));

        if let Some(name) = input.name {
            builder = builder.bind(("name", name));
        }
        if let Some(description) = input.description {
            builder = builder.bind(("description", description));
        }
        if let Some(status) = input.status {
            builder = builder.bind(("status", status_to_str(&status).to_string()));
        }

        let result = builder.await.map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<ServiceAccountRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "service_account", &id_str)?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;

        Ok(ServiceAccount {
            id,
            tenant_id,
            name: row.name,
            description: row.description,
            client_id: row.client_id,
            client_secret_hash: row.client_secret_hash,
            status: parse_status(&row.status)?,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        let id_str = id.to_string();

        // Delete the has_role edges then the record inside one transaction so
        // a concurrent reader never observes a partial delete. The has_role
        // edge carries no flat tenant_id column, so tenant scoping is a
        // node-tenant guard on the edge's `in` endpoint (in.tenant_id),
        // mirroring role.delete; without it a caller with a foreign-tenant
        // service-account id could strip another tenant's role bindings.
        // `.check()` surfaces per-statement failures instead of swallowing
        // them as Ok.
        let query = format!(
            "BEGIN TRANSACTION; \
             DELETE has_role WHERE in = service_account:`{id_str}` AND in.tenant_id = $tenant_id; \
             DELETE type::record('service_account', $id) WHERE tenant_id = $tenant_id; \
             COMMIT TRANSACTION"
        );

        self.db
            .current()
            .query(query)
            .bind(("id", id_str))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

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
            .current()
            .query(
                "SELECT count() AS total FROM service_account \
                 WHERE tenant_id = $tenant_id GROUP ALL",
            )
            .bind(("tenant_id", tenant_id_str.clone()))
            .await
            .map_err(DbError::from)?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;

        let mut result = self
            .db
            .current()
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

        Ok(paginate(items, count_rows, &pagination))
    }

    async fn rotate_secret(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<String> {
        let id_str = id.to_string();

        let raw_secret = generate_client_secret();
        let secret_hash = hash_client_secret(&raw_secret)?;

        let result = self
            .db
            .current()
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

    /// Compare-and-swap upgrade of a stored `client_secret_hash` (§13.4
    /// observation 4).
    ///
    /// Scoped by `tenant_id` as well as `client_id` — the tenant predicate is
    /// not redundant defensive noise here, it is what stops a `client_id`
    /// colliding across tenants from letting one tenant's successful
    /// authentication rewrite another tenant's stored hash.
    async fn upgrade_client_secret_hash(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        expected_hash: &str,
        new_hash: &str,
    ) -> AxiamResult<bool> {
        let result = self
            .db
            .current()
            .query(
                "UPDATE service_account SET \
                 client_secret_hash = $new_hash, \
                 updated_at = time::now() \
                 WHERE tenant_id = $tenant_id \
                 AND client_id = $client_id \
                 AND client_secret_hash = $expected_hash",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("client_id", client_id.to_string()))
            .bind(("expected_hash", expected_hash.to_string()))
            .bind(("new_hash", new_hash.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<ServiceAccountRow> = result.take(0).map_err(DbError::from)?;
        Ok(!rows.is_empty())
    }
}
