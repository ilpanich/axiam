//! SurrealDB implementation of [`OAuth2ClientRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::oauth2_client::{CreateOAuth2Client, OAuth2Client, UpdateOAuth2Client};
use axiam_core::repository::{OAuth2ClientRepository, PaginatedResult, Pagination};
use chrono::{DateTime, Utc};
use rand::Rng;
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

/// Generate a random client ID with the `oa_` prefix (32 hex chars).
fn generate_client_id() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 16] = rng.random();
    format!("oa_{}", hex::encode(bytes))
}

/// Generate a random client secret (64 hex chars = 32 bytes of entropy).
fn generate_client_secret() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rng.random();
    hex::encode(bytes)
}

#[derive(Debug, SurrealValue)]
struct OAuth2ClientRow {
    tenant_id: String,
    client_id: String,
    client_secret_hash: String,
    name: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    scopes: Vec<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct OAuth2ClientRowWithId {
    record_id: String,
    tenant_id: String,
    client_id: String,
    client_secret_hash: String,
    name: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    scopes: Vec<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl OAuth2ClientRowWithId {
    fn try_into_client(self) -> Result<OAuth2Client, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        Ok(OAuth2Client {
            id,
            tenant_id,
            client_id: self.client_id,
            client_secret_hash: self.client_secret_hash,
            name: self.name,
            redirect_uris: self.redirect_uris,
            grant_types: self.grant_types,
            scopes: self.scopes,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(Debug, SurrealValue)]
struct CountRow {
    total: u64,
}

/// SurrealDB implementation of the OAuth2Client repository.
#[derive(Clone)]
pub struct SurrealOAuth2ClientRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealOAuth2ClientRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> OAuth2ClientRepository for SurrealOAuth2ClientRepository<C> {
    async fn create(&self, input: CreateOAuth2Client) -> AxiamResult<(OAuth2Client, String)> {
        let id = Uuid::new_v4();
        let id_str = id.to_string();
        let tenant_id_str = input.tenant_id.to_string();

        let client_id = generate_client_id();
        let raw_secret = generate_client_secret();
        let secret_hash = super::service_account::hash_client_secret(&raw_secret);

        let result = self
            .db
            .query(
                "CREATE type::record('oauth2_client', $id) SET \
                 tenant_id = $tenant_id, \
                 client_id = $client_id, \
                 client_secret_hash = $secret_hash, \
                 name = $name, \
                 redirect_uris = $redirect_uris, \
                 grant_types = $grant_types, \
                 scopes = $scopes",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str))
            .bind(("client_id", client_id))
            .bind(("secret_hash", secret_hash))
            .bind(("name", input.name))
            .bind(("redirect_uris", input.redirect_uris))
            .bind(("grant_types", input.grant_types))
            .bind(("scopes", input.scopes))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<OAuth2ClientRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "oauth2_client".into(),
            id: id_str,
        })?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;

        let client = OAuth2Client {
            id,
            tenant_id,
            client_id: row.client_id,
            client_secret_hash: row.client_secret_hash,
            name: row.name,
            redirect_uris: row.redirect_uris,
            grant_types: row.grant_types,
            scopes: row.scopes,
            created_at: row.created_at,
            updated_at: row.updated_at,
        };

        Ok((client, raw_secret))
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<OAuth2Client> {
        let id_str = id.to_string();

        let mut result = self
            .db
            .query(
                "SELECT * FROM type::record('oauth2_client', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<OAuth2ClientRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "oauth2_client".into(),
            id: id_str,
        })?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;

        Ok(OAuth2Client {
            id,
            tenant_id,
            client_id: row.client_id,
            client_secret_hash: row.client_secret_hash,
            name: row.name,
            redirect_uris: row.redirect_uris,
            grant_types: row.grant_types,
            scopes: row.scopes,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn get_by_client_id(
        &self,
        tenant_id: Uuid,
        client_id: &str,
    ) -> AxiamResult<OAuth2Client> {
        let client_id_owned = client_id.to_string();

        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM oauth2_client \
                 WHERE tenant_id = $tenant_id AND client_id = $client_id",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("client_id", client_id_owned.clone()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<OAuth2ClientRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "oauth2_client".into(),
            id: format!("client_id={client_id_owned}"),
        })?;

        row.try_into_client().map_err(Into::into)
    }

    async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateOAuth2Client,
    ) -> AxiamResult<OAuth2Client> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let mut sets = Vec::new();
        if input.name.is_some() {
            sets.push("name = $name");
        }
        if input.redirect_uris.is_some() {
            sets.push("redirect_uris = $redirect_uris");
        }
        if input.grant_types.is_some() {
            sets.push("grant_types = $grant_types");
        }
        if input.scopes.is_some() {
            sets.push("scopes = $scopes");
        }
        sets.push("updated_at = time::now()");

        let query = format!(
            "UPDATE type::record('oauth2_client', $id) SET {} \
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
        if let Some(redirect_uris) = input.redirect_uris {
            builder = builder.bind(("redirect_uris", redirect_uris));
        }
        if let Some(grant_types) = input.grant_types {
            builder = builder.bind(("grant_types", grant_types));
        }
        if let Some(scopes) = input.scopes {
            builder = builder.bind(("scopes", scopes));
        }

        let result = builder.await.map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<OAuth2ClientRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "oauth2_client".into(),
            id: id_str,
        })?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;

        Ok(OAuth2Client {
            id,
            tenant_id,
            client_id: row.client_id,
            client_secret_hash: row.client_secret_hash,
            name: row.name,
            redirect_uris: row.redirect_uris,
            grant_types: row.grant_types,
            scopes: row.scopes,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        let id_str = id.to_string();

        self.db
            .query(
                "DELETE type::record('oauth2_client', $id) \
                 WHERE tenant_id = $tenant_id",
            )
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
    ) -> AxiamResult<PaginatedResult<OAuth2Client>> {
        let tenant_id_str = tenant_id.to_string();

        let mut count_result = self
            .db
            .query(
                "SELECT count() AS total FROM oauth2_client \
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
                "SELECT meta::id(id) AS record_id, * FROM oauth2_client \
                 WHERE tenant_id = $tenant_id \
                 ORDER BY created_at ASC \
                 LIMIT $limit START $offset",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<OAuth2ClientRowWithId> = result.take(0).map_err(DbError::from)?;

        let items = rows
            .into_iter()
            .map(|row| row.try_into_client())
            .collect::<Result<Vec<_>, DbError>>()?;

        Ok(PaginatedResult {
            items,
            total,
            offset: pagination.offset,
            limit: pagination.limit,
        })
    }
}
