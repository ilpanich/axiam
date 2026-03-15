//! SurrealDB implementation of [`FederationConfigRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::federation::{
    CreateFederationConfig, FederationConfig, FederationProtocol, UpdateFederationConfig,
};
use axiam_core::repository::{FederationConfigRepository, PaginatedResult, Pagination};
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct FederationConfigRow {
    tenant_id: String,
    provider: String,
    protocol: String,
    metadata_url: Option<String>,
    client_id: String,
    client_secret: String,
    attribute_map: serde_json::Value,
    enabled: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct FederationConfigRowWithId {
    record_id: String,
    tenant_id: String,
    provider: String,
    protocol: String,
    metadata_url: Option<String>,
    client_id: String,
    client_secret: String,
    attribute_map: serde_json::Value,
    enabled: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct CountRow {
    total: u64,
}

// ---------------------------------------------------------------------------
// Row -> Domain conversions
// ---------------------------------------------------------------------------

fn parse_protocol(s: &str) -> Result<FederationProtocol, DbError> {
    match s {
        "OidcConnect" => Ok(FederationProtocol::OidcConnect),
        "Saml" => Ok(FederationProtocol::Saml),
        other => Err(DbError::Migration(format!(
            "Unknown federation protocol: {other}"
        ))),
    }
}

fn protocol_to_string(p: &FederationProtocol) -> &'static str {
    match p {
        FederationProtocol::OidcConnect => "OidcConnect",
        FederationProtocol::Saml => "Saml",
    }
}

impl FederationConfigRow {
    fn try_into_entry(self, id: Uuid) -> Result<FederationConfig, DbError> {
        Ok(FederationConfig {
            id,
            tenant_id: Uuid::parse_str(&self.tenant_id)
                .map_err(|e| DbError::Migration(e.to_string()))?,
            provider: self.provider,
            protocol: parse_protocol(&self.protocol)?,
            metadata_url: self.metadata_url,
            client_id: self.client_id,
            client_secret: self.client_secret,
            attribute_map: self.attribute_map,
            enabled: self.enabled,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

impl FederationConfigRowWithId {
    fn try_into_entry(self) -> Result<FederationConfig, DbError> {
        let id = Uuid::parse_str(&self.record_id).map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(FederationConfig {
            id,
            tenant_id: Uuid::parse_str(&self.tenant_id)
                .map_err(|e| DbError::Migration(e.to_string()))?,
            provider: self.provider,
            protocol: parse_protocol(&self.protocol)?,
            metadata_url: self.metadata_url,
            client_id: self.client_id,
            client_secret: self.client_secret,
            attribute_map: self.attribute_map,
            enabled: self.enabled,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

pub struct SurrealFederationConfigRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> Clone for SurrealFederationConfigRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealFederationConfigRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> FederationConfigRepository for SurrealFederationConfigRepository<C> {
    async fn create(&self, input: CreateFederationConfig) -> AxiamResult<FederationConfig> {
        let id = Uuid::new_v4();
        let protocol = protocol_to_string(&input.protocol);
        let attribute_map = input.attribute_map.unwrap_or_else(|| serde_json::json!({}));

        let result = self
            .db
            .query(
                "CREATE type::record('federation_config', $id) SET \
                 tenant_id = $tenant_id, \
                 provider = $provider, \
                 protocol = $protocol, \
                 metadata_url = $metadata_url, \
                 client_id = $client_id, \
                 client_secret = $client_secret, \
                 attribute_map = $attribute_map, \
                 enabled = true, \
                 created_at = time::now(), \
                 updated_at = time::now()",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("provider", input.provider))
            .bind(("protocol", protocol.to_string()))
            .bind(("metadata_url", input.metadata_url))
            .bind(("client_id", input.client_id))
            // TODO: encrypt client_secret with AES-256-GCM before storage
            // (same pattern as MFA secrets and CA private keys). For now the
            // value is stored in plaintext; tracked for follow-up.
            .bind(("client_secret", input.client_secret))
            .bind(("attribute_map", attribute_map))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<FederationConfigRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "federation_config".into(),
            id: id.to_string(),
        })?;
        row.try_into_entry(id).map_err(Into::into)
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<FederationConfig> {
        let result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM federation_config \
                 WHERE meta::id(id) = $id \
                 AND tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<FederationConfigRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "federation_config".into(),
            id: id.to_string(),
        })?;
        row.try_into_entry().map_err(Into::into)
    }

    async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateFederationConfig,
    ) -> AxiamResult<FederationConfig> {
        let mut set_clauses = vec!["updated_at = time::now()".to_string()];
        let mut binds: Vec<(String, serde_json::Value)> = Vec::new();

        if let Some(ref provider) = input.provider {
            set_clauses.push("provider = $provider".into());
            binds.push(("provider".into(), serde_json::json!(provider)));
        }
        if let Some(ref metadata_url) = input.metadata_url {
            set_clauses.push("metadata_url = $metadata_url".into());
            binds.push(("metadata_url".into(), serde_json::json!(metadata_url)));
        }
        if let Some(ref client_id) = input.client_id {
            set_clauses.push("client_id = $client_id".into());
            binds.push(("client_id".into(), serde_json::json!(client_id)));
        }
        if let Some(ref client_secret) = input.client_secret {
            // TODO: encrypt client_secret before storage (see create()).
            set_clauses.push("client_secret = $client_secret".into());
            binds.push(("client_secret".into(), serde_json::json!(client_secret)));
        }
        if let Some(ref attribute_map) = input.attribute_map {
            set_clauses.push("attribute_map = $attribute_map".into());
            binds.push(("attribute_map".into(), serde_json::json!(attribute_map)));
        }
        if let Some(enabled) = input.enabled {
            set_clauses.push("enabled = $enabled".into());
            binds.push(("enabled".into(), serde_json::json!(enabled)));
        }

        let sql = format!(
            "UPDATE type::record('federation_config', $id) SET {} \
             WHERE tenant_id = $tenant_id",
            set_clauses.join(", ")
        );

        let mut query = self.db.query(&sql);
        query = query
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()));

        for (key, val) in binds {
            query = query.bind((key, val));
        }

        let result = query.await.map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<FederationConfigRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "federation_config".into(),
            id: id.to_string(),
        })?;
        row.try_into_entry(id).map_err(Into::into)
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        let result = self
            .db
            .query(
                "DELETE type::record('federation_config', $id) \
                 WHERE tenant_id = $tenant_id RETURN BEFORE",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<FederationConfigRow> = result.take(0).map_err(DbError::from)?;
        if rows.is_empty() {
            return Err(DbError::NotFound {
                entity: "federation_config".into(),
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
    ) -> AxiamResult<PaginatedResult<FederationConfig>> {
        let tid = tenant_id.to_string();

        let count_result = self
            .db
            .query(
                "SELECT count() AS total FROM federation_config \
                 WHERE tenant_id = $tenant_id GROUP ALL",
            )
            .bind(("tenant_id", tid.clone()))
            .await
            .map_err(DbError::from)?;
        let mut count_result = count_result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;
        let total = count_rows.first().map(|r| r.total).unwrap_or(0);

        let data_result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM federation_config \
                 WHERE tenant_id = $tenant_id \
                 ORDER BY created_at DESC \
                 LIMIT $limit START $offset",
            )
            .bind(("tenant_id", tid))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;
        let mut data_result = data_result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<FederationConfigRowWithId> = data_result.take(0).map_err(DbError::from)?;

        let items: Vec<FederationConfig> = rows
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
