//! SurrealDB implementation of [`WebhookRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::webhook::{CreateWebhook, RetryPolicy, UpdateWebhook, Webhook};
use axiam_core::repository::{PaginatedResult, Pagination, WebhookRepository};
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct WebhookRow {
    tenant_id: String,
    url: String,
    events: Vec<String>,
    secret: String,
    enabled: bool,
    max_retries: i64,
    initial_delay_secs: i64,
    backoff_multiplier: f64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct WebhookRowWithId {
    record_id: String,
    tenant_id: String,
    url: String,
    events: Vec<String>,
    secret: String,
    enabled: bool,
    max_retries: i64,
    initial_delay_secs: i64,
    backoff_multiplier: f64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct CountRow {
    total: u64,
}

// ---------------------------------------------------------------------------
// Row → Domain conversions
// ---------------------------------------------------------------------------

impl WebhookRow {
    fn try_into_entry(self, id: Uuid) -> Result<Webhook, DbError> {
        Ok(Webhook {
            id,
            tenant_id: Uuid::parse_str(&self.tenant_id)
                .map_err(|e| DbError::Migration(e.to_string()))?,
            url: self.url,
            events: self.events,
            secret_hash: self.secret,
            enabled: self.enabled,
            retry_policy: RetryPolicy {
                max_retries: self.max_retries as u32,
                initial_delay_secs: self.initial_delay_secs as u64,
                backoff_multiplier: self.backoff_multiplier,
            },
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

impl WebhookRowWithId {
    fn try_into_entry(self) -> Result<Webhook, DbError> {
        let id = Uuid::parse_str(&self.record_id).map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(Webhook {
            id,
            tenant_id: Uuid::parse_str(&self.tenant_id)
                .map_err(|e| DbError::Migration(e.to_string()))?,
            url: self.url,
            events: self.events,
            secret_hash: self.secret,
            enabled: self.enabled,
            retry_policy: RetryPolicy {
                max_retries: self.max_retries as u32,
                initial_delay_secs: self.initial_delay_secs as u64,
                backoff_multiplier: self.backoff_multiplier,
            },
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct SurrealWebhookRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealWebhookRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> WebhookRepository for SurrealWebhookRepository<C> {
    async fn create(&self, input: CreateWebhook) -> AxiamResult<Webhook> {
        let id = Uuid::new_v4();
        let retry = input.retry_policy.unwrap_or_default();
        let result = self
            .db
            .query(
                "CREATE type::record('webhook', $id) SET \
                 tenant_id = $tenant_id, \
                 url = $url, \
                 events = $events, \
                 secret = $secret, \
                 enabled = true, \
                 max_retries = $max_retries, \
                 initial_delay_secs = $initial_delay_secs, \
                 backoff_multiplier = $backoff_multiplier, \
                 created_at = time::now(), \
                 updated_at = time::now()",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("url", input.url))
            .bind(("events", input.events))
            .bind(("secret", input.secret))
            .bind(("max_retries", retry.max_retries as i64))
            .bind(("initial_delay_secs", retry.initial_delay_secs as i64))
            .bind(("backoff_multiplier", retry.backoff_multiplier))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<WebhookRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "webhook".into(),
            id: id.to_string(),
        })?;
        row.try_into_entry(id).map_err(Into::into)
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Webhook> {
        let result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM webhook \
                 WHERE meta::id(id) = $id AND tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<WebhookRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "webhook".into(),
            id: id.to_string(),
        })?;
        row.try_into_entry().map_err(Into::into)
    }

    async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateWebhook,
    ) -> AxiamResult<Webhook> {
        let mut set_clauses = vec!["updated_at = time::now()".to_string()];
        let mut binds: Vec<(String, serde_json::Value)> = Vec::new();

        if let Some(ref url) = input.url {
            set_clauses.push("url = $url".into());
            binds.push(("url".into(), serde_json::json!(url)));
        }
        if let Some(ref events) = input.events {
            set_clauses.push("events = $events".into());
            binds.push(("events".into(), serde_json::json!(events)));
        }
        if let Some(enabled) = input.enabled {
            set_clauses.push("enabled = $enabled".into());
            binds.push(("enabled".into(), serde_json::json!(enabled)));
        }
        if let Some(ref retry) = input.retry_policy {
            set_clauses.push("max_retries = $max_retries".into());
            set_clauses.push("initial_delay_secs = $initial_delay_secs".into());
            set_clauses.push("backoff_multiplier = $backoff_multiplier".into());
            binds.push(("max_retries".into(), serde_json::json!(retry.max_retries)));
            binds.push((
                "initial_delay_secs".into(),
                serde_json::json!(retry.initial_delay_secs),
            ));
            binds.push((
                "backoff_multiplier".into(),
                serde_json::json!(retry.backoff_multiplier),
            ));
        }

        let sql = format!(
            "UPDATE type::record('webhook', $id) SET {} \
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
        let rows: Vec<WebhookRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "webhook".into(),
            id: id.to_string(),
        })?;
        row.try_into_entry(id).map_err(Into::into)
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        let result = self
            .db
            .query(
                "DELETE type::record('webhook', $id) \
                 WHERE tenant_id = $tenant_id RETURN BEFORE",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<WebhookRow> = result.take(0).map_err(DbError::from)?;
        if rows.is_empty() {
            return Err(DbError::NotFound {
                entity: "webhook".into(),
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
    ) -> AxiamResult<PaginatedResult<Webhook>> {
        let tid = tenant_id.to_string();

        let count_result = self
            .db
            .query(
                "SELECT count() AS total FROM webhook \
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
                "SELECT meta::id(id) AS record_id, * FROM webhook \
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
        let rows: Vec<WebhookRowWithId> = data_result.take(0).map_err(DbError::from)?;

        let items: Vec<Webhook> = rows
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

    async fn get_by_event(&self, tenant_id: Uuid, event_type: &str) -> AxiamResult<Vec<Webhook>> {
        let result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM webhook \
                 WHERE tenant_id = $tenant_id \
                 AND enabled = true \
                 AND events CONTAINS $event_type",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("event_type", event_type.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<WebhookRowWithId> = result.take(0).map_err(DbError::from)?;

        rows.into_iter()
            .map(|r| r.try_into_entry().map_err(Into::into))
            .collect()
    }
}
