//! SurrealDB implementation of [`NotificationRuleRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::notification_rule::{
    CreateNotificationRule, NotificationEventType, NotificationRule, UpdateNotificationRule,
};
use axiam_core::repository::{NotificationRuleRepository, PaginatedResult, Pagination};
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

// -------------------------------------------------------------------
// Row structs
// -------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct NotificationRuleRow {
    tenant_id: String,
    name: String,
    description: String,
    events: Vec<String>,
    recipient_emails: Vec<String>,
    enabled: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct NotificationRuleRowWithId {
    record_id: String,
    tenant_id: String,
    name: String,
    description: String,
    events: Vec<String>,
    recipient_emails: Vec<String>,
    enabled: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct CountRow {
    total: u64,
}

// -------------------------------------------------------------------
// Row -> Domain conversions
// -------------------------------------------------------------------

fn parse_events(raw: Vec<String>) -> Result<Vec<NotificationEventType>, DbError> {
    raw.into_iter()
        .map(|s| {
            s.parse::<NotificationEventType>()
                .map_err(|e| DbError::Migration(e))
        })
        .collect()
}

impl NotificationRuleRow {
    fn try_into_entry(self, id: Uuid) -> Result<NotificationRule, DbError> {
        Ok(NotificationRule {
            id,
            tenant_id: Uuid::parse_str(&self.tenant_id)
                .map_err(|e| DbError::Migration(e.to_string()))?,
            name: self.name,
            description: self.description,
            events: parse_events(self.events)?,
            recipient_emails: self.recipient_emails,
            enabled: self.enabled,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

impl NotificationRuleRowWithId {
    fn try_into_entry(self) -> Result<NotificationRule, DbError> {
        let id = Uuid::parse_str(&self.record_id).map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(NotificationRule {
            id,
            tenant_id: Uuid::parse_str(&self.tenant_id)
                .map_err(|e| DbError::Migration(e.to_string()))?,
            name: self.name,
            description: self.description,
            events: parse_events(self.events)?,
            recipient_emails: self.recipient_emails,
            enabled: self.enabled,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

// -------------------------------------------------------------------
// Repository
// -------------------------------------------------------------------

pub struct SurrealNotificationRuleRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> Clone for SurrealNotificationRuleRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealNotificationRuleRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> NotificationRuleRepository for SurrealNotificationRuleRepository<C> {
    async fn create(&self, input: CreateNotificationRule) -> AxiamResult<NotificationRule> {
        let id = Uuid::new_v4();
        let events_str: Vec<String> = input.events.iter().map(|e| e.to_db_string()).collect();

        let result = self
            .db
            .query(
                "CREATE type::record('notification_rule', $id) \
                 SET \
                 tenant_id = $tenant_id, \
                 name = $name, \
                 description = $description, \
                 events = $events, \
                 recipient_emails = $recipient_emails, \
                 enabled = true, \
                 created_at = time::now(), \
                 updated_at = time::now()",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("name", input.name))
            .bind(("description", input.description))
            .bind(("events", events_str))
            .bind(("recipient_emails", input.recipient_emails))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<NotificationRuleRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "notification_rule".into(),
            id: id.to_string(),
        })?;
        row.try_into_entry(id).map_err(Into::into)
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<NotificationRule> {
        let result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM notification_rule \
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
        let rows: Vec<NotificationRuleRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "notification_rule".into(),
            id: id.to_string(),
        })?;
        row.try_into_entry().map_err(Into::into)
    }

    async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateNotificationRule,
    ) -> AxiamResult<NotificationRule> {
        let mut set_clauses = vec!["updated_at = time::now()".to_string()];
        let mut binds: Vec<(String, serde_json::Value)> = Vec::new();

        if let Some(ref name) = input.name {
            set_clauses.push("name = $name".into());
            binds.push(("name".into(), serde_json::json!(name)));
        }
        if let Some(ref description) = input.description {
            set_clauses.push("description = $description".into());
            binds.push(("description".into(), serde_json::json!(description)));
        }
        if let Some(ref events) = input.events {
            let events_str: Vec<String> = events.iter().map(|e| e.to_db_string()).collect();
            set_clauses.push("events = $events".into());
            binds.push(("events".into(), serde_json::json!(events_str)));
        }
        if let Some(ref emails) = input.recipient_emails {
            set_clauses.push("recipient_emails = $recipient_emails".into());
            binds.push(("recipient_emails".into(), serde_json::json!(emails)));
        }
        if let Some(enabled) = input.enabled {
            set_clauses.push("enabled = $enabled".into());
            binds.push(("enabled".into(), serde_json::json!(enabled)));
        }

        let sql = format!(
            "UPDATE type::record('notification_rule', $id) SET {} \
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
        let rows: Vec<NotificationRuleRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "notification_rule".into(),
            id: id.to_string(),
        })?;
        row.try_into_entry(id).map_err(Into::into)
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        let result = self
            .db
            .query(
                "DELETE type::record('notification_rule', $id) \
                 WHERE tenant_id = $tenant_id RETURN BEFORE",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<NotificationRuleRow> = result.take(0).map_err(DbError::from)?;
        if rows.is_empty() {
            return Err(DbError::NotFound {
                entity: "notification_rule".into(),
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
    ) -> AxiamResult<PaginatedResult<NotificationRule>> {
        let tid = tenant_id.to_string();

        let count_result = self
            .db
            .query(
                "SELECT count() AS total \
                 FROM notification_rule \
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
                 FROM notification_rule \
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
        let rows: Vec<NotificationRuleRowWithId> = data_result.take(0).map_err(DbError::from)?;

        let items: Vec<NotificationRule> = rows
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

    async fn get_by_event(
        &self,
        tenant_id: Uuid,
        event_type: &str,
    ) -> AxiamResult<Vec<NotificationRule>> {
        let result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM notification_rule \
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
        let rows: Vec<NotificationRuleRowWithId> = result.take(0).map_err(DbError::from)?;

        rows.into_iter()
            .map(|r| r.try_into_entry().map_err(Into::into))
            .collect()
    }
}
