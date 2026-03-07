//! SurrealDB implementation of [`AuditLogRepository`].
//!
//! Audit logs are append-only — the underlying table schema enforces
//! `FOR update NONE` and `FOR delete NONE`.

use axiam_core::error::AxiamResult;
use axiam_core::models::audit::{ActorType, AuditLogEntry, AuditOutcome, CreateAuditLogEntry};
use axiam_core::repository::{AuditLogFilter, AuditLogRepository, PaginatedResult, Pagination};
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct AuditLogRow {
    tenant_id: String,
    actor_id: String,
    actor_type: String,
    action: String,
    resource_id: Option<String>,
    outcome: String,
    ip_address: Option<String>,
    metadata: serde_json::Value,
    timestamp: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct AuditLogRowWithId {
    record_id: String,
    tenant_id: String,
    actor_id: String,
    actor_type: String,
    action: String,
    resource_id: Option<String>,
    outcome: String,
    ip_address: Option<String>,
    metadata: serde_json::Value,
    timestamp: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct CountRow {
    total: u64,
}

// ---------------------------------------------------------------------------
// Enum helpers
// ---------------------------------------------------------------------------

fn parse_actor_type(s: &str) -> Result<ActorType, DbError> {
    match s {
        "User" => Ok(ActorType::User),
        "ServiceAccount" => Ok(ActorType::ServiceAccount),
        "System" => Ok(ActorType::System),
        other => Err(DbError::Migration(format!("unknown actor type: {other}"))),
    }
}

fn actor_type_str(t: &ActorType) -> &'static str {
    match t {
        ActorType::User => "User",
        ActorType::ServiceAccount => "ServiceAccount",
        ActorType::System => "System",
    }
}

fn parse_outcome(s: &str) -> Result<AuditOutcome, DbError> {
    match s {
        "Success" => Ok(AuditOutcome::Success),
        "Failure" => Ok(AuditOutcome::Failure),
        "Denied" => Ok(AuditOutcome::Denied),
        other => Err(DbError::Migration(format!(
            "unknown audit outcome: {other}"
        ))),
    }
}

fn outcome_str(o: &AuditOutcome) -> &'static str {
    match o {
        AuditOutcome::Success => "Success",
        AuditOutcome::Failure => "Failure",
        AuditOutcome::Denied => "Denied",
    }
}

// ---------------------------------------------------------------------------
// Row → domain conversion
// ---------------------------------------------------------------------------

impl AuditLogRow {
    fn into_entry(self, id: Uuid) -> Result<AuditLogEntry, DbError> {
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let actor_id = Uuid::parse_str(&self.actor_id)
            .map_err(|e| DbError::Migration(format!("invalid actor UUID: {e}")))?;
        let resource_id = self
            .resource_id
            .as_deref()
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|e| DbError::Migration(format!("invalid resource UUID: {e}")))?;

        Ok(AuditLogEntry {
            id,
            tenant_id,
            actor_id,
            actor_type: parse_actor_type(&self.actor_type)?,
            action: self.action,
            resource_id,
            outcome: parse_outcome(&self.outcome)?,
            ip_address: self.ip_address,
            metadata: self.metadata,
            timestamp: self.timestamp,
        })
    }
}

impl AuditLogRowWithId {
    fn try_into_entry(self) -> Result<AuditLogEntry, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let actor_id = Uuid::parse_str(&self.actor_id)
            .map_err(|e| DbError::Migration(format!("invalid actor UUID: {e}")))?;
        let resource_id = self
            .resource_id
            .as_deref()
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|e| DbError::Migration(format!("invalid resource UUID: {e}")))?;

        Ok(AuditLogEntry {
            id,
            tenant_id,
            actor_id,
            actor_type: parse_actor_type(&self.actor_type)?,
            action: self.action,
            resource_id,
            outcome: parse_outcome(&self.outcome)?,
            ip_address: self.ip_address,
            metadata: self.metadata,
            timestamp: self.timestamp,
        })
    }
}

// ---------------------------------------------------------------------------
// Filter helpers (shared between count + data queries to avoid drift)
// ---------------------------------------------------------------------------

/// Pre-computed bind values for filter parameters.
enum FilterBind {
    Str(&'static str, String),
    DateTime(&'static str, DateTime<Utc>),
}

/// Build the WHERE clause and collected bind values from an `AuditLogFilter`.
///
/// Always includes `tenant_id = $tenant_id` (bound separately by the caller).
fn build_filter_clause(filter: &AuditLogFilter) -> (String, Vec<FilterBind>) {
    let mut conditions = vec!["tenant_id = $tenant_id".to_string()];
    let mut binds: Vec<FilterBind> = Vec::new();

    if let Some(actor_id) = &filter.actor_id {
        conditions.push("actor_id = $actor_id".into());
        binds.push(FilterBind::Str("actor_id", actor_id.to_string()));
    }
    if let Some(action) = &filter.action {
        conditions.push("action = $action".into());
        binds.push(FilterBind::Str("action", action.clone()));
    }
    if let Some(outcome) = &filter.outcome {
        conditions.push("outcome = $outcome".into());
        binds.push(FilterBind::Str("outcome", outcome_str(outcome).into()));
    }
    if let Some(resource_id) = &filter.resource_id {
        conditions.push("resource_id = $resource_id".into());
        binds.push(FilterBind::Str("resource_id", resource_id.to_string()));
    }
    if let Some(from) = &filter.from {
        conditions.push("timestamp >= $from_ts".into());
        binds.push(FilterBind::DateTime("from_ts", *from));
    }
    if let Some(to) = &filter.to {
        conditions.push("timestamp <= $to_ts".into());
        binds.push(FilterBind::DateTime("to_ts", *to));
    }

    (conditions.join(" AND "), binds)
}

/// Apply pre-computed filter binds to a query.
fn apply_filter_binds<'a, C: Connection>(
    mut query: surrealdb::method::Query<'a, C>,
    binds: &'a [FilterBind],
) -> surrealdb::method::Query<'a, C> {
    for bind in binds {
        match bind {
            FilterBind::Str(key, val) => {
                query = query.bind((*key, val.clone()));
            }
            FilterBind::DateTime(key, val) => {
                query = query.bind((*key, *val));
            }
        }
    }
    query
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

/// SurrealDB implementation of the audit log repository.
#[derive(Clone)]
pub struct SurrealAuditLogRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealAuditLogRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> AuditLogRepository for SurrealAuditLogRepository<C> {
    async fn append(&self, input: CreateAuditLogEntry) -> AxiamResult<AuditLogEntry> {
        let id = Uuid::new_v4();
        let id_str = id.to_string();

        let metadata = input
            .metadata
            .unwrap_or(serde_json::Value::Object(Default::default()));

        let resource_id_str = input.resource_id.map(|r| r.to_string());

        let result = self
            .db
            .query(
                "CREATE type::record('audit_log', $id) SET \
                 tenant_id = $tenant_id, \
                 actor_id = $actor_id, \
                 actor_type = $actor_type, \
                 action = $action, \
                 resource_id = $resource_id, \
                 outcome = $outcome, \
                 ip_address = $ip_address, \
                 metadata = $metadata",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("actor_id", input.actor_id.to_string()))
            .bind(("actor_type", actor_type_str(&input.actor_type).to_string()))
            .bind(("action", input.action))
            .bind(("resource_id", resource_id_str))
            .bind(("outcome", outcome_str(&input.outcome).to_string()))
            .bind(("ip_address", input.ip_address))
            .bind(("metadata", metadata))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<AuditLogRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "audit_log".into(),
            id: id_str,
        })?;

        Ok(row.into_entry(id)?)
    }

    async fn list(
        &self,
        tenant_id: Uuid,
        filter: AuditLogFilter,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        let tenant_id_str = tenant_id.to_string();

        // Build dynamic WHERE clause.
        let (where_clause, binds) = build_filter_clause(&filter);

        // Count query.
        let count_sql =
            format!("SELECT count() AS total FROM audit_log WHERE {where_clause} GROUP ALL");
        let mut count_query = self.db.query(&count_sql);
        count_query = count_query.bind(("tenant_id", tenant_id_str.clone()));
        count_query = apply_filter_binds(count_query, &binds);
        let mut count_result = count_query.await.map_err(DbError::from)?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;
        let total = count_rows.first().map(|r| r.total).unwrap_or(0);

        // Data query.
        let data_sql = format!(
            "SELECT meta::id(id) AS record_id, * FROM audit_log \
             WHERE {where_clause} \
             ORDER BY timestamp DESC \
             LIMIT $limit START $offset"
        );
        let mut data_query = self.db.query(&data_sql);
        data_query = data_query.bind(("tenant_id", tenant_id_str));
        data_query = apply_filter_binds(data_query, &binds);
        data_query = data_query.bind(("limit", pagination.limit));
        data_query = data_query.bind(("offset", pagination.offset));

        let mut data_result = data_query.await.map_err(DbError::from)?;
        let rows: Vec<AuditLogRowWithId> = data_result.take(0).map_err(DbError::from)?;

        let items: Vec<AuditLogEntry> = rows
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

    async fn list_system(
        &self,
        filter: AuditLogFilter,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        // System/unauthenticated entries are stored with nil tenant_id.
        self.list(Uuid::nil(), filter, pagination).await
    }

    async fn get_by_ids(&self, tenant_id: Uuid, ids: &[Uuid]) -> AxiamResult<Vec<AuditLogEntry>> {
        let id_strings: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
        let r = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM audit_log \
                 WHERE tenant_id = $tenant_id \
                 AND meta::id(id) IN $ids",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("ids", id_strings))
            .await
            .map_err(DbError::from)?;
        let mut result = r.check().map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<AuditLogRowWithId> = result.take(0).map_err(DbError::from)?;
        let entries: Vec<AuditLogEntry> = rows
            .into_iter()
            .map(|r| r.try_into_entry().map_err(Into::into))
            .collect::<AxiamResult<Vec<_>>>()?;

        // Preserve caller-provided order for deterministic signing
        let index: std::collections::HashMap<Uuid, AuditLogEntry> =
            entries.into_iter().map(|e| (e.id, e)).collect();
        Ok(ids.iter().filter_map(|id| index.get(id).cloned()).collect())
    }
}
