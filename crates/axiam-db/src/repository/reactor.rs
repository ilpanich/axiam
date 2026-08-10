//! SurrealDB implementation of [`ReactorRepository`] (X1).

use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::models::reactor::{
    CreateReactor, DEFAULT_TIMEOUT_MS, FailurePolicy, MAX_TIMEOUT_MS, Reactor, ReactorMode,
    UpdateReactor, default_failure_policy_for,
};
use axiam_core::repository::{PaginatedResult, Pagination, ReactorRepository};
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{CountRow, classify_write_error, paginate, take_first_or_not_found};

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct ReactorRow {
    tenant_id: String,
    name: String,
    description: String,
    events: Vec<String>,
    mode: String,
    priority: i64,
    timeout_ms: i64,
    failure_policy: String,
    enabled: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    last_seen_at: Option<DateTime<Utc>>,
}

#[derive(Debug, SurrealValue)]
struct ReactorRowWithId {
    record_id: String,
    tenant_id: String,
    name: String,
    description: String,
    events: Vec<String>,
    mode: String,
    priority: i64,
    timeout_ms: i64,
    failure_policy: String,
    enabled: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    last_seen_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Row → domain
// ---------------------------------------------------------------------------

/// Parse `mode`, defaulting an unrecognised value to [`ReactorMode::Listen`].
///
/// Listen is the safe side: a listener is fire-and-forget and cannot veto,
/// mutate or delay anything. Defaulting the other way would let a row written
/// outside the API turn itself into an interceptor on the token path.
///
/// Erroring instead was considered and rejected for the same reason SEC-092
/// rejected it on grants — one malformed row must not take a tenant's token
/// issuance down. Unlike SEC-092 there is a genuinely inert value available
/// here, so demotion is possible where dropping was needed there.
fn mode_or_safe_default(raw: &str, id: Uuid) -> ReactorMode {
    ReactorMode::from_wire(raw).unwrap_or_else(|| {
        tracing::error!(
            mode = %raw,
            reactor_id = %id,
            "reactor row carries an unrecognised mode; demoting it to 'listen' \
             so it cannot intercept"
        );
        ReactorMode::Listen
    })
}

/// Parse `failure_policy`, defaulting an unrecognised value to
/// [`FailurePolicy::FailClosed`] — an unreachable veto has not passed.
fn failure_policy_or_safe_default(raw: &str, id: Uuid) -> FailurePolicy {
    FailurePolicy::from_wire(raw).unwrap_or_else(|| {
        tracing::error!(
            failure_policy = %raw,
            reactor_id = %id,
            "reactor row carries an unrecognised failure_policy; defaulting to \
             'fail_closed'"
        );
        FailurePolicy::FailClosed
    })
}

/// Clamp a stored `timeout_ms` into the range the API would have accepted.
///
/// The v29 schema ASSERT already enforces this on write, so a value outside it
/// means the row was written outside the API. Clamping rather than trusting
/// keeps the dispatcher's wait bounded by [`MAX_TIMEOUT_MS`] no matter what is
/// in the column — the ASSERT and this clamp are the same rule stated in the
/// two places that can enforce it.
fn clamp_timeout(raw: i64, id: Uuid) -> u32 {
    let clamped = raw.clamp(1, i64::from(MAX_TIMEOUT_MS)) as u32;
    if i64::from(clamped) != raw {
        tracing::error!(
            timeout_ms = raw,
            clamped_to = clamped,
            reactor_id = %id,
            "reactor row carries an out-of-range timeout_ms; clamping"
        );
    }
    clamped
}

impl ReactorRow {
    /// The `CREATE`/`UPDATE` shape has no `record_id` projection, so the id
    /// comes from the caller. Rather than a second converter that could drift
    /// from the read path's, it borrows the id and delegates — one place
    /// decides what a row means.
    fn try_into_entry(self, id: Uuid) -> Result<Reactor, DbError> {
        ReactorRowWithId {
            record_id: id.to_string(),
            tenant_id: self.tenant_id,
            name: self.name,
            description: self.description,
            events: self.events,
            mode: self.mode,
            priority: self.priority,
            timeout_ms: self.timeout_ms,
            failure_policy: self.failure_policy,
            enabled: self.enabled,
            created_at: self.created_at,
            updated_at: self.updated_at,
            last_seen_at: self.last_seen_at,
        }
        .try_into_entry()
    }
}

impl ReactorRowWithId {
    fn try_into_entry(self) -> Result<Reactor, DbError> {
        let id = Uuid::parse_str(&self.record_id).map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(Reactor {
            id,
            tenant_id: Uuid::parse_str(&self.tenant_id)
                .map_err(|e| DbError::Migration(e.to_string()))?,
            name: self.name,
            description: self.description,
            events: self.events,
            mode: mode_or_safe_default(&self.mode, id),
            priority: self.priority as i32,
            timeout_ms: clamp_timeout(self.timeout_ms, id),
            failure_policy: failure_policy_or_safe_default(&self.failure_policy, id),
            enabled: self.enabled,
            created_at: self.created_at,
            updated_at: self.updated_at,
            last_seen_at: self.last_seen_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct SurrealReactorRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> SurrealReactorRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        let db = db.into();
        Self { db }
    }
}

impl<C: Connection> ReactorRepository for SurrealReactorRepository<C> {
    async fn create(&self, input: CreateReactor) -> AxiamResult<Reactor> {
        let id = new_id();
        // An omitted failure_policy takes the STRICTEST default among the
        // subscribed events, not a blanket one — see
        // `default_failure_policy_for`. That is how a caller registering for
        // `login.post_auth` gets fail_closed without having to know it should.
        let failure_policy = input
            .failure_policy
            .unwrap_or_else(|| default_failure_policy_for(&input.events));
        let timeout_ms = input.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);

        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('reactor', $id) SET \
                 tenant_id = $tenant_id, \
                 name = $name, \
                 description = $description, \
                 events = $events, \
                 mode = $mode, \
                 priority = $priority, \
                 timeout_ms = $timeout_ms, \
                 failure_policy = $failure_policy, \
                 enabled = $enabled, \
                 created_at = time::now(), \
                 updated_at = time::now(), \
                 last_seen_at = NONE",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("name", input.name))
            .bind(("description", input.description))
            .bind(("events", input.events))
            .bind(("mode", input.mode.as_str().to_string()))
            .bind(("priority", i64::from(input.priority)))
            .bind(("timeout_ms", i64::from(timeout_ms)))
            .bind(("failure_policy", failure_policy.as_str().to_string()))
            .bind(("enabled", input.enabled))
            .await
            .map_err(|e| classify_write_error(e, "reactor"))?;

        let mut result = result
            .check()
            .map_err(|e| classify_write_error(e, "reactor"))?;
        let rows: Vec<ReactorRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "reactor", &id.to_string())?;
        row.try_into_entry(id).map_err(Into::into)
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Reactor> {
        let result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM reactor \
                 WHERE meta::id(id) = $id AND tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<ReactorRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "reactor", &id.to_string())?;
        row.try_into_entry().map_err(Into::into)
    }

    async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateReactor,
    ) -> AxiamResult<Reactor> {
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
            set_clauses.push("events = $events".into());
            binds.push(("events".into(), serde_json::json!(events)));
        }
        if let Some(mode) = input.mode {
            set_clauses.push("mode = $mode".into());
            binds.push(("mode".into(), serde_json::json!(mode.as_str())));
        }
        if let Some(priority) = input.priority {
            set_clauses.push("priority = $priority".into());
            binds.push(("priority".into(), serde_json::json!(priority)));
        }
        if let Some(timeout_ms) = input.timeout_ms {
            set_clauses.push("timeout_ms = $timeout_ms".into());
            binds.push(("timeout_ms".into(), serde_json::json!(timeout_ms)));
        }
        if let Some(failure_policy) = input.failure_policy {
            set_clauses.push("failure_policy = $failure_policy".into());
            binds.push((
                "failure_policy".into(),
                serde_json::json!(failure_policy.as_str()),
            ));
        }
        if let Some(enabled) = input.enabled {
            set_clauses.push("enabled = $enabled".into());
            binds.push(("enabled".into(), serde_json::json!(enabled)));
        }

        // `last_seen_at` is deliberately absent from this list. It is the
        // consumer's heartbeat, not a setting, and `touch_last_seen` writes it
        // without bumping `updated_at` — an operator reading "last modified"
        // wants the last configuration change, not the last heartbeat.

        let sql = format!(
            "UPDATE type::record('reactor', $id) SET {} WHERE tenant_id = $tenant_id",
            set_clauses.join(", ")
        );

        let db = self.db.current();
        let mut query = db.query(&sql);
        query = query
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()));
        for (key, val) in binds {
            query = query.bind((key, val));
        }

        let result = query
            .await
            .map_err(|e| classify_write_error(e, "reactor"))?;
        let mut result = result
            .check()
            .map_err(|e| classify_write_error(e, "reactor"))?;
        let rows: Vec<ReactorRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "reactor", &id.to_string())?;
        row.try_into_entry(id).map_err(Into::into)
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        let result = self
            .db
            .current()
            .query(
                "DELETE type::record('reactor', $id) \
                 WHERE tenant_id = $tenant_id RETURN BEFORE",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<ReactorRow> = result.take(0).map_err(DbError::from)?;
        if rows.is_empty() {
            return Err(DbError::NotFound {
                entity: "reactor".into(),
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
    ) -> AxiamResult<PaginatedResult<Reactor>> {
        let tid = tenant_id.to_string();

        let count_result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM reactor \
                 WHERE tenant_id = $tenant_id GROUP ALL",
            )
            .bind(("tenant_id", tid.clone()))
            .await
            .map_err(DbError::from)?;
        let mut count_result = count_result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;

        let data_result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM reactor \
                 WHERE tenant_id = $tenant_id \
                 ORDER BY priority ASC, record_id ASC \
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
        let rows: Vec<ReactorRowWithId> = data_result.take(0).map_err(DbError::from)?;

        let items = rows
            .into_iter()
            .map(ReactorRowWithId::try_into_entry)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(paginate(items, count_rows, &pagination))
    }

    async fn get_enabled_by_event(
        &self,
        tenant_id: Uuid,
        event: &str,
    ) -> AxiamResult<Vec<Reactor>> {
        // `enabled = true` is in the WHERE so it uses idx_reactor_tenant_enabled;
        // the events membership is a post-filter on a set that is already
        // per-tenant and small. Ordering is (priority, id) so the interceptor
        // chain is a total order and therefore reproducible across replicas.
        let result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM reactor \
                 WHERE tenant_id = $tenant_id AND enabled = true \
                 AND $event IN events \
                 ORDER BY priority ASC, record_id ASC",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("event", event.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<ReactorRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(ReactorRowWithId::try_into_entry)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    async fn touch_last_seen(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        self.db
            .current()
            .query(
                "UPDATE type::record('reactor', $id) SET last_seen_at = time::now() \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        // Deliberately does NOT 404 on a missing row. This is called from the
        // consumer's heartbeat path, where the reactor may have been deleted
        // between the consume and the touch; failing there would turn an
        // ordinary race into a logged error on every subsequent message.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANY: Uuid = Uuid::nil();

    /// A row written outside the API cannot promote itself to an interceptor.
    #[test]
    fn an_unrecognised_mode_is_demoted_to_listen() {
        for raw in ["", "INTERCEPTOR", "veto", "block"] {
            assert_eq!(
                mode_or_safe_default(raw, ANY),
                ReactorMode::Listen,
                "mode {raw:?} must not resolve to intercept"
            );
        }
        // The two real values still parse, casing and padding included.
        assert_eq!(
            mode_or_safe_default("intercept", ANY),
            ReactorMode::Intercept
        );
        assert_eq!(mode_or_safe_default(" LISTEN ", ANY), ReactorMode::Listen);
    }

    /// An unreachable veto has not passed, so a malformed policy fails closed.
    #[test]
    fn an_unrecognised_failure_policy_fails_closed() {
        for raw in ["", "open", "fail", "fail_sometimes"] {
            assert_eq!(
                failure_policy_or_safe_default(raw, ANY),
                FailurePolicy::FailClosed,
                "policy {raw:?} must not resolve to fail_open"
            );
        }
        assert_eq!(
            failure_policy_or_safe_default("fail_open", ANY),
            FailurePolicy::FailOpen
        );
    }

    /// The v29 ASSERT and this clamp are the same rule in the two places that
    /// can enforce it. If `MAX_TIMEOUT_MS` and the schema ever disagree, the
    /// dispatcher's wait is still bounded by this.
    #[test]
    fn a_stored_timeout_is_clamped_into_the_api_range() {
        assert_eq!(clamp_timeout(0, ANY), 1);
        assert_eq!(clamp_timeout(-5, ANY), 1);
        assert_eq!(clamp_timeout(500, ANY), 500);
        assert_eq!(
            clamp_timeout(i64::from(MAX_TIMEOUT_MS), ANY),
            MAX_TIMEOUT_MS
        );
        assert_eq!(clamp_timeout(600_000, ANY), MAX_TIMEOUT_MS);
        assert_eq!(clamp_timeout(i64::MAX, ANY), MAX_TIMEOUT_MS);
    }
}
