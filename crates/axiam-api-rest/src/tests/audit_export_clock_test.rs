//! R101W3-07 (#640) — the tenant audit export's bound comes from the
//! datastore's clock, not the application host's.
//!
//! `audit_log.timestamp` is stamped by the datastore. W3.3 (#637) made
//! `tenants::delete` refuse (409) a receipt whose `exported_through` is later
//! than the receipt's own `timestamp`. An export that took its bound from the
//! application host (`Utc::now()`) was therefore refused by that check whenever
//! the host's clock led the datastore's, and — before the check — claimed rows
//! it had never paged.
//!
//! The in-memory engine reads the host's own clock, so the skew is built the
//! other way round: `Behind` is a repository whose datastore runs
//! [`SKEW_MINUTES`] behind this process. It stamps every row that far back
//! (the way the datastore would have) and answers `datastore_now()` with its
//! own, earlier, time. The process clock is the "application host" that leads.

use actix_web::body::to_bytes;
use axiam_core::error::AxiamResult;
use axiam_core::models::audit::{ActorType, AuditLogEntry, AuditOutcome, CreateAuditLogEntry};
use axiam_core::repository::{AuditLogFilter, AuditLogRepository, PaginatedResult, Pagination};
use axiam_db::repository::SurrealAuditLogRepository;
use chrono::{DateTime, Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

use crate::handlers::tenants::{AUDIT_EXPORT_ACTION, audit_export_response};

type TestDb = surrealdb::engine::local::Db;

/// How far the datastore's clock trails the application host's.
const SKEW_MINUTES: i64 = 90;

/// A datastore whose clock is [`SKEW_MINUTES`] behind the process clock.
#[derive(Clone)]
struct Behind {
    db: Surreal<TestDb>,
    inner: SurrealAuditLogRepository<TestDb>,
}

impl Behind {
    fn skew() -> Duration {
        Duration::minutes(SKEW_MINUTES)
    }
}

impl AuditLogRepository for Behind {
    async fn datastore_now(&self) -> AxiamResult<DateTime<Utc>> {
        Ok(self.inner.datastore_now().await? - Self::skew())
    }

    async fn append(&self, input: CreateAuditLogEntry) -> AxiamResult<AuditLogEntry> {
        let mut entry = self.inner.append(input).await?;
        entry.timestamp -= Self::skew();
        self.db
            .query("UPDATE type::record('audit_log', $id) SET timestamp = $ts")
            .bind(("id", entry.id.to_string()))
            .bind(("ts", entry.timestamp))
            .await
            .unwrap()
            .check()
            .unwrap();
        Ok(entry)
    }

    async fn list(
        &self,
        tenant_id: Uuid,
        filter: AuditLogFilter,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        self.inner.list(tenant_id, filter, pagination).await
    }

    async fn list_system(
        &self,
        filter: AuditLogFilter,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        self.inner.list_system(filter, pagination).await
    }

    async fn get_by_ids(&self, tenant_id: Uuid, ids: &[Uuid]) -> AxiamResult<Vec<AuditLogEntry>> {
        self.inner.get_by_ids(tenant_id, ids).await
    }

    async fn pseudonymize_actor(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        pseudonym: &str,
    ) -> AxiamResult<u64> {
        self.inner
            .pseudonymize_actor(tenant_id, user_id, pseudonym)
            .await
    }

    async fn prune_older_than(&self, cutoff: DateTime<Utc>) -> AxiamResult<u64> {
        self.inner.prune_older_than(cutoff).await
    }
}

async fn behind_datastore() -> Behind {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    Behind {
        inner: SurrealAuditLogRepository::new(db.clone()),
        db,
    }
}

fn row(tenant_id: Uuid, action: &str) -> CreateAuditLogEntry {
    CreateAuditLogEntry {
        tenant_id,
        actor_id: Uuid::new_v4(),
        actor_type: ActorType::System,
        action: action.into(),
        resource_id: None,
        outcome: AuditOutcome::Success,
        ip_address: None,
        metadata: None,
    }
}

/// The oracle. With the application clock `SKEW_MINUTES` ahead of the
/// datastore's, the export still holds every row at or before its bound, the
/// bound is the datastore's, and the receipt is stamped no earlier than the
/// bound it records — the condition under which `tenants::delete` accepts it
/// (`through > exported_at` is what it refuses).
#[tokio::test]
async fn an_application_clock_ahead_of_the_datastore_does_not_make_the_receipt_unacceptable() {
    let repo = behind_datastore().await;
    let tenant_id = Uuid::new_v4();
    for i in 0..5 {
        repo.append(row(tenant_id, &format!("seed.{i}")))
            .await
            .unwrap();
    }

    let app_clock_before = Utc::now();
    let resp = audit_export_response(repo.clone(), tenant_id, Uuid::new_v4())
        .await
        .unwrap();
    let body = to_bytes(resp.into_body()).await.ok().unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    let lines: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let (manifest, entries) = lines.split_last().unwrap();

    let through: DateTime<Utc> =
        serde_json::from_value(manifest["exported_through"].clone()).unwrap();

    // The bound is the datastore's, not the host's: it trails the host's clock
    // by about the skew (the host clock read before the export started is
    // later than the bound by at least the skew minus the test's own runtime).
    assert!(
        through < app_clock_before - Duration::minutes(SKEW_MINUTES - 5),
        "exported_through {through} must come from the datastore's clock, \
         which runs {SKEW_MINUTES} minutes behind this host's ({app_clock_before})"
    );

    // Every row stamped at or before the bound is in the export, and nothing
    // after it is.
    assert_eq!(manifest["record_count"], 5);
    assert_eq!(entries.len(), 5);
    for e in entries {
        let ts: DateTime<Utc> = serde_json::from_value(e["timestamp"].clone()).unwrap();
        assert!(ts <= through, "row {ts} is after the bound {through}");
    }

    // The receipt is stamped by the same clock, after the read: never earlier
    // than the bound it records.
    let all = repo
        .list(
            tenant_id,
            AuditLogFilter::default(),
            Pagination {
                offset: 0,
                limit: 100,
                search: None,
            },
        )
        .await
        .unwrap();
    let receipt = all
        .items
        .iter()
        .find(|e| e.action == AUDIT_EXPORT_ACTION)
        .expect("the export wrote its receipt");
    assert_eq!(
        manifest["receipt_id"],
        receipt.id.to_string(),
        "the manifest names the receipt in the log"
    );
    let recorded: DateTime<Utc> =
        serde_json::from_value(receipt.metadata["exported_through"].clone()).unwrap();
    assert_eq!(
        recorded, through,
        "the receipt records the manifest's bound"
    );
    assert!(
        recorded <= receipt.timestamp,
        "receipt bound {recorded} is later than the receipt's own stamp {} — \
         tenants::delete would refuse it (409)",
        receipt.timestamp
    );
}

/// The repository function itself: the datastore's time is read from the
/// datastore, in step with the rows it stamps.
#[tokio::test]
async fn datastore_now_is_on_the_clock_that_stamps_the_rows() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let repo = SurrealAuditLogRepository::new(db);
    let tenant_id = Uuid::new_v4();

    let first = repo.append(row(tenant_id, "a")).await.unwrap();
    let t = repo.datastore_now().await.unwrap();
    let second = repo.append(row(tenant_id, "b")).await.unwrap();

    assert!(first.timestamp <= t, "a row stamped before is not after");
    assert!(t <= second.timestamp, "a row stamped after is not before");
}
