//! T-108: request-audit rows that are lost are counted, reported, and — when a
//! dead-letter file is configured — written to it in the replayable form.
//!
//! "Lost" is two things: the worker's channel was full when the request ended
//! (`dropped`), or the datastore refused the append (`failed`). The datastore is
//! a test double, no SurrealDB.

use std::path::PathBuf;
use std::time::Duration;

use actix_web::{App, HttpResponse, test, web};
use axiam_audit::middleware::AuditMiddleware;
use axiam_audit::{DeadLetterWriter, RequestAuditLoss};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::audit::{ActorType, AuditLogEntry, AuditOutcome, CreateAuditLogEntry};
use axiam_core::repository::{AuditLogFilter, AuditLogRepository, PaginatedResult, Pagination};
use chrono::Utc;
use uuid::Uuid;

/// A datastore that refuses every append, or takes `delay` over each one.
#[derive(Clone)]
struct Datastore {
    fail: bool,
    delay: Duration,
}

impl Datastore {
    fn failing() -> Self {
        Self {
            fail: true,
            delay: Duration::ZERO,
        }
    }

    /// So slow that the worker is inside its first append for the whole test and
    /// the channel behind it fills.
    fn stuck() -> Self {
        Self {
            fail: false,
            delay: Duration::from_secs(3600),
        }
    }
}

impl AuditLogRepository for Datastore {
    async fn append(&self, input: CreateAuditLogEntry) -> AxiamResult<AuditLogEntry> {
        tokio::time::sleep(self.delay).await;
        if self.fail {
            return Err(AxiamError::Internal("datastore down".into()));
        }
        Ok(AuditLogEntry {
            id: Uuid::new_v4(),
            tenant_id: input.tenant_id,
            actor_id: input.actor_id,
            actor_type: input.actor_type,
            action: input.action,
            resource_id: input.resource_id,
            outcome: input.outcome,
            ip_address: input.ip_address,
            metadata: input.metadata.unwrap_or(serde_json::Value::Null),
            timestamp: Utc::now(),
        })
    }

    async fn list(
        &self,
        _: Uuid,
        _: AuditLogFilter,
        _: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        unimplemented!()
    }
    async fn list_system(
        &self,
        _: AuditLogFilter,
        _: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        unimplemented!()
    }
    async fn get_by_ids(&self, _: Uuid, _: &[Uuid]) -> AxiamResult<Vec<AuditLogEntry>> {
        unimplemented!()
    }
    async fn pseudonymize_actor(&self, _: Uuid, _: Uuid, _: &str) -> AxiamResult<u64> {
        unimplemented!()
    }
    async fn prune_older_than(&self, _: chrono::DateTime<Utc>) -> AxiamResult<u64> {
        unimplemented!()
    }
}

fn dlq_path() -> PathBuf {
    std::env::temp_dir().join(format!("axiam-request-audit-dlq-{}.jsonl", Uuid::new_v4()))
}

async fn requests(mw: &AuditMiddleware, n: usize) {
    let app = test::init_service(App::new().wrap(mw.clone()).route(
        "/api/thing",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;
    for _ in 0..n {
        let req = test::TestRequest::get().uri("/api/thing").to_request();
        assert!(test::call_service(&app, req).await.status().is_success());
    }
}

async fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    for _ in 0..200 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

fn rows(path: &PathBuf) -> Vec<CreateAuditLogEntry> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).expect("a dead-letter line is a CreateAuditLogEntry"))
        .collect()
}

/// A channel of 2 behind a worker stuck in its first append: of 10 requests at
/// most 3 are queued and at least 7 are refused.
const CAPACITY: usize = 2;
const REQUESTS: usize = 10;

#[actix_web::test]
async fn a_full_channel_counts_the_rows_it_drops() {
    let mw = AuditMiddleware::spawn_configured(
        Datastore::stuck(),
        None,
        DeadLetterWriter::disabled(),
        CAPACITY,
    );
    requests(&mw, REQUESTS).await;

    let s = mw.loss().snapshot();
    assert!(
        s.dropped >= (REQUESTS - CAPACITY - 1) as u64,
        "dropped {}",
        s.dropped
    );
    assert_eq!(s.failed, 0);
    assert!(s.recent_loss);
    assert!(s.last_loss_at.is_some());
}

#[actix_web::test]
async fn a_failed_append_counts_the_row() {
    let mw = AuditMiddleware::spawn_configured(
        Datastore::failing(),
        None,
        DeadLetterWriter::disabled(),
        4096,
    );
    requests(&mw, 3).await;
    let loss = mw.loss();
    wait_until("three failed appends", || loss.snapshot().failed == 3).await;

    let s = loss.snapshot();
    assert_eq!((s.dropped, s.failed), (0, 3));
    assert!(s.recent_loss);
}

#[actix_web::test]
async fn a_dropped_row_lands_in_the_dead_letter_file_in_the_replayable_form() {
    let path = dlq_path();
    // The file already holds a line: the writer appends, it does not truncate.
    std::fs::write(&path, "{\"earlier\":\"line\"}\n").unwrap();
    let mw = AuditMiddleware::spawn_configured(
        Datastore::stuck(),
        None,
        DeadLetterWriter::spawn(&path),
        CAPACITY,
    );
    requests(&mw, REQUESTS).await;
    let loss = mw.loss();
    assert!(loss.dead_letter().flush(Duration::from_secs(10)).await);

    let s = loss.snapshot();
    assert!(s.dropped >= 7);
    assert_eq!(s.dead_lettered, s.dropped, "every dropped row was written");
    assert_eq!(s.not_recoverable, 0);
    assert!(s.dead_letter_configured);

    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.starts_with("{\"earlier\":\"line\"}\n"), "appended");
    let lines: Vec<&str> = text.lines().skip(1).collect();
    assert_eq!(lines.len() as u64, s.dropped);
    for line in lines {
        let row: CreateAuditLogEntry = serde_json::from_str(line).unwrap();
        assert_eq!(row.action, "GET /api/thing");
    }
    let _ = std::fs::remove_file(&path);
}

#[actix_web::test]
async fn a_failed_row_lands_in_the_dead_letter_file() {
    let path = dlq_path();
    let mw = AuditMiddleware::spawn_configured(
        Datastore::failing(),
        None,
        DeadLetterWriter::spawn(&path),
        4096,
    );
    requests(&mw, 3).await;
    let loss = mw.loss();
    wait_until("three failed appends", || loss.snapshot().failed == 3).await;
    assert!(loss.dead_letter().flush(Duration::from_secs(10)).await);

    let written = rows(&path);
    assert_eq!(written.len(), 3);
    assert!(written.iter().all(|r| r.action == "GET /api/thing"));
    assert_eq!(loss.snapshot().dead_lettered, 3);
    let _ = std::fs::remove_file(&path);
}

#[actix_web::test]
async fn drain_waits_for_the_dead_letter_file() {
    let path = dlq_path();
    let mw = AuditMiddleware::spawn_configured(
        Datastore::failing(),
        None,
        DeadLetterWriter::spawn(&path),
        4096,
    );
    requests(&mw, 5).await;
    assert!(mw.drain(Duration::from_secs(10)).await);
    assert_eq!(rows(&path).len(), 5, "a drained stop leaves no row queued");
    let _ = std::fs::remove_file(&path);
}

#[actix_web::test]
async fn nothing_is_written_when_no_file_is_configured() {
    let dir = dlq_path();
    let mw = AuditMiddleware::spawn_configured(
        Datastore::failing(),
        None,
        DeadLetterWriter::disabled(),
        4096,
    );
    requests(&mw, 3).await;
    let loss = mw.loss();
    wait_until("three failed appends", || loss.snapshot().failed == 3).await;

    let s = loss.snapshot();
    assert!(!s.dead_letter_configured);
    assert_eq!((s.dead_lettered, s.not_recoverable), (0, 3));
    assert!(!dir.exists(), "no file is created");
}

#[actix_web::test]
async fn an_unwritable_file_makes_the_rows_unrecoverable() {
    // A directory cannot be opened for append: the writer's open fails.
    let path = std::env::temp_dir();
    let loss = RequestAuditLoss::new(DeadLetterWriter::spawn(&path));
    loss.record_failed(
        CreateAuditLogEntry {
            tenant_id: Uuid::nil(),
            actor_id: Uuid::nil(),
            actor_type: ActorType::System,
            action: "GET /x".into(),
            resource_id: None,
            outcome: AuditOutcome::Failure,
            ip_address: None,
            metadata: None,
        },
        &"datastore down",
    );
    assert!(loss.dead_letter().flush(Duration::from_secs(10)).await);
    let s = loss.snapshot();
    assert_eq!((s.dead_lettered, s.not_recoverable), (0, 1));
}
