//! T-108: request-audit rows that are lost are counted, reported, and — when a
//! dead-letter file is configured — written to it in the replayable form.
//!
//! "Lost" is two things: the worker's channel was full when the request ended
//! (`dropped`), or the datastore refused the append (`failed`). The datastore is
//! a test double, no SurrealDB.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use actix_web::{App, HttpResponse, test, web};
use axiam_audit::middleware::AuditMiddleware;
use axiam_audit::{AuditEvent, AuditEventSink, DeadLetterWriter, RequestAuditLoss};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::audit::{ActorType, AuditLogEntry, AuditOutcome, CreateAuditLogEntry};
use axiam_core::repository::{AuditLogFilter, AuditLogRepository, PaginatedResult, Pagination};
use chrono::Utc;
use uuid::Uuid;

/// A datastore that refuses every append, or takes `delay` over each one, and
/// counts the rows it took.
#[derive(Clone)]
struct Datastore {
    fail: bool,
    delay: Duration,
    appended: Arc<AtomicUsize>,
}

impl Datastore {
    fn failing() -> Self {
        Self {
            fail: true,
            delay: Duration::ZERO,
            appended: Arc::default(),
        }
    }

    /// So slow that the worker is inside its first append for the whole test and
    /// the channel behind it fills.
    fn stuck() -> Self {
        Self {
            fail: false,
            delay: Duration::from_secs(3600),
            appended: Arc::default(),
        }
    }

    /// Takes every row at once.
    fn healthy() -> Self {
        Self {
            fail: false,
            delay: Duration::ZERO,
            appended: Arc::default(),
        }
    }

    fn appended(&self) -> usize {
        self.appended.load(Ordering::SeqCst)
    }
}

impl AuditLogRepository for Datastore {
    async fn append(&self, input: CreateAuditLogEntry) -> AxiamResult<AuditLogEntry> {
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        if self.fail {
            return Err(AxiamError::Internal("datastore down".into()));
        }
        self.appended.fetch_add(1, Ordering::SeqCst);
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

/// A notification step that takes `delay` over every row, as a window claim
/// contended across replicas did on the audit worker (R1W2-01).
#[derive(Clone)]
struct SlowSink {
    delay: Duration,
    seen: Arc<AtomicUsize>,
}

impl AuditEventSink for SlowSink {
    fn on_event<'a>(
        &'a self,
        _event: &'a AuditEvent,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            tokio::time::sleep(self.delay).await;
            self.seen.fetch_add(1, Ordering::SeqCst);
        })
    }
}

/// R1W2-01: a burst twelve times the audit queue, through a notification step
/// that takes 50 ms per row, drops no audit row. The notification step runs on
/// its own task behind its own queue; it is the notifications that overflow,
/// and each is counted. (With the step on the audit worker, as before, the
/// worker took 50 ms per row and the audit queue dropped most of the burst.)
#[actix_web::test]
async fn a_slow_notification_step_drops_no_audit_row() {
    const CAPACITY: usize = 8;
    const BURST: usize = 100;
    let store = Datastore::healthy();
    let sink = SlowSink {
        delay: Duration::from_millis(50),
        seen: Arc::default(),
    };
    let mw = AuditMiddleware::spawn_configured(
        store.clone(),
        Some(Arc::new(sink.clone())),
        DeadLetterWriter::disabled(),
        CAPACITY,
    );
    let app = test::init_service(App::new().wrap(mw.clone()).route(
        "/api/thing",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;
    for _ in 0..BURST {
        let req = test::TestRequest::get().uri("/api/thing").to_request();
        assert!(test::call_service(&app, req).await.status().is_success());
        // A request's turn ends here; the workers get theirs.
        tokio::task::yield_now().await;
    }

    wait_until("every row appended", || store.appended() == BURST).await;
    let s = mw.loss().snapshot();
    assert_eq!((s.dropped, s.failed), (0, 0), "no audit row was lost");
    assert!(!s.recent_loss);

    // Every row was either notified or its notification counted as dropped.
    let dropped = mw.notifications_dropped();
    assert!(dropped > 0, "the burst overflowed the notification queue");
    wait_until("the notification queue to drain", || {
        sink.seen.load(Ordering::SeqCst) + dropped as usize == BURST
    })
    .await;
}

// ---------------------------------------------------------------------------
// R1W2-02 — the dead-letter file's budget and its lines' bounds
// ---------------------------------------------------------------------------

/// A budget small enough to cross in a test: request rows may fill nine
/// tenths of it, the GDPR records the rest.
const BUDGET: u64 = 4096;

fn request_row(action: &str) -> CreateAuditLogEntry {
    CreateAuditLogEntry {
        tenant_id: Uuid::nil(),
        actor_id: Uuid::nil(),
        actor_type: ActorType::System,
        action: action.into(),
        resource_id: None,
        outcome: AuditOutcome::Failure,
        ip_address: Some("203.0.113.7".into()),
        metadata: Some(serde_json::json!({"http_status": 500, "authenticated": false})),
    }
}

fn file_len(path: &PathBuf) -> u64 {
    std::fs::metadata(path).map_or(0, |m| m.len())
}

/// Request rows that would take the file past the request rows' share of its
/// budget are refused, counted as not recoverable, and the file reports full —
/// from then on without even queueing them.
#[tokio::test]
async fn past_the_budget_request_rows_are_refused_and_counted() {
    let path = dlq_path();
    let writer = DeadLetterWriter::spawn_with_budget(&path, BUDGET);
    let loss = RequestAuditLoss::new(writer.clone());
    for _ in 0..40 {
        loss.record_failed(request_row("GET /api/thing"), &"datastore down");
    }
    assert!(writer.flush(Duration::from_secs(10)).await);

    let limit = axiam_audit::dead_letter::request_row_limit(BUDGET);
    assert!(file_len(&path) <= limit, "{} > {limit}", file_len(&path));
    let s = loss.snapshot();
    assert!(s.dead_lettered > 0 && s.not_recoverable > 0, "{s:?}");
    assert_eq!(s.dead_lettered + s.not_recoverable, 40);
    assert_eq!(writer.refused_full(), s.not_recoverable);
    assert!(s.dead_letter_full && writer.is_full());
    assert_eq!(rows(&path).len() as u64, s.dead_lettered);

    // Once full, a row is refused at submission.
    assert_eq!(
        writer.submit(request_row("GET /api/thing")),
        axiam_audit::dead_letter::Submitted::Full
    );
    assert_eq!(writer.refused_full(), s.not_recoverable + 1);
    let _ = std::fs::remove_file(&path);
}

/// The last tenth of the budget is the GDPR records' own: a record still fits
/// after request rows filled their share, and the whole budget is the hard cap.
#[tokio::test]
async fn a_gdpr_record_still_fits_in_the_reserve() {
    use axiam_audit::dead_letter::append_blocking;

    let path = dlq_path();
    let writer = DeadLetterWriter::spawn_with_budget(&path, BUDGET);
    while writer.refused_full() == 0 {
        writer.submit(request_row("GET /api/thing"));
        assert!(writer.flush(Duration::from_secs(10)).await);
    }
    assert!(writer.is_full());

    let mut erasure = request_row("gdpr.erasure_requested");
    erasure.ip_address = None;
    append_blocking(&path, &erasure, BUDGET).expect("the reserve takes a GDPR record");
    assert_eq!(rows(&path).last().unwrap().action, "gdpr.erasure_requested");

    // Past the whole budget even a GDPR record is refused, and says why.
    let refused = loop {
        if let Err(e) = append_blocking(&path, &erasure, BUDGET) {
            break e;
        }
    };
    assert_eq!(refused.kind(), std::io::ErrorKind::StorageFull);
    assert!(file_len(&path) <= BUDGET);
    let _ = std::fs::remove_file(&path);
}

/// A 20 KiB path and a 2 KiB forwarded address make a bounded row — in the
/// datastore's row and in the dead-letter line alike.
#[actix_web::test]
async fn a_long_path_and_address_are_truncated_in_the_line() {
    use axiam_audit::dead_letter::{MAX_ACTION_BYTES, MAX_ADDRESS_BYTES};

    let path = dlq_path();
    let mw = AuditMiddleware::spawn_configured(
        Datastore::failing(),
        None,
        DeadLetterWriter::spawn(&path),
        4096,
    );
    let app = test::init_service(
        App::new()
            .wrap(mw.clone())
            .default_service(web::to(|| async { HttpResponse::NotFound().finish() })),
    )
    .await;
    let long_path = format!("/{}", "a".repeat(20 * 1024));
    let long_address = "9".repeat(2 * 1024);
    let req = test::TestRequest::get()
        .uri(&long_path)
        .insert_header(("X-Forwarded-For", long_address.as_str()))
        .to_request();
    test::call_service(&app, req).await;
    let loss = mw.loss();
    wait_until("the failed append", || loss.snapshot().failed == 1).await;
    assert!(loss.dead_letter().flush(Duration::from_secs(10)).await);

    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.len() < 1024, "a {} byte line", text.len());
    let row: CreateAuditLogEntry = serde_json::from_str(text.trim_end()).unwrap();
    assert!(row.action.len() <= MAX_ACTION_BYTES);
    assert!(row.action.starts_with("GET /aaaa") && row.action.ends_with("...[truncated]"));
    let ip = row.ip_address.expect("the forwarded address is kept, cut");
    assert!(ip.len() <= MAX_ADDRESS_BYTES && ip.ends_with("...[truncated]"));
    let _ = std::fs::remove_file(&path);
}
