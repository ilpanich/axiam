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
use axiam_audit::dead_letter::{
    DeadLetterLine, DeadLetterReason, DeadLetterRecord, decode_line, encode_line,
};
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

    /// Refuses every append, after `delay`.
    fn failing_after(delay: Duration) -> Self {
        Self {
            fail: true,
            delay,
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

/// The file's lines, each read by the decoder — which takes the envelope and
/// the bare entry earlier versions wrote alike.
fn lines_of(path: &PathBuf) -> Vec<DeadLetterLine> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| decode_line(l).expect("a dead-letter line is a dead-letter record"))
        .collect()
}

fn rows(path: &PathBuf) -> Vec<CreateAuditLogEntry> {
    lines_of(path).into_iter().map(|l| l.entry).collect()
}

/// A record of `request_row(action)` that happened now, for the file's writers.
fn record(action: &str) -> DeadLetterRecord {
    DeadLetterRecord::new(
        request_row(action),
        Utc::now(),
        DeadLetterReason::DatastoreError,
    )
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

/// #596: `try_record` is the request rows' queue for code that is not a request.
/// A row it queues is appended by the worker; one it is refused is counted as
/// dropped and written to the dead-letter file as `channel_full`, and the call
/// never waits on the datastore (the worker here is stuck for an hour).
#[actix_web::test]
async fn try_record_queues_without_waiting_and_a_full_channel_is_a_counted_loss() {
    let path = dlq_path();
    let store = Datastore::stuck();
    let mw = AuditMiddleware::spawn_configured(
        store.clone(),
        None,
        DeadLetterWriter::spawn(&path),
        CAPACITY,
    );
    let started = std::time::Instant::now();
    let queued: Vec<bool> = (0..REQUESTS)
        .map(|i| mw.try_record(request_row(&format!("outbound {i}"))))
        .collect();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "try_record never waits on the datastore"
    );
    // The worker holds one, the channel holds CAPACITY; the rest are refused.
    assert!(queued.iter().filter(|q| **q).count() <= CAPACITY + 1);
    assert!(queued[0], "the first row finds room");
    assert!(!queued[REQUESTS - 1], "the last finds none");
    assert_eq!(
        store.appended(),
        0,
        "no append completed on the caller's path"
    );

    let loss = mw.loss();
    assert!(loss.dead_letter().flush(Duration::from_secs(10)).await);
    let s = loss.snapshot();
    let refused = queued.iter().filter(|q| !**q).count() as u64;
    assert_eq!(s.dropped, refused);
    assert_eq!(s.dead_lettered, refused);
    let lines = lines_of(&path);
    assert_eq!(lines.len() as u64, refused);
    assert!(
        lines
            .iter()
            .all(|l| l.reason.as_deref() == Some("channel_full")
                && l.entry.action.starts_with("outbound "))
    );
    let _ = std::fs::remove_file(&path);
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
    let before = Utc::now();
    // The file already holds a line, a bare one as earlier versions wrote it: the
    // writer appends, it does not truncate, and the decoder reads both forms.
    let bare = serde_json::to_string(&request_row("GET /earlier")).unwrap();
    std::fs::write(&path, format!("{bare}\n")).unwrap();
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
    assert!(text.starts_with(&format!("{bare}\n")), "appended");
    let lines: Vec<DeadLetterLine> = lines_of(&path).into_iter().skip(1).collect();
    assert_eq!(lines.len() as u64, s.dropped);
    for line in lines {
        assert_eq!(line.entry.action, "GET /api/thing");
        let at = line.occurred_at.expect("a new line carries its time");
        assert!(at >= before && at <= Utc::now(), "{at} outside the test");
        let reason = line.reason.as_deref().unwrap();
        assert!(
            reason == "channel_full" || reason == "channel_closed",
            "{reason}"
        );
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

    let written = lines_of(&path);
    assert_eq!(written.len(), 3);
    assert!(written.iter().all(|l| l.entry.action == "GET /api/thing"));
    assert!(
        written
            .iter()
            .all(|l| l.reason.as_deref() == Some("datastore_error") && l.occurred_at.is_some())
    );
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
        Utc::now(),
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
        loss.record_failed(request_row("GET /api/thing"), Utc::now(), &"datastore down");
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
        writer.submit(record("GET /api/thing")),
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
        writer.submit(record("GET /api/thing"));
        assert!(writer.flush(Duration::from_secs(10)).await);
    }
    assert!(writer.is_full());

    let mut erasure = record("gdpr.erasure_requested");
    erasure.entry.ip_address = None;
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
    let row = decode_line(text.trim_end()).unwrap().entry;
    assert!(row.action.len() <= MAX_ACTION_BYTES);
    assert!(row.action.starts_with("GET /aaaa") && row.action.ends_with("...[truncated]"));
    let ip = row.ip_address.expect("the forwarded address is kept, cut");
    assert!(ip.len() <= MAX_ADDRESS_BYTES && ip.ends_with("...[truncated]"));
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// The file's mode and its writes (#594)
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn mode_of(path: &PathBuf) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// A file the process creates is owner-only whatever the umask is, by either
/// opener: the GDPR records' (`append_blocking`, and the off-thread form a
/// handler awaits) and the request-audit writer's task.
#[cfg(unix)]
#[tokio::test]
async fn a_created_dead_letter_file_is_owner_only() {
    use axiam_audit::dead_letter::{DeadLetterTarget, append_blocking, append_off_thread};

    // Under the usual 022 umask the process's own default would be 0644, the
    // mode the issue describes; the openers set 0600 whatever it is.
    let blocking = dlq_path();
    append_blocking(&blocking, &record("gdpr.erasure_requested"), BUDGET).unwrap();
    assert_eq!(mode_of(&blocking), 0o600, "append_blocking");

    let off_thread = dlq_path();
    append_off_thread(
        DeadLetterTarget {
            path: off_thread.clone(),
            max_bytes: BUDGET,
        },
        record("gdpr.data_export_requested"),
    )
    .await
    .unwrap();
    assert_eq!(mode_of(&off_thread), 0o600, "append_off_thread");
    assert_eq!(rows(&off_thread).len(), 1);

    let writer_file = dlq_path();
    let writer = DeadLetterWriter::spawn_with_budget(&writer_file, BUDGET);
    writer.submit(record("GET /api/thing"));
    assert!(writer.flush(Duration::from_secs(10)).await);
    assert_eq!(mode_of(&writer_file), 0o600, "the writer task");
    assert_eq!(rows(&writer_file).len(), 1);

    for p in [blocking, off_thread, writer_file] {
        let _ = std::fs::remove_file(&p);
    }
}

/// `mode(0o600)` applies only at creation, so a file an earlier run made
/// readable by group and others is restricted when either opener meets it —
/// and its existing lines are kept.
#[cfg(unix)]
#[tokio::test]
async fn an_existing_world_readable_file_is_restricted_when_opened() {
    use axiam_audit::dead_letter::append_blocking;
    use std::os::unix::fs::PermissionsExt as _;

    let open_wide = |path: &PathBuf| {
        std::fs::write(path, "").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(mode_of(path), 0o644);
    };

    let blocking = dlq_path();
    open_wide(&blocking);
    append_blocking(&blocking, &record("gdpr.erasure_requested"), BUDGET).unwrap();
    assert_eq!(mode_of(&blocking), 0o600, "append_blocking");
    assert_eq!(rows(&blocking).len(), 1);

    let writer_file = dlq_path();
    open_wide(&writer_file);
    let writer = DeadLetterWriter::spawn_with_budget(&writer_file, BUDGET);
    writer.submit(record("GET /api/thing"));
    assert!(writer.flush(Duration::from_secs(10)).await);
    assert_eq!(mode_of(&writer_file), 0o600, "the writer task");
    assert_eq!(rows(&writer_file).len(), 1);

    for p in [blocking, writer_file] {
        let _ = std::fs::remove_file(&p);
    }
}

/// Each record is one line: GDPR appends and the writer task's batches, run
/// at once against one file, never leave two records on a line or a line
/// without its newline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writers_never_share_a_line() {
    use axiam_audit::dead_letter::{DeadLetterTarget, append_off_thread};

    let path = dlq_path();
    let writer = DeadLetterWriter::spawn_with_budget(&path, 64 * 1024 * 1024);
    let target = DeadLetterTarget {
        path: path.clone(),
        max_bytes: 64 * 1024 * 1024,
    };
    let gdpr = tokio::spawn({
        let target = target.clone();
        async move {
            for _ in 0..200 {
                append_off_thread(target.clone(), record("gdpr.erasure_requested"))
                    .await
                    .unwrap();
            }
        }
    });
    for _ in 0..400 {
        writer.submit(record("GET /api/thing"));
        tokio::task::yield_now().await;
    }
    gdpr.await.unwrap();
    assert!(writer.flush(Duration::from_secs(30)).await);

    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.ends_with('\n'));
    let lines: Vec<&str> = text.lines().collect();
    let parsed = rows(&path);
    assert_eq!(
        lines.len(),
        parsed.len(),
        "every line is exactly one record"
    );
    assert_eq!(
        parsed
            .iter()
            .filter(|r| r.action == "gdpr.erasure_requested")
            .count(),
        200
    );
    assert_eq!(lines.len() as u64, 200 + writer.written());
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// The envelope: when, and why (#595)
// ---------------------------------------------------------------------------

/// A failed row's `occurred_at` is when the request finished, not when the
/// worker gave up on the append: the datastore here takes 400 ms to refuse it.
#[actix_web::test]
async fn a_failed_rows_time_is_the_requests_not_the_flushs() {
    let path = dlq_path();
    let delay = Duration::from_millis(400);
    let mw = AuditMiddleware::spawn_configured(
        Datastore::failing_after(delay),
        None,
        DeadLetterWriter::spawn(&path),
        4096,
    );
    let before = Utc::now();
    requests(&mw, 1).await;
    let after_request = Utc::now();
    let loss = mw.loss();
    wait_until("the failed append", || loss.snapshot().failed == 1).await;
    assert!(loss.dead_letter().flush(Duration::from_secs(10)).await);
    let after_flush = Utc::now();

    let lines = lines_of(&path);
    assert_eq!(lines.len(), 1);
    let at = lines[0].occurred_at.expect("a time");
    assert!(before <= at && at <= after_request, "{at} is the request's");
    assert!(
        after_flush - at >= chrono::Duration::from_std(delay).unwrap(),
        "the line was written at least {delay:?} after the event it dates"
    );
    assert_eq!(lines[0].reason.as_deref(), Some("datastore_error"));
    let _ = std::fs::remove_file(&path);
}

/// Each reason is a short fixed name, and the line carries nothing of the
/// error that caused it.
#[actix_web::test]
async fn the_reason_is_a_short_name_and_never_the_errors_text() {
    let path = dlq_path();
    let loss = RequestAuditLoss::new(DeadLetterWriter::spawn(&path));
    let secret = "password=hunter2 at 10.0.0.5: connection refused".repeat(100);
    loss.record_failed(request_row("GET /a"), Utc::now(), &secret);
    loss.record_dropped(
        request_row("GET /b"),
        Utc::now(),
        DeadLetterReason::ChannelFull,
    );
    loss.record_dropped(
        request_row("GET /c"),
        Utc::now(),
        DeadLetterReason::ChannelClosed,
    );
    assert!(loss.dead_letter().flush(Duration::from_secs(10)).await);

    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("hunter2") && !text.contains("refused"));
    let reasons: Vec<_> = lines_of(&path)
        .into_iter()
        .map(|l| l.reason.unwrap())
        .collect();
    assert_eq!(
        reasons,
        ["datastore_error", "channel_full", "channel_closed"]
    );
    let _ = std::fs::remove_file(&path);
}

/// The wire shape operators' tooling reads, and the bare form it replaces.
#[tokio::test]
async fn a_line_is_the_envelope_and_the_decoder_reads_the_bare_form_too() {
    let at: chrono::DateTime<Utc> = "2026-10-13T08:30:00.123Z".parse().unwrap();
    let line = encode_line(&DeadLetterRecord::new(
        request_row("GET /x"),
        at,
        DeadLetterReason::ChannelFull,
    ))
    .unwrap();
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["occurred_at"], "2026-10-13T08:30:00.123Z");
    assert_eq!(v["reason"], "channel_full");
    assert_eq!(v["entry"]["action"], "GET /x");
    assert_eq!(v.as_object().unwrap().len(), 3);

    let decoded = decode_line(&line).unwrap();
    assert_eq!(decoded.occurred_at, Some(at));
    assert_eq!(decoded.reason.as_deref(), Some("channel_full"));
    assert_eq!(decoded.entry.action, "GET /x");

    // A line an earlier version wrote: the entry alone.
    let bare = serde_json::to_string(&request_row("GET /old")).unwrap();
    let decoded = decode_line(&bare).unwrap();
    assert_eq!(decoded.occurred_at, None);
    assert_eq!(decoded.reason, None);
    assert_eq!(decoded.entry.action, "GET /old");

    assert!(decode_line("{\"earlier\":\"line\"}").is_err());
}

/// The budget counts the line as written, envelope included.
#[tokio::test]
async fn the_budget_counts_the_enveloped_line() {
    use axiam_audit::dead_letter::append_blocking;

    let path = dlq_path();
    let rec = record("gdpr.erasure_requested");
    let line = encode_line(&rec).unwrap();
    let bare = serde_json::to_string(&rec.entry).unwrap();
    assert!(line.len() > bare.len(), "the envelope adds bytes");

    // A budget one byte short of the line (and its newline) refuses it; one
    // that fits takes it, and the file is exactly the line's length.
    let tight = line.len() as u64;
    let refused = append_blocking(&path, &rec, tight).unwrap_err();
    assert_eq!(refused.kind(), std::io::ErrorKind::StorageFull);
    assert_eq!(file_len(&path), 0);
    append_blocking(&path, &rec, tight + 1).unwrap();
    assert_eq!(file_len(&path), tight + 1);
    let _ = std::fs::remove_file(&path);
}
