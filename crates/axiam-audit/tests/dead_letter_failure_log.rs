//! The failure of an off-thread dead-letter append is logged by the blocking
//! task itself (#690), so a caller cut before the task finished does not take
//! the line with it. The line names the path and the I/O error, nothing of the
//! record.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axiam_audit::dead_letter::{
    DeadLetterReason, DeadLetterRecord, DeadLetterTarget, append_off_thread,
};
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use chrono::Utc;
use uuid::Uuid;

/// In-memory `MakeWriter` the test reads the log back from.
#[derive(Clone)]
struct BufWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for BufWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufWriter {
    type Writer = BufWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn a_failed_append_is_logged_though_its_awaiter_was_dropped() {
    let log_buf = Arc::new(Mutex::new(Vec::new()));
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(BufWriter(log_buf.clone()))
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    );

    let path = std::env::temp_dir()
        .join(format!("axiam-dlq-missing-{}", Uuid::new_v4()))
        .join("dlq.jsonl");
    let pseudonym = format!("DELETED_USER_{}", Uuid::new_v4());
    let record = DeadLetterRecord::new(
        CreateAuditLogEntry {
            tenant_id: Uuid::new_v4(),
            actor_id: Uuid::new_v4(),
            actor_type: ActorType::System,
            action: "gdpr.erasure_requested".into(),
            resource_id: None,
            outcome: AuditOutcome::Failure,
            ip_address: None,
            metadata: Some(serde_json::json!({ "pseudonym": pseudonym })),
        },
        Utc::now(),
        DeadLetterReason::DatastoreError,
    );
    let target = DeadLetterTarget {
        path: path.clone(),
        max_bytes: 1 << 20,
    };

    // One poll spawns the blocking task; dropping the future then leaves it
    // without an awaiter before it can report.
    let mut fut = Box::pin(append_off_thread(target, record));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(fut.as_mut().poll(&mut cx).is_pending());
    drop(fut);

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let logged = loop {
        let out = String::from_utf8(log_buf.lock().unwrap().clone()).unwrap();
        if out.contains("failed to append audit dead-letter file") {
            break out;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the blocking task logged nothing: {out:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert!(
        logged.contains(&path.display().to_string()),
        "path: {logged}"
    );
    assert!(
        !logged.contains(&pseudonym) && !logged.contains("gdpr.erasure_requested"),
        "nothing of the record: {logged}"
    );
}

/// The awaited case: the caller that is still there gets the I/O error back,
/// and the failure is logged once — by the blocking task, not again by the
/// caller (#690).
#[tokio::test]
async fn an_awaited_failed_append_returns_the_error_and_is_logged_once() {
    let log_buf = Arc::new(Mutex::new(Vec::new()));
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(BufWriter(log_buf.clone()))
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    );

    let path = std::env::temp_dir()
        .join(format!("axiam-dlq-missing-{}", Uuid::new_v4()))
        .join("dlq.jsonl");
    let record = DeadLetterRecord::new(
        CreateAuditLogEntry {
            tenant_id: Uuid::new_v4(),
            actor_id: Uuid::new_v4(),
            actor_type: ActorType::System,
            action: "gdpr.erasure_requested".into(),
            resource_id: None,
            outcome: AuditOutcome::Failure,
            ip_address: None,
            metadata: None,
        },
        Utc::now(),
        DeadLetterReason::DatastoreError,
    );
    let target = DeadLetterTarget {
        path: path.clone(),
        max_bytes: 1 << 20,
    };

    let err = append_off_thread(target, record)
        .await
        .expect_err("the directory does not exist");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);

    let out = String::from_utf8(log_buf.lock().unwrap().clone()).unwrap();
    assert_eq!(
        out.matches("failed to append audit dead-letter file")
            .count(),
        1,
        "{out}"
    );
    assert!(out.contains(&path.display().to_string()), "path: {out}");
}

/// A subscriber that records the events of the thread it was installed on and
/// panics on an event from any other, so the blocking task that logs the I/O
/// failure panics.
struct PanicOffThread {
    owner: std::thread::ThreadId,
    events: Arc<Mutex<Vec<String>>>,
}

impl tracing::Subscriber for PanicOffThread {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Message(String);
        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }
        assert_eq!(
            std::thread::current().id(),
            self.owner,
            "the blocking task's log call panics by design"
        );
        let mut message = Message(String::new());
        event.record(&mut message);
        self.events.lock().unwrap().push(message.0);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// The other failure: the write task panics, so the closure never returned and
/// nothing logged there. The awaiter that is still there reports it, and gets
/// an I/O error naming the task (#690).
#[tokio::test]
async fn a_write_task_that_panics_is_reported_by_the_awaiter() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let _guard = tracing::subscriber::set_default(PanicOffThread {
        owner: std::thread::current().id(),
        events: events.clone(),
    });

    let path = std::env::temp_dir()
        .join(format!("axiam-dlq-missing-{}", Uuid::new_v4()))
        .join("dlq.jsonl");
    let record = DeadLetterRecord::new(
        CreateAuditLogEntry {
            tenant_id: Uuid::new_v4(),
            actor_id: Uuid::new_v4(),
            actor_type: ActorType::System,
            action: "gdpr.erasure_requested".into(),
            resource_id: None,
            outcome: AuditOutcome::Failure,
            ip_address: None,
            metadata: None,
        },
        Utc::now(),
        DeadLetterReason::DatastoreError,
    );
    let target = DeadLetterTarget {
        path,
        max_bytes: 1 << 20,
    };

    let err = append_off_thread(target, record)
        .await
        .expect_err("the write task panicked");
    assert_eq!(err.kind(), std::io::ErrorKind::Other);
    assert!(
        err.to_string().starts_with("dead-letter write task failed"),
        "{err}"
    );
    assert_eq!(
        *events.lock().unwrap(),
        ["gdpr: failed to append audit dead-letter file"],
        "the awaiter logged the failure the task could not"
    );
}
