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
