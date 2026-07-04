//! Integration test for the GDPR erasure audit dead-letter queue
//! (SECHRD-12 / T19.27, decision D-02).
//!
//! When the erasure audit DB-write fails, the record must be dead-lettered
//! to BOTH an append-only local file AND a structured `tracing` audit event
//! (T-24-61). The dead-letter file must be opened in append mode and must
//! never truncate an existing file (T-24-62).
//!
//! Drives the failure via the injectable `AuditWriteSink` seam
//! (`axiam_api_rest::handlers::gdpr::AuditWriteSink`) — no live/broken
//! database required.

use std::sync::{Arc, Mutex};

use axiam_api_rest::handlers::gdpr::{
    AuditWriteSink, GDPR_AUDIT_DLQ_FILE_ENV, write_erasure_audit_with_dlq,
};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::audit::{ActorType, AuditLogEntry, AuditOutcome, CreateAuditLogEntry};
use uuid::Uuid;

/// Test double that always fails, simulating a transient SurrealDB outage on
/// the erasure audit-write path.
struct FailingAuditSink;

impl AuditWriteSink for FailingAuditSink {
    async fn write(&self, _entry: CreateAuditLogEntry) -> AxiamResult<AuditLogEntry> {
        Err(AxiamError::Database(
            "simulated erasure audit DB outage".into(),
        ))
    }
}

/// In-memory `tracing_subscriber::fmt::MakeWriter` so the test can assert on
/// the structured audit DLQ event without a real log sink.
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

#[test]
fn gdpr_audit_dlq_on_db_failure() {
    let dlq_path = std::env::temp_dir().join(format!(
        "axiam-gdpr-audit-dlq-test-{}-{}.jsonl",
        std::process::id(),
        Uuid::new_v4()
    ));

    // Pre-populate the dead-letter file with a sentinel line to prove the
    // append-only sink never truncates an existing file (T-24-62).
    std::fs::write(&dlq_path, "SENTINEL-EXISTING-LINE\n").expect("seed dead-letter file");

    // SAFETY: this test binary has a single test function that touches this
    // env var, and it runs single-threaded within this process (no other
    // test in this file reads/writes it concurrently). Rust 2024 requires
    // `unsafe` for env mutation because another thread could otherwise be
    // reading env simultaneously (mirrors bootstrap_test.rs's convention).
    unsafe {
        std::env::set_var(GDPR_AUDIT_DLQ_FILE_ENV, &dlq_path);
    }

    let tenant_id = Uuid::new_v4();
    let entry = CreateAuditLogEntry {
        tenant_id,
        actor_id: Uuid::nil(),
        actor_type: ActorType::System,
        action: "gdpr.user_pseudonymized".into(),
        resource_id: None,
        outcome: AuditOutcome::Success,
        ip_address: None,
        metadata: Some(serde_json::json!({ "pseudonym": "DELETED_USER_test0123456789" })),
    };

    let log_buf = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(BufWriter(log_buf.clone()))
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        tokio_test::block_on(write_erasure_audit_with_dlq(&FailingAuditSink, entry));
    });

    // SAFETY: see above — sole test in this binary touching this env var.
    unsafe {
        std::env::remove_var(GDPR_AUDIT_DLQ_FILE_ENV);
    }

    // --- Sink 1: append-only dead-letter file --------------------------
    let contents = std::fs::read_to_string(&dlq_path).expect("read dead-letter file");
    let lines: Vec<&str> = contents.lines().collect();
    let _ = std::fs::remove_file(&dlq_path);

    assert_eq!(
        lines.len(),
        2,
        "expected the pre-existing sentinel line plus exactly one dead-lettered \
         record (proves append-only, no truncate), got: {contents:?}"
    );
    assert_eq!(
        lines[0], "SENTINEL-EXISTING-LINE",
        "existing dead-letter file content must survive — file must be opened append-only, \
         never truncated (T-24-62)"
    );
    assert!(
        lines[1].contains(&tenant_id.to_string()) && lines[1].contains("gdpr.user_pseudonymized"),
        "dead-lettered line missing expected erasure-audit fields: {}",
        lines[1]
    );

    // --- Sink 2: structured tracing audit DLQ event ---------------------
    let log_output = String::from_utf8(log_buf.lock().unwrap().clone()).expect("utf8 log output");
    assert!(
        log_output.contains("axiam.audit.dlq"),
        "expected a structured tracing audit event on target axiam.audit.dlq, got: {log_output}"
    );
    assert!(
        log_output.contains(&tenant_id.to_string()),
        "structured audit DLQ event missing tenant_id, got: {log_output}"
    );
    assert!(
        log_output.contains("gdpr_audit_dlq"),
        "structured audit DLQ event missing expected message, got: {log_output}"
    );
}
