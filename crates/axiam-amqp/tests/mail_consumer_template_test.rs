//! FUNC-03 / D-05 / D-06: custom-template resolution + fetch-error fallback.
//!
//! `send_with_retry_and_audit` does not return the rendered `EmailMessage`
//! (it is delivered directly via the resolved `EmailService`/provider), so
//! these tests cannot assert on the message object itself. Instead they
//! capture the `tracing::debug!("email details", subject = ..)` line that
//! `EmailService::send` emits *before* attempting the (always-failing, in
//! this broker-free harness) network send — mirroring the tracing-capture
//! technique already used by `axiam-api-rest/tests/gdpr_audit_dlq_test.rs`.
//!
//! This file is deliberately kept separate from `mail_consumer_test.rs`
//! (its own cargo test binary/process). `tracing::subscriber::set_default`
//! only overrides the *dispatch* on the calling thread, but the per-callsite
//! `Interest` cache it invalidates via `rebuild_interest_cache()` is
//! process-global. Sharing a process with other SurrealDB-touching tests
//! (`mail_consumer_test.rs` has five) risks a cross-test race where a
//! concurrent test's tracing/dispatch transition silently caches these
//! tests' callsites as "never enabled", dropping the captured log lines
//! non-deterministically — confirmed empirically while authoring this file
//! (intermittent failures under cargo test's default parallel runner,
//! consistently passing under `--test-threads=1`). Isolating into a
//! single-purpose binary (mirroring `gdpr_audit_dlq_test.rs`, the sole test
//! in its own file for the same reason) removes the race entirely: the two
//! tests below are additionally serialized against each other end-to-end
//! via `TRACING_CAPTURE_LOCK` (held for the *entire* test body, not just the
//! subscriber-active window) as defense in depth, since both also touch
//! SurrealDB.

use axiam_amqp::mail_consumer::{SendOutcome, send_with_retry_and_audit};
use axiam_amqp::messages::{MailType, OutboundMailMessage};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::email::{ProviderConfig, SetOrgEmailConfig, SmtpConfig};
use axiam_core::models::email_template::{EmailTemplate, SetEmailTemplate, TemplateKind};
use axiam_core::repository::{EmailConfigRepository, EmailTemplateRepository};
use axiam_db::{
    SurrealAuditLogRepository, SurrealEmailConfigRepository, SurrealEmailTemplateRepository,
    SurrealUserRepository,
};
use chrono::Utc;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

/// Serializes the two tests in this file end-to-end (from before `setup_db`
/// through the final log assertion) so their SurrealDB usage and tracing
/// dispatch overrides never interleave. See the module doc comment above.
///
/// Uses `tokio::sync::Mutex` (not `std::sync::Mutex`) because the guard is
/// held across `.await` points for the test's whole body — an async-aware
/// lock is required there (`clippy::await_holding_lock`).
fn tracing_capture_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

// ---------------------------------------------------------------------------
// Test helpers (duplicated from mail_consumer_test.rs — kept file-local so
// this binary has zero dependency on that file's internals).
// ---------------------------------------------------------------------------

async fn setup_db() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn email_key() -> [u8; 32] {
    [0xBCu8; 32]
}

/// Seed a minimal SMTP email config that points to a non-existent server
/// (delivery will fail, which is the behavior we want for these tests).
async fn seed_failing_email_config(db: &Surreal<Db>, org_id: Uuid, _tenant_id: Uuid) {
    let repo = SurrealEmailConfigRepository::new(db.clone(), email_key());
    let input = SetOrgEmailConfig {
        enabled: true,
        from_name: "Test".into(),
        from_email: "test@example.com".into(),
        reply_to: None,
        provider: ProviderConfig::Smtp(SmtpConfig {
            host: "127.0.0.1".into(),
            port: 1, // nothing listening here — delivery will always fail
            username: "user".into(),
            password: "pass".into(),
            starttls: false,
        }),
    };
    repo.set_org_config(org_id, input).await.unwrap();
}

fn make_msg(
    mail_type: MailType,
    org_id: Uuid,
    tenant_id: Uuid,
    attempt: u32,
) -> OutboundMailMessage {
    OutboundMailMessage {
        mail_type,
        tenant_id,
        org_id,
        user_id: Uuid::new_v4(),
        to_address: "victim@example.com".into(),
        template_context: serde_json::json!({
            "username": "alice",
            "tenant_name": "Test Tenant",
            "action_url": "https://example.com/action",
            "expiry_time": "2026-12-31T00:00:00Z",
        }),
        attempt_count: attempt,
        enqueued_at: Utc::now(),
    }
}

/// In-memory `tracing_subscriber::fmt::MakeWriter` so tests can assert on
/// the structured `EmailService::send` debug log without a real log sink.
#[derive(Clone)]
struct BufWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

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

/// `EmailTemplateRepository` test double whose org/tenant fetches always
/// fail — proves D-06's fail-safe-to-built-in behavior on a genuine fetch
/// `Err`, independent of `SurrealEmailTemplateRepository`'s real DB path.
struct FailingTemplateRepo;

impl EmailTemplateRepository for FailingTemplateRepo {
    async fn get_org_template(
        &self,
        _org_id: Uuid,
        _kind: TemplateKind,
    ) -> AxiamResult<Option<EmailTemplate>> {
        Err(AxiamError::Database(
            "simulated org template fetch failure — test double".into(),
        ))
    }

    async fn set_org_template(
        &self,
        _org_id: Uuid,
        _input: SetEmailTemplate,
    ) -> AxiamResult<EmailTemplate> {
        unimplemented!("not exercised by the D-06 fallback test")
    }

    async fn delete_org_template(&self, _org_id: Uuid, _kind: TemplateKind) -> AxiamResult<()> {
        unimplemented!("not exercised by the D-06 fallback test")
    }

    async fn list_org_templates(&self, _org_id: Uuid) -> AxiamResult<Vec<EmailTemplate>> {
        unimplemented!("not exercised by the D-06 fallback test")
    }

    async fn get_tenant_template(
        &self,
        _tenant_id: Uuid,
        _kind: TemplateKind,
    ) -> AxiamResult<Option<EmailTemplate>> {
        Err(AxiamError::Database(
            "simulated tenant template fetch failure — test double".into(),
        ))
    }

    async fn set_tenant_template(
        &self,
        _tenant_id: Uuid,
        _input: SetEmailTemplate,
    ) -> AxiamResult<EmailTemplate> {
        unimplemented!("not exercised by the D-06 fallback test")
    }

    async fn delete_tenant_template(
        &self,
        _tenant_id: Uuid,
        _kind: TemplateKind,
    ) -> AxiamResult<()> {
        unimplemented!("not exercised by the D-06 fallback test")
    }

    async fn list_tenant_templates(&self, _tenant_id: Uuid) -> AxiamResult<Vec<EmailTemplate>> {
        unimplemented!("not exercised by the D-06 fallback test")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// With a seeded tenant custom template, `send_with_retry_and_audit` renders
/// and attempts to deliver an email carrying that custom template's subject
/// (tenant precedence, D-05) — not the built-in default subject.
#[tokio::test]
async fn custom_tenant_template_is_used_when_present() {
    // Held for the whole test body — see the module doc comment.
    let _tracing_serialize = tracing_capture_lock().lock().await;

    let db = setup_db().await;
    let org_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    seed_failing_email_config(&db, org_id, tenant_id).await;

    let email_repo = SurrealEmailConfigRepository::new(db.clone(), email_key());
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let user_repo = SurrealUserRepository::new(db.clone());
    let template_repo = SurrealEmailTemplateRepository::new(db.clone());

    const CUSTOM_MARKER: &str = "CUSTOM-TENANT-SUBJECT-MARKER-9f3a";
    template_repo
        .set_tenant_template(
            tenant_id,
            SetEmailTemplate {
                kind: TemplateKind::PasswordReset,
                subject: CUSTOM_MARKER.into(),
                html_body: "<p>custom html body</p>".into(),
                text_body: "custom text body".into(),
            },
        )
        .await
        .expect("seed tenant custom template");

    let log_buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(BufWriter(log_buf.clone()))
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let msg = make_msg(MailType::PasswordReset, org_id, tenant_id, 0);
    let outcome = send_with_retry_and_audit(
        &msg,
        &email_repo,
        &audit_repo,
        &user_repo,
        &template_repo,
    )
    .await
    .expect("delivery attempt must still proceed (built-in-vs-custom is orthogonal to transport)");

    drop(_guard);

    assert!(
        matches!(outcome, SendOutcome::RetryNeeded { .. }),
        "expected RetryNeeded against the fake SMTP sink, got {:?}",
        outcome
    );

    let log_output = String::from_utf8(log_buf.lock().unwrap().clone()).expect("utf8 log output");
    assert!(
        log_output.contains(CUSTOM_MARKER),
        "EmailService::send's debug log must carry the resolved tenant custom \
         template's subject, proving D-05 tenant-precedence resolution reached \
         the render/send path; log output: {log_output}"
    );
}

/// When both `get_org_template` and `get_tenant_template` return `Err`, the
/// consumer must NOT propagate that as a hard `SendError` — it logs a
/// warning and falls back to the built-in template, still attempting
/// delivery (D-06). SEC-055 recipient re-resolution is unaffected.
#[tokio::test]
async fn template_fetch_error_falls_back_to_builtin_and_still_attempts_delivery() {
    // Held for the whole test body — see the module doc comment.
    let _tracing_serialize = tracing_capture_lock().lock().await;

    let db = setup_db().await;
    let org_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    seed_failing_email_config(&db, org_id, tenant_id).await;

    let email_repo = SurrealEmailConfigRepository::new(db.clone(), email_key());
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let user_repo = SurrealUserRepository::new(db.clone());
    let template_repo = FailingTemplateRepo;

    let log_buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(BufWriter(log_buf.clone()))
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let msg = make_msg(MailType::PasswordReset, org_id, tenant_id, 0);
    let outcome =
        send_with_retry_and_audit(&msg, &email_repo, &audit_repo, &user_repo, &template_repo).await;

    drop(_guard);

    // D-06: a template-fetch Err must never surface as a hard SendError —
    // the mail pipeline still attempts delivery (RetryNeeded against the
    // fake SMTP sink here), it just uses the built-in template instead.
    assert!(
        outcome.is_ok(),
        "a template-fetch Err must fall back to the built-in template and still \
         attempt delivery, not propagate as SendError; got {:?}",
        outcome
    );
    assert!(
        matches!(outcome, Ok(SendOutcome::RetryNeeded { .. })),
        "expected RetryNeeded (delivery still attempted) despite template fetch \
         failure, got {:?}",
        outcome
    );

    let log_output = String::from_utf8(log_buf.lock().unwrap().clone()).expect("utf8 log output");
    assert!(
        log_output.contains("D-06") && log_output.contains("could not fetch"),
        "expected a D-06 fallback warning for both the org and tenant fetch \
         failures; log output: {log_output}"
    );
    let warn_count = log_output.matches("D-06").count();
    assert_eq!(
        warn_count, 2,
        "expected exactly two D-06 fallback warnings (org fetch + tenant fetch), got {warn_count}; log: {log_output}"
    );

    // Built-in fallback content check: the built-in PasswordReset subject
    // ("Reset your password for ...") must appear in the debug log, proving
    // resolve_template fell through to builtin_template(kind), not some
    // stale/garbage template.
    assert!(
        log_output.contains("Reset your password for"),
        "expected the built-in PasswordReset subject in the debug log after \
         fallback; log output: {log_output}"
    );
}
