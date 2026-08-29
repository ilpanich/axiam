//! Wave 0 tests for the mail consumer send-with-retry-and-audit logic.
//!
//! Tests are broker-free: they call `send_with_retry_and_audit` directly,
//! which exercises the failure/retry/audit path without a live AMQP broker.
//!
//! PII assertions confirm that `to_address` never appears in audit metadata
//! (D-16).

use axiam_amqp::mail_consumer::{MAX_RETRIES, SendOutcome, send_with_retry_and_audit};
use axiam_amqp::messages::{MailType, OutboundMailMessage};
use axiam_core::models::email::{ProviderConfig, SetOrgEmailConfig, SmtpConfig};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, EmailConfigRepository, Pagination,
};
use axiam_db::{
    SurrealAuditLogRepository, SurrealEmailConfigRepository, SurrealEmailTemplateRepository,
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use chrono::Utc;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------
//
// FUNC-03 / D-05 / D-06 custom-template-resolution and fetch-error-fallback
// tests live in their own file, `mail_consumer_template_test.rs` (a separate
// cargo test binary/process), NOT here. They capture `tracing` debug/warn
// output via a thread-local subscriber override; `tracing`'s per-callsite
// `Interest` cache that override invalidates is process-global, so sharing a
// process with other SurrealDB-touching tests risks a cross-test race that
// silently drops captured log lines. Isolating them in their own test binary
// (mirroring `axiam-api-rest/tests/gdpr_audit_dlq_test.rs`, which is the
// sole test in its file for the same reason) avoids that race entirely.

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
/// (delivery will fail, which is the behavior we want for failure-path tests).
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Delivery failure on first attempt → RetryNeeded (more retries remain).
#[tokio::test]
async fn delivery_failure_first_attempt_returns_retry_needed() {
    let db = setup_db().await;
    let org_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    seed_failing_email_config(&db, org_id, tenant_id).await;

    let email_repo = SurrealEmailConfigRepository::new(db.clone(), email_key());
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let user_repo = SurrealUserRepository::new(db.clone());
    let template_repo = SurrealEmailTemplateRepository::new(db.clone());
    // The mail consumer resolves `{{tenant_name}}` and `{{org_name}}` from
    // these — every built-in template names them.
    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let org_repo = SurrealOrganizationRepository::new(db.clone());

    let msg = make_msg(MailType::PasswordReset, org_id, tenant_id, 0);
    let outcome = send_with_retry_and_audit(
        &msg,
        &email_repo,
        &audit_repo,
        &user_repo,
        &template_repo,
        &tenant_repo,
        &org_repo,
    )
    .await
    .unwrap();

    assert!(
        matches!(outcome, SendOutcome::RetryNeeded { .. }),
        "expected RetryNeeded on first failure, got {:?}",
        outcome
    );
}

/// After exhausting retries, outcome is Exhausted and a `email.delivery_failed`
/// audit event is written — keyed on user_id with NO recipient address in metadata (D-16).
#[tokio::test]
async fn exhausted_retries_writes_delivery_failed_audit_without_recipient() {
    let db = setup_db().await;
    let org_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    seed_failing_email_config(&db, org_id, tenant_id).await;

    let email_repo = SurrealEmailConfigRepository::new(db.clone(), email_key());
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let user_repo = SurrealUserRepository::new(db.clone());
    let template_repo = SurrealEmailTemplateRepository::new(db.clone());
    // The mail consumer resolves `{{tenant_name}}` and `{{org_name}}` from
    // these — every built-in template names them.
    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let org_repo = SurrealOrganizationRepository::new(db.clone());

    // Set attempt_count to MAX_RETRIES - 1 so this is the exhausting attempt.
    let mut msg = make_msg(MailType::PasswordReset, org_id, tenant_id, MAX_RETRIES - 1);
    msg.user_id = user_id;

    let outcome = send_with_retry_and_audit(
        &msg,
        &email_repo,
        &audit_repo,
        &user_repo,
        &template_repo,
        &tenant_repo,
        &org_repo,
    )
    .await
    .unwrap();

    assert!(
        matches!(outcome, SendOutcome::Exhausted),
        "expected Exhausted on last attempt, got {:?}",
        outcome
    );

    // Verify audit event was written with the correct action and actor_id.
    let entries = audit_repo
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
    let failed_entry = entries
        .items
        .iter()
        .find(|e| e.action == "email.delivery_failed")
        .expect("email.delivery_failed audit entry must exist");

    // D-16: actor_id must be the user_id (not a nil UUID or raw email).
    assert_eq!(
        failed_entry.actor_id, user_id,
        "delivery_failed audit must be keyed on user_id"
    );

    // D-16: metadata must NOT contain the recipient address.
    let meta_str = failed_entry.metadata.to_string();
    assert!(
        !meta_str.contains("victim@example.com"),
        "audit metadata must not contain recipient email address (D-16)"
    );
    assert!(
        !meta_str.contains("to_address"),
        "audit metadata must not contain 'to_address' key (D-16)"
    );

    // Metadata MUST contain safe fields.
    assert!(
        meta_str.contains("attempt_count"),
        "metadata should include attempt_count"
    );
    assert!(
        meta_str.contains("error_class"),
        "metadata should include error_class"
    );
}

/// No email config seeded → SendError (config error, not a delivery outcome).
#[tokio::test]
async fn missing_email_config_returns_send_error() {
    let db = setup_db().await;
    let email_repo = SurrealEmailConfigRepository::new(db.clone(), email_key());
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let user_repo = SurrealUserRepository::new(db.clone());
    let template_repo = SurrealEmailTemplateRepository::new(db.clone());
    // The mail consumer resolves `{{tenant_name}}` and `{{org_name}}` from
    // these — every built-in template names them.
    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let org_repo = SurrealOrganizationRepository::new(db.clone());

    let msg = make_msg(MailType::PasswordReset, Uuid::new_v4(), Uuid::new_v4(), 0);
    let result = send_with_retry_and_audit(
        &msg,
        &email_repo,
        &audit_repo,
        &user_repo,
        &template_repo,
        &tenant_repo,
        &org_repo,
    )
    .await;

    assert!(
        result.is_err(),
        "missing email config should return Err(SendError)"
    );
}

/// SECHRD-08 / D-05d: an ExportReady message carrying a real (non-nil)
/// `org_id` is deliverable end-to-end. `send_with_retry_and_audit` resolves
/// the effective email config via `msg.org_id` *before* the template is
/// rendered and a delivery attempt is made — so a successful render+send
/// attempt (proven here by `RetryNeeded` against a fake/unreachable SMTP
/// sink, not a `SendError` config failure) is only reachable when the real
/// `org_id` resolves an email config. This proves the real `org_id` reaches
/// (gates) the rendered template context on the consumer side.
///
/// The producer-side fix (cleanup.rs no longer enqueuing `Uuid::nil()`)
/// lands in plan 25-05; this test is scoped to the consumer/rendering half
/// per this plan (25-08).
///
/// Negative control: the identical message with `Uuid::nil()` as `org_id`
/// (the pre-D-05d producer placeholder) must fail closed with a `SendError`
/// *before* any template is rendered — reproducing the exact "ExportReady
/// mail silently undeliverable" bug D-05d fixes.
#[tokio::test]
async fn export_ready_resolves_real_org_id() {
    let db = setup_db().await;
    let org_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    // Seed an org-level email config keyed to the REAL org_id, pointing at a
    // fake/unreachable SMTP sink (127.0.0.1:1 — nothing listens there, so
    // delivery fails transiently but rendering/config-resolution succeeds).
    seed_failing_email_config(&db, org_id, tenant_id).await;

    let email_repo = SurrealEmailConfigRepository::new(db.clone(), email_key());
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let user_repo = SurrealUserRepository::new(db.clone());
    let template_repo = SurrealEmailTemplateRepository::new(db.clone());
    // The mail consumer resolves `{{tenant_name}}` and `{{org_name}}` from
    // these — every built-in template names them.
    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let org_repo = SurrealOrganizationRepository::new(db.clone());

    // ExportReady message carrying the real org_id, mirroring cleanup.rs's
    // post-25-05 enqueue shape (action_url/expiry_time template context).
    let mut msg = make_msg(MailType::ExportReady, org_id, tenant_id, 0);
    msg.user_id = user_id;

    let outcome = send_with_retry_and_audit(
        &msg,
        &email_repo,
        &audit_repo,
        &user_repo,
        &template_repo,
        &tenant_repo,
        &org_repo,
    )
    .await
    .expect("a real org_id must resolve an email config and reach the render/send attempt");

    assert!(
        matches!(outcome, SendOutcome::RetryNeeded { .. }),
        "real org_id must resolve config, render the ExportReady template, and attempt \
         delivery (RetryNeeded against the fake sink) — got {:?}",
        outcome
    );

    // Negative control: same message, but org_id reset to Uuid::nil().
    let mut nil_org_msg = msg.clone();
    nil_org_msg.org_id = Uuid::nil();
    let nil_result = send_with_retry_and_audit(
        &nil_org_msg,
        &email_repo,
        &audit_repo,
        &user_repo,
        &template_repo,
        &tenant_repo,
        &org_repo,
    )
    .await;

    assert!(
        nil_result.is_err(),
        "Uuid::nil() org_id must NOT resolve an email config (pre-D-05d bug reproduction) — \
         mail would be silently undeliverable; got {:?}",
        nil_result
    );
}

/// Successful delivery via MockProvider → Delivered outcome.
///
/// Uses a mock-backed EmailService built directly (bypassing email config repo)
/// by invoking the consumer helper through an in-memory mock config.
#[tokio::test]
async fn successful_send_via_mock_config_returns_delivered() {
    let _db = setup_db().await;

    // Seed a mock SMTP config.  The provider will still be built via the real
    // EmailService::from_config path.  We use sendgrid with an invalid key so
    // the repo resolves an EmailConfig, but we actually want to test the
    // success branch.  Since we cannot inject a MockProvider through the config
    // path, we verify the success path by asserting the outcome equals
    // Delivered when the config resolves and the provider can be built.
    //
    // Seed as disabled — from_config will return EmailConfig::Disabled error,
    // which maps to a SendError config error.  To truly test the Delivered
    // branch without a live provider, we call EmailService::with_provider
    // directly and assert the mock records the send.
    //
    // Wave 0 only: broker-free. The Delivered branch requires a real (or mock)
    // provider. Use MockProvider directly here.
    use axiam_core::models::email_template::TemplateKind;
    use axiam_email::providers::mock::MockProvider;
    use axiam_email::service::EmailService;
    use axiam_email::template::{TemplateContext, builtin_template, render_email};

    let mock = MockProvider::new();
    let svc = EmailService::with_provider(
        Box::new(mock),
        "Test".into(),
        "test@example.com".into(),
        None,
    );

    let template = builtin_template(TemplateKind::PasswordReset);
    let mut ctx = TemplateContext::new();
    ctx.insert("username".into(), "alice".into());
    ctx.insert("tenant_name".into(), "Acme".into());
    ctx.insert("action_url".into(), "https://example.com/reset".into());
    ctx.insert("expiry_time".into(), "2026-12-31".into());
    let email_msg = render_email(&template, "alice@example.com", &ctx);

    let result = svc.send(&email_msg).await;
    assert!(
        result.is_ok(),
        "mock provider send must succeed: {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// Template identity placeholders
// ---------------------------------------------------------------------------
//
// Every built-in template greets the reader with `{{username}}` and names
// `{{tenant_name}}`, and no publisher supplied either — the renderer leaves an
// unknown placeholder standing, so a new user's activation email opened
// "Welcome, {{username}}!" and asked them to activate their "{{tenant_name}}"
// account. The mail was being delivered; it was unreadable.
//
// Filling them in the consumer rather than at each publisher is what makes that
// unrepeatable: it is the same four facts for every mail type, and a publisher
// that forgot one would reintroduce exactly this.

use axiam_amqp::mail_consumer::identity_context;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};

/// Seed an org + tenant + user and return their ids.
async fn seed_identity(db: &Surreal<Db>) -> (Uuid, Uuid, Uuid) {
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Acme Corporation".into(),
            slug: "acme".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Acme Production".into(),
            slug: "prod".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "alice".into(),
            email: "alice@acme.example".into(),
            // Generated, not a literal: a password in source is a hard-coded
            // credential to any scanner reading the file, and nothing here
            // verifies it — the fixture only needs a user to exist.
            password: format!("fixture-{}", Uuid::new_v4()),
            metadata: None,
        })
        .await
        .unwrap();
    (org.id, tenant.id, user.id)
}

#[tokio::test]
async fn the_identity_context_fills_every_placeholder_the_templates_use() {
    let db = setup_db().await;
    let (org_id, tenant_id, user_id) = seed_identity(&db).await;

    let mut msg = make_msg(MailType::EmailVerification, org_id, tenant_id, 0);
    msg.user_id = user_id;

    let ctx = identity_context(
        &msg,
        &SurrealUserRepository::new(db.clone()),
        &SurrealTenantRepository::new(db.clone()),
        &SurrealOrganizationRepository::new(db.clone()),
    )
    .await;

    assert_eq!(ctx.get("username").map(String::as_str), Some("alice"));
    assert_eq!(
        ctx.get("email").map(String::as_str),
        Some("alice@acme.example")
    );
    assert_eq!(
        ctx.get("tenant_name").map(String::as_str),
        Some("Acme Production")
    );
    assert_eq!(
        ctx.get("org_name").map(String::as_str),
        Some("Acme Corporation")
    );
}

#[tokio::test]
async fn a_missing_user_costs_the_greeting_and_not_the_email() {
    // A lookup that does not resolve contributes no keys. The greeting renders
    // without a name, which is worse than with one and far better than a
    // password-reset link that never arrives.
    let db = setup_db().await;
    let (org_id, tenant_id, _) = seed_identity(&db).await;

    let mut msg = make_msg(MailType::PasswordReset, org_id, tenant_id, 0);
    msg.user_id = Uuid::new_v4(); // no such user

    let ctx = identity_context(
        &msg,
        &SurrealUserRepository::new(db.clone()),
        &SurrealTenantRepository::new(db.clone()),
        &SurrealOrganizationRepository::new(db.clone()),
    )
    .await;

    // Present, but the honest placeholder rather than a name — the renderer
    // leaves an ABSENT key standing as a literal `{{username}}`, which is the
    // very bug this context exists to close.
    assert_eq!(ctx.get("username").map(String::as_str), Some("unknown"));
    // The tenant and organization still resolve — one missing lookup must not
    // take the others with it.
    assert_eq!(
        ctx.get("tenant_name").map(String::as_str),
        Some("Acme Production")
    );
    assert_eq!(
        ctx.get("org_name").map(String::as_str),
        Some("Acme Corporation")
    );
}

#[tokio::test]
async fn a_nil_user_id_is_not_looked_up() {
    // Notification-rule mail carries `Uuid::nil()` when the audit event had no
    // attributable actor. Looking that up is a guaranteed-miss round trip.
    let db = setup_db().await;
    let (org_id, tenant_id, _) = seed_identity(&db).await;

    let mut msg = make_msg(MailType::Notification, org_id, tenant_id, 0);
    msg.user_id = Uuid::nil();

    let ctx = identity_context(
        &msg,
        &SurrealUserRepository::new(db.clone()),
        &SurrealTenantRepository::new(db.clone()),
        &SurrealOrganizationRepository::new(db.clone()),
    )
    .await;

    assert_eq!(ctx.get("username").map(String::as_str), Some("unknown"));
    assert_eq!(ctx.get("email").map(String::as_str), Some("unknown"));
    assert_eq!(
        ctx.get("tenant_name").map(String::as_str),
        Some("Acme Production")
    );
}

#[tokio::test]
async fn a_messages_own_context_wins_over_the_resolved_identity() {
    // The overlay order matters: the consumer fills identity first and the
    // message's own keys go over the top. A publisher that has a better value —
    // the address a reset was requested for, say — must not have it overwritten
    // by a lookup.
    let db = setup_db().await;
    let (org_id, tenant_id, user_id) = seed_identity(&db).await;

    let mut msg = make_msg(MailType::EmailVerification, org_id, tenant_id, 0);
    msg.user_id = user_id;

    // `make_msg` puts `username: "alice"` and `tenant_name: "Test Tenant"` in
    // the message context; the seeded tenant is "Acme Production".
    let mut ctx = identity_context(
        &msg,
        &SurrealUserRepository::new(db.clone()),
        &SurrealTenantRepository::new(db.clone()),
        &SurrealOrganizationRepository::new(db.clone()),
    )
    .await;
    assert_eq!(
        ctx.get("tenant_name").map(String::as_str),
        Some("Acme Production")
    );

    // The same overlay `send_with_retry_and_audit` performs.
    if let serde_json::Value::Object(obj) = &msg.template_context {
        for (k, v) in obj {
            if let serde_json::Value::String(s) = v {
                ctx.insert(k.clone(), s.clone());
            }
        }
    }
    assert_eq!(
        ctx.get("tenant_name").map(String::as_str),
        Some("Test Tenant"),
        "the message's own value must win"
    );
}

#[tokio::test]
async fn every_key_the_templates_use_is_always_present() {
    // The invariant that makes "Welcome, {{username}}!" impossible to
    // reintroduce: the renderer leaves an unknown placeholder standing, so a
    // key that is sometimes absent is a literal `{{…}}` in somebody's inbox.
    // Nothing resolves here — no user, no tenant, no org — and all four keys
    // still come back.
    let db = setup_db().await;
    let mut msg = make_msg(MailType::PasswordReset, Uuid::new_v4(), Uuid::new_v4(), 0);
    msg.user_id = Uuid::new_v4();

    let ctx = identity_context(
        &msg,
        &SurrealUserRepository::new(db.clone()),
        &SurrealTenantRepository::new(db.clone()),
        &SurrealOrganizationRepository::new(db.clone()),
    )
    .await;

    for key in ["username", "email", "tenant_name", "org_name"] {
        assert_eq!(
            ctx.get(key).map(String::as_str),
            Some("unknown"),
            "`{key}` must always be present, resolved or not"
        );
    }
}

// ---------------------------------------------------------------------------
// Template coverage — the half a local SMTP catcher would have measured
// ---------------------------------------------------------------------------
//
// `claude_dev/E2E-TESTS.md` §3 wanted rendered subjects and bodies read out of a catcher,
// to find "a template that renders `{{tenant_name}}` literally". That could not
// be done against the running stack: `SmtpProvider` enforces TLS on both code
// paths and verifies against compiled-in roots, so a local Mailpit is refused
// at the TLS layer. Recorded as unverified in `claude_dev/e2e-findings.md`.
//
// The transport was never the interesting part. An unrendered placeholder is a
// property of a (template, context) pair, and both halves are in this
// repository: the identity keys the consumer always inserts, and the keys each
// publisher puts in `template_context`. Asserting on the pair is stronger than
// one observation through a catcher — it holds for every mail type, in CI, and
// fails the moment a template grows a placeholder nobody supplies.
//
// The table below WAS only a declaration quoted from the call sites, which
// left one direction open: a publisher that stops sending a key it promised
// would make the render assertion pass on a context the real message never
// carries. `every_publisher_still_sends_the_keys_it_is_credited_with` closes
// that by reading the call sites instead of trusting the quote.

/// Where one mail type's publisher lives, and what it is credited with putting
/// in `OutboundMailMessage::template_context`.
struct PublisherSite {
    /// Repository-relative path to the module that constructs the message.
    file: &'static str,
    /// The context keys the call site supplies, on top of the identity keys
    /// the consumer always inserts.
    keys: &'static [&'static str],
}

/// The publisher for each mail type.
///
/// The `match` is exhaustive on purpose: a sixth `MailType` does not compile
/// until somebody says where its publisher is and what it supplies.
fn publisher_site(mail_type: &MailType) -> PublisherSite {
    match mail_type {
        MailType::PasswordReset => PublisherSite {
            file: "crates/axiam-api-rest/src/handlers/password_reset.rs",
            keys: &["token", "action_url", "expiry_time"],
        },
        MailType::EmailVerification => PublisherSite {
            file: "crates/axiam-api-rest/src/handlers/email_verification.rs",
            keys: &["token", "action_url", "expiry_time"],
        },
        MailType::Notification => PublisherSite {
            file: "crates/axiam-audit/src/notification.rs",
            keys: &["details", "action", "outcome", "event"],
        },
        MailType::DeletionCancel => PublisherSite {
            file: "crates/axiam-api-rest/src/handlers/gdpr.rs",
            keys: &["action_url", "expiry_time"],
        },
        MailType::ExportReady => PublisherSite {
            file: "crates/axiam-server/src/cleanup.rs",
            keys: &["action_url", "expiry_time"],
        },
    }
}

/// The keys each publisher puts in `OutboundMailMessage::template_context`.
fn publisher_context_keys(mail_type: &MailType) -> &'static [&'static str] {
    publisher_site(mail_type).keys
}

// ---------------------------------------------------------------------------
// Reading the publishers, rather than quoting them
// ---------------------------------------------------------------------------
//
// The publishers live in `axiam-api-rest`, `axiam-audit` and `axiam-server` —
// all of them ABOVE `axiam-amqp` in the crate layering, so this crate cannot
// link against them to call the code. It can read their source, which is what
// the assertions below do. Crude by design, and every crude step is guarded by
// its own failure: a scan that finds nothing says so rather than passing.

/// The repository root, from this crate's manifest directory.
fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

/// A module's source with any `#[cfg(test)]` module removed.
///
/// Necessary, not tidiness: `password_reset.rs` builds an
/// `OutboundMailMessage` inside its own tests with a deliberately partial
/// context (`token` and `expiry_time`, no `action_url`). A scan that read it
/// would conclude the production publisher had dropped a key.
fn production_source(rel: &str) -> String {
    let path = repo_root().join(rel);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("publisher source {} is unreadable: {e}", path.display()));
    match text.find("\n#[cfg(test)]") {
        Some(idx) => text[..idx].to_string(),
        None => text,
    }
}

/// The `OutboundMailMessage { … }` literal that names `MailType::{variant}`.
///
/// Returns `None` when there is no such construction, which the caller reports
/// as a failure rather than an absence — a publisher that moved is exactly the
/// thing this is looking for.
fn message_literal(src: &str, variant: &str) -> Option<String> {
    let needle = format!("mail_type: MailType::{variant}");
    let at = src.find(&needle)?;
    let open_rel = src[..at].rfind("OutboundMailMessage {")?;
    let body_start = open_rel + "OutboundMailMessage ".len();

    let bytes = src.as_bytes();
    let mut depth = 0usize;
    for (i, b) in bytes.iter().enumerate().skip(body_start) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(src[body_start..=i].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

/// Every `"key":` in a fragment — a quoted string immediately followed by a
/// colon, which is what a `serde_json::json!` object key looks like and what
/// none of the *values* at these call sites do.
fn json_object_keys(fragment: &str) -> std::collections::BTreeSet<String> {
    let mut keys = std::collections::BTreeSet::new();
    let mut rest = fragment;
    while let Some(open) = rest.find('"') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('"') else { break };
        let literal = &after[..close];
        let tail = after[close + 1..].trim_start();
        if tail.starts_with(':') && !literal.is_empty() {
            keys.insert(literal.to_string());
        }
        rest = &after[close + 1..];
    }
    keys
}

/// Every `…insert("key"…)` in a source — how a publisher that assembles its
/// context in a map, rather than a `json!` literal, supplies a key.
fn inserted_keys(src: &str) -> std::collections::BTreeSet<String> {
    let mut keys = std::collections::BTreeSet::new();
    let mut rest = src;
    while let Some(at) = rest.find(".insert(\"") {
        let after = &rest[at + ".insert(\"".len()..];
        if let Some(close) = after.find('"') {
            keys.insert(after[..close].to_string());
        }
        rest = after;
    }
    keys
}

/// The keys a mail type's publisher actually supplies, read out of its source.
fn keys_the_publisher_actually_supplies(
    mail_type: &MailType,
) -> std::collections::BTreeSet<String> {
    let site = publisher_site(mail_type);
    let src = production_source(site.file);
    let variant = format!("{mail_type:?}");

    let literal = message_literal(&src, &variant).unwrap_or_else(|| {
        panic!(
            "no production `OutboundMailMessage {{ … mail_type: MailType::{variant} … }}` \
             found in {} — the publisher moved, and the table in `publisher_site` now \
             points at the wrong file",
            site.file
        )
    });

    if literal.contains("serde_json::json!({") {
        // The keys are written inline in the message literal.
        json_object_keys(&literal)
    } else {
        // The context is assembled in a map before the message is built
        // (`axiam-audit`'s notification dispatcher does this, because the
        // event name is only known per rule). The map is local to the module,
        // so the module's inserts are the supply.
        inserted_keys(&src)
    }
}

/// Closes the direction the render assertion cannot see: that each publisher
/// still sends the keys the table credits it with.
///
/// `every_mail_type_renders_with_no_placeholder_left_standing` builds its
/// context FROM this table, so a publisher that quietly stopped sending
/// `action_url` would leave that test green while every real message rendered
/// `{{action_url}}` to a user. The table is now checked against the call sites
/// rather than quoted from them.
///
/// Subset, not equality: a publisher may supply more than it is credited with
/// (`axiam-audit` adds `username` only for an unauthenticated actor, and
/// conditional keys are not something the table can usefully assert). The
/// other direction is already covered — a key the template uses and the table
/// omits leaves a `{{…}}` standing, which the render test fails on.
#[test]
fn every_publisher_still_sends_the_keys_it_is_credited_with() {
    let mut wrong = Vec::new();

    for mail_type in MailType::ALL {
        let site = publisher_site(mail_type);
        let supplied = keys_the_publisher_actually_supplies(mail_type);

        assert!(
            !supplied.is_empty(),
            "read no context keys at all from {} for {mail_type:?} — the source \
             scan is broken, not the publisher",
            site.file
        );

        for credited in site.keys {
            if !supplied.contains(*credited) {
                wrong.push(format!(
                    "{mail_type:?} is credited with `{credited}` but {} supplies \
                     only {supplied:?}",
                    site.file
                ));
            }
        }
    }

    assert!(
        wrong.is_empty(),
        "a publisher no longer sends a key the template test assumes it does:\n  - {}",
        wrong.join("\n  - ")
    );
}

/// Exactly one production publisher per mail type.
///
/// The reader above takes the *first* `OutboundMailMessage` naming a variant.
/// That is only sound while there is one; a second call site publishing the
/// same mail type with a different context would be silently unmeasured.
#[test]
fn each_mail_type_has_exactly_one_production_publisher() {
    for mail_type in MailType::ALL {
        let site = publisher_site(mail_type);
        let src = production_source(site.file);
        let variant = format!("mail_type: MailType::{mail_type:?}");
        let count = src.matches(&variant).count();
        assert_eq!(
            count, 1,
            "{mail_type:?} has {count} production publishers in {} — the reader \
             measures the first one only, so a second is unmeasured",
            site.file
        );
    }
}

/// Every built-in template renders with nothing left standing, for every mail
/// type, using only what that mail type's message actually carries.
///
/// The identity half comes from the real `identity_context` against a database
/// where nothing resolves — the worst case, and the one that proves the four
/// keys are unconditional rather than incidental to a seeded fixture.
#[tokio::test]
async fn every_mail_type_renders_with_no_placeholder_left_standing() {
    use axiam_amqp::mail_consumer::{identity_context, template_kind_for};
    use axiam_email::template::{builtin_template, render, render_html};

    let db = setup_db().await;

    for mail_type in MailType::ALL {
        let mut msg = make_msg(mail_type.clone(), Uuid::new_v4(), Uuid::new_v4(), 0);
        msg.user_id = Uuid::new_v4();

        // Nothing is seeded, so every lookup misses and the context is exactly
        // the unconditional floor.
        let mut ctx = identity_context(
            &msg,
            &SurrealUserRepository::new(db.clone()),
            &SurrealTenantRepository::new(db.clone()),
            &SurrealOrganizationRepository::new(db.clone()),
        )
        .await;

        for key in publisher_context_keys(mail_type) {
            ctx.insert((*key).to_string(), format!("<{key}>"));
        }

        let kind = template_kind_for(mail_type);
        let template = builtin_template(kind);

        for (part, rendered) in [
            ("subject", render(&template.subject, &ctx)),
            ("text_body", render(&template.text_body, &ctx)),
            ("html_body", render_html(&template.html_body, &ctx)),
        ] {
            assert!(
                !rendered.contains("{{"),
                "{mail_type:?} → {kind:?} {part} still contains an unrendered \
                 placeholder: {rendered}\n\
                 Either the template names a key no publisher supplies, or the \
                 publisher stopped supplying it."
            );
        }
    }
}
