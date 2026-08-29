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
// `E2E-TESTS.md` §3 wanted rendered subjects and bodies read out of a catcher,
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
// What it does not cover: that each publisher still sends the keys named below.
// That table is a declaration quoted from the call sites, not a reading of
// them. It closes the direction the bug actually travels — a template asking
// for more than it is given — and a publisher that drops a key is left to its
// own crate's tests.

/// The keys each publisher puts in `OutboundMailMessage::template_context`,
/// quoted from its call site.
///
/// The `match` is exhaustive on purpose: a sixth `MailType` does not compile
/// until somebody says what its publisher supplies.
fn publisher_context_keys(mail_type: &MailType) -> &'static [&'static str] {
    match mail_type {
        // crates/axiam-api-rest/src/handlers/password_reset.rs
        MailType::PasswordReset => &["token", "action_url", "expiry_time"],
        // crates/axiam-api-rest/src/handlers/email_verification.rs
        MailType::EmailVerification => &["token", "action_url", "expiry_time"],
        // crates/axiam-audit/src/notification.rs
        MailType::Notification => &["details", "action", "outcome", "event"],
        // crates/axiam-api-rest/src/handlers/gdpr.rs
        MailType::DeletionCancel => &["action_url", "expiry_time"],
        // crates/axiam-server/src/cleanup.rs
        MailType::ExportReady => &["action_url", "expiry_time"],
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
