//! Broker-free tests for `send_with_retry_and_audit` — the core mail
//! delivery/retry/audit logic factored out of the AMQP consumer loop so it can
//! be exercised without a live RabbitMQ broker or SMTP server.
//!
//! Delivery failures are produced by pointing an SMTP `EmailConfig` at a
//! loopback port that refuses connections, so `EmailService::send` fails fast
//! and the retry/exhaustion branches run deterministically.

use std::sync::Mutex;

use axiam_amqp::mail_consumer::{MAX_RETRIES, SendOutcome, send_with_retry_and_audit};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::audit::{AuditLogEntry, CreateAuditLogEntry};
use axiam_core::models::email::{
    EmailConfig, EmailConfigOverride, ProviderConfig, SetOrgEmailConfig, SmtpConfig,
};
use axiam_core::models::email_template::{EmailTemplate, SetEmailTemplate, TemplateKind};
use axiam_core::models::mail::{MailType, OutboundMailMessage};
use axiam_core::models::settings::SettingsScope;
use axiam_core::models::user::{CreateUser, UpdateUser, User, UserStatus};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, EmailConfigRepository, EmailTemplateRepository,
    PaginatedResult, Pagination, UserRepository,
};
use chrono::Utc;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// EmailConfigRepository mock
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct MockEmailConfigRepo {
    effective: Option<EmailConfig>,
}

fn smtp_unreachable_config() -> EmailConfig {
    EmailConfig {
        id: Uuid::new_v4(),
        scope: SettingsScope::Org,
        scope_id: Uuid::new_v4(),
        enabled: true,
        from_name: "AXIAM".into(),
        from_email: "noreply@example.com".into(),
        reply_to: None,
        provider: ProviderConfig::Smtp(SmtpConfig {
            host: "127.0.0.1".into(),
            port: 1, // refuses connection -> fast send failure
            username: "u".into(),
            password: "p".into(),
            starttls: false,
        }),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

impl EmailConfigRepository for MockEmailConfigRepo {
    async fn get_org_config(&self, _o: Uuid) -> AxiamResult<Option<EmailConfig>> {
        unimplemented!()
    }
    async fn set_org_config(&self, _o: Uuid, _i: SetOrgEmailConfig) -> AxiamResult<EmailConfig> {
        unimplemented!()
    }
    async fn delete_org_config(&self, _o: Uuid) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn get_tenant_override(&self, _t: Uuid) -> AxiamResult<Option<EmailConfigOverride>> {
        unimplemented!()
    }
    async fn set_tenant_override(
        &self,
        _t: Uuid,
        _i: EmailConfigOverride,
    ) -> AxiamResult<EmailConfigOverride> {
        unimplemented!()
    }
    async fn delete_tenant_override(&self, _t: Uuid) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn get_effective_config(&self, _o: Uuid, _t: Uuid) -> AxiamResult<Option<EmailConfig>> {
        Ok(self.effective.clone())
    }
}

// ---------------------------------------------------------------------------
// EmailTemplateRepository mock
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct MockTemplateRepo {
    /// When true, the org/tenant template fetches return a DB error so the
    /// fail-safe fallback-to-built-in path (D-06) is exercised.
    fail_fetch: bool,
}

impl EmailTemplateRepository for MockTemplateRepo {
    async fn get_org_template(
        &self,
        _o: Uuid,
        _k: TemplateKind,
    ) -> AxiamResult<Option<EmailTemplate>> {
        if self.fail_fetch {
            Err(AxiamError::Database("boom".into()))
        } else {
            Ok(None)
        }
    }
    async fn set_org_template(&self, _o: Uuid, _i: SetEmailTemplate) -> AxiamResult<EmailTemplate> {
        unimplemented!()
    }
    async fn delete_org_template(&self, _o: Uuid, _k: TemplateKind) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn list_org_templates(&self, _o: Uuid) -> AxiamResult<Vec<EmailTemplate>> {
        unimplemented!()
    }
    async fn get_tenant_template(
        &self,
        _t: Uuid,
        _k: TemplateKind,
    ) -> AxiamResult<Option<EmailTemplate>> {
        if self.fail_fetch {
            Err(AxiamError::Database("boom".into()))
        } else {
            Ok(None)
        }
    }
    async fn set_tenant_template(
        &self,
        _t: Uuid,
        _i: SetEmailTemplate,
    ) -> AxiamResult<EmailTemplate> {
        unimplemented!()
    }
    async fn delete_tenant_template(&self, _t: Uuid, _k: TemplateKind) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn list_tenant_templates(&self, _t: Uuid) -> AxiamResult<Vec<EmailTemplate>> {
        unimplemented!()
    }
}

// ---------------------------------------------------------------------------
// UserRepository mock
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct MockUserRepo {
    found: bool,
}

impl UserRepository for MockUserRepo {
    async fn create(&self, _i: CreateUser) -> AxiamResult<User> {
        unimplemented!()
    }
    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<User> {
        if !self.found {
            return Err(AxiamError::NotFound {
                entity: "user".into(),
                id: id.to_string(),
            });
        }
        Ok(User {
            id,
            tenant_id,
            username: "bob".into(),
            email: "resolved@example.com".into(),
            password_hash: "x".into(),
            status: UserStatus::Active,
            mfa_enabled: false,
            mfa_secret: None,
            totp_last_used_step: None,
            failed_login_attempts: 0,
            last_failed_login_at: None,
            locked_until: None,
            email_verified_at: None,
            deletion_pending: false,
            scheduled_purge_at: None,
            metadata: serde_json::Value::Null,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
    }
    async fn get_by_username(&self, _t: Uuid, _u: &str) -> AxiamResult<User> {
        unimplemented!()
    }
    async fn get_by_email(&self, _t: Uuid, _e: &str) -> AxiamResult<User> {
        unimplemented!()
    }
    async fn update(&self, _t: Uuid, _i: Uuid, _u: UpdateUser) -> AxiamResult<User> {
        unimplemented!()
    }
    async fn delete(&self, _t: Uuid, _i: Uuid) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn update_totp_step(&self, _t: Uuid, _i: Uuid, _s: u64) -> AxiamResult<bool> {
        unimplemented!()
    }
    async fn list(&self, _t: Uuid, _p: Pagination) -> AxiamResult<PaginatedResult<User>> {
        unimplemented!()
    }
    async fn increment_failed_logins(
        &self,
        _t: Uuid,
        _u: Uuid,
        _lt: u32,
        _b: i64,
        _bm: f64,
        _m: i64,
    ) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn anonymize_user(&self, _t: Uuid, _u: Uuid, _e: &str, _p: &str) -> AxiamResult<()> {
        unimplemented!()
    }
}

// ---------------------------------------------------------------------------
// AuditLogRepository mock
// ---------------------------------------------------------------------------

struct MockAuditRepo {
    appended: Mutex<Vec<CreateAuditLogEntry>>,
}

impl MockAuditRepo {
    fn new() -> Self {
        Self {
            appended: Mutex::new(Vec::new()),
        }
    }
}

impl AuditLogRepository for MockAuditRepo {
    async fn append(&self, input: CreateAuditLogEntry) -> AxiamResult<AuditLogEntry> {
        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            tenant_id: input.tenant_id,
            actor_id: input.actor_id,
            actor_type: input.actor_type.clone(),
            action: input.action.clone(),
            resource_id: input.resource_id,
            outcome: input.outcome.clone(),
            ip_address: input.ip_address.clone(),
            metadata: input.metadata.clone().unwrap_or(serde_json::Value::Null),
            timestamp: Utc::now(),
        };
        self.appended.lock().unwrap().push(input);
        Ok(entry)
    }
    async fn list(
        &self,
        _t: Uuid,
        _f: AuditLogFilter,
        _p: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        unimplemented!()
    }
    async fn list_system(
        &self,
        _f: AuditLogFilter,
        _p: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        unimplemented!()
    }
    async fn get_by_ids(&self, _t: Uuid, _ids: &[Uuid]) -> AxiamResult<Vec<AuditLogEntry>> {
        unimplemented!()
    }
    async fn pseudonymize_actor(&self, _t: Uuid, _u: Uuid, _p: &str) -> AxiamResult<u64> {
        unimplemented!()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn msg(attempt_count: u32) -> OutboundMailMessage {
    OutboundMailMessage {
        mail_type: MailType::PasswordReset,
        tenant_id: Uuid::new_v4(),
        org_id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        to_address: "advisory@example.com".into(),
        template_context: serde_json::json!({"reset_link": "https://x/y", "count": 3}),
        attempt_count,
        enqueued_at: Utc::now(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_email_config_returns_send_error() {
    let cfg = MockEmailConfigRepo { effective: None };
    let audit = MockAuditRepo::new();
    let err = send_with_retry_and_audit(
        &msg(0),
        &cfg,
        &audit,
        &MockUserRepo { found: true },
        &MockTemplateRepo { fail_fetch: false },
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("no email config"));
}

#[tokio::test]
async fn disabled_email_config_returns_send_error() {
    let mut ec = smtp_unreachable_config();
    ec.enabled = false;
    let cfg = MockEmailConfigRepo {
        effective: Some(ec),
    };
    let audit = MockAuditRepo::new();
    let err = send_with_retry_and_audit(
        &msg(0),
        &cfg,
        &audit,
        &MockUserRepo { found: true },
        &MockTemplateRepo { fail_fetch: false },
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("disabled"));
}

#[tokio::test]
async fn transient_failure_with_retries_remaining_signals_retry() {
    let cfg = MockEmailConfigRepo {
        effective: Some(smtp_unreachable_config()),
    };
    let audit = MockAuditRepo::new();
    // attempt_count 0 -> 0+1 < MAX_RETRIES(3) so RetryNeeded.
    let outcome = send_with_retry_and_audit(
        &msg(0),
        &cfg,
        &audit,
        &MockUserRepo { found: true },
        &MockTemplateRepo { fail_fetch: false },
    )
    .await
    .unwrap();
    match outcome {
        SendOutcome::RetryNeeded { error_class } => {
            assert!(!error_class.is_empty());
        }
        other => panic!("expected RetryNeeded, got {other:?}"),
    }
    // No audit written on a retryable failure.
    assert!(audit.appended.lock().unwrap().is_empty());
}

#[tokio::test]
async fn exhausted_retries_writes_pii_minimal_audit() {
    let cfg = MockEmailConfigRepo {
        effective: Some(smtp_unreachable_config()),
    };
    let audit = MockAuditRepo::new();
    // attempt_count MAX_RETRIES-1 -> +1 == MAX_RETRIES so Exhausted.
    let outcome = send_with_retry_and_audit(
        &msg(MAX_RETRIES - 1),
        &cfg,
        &audit,
        &MockUserRepo { found: true },
        &MockTemplateRepo { fail_fetch: false },
    )
    .await
    .unwrap();
    assert!(matches!(outcome, SendOutcome::Exhausted));

    let entries = audit.appended.lock().unwrap();
    assert_eq!(entries.len(), 1);
    let e = &entries[0];
    assert_eq!(e.action, "email.delivery_failed");
    // D-16: audit metadata must never contain the recipient address.
    let meta = e.metadata.as_ref().unwrap().to_string();
    assert!(!meta.contains("resolved@example.com"));
    assert!(!meta.contains("advisory@example.com"));
    assert!(meta.contains("error_class"));
}

#[tokio::test]
async fn template_fetch_failure_falls_back_and_still_processes() {
    // D-06: even when both template fetches error, the send path proceeds
    // using the built-in template (here it still fails at SMTP → RetryNeeded).
    let cfg = MockEmailConfigRepo {
        effective: Some(smtp_unreachable_config()),
    };
    let audit = MockAuditRepo::new();
    let outcome = send_with_retry_and_audit(
        &msg(0),
        &cfg,
        &audit,
        &MockUserRepo { found: true },
        &MockTemplateRepo { fail_fetch: true },
    )
    .await
    .unwrap();
    assert!(matches!(outcome, SendOutcome::RetryNeeded { .. }));
}

#[tokio::test]
async fn user_lookup_failure_falls_back_to_advisory_address() {
    // SEC-055 fallback branch: user repo returns NotFound → to_address used.
    let cfg = MockEmailConfigRepo {
        effective: Some(smtp_unreachable_config()),
    };
    let audit = MockAuditRepo::new();
    let outcome = send_with_retry_and_audit(
        &msg(0),
        &cfg,
        &audit,
        &MockUserRepo { found: false },
        &MockTemplateRepo { fail_fetch: false },
    )
    .await
    .unwrap();
    assert!(matches!(outcome, SendOutcome::RetryNeeded { .. }));
}
