//! SA-14 (N3): the mail queue's consumer must not turn a message into mail
//! that a publisher, rather than the server's own records, addressed.
//!
//! Broker-free: `send_with_retry_and_audit` is driven directly, against a
//! SendGrid-shaped loopback mock (`wiremock`) reached through the tests-only
//! `allowing_private_http_for_tests` seam, so what the provider was asked to
//! send is observable.

use axiam_amqp::mail_consumer::send_with_retry_and_audit;
use axiam_core::error::AxiamResult;
use axiam_core::models::email::{
    ApiProviderConfig, EmailConfig, EmailConfigOverride, ProviderConfig, SetOrgEmailConfig,
};
use axiam_core::models::mail::{MailType, OutboundMailMessage};
use axiam_core::models::settings::SettingsScope;
use axiam_core::repository::EmailConfigRepository;
use axiam_db::{
    SurrealAuditLogRepository, SurrealEmailTemplateRepository, SurrealOrganizationRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_email::EmailEgress;
use chrono::Utc;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn setup_db() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

/// An email config repository whose effective config is a SendGrid provider
/// pointed at `url`.
#[derive(Clone)]
struct LoopbackSendGrid {
    url: String,
}

impl EmailConfigRepository for LoopbackSendGrid {
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
        Ok(Some(EmailConfig {
            id: Uuid::new_v4(),
            scope: SettingsScope::Org,
            scope_id: Uuid::new_v4(),
            enabled: true,
            from_name: "Tenant Brand".into(),
            from_email: "noreply@example.com".into(),
            reply_to: None,
            provider: ProviderConfig::SendGrid(ApiProviderConfig {
                api_key: "test-key".into(),
                api_url: Some(self.url.clone()),
            }),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }))
    }
}

/// The bodies of every request the mock provider received, as text.
async fn received_bodies(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect()
}

/// SA-14 (N3), report validation test 1. A `PasswordReset` whose `user_id`
/// resolves to no user used to be sent to the message's own `to_address`,
/// carrying the message's own `action_url` — a tenant-branded reset mail to an
/// address and link of the publisher's choosing. The recipient of every type
/// but `Notification` is the user record's address or nobody.
#[tokio::test]
async fn sa14_an_unresolvable_user_is_not_mailed_at_the_messages_address() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(202))
        .mount(&server)
        .await;

    let db = setup_db().await;
    let config = LoopbackSendGrid {
        url: format!("{}/v3/mail/send", server.uri()),
    };
    let msg = OutboundMailMessage {
        mail_type: MailType::PasswordReset,
        tenant_id: Uuid::new_v4(),
        org_id: Uuid::new_v4(),
        user_id: Uuid::nil(),
        to_address: "attacker@example.invalid".into(),
        template_context: serde_json::json!({
            "action_url": "https://example.invalid/x",
            "expiry_time": "2026-12-31T00:00:00Z",
        }),
        attempt_count: 0,
        enqueued_at: Utc::now(),
    };

    let result = send_with_retry_and_audit(
        &msg,
        &EmailEgress::default().allowing_private_http_for_tests(),
        &config,
        &SurrealAuditLogRepository::new(db.clone()),
        &SurrealUserRepository::new(db.clone()),
        &SurrealEmailTemplateRepository::new(db.clone()),
        &SurrealTenantRepository::new(db.clone()),
        &SurrealOrganizationRepository::new(db.clone()),
    )
    .await;

    let bodies = received_bodies(&server).await;
    assert!(
        bodies.is_empty(),
        "nothing may be sent for an unresolvable recipient; the provider received {bodies:?}"
    );
    assert!(
        result.is_err(),
        "an unresolvable recipient is a send error, not a delivery: {result:?}"
    );
}

/// Control: a `Notification` keeps its rule-supplied address (its recipients
/// are not users), so the mock does receive that one.
#[tokio::test]
async fn sa14_a_notification_still_goes_to_its_rule_address() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(202))
        .mount(&server)
        .await;

    let db = setup_db().await;
    let config = LoopbackSendGrid {
        url: format!("{}/v3/mail/send", server.uri()),
    };
    let msg = OutboundMailMessage {
        mail_type: MailType::Notification,
        tenant_id: Uuid::new_v4(),
        org_id: Uuid::new_v4(),
        user_id: Uuid::nil(),
        to_address: "secops@example.com".into(),
        template_context: serde_json::json!({}),
        attempt_count: 0,
        enqueued_at: Utc::now(),
    };
    let result = send_with_retry_and_audit(
        &msg,
        &EmailEgress::default().allowing_private_http_for_tests(),
        &config,
        &SurrealAuditLogRepository::new(db.clone()),
        &SurrealUserRepository::new(db.clone()),
        &SurrealEmailTemplateRepository::new(db.clone()),
        &SurrealTenantRepository::new(db.clone()),
        &SurrealOrganizationRepository::new(db.clone()),
    )
    .await;
    assert!(result.is_ok(), "{result:?}");
    let bodies = received_bodies(&server).await;
    assert_eq!(bodies.len(), 1);
    assert!(bodies[0].contains("secops@example.com"), "{}", bodies[0]);
}

// ---------------------------------------------------------------------------
// The mail queue's signed envelope (SA-14, N3)
// ---------------------------------------------------------------------------

use axiam_amqp::internal_envelope::{InternalQueueGate, InternalSigner, MAIL_PURPOSE};
use axiam_amqp::mail_consumer::open_mail_delivery;
use axiam_amqp::mail_publisher::seal_mail;
use axiam_core::repository::{AuditLogFilter, AuditLogRepository, Pagination};
use axiam_db::SurrealAmqpNonceRepository;

const MASTER: &[u8] = b"sa14-integration-master-key";

fn mail() -> OutboundMailMessage {
    OutboundMailMessage {
        mail_type: MailType::PasswordReset,
        tenant_id: Uuid::new_v4(),
        org_id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        to_address: String::new(),
        template_context: serde_json::json!({"action_url": "https://example.com/r"}),
        attempt_count: 0,
        enqueued_at: Utc::now(),
    }
}

fn gate(db: &Surreal<Db>, require_signature: bool) -> InternalQueueGate {
    InternalQueueGate::new(
        MASTER.to_vec(),
        require_signature,
        chrono::Duration::seconds(300),
        SurrealAmqpNonceRepository::new(db.clone()),
    )
}

/// The rejection rows in the system (nil-tenant) audit log, as reasons.
async fn rejection_reasons(audit: &SurrealAuditLogRepository<Db>) -> Vec<String> {
    audit
        .list(
            Uuid::nil(),
            AuditLogFilter::default(),
            Pagination {
                offset: 0,
                limit: 100,
                search: None,
            },
        )
        .await
        .unwrap()
        .items
        .iter()
        .filter(|e| e.action == "amqp.internal_message_rejected")
        .map(|e| e.metadata["reason"].as_str().unwrap().to_owned())
        .collect()
}

/// What the publisher seals, the consumer admits once — through the durable
/// nonce store, so the same bytes again are a replay.
#[tokio::test]
async fn sa14_a_sealed_mail_message_is_admitted_once() {
    let db = setup_db().await;
    let audit = SurrealAuditLogRepository::new(db.clone());
    let g = gate(&db, true);
    let msg = mail();
    let raw = seal_mail(&InternalSigner::new(MASTER.to_vec()), &msg).unwrap();

    let opened = open_mail_delivery(&raw, &g, &audit, Utc::now()).await;
    assert_eq!(opened.map(|m| m.user_id), Some(msg.user_id));
    assert!(
        open_mail_delivery(&raw, &g, &audit, Utc::now())
            .await
            .is_none()
    );
    assert_eq!(rejection_reasons(&audit).await, ["replay"]);
}

/// The pre-SA-14 shape — a bare `OutboundMailMessage`, which is all a forger
/// with broker write access could produce — is refused and audited.
#[tokio::test]
async fn sa14_an_unsigned_mail_message_is_refused_and_audited() {
    let db = setup_db().await;
    let audit = SurrealAuditLogRepository::new(db.clone());
    let raw = serde_json::to_vec(&mail()).unwrap();

    assert!(
        open_mail_delivery(&raw, &gate(&db, true), &audit, Utc::now())
            .await
            .is_none()
    );
    assert_eq!(rejection_reasons(&audit).await, ["unsigned"]);

    // During a rolling upgrade (`require_signature = false`) it is admitted.
    assert!(
        open_mail_delivery(&raw, &gate(&db, false), &audit, Utc::now())
            .await
            .is_some()
    );
}

/// A message signed with a key other than the server-only one (here: another
/// master) is refused, as is a stale one.
#[tokio::test]
async fn sa14_a_foreign_or_stale_mail_message_is_refused() {
    let db = setup_db().await;
    let audit = SurrealAuditLogRepository::new(db.clone());
    let g = gate(&db, true);

    let foreign = InternalSigner::new(b"some-other-key".to_vec())
        .seal(MAIL_PURPOSE, &mail(), Utc::now())
        .unwrap();
    assert!(
        open_mail_delivery(&foreign, &g, &audit, Utc::now())
            .await
            .is_none()
    );

    let stale = InternalSigner::new(MASTER.to_vec())
        .seal(
            MAIL_PURPOSE,
            &mail(),
            Utc::now() - chrono::Duration::hours(1),
        )
        .unwrap();
    assert!(
        open_mail_delivery(&stale, &g, &audit, Utc::now())
            .await
            .is_none()
    );

    let mut reasons = rejection_reasons(&audit).await;
    reasons.sort();
    assert_eq!(reasons, ["bad_signature", "stale"]);
}
