//! The minimal profile's in-process mail worker (T23.8.1, G-8, D-59), driven
//! through the real broker-free send path against an in-memory datastore and an
//! SMTP server that is not there: a published message is attempted
//! [`MAX_RETRIES`] times, with the retries re-dispatched in process, and the
//! PII-minimal `email.delivery_failed` row is the whole record afterwards.

use std::time::Duration;

use axiam_amqp::mail_consumer::MAX_RETRIES;
use axiam_amqp::messages::{MailType, OutboundMailMessage};
use axiam_amqp::{in_process_mail_channel, spawn_in_process_mail_worker};
use axiam_core::models::email::{ProviderConfig, SetOrgEmailConfig, SmtpConfig};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, EmailConfigRepository, MailPublisher, Pagination,
};
use axiam_db::{
    SurrealAuditLogRepository, SurrealEmailConfigRepository, SurrealEmailTemplateRepository,
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use chrono::Utc;
use sha2::{Digest, Sha256};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

async fn setup_db() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

/// A 32-byte key derived at run time, never a literal.
fn email_key() -> [u8; 32] {
    Sha256::digest(axiam_test_support::test_password().as_bytes()).into()
}

fn failing_smtp() -> ProviderConfig {
    ProviderConfig::Smtp(SmtpConfig {
        host: "127.0.0.1".into(),
        port: 1, // nothing listens here: every attempt fails
        username: "user".into(),
        password: axiam_test_support::test_password(),
        starttls: false,
    })
}

fn message(org_id: Uuid, tenant_id: Uuid, user_id: Uuid) -> OutboundMailMessage {
    OutboundMailMessage {
        mail_type: MailType::PasswordReset,
        tenant_id,
        org_id,
        user_id,
        to_address: "victim@example.com".into(),
        template_context: serde_json::json!({"action_url": "https://example.com/action"}),
        attempt_count: 0,
        enqueued_at: Utc::now(),
    }
}

#[tokio::test]
async fn a_failing_message_is_retried_in_process_then_leaves_one_audit_row() {
    let db = setup_db().await;
    let org_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    SurrealEmailConfigRepository::new(db.clone(), email_key())
        .set_org_config(
            org_id,
            SetOrgEmailConfig {
                enabled: true,
                from_name: "Test".into(),
                from_email: "test@example.com".into(),
                reply_to: None,
                provider: failing_smtp(),
            },
        )
        .await
        .unwrap();

    let (publisher, queue) = in_process_mail_channel();
    let _worker = spawn_in_process_mail_worker(
        queue,
        SurrealEmailConfigRepository::new(db.clone(), email_key()),
        SurrealAuditLogRepository::new(db.clone()),
        SurrealUserRepository::new(db.clone()),
        SurrealEmailTemplateRepository::new(db.clone()),
        SurrealTenantRepository::new(db.clone()),
        SurrealOrganizationRepository::new(db.clone()),
        // The production schedule is 10 s doubling; a millisecond here.
        |_attempt| Duration::from_millis(5),
    );

    publisher
        .publish(message(org_id, tenant_id, user_id))
        .await
        .unwrap();

    let audit = SurrealAuditLogRepository::new(db.clone());
    let mut rows = Vec::new();
    for _ in 0..600 {
        let page = audit
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
        rows = page
            .items
            .into_iter()
            .filter(|e| e.action == "email.delivery_failed")
            .collect();
        if !rows.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(
        rows.len(),
        1,
        "exactly one email.delivery_failed row, after {MAX_RETRIES} attempts"
    );
    let row = &rows[0];
    assert_eq!(row.actor_id, user_id, "keyed on the user, never an address");
    let meta = row.metadata.to_string();
    assert!(!meta.contains("victim@example.com"), "D-16: no recipient");
    assert!(meta.contains("error_class"));
    // The last attempt carries attempt_count = MAX_RETRIES - 1: the retries
    // were re-dispatched with an incremented count.
    assert!(
        meta.contains(&format!("\"attempt_count\":{}", MAX_RETRIES - 1)),
        "the exhausting attempt is the {MAX_RETRIES}th: {meta}"
    );
}
