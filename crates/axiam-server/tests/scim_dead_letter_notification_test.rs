//! **T23.6.3** — a dead-lettered outbound SCIM delivery mails the tenant's
//! administrators through a notification rule (G-6, D-58).
//!
//! The row is the one the outbound dispatcher's consumer writes
//! (`scim_push.delivery_failed`, system actor, outcome `Failure`). It is not an
//! HTTP request, so it reaches the rules through `NotifyingAuditLog`, which the
//! composition root gives that consumer in place of the bare repository. Real
//! repositories throughout; only the mail broker is a recorder.

use std::sync::{Arc, Mutex};

use axiam_audit::{NotificationSink, NotifyingAuditLog};
use axiam_core::error::AxiamResult;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::mail::{MailType, OutboundMailMessage};
use axiam_core::models::notification_rule::{CreateNotificationRule, NotificationEventType};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, MailPublisher, NotificationRuleRepository,
    OrganizationRepository, Pagination, TenantRepository,
};
use axiam_db::{
    SurrealAuditLogRepository, SurrealNotificationRuleRepository, SurrealOrganizationRepository,
    SurrealTenantRepository, run_migrations,
};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

#[derive(Clone, Default)]
struct RecordedMail(Arc<Mutex<Vec<OutboundMailMessage>>>);

impl MailPublisher for RecordedMail {
    async fn publish(&self, msg: OutboundMailMessage) -> AxiamResult<()> {
        self.0.lock().unwrap().push(msg);
        Ok(())
    }
}

fn dispatcher_row(tenant_id: Uuid, action: &str, outcome: AuditOutcome) -> CreateAuditLogEntry {
    CreateAuditLogEntry {
        tenant_id,
        actor_id: Uuid::nil(),
        actor_type: ActorType::System,
        action: action.into(),
        resource_id: Some(Uuid::new_v4()),
        outcome,
        ip_address: None,
        metadata: Some(serde_json::json!({"error": "the receiver refused the request"})),
    }
}

async fn setup() -> (Surreal<Db>, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    run_migrations(&db).await.unwrap();
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: format!("org-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Tenant".into(),
            slug: format!("tenant-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    (db, org.id, tenant.id)
}

#[tokio::test]
async fn a_scim_dead_letter_row_mails_every_recipient_of_a_matching_rule() {
    let (db, org_id, tenant_id) = setup().await;
    let rules = SurrealNotificationRuleRepository::new(db.clone());
    rules
        .create(CreateNotificationRule {
            tenant_id,
            name: "scim failures".into(),
            description: String::new(),
            events: vec![NotificationEventType::ScimDeliveryFailed],
            recipient_emails: vec!["soc@example.com".into(), "oncall@example.com".into()],
        })
        .await
        .unwrap();
    // A rule for another event of the same tenant is not mailed.
    rules
        .create(CreateNotificationRule {
            tenant_id,
            name: "logins".into(),
            description: String::new(),
            events: vec![NotificationEventType::LoginFailure],
            recipient_emails: vec!["other@example.com".into()],
        })
        .await
        .unwrap();

    let mail = RecordedMail::default();
    let audit = NotifyingAuditLog::new(
        SurrealAuditLogRepository::new(db.clone()),
        Arc::new(NotificationSink::new(rules, mail.clone())),
        SurrealTenantRepository::new(db.clone()),
    );

    // The dispatcher's retry-in-progress row and another kind's dead letter are
    // not the event.
    audit
        .append(dispatcher_row(
            tenant_id,
            "scim_push.delivery_attempt",
            AuditOutcome::Failure,
        ))
        .await
        .unwrap();
    audit
        .append(dispatcher_row(
            tenant_id,
            "webhook.delivery_failed",
            AuditOutcome::Failure,
        ))
        .await
        .unwrap();
    assert!(mail.0.lock().unwrap().is_empty());

    // The dead letter itself.
    audit
        .append(dispatcher_row(
            tenant_id,
            "scim_push.delivery_failed",
            AuditOutcome::Failure,
        ))
        .await
        .unwrap();

    let sent = mail.0.lock().unwrap().clone();
    assert_eq!(sent.len(), 2, "one mail per recipient");
    let mut recipients: Vec<&str> = sent.iter().map(|m| m.to_address.as_str()).collect();
    recipients.sort_unstable();
    assert_eq!(recipients, ["oncall@example.com", "soc@example.com"]);
    for message in &sent {
        assert!(matches!(message.mail_type, MailType::Notification));
        assert_eq!(message.tenant_id, tenant_id);
        assert_eq!(message.org_id, org_id, "the organization was resolved");
        let context = message.template_context.as_object().unwrap();
        assert_eq!(context["event"], "scim_delivery_failed");
        assert_eq!(context["username"], "AXIAM (an automated process)");
        // No receiver detail travels in the mail: the action and outcome only.
        assert!(
            !message
                .template_context
                .to_string()
                .contains("the receiver refused")
        );
    }

    // And every row, mapped or not, was appended.
    let page = audit
        .list(tenant_id, AuditLogFilter::default(), Pagination::default())
        .await
        .unwrap();
    assert_eq!(page.total, 3);
}
