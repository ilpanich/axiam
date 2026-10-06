//! **T23.6.3** — a dead-lettered outbound SCIM delivery mails the tenant's
//! administrators through a notification rule (G-6, D-58).
//!
//! The row is the one the outbound dispatcher's consumer writes
//! (`scim_push.delivery_failed`, system actor, outcome `Failure`, the target as
//! its resource). It is not an HTTP request, so it reaches the rules through a
//! `NotifyingAuditLog`, which the composition root gives that consumer in place
//! of the bare repository — built by
//! `axiam_server::scim_notification::scim_dead_letter_audit`, the very function
//! these tests call. Since the W5 F4 review (T-418, D-73) that wrapper lets one
//! dead letter **per target per hour** through to the rules; every row is
//! still appended. Real repositories throughout; only the mail broker is a
//! recorder.

use std::sync::{Arc, Mutex, OnceLock};

use axiam_audit::NotificationSink;
use axiam_core::error::AxiamResult;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::mail::{MailType, OutboundMailMessage};
use axiam_core::models::notification_rule::{CreateNotificationRule, NotificationEventType};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::scim_target::{
    DeprovisionPolicy, NewScimTarget, ScimTargetAuth, ScimTargetScope, UserNameSource,
};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, MailPublisher, NotificationRuleRepository,
    OrganizationRepository, Pagination, ScimTargetRepository, ScimTargetStateRepository,
    TenantRepository,
};
use axiam_db::{
    SurrealAuditLogRepository, SurrealNotificationRuleRepository, SurrealOrganizationRepository,
    SurrealScimTargetRepository, SurrealScimTargetStateRepository, SurrealTenantRepository,
    run_migrations,
};
use axiam_server::scim_notification::scim_dead_letter_audit;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone, Default)]
struct RecordedMail(Arc<Mutex<Vec<OutboundMailMessage>>>);

impl MailPublisher for RecordedMail {
    async fn publish(&self, msg: OutboundMailMessage) -> AxiamResult<()> {
        self.0.lock().unwrap().push(msg);
        Ok(())
    }
}

/// The row the dispatcher writes for one attempt of a delivery to `target_id`.
fn dispatcher_row(
    tenant_id: Uuid,
    target_id: Uuid,
    action: &str,
    outcome: AuditOutcome,
) -> CreateAuditLogEntry {
    CreateAuditLogEntry {
        tenant_id,
        actor_id: Uuid::nil(),
        actor_type: ActorType::System,
        action: action.into(),
        resource_id: Some(target_id),
        outcome,
        ip_address: None,
        metadata: Some(serde_json::json!({"error": "the receiver refused the request"})),
    }
}

/// The sealing key for the targets' credentials, made once per binary.
fn sealing() -> [u8; 32] {
    static SEALING: OnceLock<[u8; 32]> = OnceLock::new();
    *SEALING.get_or_init(|| {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        out
    })
}

/// A SCIM target of `tenant_id`, with its delivery-state row.
async fn target(db: &Surreal<Db>, tenant_id: Uuid) -> Uuid {
    SurrealScimTargetRepository::new(db.clone(), Some(sealing()))
        .create(NewScimTarget {
            tenant_id,
            name: format!("Downstream {}", Uuid::new_v4().simple()),
            base_url: "https://scim.example.com/v2".into(),
            enabled: true,
            auth: ScimTargetAuth::Bearer,
            credential: Zeroizing::new(format!("c-{}", Uuid::new_v4().simple())),
            scope: ScimTargetScope::AllUsers,
            push_groups: false,
            user_name_from: UserNameSource::Username,
            deprovision: DeprovisionPolicy::Deactivate,
        })
        .await
        .unwrap()
        .id
}

/// A rule for `scim_delivery_failed` with two recipients, and one for another
/// event.
async fn rules(db: &Surreal<Db>, tenant_id: Uuid) -> SurrealNotificationRuleRepository<Db> {
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
    rules
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
    let rules = rules(&db, tenant_id).await;
    let target_id = target(&db, tenant_id).await;

    let mail = RecordedMail::default();
    let audit = scim_dead_letter_audit(
        SurrealAuditLogRepository::new(db.clone()),
        Arc::new(NotificationSink::new(rules, mail.clone())),
        SurrealTenantRepository::new(db.clone()),
        SurrealScimTargetStateRepository::new(db.clone()),
    );

    // The dispatcher's retry-in-progress row and another kind's dead letter are
    // not the event.
    audit
        .append(dispatcher_row(
            tenant_id,
            target_id,
            "scim_push.delivery_attempt",
            AuditOutcome::Failure,
        ))
        .await
        .unwrap();
    audit
        .append(dispatcher_row(
            tenant_id,
            target_id,
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
            target_id,
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

/// W5 F4 review, T-418 (D-73): a target that dead-letters every reference —
/// down past its retry budget, or refusing AXIAM's credential at the next
/// reconciliation — mails each recipient **once per hour**, not once per dead
/// letter. Every row is still appended. Another target is its own claim, and a
/// target whose last notification is an hour old notifies again.
#[tokio::test]
async fn a_targets_dead_letters_mail_each_recipient_once_an_hour_not_once_each() {
    let (db, _org_id, tenant_id) = setup().await;
    let rules = rules(&db, tenant_id).await;
    let down = target(&db, tenant_id).await;
    let other = target(&db, tenant_id).await;

    let mail = RecordedMail::default();
    let audit = scim_dead_letter_audit(
        SurrealAuditLogRepository::new(db.clone()),
        Arc::new(NotificationSink::new(rules, mail.clone())),
        SurrealTenantRepository::new(db.clone()),
        SurrealScimTargetStateRepository::new(db.clone()),
    );
    let dead_letter = |target_id| {
        dispatcher_row(
            tenant_id,
            target_id,
            "scim_push.delivery_failed",
            AuditOutcome::Failure,
        )
    };

    // Fifty dead letters of one target: one mail per recipient.
    for _ in 0..50 {
        audit.append(dead_letter(down)).await.unwrap();
    }
    assert_eq!(
        mail.0.lock().unwrap().len(),
        2,
        "one notification per target per hour, whatever the number of dead letters"
    );

    // Another target of the tenant is announced on its own.
    audit.append(dead_letter(other)).await.unwrap();
    assert_eq!(mail.0.lock().unwrap().len(), 4);

    // A dead letter naming no target of this tenant notifies nobody.
    audit.append(dead_letter(Uuid::new_v4())).await.unwrap();
    assert_eq!(mail.0.lock().unwrap().len(), 4);

    // An hour after the last notification the outage is announced again.
    db.query(
        "UPDATE type::record('scim_target_state', $id) \
         SET failure_notified_at = time::now() - 61m",
    )
    .bind(("id", down.to_string()))
    .await
    .unwrap()
    .check()
    .unwrap();
    audit.append(dead_letter(down)).await.unwrap();
    assert_eq!(mail.0.lock().unwrap().len(), 6);

    // Every row was appended — the audit trail is per dead letter.
    let page = audit
        .list(tenant_id, AuditLogFilter::default(), Pagination::default())
        .await
        .unwrap();
    assert_eq!(page.total, 53);
    // Nothing here touched the delivery counts (the deliverer writes those).
    let state = SurrealScimTargetStateRepository::new(db.clone())
        .get(tenant_id, down)
        .await
        .unwrap();
    assert_eq!(state.dead_lettered_total, 0);
}
