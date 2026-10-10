//! **#551, T-117** — a notification rule mails each recipient once per event
//! type and window, not once per event.
//!
//! The request path's sink — the one the composition root gives the audit
//! middleware's worker — is driven here with the rows that worker hands it: a
//! failed sign-in is `POST /api/v1/auth/login` with outcome `Failure`, no
//! actor. The window of `(tenant, rule, event)` is claimed in the datastore,
//! so "two replicas" is two sinks over one database. Real repositories
//! throughout; only the mail broker is a recorder.
//!
//! Since R1W2-01 a sink counts the events of a window it knows to be open in
//! memory and writes the count at its next claim or flush; the audit
//! middleware's sink task flushes every ten seconds and when it stops. These
//! tests age the window in the datastore to stand for time passing, so each
//! flushes first, as that task would have by then.

use std::sync::{Arc, Mutex};

use axiam_audit::{AuditEvent, AuditEventSink, NotificationSink};
use axiam_core::error::AxiamResult;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::mail::OutboundMailMessage;
use axiam_core::models::notification_rule::{CreateNotificationRule, NotificationEventType};
use axiam_core::repository::{MailPublisher, NotificationRuleRepository};
use axiam_db::{
    SurrealNotificationRuleRepository, SurrealNotificationWindowRepository, run_migrations,
};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

#[derive(Clone, Default)]
struct RecordedMail(Arc<Mutex<Vec<OutboundMailMessage>>>);

impl RecordedMail {
    fn sent(&self) -> Vec<OutboundMailMessage> {
        self.0.lock().unwrap().clone()
    }

    fn to(&self, address: &str) -> Vec<OutboundMailMessage> {
        self.sent()
            .into_iter()
            .filter(|m| m.to_address == address)
            .collect()
    }
}

impl MailPublisher for RecordedMail {
    async fn publish(&self, msg: OutboundMailMessage) -> AxiamResult<()> {
        self.0.lock().unwrap().push(msg);
        Ok(())
    }
}

type Sink = NotificationSink<
    SurrealNotificationRuleRepository<Db>,
    SurrealNotificationWindowRepository<Db>,
    RecordedMail,
>;

/// A replica's sink: its own repositories over the shared datastore.
fn sink(db: &Surreal<Db>, mail: &RecordedMail) -> Sink {
    NotificationSink::new(
        SurrealNotificationRuleRepository::new(db.clone()),
        SurrealNotificationWindowRepository::new(db.clone()),
        mail.clone(),
    )
}

async fn database() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    run_migrations(&db).await.unwrap();
    db
}

async fn rule(
    db: &Surreal<Db>,
    tenant_id: Uuid,
    events: Vec<NotificationEventType>,
    recipients: &[&str],
    window_minutes: Option<u32>,
) -> Uuid {
    SurrealNotificationRuleRepository::new(db.clone())
        .create(CreateNotificationRule {
            tenant_id,
            name: format!("rule {}", Uuid::new_v4().simple()),
            description: String::new(),
            events,
            recipient_emails: recipients.iter().map(|r| r.to_string()).collect(),
            window_minutes,
        })
        .await
        .unwrap()
        .id
}

/// The row the audit middleware's worker hands the sink for a failed sign-in
/// (`Failure`) or a refused one on a locked account (`Denied`).
fn sign_in(tenant_id: Uuid, outcome: AuditOutcome) -> AuditEvent {
    AuditEvent {
        entry: CreateAuditLogEntry {
            tenant_id,
            actor_id: Uuid::nil(),
            actor_type: ActorType::User,
            action: "POST /api/v1/auth/login".into(),
            resource_id: None,
            outcome,
            ip_address: Some("203.0.113.7".into()),
            metadata: None,
        },
        org_id: Uuid::new_v4(),
    }
}

/// Move every window of `rule_id` back by `minutes`, as that much time passing
/// would.
async fn age_windows(db: &Surreal<Db>, rule_id: Uuid, minutes: i64) {
    db.query(
        "UPDATE notification_window SET opened_at = opened_at - type::duration($age) \
         WHERE rule_id = $rule_id",
    )
    .bind(("age", format!("{minutes}m")))
    .bind(("rule_id", rule_id.to_string()))
    .await
    .unwrap()
    .check()
    .unwrap();
}

/// The issue's test: a burst of a hundred `LoginFailure` rows mails each
/// recipient once, and the next window's mail carries the count.
#[tokio::test]
async fn a_burst_of_a_hundred_login_failures_mails_each_recipient_once() {
    let db = database().await;
    let tenant_id = Uuid::new_v4();
    let rule_id = rule(
        &db,
        tenant_id,
        vec![NotificationEventType::LoginFailure],
        &["soc@example.com", "oncall@example.com"],
        None,
    )
    .await;
    let mail = RecordedMail::default();
    let sink = sink(&db, &mail);

    for _ in 0..100 {
        sink.on_event(&sign_in(tenant_id, AuditOutcome::Failure))
            .await;
    }
    assert_eq!(mail.to("soc@example.com").len(), 1);
    assert_eq!(mail.to("oncall@example.com").len(), 1);
    let first = &mail.sent()[0].template_context;
    assert_eq!(first["event"], "login_failure");
    assert_eq!(first["suppressed_count"], "0");

    // Fifteen minutes on — the default window — the next failure is mailed,
    // and the mail says how many of the burst were not.
    sink.flush_local_counts().await;
    age_windows(&db, rule_id, 15).await;
    sink.on_event(&sign_in(tenant_id, AuditOutcome::Failure))
        .await;
    for recipient in ["soc@example.com", "oncall@example.com"] {
        let sent = mail.to(recipient);
        assert_eq!(sent.len(), 2, "{recipient}");
        let context = &sent[1].template_context;
        assert_eq!(context["suppressed_count"], "99");
        assert!(
            context["window_note"]
                .as_str()
                .unwrap()
                .contains("Not mailed in the previous window: 99 login_failure events."),
            "{context}"
        );
    }
}

/// Two replicas sharing one datastore, each handed half of a concurrent burst,
/// still mail each recipient once: the window is claimed in the datastore,
/// not in a replica's memory.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_replicas_sharing_one_datastore_mail_each_recipient_once() {
    let db = database().await;
    let tenant_id = Uuid::new_v4();
    let rule_id = rule(
        &db,
        tenant_id,
        vec![NotificationEventType::LoginFailure],
        &["soc@example.com"],
        None,
    )
    .await;
    let mail = RecordedMail::default();

    let mut replicas = tokio::task::JoinSet::new();
    for _ in 0..2 {
        let replica = Arc::new(sink(&db, &mail));
        replicas.spawn(async move {
            for _ in 0..50 {
                replica
                    .on_event(&sign_in(tenant_id, AuditOutcome::Failure))
                    .await;
            }
            replica.flush_local_counts().await;
        });
    }
    replicas.join_all().await;
    assert_eq!(mail.to("soc@example.com").len(), 1);

    // Every one of the other 99 was counted, whichever replica saw it.
    age_windows(&db, rule_id, 15).await;
    sink(&db, &mail)
        .on_event(&sign_in(tenant_id, AuditOutcome::Failure))
        .await;
    let sent = mail.to("soc@example.com");
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1].template_context["suppressed_count"], "99");
}

/// The window is per `(tenant, rule, event)`: another rule for the same event,
/// another event of the same rule and the same rule's event in another tenant
/// each mail on their own.
#[tokio::test]
async fn a_different_rule_or_event_has_its_own_window() {
    let db = database().await;
    let tenant_id = Uuid::new_v4();
    rule(
        &db,
        tenant_id,
        vec![
            NotificationEventType::LoginFailure,
            NotificationEventType::AccountLocked,
        ],
        &["soc@example.com"],
        None,
    )
    .await;
    rule(
        &db,
        tenant_id,
        vec![NotificationEventType::LoginFailure],
        &["oncall@example.com"],
        None,
    )
    .await;
    let other_tenant = Uuid::new_v4();
    rule(
        &db,
        other_tenant,
        vec![NotificationEventType::LoginFailure],
        &["other@example.com"],
        None,
    )
    .await;
    let mail = RecordedMail::default();
    let sink = sink(&db, &mail);

    for _ in 0..10 {
        sink.on_event(&sign_in(tenant_id, AuditOutcome::Failure))
            .await;
    }
    // One per rule.
    assert_eq!(mail.to("soc@example.com").len(), 1);
    assert_eq!(mail.to("oncall@example.com").len(), 1);

    // The first rule's other event has a window of its own.
    for _ in 0..10 {
        sink.on_event(&sign_in(tenant_id, AuditOutcome::Denied))
            .await;
    }
    let soc = mail.to("soc@example.com");
    assert_eq!(soc.len(), 2);
    assert_eq!(soc[1].template_context["event"], "account_locked");
    assert_eq!(mail.to("oncall@example.com").len(), 1);

    // Another tenant's rule is not touched by this tenant's burst.
    assert!(mail.to("other@example.com").is_empty());
    sink.on_event(&sign_in(other_tenant, AuditOutcome::Failure))
        .await;
    assert_eq!(mail.to("other@example.com").len(), 1);
}

/// Each rule's own window is the one applied: two minutes on, a one-minute
/// rule has reopened and an hour-long one is still counting.
#[tokio::test]
async fn the_rules_own_window_is_honoured() {
    let db = database().await;
    let tenant_id = Uuid::new_v4();
    let minute = rule(
        &db,
        tenant_id,
        vec![NotificationEventType::LoginFailure],
        &["minute@example.com"],
        Some(1),
    )
    .await;
    let hour = rule(
        &db,
        tenant_id,
        vec![NotificationEventType::LoginFailure],
        &["hour@example.com"],
        Some(60),
    )
    .await;
    let mail = RecordedMail::default();
    let sink = sink(&db, &mail);

    for _ in 0..3 {
        sink.on_event(&sign_in(tenant_id, AuditOutcome::Failure))
            .await;
    }
    sink.flush_local_counts().await;
    age_windows(&db, minute, 2).await;
    age_windows(&db, hour, 2).await;
    sink.on_event(&sign_in(tenant_id, AuditOutcome::Failure))
        .await;

    let by_minute = mail.to("minute@example.com");
    assert_eq!(by_minute.len(), 2);
    assert_eq!(by_minute[1].template_context["suppressed_count"], "2");
    assert!(
        by_minute[1].template_context["window_note"]
            .as_str()
            .unwrap()
            .contains("at most once every minute")
    );
    assert_eq!(mail.to("hour@example.com").len(), 1);
}
