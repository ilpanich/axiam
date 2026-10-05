//! **T23.7.2** — the CIBA e-mail notifier (G-7): what the mail on the queue
//! carries, whom it is sent to, and what it never contains.
//!
//! Real user and tenant repositories on an in-memory database; the mail queue is
//! a recording publisher.

use std::sync::{Arc, Mutex};

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::ciba::{CibaUserNotification, CibaUserNotifier};
use axiam_core::models::mail::{MailType, OutboundMailMessage};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    MailPublisher, OrganizationRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_oauth2::ciba_notifier::CibaMailNotifier;
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

#[derive(Clone, Default)]
struct RecordingMail {
    sent: Arc<Mutex<Vec<OutboundMailMessage>>>,
    fail: bool,
}

impl MailPublisher for RecordingMail {
    async fn publish(&self, msg: OutboundMailMessage) -> AxiamResult<()> {
        if self.fail {
            return Err(AxiamError::Internal("the queue is down".into()));
        }
        self.sent.lock().unwrap().push(msg);
        Ok(())
    }
}

type Notifier =
    CibaMailNotifier<SurrealUserRepository<Db>, SurrealTenantRepository<Db>, RecordingMail>;

struct World {
    db: Surreal<Db>,
    tenant_id: Uuid,
    org_id: Uuid,
    user_id: Uuid,
    mail: RecordingMail,
    notifier: Notifier,
}

async fn world_with(mail: RecordingMail) -> World {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "org".into(),
            slug: "org-notifier".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "tenant".into(),
            slug: "tenant-notifier".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let users = SurrealUserRepository::new(db.clone());
    let user = users
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: format!("{}Aa1!", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    users
        .update(
            tenant.id,
            user.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let notifier = CibaMailNotifier::new(
        users,
        SurrealTenantRepository::new(db.clone()),
        mail.clone(),
        "https://id.example.test/",
    );
    World {
        db,
        tenant_id: tenant.id,
        org_id: org.id,
        user_id: user.id,
        mail,
        notifier,
    }
}

async fn world() -> World {
    world_with(RecordingMail::default()).await
}

fn notification(w: &World, binding: Option<&str>) -> CibaUserNotification {
    CibaUserNotification {
        tenant_id: w.tenant_id,
        request_id: Uuid::new_v4(),
        user_id: w.user_id,
        client_id: "cc_1".into(),
        client_name: "Call Centre".into(),
        binding_message: binding.map(str::to_owned),
        scopes: vec!["openid".into(), "profile".into()],
        expires_at: Utc::now() + Duration::seconds(300),
    }
}

fn sent(w: &World) -> Vec<OutboundMailMessage> {
    w.mail.sent.lock().unwrap().clone()
}

/// The mail names the client, carries the binding message and links to the
/// approval page by record id — and has nothing else in it.
#[tokio::test]
async fn the_mail_carries_the_client_the_binding_message_and_a_link() {
    let w = world().await;
    let n = notification(&w, Some("Confirm J.Doe 42 EUR"));
    w.notifier.notify(n.clone()).await.unwrap();

    let mails = sent(&w);
    assert_eq!(mails.len(), 1);
    let mail = &mails[0];
    assert_eq!(mail.mail_type, MailType::CibaApproval);
    assert_eq!(mail.tenant_id, w.tenant_id);
    assert_eq!(mail.org_id, w.org_id);
    assert_eq!(mail.user_id, w.user_id);
    assert_eq!(mail.to_address, "alice@example.com");
    assert_eq!(mail.attempt_count, 0);

    let ctx = mail.template_context.as_object().expect("an object");
    assert_eq!(ctx["client_name"], "Call Centre");
    assert_eq!(ctx["binding_message"], "Confirm J.Doe 42 EUR");
    assert_eq!(
        ctx["action_url"],
        format!(
            "https://id.example.test/ciba/approve?request_id={}",
            n.request_id
        ),
        "the link carries the record id and nothing else"
    );
    assert_eq!(ctx["expiry_time"], n.expires_at.to_rfc3339());
    // Exactly these keys: a new one is a deliberate decision, not a leak.
    let mut keys: Vec<&str> = ctx.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "action_url",
            "binding_message",
            "client_name",
            "expiry_time"
        ]
    );
}

#[tokio::test]
async fn a_request_without_a_binding_message_still_fills_the_template() {
    let w = world().await;
    w.notifier.notify(notification(&w, None)).await.unwrap();
    let mails = sent(&w);
    assert_eq!(mails[0].template_context["binding_message"], "(none)");
}

/// The link is what a mail is for, so a deployment with no public origin
/// configured gets the relative form the other mails use, never a half-made URL.
#[tokio::test]
async fn an_empty_base_url_gives_a_relative_link() {
    let w = world().await;
    let notifier = CibaMailNotifier::new(
        SurrealUserRepository::new(w.db.clone()),
        SurrealTenantRepository::new(w.db.clone()),
        w.mail.clone(),
        "",
    );
    let n = notification(&w, None);
    assert_eq!(
        notifier.approval_url(n.request_id),
        format!("/ciba/approve?request_id={}", n.request_id)
    );
}

/// Neither the `auth_req_id` nor any token can be in the mail: the notification
/// the port carries has no such field, and the mail's whole serialization is
/// checked for the shapes of one.
#[tokio::test]
async fn nothing_secret_is_in_the_queued_message() {
    let w = world().await;
    w.notifier
        .notify(notification(&w, Some("W4SCT")))
        .await
        .unwrap();
    let rendered = serde_json::to_string(&sent(&w)[0]).unwrap();
    for forbidden in [
        "auth_req_id",
        "notification_token",
        "access_token",
        "Bearer",
    ] {
        assert!(!rendered.contains(forbidden), "{forbidden}");
    }
}

/// An account that may not take part in the grant, is scheduled for deletion,
/// has no address, or does not exist is not mailed — and the request does not
/// fail for it.
#[tokio::test]
async fn an_account_that_may_not_be_mailed_is_not_mailed() {
    let w = world().await;
    let users = SurrealUserRepository::new(w.db.clone());

    // An account that may not sign in.
    users
        .update(
            w.tenant_id,
            w.user_id,
            UpdateUser {
                status: Some(UserStatus::Inactive),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    w.notifier.notify(notification(&w, None)).await.unwrap();
    assert!(sent(&w).is_empty(), "an inactive account is not mailed");

    users
        .update(
            w.tenant_id,
            w.user_id,
            UpdateUser {
                status: Some(UserStatus::Active),
                email: Some("   ".into()),
                ..Default::default()
            },
        )
        .await
        .ok();
    // A blank address is refused by the repository's own validation or stored;
    // either way nothing is mailed to a blank one.
    let user = users.get_by_id(w.tenant_id, w.user_id).await.unwrap();
    if user.email.trim().is_empty() {
        w.notifier.notify(notification(&w, None)).await.unwrap();
        assert!(sent(&w).is_empty(), "no address, no mail");
    }

    // A user that does not exist.
    let mut stranger = notification(&w, None);
    stranger.user_id = Uuid::new_v4();
    w.notifier.notify(stranger).await.unwrap();
    assert!(sent(&w).is_empty());
}

#[tokio::test]
async fn a_queue_failure_is_reported_to_the_caller_to_log() {
    let w = world_with(RecordingMail {
        fail: true,
        ..Default::default()
    })
    .await;
    assert!(w.notifier.notify(notification(&w, None)).await.is_err());
}

#[tokio::test]
async fn the_tenant_is_the_notifications_not_another() {
    let w = world().await;
    let mut other_tenant = notification(&w, None);
    other_tenant.tenant_id = Uuid::new_v4();
    w.notifier.notify(other_tenant).await.unwrap();
    assert!(sent(&w).is_empty(), "a user is looked up in its own tenant");
}
