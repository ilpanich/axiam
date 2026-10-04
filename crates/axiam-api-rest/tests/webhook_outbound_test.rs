//! The webhook kind seen through the shared outbound dispatcher's ports
//! (D-36, T23.5.1): `emit` enqueues through `OutboundPublisher`, and
//! `WebhookDeliveryService` classifies one attempt through
//! `OutboundDeliverer`. Broker-free: the publisher is a recording double and
//! the SSRF guard (which refuses loopback) supplies a deterministic failure.

use std::sync::{Arc, Mutex, OnceLock};

use axiam_api_rest::webhook::WebhookDeliveryService;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::webhook::CreateWebhook;
use axiam_core::outbound::{
    DeliveryOutcome, OutboundDeliverer, OutboundError, OutboundFuture, OutboundKind,
    OutboundMessage, OutboundPublisher,
};
use axiam_core::repository::{OrganizationRepository, TenantRepository, WebhookRepository};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealWebhookRepository,
};
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

/// An AES-256-GCM key generated at run time, not a literal.
fn enc_key() -> [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    *KEY.get_or_init(|| {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        bytes
    })
}

async fn setup_db() -> (surrealdb::Surreal<TestDb>, Uuid) {
    let db = surrealdb::Surreal::new::<surrealdb::engine::local::Mem>(())
        .await
        .unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Webhook Outbound Org".into(),
            slug: "webhook-outbound-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Webhook Outbound Tenant".into(),
            slug: "webhook-outbound-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    (db, tenant.id)
}

async fn create_webhook(
    repo: &SurrealWebhookRepository<TestDb>,
    service: &WebhookDeliveryService<SurrealWebhookRepository<TestDb>>,
    tenant_id: Uuid,
    url: &str,
    event: &str,
) -> Uuid {
    // The stored secret is generated, not a literal.
    let plaintext = Uuid::new_v4().to_string();
    let stored = service.encrypt_secret(&plaintext).expect("encrypt");
    repo.create(CreateWebhook {
        tenant_id,
        url: url.into(),
        events: vec![event.into()],
        secret: stored,
        retry_policy: None,
    })
    .await
    .expect("create webhook")
    .id
}

/// Records every enqueued message; optionally refuses them.
#[derive(Default)]
struct RecordingPublisher {
    messages: Mutex<Vec<OutboundMessage>>,
    fail: bool,
}

impl OutboundPublisher for RecordingPublisher {
    fn enqueue<'a>(
        &'a self,
        msg: &'a OutboundMessage,
    ) -> OutboundFuture<'a, Result<(), OutboundError>> {
        Box::pin(async move {
            if self.fail {
                return Err(OutboundError::Enqueue("broker down".into()));
            }
            self.messages.lock().unwrap().push(msg.clone());
            Ok(())
        })
    }
}

fn outbound_message(tenant_id: Uuid, target_id: Uuid) -> OutboundMessage {
    OutboundMessage {
        kind: OutboundKind::Webhook,
        tenant_id,
        target_id,
        delivery_id: Uuid::new_v4(),
        event_type: "user.created".into(),
        payload: serde_json::json!({"hello": "world"}),
        attempt: 0,
    }
}

#[actix_rt::test]
async fn emit_enqueues_one_webhook_message_per_matching_webhook() {
    let (db, tenant_id) = setup_db().await;
    let repo = SurrealWebhookRepository::new(db.clone());
    let service = WebhookDeliveryService::new(repo.clone(), Some(enc_key()));

    let a = create_webhook(
        &repo,
        &service,
        tenant_id,
        "https://a.invalid/h",
        "user.created",
    )
    .await;
    let b = create_webhook(
        &repo,
        &service,
        tenant_id,
        "https://b.invalid/h",
        "user.created",
    )
    .await;
    let _other = create_webhook(
        &repo,
        &service,
        tenant_id,
        "https://c.invalid/h",
        "user.deleted",
    )
    .await;

    let publisher = RecordingPublisher::default();
    let payload = serde_json::json!({"id": "u-1"});
    service
        .emit(
            &publisher,
            tenant_id,
            "user.created".into(),
            payload.clone(),
        )
        .await;

    let messages = publisher.messages.lock().unwrap();
    assert_eq!(
        messages.len(),
        2,
        "one message per webhook subscribed to the event"
    );
    let mut targets: Vec<Uuid> = messages.iter().map(|m| m.target_id).collect();
    targets.sort();
    let mut expected = vec![a, b];
    expected.sort();
    assert_eq!(targets, expected);
    for m in messages.iter() {
        assert_eq!(m.kind, OutboundKind::Webhook);
        assert_eq!(m.tenant_id, tenant_id);
        assert_eq!(m.event_type, "user.created");
        assert_eq!(m.payload, payload);
        assert_eq!(m.attempt, 0, "first attempt");
    }
    assert_ne!(
        messages[0].delivery_id, messages[1].delivery_id,
        "each webhook gets its own delivery id"
    );
}

/// `emit` is a best-effort side effect: a publisher that refuses must not
/// panic or propagate.
#[actix_rt::test]
async fn emit_survives_a_publisher_failure() {
    let (db, tenant_id) = setup_db().await;
    let repo = SurrealWebhookRepository::new(db.clone());
    let service = WebhookDeliveryService::new(repo.clone(), Some(enc_key()));
    create_webhook(
        &repo,
        &service,
        tenant_id,
        "https://a.invalid/h",
        "user.created",
    )
    .await;

    let publisher = RecordingPublisher {
        fail: true,
        ..Default::default()
    };
    service
        .emit(
            &publisher,
            tenant_id,
            "user.created".into(),
            serde_json::json!({}),
        )
        .await;
    assert!(publisher.messages.lock().unwrap().is_empty());
}

#[actix_rt::test]
async fn the_service_is_the_webhook_deliverer() {
    let (db, _tenant_id) = setup_db().await;
    let service = WebhookDeliveryService::new(SurrealWebhookRepository::new(db), Some(enc_key()));
    let deliverer: Arc<dyn OutboundDeliverer> = Arc::new(service);
    assert_eq!(deliverer.kind(), OutboundKind::Webhook);
}

/// The SSRF guard refuses a loopback target on every attempt: the deliverer
/// reports a retry (today's behaviour retries every failure to the maximum),
/// never `Delivered` and never an immediate dead letter.
#[actix_rt::test]
async fn a_blocked_target_is_a_retry() {
    let (db, tenant_id) = setup_db().await;
    let repo = SurrealWebhookRepository::new(db.clone());
    let service = WebhookDeliveryService::new(repo.clone(), Some(enc_key()));
    let id = create_webhook(
        &repo,
        &service,
        tenant_id,
        "https://127.0.0.1:9/outbound-deliverer-test",
        "user.created",
    )
    .await;

    let outcome = service
        .deliver_attempt(&outbound_message(tenant_id, id))
        .await
        .expect("a classified outcome, not an error");
    assert!(
        matches!(outcome, DeliveryOutcome::Retry { .. }),
        "got {outcome:?}"
    );
}

#[actix_rt::test]
async fn an_unknown_webhook_is_a_retry() {
    let (db, tenant_id) = setup_db().await;
    let service = WebhookDeliveryService::new(SurrealWebhookRepository::new(db), Some(enc_key()));

    let outcome = service
        .deliver_attempt(&outbound_message(tenant_id, Uuid::new_v4()))
        .await
        .unwrap();
    match outcome {
        DeliveryOutcome::Retry { reason } => assert!(reason.contains("lookup"), "{reason}"),
        other => panic!("expected Retry, got {other:?}"),
    }
}

#[actix_rt::test]
async fn a_missing_encryption_key_is_a_retry() {
    let (db, tenant_id) = setup_db().await;
    let service = WebhookDeliveryService::new(SurrealWebhookRepository::new(db), None);

    let outcome = service
        .deliver_attempt(&outbound_message(tenant_id, Uuid::new_v4()))
        .await
        .unwrap();
    match outcome {
        DeliveryOutcome::Retry { reason } => assert!(reason.contains("encryption key"), "{reason}"),
        other => panic!("expected Retry, got {other:?}"),
    }
}
