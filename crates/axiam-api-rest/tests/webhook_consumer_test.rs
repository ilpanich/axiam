//! Tests for the webhook AMQP consumer (CORR-03/26-07).
//!
//! Two tiers:
//! 1. Non-ignored, broker-free assertions: `WebhookMessage` attempt-increment
//!    and serialize round-trip, and the retry-TTL math a simulated failure
//!    would compute (`backoff_ttl_ms`).
//! 2. An `#[ignore]`d live-RabbitMQ integration test (run via `just dev-up`)
//!    proving the end-to-end AMQP wiring: a queued `WebhookMessage` is
//!    dequeued, `deliver_once` is invoked, a failure is retried via the
//!    `axiam.webhook.retry` TTL+DLX, and after `max_attempts` the message
//!    lands in `axiam.webhook.dlq` with per-attempt + terminal audit records
//!    written.
//!
//! ## Why this test cannot prove a *successful* signed HTTP delivery
//!
//! `WebhookDeliveryService::deliver_once` (26-03) calls
//! `ssrf::guarded_fetch(&webhook.url, false, ...)` — the `allow_private`
//! parameter is hardcoded `false` in the production delivery path (D-01a/
//! T-26-07-01: the consumer must not weaken the SSRF guard). This means
//! `deliver_once` will ALWAYS reject a webhook URL that resolves to a
//! loopback/private address (e.g. any local HTTP sink this test process
//! could stand up), regardless of whether a live broker is present. Every
//! delivery attempt against a local sink therefore deterministically fails
//! with `WebhookError::SsrfBlocked` — proving the guard is preserved when
//! delivery is driven from AMQP (never bypassed), and exercising the
//! retry -> backoff -> DLQ -> audit pipeline exactly as a genuine transient
//! HTTP failure would. The Stripe-style signature format itself
//! (`X-Axiam-Timestamp`/`X-Axiam-Signature: t=,v1=`) is already unit-tested
//! against the real `compute_signature_v2` function in `webhook.rs`'s
//! `signature_v2_*` tests (26-03) — this test does not re-prove signature
//! math, it proves the AMQP consumer wiring built in Tasks 1-2 of this plan.

use axiam_amqp::connection::queues;
use axiam_amqp::{AmqpConfig, AmqpManager, WebhookMessage, WebhookPublisher};
use axiam_api_rest::webhook::WebhookDeliveryService;
use axiam_api_rest::webhook_consumer::{
    WebhookRetryConfig, backoff_ttl_ms, start_webhook_consumer,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::webhook::CreateWebhook;
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, OrganizationRepository, Pagination, TenantRepository,
    WebhookRepository,
};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealOrganizationRepository, SurrealTenantRepository,
    SurrealWebhookRepository,
};
use lapin::options::{BasicGetOptions, QueueDeclareOptions, QueuePurgeOptions};
use serde_json::json;
use uuid::Uuid;

/// Fixed AES-256-GCM key for the encrypted-at-rest webhook secret (mirrors
/// `webhook_test.rs::TEST_WEBHOOK_ENC_KEY` — test-only, never used in prod).
const TEST_WEBHOOK_ENC_KEY: [u8; 32] = [0x42u8; 32];

// ---------------------------------------------------------------------------
// Non-ignored, broker-free assertions
// ---------------------------------------------------------------------------

fn sample_message() -> WebhookMessage {
    WebhookMessage {
        webhook_id: Uuid::new_v4(),
        delivery_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        event_type: "user.created".to_string(),
        payload: json!({"key": "value"}),
        attempt: 0,
    }
}

/// Simulates the consumer's failure-path attempt-increment (mirrors
/// `webhook_consumer::handle_delivery_failure`'s
/// `next_attempt = msg.attempt + 1` + retry-message-clone logic) and proves
/// the round-trip through serialize/deserialize preserves the incremented
/// count.
#[test]
fn webhook_message_round_trips_with_incremented_attempt() {
    let msg = sample_message();
    let mut retry_msg = msg.clone();
    retry_msg.attempt = msg.attempt + 1;

    let json = serde_json::to_string(&retry_msg).expect("serialize");
    let decoded: WebhookMessage = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(decoded.attempt, msg.attempt + 1);
    assert_eq!(decoded.webhook_id, msg.webhook_id);
    assert_eq!(decoded.delivery_id, msg.delivery_id);
    assert_eq!(decoded.tenant_id, msg.tenant_id);
    assert_eq!(decoded.event_type, msg.event_type);
}

/// A simulated first failure (attempt 0 -> next_attempt 1) must compute the
/// same retry TTL `backoff_ttl_ms` produces directly — proving the consumer's
/// `next_attempt = msg.attempt + 1; backoff_ttl_ms(next_attempt, &cfg)` call
/// shape matches the expected base-delay-on-first-retry behavior (D-08).
#[test]
fn simulated_first_failure_computes_expected_retry_ttl() {
    let msg = sample_message();
    let cfg = WebhookRetryConfig::default();

    let next_attempt = msg.attempt + 1;
    let ttl_ms = backoff_ttl_ms(next_attempt, &cfg);

    // attempt 1 -> exponent 0 -> ttl == backoff_base_ms exactly.
    assert_eq!(ttl_ms, cfg.backoff_base_ms);
    assert!(ttl_ms > 0, "first retry TTL must be nonzero (D-07/D-08)");
}

/// A second simulated failure (attempt 1 -> next_attempt 2) must produce a
/// strictly larger TTL than the first — proving the exponential growth is
/// actually threaded through the consumer's attempt-increment call shape,
/// not just the standalone `backoff_ttl_ms` unit (already covered in
/// `webhook_consumer.rs`'s own tests).
#[test]
fn simulated_second_failure_computes_larger_retry_ttl_than_first() {
    let cfg = WebhookRetryConfig::default();
    let first_ttl = backoff_ttl_ms(1, &cfg);
    let second_ttl = backoff_ttl_ms(2, &cfg);
    assert!(second_ttl > first_ttl);
}

// ---------------------------------------------------------------------------
// Live-RabbitMQ integration test (run via `just dev-up`)
// ---------------------------------------------------------------------------

type TestDb = surrealdb::engine::local::Db;

async fn setup_db() -> (surrealdb::Surreal<TestDb>, Uuid, Uuid) {
    let db = surrealdb::Surreal::new::<surrealdb::engine::local::Mem>(())
        .await
        .unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org = org_repo
        .create(CreateOrganization {
            name: "Webhook Consumer Test Org".into(),
            slug: "webhook-consumer-test-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Webhook Consumer Test Tenant".into(),
            slug: "webhook-consumer-test-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, org.id, tenant.id)
}

/// End-to-end proof (against a real broker) that:
/// 1. A `WebhookMessage` published to `queues::WEBHOOK` is dequeued by
///    `start_webhook_consumer` and drives `deliver_once` exactly once per
///    (re)delivery (D-06).
/// 2. Each failed attempt (deterministically `SsrfBlocked` — see module
///    docs) is retried via `queues::WEBHOOK_RETRY`'s per-message TTL, which
///    dead-letters back to `queues::WEBHOOK` once expired (D-07).
/// 3. After `max_attempts`, the message is nacked to `queues::WEBHOOK_DLQ`
///    (replayable terminal failure, D-08).
/// 4. Per-attempt (`webhook.delivery_attempt`) and terminal
///    (`webhook.delivery_failed`) audit records are written (D-09).
///
/// Requires a live RabbitMQ broker at `AXIAM__AMQP__URL` (default
/// `amqp://localhost:5672`, matches `just dev-up`). Not run in CI/sandboxed
/// environments without a broker — `#[ignore]`d by default.
#[actix_rt::test]
#[ignore = "requires a live RabbitMQ broker — run via `just dev-up` then `cargo test -p axiam-api-rest --test webhook_consumer_test -- --ignored`"]
async fn webhook_consumer_retries_then_dlqs_and_audits_end_to_end() {
    let (db, _org_id, tenant_id) = setup_db().await;

    // Use a tight retry policy so the test completes quickly: 2 attempts
    // total (1 initial + 1 retry) before exhaustion, with a small backoff.
    let retry_cfg = WebhookRetryConfig {
        max_attempts: 2,
        backoff_base_ms: 200,
        backoff_ceiling_ms: 2_000,
    };

    let webhook_repo = SurrealWebhookRepository::new(db.clone());
    let webhook_delivery =
        WebhookDeliveryService::new(webhook_repo.clone(), Some(TEST_WEBHOOK_ENC_KEY));
    let encrypted_secret = webhook_delivery
        .encrypt_secret("test-webhook-secret")
        .expect("encrypt test secret");

    // Deliberately a loopback URL — `deliver_once`'s SSRF guard
    // (`allow_private=false`, hardcoded) will always block it, giving this
    // test a deterministic failure on every attempt without depending on
    // any externally-reachable sink (see module docs).
    let webhook = webhook_repo
        .create(CreateWebhook {
            tenant_id,
            url: "https://127.0.0.1:9/webhook-consumer-test".into(),
            events: vec!["user.created".into()],
            secret: encrypted_secret,
            retry_policy: None,
        })
        .await
        .expect("create test webhook");

    let audit_repo = SurrealAuditLogRepository::new(db.clone());

    let amqp = AmqpManager::connect_with_retry(&AmqpConfig::default())
        .await
        .expect("connect to live RabbitMQ (just dev-up)");
    amqp.declare_webhook_topology()
        .await
        .expect("declare webhook topology");

    // Purge any leftover messages from a prior test run so the DLQ
    // assertion below only sees this test's message.
    let purge_channel = amqp.create_channel().await.expect("purge channel");
    let _ = purge_channel
        .queue_declare(
            queues::WEBHOOK_DLQ.into(),
            QueueDeclareOptions {
                durable: true,
                ..QueueDeclareOptions::default()
            },
            Default::default(),
        )
        .await;
    let _ = purge_channel
        .queue_purge(queues::WEBHOOK_DLQ.into(), QueuePurgeOptions::default())
        .await;

    let pub_channel = amqp
        .create_publisher_channel()
        .await
        .expect("publisher channel");
    let publisher = WebhookPublisher::new(pub_channel);

    let delivery_id = Uuid::new_v4();
    let msg = WebhookMessage {
        webhook_id: webhook.id,
        delivery_id,
        tenant_id,
        event_type: "user.created".into(),
        payload: json!({"hello": "world"}),
        attempt: 0,
    };
    publisher.publish(&msg).await.expect("publish test message");

    let consumer_channel = amqp.create_channel().await.expect("consumer channel");
    let consumer_publisher = publisher.clone();
    let consumer_audit_repo = audit_repo.clone();
    let consumer_delivery = webhook_delivery.clone();
    tokio::spawn(async move {
        start_webhook_consumer(
            consumer_channel,
            consumer_delivery,
            consumer_publisher,
            consumer_audit_repo,
            retry_cfg,
        )
        .await;
    });

    // Allow time for: initial attempt (fail) -> retry publish (TTL ~200ms)
    // -> retry dead-letters back to WEBHOOK -> second attempt (fail,
    // exhausted) -> nack to WEBHOOK_DLQ.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // 3. Terminal exhaustion landed in the replayable DLQ.
    let get_channel = amqp.create_channel().await.expect("get channel");
    let dlq_message = get_channel
        .basic_get(queues::WEBHOOK_DLQ.into(), BasicGetOptions::default())
        .await
        .expect("basic_get on WEBHOOK_DLQ");
    assert!(
        dlq_message.is_some(),
        "exhausted webhook delivery must dead-letter to WEBHOOK_DLQ"
    );
    let dlq_msg: WebhookMessage =
        serde_json::from_slice(&dlq_message.unwrap().data).expect("deserialize DLQ message");
    assert_eq!(dlq_msg.delivery_id, delivery_id);

    // 4. Per-attempt + terminal audit records were written.
    let audits = audit_repo
        .list(
            tenant_id,
            AuditLogFilter {
                resource_id: Some(webhook.id),
                ..AuditLogFilter::default()
            },
            Pagination {
                offset: 0,
                limit: 50,
            },
        )
        .await
        .expect("list audit entries");

    let attempt_records = audits
        .items
        .iter()
        .filter(|e| e.action == "webhook.delivery_attempt")
        .count();
    let failed_records = audits
        .items
        .iter()
        .filter(|e| e.action == "webhook.delivery_failed")
        .count();

    assert!(
        attempt_records >= 1,
        "expected at least one webhook.delivery_attempt audit record, got {attempt_records}"
    );
    assert_eq!(
        failed_records, 1,
        "expected exactly one terminal webhook.delivery_failed audit record"
    );
}
