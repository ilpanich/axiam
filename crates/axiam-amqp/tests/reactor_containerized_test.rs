//! Containerized-reactor integration test (X1 / R2.4) — the interceptor
//! chain driven over a REAL RabbitMQ broker.
//!
//! # Why this test builds its own transport
//!
//! `sdks/CONTRACT.md` §22.1's scope note is still accurate as of this test:
//! the server's lapin `ReactorTransport` is not merged (`axiam-server`
//! composes [`axiam_amqp::UnavailableReactorTransport`] instead, and every
//! dispatch resolves through the registration's failure policy — see
//! `dispatcher.rs`'s doc comment on that type). There is therefore no
//! production transport this test could exercise end-to-end.
//!
//! What it exercises instead: [`run_chain`] — the broker-free composition
//! logic (ordering, patch merge, deny short-circuit, failure-policy
//! resolution) that both the production gate and this test drive — wired to
//! a **minimal test-only RPC transport** (`LapinRpcTransport`) that talks to
//! a real broker using the exact topology primitives §22.1 defines
//! (`queue_name`, the standard AMQP `reply_to`/`correlation_id` RPC
//! convention). A `spawn_fake_reactor` task plays the reactor side: it
//! consumes from its queue and replies exactly as an SDK's `reactor_serve`
//! helper would (§22.10) — signed, correlated, decision-plus-optional-patch.
//!
//! This proves the wire-level plumbing (topology names, publish/consume,
//! signed round-trip, timeout-as-failure) survives a real broker, which a
//! broker-free unit test cannot. It does **not** prove the not-yet-merged
//! production transport, because that code does not exist yet — R2.4 records
//! this test as authored-and-passing against `LapinRpcTransport`, not
//! against `axiam-server`'s composition.
//!
//! Two things this harness deliberately does NOT do, because a real reactor
//! must not do them either (§22.1): declare the exchange, or bind a queue to
//! it. `LapinRpcTransport` publishes directly to the reactor's named queue
//! (the routing the server would normally arrange via the exchange/binding
//! it owns), and `spawn_fake_reactor` only ever declares **its own** queue —
//! the one thing an actor is allowed to touch.
//!
//! # Running
//!
//! Requires a live RabbitMQ broker at `AXIAM__AMQP__URL` (default
//! `amqp://localhost:5672`, matches `just dev-up`) — `#[ignore]`d by
//! default, same convention as `webhook_consumer_test.rs`:
//!
//! ```text
//! just dev-up
//! cargo test -p axiam-amqp --test reactor_containerized_test -- --ignored --test-threads=1
//! ```
//!
//! **This test was authored but never executed in the development
//! environment that produced it — there is no docker daemon there.** It only
//! compiles clean and lists correctly
//! (`cargo test -p axiam-amqp --test reactor_containerized_test -- --list`).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axiam_amqp::messages::CURRENT_KEY_VERSION;
use axiam_amqp::reactor::dispatcher::{DispatchFailure, ReactorTransport, run_chain};
use axiam_amqp::reactor::protocol::{ReactorEventMessage, ReactorReply, ReplyDecision, queue_name};
use axiam_amqp::{AmqpConfig, AmqpManager};
use axiam_core::models::reactor::{FailurePolicy, Reactor, ReactorMode};
use chrono::Utc;
use futures_lite::StreamExt;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, BasicPublishOptions, QueueDeclareOptions,
};
use lapin::types::FieldTable;
use lapin::{BasicProperties, Channel};
use uuid::Uuid;

/// Shared by every event/reply signed in this test — a fixed test-only key,
/// never a production secret (mirrors every other AMQP test's `MASTER`).
const MASTER: &[u8] = b"test-amqp-master-signing-key-for-reactor-containerized";

// ---------------------------------------------------------------------------
// The test-only RPC transport (see module docs for why this is not the
// production lapin transport)
// ---------------------------------------------------------------------------

struct LapinRpcTransport {
    channel: Channel,
}

impl ReactorTransport for LapinRpcTransport {
    async fn round_trip(
        &self,
        reactor: &Reactor,
        event: &'static str,
        correlation_id: Uuid,
        payload: serde_json::Value,
        timeout_ms: u32,
    ) -> Result<ReactorReply, DispatchFailure> {
        let msg = ReactorEventMessage::signed(
            MASTER,
            reactor.tenant_id,
            event,
            correlation_id,
            payload,
            timeout_ms,
            Utc::now(),
        )
        .map_err(|e| DispatchFailure::Transport(e.to_string()))?;

        // §22.1's standard AMQP RPC convention: an exclusive, auto-delete
        // reply queue named for this one round trip.
        let reply_queue = self
            .channel
            .queue_declare(
                "".into(),
                QueueDeclareOptions {
                    exclusive: true,
                    auto_delete: true,
                    ..QueueDeclareOptions::default()
                },
                FieldTable::default(),
            )
            .await
            .map_err(|e| DispatchFailure::Transport(e.to_string()))?;
        let reply_queue_name = reply_queue.name().as_str().to_string();

        let mut consumer = self
            .channel
            .basic_consume(
                reply_queue_name.clone().into(),
                format!("reply-{correlation_id}").into(),
                BasicConsumeOptions {
                    no_ack: true,
                    ..BasicConsumeOptions::default()
                },
                FieldTable::default(),
            )
            .await
            .map_err(|e| DispatchFailure::Transport(e.to_string()))?;

        let body =
            serde_json::to_vec(&msg).map_err(|e| DispatchFailure::Transport(e.to_string()))?;
        let props = BasicProperties::default()
            .with_reply_to(reply_queue_name.clone().into())
            .with_correlation_id(correlation_id.to_string().into());

        self.channel
            .basic_publish(
                "".into(),
                queue_name(reactor.tenant_id, reactor.id).into(),
                BasicPublishOptions::default(),
                &body,
                props,
            )
            .await
            .map_err(|e| DispatchFailure::Transport(e.to_string()))?
            .await
            .map_err(|e| DispatchFailure::Transport(e.to_string()))?;

        // The effective per-reactor budget `run_chain` computed — a late
        // reply past this point is exactly what §22.3 says an SDK runtime
        // SHOULD abandon rather than send.
        match tokio::time::timeout(
            Duration::from_millis(u64::from(timeout_ms)),
            consumer.next(),
        )
        .await
        {
            Ok(Some(Ok(delivery))) => serde_json::from_slice::<ReactorReply>(&delivery.data)
                .map_err(|e| DispatchFailure::Transport(e.to_string())),
            Ok(Some(Err(e))) => Err(DispatchFailure::Transport(e.to_string())),
            Ok(None) => Err(DispatchFailure::Transport("reply consumer closed".into())),
            Err(_) => Err(DispatchFailure::Timeout),
        }
    }

    async fn publish_listen(
        &self,
        _reactor: &Reactor,
        _event: &'static str,
        _payload: serde_json::Value,
    ) -> Result<(), DispatchFailure> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The fake reactor — plays the SDK `reactor_serve` side (§22.10)
// ---------------------------------------------------------------------------

/// What a fake reactor answers with, chosen by the test rather than computed
/// from the event — these are scenario scripts, not a real handler.
enum Answer {
    Allow,
    Deny(&'static str),
    Mutate(BTreeMap<String, String>),
    /// Consumes and acks the event, but never publishes a reply — the
    /// "reactor is unreachable / crashed mid-request" case that produces a
    /// timeout on the server side.
    NeverReply,
}

/// Spawn a task that declares **only its own queue** (§22.1: actors consume,
/// they never declare topology otherwise) and answers every event it
/// receives with a fixed, pre-signed `Answer`. Returns the number of events
/// it has received so far, for the deny-short-circuit assertion — a reactor
/// later in the chain than a deny must receive **zero** events.
async fn spawn_fake_reactor(
    channel: Channel,
    tenant_id: Uuid,
    reactor_id: Uuid,
    answer: Answer,
) -> Arc<AtomicUsize> {
    let hits = Arc::new(AtomicUsize::new(0));
    let queue = queue_name(tenant_id, reactor_id);

    channel
        .queue_declare(
            queue.clone().into(),
            // durable, not transient. RabbitMQ deprecated transient
            // non-exclusive queues and its recent images REFUSE the declare
            // outright ("Feature `transient_nonexcl_queues` is deprecated ...
            // not permitted anymore"), taking the whole connection down — which
            // is how this first surfaced in CI. Durable also matches how
            // axiam-amqp's own connection.rs declares every real queue, so the
            // test exercises the production shape rather than a weaker one.
            // auto_delete still cleans the queue up when the fake reactor
            // disconnects at end of test.
            QueueDeclareOptions {
                durable: true,
                auto_delete: true,
                ..QueueDeclareOptions::default()
            },
            FieldTable::default(),
        )
        .await
        .expect("fake reactor must be able to declare its own queue");

    let mut consumer = channel
        .basic_consume(
            queue.clone().into(),
            format!("fake-reactor-{reactor_id}").into(),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
        .expect("fake reactor consume");

    let hits_for_task = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Some(Ok(delivery)) = consumer.next().await {
            hits_for_task.fetch_add(1, Ordering::SeqCst);
            let event: ReactorEventMessage =
                serde_json::from_slice(&delivery.data).expect("decode event");
            delivery
                .ack(BasicAckOptions::default())
                .await
                .expect("ack event");

            let Answer::NeverReply = &answer else {
                let (decision, reason, patch) = match &answer {
                    Answer::Allow => (ReplyDecision::Allow, None, None),
                    Answer::Deny(r) => (ReplyDecision::Deny, Some((*r).to_string()), None),
                    Answer::Mutate(p) => (ReplyDecision::Mutate, None, Some(p.clone())),
                    Answer::NeverReply => unreachable!(),
                };
                let mut reply = ReactorReply {
                    correlation_id: event.correlation_id,
                    tenant_id: event.tenant_id,
                    event: event.event.clone(),
                    decision,
                    reason,
                    patch,
                    require_mfa: false,
                    key_version: CURRENT_KEY_VERSION,
                    nonce: Uuid::new_v4(),
                    issued_at: Utc::now(),
                    hmac_signature: None,
                };
                reply.sign(MASTER).expect("sign reply");

                if let Some(reply_to) = delivery.properties.reply_to().clone() {
                    channel
                        .basic_publish(
                            "".into(),
                            reply_to.as_str().into(),
                            BasicPublishOptions::default(),
                            &serde_json::to_vec(&reply).expect("serialize reply"),
                            BasicProperties::default(),
                        )
                        .await
                        .expect("publish reply")
                        .await
                        .expect("reply publish confirm");
                }
                continue;
            };
            // NeverReply: acked above, nothing published — the timeout scenario.
        }
    });

    hits
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn reactor(tenant: Uuid, event: &str, priority: i32, policy: FailurePolicy) -> Reactor {
    Reactor {
        id: Uuid::new_v4(),
        tenant_id: tenant,
        name: format!("test-reactor-{priority}"),
        description: String::new(),
        events: vec![event.to_string()],
        mode: ReactorMode::Intercept,
        priority,
        timeout_ms: 500,
        failure_policy: policy,
        enabled: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_seen_at: None,
    }
}

async fn connect() -> AmqpManager {
    AmqpManager::connect_with_retry(&AmqpConfig::default())
        .await
        .expect("connect to live RabbitMQ (just dev-up)")
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// Happy path: one interceptor, replies `allow`, over a real broker.
#[tokio::test]
#[ignore = "requires a live RabbitMQ broker — run via `just dev-up` then \
            `cargo test -p axiam-amqp --test reactor_containerized_test -- --ignored`"]
async fn happy_path_allow_round_trips_over_real_rabbitmq() {
    let amqp = connect().await;
    let tenant = Uuid::new_v4();
    let r = reactor(tenant, "login.post_auth", 0, FailurePolicy::FailClosed);

    let fake_channel = amqp.create_channel().await.unwrap();
    spawn_fake_reactor(fake_channel, tenant, r.id, Answer::Allow).await;

    let transport = LapinRpcTransport {
        channel: amqp.create_publisher_channel().await.unwrap(),
    };
    let result = run_chain(
        &transport,
        MASTER,
        &[r],
        "login.post_auth",
        serde_json::json!({"sub": "alice"}),
        Utc::now,
        || 0,
    )
    .await;

    assert!(result.outcome.permits());
    assert!(result.failures.is_empty());
}

/// A reactor that never replies produces a timeout, which a `fail_closed`
/// registration resolves to a deny — the real-broker proof of the failure
/// path (`sdks/CONTRACT.md` §22.8).
#[tokio::test]
#[ignore = "requires a live RabbitMQ broker — run via `just dev-up` then \
            `cargo test -p axiam-amqp --test reactor_containerized_test -- --ignored`"]
async fn an_unanswered_event_times_out_and_denies_under_fail_closed() {
    let amqp = connect().await;
    let tenant = Uuid::new_v4();
    let mut r = reactor(tenant, "login.post_auth", 0, FailurePolicy::FailClosed);
    r.timeout_ms = 300; // keep the ignored test fast

    let fake_channel = amqp.create_channel().await.unwrap();
    spawn_fake_reactor(fake_channel, tenant, r.id, Answer::NeverReply).await;

    let transport = LapinRpcTransport {
        channel: amqp.create_publisher_channel().await.unwrap(),
    };
    let result = run_chain(
        &transport,
        MASTER,
        &[r],
        "login.post_auth",
        serde_json::json!({"sub": "alice"}),
        Utc::now,
        || 0,
    )
    .await;

    assert!(
        !result.outcome.permits(),
        "an unreachable fail_closed reactor must deny"
    );
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].1, DispatchFailure::Timeout);
}

/// A signed reply carrying a field outside `token.pre_issue`'s `ext.`
/// allow-list is refused and takes the failure-policy path — over a real
/// broker, proving the rejection happens on the dispatcher side, not merely
/// in the broker-free unit tests.
#[tokio::test]
#[ignore = "requires a live RabbitMQ broker — run via `just dev-up` then \
            `cargo test -p axiam-amqp --test reactor_containerized_test -- --ignored`"]
async fn a_forbidden_patch_field_is_refused_over_real_rabbitmq() {
    let amqp = connect().await;
    let tenant = Uuid::new_v4();
    let r = reactor(tenant, "token.pre_issue", 0, FailurePolicy::FailClosed);

    let mut forbidden_patch = BTreeMap::new();
    forbidden_patch.insert("sub".to_string(), "root".to_string());

    let fake_channel = amqp.create_channel().await.unwrap();
    spawn_fake_reactor(fake_channel, tenant, r.id, Answer::Mutate(forbidden_patch)).await;

    let transport = LapinRpcTransport {
        channel: amqp.create_publisher_channel().await.unwrap(),
    };
    let result = run_chain(
        &transport,
        MASTER,
        &[r],
        "token.pre_issue",
        serde_json::json!({"sub": "alice"}),
        Utc::now,
        || 0,
    )
    .await;

    assert!(
        !result.outcome.permits(),
        "a reactor must not be able to set 'sub', even correctly signed"
    );
}

/// Two interceptors in priority order, each mutating `token.pre_issue`'s
/// `ext.` namespace: the merged patch carries both fields, and the
/// higher-priority reactor's value wins on the shared key.
#[tokio::test]
#[ignore = "requires a live RabbitMQ broker — run via `just dev-up` then \
            `cargo test -p axiam-amqp --test reactor_containerized_test -- --ignored`"]
async fn a_priority_chain_merges_patches_with_later_winning_over_real_rabbitmq() {
    let amqp = connect().await;
    let tenant = Uuid::new_v4();
    let first = reactor(tenant, "token.pre_issue", 1, FailurePolicy::FailOpen);
    let second = reactor(tenant, "token.pre_issue", 2, FailurePolicy::FailOpen);

    let mut first_patch = BTreeMap::new();
    first_patch.insert("ext.department".to_string(), "eng".to_string());
    first_patch.insert("ext.shared".to_string(), "from-first".to_string());
    let mut second_patch = BTreeMap::new();
    second_patch.insert("ext.cost_center".to_string(), "42".to_string());
    second_patch.insert("ext.shared".to_string(), "from-second".to_string());

    let first_channel = amqp.create_channel().await.unwrap();
    spawn_fake_reactor(first_channel, tenant, first.id, Answer::Mutate(first_patch)).await;
    let second_channel = amqp.create_channel().await.unwrap();
    spawn_fake_reactor(
        second_channel,
        tenant,
        second.id,
        Answer::Mutate(second_patch),
    )
    .await;

    let transport = LapinRpcTransport {
        channel: amqp.create_publisher_channel().await.unwrap(),
    };
    let result = run_chain(
        &transport,
        MASTER,
        &[first, second],
        "token.pre_issue",
        serde_json::json!({}),
        Utc::now,
        || 0,
    )
    .await;

    match result.outcome {
        axiam_core::models::reactor::ReactorOutcome::Mutate { patch } => {
            assert_eq!(patch["ext.department"], "eng");
            assert_eq!(patch["ext.cost_center"], "42");
            assert_eq!(
                patch["ext.shared"], "from-second",
                "the higher-priority (later) reactor must win the shared key"
            );
        }
        other => panic!("expected a mutation, got {other:?}"),
    }
}

/// The first reactor's deny short-circuits the chain: the second, later
/// reactor must receive ZERO events — asserted against a real queue, not a
/// mocked call count.
#[tokio::test]
#[ignore = "requires a live RabbitMQ broker — run via `just dev-up` then \
            `cargo test -p axiam-amqp --test reactor_containerized_test -- --ignored`"]
async fn a_deny_short_circuits_the_chain_over_real_rabbitmq() {
    let amqp = connect().await;
    let tenant = Uuid::new_v4();
    let first = reactor(tenant, "login.post_auth", 1, FailurePolicy::FailClosed);
    let second = reactor(tenant, "login.post_auth", 2, FailurePolicy::FailClosed);

    let first_channel = amqp.create_channel().await.unwrap();
    spawn_fake_reactor(
        first_channel,
        tenant,
        first.id,
        Answer::Deny("embargoed region"),
    )
    .await;
    let second_channel = amqp.create_channel().await.unwrap();
    let second_hits = spawn_fake_reactor(second_channel, tenant, second.id, Answer::Allow).await;

    let transport = LapinRpcTransport {
        channel: amqp.create_publisher_channel().await.unwrap(),
    };
    let result = run_chain(
        &transport,
        MASTER,
        &[first, second],
        "login.post_auth",
        serde_json::json!({"sub": "alice"}),
        Utc::now,
        || 0,
    )
    .await;

    assert!(!result.outcome.permits());

    // Give the second reactor's consumer task a moment to have observed
    // anything it was going to observe, then assert it saw nothing at all —
    // not merely that it did not reply.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        second_hits.load(Ordering::SeqCst),
        0,
        "nothing later in the chain than a deny should ever be dispatched to"
    );
}
