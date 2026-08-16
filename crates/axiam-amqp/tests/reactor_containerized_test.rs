//! Containerized-reactor integration test (X1 / R2.4) — the interceptor
//! chain driven over a REAL RabbitMQ broker, through the REAL transport.
//!
//! # What this exercises
//!
//! [`LapinReactorTransport`] — the production transport `axiam-server`
//! composes — wired to [`run_chain`], against a live broker. Both halves of
//! the round trip are real: the server side declares the §22.1 topology,
//! signs the event, publishes it and correlates the reply; the reactor side is
//! a `spawn_fake_reactor` task that consumes and replies exactly as an SDK's
//! `reactor_serve` helper would (§22.10) — signed, correlated,
//! decision-plus-optional-patch.
//!
//! What that proves over the broker-free unit tests in `dispatcher.rs`: the
//! topology names, the publish/consume path, the signed round trip, the
//! reply-queue correlation, and timeout-as-failure all survive a real broker.
//!
//! # The one asymmetry, and why it is the point
//!
//! **The fake reactor declares nothing.** §22.1 is explicit that actors
//! consume and never declare topology — a reactor that can bind is a reactor
//! that can bind itself to `*.token.pre_issue` and read another tenant's
//! issuance events. So each test calls
//! [`LapinReactorTransport::declare_reactor_topology`] (the operation the
//! server owns, and the one the admin registration path should call at
//! create/update time) and the fake reactor only `basic_consume`s the queue it
//! finds. A regression that moved the declare back to the actor would fail
//! these tests at the consume, which is exactly the failure to want.
//!
//! (Historical note: before the transport was merged this file carried its own
//! minimal `LapinRpcTransport`, because there was no production transport to
//! exercise. It was also authored blind — "never executed in the development
//! environment that produced it, there is no docker daemon there, it only
//! compiles clean and lists correctly". Its first real execution was
//! 2026-08-16 and it did not connect: see `test_amqp_config` below for the two
//! broker-config faults that blind authoring left behind.)
//!
//! # Running
//!
//! Requires a live RabbitMQ broker at `AXIAM__AMQP__URL` (default
//! `amqp://axiam:axiam@localhost:5672`, matches `just dev-up`) — `#[ignore]`d
//! by default, same convention as `webhook_consumer_test.rs`:
//!
//! ```text
//! just dev-up
//! cargo test -p axiam-amqp --test reactor_containerized_test -- --ignored --test-threads=1
//! ```

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axiam_amqp::messages::CURRENT_KEY_VERSION;
use axiam_amqp::reactor::dispatcher::{DispatchFailure, ReactorTransport, run_chain};
use axiam_amqp::reactor::protocol::{
    REACTOR_EXCHANGE, ReactorEventMessage, ReactorReply, ReplyDecision, queue_name, routing_key,
};
use axiam_amqp::reactor::transport::LapinReactorTransport;
use axiam_amqp::{AmqpConfig, AmqpManager};
use axiam_core::models::reactor::{FailurePolicy, Reactor, ReactorMode};
use chrono::Utc;
use futures_lite::StreamExt;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, BasicGetOptions, BasicPublishOptions,
    QueueDeclareOptions, QueueDeleteOptions,
};
use lapin::types::FieldTable;
use lapin::{BasicProperties, Channel};
use uuid::Uuid;

/// Shared by every event/reply signed in this test — a fixed test-only key,
/// never a production secret (mirrors every other AMQP test's `MASTER`).
const MASTER: &[u8] = b"test-amqp-master-signing-key-for-reactor-containerized";

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

/// Spawn a task that consumes the queue **the server declared** (§22.1: actors
/// consume, they never declare topology) and answers every event it receives
/// with a fixed, pre-signed `Answer`. Returns the number of events it has
/// received so far, for the deny-short-circuit assertion — a reactor later in
/// the chain than a deny must receive **zero** events.
async fn spawn_fake_reactor(
    channel: Channel,
    tenant_id: Uuid,
    reactor_id: Uuid,
    answer: Answer,
) -> Arc<AtomicUsize> {
    let hits = Arc::new(AtomicUsize::new(0));
    let queue = queue_name(tenant_id, reactor_id);

    // No `queue_declare` here, deliberately — see the module docs. If the
    // server-side declare regressed, this consume is what fails.
    let mut consumer = channel
        .basic_consume(
            queue.clone().into(),
            format!("fake-reactor-{reactor_id}").into(),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
        .expect("fake reactor consume (the SERVER must have declared this queue)");

    let hits_for_task = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Some(Ok(delivery)) = consumer.next().await {
            hits_for_task.fetch_add(1, Ordering::SeqCst);
            let event: ReactorEventMessage =
                serde_json::from_slice(&delivery.data).expect("decode event");
            assert!(
                event.verify(MASTER),
                "the server must sign every event it publishes (§22.2)"
            );
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

/// Broker URL for the test. `AmqpConfig::default()` is NOT usable here and the
/// header's claim that it "matches `just dev-up`" was wrong on two counts —
/// neither was caught because this file had never been executed:
///
///  * its `url` is `amqp://localhost:5672` with no credentials, so it dials as
///    `guest`, while `docker/docker-compose.dev.yml` provisions the broker with
///    `RABBITMQ_DEFAULT_USER/PASS = axiam/axiam` (and `guest` is refused
///    non-locally by RabbitMQ anyway);
///  * `allow_plaintext` defaults to `false`, and `AmqpConfig::validate` turns a
///    plaintext `amqp://` URL under that setting into `AmqpError::Config`,
///    which `connect_with_retry` deliberately does NOT retry — so the test
///    failed before dialling, with a message about TLS rather than about the
///    broker.
///
/// `AXIAM__AMQP__URL` is honoured (that part of the header was the intent), and
/// the default now matches what `just dev-up` actually stands up.
fn test_amqp_config() -> AmqpConfig {
    AmqpConfig {
        url: std::env::var("AXIAM__AMQP__URL")
            .unwrap_or_else(|_| "amqp://axiam:axiam@localhost:5672".to_string()),
        // A local throwaway dev broker over loopback. The production guard is
        // exactly right; this is the documented escape hatch for it.
        allow_plaintext: true,
        ..AmqpConfig::default()
    }
}

/// Connect and bring up the production transport, waiting for its supervisor
/// to establish a session.
///
/// `LapinReactorTransport::start` is infallible by design — until the first
/// session exists every dispatch fails as a transport error and the
/// registration's failure policy decides — so a test that dispatched
/// immediately would be racing the supervisor and would "pass" a fail-open
/// scenario for the wrong reason.
async fn connected_transport() -> (Arc<AmqpManager>, LapinReactorTransport) {
    let amqp = Arc::new(
        AmqpManager::connect_with_retry(&test_amqp_config())
            .await
            .expect("connect to live RabbitMQ (just dev-up)"),
    );
    let transport = LapinReactorTransport::start(Arc::clone(&amqp), MASTER.to_vec());

    for _ in 0..100 {
        if transport.is_connected() {
            return (amqp, transport);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the reactor transport did not establish a broker session within 2s");
}

/// Delete the durable queues this test created.
///
/// Reactor queues are durable and not auto-delete on purpose — a registration
/// outlives its actor's restarts — so an integration test that generates fresh
/// UUIDs on every run would otherwise leave a queue behind each time. The
/// production reclaim path is `x-expires` (seven idle days), which is the
/// right bound for a deployment and far too slow for a dev broker.
async fn cleanup(channel: &Channel, tenant: Uuid, reactor_ids: &[Uuid]) {
    for id in reactor_ids {
        let _ = channel
            .queue_delete(
                queue_name(tenant, *id).into(),
                QueueDeleteOptions::default(),
            )
            .await;
    }
}

/// Take one message off a queue, retrying briefly.
///
/// A publish is confirmed by the broker before it is *routed to and visible
/// on* a queue, so a single `basic_get` immediately after one is a race. The
/// retry is only for the positive case; [`expect_empty`] is the negative one
/// and must not retry, or it would just be a slow way to observe the same
/// thing.
async fn get_one(channel: &Channel, queue: &str) -> Option<lapin::message::BasicGetMessage> {
    for _ in 0..50 {
        match channel
            .basic_get(queue.into(), BasicGetOptions { no_ack: true })
            .await
        {
            Ok(Some(msg)) => return Some(msg),
            Ok(None) => tokio::time::sleep(Duration::from_millis(20)).await,
            Err(_) => return None,
        }
    }
    None
}

/// Assert a queue receives nothing, having given the broker time to have
/// delivered it if it were going to.
async fn expect_empty(channel: &Channel, queue: &str, why: &str) {
    tokio::time::sleep(Duration::from_millis(250)).await;
    let got = channel
        .basic_get(queue.into(), BasicGetOptions { no_ack: true })
        .await
        .expect("basic_get");
    assert!(got.is_none(), "{why}");
}

/// Open a channel, retrying while the broker settles.
///
/// A restarted RabbitMQ accepts a TCP connection before it is ready to serve,
/// and lapin's auto-recovery races that: there is a window where the transport
/// has a session but a *fresh* `create_channel` still fails with
/// `CONNECTION_FORCED`. `axiam-server`'s supervisors all retry through this
/// window; this helper is the test harness doing the same, and it is not
/// papering over anything — the assertion that matters is that a dispatch
/// eventually round-trips.
async fn channel_with_retry(amqp: &AmqpManager) -> Channel {
    let mut last = None;
    for _ in 0..150 {
        match amqp.create_channel().await {
            Ok(channel) => return channel,
            Err(e) => {
                last = Some(e);
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
    panic!("no usable channel after the broker settled: {last:?}");
}

/// Publish a bare message through the reactor topic exchange, which is how a
/// binding is observed: a bound queue receives it, an unbound one does not.
async fn publish_through_exchange(channel: &Channel, tenant: Uuid, event: &str) {
    channel
        .basic_publish(
            REACTOR_EXCHANGE.into(),
            routing_key(tenant, event).into(),
            BasicPublishOptions::default(),
            b"binding-probe",
            BasicProperties::default(),
        )
        .await
        .expect("publish through the reactor exchange")
        .await
        .expect("publish confirm");
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// The server declares the exchange, the queue and the bindings; the actor
/// declares nothing (§22.1). Asserted with a **passive** declare, which
/// succeeds only if the queue already exists and fails otherwise — so this
/// checks the server created it rather than creating it itself.
#[tokio::test]
#[ignore = "requires a live RabbitMQ broker — run via `just dev-up` then \
            `cargo test -p axiam-amqp --test reactor_containerized_test -- --ignored`"]
async fn the_server_declares_the_reactor_queue_and_the_actor_declares_nothing() {
    let (amqp, transport) = connected_transport().await;
    let tenant = Uuid::new_v4();
    let r = reactor(tenant, "token.pre_issue", 0, FailurePolicy::FailOpen);

    let probe = amqp.create_channel().await.unwrap();
    let before = probe
        .queue_declare(
            queue_name(tenant, r.id).into(),
            QueueDeclareOptions {
                passive: true,
                ..QueueDeclareOptions::default()
            },
            FieldTable::default(),
        )
        .await;
    assert!(
        before.is_err(),
        "nothing should have declared this queue yet"
    );

    transport
        .declare_reactor_topology(&r)
        .await
        .expect("the server declares the reactor's topology");

    // A passive declare fails the CHANNEL when the queue is missing, so this
    // needs a fresh one after the expected failure above.
    let probe = amqp.create_channel().await.unwrap();
    probe
        .queue_declare(
            queue_name(tenant, r.id).into(),
            QueueDeclareOptions {
                passive: true,
                ..QueueDeclareOptions::default()
            },
            FieldTable::default(),
        )
        .await
        .expect("the queue must exist once the server has declared it");

    cleanup(&probe, tenant, &[r.id]).await;
}

/// A `listen` publish reaches the reactor and carries **no reply address**.
///
/// The missing `reply_to` is the wire-level statement of `ReactorMode::Listen`'s
/// contract — "a listener cannot affect any outcome". A listener that was handed
/// a reply queue would be one `basic_publish` away from answering, and the only
/// thing standing between it and an accepted answer would be the dispatcher
/// declining to wait.
///
/// Note what this does *not* claim: nothing in `axiam-server` calls
/// `publish_listen` yet (`run_chain` filters listeners out and the gate returns
/// early once the interceptor list is empty), which is why the REST layer
/// refuses `listen` registrations. This test covers the transport half so that
/// whoever wires the fan-out inherits a proven publish rather than an untested
/// one.
#[tokio::test]
#[ignore = "requires a live RabbitMQ broker — run via `just dev-up` then \
            `cargo test -p axiam-amqp --test reactor_containerized_test -- --ignored`"]
async fn a_listen_publish_reaches_the_reactor_carrying_no_reply_address() {
    let (amqp, transport) = connected_transport().await;
    let tenant = Uuid::new_v4();
    let mut r = reactor(tenant, "token.pre_issue", 0, FailurePolicy::FailOpen);
    r.mode = ReactorMode::Listen;

    transport.declare_reactor_topology(&r).await.unwrap();
    transport
        .publish_listen(&r, "token.pre_issue", serde_json::json!({"sub": "alice"}))
        .await
        .expect("a listen publish must succeed over a live broker");

    let probe = amqp.create_channel().await.unwrap();
    let queue = queue_name(tenant, r.id);
    let msg = get_one(&probe, &queue)
        .await
        .expect("the listener's queue must receive the event");

    let event: ReactorEventMessage =
        serde_json::from_slice(&msg.delivery.data).expect("decode listen event");
    cleanup(&probe, tenant, &[r.id]).await;

    assert!(
        event.verify(MASTER),
        "a listen event is signed exactly like an interception (§22.2)"
    );
    assert_eq!(event.event, "token.pre_issue");
    assert_eq!(event.tenant_id, tenant);
    assert!(
        msg.delivery.properties.reply_to().is_none(),
        "a listener must not be handed a reply address — it cannot affect an outcome"
    );
}

/// Removing an event from a registration **unbinds** it.
///
/// The declare path is self-correcting in both directions, and this is the
/// direction that is easy to leave out: an operator who removes
/// `login.post_auth` from a registration has un-subscribed from it, and a
/// binding left behind would keep delivering the event they just said they did
/// not want. Observed the only way a binding can be — by publishing through the
/// exchange and seeing whether the queue receives it.
#[tokio::test]
#[ignore = "requires a live RabbitMQ broker — run via `just dev-up` then \
            `cargo test -p axiam-amqp --test reactor_containerized_test -- --ignored`"]
async fn removing_an_event_from_a_registration_unbinds_it() {
    let (amqp, transport) = connected_transport().await;
    let tenant = Uuid::new_v4();
    let mut r = reactor(tenant, "token.pre_issue", 0, FailurePolicy::FailOpen);
    r.events = vec!["token.pre_issue".into(), "login.post_auth".into()];

    transport.declare_reactor_topology(&r).await.unwrap();

    let probe = amqp.create_publisher_channel().await.unwrap();
    let queue = queue_name(tenant, r.id);

    publish_through_exchange(&probe, tenant, "login.post_auth").await;
    assert!(
        get_one(&probe, &queue).await.is_some(),
        "a registered event must be bound to the reactor's queue"
    );

    // The operator drops `login.post_auth` from the registration.
    r.events = vec!["token.pre_issue".into()];
    transport
        .declare_reactor_topology(&r)
        .await
        .expect("re-declaring a changed registration");

    publish_through_exchange(&probe, tenant, "login.post_auth").await;
    expect_empty(
        &probe,
        &queue,
        "an un-subscribed event must no longer reach the reactor",
    )
    .await;

    // …and the binding that survived still works, so the unbind was surgical
    // rather than a queue-wide reset.
    publish_through_exchange(&probe, tenant, "token.pre_issue").await;
    let survived = get_one(&probe, &queue).await.is_some();
    cleanup(&probe, tenant, &[r.id]).await;
    assert!(
        survived,
        "removing one event must not unbind the ones that remain"
    );
}

/// Losing the broker session **wakes an in-flight dispatch** instead of
/// stranding it until its timeout.
///
/// The reactor here has a 5 s budget and nothing consuming its queue, so if
/// `abandon_all_pending` did not run the round trip would sit for the full 5 s
/// and then report a `Timeout`. Coming back in a fraction of that, with a
/// transport error rather than a timeout, is the assertion — and the
/// distinction matters downstream: `§22.8` resolves both through the failure
/// policy, but only one of them is honest about what happened, and a fail-open
/// login should not spend five seconds discovering the broker is gone.
///
/// **What this deliberately does not assert is recovery**, and the reason is
/// not that recovery is missing — `AmqpManager` dials with
/// `enable_auto_recover`, and
/// [`a_dispatch_still_round_trips_after_a_broker_restart`] proves a whole round
/// trip survives a real broker restart. It is that lapin recovers *recoverable*
/// errors, and a deliberate client-side `Connection::close` is not one: it is
/// an instruction, not a fault, and a client library that reconnected after
/// being told to disconnect would be broken. So this test gets a permanently
/// dead session, which is exactly what it wants — an unambiguous teardown to
/// assert against.
#[tokio::test]
#[ignore = "requires a live RabbitMQ broker — run via `just dev-up` then \
            `cargo test -p axiam-amqp --test reactor_containerized_test -- --ignored`"]
async fn losing_the_broker_session_wakes_an_in_flight_dispatch() {
    let (amqp, transport) = connected_transport().await;
    let tenant = Uuid::new_v4();
    let r = reactor(tenant, "login.post_auth", 0, FailurePolicy::FailClosed);

    transport.declare_reactor_topology(&r).await.unwrap();
    // No fake reactor at all: nothing will ever reply to this.

    let dispatching = transport.clone();
    let dispatched = r.clone();
    let in_flight = tokio::spawn(async move {
        let started = std::time::Instant::now();
        let result = dispatching
            .round_trip(
                &dispatched,
                "login.post_auth",
                Uuid::new_v4(),
                serde_json::json!({"sub": "alice"}),
                5_000,
            )
            .await;
        (started.elapsed(), result)
    });

    // Let the publish land, then take the session away underneath it.
    tokio::time::sleep(Duration::from_millis(200)).await;
    amqp.connection()
        .close(200, "test: simulated broker loss".into())
        .await
        .expect("close the connection");

    let (elapsed, result) = in_flight.await.expect("the dispatch task must not panic");

    assert!(
        matches!(result, Err(DispatchFailure::Transport(_))),
        "a lost session is a transport failure, not a timeout — got {result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(4),
        "the dispatch must be woken when the session dies, not left to time out \
         (took {elapsed:?} of a 5s budget)"
    );

    // The transport also stops advertising a session it no longer has, so a
    // later dispatch fails fast instead of publishing into a dead channel.
    for _ in 0..100 {
        if !transport.is_connected() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        !transport.is_connected(),
        "the transport must report itself down once its session is gone"
    );

    // This test killed its own connection, so cleanup needs a fresh one.
    let fresh = AmqpManager::connect_with_retry(&test_amqp_config())
        .await
        .expect("reconnect for cleanup");
    cleanup(&fresh.create_channel().await.unwrap(), tenant, &[r.id]).await;
}

/// A dispatch still round-trips **after the broker has been restarted**.
///
/// This is the test that earns `enable_auto_recover`, and it is here rather
/// than in `amqp_recovery_test.rs` because the risk it covers is specific to
/// this transport. Auto-recovery replays the consumer topology onto the new
/// connection, and this transport's reply queue is **server-named** (`""`) and
/// exclusive. If a replay produced a differently-named queue while `Shared`
/// still advertised the old name, every subsequent round trip would publish a
/// `reply_to` nobody consumes, and every dispatch would time out — a failure
/// mode strictly worse than the one auto-recovery was turned on to fix,
/// because the transport would report itself perfectly healthy throughout.
///
/// Destructive, so it carries the same opt-in as `amqp_recovery_test.rs`.
#[tokio::test]
#[ignore = "destructive: restarts the RabbitMQ container — needs \
            AXIAM_TEST_ALLOW_BROKER_RESTART=1"]
async fn a_dispatch_still_round_trips_after_a_broker_restart() {
    if std::env::var("AXIAM_TEST_ALLOW_BROKER_RESTART").as_deref() != Ok("1") {
        eprintln!("SKIPPED: set AXIAM_TEST_ALLOW_BROKER_RESTART=1 to run this");
        return;
    }

    let (amqp, transport) = connected_transport().await;
    let tenant = Uuid::new_v4();
    let r = reactor(tenant, "login.post_auth", 0, FailurePolicy::FailClosed);

    // Prove the transport works before the restart, so a failure afterwards is
    // unambiguously about the restart.
    transport.declare_reactor_topology(&r).await.unwrap();
    spawn_fake_reactor(
        amqp.create_channel().await.unwrap(),
        tenant,
        r.id,
        Answer::Allow,
    )
    .await;
    let before = run_chain(
        &transport,
        MASTER,
        std::slice::from_ref(&r),
        "login.post_auth",
        serde_json::json!({"sub": "alice"}),
        Utc::now,
        || 0,
    )
    .await;
    assert!(before.outcome.permits(), "sanity: works before the restart");

    let status = std::process::Command::new("docker")
        .args(["restart", "axiam-rabbitmq"])
        .status()
        .expect("docker restart must run");
    assert!(status.success(), "docker restart axiam-rabbitmq failed");

    // A restarted broker accepts connections before it can serve them, so the
    // transport's supervisor legitimately *flaps* for a few seconds: it gets a
    // session, the broker forces it closed, it backs off and retries. The
    // assertion is therefore "a dispatch eventually round-trips", not "the
    // first attempt after `is_connected()` works" — and whether recovery comes
    // from lapin's auto-recovery or from this transport's own supervisor is
    // deliberately not asserted. What must hold is that it comes.
    let mut declared = false;
    for _ in 0..300 {
        if transport.is_connected() && transport.declare_reactor_topology(&r).await.is_ok() {
            declared = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        declared,
        "the transport never re-established a usable session after the broker restart"
    );

    // The actor reconnects too — a real reactor's SDK runtime does this, and
    // the queue is durable so it is still there.
    spawn_fake_reactor(channel_with_retry(&amqp).await, tenant, r.id, Answer::Allow).await;

    let mut after = None;
    for _ in 0..60 {
        let result = run_chain(
            &transport,
            MASTER,
            std::slice::from_ref(&r),
            "login.post_auth",
            serde_json::json!({"sub": "alice"}),
            Utc::now,
            || 0,
        )
        .await;
        let permitted = result.outcome.permits();
        after = Some(result);
        if permitted {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    cleanup(&channel_with_retry(&amqp).await, tenant, &[r.id]).await;
    let after = after.expect("at least one dispatch attempt");
    assert!(
        after.outcome.permits(),
        "a dispatch must round-trip after a broker restart — got {:?} with failures {:?}. \
         A persistent Timeout here would mean the reply queue the transport advertises is \
         not the one it consumes, which is the specific hazard of replaying a server-named \
         exclusive queue.",
        after.outcome,
        after.failures
    );
}

/// Happy path: one interceptor, replies `allow`, over a real broker.
#[tokio::test]
#[ignore = "requires a live RabbitMQ broker — run via `just dev-up` then \
            `cargo test -p axiam-amqp --test reactor_containerized_test -- --ignored`"]
async fn happy_path_allow_round_trips_over_real_rabbitmq() {
    let (amqp, transport) = connected_transport().await;
    let tenant = Uuid::new_v4();
    let r = reactor(tenant, "login.post_auth", 0, FailurePolicy::FailClosed);

    transport.declare_reactor_topology(&r).await.unwrap();
    let fake_channel = amqp.create_channel().await.unwrap();
    spawn_fake_reactor(fake_channel, tenant, r.id, Answer::Allow).await;

    let result = run_chain(
        &transport,
        MASTER,
        std::slice::from_ref(&r),
        "login.post_auth",
        serde_json::json!({"sub": "alice"}),
        Utc::now,
        || 0,
    )
    .await;

    cleanup(&amqp.create_channel().await.unwrap(), tenant, &[r.id]).await;
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
    let (amqp, transport) = connected_transport().await;
    let tenant = Uuid::new_v4();
    let mut r = reactor(tenant, "login.post_auth", 0, FailurePolicy::FailClosed);
    r.timeout_ms = 300; // keep the ignored test fast

    transport.declare_reactor_topology(&r).await.unwrap();
    let fake_channel = amqp.create_channel().await.unwrap();
    spawn_fake_reactor(fake_channel, tenant, r.id, Answer::NeverReply).await;

    let started = std::time::Instant::now();
    let result = run_chain(
        &transport,
        MASTER,
        std::slice::from_ref(&r),
        "login.post_auth",
        serde_json::json!({"sub": "alice"}),
        Utc::now,
        || 0,
    )
    .await;
    let elapsed = started.elapsed();

    cleanup(&amqp.create_channel().await.unwrap(), tenant, &[r.id]).await;
    assert!(
        !result.outcome.permits(),
        "an unreachable fail_closed reactor must deny"
    );
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].1, DispatchFailure::Timeout);

    // `timeout_ms` bounds the WHOLE round trip, not merely the wait for a
    // reply. The declare and the publish are broker RPCs, and since
    // `AmqpManager` dials with `enable_auto_recover` a channel under recovery
    // makes them *wait* rather than fail — so leaving them outside the budget
    // would make a recovering broker an unbounded login. `run_chain` bounds
    // the chain only between reactors, so nothing else would catch it.
    assert!(
        elapsed < Duration::from_millis(2_000),
        "a 300ms reactor budget must bound the whole round trip, not just the \
         reply wait (took {elapsed:?})"
    );
}

/// A signed reply carrying a field outside `token.pre_issue`'s `ext.`
/// allow-list is refused and takes the failure-policy path — over a real
/// broker, proving the rejection happens on the dispatcher side, not merely
/// in the broker-free unit tests.
#[tokio::test]
#[ignore = "requires a live RabbitMQ broker — run via `just dev-up` then \
            `cargo test -p axiam-amqp --test reactor_containerized_test -- --ignored`"]
async fn a_forbidden_patch_field_is_refused_over_real_rabbitmq() {
    let (amqp, transport) = connected_transport().await;
    let tenant = Uuid::new_v4();
    let r = reactor(tenant, "token.pre_issue", 0, FailurePolicy::FailClosed);

    let mut forbidden_patch = BTreeMap::new();
    forbidden_patch.insert("sub".to_string(), "root".to_string());

    transport.declare_reactor_topology(&r).await.unwrap();
    let fake_channel = amqp.create_channel().await.unwrap();
    spawn_fake_reactor(fake_channel, tenant, r.id, Answer::Mutate(forbidden_patch)).await;

    let result = run_chain(
        &transport,
        MASTER,
        std::slice::from_ref(&r),
        "token.pre_issue",
        serde_json::json!({"sub": "alice"}),
        Utc::now,
        || 0,
    )
    .await;

    cleanup(&amqp.create_channel().await.unwrap(), tenant, &[r.id]).await;
    assert!(
        !result.outcome.permits(),
        "a reactor must not be able to set 'sub', even correctly signed"
    );
}

/// Two interceptors in priority order, each mutating `token.pre_issue`'s
/// `ext.` namespace: the merged patch carries both fields, and the
/// higher-priority reactor's value wins on the shared key.
///
/// This is also the scenario that pins **why an interception is addressed to
/// the reactor's queue rather than fanned out through the topic exchange**:
/// both reactors are registered for the same `(tenant, event)`, so a publish
/// through the exchange would deliver one correlation_id to both and let
/// whichever answered first be consumed as the other's reply.
#[tokio::test]
#[ignore = "requires a live RabbitMQ broker — run via `just dev-up` then \
            `cargo test -p axiam-amqp --test reactor_containerized_test -- --ignored`"]
async fn a_priority_chain_merges_patches_with_later_winning_over_real_rabbitmq() {
    let (amqp, transport) = connected_transport().await;
    let tenant = Uuid::new_v4();
    let first = reactor(tenant, "token.pre_issue", 1, FailurePolicy::FailOpen);
    let second = reactor(tenant, "token.pre_issue", 2, FailurePolicy::FailOpen);

    let mut first_patch = BTreeMap::new();
    first_patch.insert("ext.department".to_string(), "eng".to_string());
    first_patch.insert("ext.shared".to_string(), "from-first".to_string());
    let mut second_patch = BTreeMap::new();
    second_patch.insert("ext.cost_center".to_string(), "42".to_string());
    second_patch.insert("ext.shared".to_string(), "from-second".to_string());

    transport.declare_reactor_topology(&first).await.unwrap();
    transport.declare_reactor_topology(&second).await.unwrap();
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

    let ids = [first.id, second.id];
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

    cleanup(&amqp.create_channel().await.unwrap(), tenant, &ids).await;
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
    let (amqp, transport) = connected_transport().await;
    let tenant = Uuid::new_v4();
    let first = reactor(tenant, "login.post_auth", 1, FailurePolicy::FailClosed);
    let second = reactor(tenant, "login.post_auth", 2, FailurePolicy::FailClosed);

    transport.declare_reactor_topology(&first).await.unwrap();
    transport.declare_reactor_topology(&second).await.unwrap();
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

    let ids = [first.id, second.id];
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
    let hits = second_hits.load(Ordering::SeqCst);
    cleanup(&amqp.create_channel().await.unwrap(), tenant, &ids).await;
    assert_eq!(
        hits, 0,
        "nothing later in the chain than a deny should ever be dispatched to"
    );
}
