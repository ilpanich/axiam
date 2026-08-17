//! Does an `AmqpManager` survive a broker restart? (CQ-B53 follow-up)
//!
//! # Why this test exists
//!
//! Every long-lived AMQP consumer in `axiam-server` is supervised by the same
//! shape of loop: on failure, call `amqp.create_channel()` on the shared
//! [`AmqpManager`] and start again (the cache-invalidation consumer at
//! `main.rs`, the webhook consumer, and the X1 reactor transport's reply
//! session). Every one of those loops rebuilds a **channel** on an existing
//! **connection**, and none of them redials.
//!
//! That is correct for the failure it was written for — a channel-level
//! exception closes one channel and leaves the connection up — and says
//! nothing about the failure an operator actually causes: restarting the
//! broker. This test answers that question with a real restart rather than an
//! argument, for both the properties AXIAM used to pass and the ones it passes
//! now.
//!
//! # Running
//!
//! Destructive: it restarts the dev broker container, so it is `#[ignore]`d
//! *and* gated behind an explicit opt-in, because "the tests restarted my
//! broker" is a surprise nobody should get from `--ignored` alone.
//!
//! ```text
//! just dev-up
//! AXIAM_TEST_ALLOW_BROKER_RESTART=1 cargo test -p axiam-amqp \
//!     --test amqp_recovery_test -- --ignored --test-threads=1 --nocapture
//! ```

use std::time::Duration;

use axiam_amqp::{AmqpConfig, AmqpManager};

/// Matches `docker/docker-compose.dev.yml`: `amqps://` on 5671, verified
/// against the private CA `scripts/gen-broker-tls.sh` minted (AMQP is
/// TLS-only — there is no plaintext listener to fall back to).
fn test_amqp_config() -> AmqpConfig {
    AmqpConfig {
        url: std::env::var("AXIAM__AMQP__URL")
            .unwrap_or_else(|_| "amqps://axiam:axiam@localhost:5671".to_string()),
        tls: axiam_amqp::AmqpTlsConfig {
            ca_cert_path: Some(
                std::env::var("AXIAM__AMQP__TLS__CA_CERT_PATH").unwrap_or_else(|_| {
                    concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../docker/.secrets/broker-tls/ca.pem"
                    )
                    .to_string()
                }),
            ),
            ..Default::default()
        },
        ..AmqpConfig::default()
    }
}

/// The container `just dev-up` stands up.
const BROKER_CONTAINER: &str = "axiam-rabbitmq";

fn restart_broker() {
    let status = std::process::Command::new("docker")
        .args(["restart", BROKER_CONTAINER])
        .status()
        .expect("docker restart must run (is docker on PATH?)");
    assert!(status.success(), "docker restart {BROKER_CONTAINER} failed");
}

/// Poll `create_channel` until it works or the deadline passes.
///
/// Returns how long recovery took. `None` means it never recovered — which is
/// the interesting answer, not an inconclusive one.
async fn time_to_usable_channel(amqp: &AmqpManager, deadline: Duration) -> Option<Duration> {
    let started = std::time::Instant::now();
    while started.elapsed() < deadline {
        if amqp.create_channel().await.is_ok() {
            return Some(started.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    None
}

/// A restarted broker must leave the shared `AmqpManager` usable again.
///
/// Before `enable_auto_recover` this failed: `ConnectionProperties::default()`
/// leaves auto-recovery **off** and the TCP reconnect backoff at *zero*
/// retries, so the `Connection` stayed dead and every supervisor loop in the
/// server span on `create_channel` until the process was restarted. The
/// symptom is the nastiest kind — the server keeps serving, the reactor
/// transport reports itself down forever, `fail_closed` registrations deny
/// every login, and nothing recovers without a restart nobody knows to do.
#[tokio::test]
#[ignore = "destructive: restarts the RabbitMQ container — needs \
            AXIAM_TEST_ALLOW_BROKER_RESTART=1"]
async fn the_shared_connection_recovers_from_a_broker_restart() {
    if std::env::var("AXIAM_TEST_ALLOW_BROKER_RESTART").as_deref() != Ok("1") {
        eprintln!("SKIPPED: set AXIAM_TEST_ALLOW_BROKER_RESTART=1 to run this");
        return;
    }

    let amqp = AmqpManager::connect_with_retry(&test_amqp_config())
        .await
        .expect("connect to live RabbitMQ (just dev-up)");
    amqp.create_channel()
        .await
        .expect("a channel before the restart");

    restart_broker();

    // Generous: the container has to come back up before the client can
    // possibly succeed, and a cold RabbitMQ takes several seconds.
    let recovered = time_to_usable_channel(&amqp, Duration::from_secs(60)).await;

    assert!(
        recovered.is_some(),
        "the shared AmqpManager never became usable again after a broker \
         restart — every supervised consumer in axiam-server would spin on \
         create_channel until the process is restarted"
    );
    eprintln!("recovered in {:?}", recovered.unwrap());

    // Recovery is not just "create_channel returns Ok" — the channel has to
    // actually carry a declare to the broker.
    let channel = amqp.create_channel().await.expect("post-restart channel");
    channel
        .queue_declare(
            "axiam.test.recovery-probe".into(),
            lapin::options::QueueDeclareOptions {
                durable: true,
                ..lapin::options::QueueDeclareOptions::default()
            },
            lapin::types::FieldTable::default(),
        )
        .await
        .expect("a recovered channel must be able to declare");
    let _ = channel
        .queue_delete(
            "axiam.test.recovery-probe".into(),
            lapin::options::QueueDeleteOptions::default(),
        )
        .await;
}
