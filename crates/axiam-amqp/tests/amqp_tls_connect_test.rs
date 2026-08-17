//! The `amqps://` dial path, without a broker (A6).
//!
//! Both tests here exist because the same fault produced *no output at all*:
//! CI ran the containerized reactor suite against the first TLS broker this
//! project ever booted, printed `running 10 tests`, and was killed ten minutes
//! later having printed nothing else. No panic in the log, no failing
//! assertion, no error — the job simply stopped.
//!
//! The cause was a rustls `CryptoProvider` panic on lapin's `lapin-io-loop`
//! thread (see [`axiam_amqp`]'s `connection::ensure_crypto_provider`). Two
//! independent defects turned it into silence:
//!
//! 1. Nothing installed the process-level provider outside `axiam-server`'s
//!    `main()`, so every other process that dialled `amqps://` panicked — and
//!    a panic on lapin's own thread is not a panic the caller ever sees.
//! 2. `Connection::connect_with_config` has no timeout, so the caller awaited
//!    a future that the dead thread would have resolved, forever. The retry
//!    budget could not help: there was no error to retry.
//!
//! Neither test needs a broker, which is the point — the fault they cover is
//! in the client, and a test that needed a live broker would have been
//! `#[ignore]`d and would not have caught it.

use std::time::Duration;

use axiam_amqp::{AmqpConfig, AmqpManager, AmqpTlsConfig};
use tokio::net::TcpListener;

/// Bind a listener that completes the TCP handshake and then says nothing at
/// all — the shape a published-but-unserved port has, and what a broker whose
/// TLS listener failed to bind looks like from the outside.
///
/// The accepted socket is deliberately held rather than dropped: closing it
/// would produce an EOF and a prompt error, which is the case that was never
/// in doubt.
async fn silent_tls_port() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });
    (port, task)
}

fn config_for(port: u16, connect_timeout_ms: u64) -> AmqpConfig {
    AmqpConfig {
        url: format!("amqps://guest:guest@127.0.0.1:{port}"),
        // System roots: this peer has no certificate to verify anyway, and the
        // test is about what happens *before* verification could matter.
        tls: AmqpTlsConfig::default(),
        max_retries: 0,
        connect_timeout_ms,
        ..AmqpConfig::default()
    }
}

/// A dial that cannot complete fails within its budget, with an error that
/// says so.
///
/// Before `connect_timeout_ms` existed this call never returned. The outer
/// `tokio::time::timeout` here is the assertion, not a convenience: if the
/// bound regresses, this test must fail rather than hang the suite the way the
/// job it comes from did.
#[tokio::test]
async fn a_dial_that_never_completes_times_out_instead_of_hanging() {
    let (port, server) = silent_tls_port().await;

    let started = std::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        AmqpManager::connect_with_retry(&config_for(port, 1_000)),
    )
    .await
    .expect("the dial must be bounded by connect_timeout_ms — an unbounded connect is the exact defect this covers");

    match result.map(|_| "connected") {
        Err(axiam_amqp::AmqpError::ConnectTimeout { timeout_ms, .. }) => {
            assert_eq!(timeout_ms, 1_000, "the configured budget must be reported");
        }
        other => panic!("expected a ConnectTimeout against a silent port, got {other:?}"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "the timeout must be the configured one, not an incidental upper bound (took {:?})",
        started.elapsed()
    );

    server.abort();
}

/// Dialling `amqps://` from a process that has installed no rustls provider
/// must not panic, and must leave one installed.
///
/// This is the tripwire for the original fault. rustls 0.23 refuses to
/// auto-select a default when a process links both `ring` and `aws-lc-rs` —
/// which this workspace does, transitively — and every consumer of this crate
/// that is not `axiam-server` reaches rustls without having installed one.
/// The assertion is about *this crate* being self-sufficient: nothing in this
/// test installs a provider, so if the library stops doing it, the dial below
/// panics on lapin's IO thread and the `get_default` assertion fails.
#[tokio::test]
async fn dialling_amqps_installs_the_process_crypto_provider() {
    let (port, server) = silent_tls_port().await;

    // Deliberately no `install_default()` call here.
    let _ = tokio::time::timeout(
        Duration::from_secs(20),
        AmqpManager::connect_with_retry(&config_for(port, 1_000)),
    )
    .await
    .expect("bounded dial");

    assert!(
        rustls::crypto::CryptoProvider::get_default().is_some(),
        "dialling amqps:// must install the process-level rustls CryptoProvider. Without one, \
         rustls panics on lapin's IO thread, the connect future is never resolved, and the \
         caller waits forever with nothing in the log to explain it."
    );

    server.abort();
}
