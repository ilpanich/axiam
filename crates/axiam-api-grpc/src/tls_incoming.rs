//! TLS termination for the gRPC listener (R-1, closes T-234).
//!
//! # Why the listener terminates TLS itself
//!
//! Until this module existed, the gRPC listener handed a
//! [`tonic::transport::ServerTlsConfig`] to tonic and let tonic do the
//! handshake. That has two consequences tonic 0.14 gives no way to avoid,
//! because `ServerTlsConfig` accepts neither a [`rustls::ServerConfig`] nor a
//! certificate resolver:
//!
//! 1. **The leaf is bound for the process's life.** `Identity::from_pem` copies
//!    the bytes once, at boot. An ACME renewal at day 60 therefore took effect
//!    at the next restart — which for a 90-day leaf means the listener starts
//!    serving an expired certificate unless an operator remembers to bounce the
//!    container. This is exactly the failure
//!    [`axiam_server::tls::ReloadableCertResolver`] was written to fix for the
//!    REST listener (T-214); T-234 recorded that gRPC still had it.
//! 2. **TLS 1.2 stayed negotiable.** `ServerTlsConfig` builds its rustls config
//!    through `ServerConfig::builder()`, which installs the crate's default
//!    protocol versions. The REST listener pins
//!    `with_protocol_versions(&[&rustls::version::TLS13])`; gRPC could not.
//!
//! Both are properties of the `rustls::ServerConfig`, so the fix is to build
//! that config ourselves and hand tonic a stream that is *already encrypted*,
//! through [`tonic::transport::server::Router::serve_with_incoming`]. The
//! config is supplied by the composition root as a value ([`super::GrpcTls`]) —
//! `axiam-api-grpc` is layer 6 and `axiam-server`, where the resolver lives, is
//! layer 8, so the dependency has to point that way (see
//! `scripts/check-crate-layering.py`).
//!
//! # Peer addresses still work
//!
//! [`crate::middleware::rate_limit::GrpcTrustedHopsKeyExtractor`] keys on the
//! verified connection peer, read from the `TcpConnectInfo` /
//! `TlsConnectInfo<TcpConnectInfo>` request extensions. tonic populates those
//! from the [`tonic::transport::server::Connected`] implementation on whatever
//! the incoming stream yields, and `tokio_rustls::server::TlsStream<T>`
//! implements it (`tonic-0.14.6/src/transport/server/conn.rs:106`, under the
//! `tls-connect-info` feature that `tls-ring` enables) with
//! `ConnectInfo = TlsConnectInfo<T::ConnectInfo>`. So a stream of
//! `TlsStream<TcpStream>` inserts exactly one extension,
//! `TlsConnectInfo<TcpConnectInfo>` — the second arm the extractor already
//! looks in. Verified against the pinned tonic before this module was written,
//! because if `remote_addr()` came back `None` the extractor would return
//! `UnableToExtractKey` and the limiter would fail closed for every caller.
//!
//! # The one new denial-of-service surface, and its bound
//!
//! Doing the handshake ourselves means a client that opens TCP and then says
//! nothing occupies server state. Two limits contain it, and neither can block
//! the accept loop:
//!
//! - every handshake runs in its own task, so a silent client delays only
//!   itself;
//! - each task holds one of [`MAX_CONCURRENT_HANDSHAKES`] permits, acquired
//!   with a **non-blocking** `try_acquire_owned`. A connection that arrives
//!   with no permit free is dropped immediately rather than queued, so the
//!   accept loop's cost per connection stays constant no matter how many
//!   half-open clients are in flight;
//! - a permit is released after at most [`HANDSHAKE_TIMEOUT`], so a saturated
//!   listener recovers on its own.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures::Stream;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

/// How many TLS handshakes may be in flight at once.
///
/// Sized as a bound on memory, not on throughput: a rustls server-side
/// handshake buffers a few tens of kilobytes, so 512 concurrent ones is under
/// ~20 MiB — comfortably more than any real burst of gRPC clients reconnecting
/// after a rolling restart, and far below what an unbounded accept loop would
/// let a flood allocate.
pub const MAX_CONCURRENT_HANDSHAKES: usize = 512;

/// How long one handshake may take before its connection is dropped.
///
/// This is what turns the permit bound above into a self-healing one: without
/// it, `MAX_CONCURRENT_HANDSHAKES` clients that connect and never speak would
/// hold every permit forever. Generous enough for a slow mobile link doing a
/// full ECDHE exchange; short enough that a saturated listener recovers within
/// one operator's attention span.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Depth of the queue between the handshake tasks and tonic's accept side.
///
/// Bounded on purpose: if tonic is slower than the handshakes complete, the
/// backpressure lands on a handshake task (which is holding a permit and will
/// time out) rather than on an unbounded buffer of established connections.
const READY_QUEUE_DEPTH: usize = 128;

/// Whether the shed-on-saturation warning has already been logged.
///
/// Once per process. The condition that triggers it is by definition a flood,
/// and one line per shed connection would be a log amplification of the very
/// attack the bound exists to survive.
static SHED_WARNED: AtomicBool = AtomicBool::new(false);

/// Accept TCP connections on `listener`, complete the TLS handshake for each,
/// and yield the encrypted streams.
///
/// The returned stream is what
/// [`tonic::transport::server::Router::serve_with_incoming`] consumes. It ends
/// when the accept loop stops, which happens only on an accept error that is
/// not transient; that error is also sent on `fatal` so the caller can fail the
/// server task rather than returning `Ok(())` from a listener that has silently
/// died.
///
/// A failed or timed-out handshake logs at `debug` and drops **that connection
/// only** — it must never take the accept loop down, because "one malformed
/// ClientHello stops the listener" is a one-packet denial of service.
pub(crate) fn tls_incoming(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    fatal: oneshot::Sender<io::Error>,
) -> impl Stream<Item = io::Result<TlsStream<TcpStream>>> + Send + 'static {
    tls_incoming_with_bounds(
        listener,
        config,
        fatal,
        Bounds {
            max_concurrent_handshakes: MAX_CONCURRENT_HANDSHAKES,
            handshake_timeout: HANDSHAKE_TIMEOUT,
        },
    )
}

/// The two limits that contain the denial-of-service surface terminating TLS
/// here introduces.
///
/// A parameter rather than a pair of constants read directly, so both bounds
/// can be *exercised*: at their production values a test would need 512
/// half-open connections and a ten-second wait to reach either, which is a test
/// nobody runs and therefore a bound nobody has seen work. The production
/// values are still [`MAX_CONCURRENT_HANDSHAKES`] and [`HANDSHAKE_TIMEOUT`],
/// passed at the one call site above.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Bounds {
    /// How many handshakes may be in flight at once; a connection arriving with
    /// no permit free is dropped rather than queued.
    pub(crate) max_concurrent_handshakes: usize,
    /// How long one handshake may take before its connection is dropped and its
    /// permit released.
    pub(crate) handshake_timeout: Duration,
}

fn tls_incoming_with_bounds(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    fatal: oneshot::Sender<io::Error>,
    bounds: Bounds,
) -> impl Stream<Item = io::Result<TlsStream<TcpStream>>> + Send + 'static {
    let (ready_tx, ready_rx) = mpsc::channel::<TlsStream<TcpStream>>(READY_QUEUE_DEPTH);

    tokio::spawn(accept_loop(listener, config, ready_tx, fatal, bounds));

    // `unfold` rather than a `ReceiverStream` so this crate does not need
    // tokio-stream as a non-dev dependency for one adapter.
    futures::stream::unfold(ready_rx, |mut rx| async move {
        rx.recv().await.map(|io| (Ok(io), rx))
    })
}

/// The accept loop itself.
///
/// Everything it does per connection is O(1) and non-blocking apart from
/// `accept()`: set `TCP_NODELAY`, take a permit without waiting, spawn. That is
/// the property that makes "a flood of half-open TLS clients cannot starve the
/// accept loop" true by construction rather than by timing.
async fn accept_loop(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    ready_tx: mpsc::Sender<TlsStream<TcpStream>>,
    fatal: oneshot::Sender<io::Error>,
    bounds: Bounds,
) {
    let acceptor = TlsAcceptor::from(config);
    let permits = Arc::new(Semaphore::new(bounds.max_concurrent_handshakes));

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) if is_transient_accept_error(&e) => {
                // Out of file descriptors, a connection reset between the
                // SYN and our accept(), a signal — none of these say anything
                // about the listener's health.
                tracing::debug!(error = %e, "gRPC TLS listener: transient accept error, continuing");
                continue;
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "gRPC TLS listener: unrecoverable accept error — the listener is stopping"
                );
                let _ = fatal.send(e);
                return;
            }
        };

        // Parity with tonic's own `serve()` path, which binds through
        // `TcpIncoming` with `tcp_nodelay: true`. `serve_with_incoming`
        // documents that it ignores the builder's TCP settings, so the option
        // has to be set here or gRPC would quietly regain Nagle's algorithm —
        // the same interaction with delayed ACKs that I5 removed from REST.
        let _ = tcp.set_nodelay(true);

        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            if !SHED_WARNED.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    max_concurrent_handshakes = bounds.max_concurrent_handshakes,
                    handshake_timeout_secs = bounds.handshake_timeout.as_secs(),
                    "gRPC TLS handshake capacity is saturated; connections are being \
                     shed until in-flight handshakes complete or time out. This warning \
                     is logged once per process."
                );
            }
            tracing::debug!(peer = %peer, "gRPC TLS connection shed: no handshake permit free");
            drop(tcp);
            continue;
        };

        let acceptor = acceptor.clone();
        let ready_tx = ready_tx.clone();
        tokio::spawn(async move {
            // Held for the whole handshake, released on every exit path.
            let _permit = permit;
            match tokio::time::timeout(bounds.handshake_timeout, acceptor.accept(tcp)).await {
                Ok(Ok(tls)) => {
                    // A closed receiver means tonic has stopped serving; the
                    // connection is dropped with it, which is correct.
                    let _ = ready_tx.send(tls).await;
                }
                Ok(Err(e)) => {
                    tracing::debug!(peer = %peer, error = %e, "gRPC TLS handshake failed");
                }
                Err(_) => {
                    tracing::debug!(
                        peer = %peer,
                        timeout_ms = bounds.handshake_timeout.as_millis(),
                        "gRPC TLS handshake timed out"
                    );
                }
            }
        });
    }
}

/// Whether an `accept()` error describes this connection or the listener.
///
/// Mirrors tonic's own `handle_tcp_accept_error`
/// (`tonic-0.14.6/src/transport/server/io_stream.rs`): these kinds are reported
/// for the connection that was being accepted, so retrying is right. Anything
/// else — a closed or invalid socket — is the listener itself, and looping on it
/// would spin a core while logging nothing an operator could act on.
fn is_transient_accept_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::Interrupted
            | io::ErrorKind::InvalidData
            | io::ErrorKind::WouldBlock
    )
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Mutex;

    use futures::StreamExt as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;
    use tokio::io::AsyncWriteExt as _;
    use tokio::net::TcpStream as TokioTcpStream;
    use tokio_rustls::TlsConnector;
    use tonic::transport::server::{Connected, TcpConnectInfo, TlsConnectInfo};
    use tower_governor::key_extractor::KeyExtractor;

    use super::*;
    use crate::middleware::rate_limit::GrpcTrustedHopsKeyExtractor;

    // -----------------------------------------------------------------------
    // Test PKI and a resolver whose leaf can be swapped mid-flight
    // -----------------------------------------------------------------------

    /// A throwaway self-signed leaf, generated at run time rather than written
    /// as a PEM literal (which static secret scanners flag).
    fn test_leaf() -> Arc<CertifiedKey> {
        let provider = rustls::crypto::ring::default_provider();
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate a self-signed test leaf");
        let cert = CertificateDer::from(generated.cert.der().to_vec());
        let key = PrivateKeyDer::try_from(generated.signing_key.serialize_der())
            .expect("serialize the test key to DER");
        Arc::new(
            CertifiedKey::from_der(vec![cert], key, &provider).expect("the test pair must match"),
        )
    }

    /// The minimum a renewal needs: a resolver rustls consults per handshake,
    /// whose leaf can be replaced while the listener runs.
    ///
    /// Deliberately *not* `axiam_server::tls::ReloadableCertResolver` — that
    /// crate is layer 8 and this one is layer 6, and the property under test
    /// here belongs to the listener anyway: that it asks the resolver on every
    /// handshake rather than binding a leaf at boot. Whether the production
    /// resolver swaps correctly is `axiam-server`'s own test.
    #[derive(Debug)]
    struct SwappableResolver(Mutex<Arc<CertifiedKey>>);

    impl SwappableResolver {
        fn new(initial: Arc<CertifiedKey>) -> Self {
            Self(Mutex::new(initial))
        }

        fn replace(&self, next: Arc<CertifiedKey>) {
            *self.0.lock().expect("test resolver lock") = next;
        }
    }

    impl ResolvesServerCert for SwappableResolver {
        fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(Arc::clone(&self.0.lock().expect("test resolver lock")))
        }
    }

    /// The listener's side of the connection, shaped like what
    /// `axiam_server::tls::build_grpc_rustls_server_config` builds: TLS 1.3
    /// only, no client auth, ALPN `h2`, leaf behind a resolver.
    fn server_config(resolver: Arc<dyn ResolvesServerCert>) -> Arc<rustls::ServerConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 must be configurable")
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        config.alpn_protocols = vec![b"h2".to_vec()];
        Arc::new(config)
    }

    // -----------------------------------------------------------------------
    // A client that records the leaf it was presented, and trusts anything
    // -----------------------------------------------------------------------

    /// Records the end-entity certificate the server presented and accepts it.
    ///
    /// Accepting everything is right for these tests: what is under test is
    /// *which* leaf the listener resolved and *which* protocol version it
    /// agreed to, not whether a chain validates — that is rustls' own
    /// behaviour and it is not what R-1 changed.
    #[derive(Debug)]
    struct RecordingVerifier {
        seen: Mutex<Option<CertificateDer<'static>>>,
        provider: Arc<rustls::crypto::CryptoProvider>,
    }

    impl RecordingVerifier {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                seen: Mutex::new(None),
                provider: Arc::new(rustls::crypto::ring::default_provider()),
            })
        }

        fn presented(&self) -> CertificateDer<'static> {
            self.seen
                .lock()
                .expect("verifier lock")
                .clone()
                .expect("the server must have presented a leaf")
        }
    }

    impl rustls::client::danger::ServerCertVerifier for RecordingVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            *self.seen.lock().expect("verifier lock") = Some(end_entity.clone().into_owned());
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        /// Unreachable by construction: the listener is TLS 1.3-only, so the
        /// one TLS 1.2 client in this module is refused at version negotiation
        /// — before any signature exists to verify. Required by the trait.
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            unreachable!("the listener under test never negotiates TLS 1.2")
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    /// A client pinned to `versions`, trusting whatever it is presented.
    fn client_config(
        verifier: Arc<RecordingVerifier>,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> Arc<rustls::ClientConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .expect("client protocol versions must be configurable")
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        Arc::new(config)
    }

    /// Bring up a listener over `resolver` and return its address plus a handle
    /// that keeps every accepted stream alive (so a renewal cannot be mistaken
    /// for a dropped connection just because the test dropped the server side).
    fn spawn_listener(
        resolver: Arc<dyn ResolvesServerCert>,
        listener: TcpListener,
    ) -> Arc<Mutex<Vec<TlsStream<TcpStream>>>> {
        // Deliberately through `tls_incoming`, not `tls_incoming_with_bounds`:
        // that is the entry point `start_grpc_server` calls, so it is the one
        // that must be exercised. Only the two tests that need to *reach* a
        // bound go through the inner function.
        drive(tls_incoming, resolver, listener)
    }

    /// As above, with the two bounds set explicitly so a test can reach them
    /// without 512 connections and a ten-second wait.
    fn spawn_listener_with(
        resolver: Arc<dyn ResolvesServerCert>,
        listener: TcpListener,
        bounds: Bounds,
    ) -> Arc<Mutex<Vec<TlsStream<TcpStream>>>> {
        drive(
            move |listener, config, fatal| {
                tls_incoming_with_bounds(listener, config, fatal, bounds)
            },
            resolver,
            listener,
        )
    }

    /// Consume an incoming stream, keeping every accepted connection alive.
    ///
    /// Holding them matters: a renewal must not be mistakable for a dropped
    /// connection just because the test dropped the server side of it.
    fn drive<F, S>(
        build: F,
        resolver: Arc<dyn ResolvesServerCert>,
        listener: TcpListener,
    ) -> Arc<Mutex<Vec<TlsStream<TcpStream>>>>
    where
        F: FnOnce(TcpListener, Arc<rustls::ServerConfig>, oneshot::Sender<io::Error>) -> S,
        S: Stream<Item = io::Result<TlsStream<TcpStream>>> + Send + 'static,
    {
        let accepted = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&accepted);
        let (fatal_tx, _fatal_rx) = oneshot::channel();
        let mut incoming = Box::pin(build(listener, server_config(resolver), fatal_tx));
        tokio::spawn(async move {
            while let Some(Ok(stream)) = incoming.next().await {
                sink.lock().expect("accepted lock").push(stream);
            }
        });
        accepted
    }

    async fn connect(
        addr: SocketAddr,
        config: Arc<rustls::ClientConfig>,
    ) -> io::Result<(SocketAddr, tokio_rustls::client::TlsStream<TokioTcpStream>)> {
        let tcp = TokioTcpStream::connect(addr).await?;
        let local = tcp.local_addr()?;
        let name = ServerName::try_from("localhost").expect("a valid DNS name");
        let stream = TlsConnector::from(config).connect(name, tcp).await?;
        Ok((local, stream))
    }

    // -----------------------------------------------------------------------
    // The tests
    // -----------------------------------------------------------------------

    /// Plan §2 test 1 — a renewal takes effect on the *running* listener.
    ///
    /// This is the whole of T-234 in one assertion: the leaf presented on the
    /// second handshake is the one installed after the first, with no restart
    /// and no dropped connection. Under `ServerTlsConfig` it could not be,
    /// because `Identity::from_pem` copied the bytes once at boot.
    #[tokio::test]
    async fn a_renewed_leaf_is_presented_to_the_next_handshake() {
        let first = test_leaf();
        let second = test_leaf();
        assert_ne!(
            first.cert, second.cert,
            "the two generated leaves must differ, or this test proves nothing"
        );

        let resolver = Arc::new(SwappableResolver::new(Arc::clone(&first)));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let _accepted = spawn_listener(
            Arc::clone(&resolver) as Arc<dyn ResolvesServerCert>,
            listener,
        );

        let before = RecordingVerifier::new();
        let (_, mut established) = connect(
            addr,
            client_config(Arc::clone(&before), &[&rustls::version::TLS13]),
        )
        .await
        .expect("the first handshake must succeed");
        assert_eq!(
            before.presented(),
            first.cert[0],
            "the listener must serve the leaf its resolver held at the time"
        );

        // The renewal. Nothing is restarted and nothing is rebound.
        resolver.replace(Arc::clone(&second));

        let after = RecordingVerifier::new();
        let (_, _renewed) = connect(
            addr,
            client_config(Arc::clone(&after), &[&rustls::version::TLS13]),
        )
        .await
        .expect("the second handshake must succeed");
        assert_eq!(
            after.presented(),
            second.cert[0],
            "a swap on the resolver must reach the very next handshake"
        );

        // ...and the connection opened before the swap is still usable. A
        // renewal that silently killed established connections would trade one
        // outage for another.
        established
            .write_all(b"still open")
            .await
            .expect("the connection established before the renewal must survive it");
    }

    /// Plan §2 test 2 — a TLS 1.2-only client is refused, not downgraded.
    ///
    /// The second half of T-234, and the caveat T-233 recorded: tonic's
    /// `ServerTlsConfig` had no protocol-version knob, so this listener used to
    /// negotiate TLS 1.2 happily while the REST one next to it would not.
    #[tokio::test]
    async fn a_tls12_only_client_is_refused() {
        let resolver = Arc::new(SwappableResolver::new(test_leaf()));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let _accepted = spawn_listener(resolver as Arc<dyn ResolvesServerCert>, listener);

        let verifier = RecordingVerifier::new();
        let result = connect(addr, client_config(verifier, &[&rustls::version::TLS12])).await;

        assert!(
            result.is_err(),
            "a TLS 1.2-only client must fail the handshake, not be served"
        );
    }

    /// Plan §2 test 3 — the peer address survives the new listener.
    ///
    /// The rate limiter keys on the verified connection peer, which it reads
    /// from the request extension tonic populates from the `Connected` impl of
    /// whatever the incoming stream yields. If that came back `None` for
    /// `TlsStream<TcpStream>`, every gRPC request would key on "no address",
    /// [`GrpcTrustedHopsKeyExtractor`] would return `UnableToExtractKey`, and
    /// the limiter would fail closed for everyone — so this asserts the exact
    /// chain: real handshake → `connect_info()` → request extension →
    /// extractor → the client's IP.
    #[tokio::test]
    async fn the_peer_address_of_a_tls_connection_reaches_the_rate_limit_extractor() {
        let resolver = Arc::new(SwappableResolver::new(test_leaf()));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let accepted = spawn_listener(resolver as Arc<dyn ResolvesServerCert>, listener);

        let verifier = RecordingVerifier::new();
        let (client_addr, _client) =
            connect(addr, client_config(verifier, &[&rustls::version::TLS13]))
                .await
                .expect("handshake");

        // Let the accept task push the server side into the sink.
        let server_side = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(stream) = accepted.lock().expect("accepted lock").pop() {
                    return stream;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the listener must yield the accepted stream");

        // Exactly what tonic's `ConnectInfo` service does with the value the
        // `Connected` impl returns (`transport/server/service/io.rs`).
        let connect_info = server_side.connect_info();
        let mut req = http::Request::builder().body(()).expect("request");
        req.extensions_mut().insert(connect_info);

        // Sanity: the extension really is the TLS-shaped one, i.e. the second
        // arm of the extractor's lookup and not the plaintext first arm.
        assert!(
            req.extensions()
                .get::<TlsConnectInfo<TcpConnectInfo>>()
                .is_some(),
            "a TLS listener must insert TlsConnectInfo<TcpConnectInfo>"
        );

        let key = GrpcTrustedHopsKeyExtractor::new(0)
            .extract(&req)
            .expect("the peer address must be extractable, or the limiter fails closed");
        assert_eq!(
            key,
            client_addr.ip(),
            "the rate-limit key must be the client's own address"
        );
    }

    /// Plan §2 test 4 — half-open clients do not starve the accept loop.
    ///
    /// The one new denial-of-service surface terminating TLS ourselves
    /// introduces. Every handshake runs in its own task and takes its permit
    /// without waiting, so a client that opens TCP and then says nothing delays
    /// only itself; before that structure, a single silent client blocked the
    /// accept loop for the whole handshake timeout.
    #[tokio::test]
    async fn a_flood_of_half_open_clients_does_not_block_a_well_behaved_one() {
        const FLOOD: usize = 64;

        let resolver = Arc::new(SwappableResolver::new(test_leaf()));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let _accepted = spawn_listener(resolver as Arc<dyn ResolvesServerCert>, listener);

        // Opened and held, never spoken on. Kept in scope so nothing closes
        // them early and lets the listener recover for the wrong reason.
        let mut silent = Vec::with_capacity(FLOOD);
        for _ in 0..FLOOD {
            silent.push(
                TokioTcpStream::connect(addr)
                    .await
                    .expect("the listener must keep accepting TCP under the flood"),
            );
        }

        let verifier = RecordingVerifier::new();
        let served = tokio::time::timeout(
            Duration::from_secs(5),
            connect(addr, client_config(verifier, &[&rustls::version::TLS13])),
        )
        .await;

        assert!(
            matches!(served, Ok(Ok(_))),
            "a well-behaved client must complete its handshake while {FLOOD} \
             half-open connections are outstanding, got {served:?}"
        );
        // The flood is deliberately under the permit ceiling: this test is
        // about the accept loop not blocking, not about the shed path, and a
        // flood over the ceiling would shed the well-behaved client too.
        const { assert!(FLOOD < MAX_CONCURRENT_HANDSHAKES) };
    }

    /// A failed handshake drops **that connection only**.
    ///
    /// "One malformed ClientHello stops the listener" would be a one-packet
    /// denial of service, so this is the property that matters most about the
    /// error arm: the garbage connection dies, the accept loop does not, and
    /// the very next well-behaved client is served.
    #[tokio::test]
    async fn a_failed_handshake_does_not_take_the_listener_down() {
        use tokio::io::AsyncWriteExt as _;

        let resolver = Arc::new(SwappableResolver::new(test_leaf()));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let _accepted = spawn_listener(resolver as Arc<dyn ResolvesServerCert>, listener);

        // Not a ClientHello. rustls refuses it, and the handshake task takes
        // the `Ok(Err(..))` arm.
        let mut garbage = TokioTcpStream::connect(addr).await.expect("connect");
        garbage
            .write_all(b"this is not a TLS ClientHello\r\n\r\n")
            .await
            .expect("write");
        let _ = garbage.flush().await;

        let verifier = RecordingVerifier::new();
        let served = tokio::time::timeout(
            Duration::from_secs(5),
            connect(addr, client_config(verifier, &[&rustls::version::TLS13])),
        )
        .await;

        assert!(
            matches!(served, Ok(Ok(_))),
            "a rejected handshake must not stop the accept loop, got {served:?}"
        );
    }

    /// A client that opens TCP and never speaks releases its permit at the
    /// timeout, so the listener recovers on its own.
    ///
    /// This is what makes the permit bound self-healing rather than a
    /// one-way ratchet into permanent refusal. At the production
    /// [`HANDSHAKE_TIMEOUT`] the test would take ten seconds; the bound is
    /// injected so the *behaviour* can be exercised in milliseconds.
    #[tokio::test]
    async fn a_silent_client_releases_its_permit_at_the_timeout() {
        let resolver = Arc::new(SwappableResolver::new(test_leaf()));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let _accepted = spawn_listener_with(
            resolver as Arc<dyn ResolvesServerCert>,
            listener,
            Bounds {
                // Exactly one handshake at a time, so the silent client below
                // holds the *only* permit and a second connection must wait for
                // the timeout to release it.
                max_concurrent_handshakes: 1,
                handshake_timeout: Duration::from_millis(150),
            },
        );

        let silent = TokioTcpStream::connect(addr).await.expect("connect");
        // Let the accept loop take the permit for it.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Now the pool is empty; this one is shed. That arm is the load-shed
        // path, and shedding rather than queueing is what keeps the accept loop
        // constant-cost under a flood.
        let shed = tokio::time::timeout(
            Duration::from_millis(80),
            connect(
                addr,
                client_config(RecordingVerifier::new(), &[&rustls::version::TLS13]),
            ),
        )
        .await;
        assert!(
            !matches!(shed, Ok(Ok(_))),
            "with every permit held, a new connection must be shed rather than served"
        );

        // ...and once the silent client's permit times out, service resumes
        // with no intervention.
        tokio::time::sleep(Duration::from_millis(250)).await;
        let recovered = tokio::time::timeout(
            Duration::from_secs(5),
            connect(
                addr,
                client_config(RecordingVerifier::new(), &[&rustls::version::TLS13]),
            ),
        )
        .await;
        assert!(
            matches!(recovered, Ok(Ok(_))),
            "the timeout must release the permit and let the listener recover, got {recovered:?}"
        );
        drop(silent);
    }

    #[test]
    fn per_connection_accept_errors_are_transient() {
        for kind in [
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::Interrupted,
            io::ErrorKind::InvalidData,
            io::ErrorKind::WouldBlock,
        ] {
            assert!(
                is_transient_accept_error(&io::Error::new(kind, "test")),
                "{kind:?} describes one connection, not the listener"
            );
        }
    }

    #[test]
    fn listener_level_accept_errors_are_fatal() {
        for kind in [
            io::ErrorKind::NotConnected,
            io::ErrorKind::AddrNotAvailable,
            io::ErrorKind::PermissionDenied,
        ] {
            assert!(
                !is_transient_accept_error(&io::Error::new(kind, "test")),
                "{kind:?} is the listener's own state; looping on it would spin"
            );
        }
    }
}
