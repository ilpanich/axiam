//! S-8 (DF-005) — client-certificate verification on the gRPC listener.
//!
//! Two layers, because the property has two halves and each can break alone:
//!
//! * **The handshake.** Who is asked for a certificate, who is refused, and
//!   what the server ends up holding — driven with `tokio-rustls` directly
//!   against the `ServerConfig` `axiam_server::tls` builds, with a client-side
//!   certificate resolver that records whether the server asked at all. That
//!   is how `off` is compared with the pre-S-8 listener: by what happens on the
//!   wire, not by comparing structs (plan §4 S-8, I1).
//! * **What reaches the application.** The real `start_grpc_server` — real
//!   accept loop (`tls_incoming`), real auth interceptor, real
//!   `TokenService` — called by a real tonic client. `IntrospectToken` on the
//!   caller's own token is the probe: the interceptor alone decides between
//!   `Unauthenticated` and an answer, and the answer echoes the token's `cnf`.
//!   A certificate-bound token succeeding there proves `Request::peer_certs()`
//!   was populated through the custom accept loop; nothing else in the stack
//!   could have supplied the thumbprint.
//!
//! Every server here builds its client verifier through the production
//! builder, so every one joins the process-wide reload registry. That is
//! harmless — a reload re-reads each listener's own bundle file, and no test
//! but the reload test changes its file after building.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axiam_api_grpc::proto::IntrospectTokenRequest;
use axiam_api_grpc::proto::token_service_client::TokenServiceClient;
use axiam_api_grpc::{GrpcConfig, GrpcTls, start_grpc_server};
use axiam_api_rest::TrustAnchorReloader as _;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{CnfClaim, issue_service_account_token};
use axiam_authz::AuthorizationEngine;
use axiam_core::ca_keys::CaKeyCustody;
use axiam_core::models::certificate::{KeyAlgorithm, StoreCaCertificate};
use axiam_core::repository::CaCertificateRepository as _;
use axiam_db::SurrealCaCertificateRepository;
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealGroupRepository, SurrealPermissionRepository,
    SurrealReactorRepository, SurrealResourceRepository, SurrealRoleRepository,
    SurrealScopeRepository, SurrealUserRepository,
};
use axiam_server::mtls_anchors::TrustAnchorReload;
use axiam_server::tls::{
    GrpcClientAuth, build_grpc_rustls_server_config_with_client_auth, resolve_grpc_tls,
};
use rcgen::{
    BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ED25519,
};
use rustls::client::ResolvesClientCert;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Test PKI
// ---------------------------------------------------------------------------

/// A CA generated at run time (no PEM literals for secret scanners to flag).
struct Ca {
    params: CertificateParams,
    key: KeyPair,
    pem: String,
}

fn ca(name: &str) -> Ca {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let pem = params.self_signed(&key).unwrap().pem();
    Ca { params, key, pem }
}

/// A leaf issued by `issuer`.
struct Leaf {
    cert_pem: String,
    key_pem: String,
    der: CertificateDer<'static>,
}

/// Names the certificate by its thumbprint and never prints the key — the
/// rule for any `Debug` near key material, test code included.
impl std::fmt::Debug for Leaf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Leaf")
            .field("x5t#S256", &thumbprint(self.der.as_ref()))
            .finish_non_exhaustive()
    }
}

fn leaf(issuer: &Ca, sans: &[&str]) -> Leaf {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut params =
        CertificateParams::new(sans.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>()).unwrap();
    params.is_ca = IsCa::NoCa;
    let cert = params
        .signed_by(&key, &Issuer::from_params(&issuer.params, &issuer.key))
        .unwrap();
    Leaf {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        der: cert.der().clone(),
    }
}

/// The server's own CA and leaf (`localhost`), plus two client CAs: `a` is the
/// anchor every listener here trusts at boot, `b` is one it does not.
struct Pki {
    server_ca: Ca,
    server: Leaf,
    a: Ca,
    b: Ca,
}

fn pki() -> Pki {
    let server_ca = ca("gRPC Server CA");
    let server = leaf(&server_ca, &["localhost"]);
    Pki {
        server_ca,
        server,
        a: ca("Client CA A"),
        b: ca("Client CA B"),
    }
}

/// A scratch directory removed on drop, including after a failed assertion.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("axiam-grpc-mtls-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// The server configuration, built by the production code from files on disk.
fn server_config(
    pki: &Pki,
    dir: &Scratch,
    client_auth: impl FnOnce(PathBuf) -> GrpcClientAuth,
) -> ServerConfig {
    let cert = dir.write("server.pem", &pki.server.cert_pem);
    let key = dir.write("server.key", &pki.server.key_pem);
    let bundle = dir.write("client-ca-bundle.pem", &pki.a.pem);
    build_grpc_rustls_server_config_with_client_auth(&cert, &key, &client_auth(bundle))
        .expect("the gRPC listener config must build")
}

fn ring() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

// ---------------------------------------------------------------------------
// Handshake probes
// ---------------------------------------------------------------------------

/// A client certificate resolver that records whether the server asked.
///
/// rustls calls `resolve` only when the server sent a `CertificateRequest`, so
/// `asked` is the one observation that tells "not asked" from "asked, and
/// answered with nothing" — the difference between `off` and `optional`.
#[derive(Debug)]
struct Recording {
    key: Option<Arc<CertifiedKey>>,
    asked: AtomicBool,
}

impl ResolvesClientCert for Recording {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.asked.store(true, Ordering::SeqCst);
        self.key.clone()
    }

    fn has_certs(&self) -> bool {
        self.key.is_some()
    }
}

/// How a probing client is shaped.
#[derive(Clone, Copy, Debug)]
enum Shape<'a> {
    /// TLS 1.3, ALPN `h2`, no certificate.
    Anonymous,
    /// TLS 1.3, ALPN `h2`, presents this certificate when asked.
    Presenting(&'a Leaf),
    /// TLS 1.2 only — the listener must refuse it.
    Tls12Only,
    /// ALPN `http/1.1` only — gRPC is HTTP/2 and nothing else.
    Http11Only,
}

/// What one handshake did, observed from both ends.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    /// The server completed the handshake.
    server_accepted: bool,
    /// The server sent a `CertificateRequest`.
    client_was_asked: bool,
    /// How many peer certificates the server holds afterwards — what tonic's
    /// `TlsConnectInfo` would carry to `Request::peer_certs()`.
    server_peer_certs: Option<usize>,
    alpn: Option<Vec<u8>>,
    version: Option<rustls::ProtocolVersion>,
}

fn client_config(pki: &Pki, shape: Shape<'_>) -> (Arc<ClientConfig>, Arc<Recording>) {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(pki.server_ca.pem.as_bytes()).unwrap())
        .unwrap();
    let key = match shape {
        Shape::Presenting(l) => Some(Arc::new(
            CertifiedKey::from_der(
                vec![l.der.clone()],
                PrivateKeyDer::from_pem_slice(l.key_pem.as_bytes()).unwrap(),
                &rustls::crypto::ring::default_provider(),
            )
            .unwrap(),
        )),
        _ => None,
    };
    let recording = Arc::new(Recording {
        key,
        asked: AtomicBool::new(false),
    });
    let versions: &[&rustls::SupportedProtocolVersion] = match shape {
        Shape::Tls12Only => &[&rustls::version::TLS12],
        _ => &[&rustls::version::TLS13],
    };
    let mut config = ClientConfig::builder_with_provider(ring())
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots)
        .with_client_cert_resolver(Arc::clone(&recording) as Arc<dyn ResolvesClientCert>);
    config.alpn_protocols = match shape {
        Shape::Http11Only => vec![b"http/1.1".to_vec()],
        _ => vec![b"h2".to_vec()],
    };
    (Arc::new(config), recording)
}

async fn probe(server: Arc<ServerConfig>, pki: &Pki, shape: Shape<'_>) -> Outcome {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server);
    let server_side = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.ok()?;
        let (_, conn) = tls.get_ref();
        Some((
            conn.peer_certificates().map(<[CertificateDer<'_>]>::len),
            conn.alpn_protocol().map(<[u8]>::to_vec),
            conn.protocol_version(),
        ))
    });

    let (client, recording) = client_config(pki, shape);
    let tcp = TcpStream::connect(addr).await.unwrap();
    // The client's verdict is not the one that matters: under TLS 1.3 the
    // client finishes before the server has checked its certificate. The
    // server's is, and it is what `server_accepted` reports.
    let _client = TlsConnector::from(client)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await;

    let server = tokio::time::timeout(Duration::from_secs(10), server_side)
        .await
        .expect("the server side of a probe must finish")
        .unwrap();
    Outcome {
        server_accepted: server.is_some(),
        client_was_asked: recording.asked.load(Ordering::SeqCst),
        server_peer_certs: server.as_ref().and_then(|s| s.0),
        alpn: server.as_ref().and_then(|s| s.1.clone()),
        version: server.as_ref().and_then(|s| s.2),
    }
}

// ---------------------------------------------------------------------------
// The real listener
// ---------------------------------------------------------------------------

type TestEngine = AuthorizationEngine<
    SurrealRoleRepository<Db>,
    SurrealPermissionRepository<Db>,
    SurrealResourceRepository<Db>,
    SurrealScopeRepository<Db>,
    SurrealGroupRepository<Db>,
>;

fn engine(db: &Surreal<Db>) -> TestEngine {
    AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    )
}

async fn database() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

/// A throwaway Ed25519 signing pair — test material only.
fn auth_config() -> AuthConfig {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    AuthConfig {
        jwt_private_key_pem: key.serialize_pem(),
        jwt_public_key_pem: key.public_key_pem(),
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

/// Serve the production gRPC stack over `tls` and return where it listens.
async fn serve(db: &Surreal<Db>, auth: &AuthConfig, tls: ServerConfig) -> SocketAddr {
    // `start_grpc_server` binds for itself, so reserve a port and release it.
    let addr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let (db, auth) = (db.clone(), auth.clone());
    tokio::spawn(async move {
        let grpc_config = GrpcConfig {
            host: "127.0.0.1".into(),
            port: addr.port(),
            ..GrpcConfig::default()
        };
        let lockout = axiam_auth::lockout::StaticLockoutPolicy(
            axiam_auth::lockout::policy_from_config(&auth),
        );
        let result = start_grpc_server(
            addr,
            engine(&db),
            SurrealUserRepository::new(db.clone()),
            auth,
            &grpc_config,
            db.clone(),
            16,
            None,
            engine(&db),
            SurrealReactorRepository::new(db.clone()),
            SurrealAuditLogRepository::new(db.clone()),
            Arc::new(|_tenant| {}),
            true,
            Arc::new(tokio::sync::Semaphore::new(4)),
            Arc::new(lockout),
            GrpcTls::Rustls(Arc::new(tls)),
        )
        .await;
        panic!("the gRPC listener stopped: {result:?}");
    });

    for _ in 0..200 {
        if TcpStream::connect(addr).await.is_ok() {
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("the gRPC listener never came up on {addr}");
}

/// RFC 8705 §3.1 `x5t#S256` over a DER certificate.
fn thumbprint(der: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(der))
}

/// A device token as `/auth/device` mints it since S-3: machine audience,
/// bound to `presented`'s thumbprint when given.
fn device_token(auth: &AuthConfig, bound_to: Option<&Leaf>) -> String {
    issue_service_account_token(
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4().to_string(),
        bound_to.map(|l| CnfClaim::from_certificate_thumbprint(thumbprint(l.der.as_ref()))),
        auth,
    )
    .unwrap()
}

/// Introspect `token` with `token` itself as the bearer, over a connection
/// that presents `presenting` (or nothing).
///
/// `Ok(cnf thumbprint)` when the interceptor let the call through; the `Err`
/// is the status it answered with, or the transport error when the handshake
/// itself was refused.
async fn introspect_self(
    pki: &Pki,
    addr: SocketAddr,
    token: &str,
    presenting: Option<&Leaf>,
) -> Result<String, String> {
    let mut tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&pki.server_ca.pem))
        .domain_name("localhost");
    if let Some(l) = presenting {
        tls = tls.identity(Identity::from_pem(&l.cert_pem, &l.key_pem));
    }
    let channel = Channel::from_shared(format!("https://{addr}"))
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .map_err(|e| format!("transport: {e:?}"))?;

    let bearer: tonic::metadata::MetadataValue<_> = format!("Bearer {token}").parse().unwrap();
    let mut client =
        TokenServiceClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
            req.metadata_mut().insert("authorization", bearer.clone());
            Ok(req)
        });
    let response = client
        .introspect_token(IntrospectTokenRequest {
            access_token: token.to_owned(),
        })
        .await
        .map_err(|status| format!("{:?}: {}", status.code(), status.message()))?
        .into_inner();
    assert!(
        response.active,
        "a token the interceptor admitted introspects as active"
    );
    Ok(response.cnf.map(|c| c.x5t_s256).unwrap_or_default())
}

fn assert_unauthenticated(result: Result<String, String>, why: &str) {
    match result {
        Err(e) if e.starts_with("Unauthenticated") => {}
        other => panic!("{why}: expected Unauthenticated, got {other:?}"),
    }
}

/// One-time process setup: tonic's client side resolves the process-default
/// provider, and this binary links two (see tests/grpc_tls_crypto_provider.rs).
fn init() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

// ---------------------------------------------------------------------------
// I1 — `off` is the listener T-234 shipped
// ---------------------------------------------------------------------------

/// The pre-S-8 gRPC `ServerConfig`, reconstructed from the code it replaced:
/// ring, TLS 1.3 only, `with_no_client_auth()`, ALPN `h2`. The leaf is
/// installed with `with_single_cert` rather than through the reloadable
/// resolver, which decides *which* leaf is served and nothing about the
/// handshake's shape.
fn todays_config(pki: &Pki) -> ServerConfig {
    let mut config = ServerConfig::builder_with_provider(ring())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![pki.server.der.clone()],
            PrivateKeyDer::from_pem_slice(pki.server.key_pem.as_bytes()).unwrap(),
        )
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    config
}

/// **I1.** Under `off`, every client shape gets exactly the handshake the
/// pre-S-8 listener gave it — and a client that *offers* a certificate is
/// neither asked for it nor has it reach the server.
///
/// `off` is taken the way an operator reaches it: through
/// `resolve_grpc_tls` with only the two certificate variables set, then the
/// production builder.
#[tokio::test]
async fn off_is_byte_for_byte_todays_handshake() {
    init();
    let pki = pki();
    let dir = Scratch::new();
    let cert = dir.write("server.pem", &pki.server.cert_pem);
    let key = dir.write("server.key", &pki.server.key_pem);
    let (cert_s, key_s) = (cert.display().to_string(), key.display().to_string());
    let settings = resolve_grpc_tls(|name| match name {
        "AXIAM__GRPC_TLS_CERT_PATH" => Some(cert_s.clone()),
        "AXIAM__GRPC_TLS_KEY_PATH" => Some(key_s.clone()),
        _ => None,
    })
    .unwrap()
    .expect("both certificate variables set is TLS");
    assert_eq!(settings.client_auth, GrpcClientAuth::off());
    let off = Arc::new(
        build_grpc_rustls_server_config_with_client_auth(
            &settings.cert_path,
            &settings.key_path,
            &settings.client_auth,
        )
        .unwrap(),
    );
    let today = Arc::new(todays_config(&pki));

    let presenting = leaf(&pki.a, &["device-01.example"]);
    for shape in [
        Shape::Anonymous,
        Shape::Presenting(&presenting),
        Shape::Tls12Only,
        Shape::Http11Only,
    ] {
        let before = probe(Arc::clone(&today), &pki, shape).await;
        let after = probe(Arc::clone(&off), &pki, shape).await;
        assert_eq!(after, before, "the handshake differs for {shape:?}");
        assert!(!after.client_was_asked, "`off` must never ask ({shape:?})");
        assert_eq!(
            after.server_peer_certs, None,
            "nothing may reach the server"
        );
    }
    assert!(
        probe(Arc::clone(&off), &pki, Shape::Anonymous)
            .await
            .server_accepted,
        "control: the ordinary client is served"
    );

    // And the consequence one layer up: over the real listener under `off`,
    // a certificate the client holds is not exposed to the interceptor, so a
    // token bound to it is refused exactly as before S-8 — while an unbound
    // token is served as it always was.
    let db = database().await;
    let auth = auth_config();
    let addr = serve(&db, &auth, (*off).clone()).await;
    assert_unauthenticated(
        introspect_self(
            &pki,
            addr,
            &device_token(&auth, Some(&presenting)),
            Some(&presenting),
        )
        .await,
        "under `off` the certificate must not reach `peer_certs()`",
    );
    assert_eq!(
        introspect_self(&pki, addr, &device_token(&auth, None), Some(&presenting)).await,
        Ok(String::new()),
        "an unbound token is served under `off`, certificate or not"
    );
}

// ---------------------------------------------------------------------------
// required / optional at the handshake
// ---------------------------------------------------------------------------

#[tokio::test]
async fn required_refuses_a_handshake_without_a_client_certificate() {
    init();
    let pki = pki();
    let dir = Scratch::new();
    let required = Arc::new(server_config(&pki, &dir, GrpcClientAuth::required));

    let anonymous = probe(Arc::clone(&required), &pki, Shape::Anonymous).await;
    assert!(anonymous.client_was_asked, "`required` asks");
    assert!(
        !anonymous.server_accepted,
        "and refuses a client with nothing to give"
    );

    let foreign = leaf(&pki.b, &["device-b.example"]);
    assert!(
        !probe(Arc::clone(&required), &pki, Shape::Presenting(&foreign))
            .await
            .server_accepted,
        "a certificate from a CA that is not an anchor is refused too"
    );

    // The I4 twin: a certificate that chains to the anchor is admitted, and
    // the server holds it afterwards.
    let device = leaf(&pki.a, &["device-01.example"]);
    let admitted = probe(Arc::clone(&required), &pki, Shape::Presenting(&device)).await;
    assert!(
        admitted.server_accepted,
        "a chained certificate is admitted"
    );
    assert_eq!(admitted.server_peer_certs, Some(1));

    // End to end: the refusal happens before any RPC is answered.
    let db = database().await;
    let auth = auth_config();
    let addr = serve(&db, &auth, (*required).clone()).await;
    let refused = introspect_self(&pki, addr, &device_token(&auth, None), None).await;
    assert!(
        refused
            .as_ref()
            .is_err_and(|e| !e.starts_with("Unauthenticated")),
        "without a certificate the call must fail in the transport, not reach the \
         interceptor: {refused:?}"
    );
}

#[tokio::test]
async fn optional_accepts_both_and_exposes_the_certificate_when_present() {
    init();
    let pki = pki();
    let dir = Scratch::new();
    let optional = Arc::new(server_config(&pki, &dir, GrpcClientAuth::optional));

    let anonymous = probe(Arc::clone(&optional), &pki, Shape::Anonymous).await;
    assert!(anonymous.client_was_asked, "`optional` asks");
    assert!(
        anonymous.server_accepted,
        "and accepts a client that has nothing"
    );
    assert_eq!(anonymous.server_peer_certs, None);

    let device = leaf(&pki.a, &["device-01.example"]);
    let presenting = probe(Arc::clone(&optional), &pki, Shape::Presenting(&device)).await;
    assert!(presenting.server_accepted);
    assert_eq!(
        presenting.server_peer_certs,
        Some(1),
        "the certificate is held"
    );

    let foreign = leaf(&pki.b, &["device-b.example"]);
    assert!(
        !probe(Arc::clone(&optional), &pki, Shape::Presenting(&foreign))
            .await
            .server_accepted,
        "`optional` still verifies what it is given: an unchained certificate is refused"
    );

    // Exposed to the application: the interceptor matches the bound token's
    // thumbprint against the certificate, which it can only have read from
    // `Request::peer_certs()`.
    let db = database().await;
    let auth = auth_config();
    let addr = serve(&db, &auth, (*optional).clone()).await;
    assert_eq!(
        introspect_self(
            &pki,
            addr,
            &device_token(&auth, Some(&device)),
            Some(&device)
        )
        .await,
        Ok(thumbprint(device.der.as_ref())),
    );
    assert_eq!(
        introspect_self(&pki, addr, &device_token(&auth, None), None).await,
        Ok(String::new()),
        "an anonymous client with an unbound token is served as before"
    );
}

// ---------------------------------------------------------------------------
// The payoff of S-3 on this transport
// ---------------------------------------------------------------------------

/// A device token bound to its certificate (S-3) is accepted over gRPC when
/// that certificate is presented — under both verifying modes. Before S-8 no
/// certificate could arrive here, so this token was refused on every call.
#[tokio::test]
async fn a_bound_token_with_its_certificate_is_accepted() {
    init();
    let pki = pki();
    let device = leaf(&pki.a, &["device-01.example"]);
    for mode in [GrpcClientAuth::optional, GrpcClientAuth::required] {
        let dir = Scratch::new();
        let db = database().await;
        let auth = auth_config();
        let addr = serve(&db, &auth, server_config(&pki, &dir, mode)).await;

        assert_eq!(
            introspect_self(
                &pki,
                addr,
                &device_token(&auth, Some(&device)),
                Some(&device)
            )
            .await,
            Ok(thumbprint(device.der.as_ref())),
        );
        // I4 twin: an unbound token is not affected by the certificate.
        assert_eq!(
            introspect_self(&pki, addr, &device_token(&auth, None), Some(&device)).await,
            Ok(String::new()),
        );
    }
}

/// A token bound to one device's certificate, presented over a connection
/// authenticated by another device's — a valid certificate from the same
/// anchor, so the handshake succeeds and only the binding can refuse it.
#[tokio::test]
async fn a_bound_token_presented_with_a_different_certificate_is_refused() {
    init();
    let pki = pki();
    let owner = leaf(&pki.a, &["device-01.example"]);
    let other = leaf(&pki.a, &["device-02.example"]);
    for (mode, required) in [
        (
            GrpcClientAuth::optional as fn(PathBuf) -> GrpcClientAuth,
            false,
        ),
        (GrpcClientAuth::required, true),
    ] {
        let dir = Scratch::new();
        let db = database().await;
        let auth = auth_config();
        let addr = serve(&db, &auth, server_config(&pki, &dir, mode)).await;

        let stolen = device_token(&auth, Some(&owner));
        assert_unauthenticated(
            introspect_self(&pki, addr, &stolen, Some(&other)).await,
            "another device's certificate must not satisfy the binding",
        );
        let anonymous = introspect_self(&pki, addr, &stolen, None).await;
        if required {
            // The anonymous connection is refused in the handshake and never
            // reaches the interceptor. Its client completes its TLS 1.3 flight
            // first, so the refusal surfaces on the first call as a transport
            // failure rather than at `connect()`.
            assert!(
                anonymous
                    .as_ref()
                    .is_err_and(|e| !e.starts_with("Unauthenticated")),
                "under `required` no certificate is a handshake refusal: {anonymous:?}"
            );
        } else {
            assert_unauthenticated(anonymous, "no certificate must not satisfy the binding");
        }
        // The twin: the owner's own certificate still works on this listener.
        assert!(
            introspect_self(&pki, addr, &stolen, Some(&owner))
                .await
                .is_ok()
        );
    }
}

// ---------------------------------------------------------------------------
// One reload path
// ---------------------------------------------------------------------------

/// Flagging a CA as an mTLS trust anchor reaches the gRPC listener without a
/// restart, through the same reload the REST listener takes.
///
/// Driven through `TrustAnchorReload` — the object the admin API's "flag this
/// CA" handler calls — so the path is the whole one: database, bundle file,
/// `reload_trust_anchors`, and the gRPC listener's verifier re-reading the
/// bundle it was pointed at. The listener is pointed at that same bundle, which
/// is the documented topology.
#[tokio::test]
async fn a_reloaded_anchor_is_honoured_on_the_grpc_listener() {
    init();
    let pki = pki();
    let dir = Scratch::new();
    let db = database().await;
    let auth = auth_config();

    // CA A is flagged at boot; the bundle is what the boot path would write.
    let organization = Uuid::new_v4();
    let repo = SurrealCaCertificateRepository::new(db.clone());
    store_flagged_ca(&repo, organization, &pki.a.pem).await;
    let reloader = TrustAnchorReload::new(
        SurrealCaCertificateRepository::new(db.clone()),
        Some(dir.0.join("client-ca-bundle.pem")),
    );
    reloader.reload().await.expect("the boot bundle is written");

    let config = server_config(&pki, &dir, |_| {
        GrpcClientAuth::required(dir.0.join("client-ca-bundle.pem"))
    });
    let addr = serve(&db, &auth, config).await;

    let from_b = leaf(&pki.b, &["device-b.example"]);
    let token = device_token(&auth, Some(&from_b));
    assert!(
        introspect_self(&pki, addr, &token, Some(&from_b))
            .await
            .is_err(),
        "before CA B is flagged, its certificates are refused"
    );

    store_flagged_ca(&repo, organization, &pki.b.pem).await;
    assert_eq!(
        reloader.reload().await.expect("the reload succeeds"),
        Some(2),
        "the reload reports the gRPC listener's anchors as applied, not `restart`"
    );

    assert_eq!(
        introspect_self(&pki, addr, &token, Some(&from_b)).await,
        Ok(thumbprint(from_b.der.as_ref())),
        "after the reload, CA B's certificate completes the handshake on a new \
         connection and satisfies the binding"
    );
    let from_a = leaf(&pki.a, &["device-a.example"]);
    assert!(
        introspect_self(
            &pki,
            addr,
            &device_token(&auth, Some(&from_a)),
            Some(&from_a)
        )
        .await
        .is_ok(),
        "and CA A, still flagged, is still trusted"
    );
}

async fn store_flagged_ca(repo: &SurrealCaCertificateRepository<Db>, org: Uuid, pem: &str) {
    let id = Uuid::new_v4();
    repo.create(StoreCaCertificate {
        id,
        organization_id: org,
        tenant_id: None,
        parent_ca_id: None,
        subject: "Client CA".into(),
        public_cert_pem: pem.into(),
        chain_pem: None,
        fingerprint: format!("fp-{id}"),
        key_algorithm: KeyAlgorithm::Ed25519,
        not_before: chrono::Utc::now() - chrono::Duration::days(1),
        not_after: chrono::Utc::now() + chrono::Duration::days(365),
        encrypted_private_key: None,
        key_custody: CaKeyCustody::Vault,
        key_locator: Some(format!("axiam/ca/{id}")),
    })
    .await
    .unwrap();
    repo.set_mtls_trust_anchor(org, id, true).await.unwrap();
}
