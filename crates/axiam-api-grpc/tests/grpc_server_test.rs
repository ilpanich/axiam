//! Boot-path coverage for `start_grpc_server` and the gRPC rate-limit layer
//! constructors — driven without the `client` feature so it runs in the
//! default coverage pass.
//!
//! `start_grpc_server` serves forever, so each boot test races it against a
//! short timeout: all of the synchronous setup (rate-limit layers, service
//! registration, transport limits, TLS branch selection) executes before the
//! server parks on its accept loop, which is exactly the code we want to cover.
//!
//! # What moved out of here in R-1
//!
//! The two "a set-but-unreadable path must panic at boot" tests used to live
//! here, because `start_grpc_server` read `AXIAM__GRPC_TLS_CERT_PATH` /
//! `_KEY_PATH` itself. It no longer does — the composition root reads them and
//! passes a [`GrpcTls`] value, because building a config that shares the REST
//! listener's certificate resolver is only possible in the crate that owns the
//! resolver. Those tests moved with the behaviour, to
//! `axiam-server`'s `tls` module, along with new coverage for the resolver
//! being genuinely shared. Nothing about the guarantee changed: a typo is
//! still a failed boot.
//!
//! What is tested here instead is that both listener modes come up. The TLS
//! mode's *behaviour* — a renewal mid-flight, a TLS 1.2 client refused, the
//! peer address reaching the rate limiter, a handshake flood — is covered by
//! the unit tests in `src/tls_incoming.rs`, which can drive the accept loop
//! directly.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axiam_api_grpc::GrpcConfig;
use axiam_api_grpc::middleware::rate_limit::{GrpcSharedRateLimitLayer, build_grpc_governor_layer};
use axiam_api_grpc::{GrpcTls, start_grpc_server};
use axiam_auth::config::AuthConfig;
use axiam_authz::AuthorizationEngine;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealGroupRepository, SurrealOrganizationRepository,
    SurrealPermissionRepository, SurrealReactorRepository, SurrealResourceRepository,
    SurrealRoleRepository, SurrealScopeRepository, SurrealTenantRepository, SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

type TestDb = surrealdb::engine::local::Db;
type TestEngine = AuthorizationEngine<
    SurrealRoleRepository<TestDb>,
    SurrealPermissionRepository<TestDb>,
    SurrealResourceRepository<TestDb>,
    SurrealScopeRepository<TestDb>,
    SurrealGroupRepository<TestDb>,
>;

const PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n-----END PRIVATE KEY-----";
const PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n-----END PUBLIC KEY-----";

/// A TLS 1.3-only server configuration over a throwaway self-signed leaf
/// (CN=localhost), generated at test runtime rather than written as a PEM
/// literal (which static secret scanners flag). Not a real credential.
///
/// Shaped like what `axiam_server::tls::build_grpc_rustls_server_config`
/// hands the listener in production — that function cannot be called from
/// here, since `axiam-server` is layer 8 and this crate is layer 6.
fn test_tls_config() -> Arc<rustls::ServerConfig> {
    // Mirrors axiam-server's main(): both `ring` and `aws-lc-rs` are linked
    // transitively, so nothing may resolve the process-default provider
    // implicitly. Selecting one explicitly is what the production builder does.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed test cert");
    let cert = rustls::pki_types::CertificateDer::from(generated.cert.der().to_vec());
    let key = rustls::pki_types::PrivateKeyDer::try_from(generated.signing_key.serialize_der())
        .expect("serialize the test key to DER");

    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 must be configurable")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("the generated pair must build a server config");
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

use axiam_test_support::test_password;

fn test_auth_config() -> AuthConfig {
    AuthConfig {
        jwt_private_key_pem: PRIV_PEM.into(),
        jwt_public_key_pem: PUB_PEM.into(),
        jwt_issuer: "axiam-test".into(),
        ..Default::default()
    }
}

async fn setup() -> (Surreal<TestDb>, SurrealUserRepository<TestDb>) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Boot Org".into(),
            slug: "boot-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Boot Tenant".into(),
            slug: "boot-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user_repo = SurrealUserRepository::new(db.clone());
    user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "boot-user".into(),
            email: "boot-user@example.com".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap();

    (db.clone(), user_repo)
}

fn make_engine(db: &Surreal<TestDb>) -> TestEngine {
    AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    )
}

/// X1 / R2.3 — the extra reactor-admin arguments every `start_grpc_server`
/// call site below now needs: its own `AuthorizationEngine` instance (the
/// type does not implement `Clone`, so `make_engine` is called again rather
/// than reused), a reactor repository, an audit repository, and a routing
/// invalidator. These boot tests never register a reactor, so a no-op
/// invalidator is correct — nothing here exercises `ReactorAdminService`
/// itself; that lives in the CRUD-level test coverage for the service.
#[allow(clippy::type_complexity)]
fn reactor_admin_args(
    db: &Surreal<TestDb>,
) -> (
    TestEngine,
    SurrealReactorRepository<TestDb>,
    SurrealAuditLogRepository<TestDb>,
    std::sync::Arc<dyn Fn(uuid::Uuid) + Send + Sync>,
) {
    (
        make_engine(db),
        SurrealReactorRepository::new(db.clone()),
        SurrealAuditLogRepository::new(db.clone()),
        std::sync::Arc::new(|_tenant_id| {}),
    )
}

/// Everything `start_grpc_server` needs that these boot tests do not vary,
/// so the two mode tests below differ in exactly one argument — the [`GrpcTls`]
/// value — and a reader can see that that is the only difference.
#[allow(clippy::type_complexity)]
async fn boot(tls: GrpcTls) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (db, user_repo) = setup().await;
    let engine = make_engine(&db);
    let (reactor_engine, reactor_repo, reactor_audit_repo, reactor_routing_invalidator) =
        reactor_admin_args(&db);
    let grpc_config = GrpcConfig {
        host: "127.0.0.1".into(),
        port: 0,
        grpc_authz_per_sec: 100,
        ..GrpcConfig::default()
    };
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    start_grpc_server(
        addr,
        engine,
        user_repo,
        test_auth_config(),
        &grpc_config,
        db.clone(),
        16,
        // A4/J10: strict revocation off — the shipped default posture.
        None,
        reactor_engine,
        reactor_repo,
        reactor_audit_repo,
        reactor_routing_invalidator,
        // SEC-101: the test double's transport can dispatch.
        true,
        // B1: in production this is a clone of `AppState`'s process-wide gate;
        // these tests only need the boot path to accept one.
        std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
        // In production this resolves the tenant's configured
        // `max_failed_login_attempts` from the settings store; the boot path
        // only needs to accept a source.
        std::sync::Arc::new(axiam_auth::lockout::StaticLockoutPolicy(
            axiam_auth::lockout::policy_from_config(&test_auth_config()),
        )),
        tls,
    )
    .await
}

/// Plan §2 test 5 — plaintext mode is unchanged by R-1.
///
/// This arm still goes straight through `Router::serve(addr)`: tonic binds,
/// tonic sets `TCP_NODELAY`, nothing in `tls_incoming` runs. The E2E suite and
/// every benchmark that is not the native-TLS overlay depend on that, so it is
/// asserted rather than assumed.
#[tokio::test]
async fn start_grpc_server_boots_in_plaintext_mode() {
    // The server serves indefinitely; time out once all setup has run and it
    // has parked on its accept loop. A timeout (not a completion) is the
    // success signal that boot reached the serving state without erroring.
    let result = tokio::time::timeout(Duration::from_millis(400), boot(GrpcTls::Plaintext)).await;
    assert!(
        result.is_err(),
        "server unexpectedly returned before timeout: {result:?}"
    );
}

/// TLS-enabled boot path (REQ-15 AC-1 / R-1): given a `GrpcTls::Rustls`
/// configuration, the listener must bind, stand up its own accept loop, and
/// park exactly like the plaintext path — same race-against-timeout technique.
///
/// Where the pre-R-1 version of this test set two environment variables, this
/// one passes a value: reading the environment is the composition root's job
/// now, and `axiam-server`'s tests cover it.
#[tokio::test]
async fn start_grpc_server_boots_in_tls_mode() {
    let result = tokio::time::timeout(
        Duration::from_millis(400),
        boot(GrpcTls::Rustls(test_tls_config())),
    )
    .await;
    assert!(
        result.is_err(),
        "TLS-mode server unexpectedly returned before timeout: {result:?}"
    );
}

/// A `GrpcTls` value is cloneable, because the composition root builds one and
/// the listener task takes it by value.
///
/// Trivial, and worth one line: `Arc<ServerConfig>` is what makes it cheap, and
/// someone replacing it with an owned `ServerConfig` would make every clone a
/// full copy of the certificate resolver's handle graph — and, worse, would
/// stop the two listeners sharing one resolver.
#[test]
fn grpc_tls_is_cheaply_cloneable() {
    let tls = GrpcTls::Rustls(test_tls_config());
    let clone = tls.clone();
    match (tls, clone) {
        (GrpcTls::Rustls(a), GrpcTls::Rustls(b)) => {
            assert!(Arc::ptr_eq(&a, &b), "cloning must share the configuration");
        }
        _ => panic!("clone must preserve the variant"),
    }
}

#[test]
fn build_grpc_governor_layer_constructs_with_valid_rate() {
    // Exercises the quota/burst math and key-extractor wiring.
    let _layer = build_grpc_governor_layer(50);
}

#[test]
#[should_panic(expected = "grpc_authz_per_sec must be >= 1")]
fn build_grpc_governor_layer_panics_on_zero_rate() {
    let _ = build_grpc_governor_layer(0);
}

#[tokio::test]
async fn shared_rate_limit_layer_is_cloneable() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    let layer = GrpcSharedRateLimitLayer::new(db, "grpc_authz", 100, 0);
    // Cloning is what tonic/tower does per connection — cover the Clone impl.
    let _clone = layer.clone();
}
