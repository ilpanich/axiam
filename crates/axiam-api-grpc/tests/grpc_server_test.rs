//! Boot-path coverage for `start_grpc_server` and the gRPC rate-limit layer
//! constructors — driven without the `client` feature so it runs in the
//! default coverage pass.
//!
//! `start_grpc_server` serves forever, so each boot test races it against a
//! short timeout: all of the synchronous setup (rate-limit layers, service
//! registration, transport limits, TLS branch selection) executes before the
//! server parks on `serve()`, which is exactly the code we want to cover.

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::Mutex;

use axiam_api_grpc::GrpcConfig;
use axiam_api_grpc::middleware::rate_limit::{GrpcSharedRateLimitLayer, build_grpc_governor_layer};
use axiam_api_grpc::start_grpc_server;
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

/// Generates a throwaway self-signed leaf (CN=localhost) at test runtime,
/// used ONLY to drive `start_grpc_server`'s TLS-enabled branch
/// (AXIAM__GRPC_TLS_CERT_PATH / KEY_PATH set) — not a real credential.
/// Runtime-generated (rather than a hard-coded PEM literal) so static
/// secret scanners don't flag it.
fn test_tls_pki() -> (String, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed test cert");
    (cert.cert.pem(), cert.signing_key.serialize_pem())
}

// ---------------------------------------------------------------------------
// Global env-mutation lock — `AXIAM__GRPC_TLS_CERT_PATH` / `KEY_PATH` are
// process-global, so the plaintext-mode and TLS-mode boot tests (which set
// opposite states) must not race within this test binary. Mirrors the
// `env_lock`/`env_guard` pattern in axiam-api-rest/tests/bootstrap_test.rs.
// ---------------------------------------------------------------------------

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

async fn env_guard() -> tokio::sync::MutexGuard<'static, ()> {
    env_lock().lock().await
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

#[tokio::test]
async fn start_grpc_server_boots_in_plaintext_mode() {
    let _guard = env_guard().await;
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
    // Ensure the TLS branch is NOT taken.
    unsafe {
        std::env::remove_var("AXIAM__GRPC_TLS_CERT_PATH");
        std::env::remove_var("AXIAM__GRPC_TLS_KEY_PATH");
    }

    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = start_grpc_server(
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
    );

    // The server serves indefinitely; time out once all setup has run and it
    // has parked on `serve()`. A timeout (not a completion) is the success
    // signal that boot reached the serving state without erroring.
    let result = tokio::time::timeout(Duration::from_millis(400), server).await;
    assert!(
        result.is_err(),
        "server unexpectedly returned before timeout: {result:?}"
    );
}

/// TLS-enabled boot path (REQ-15 AC-1): with both `AXIAM__GRPC_TLS_CERT_PATH`
/// and `AXIAM__GRPC_TLS_KEY_PATH` pointing at readable PEM files, the server
/// must take the `ServerTlsConfig` branch (reads the cert/key files, builds
/// the `Identity`, wires it into the builder) and park on `serve()` exactly
/// like the plaintext path — same race-against-timeout technique as above.
#[tokio::test]
async fn start_grpc_server_boots_in_tls_mode() {
    // Mirror axiam-server's main(): tonic's `ServerTlsConfig` resolves the
    // process-level rustls `CryptoProvider`, but with both `ring` (tonic's
    // "tls-ring" feature) and `aws-lc-rs` linked transitively, rustls refuses
    // to auto-select one. Installing `ring` explicitly is what
    // axiam-server/tests/grpc_tls_crypto_provider.rs proves fixes the
    // real panic-on-handshake bug; idempotent across tests in this binary.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let _guard = env_guard().await;
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

    let dir = std::env::temp_dir();
    let cert_path = dir.join(format!("axiam-grpc-test-cert-{}.pem", uuid::Uuid::new_v4()));
    let key_path = dir.join(format!("axiam-grpc-test-key-{}.pem", uuid::Uuid::new_v4()));
    let (cert_pem, key_pem) = test_tls_pki();
    std::fs::write(&cert_path, cert_pem).unwrap();
    std::fs::write(&key_path, key_pem).unwrap();

    // SAFETY: serialized by `env_guard()` above — no other test in this
    // binary observes or mutates these two vars concurrently.
    unsafe {
        std::env::set_var("AXIAM__GRPC_TLS_CERT_PATH", &cert_path);
        std::env::set_var("AXIAM__GRPC_TLS_KEY_PATH", &key_path);
    }

    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = start_grpc_server(
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
    );

    let result = tokio::time::timeout(Duration::from_millis(400), server).await;

    unsafe {
        std::env::remove_var("AXIAM__GRPC_TLS_CERT_PATH");
        std::env::remove_var("AXIAM__GRPC_TLS_KEY_PATH");
    }
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert!(
        result.is_err(),
        "TLS-mode server unexpectedly returned before timeout: {result:?}"
    );
}

/// Drop guard that always clears the two TLS env vars and removes any temp
/// PEM files, even when the test body panics (as the two tests below
/// deliberately do) — otherwise a panicking test would leak state into
/// whichever test in this binary runs next.
struct TlsEnvCleanup {
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
}

impl Drop for TlsEnvCleanup {
    fn drop(&mut self) {
        unsafe {
            std::env::remove_var("AXIAM__GRPC_TLS_CERT_PATH");
            std::env::remove_var("AXIAM__GRPC_TLS_KEY_PATH");
        }
        let _ = std::fs::remove_file(&self.cert_path);
        let _ = std::fs::remove_file(&self.key_path);
    }
}

/// REQ-15 AC-1 defensive check: if `AXIAM__GRPC_TLS_CERT_PATH` is set but the
/// file isn't readable, the server must fail loudly at boot (a `panic!` with
/// a clear message) rather than silently falling back to plaintext or
/// producing an opaque I/O error deep in tonic's transport stack.
#[tokio::test]
#[should_panic(expected = "AXIAM__GRPC_TLS_CERT_PATH set but file not readable")]
async fn start_grpc_server_panics_when_cert_file_unreadable() {
    let _guard = env_guard().await;
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

    let dir = std::env::temp_dir();
    let missing_cert = dir.join(format!(
        "axiam-grpc-missing-cert-{}.pem",
        uuid::Uuid::new_v4()
    ));
    let key_path = dir.join(format!("axiam-grpc-test-key-{}.pem", uuid::Uuid::new_v4()));
    let (_cert_pem, key_pem) = test_tls_pki();
    std::fs::write(&key_path, key_pem).unwrap();
    let _cleanup = TlsEnvCleanup {
        cert_path: missing_cert.clone(),
        key_path: key_path.clone(),
    };

    // SAFETY: serialized by `env_guard()`.
    unsafe {
        std::env::set_var("AXIAM__GRPC_TLS_CERT_PATH", &missing_cert);
        std::env::set_var("AXIAM__GRPC_TLS_KEY_PATH", &key_path);
    }

    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    // No timeout race here: the panic happens synchronously (before the
    // function reaches any await point), so a direct `.await` observes it.
    let _ = start_grpc_server(
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
        std::sync::Arc::new(axiam_auth::lockout::StaticLockoutPolicy(
            axiam_auth::lockout::policy_from_config(&test_auth_config()),
        )),
    )
    .await;
}

/// Same defensive check for `AXIAM__GRPC_TLS_KEY_PATH` (checked second, after
/// the cert path succeeds).
#[tokio::test]
#[should_panic(expected = "AXIAM__GRPC_TLS_KEY_PATH set but file not readable")]
async fn start_grpc_server_panics_when_key_file_unreadable() {
    let _guard = env_guard().await;
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

    let dir = std::env::temp_dir();
    let cert_path = dir.join(format!("axiam-grpc-test-cert-{}.pem", uuid::Uuid::new_v4()));
    let missing_key = dir.join(format!(
        "axiam-grpc-missing-key-{}.pem",
        uuid::Uuid::new_v4()
    ));
    let (cert_pem, _key_pem) = test_tls_pki();
    std::fs::write(&cert_path, cert_pem).unwrap();
    let _cleanup = TlsEnvCleanup {
        cert_path: cert_path.clone(),
        key_path: missing_key.clone(),
    };

    // SAFETY: serialized by `env_guard()`.
    unsafe {
        std::env::set_var("AXIAM__GRPC_TLS_CERT_PATH", &cert_path);
        std::env::set_var("AXIAM__GRPC_TLS_KEY_PATH", &missing_key);
    }

    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let _ = start_grpc_server(
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
        std::sync::Arc::new(axiam_auth::lockout::StaticLockoutPolicy(
            axiam_auth::lockout::policy_from_config(&test_auth_config()),
        )),
    )
    .await;
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
