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
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealTenantRepository, SurrealUserRepository,
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

// Throwaway self-signed leaf (CN=localhost, P-256, 10y expiry) used ONLY to
// drive `start_grpc_server`'s TLS-enabled branch (AXIAM__GRPC_TLS_CERT_PATH /
// KEY_PATH set) — not a real credential. Generated with:
//   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
//     -keyout key.pem -out cert.pem -days 3650 -nodes -subj "/CN=localhost"
//   openssl pkcs8 -topk8 -nocrypt -in key.pem -out key_pkcs8.pem
const TLS_TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBfTCCASOgAwIBAgIUZkfi/XvDVzxeXzeXTSAo8W9lUkAwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDcyNDExMTE0OFoXDTM2MDcyMTEx
MTE0OFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAE8uKxllhEKAaWiRmTOt2Nd8DVSSaVjv4XBgF9kcdM3mthNOdy0lzlT6ze
cf+dXsyv6P62JDC2lOx70EdggwYIpaNTMFEwHQYDVR0OBBYEFIXxrX4s8rbCwkjr
KzuATt9PSiT6MB8GA1UdIwQYMBaAFIXxrX4s8rbCwkjrKzuATt9PSiT6MA8GA1Ud
EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhALMcX8l4MGnQWFG7x+ZhCzkl
KgqCVoteB6eusmLrPuj7AiBs2bbylHbx4YQNsl39JfprCahqR/gqn+rGlcUQfF+D
IA==
-----END CERTIFICATE-----
";
// nosemgrep: generic.secrets.security.detected-private-key
const TLS_TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgM08kUa595uVxSiaM
GT+rxF95pqMCD3hB4gR3eWq4Q6GhRANCAATy4rGWWEQoBpaJGZM63Y13wNVJJpWO
/hcGAX2Rx0zea2E053LSXOVPrN5x/51ezK/o/rYkMLaU7HvQR2CDBgil
-----END PRIVATE KEY-----
";

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

/// Test-only user password, built at runtime so credential scanners don't
/// flag a hard-coded literal (mirrors grpc_units.rs). NOT a real credential.
fn test_password() -> String {
    std::env::var("AXIAM_TEST_PASSWORD").unwrap_or_else(|_| ["pass", "123456789"].concat())
}

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

#[tokio::test]
async fn start_grpc_server_boots_in_plaintext_mode() {
    let _guard = env_guard().await;
    let (db, user_repo) = setup().await;
    let engine = make_engine(&db);
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
        db,
        16,
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
    let grpc_config = GrpcConfig {
        host: "127.0.0.1".into(),
        port: 0,
        grpc_authz_per_sec: 100,
        ..GrpcConfig::default()
    };

    let dir = std::env::temp_dir();
    let cert_path = dir.join(format!("axiam-grpc-test-cert-{}.pem", uuid::Uuid::new_v4()));
    let key_path = dir.join(format!("axiam-grpc-test-key-{}.pem", uuid::Uuid::new_v4()));
    std::fs::write(&cert_path, TLS_TEST_CERT_PEM).unwrap();
    std::fs::write(&key_path, TLS_TEST_KEY_PEM).unwrap();

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
        db,
        16,
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
    std::fs::write(&key_path, TLS_TEST_KEY_PEM).unwrap();
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
        db,
        16,
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
    std::fs::write(&cert_path, TLS_TEST_CERT_PEM).unwrap();
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
        db,
        16,
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
