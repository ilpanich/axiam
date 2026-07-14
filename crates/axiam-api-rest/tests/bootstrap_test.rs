//! Integration tests for the admin bootstrap endpoint.
//!
//! Covers the first-run flow:
//!
//! - `POST /api/v1/admin/bootstrap` creates the organization, the default
//!   tenant AND the first admin user in one call on a fresh, empty database.
//! - After the first admin is created, the endpoint is disabled (returns 409
//!   Conflict — the global `bootstrap_lock` uniqueness invariant).
//! - When `AXIAM_BOOTSTRAP_ADMIN_EMAIL` is set, a mismatching email returns 403.
//! - The mandatory gate refuses bootstrap when neither the env var nor a
//!   valid setup token is presented (SECHRD-04 / D-03a).
//! - Two concurrent first-run requests create at most one super-admin
//!   (SECHRD-04 / D-03c).
//! - The newly-bootstrapped admin can authenticate via `/auth/login`.

use std::net::SocketAddr;
use std::sync::OnceLock;
use tokio::sync::Mutex;

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::AuthzChecker;
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_authz::AuthorizationEngine;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::repository::{OrganizationRepository, TenantRepository};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use serde_json::Value;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12345";
/// Test-only placeholder password — not a real credential.
const TEST_PASSWORD: &str = "bootstrap-test-placeholder-password"; // gitleaks:allow

// ---------------------------------------------------------------------------
// Global env-mutation lock.
//
// `std::env::set_var` is process-global. Rust 2024 requires `unsafe` for env
// mutation because another thread may be reading env simultaneously. We
// serialize the bootstrap email test with this mutex so it cannot race with
// other tests in the same test binary.
// ---------------------------------------------------------------------------

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Acquire the env-mutation lock for the duration of a test. Using
/// `tokio::sync::Mutex` is deliberate: the guard is held across `await`
/// points inside the test body, which clippy (rightly) forbids for
/// `std::sync::Mutex`.
async fn env_guard() -> tokio::sync::MutexGuard<'static, ()> {
    env_lock().lock().await
}

// ---------------------------------------------------------------------------
// Shared setup
// ---------------------------------------------------------------------------

fn test_keypair() -> (String, String) {
    // Test-only non-secret Ed25519 key pair used solely for JWT signing in unit tests.
    let pem_header = "-----BEGIN PRIVATE KEY-----"; // nosemgrep: generic.secrets.security.detected-private-key
    let pem_body = "MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM";
    let pem_footer = "-----END PRIVATE KEY-----";
    let private_key = format!("{pem_header}\n{pem_body}\n{pem_footer}");
    let public_key = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----"
        .to_owned();
    (private_key, public_key)
}

fn test_auth_config() -> AuthConfig {
    let (priv_pem, pub_pem) = test_keypair();
    AuthConfig {
        jwt_private_key_pem: priv_pem,
        jwt_public_key_pem: pub_pem,
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

fn make_authz(db: &Surreal<TestDb>) -> Arc<dyn AuthzChecker> {
    Arc::new(AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    ))
}

/// Fresh, empty in-memory DB: migrations only, NO organization, tenant, users
/// or seeded roles. The bootstrap handler creates the organization, the default
/// tenant, and seeds permissions/roles itself.
async fn setup_empty_db() -> Surreal<TestDb> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

/// Fresh DB pre-seeded with an org + default tenant (no users). Used by the
/// concurrency test so bootstrap's get-or-create reuses them and the only
/// contention under test is the global `bootstrap_lock`.
async fn setup_with_org_tenant() -> (Surreal<TestDb>, Uuid, Uuid) {
    let db = setup_empty_db().await;
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Race Org".into(),
            slug: "race-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "Default".into(),
            slug: "default".into(),
            metadata: None,
        })
        .await
        .unwrap();
    (db, org.id, tenant.id)
}

macro_rules! test_app {
    ($db:expr, $auth:expr, $authz:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new($authz.clone()))
                .app_data(web::Data::new(AppState::for_test(
                    $db.clone(),
                    $auth.clone(),
                )))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `bootstrap_setup_token`
///
/// SECHRD-04 (Task 1, D-03b): on a fresh, never-bootstrapped database the
/// mint routine mints a first-run setup token exactly once and persists
/// only its sha256 hash — the plaintext token is never written to the
/// database. Once minted (or once any user exists), subsequent calls are a
/// no-op.
#[actix_rt::test]
async fn bootstrap_setup_token() {
    use chrono::{DateTime, Utc};
    use sha2::{Digest, Sha256};
    use surrealdb::types::SurrealValue;

    #[derive(Debug, SurrealValue)]
    struct CountRow {
        total: u64,
    }

    #[derive(Debug, SurrealValue)]
    struct TokenRow {
        #[allow(dead_code)]
        created_at: DateTime<Utc>,
    }

    let db = setup_empty_db().await;

    // Fresh DB, no users: mint must produce a token.
    let minted = axiam_db::mint_bootstrap_setup_token_if_needed(&db)
        .await
        .unwrap();
    let token = minted.expect("first mint on a fresh DB must produce a token");

    // The persisted record ID is the token's sha256 hash, never the
    // plaintext — verify the record exists at exactly that hash.
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let expected_hash = hex::encode(hasher.finalize());

    let mut result = db
        .query("SELECT created_at FROM type::record('bootstrap_setup_token', $hash)")
        .bind(("hash", expected_hash))
        .await
        .unwrap();
    let rows: Vec<TokenRow> = result.take(0).unwrap();
    assert_eq!(
        rows.len(),
        1,
        "the setup token's sha256 hash must be the exact persisted record ID"
    );

    // Second call: already minted -> no-op, no new token returned.
    let second = axiam_db::mint_bootstrap_setup_token_if_needed(&db)
        .await
        .unwrap();
    assert!(
        second.is_none(),
        "a setup token must be minted at most once per database"
    );

    // Exactly one row exists in the table overall after two mint calls.
    let mut count_result = db
        .query("SELECT count() AS total FROM bootstrap_setup_token GROUP ALL")
        .await
        .unwrap();
    let counts: Vec<CountRow> = count_result.take(0).unwrap();
    assert_eq!(
        counts.first().map(|c| c.total).unwrap_or(0),
        1,
        "exactly one setup token row must exist after two mint calls"
    );
}

/// `bootstrap_creates_org_tenant_admin`
///
/// A fresh, empty database accepts the bootstrap request and creates the
/// organization, the default tenant AND the first admin — 201 Created with the
/// created ids/slugs in the body.
#[actix_rt::test]
async fn bootstrap_creates_org_tenant_admin() {
    let _guard = env_guard().await;
    // The gate is mandatory — set the env var to match the request email.
    // SAFETY: serialized via env_lock; no other thread reads env in this binary.
    unsafe {
        std::env::set_var("AXIAM_BOOTSTRAP_ADMIN_EMAIL", "first-admin@example.com");
    }

    let db = setup_empty_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let peer: SocketAddr = TEST_PEER.parse().unwrap();
    let req = test::TestRequest::post()
        .uri("/api/v1/admin/bootstrap")
        .peer_addr(peer)
        .set_json(serde_json::json!({
            "organization_name": "First Org",
            "organization_slug": "first-org",
            "tenant_name": "Default",
            "tenant_slug": "default",
            "email": "first-admin@example.com",
            "username": "firstadmin",
            "password": TEST_PASSWORD,
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    let body = test::read_body(resp).await;

    // SAFETY: serialized via env_lock.
    unsafe {
        std::env::remove_var("AXIAM_BOOTSTRAP_ADMIN_EMAIL");
    }

    assert_eq!(
        status,
        201,
        "bootstrap should return 201 on a fresh database, got {status}. body = {}",
        String::from_utf8_lossy(&body)
    );

    let body_json: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        body_json.get("user_id").is_some(),
        "response body must include user_id, got {body_json}"
    );
    assert_eq!(
        body_json.get("organization_slug").and_then(Value::as_str),
        Some("first-org")
    );
    assert_eq!(
        body_json.get("tenant_slug").and_then(Value::as_str),
        Some("default")
    );

    // The org and tenant were actually created.
    let org = SurrealOrganizationRepository::new(db.clone())
        .get_by_slug("first-org")
        .await
        .expect("bootstrap must create the organization");
    SurrealTenantRepository::new(db.clone())
        .get_by_slug(org.id, "default")
        .await
        .expect("bootstrap must create the default tenant");
}

/// `bootstrap_returns_409_after_admin`
///
/// A second bootstrap call, once the system has been initialized (with the
/// gate satisfied both times), must be rejected with 409 Conflict — the global
/// `bootstrap_lock` uniqueness invariant.
#[actix_rt::test]
async fn bootstrap_returns_409_after_admin() {
    let _guard = env_guard().await;
    // SAFETY: serialized via env_lock.
    unsafe {
        std::env::set_var("AXIAM_BOOTSTRAP_ADMIN_EMAIL", "first@example.com");
    }

    let db = setup_empty_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let peer: SocketAddr = TEST_PEER.parse().unwrap();

    // First bootstrap — must succeed.
    let req = test::TestRequest::post()
        .uri("/api/v1/admin/bootstrap")
        .peer_addr(peer)
        .set_json(serde_json::json!({
            "organization_name": "First Org",
            "email": "first@example.com",
            "username": "firstadmin",
            "password": TEST_PASSWORD,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201, "first bootstrap must succeed");

    // Second bootstrap — must be refused even though the gate is satisfied.
    let req = test::TestRequest::post()
        .uri("/api/v1/admin/bootstrap")
        .peer_addr(peer)
        .set_json(serde_json::json!({
            "organization_name": "Second Org",
            "email": "first@example.com",
            "username": "secondadmin",
            "password": TEST_PASSWORD,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();

    // SAFETY: serialized via env_lock.
    unsafe {
        std::env::remove_var("AXIAM_BOOTSTRAP_ADMIN_EMAIL");
    }

    assert_eq!(
        status, 409,
        "second bootstrap must be refused with 409 Conflict, got {status}"
    );
}

/// `bootstrap_concurrent_race_single_admin`
///
/// SECHRD-04 (Task 3, D-03c): two concurrent first-run bootstrap requests must
/// produce AT MOST ONE super-admin. The race loser gets 409 and its whole
/// transaction rolls back. The org/tenant are pre-seeded (with the slugs both
/// racers reference) so the only contention under test is the global lock.
#[actix_rt::test]
async fn bootstrap_concurrent_race_single_admin() {
    let _guard = env_guard().await;
    // SAFETY: serialized via env_lock.
    unsafe {
        std::env::remove_var("AXIAM_BOOTSTRAP_ADMIN_EMAIL");
    }

    let (db, _org_id, tenant_id) = setup_with_org_tenant().await;

    // Mint a single setup token both racers present.
    let token = axiam_db::mint_bootstrap_setup_token_if_needed(&db)
        .await
        .unwrap()
        .expect("fresh DB should mint a setup token");

    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let peer: SocketAddr = TEST_PEER.parse().unwrap();

    let make_req = |username: &str, email: &str, token: &str| {
        test::TestRequest::post()
            .uri("/api/v1/admin/bootstrap")
            .peer_addr(peer)
            .set_json(serde_json::json!({
                "organization_name": "Race Org",
                "organization_slug": "race-org",
                "tenant_name": "Default",
                "tenant_slug": "default",
                "email": email,
                "username": username,
                "password": TEST_PASSWORD,
                "setup_token": token,
            }))
            .to_request()
    };

    let req1 = make_req("racer-one", "racer-one@example.com", &token);
    let req2 = make_req("racer-two", "racer-two@example.com", &token);

    let (resp1, resp2) = tokio::join!(
        test::call_service(&app, req1),
        test::call_service(&app, req2)
    );

    let statuses = [resp1.status().as_u16(), resp2.status().as_u16()];
    let created_count = statuses.iter().filter(|s| **s == 201).count();
    let conflict_count = statuses.iter().filter(|s| **s == 409).count();

    assert_eq!(
        created_count, 1,
        "exactly one concurrent bootstrap request must succeed (201), got statuses {statuses:?}"
    );
    assert_eq!(
        conflict_count, 1,
        "the race loser must get 409 AlreadyExists, got statuses {statuses:?}"
    );

    // Exactly one super-admin exists after the race.
    use axiam_core::repository::{Pagination, UserRepository};
    let users = SurrealUserRepository::new(db.clone())
        .list(
            tenant_id,
            Pagination {
                offset: 0,
                limit: 10,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        users.total, 1,
        "exactly one super-admin must exist after a concurrent bootstrap race, got {}",
        users.total
    );
}

/// `bootstrap_rejects_wrong_email`
///
/// When `AXIAM_BOOTSTRAP_ADMIN_EMAIL` is set, requests whose email does not
/// match the expected value are rejected with 403 (D-10).
#[actix_rt::test]
async fn bootstrap_rejects_wrong_email() {
    let _guard = env_guard().await;
    // SAFETY: serialized via env_lock.
    unsafe {
        std::env::set_var("AXIAM_BOOTSTRAP_ADMIN_EMAIL", "only-me@example.com");
    }

    let db = setup_empty_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let peer: SocketAddr = TEST_PEER.parse().unwrap();
    let req = test::TestRequest::post()
        .uri("/api/v1/admin/bootstrap")
        .peer_addr(peer)
        .set_json(serde_json::json!({
            "organization_name": "Gated Org",
            "email": "someone-else@example.com",
            "username": "impostor",
            "password": TEST_PASSWORD,
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();

    // Clean up before asserting so a failure here doesn't leak state to
    // sibling tests.
    // SAFETY: serialized via env_lock.
    unsafe {
        std::env::remove_var("AXIAM_BOOTSTRAP_ADMIN_EMAIL");
    }

    assert_eq!(
        status, 403,
        "bootstrap with email-mismatch must return 403, got {status}"
    );
}

/// `bootstrap_refused_when_gate_unset`
///
/// SECHRD-04 (Task 2, D-03a): when `AXIAM_BOOTSTRAP_ADMIN_EMAIL` is unset
/// AND no (valid) setup token is presented, bootstrap must fail closed —
/// a non-2xx response and nothing created.
#[actix_rt::test]
async fn bootstrap_refused_when_gate_unset() {
    use surrealdb::types::SurrealValue;

    #[derive(Debug, SurrealValue)]
    struct CountRow {
        total: u64,
    }

    let _guard = env_guard().await;
    // SAFETY: serialized via env_lock; ensure the email gate is OFF.
    unsafe {
        std::env::remove_var("AXIAM_BOOTSTRAP_ADMIN_EMAIL");
    }

    let db = setup_empty_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let peer: SocketAddr = TEST_PEER.parse().unwrap();

    // No setup_token field at all — neither gate is satisfied.
    let req = test::TestRequest::post()
        .uri("/api/v1/admin/bootstrap")
        .peer_addr(peer)
        .set_json(serde_json::json!({
            "organization_name": "Nobody Org",
            "email": "nobody@example.com",
            "username": "nobody",
            "password": TEST_PASSWORD,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    assert!(
        !(200..300).contains(&status),
        "bootstrap with no gate satisfied must be refused (non-2xx), got {status}"
    );

    // An invalid/unknown setup token must also be refused.
    let req = test::TestRequest::post()
        .uri("/api/v1/admin/bootstrap")
        .peer_addr(peer)
        .set_json(serde_json::json!({
            "organization_name": "Nobody Org 2",
            "email": "nobody2@example.com",
            "username": "nobody2",
            "password": TEST_PASSWORD,
            "setup_token": "not-a-real-token",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    assert!(
        !(200..300).contains(&status),
        "bootstrap with an invalid setup token must be refused (non-2xx), got {status}"
    );

    // Nothing was created by either attempt (no users, no organizations).
    let mut result = db
        .query("SELECT count() AS total FROM user GROUP ALL")
        .await
        .unwrap();
    let users: Vec<CountRow> = result.take(0).unwrap();
    assert_eq!(
        users.first().map(|c| c.total).unwrap_or(0),
        0,
        "no admin should be created when the gate is unset/invalid"
    );
    let mut result = db
        .query("SELECT count() AS total FROM organization GROUP ALL")
        .await
        .unwrap();
    let orgs: Vec<CountRow> = result.take(0).unwrap();
    assert_eq!(
        orgs.first().map(|c| c.total).unwrap_or(0),
        0,
        "no organization should be created when the gate is unset/invalid"
    );
}

/// `bootstrap_admin_can_login`
///
/// After a successful bootstrap, the new admin can log in via `/auth/login`
/// with the bootstrap credentials, resolving the workspace by the created
/// org/tenant.
#[actix_rt::test]
async fn bootstrap_admin_can_login() {
    let _guard = env_guard().await;
    // SAFETY: serialized via env_lock.
    unsafe {
        std::env::set_var("AXIAM_BOOTSTRAP_ADMIN_EMAIL", "root@example.com");
    }

    let db = setup_empty_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let peer: SocketAddr = TEST_PEER.parse().unwrap();

    // 1. Bootstrap — creates org "login-org", tenant "default" and the admin.
    let req = test::TestRequest::post()
        .uri("/api/v1/admin/bootstrap")
        .peer_addr(peer)
        .set_json(serde_json::json!({
            "organization_name": "Login Org",
            "organization_slug": "login-org",
            "tenant_name": "Default",
            "tenant_slug": "default",
            "email": "root@example.com",
            "username": "rootadmin",
            "password": TEST_PASSWORD,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    // SAFETY: serialized via env_lock.
    unsafe {
        std::env::remove_var("AXIAM_BOOTSTRAP_ADMIN_EMAIL");
    }
    assert_eq!(resp.status().as_u16(), 201, "bootstrap must succeed");

    // 2. Resolve the created org/tenant ids to drive the login request. The
    //    admin is created Active, so no extra activation step is needed.
    let org = SurrealOrganizationRepository::new(db.clone())
        .get_by_slug("login-org")
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .get_by_slug(org.id, "default")
        .await
        .unwrap();

    // 3. Login with the bootstrap credentials.
    let req = test::TestRequest::post()
        .uri("/api/v1/auth/login")
        .peer_addr(peer)
        .set_json(serde_json::json!({
            "tenant_id": tenant.id,
            "org_id": org.id,
            "username_or_email": "rootadmin",
            "password": TEST_PASSWORD,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    let body = test::read_body(resp).await;
    assert_eq!(
        status,
        200,
        "bootstrapped admin must be able to log in, got {status}. body = {}",
        String::from_utf8_lossy(&body)
    );
}
