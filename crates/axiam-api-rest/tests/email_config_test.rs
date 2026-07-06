//! Integration tests for the admin email-config REST API (Task 3 — FUNC-03 / D-13).
//!
//! Uses the real-RBAC harness (mirrors `rbac_test.rs`, NOT `AllowAllAuthzChecker`)
//! because the cross-scope-403 assertions must exercise the actual authorization
//! engine + ownership check, not a bypass.
//!
//! Covers:
//! - PUT/GET round trip at org and tenant scope, secrets always omitted from the
//!   response body (D-01).
//! - A caller whose own org_id/tenant_id differs from the path parameter gets 403
//!   (T-28-01 IDOR mitigation).
//! - DELETE removes the row; a subsequent GET returns 404.
//! - D-02: an omitted secret on a second PUT preserves the previously stored
//!   secret (verified directly via the repository, since GET never re-exposes it).

use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::AuthzChecker;
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_authz::AuthorizationEngine;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    EmailConfigRepository, OrganizationRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealEmailConfigRepository, SurrealGroupRepository, SurrealOrganizationRepository,
    SurrealPermissionRepository, SurrealResourceRepository, SurrealRoleRepository,
    SurrealScopeRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_db::{seed_default_roles, seed_permissions};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

/// Test-only 32-byte email encryption key — not a real credential. gitleaks:allow
const TEST_EMAIL_KEY: [u8; 32] = [0x42; 32];

/// Test-only placeholder password — not a real credential.
const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow

/// Arbitrary CSRF double-submit token (SEC-046).
const CSRF_TOKEN: &str = "test-csrf-token";

// -------------------------------------------------------------------------
// Key / config helpers (same Ed25519 keypair as rbac_test.rs)
// -------------------------------------------------------------------------

fn test_keypair() -> (String, String) {
    let private_key = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM
-----END PRIVATE KEY-----";
    let public_key = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";
    (private_key.into(), public_key.into())
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

fn mint_token(auth: &AuthConfig, user_id: Uuid, tenant_id: Uuid, org_id: Uuid) -> String {
    issue_access_token(
        user_id,
        tenant_id,
        org_id,
        &[],
        auth,
        uuid::Uuid::new_v4().to_string(),
        axiam_auth::token::AUD_USER,
    )
    .unwrap()
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

/// Fresh in-memory DB with an org + tenant + the default permission registry
/// and default roles seeded (email_config:read/write included via
/// `PERMISSION_REGISTRY`). Returns the IDs a test needs to mint tokens.
async fn setup_db() -> (Surreal<TestDb>, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org = org_repo
        .create(CreateOrganization {
            name: "Test Org".into(),
            slug: "email-config-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Test Tenant".into(),
            slug: "email-config-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    seed_permissions(&db, tenant.id, PERMISSION_REGISTRY)
        .await
        .unwrap();
    seed_default_roles(&db, tenant.id, PERMISSION_REGISTRY)
        .await
        .unwrap();

    (db, org.id, tenant.id)
}

async fn create_admin(db: &Surreal<TestDb>, tenant_id: Uuid) -> Uuid {
    use axiam_core::repository::{Pagination, RoleRepository};

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: "admin".into(),
            email: "admin@example.com".into(),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();
    user_repo
        .update(
            tenant_id,
            user.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let role_repo = SurrealRoleRepository::new(db.clone());
    let roles = role_repo
        .list(
            tenant_id,
            Pagination {
                offset: 0,
                limit: 1000,
            },
        )
        .await
        .unwrap();
    let role = roles
        .items
        .into_iter()
        .find(|r| r.name == "admin")
        .expect("default role `admin` not seeded");
    role_repo
        .assign_to_user(tenant_id, user.id, role.id, None)
        .await
        .unwrap();

    user.id
}

// -------------------------------------------------------------------------
// App-data bundle — mirrors rbac_test.rs's test_app!, plus the
// SurrealEmailConfigRepository this plan's handlers extract.
// -------------------------------------------------------------------------

macro_rules! test_app {
    ($db:expr, $auth:expr, $authz:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new($authz.clone()))
                .app_data(web::Data::new({
                    let mut state = AppState::for_test($db.clone(), $auth.clone());
                    state.email_config_repo = Some(SurrealEmailConfigRepository::new(
                        $db.clone(),
                        TEST_EMAIL_KEY,
                    ));
                    state
                }))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    };
}

fn bearer_req(method: fn() -> test::TestRequest, uri: &str, token: &str) -> test::TestRequest {
    method()
        .uri(uri)
        .peer_addr("127.0.0.1:12345".parse().unwrap())
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
}

fn sample_smtp_config_body(password: &str) -> serde_json::Value {
    serde_json::json!({
        "enabled": true,
        "from_name": "AXIAM",
        "from_email": "noreply@example.com",
        "reply_to": "support@example.com",
        "provider": {
            "kind": "smtp",
            "host": "smtp.example.com",
            "port": 587,
            "username": "mailer",
            "password": password,
            "starttls": true
        }
    })
}

// -------------------------------------------------------------------------
// Org-scope tests
// -------------------------------------------------------------------------

/// PUT then GET at org scope: 200, secrets never appear in either response body.
#[actix_rt::test]
async fn org_email_config_put_get_round_trip_omits_secrets() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let admin_id = create_admin(&db, tenant_id).await;
    let token = mint_token(&auth, admin_id, tenant_id, org_id);
    let app = test_app!(db, auth, authz);

    const SECRET: &str = "super-secret-smtp-password-do-not-leak";

    let put_req = bearer_req(
        test::TestRequest::put,
        &format!("/api/v1/organizations/{org_id}/email-config"),
        &token,
    )
    .set_json(sample_smtp_config_body(SECRET))
    .to_request();
    let put_resp = test::call_service(&app, put_req).await;
    assert_eq!(put_resp.status().as_u16(), 200, "PUT must succeed");
    let put_body: serde_json::Value = test::read_body_json(put_resp).await;
    let put_body_str = put_body.to_string();
    assert!(
        !put_body_str.contains("password"),
        "PUT response must not contain a password key: {put_body_str}"
    );
    assert!(
        !put_body_str.contains(SECRET),
        "PUT response must not leak the plaintext secret"
    );
    assert_eq!(put_body["from_name"], "AXIAM");
    assert_eq!(put_body["from_email"], "noreply@example.com");

    let get_req = bearer_req(
        test::TestRequest::get,
        &format!("/api/v1/organizations/{org_id}/email-config"),
        &token,
    )
    .to_request();
    let get_resp = test::call_service(&app, get_req).await;
    assert_eq!(get_resp.status().as_u16(), 200, "GET must succeed");
    let get_body: serde_json::Value = test::read_body_json(get_resp).await;
    let get_body_str = get_body.to_string();
    assert!(
        !get_body_str.contains("password"),
        "GET response must not contain a password key: {get_body_str}"
    );
    assert!(
        !get_body_str.contains(SECRET),
        "GET response must not leak the plaintext secret"
    );
    assert_eq!(get_body["from_name"], "AXIAM");
    assert_eq!(get_body["from_email"], "noreply@example.com");
    assert_eq!(get_body["reply_to"], "support@example.com");
    assert_eq!(get_body["provider"]["host"], "smtp.example.com");
}

/// A caller whose own org_id differs from the path org_id must get 403 on
/// both GET and PUT (T-28-01 IDOR mitigation) — the ownership check runs
/// regardless of whether the target org actually exists.
#[actix_rt::test]
async fn org_email_config_cross_org_returns_403() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let admin_id = create_admin(&db, tenant_id).await;
    let token = mint_token(&auth, admin_id, tenant_id, org_id);
    let app = test_app!(db, auth, authz);

    let other_org_id = Uuid::new_v4();

    let get_req = bearer_req(
        test::TestRequest::get,
        &format!("/api/v1/organizations/{other_org_id}/email-config"),
        &token,
    )
    .to_request();
    let get_resp = test::call_service(&app, get_req).await;
    assert_eq!(get_resp.status().as_u16(), 403, "cross-org GET must be 403");

    let put_req = bearer_req(
        test::TestRequest::put,
        &format!("/api/v1/organizations/{other_org_id}/email-config"),
        &token,
    )
    .set_json(sample_smtp_config_body("irrelevant"))
    .to_request();
    let put_resp = test::call_service(&app, put_req).await;
    assert_eq!(put_resp.status().as_u16(), 403, "cross-org PUT must be 403");
}

/// DELETE removes the org's email config row; a subsequent GET returns 404.
#[actix_rt::test]
async fn org_email_config_delete_then_get_returns_404() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let admin_id = create_admin(&db, tenant_id).await;
    let token = mint_token(&auth, admin_id, tenant_id, org_id);
    let app = test_app!(db, auth, authz);

    let put_req = bearer_req(
        test::TestRequest::put,
        &format!("/api/v1/organizations/{org_id}/email-config"),
        &token,
    )
    .set_json(sample_smtp_config_body("some-password"))
    .to_request();
    assert_eq!(
        test::call_service(&app, put_req).await.status().as_u16(),
        200
    );

    let delete_req = bearer_req(
        test::TestRequest::delete,
        &format!("/api/v1/organizations/{org_id}/email-config"),
        &token,
    )
    .to_request();
    let delete_resp = test::call_service(&app, delete_req).await;
    assert_eq!(delete_resp.status().as_u16(), 204, "DELETE must succeed");

    let get_req = bearer_req(
        test::TestRequest::get,
        &format!("/api/v1/organizations/{org_id}/email-config"),
        &token,
    )
    .to_request();
    let get_resp = test::call_service(&app, get_req).await;
    assert_eq!(
        get_resp.status().as_u16(),
        404,
        "GET after delete must be 404"
    );
}

/// D-02: a second PUT that omits the secret preserves the previously stored
/// one. GET never re-exposes the secret (D-01), so this is verified directly
/// via the repository (bypassing HTTP serialization).
#[actix_rt::test]
async fn org_email_config_omitted_secret_preserves_stored_password() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let admin_id = create_admin(&db, tenant_id).await;
    let token = mint_token(&auth, admin_id, tenant_id, org_id);
    let app = test_app!(db, auth, authz);

    const ORIGINAL_SECRET: &str = "original-smtp-password-keep-me";

    let put1_req = bearer_req(
        test::TestRequest::put,
        &format!("/api/v1/organizations/{org_id}/email-config"),
        &token,
    )
    .set_json(sample_smtp_config_body(ORIGINAL_SECRET))
    .to_request();
    assert_eq!(
        test::call_service(&app, put1_req).await.status().as_u16(),
        200
    );

    // Second PUT: omit the password field entirely (D-02 sentinel via
    // `#[serde(default)]` — deserializes to an empty string, which the
    // repository treats as "preserve the stored ciphertext").
    let mut body_without_secret = sample_smtp_config_body("");
    body_without_secret["provider"]
        .as_object_mut()
        .unwrap()
        .remove("password");
    let put2_req = bearer_req(
        test::TestRequest::put,
        &format!("/api/v1/organizations/{org_id}/email-config"),
        &token,
    )
    .set_json(body_without_secret)
    .to_request();
    let put2_resp = test::call_service(&app, put2_req).await;
    assert_eq!(
        put2_resp.status().as_u16(),
        200,
        "second PUT (omitted secret) must still succeed"
    );

    // GET still succeeds (config remains usable).
    let get_req = bearer_req(
        test::TestRequest::get,
        &format!("/api/v1/organizations/{org_id}/email-config"),
        &token,
    )
    .to_request();
    assert_eq!(
        test::call_service(&app, get_req).await.status().as_u16(),
        200
    );

    // Verify the preserved secret directly via the repository (D-02) — the
    // HTTP layer never re-exposes it (D-01).
    let repo = SurrealEmailConfigRepository::new(db.clone(), TEST_EMAIL_KEY);
    let stored = repo
        .get_org_config(org_id)
        .await
        .unwrap()
        .expect("org config must still exist");
    match stored.provider {
        axiam_core::models::email::ProviderConfig::Smtp(smtp) => {
            assert_eq!(
                smtp.password, ORIGINAL_SECRET,
                "omitted-secret PUT must preserve the originally stored password"
            );
        }
        other => panic!("expected SMTP provider, got {other:?}"),
    }
}

// -------------------------------------------------------------------------
// Tenant-scope tests
// -------------------------------------------------------------------------

/// PUT/GET/DELETE round trip at tenant scope (explicit {tenant_id} path
/// segment, D-13) — secrets omitted, DELETE then GET returns 404.
#[actix_rt::test]
async fn tenant_email_config_put_get_delete_round_trip() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let admin_id = create_admin(&db, tenant_id).await;
    let token = mint_token(&auth, admin_id, tenant_id, org_id);
    let app = test_app!(db, auth, authz);

    let put_body = serde_json::json!({
        "from_name": "Tenant Mail"
    });
    let put_req = bearer_req(
        test::TestRequest::put,
        &format!("/api/v1/tenants/{tenant_id}/email-config"),
        &token,
    )
    .set_json(put_body)
    .to_request();
    let put_resp = test::call_service(&app, put_req).await;
    assert_eq!(put_resp.status().as_u16(), 200, "tenant PUT must succeed");
    let put_body: serde_json::Value = test::read_body_json(put_resp).await;
    assert_eq!(put_body["from_name"], "Tenant Mail");

    let get_req = bearer_req(
        test::TestRequest::get,
        &format!("/api/v1/tenants/{tenant_id}/email-config"),
        &token,
    )
    .to_request();
    let get_resp = test::call_service(&app, get_req).await;
    assert_eq!(get_resp.status().as_u16(), 200, "tenant GET must succeed");
    let get_body: serde_json::Value = test::read_body_json(get_resp).await;
    assert_eq!(get_body["from_name"], "Tenant Mail");

    let delete_req = bearer_req(
        test::TestRequest::delete,
        &format!("/api/v1/tenants/{tenant_id}/email-config"),
        &token,
    )
    .to_request();
    assert_eq!(
        test::call_service(&app, delete_req).await.status().as_u16(),
        204,
        "tenant DELETE must succeed"
    );

    let get_after_delete_req = bearer_req(
        test::TestRequest::get,
        &format!("/api/v1/tenants/{tenant_id}/email-config"),
        &token,
    )
    .to_request();
    assert_eq!(
        test::call_service(&app, get_after_delete_req)
            .await
            .status()
            .as_u16(),
        404,
        "tenant GET after delete must be 404"
    );
}

/// A caller whose own tenant_id differs from the path tenant_id must get 403
/// on both GET and PUT.
#[actix_rt::test]
async fn tenant_email_config_cross_tenant_returns_403() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let admin_id = create_admin(&db, tenant_id).await;
    let token = mint_token(&auth, admin_id, tenant_id, org_id);
    let app = test_app!(db, auth, authz);

    let other_tenant_id = Uuid::new_v4();

    let get_req = bearer_req(
        test::TestRequest::get,
        &format!("/api/v1/tenants/{other_tenant_id}/email-config"),
        &token,
    )
    .to_request();
    assert_eq!(
        test::call_service(&app, get_req).await.status().as_u16(),
        403,
        "cross-tenant GET must be 403"
    );

    let put_req = bearer_req(
        test::TestRequest::put,
        &format!("/api/v1/tenants/{other_tenant_id}/email-config"),
        &token,
    )
    .set_json(serde_json::json!({ "from_name": "Hijacked" }))
    .to_request();
    assert_eq!(
        test::call_service(&app, put_req).await.status().as_u16(),
        403,
        "cross-tenant PUT must be 403"
    );
}
