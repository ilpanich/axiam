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
//! - #529 (T-473): the outbound address policy on a saved provider, at both
//!   scopes; the delivery self-test's answer to a refused or unreachable
//!   provider; the self-test's own rate limiter.
//!
//! Host names are answered by a scripted resolver ([`names`]), never by DNS:
//! `smtp.example.com` is public, the `*.example.test` names point where their
//! name says.

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
use axiam_core::models::role::AssignmentScope;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
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
use axiam_email::egress::{
    AddressPolicy, EmailEgress, HOST_NOT_PERMITTED, ResolveFuture, Resolver, parse_allowed_networks,
};
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
            kind: TenantKind::Standard,
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

/// The organization's own reserved tenant, seeded, and its id.
///
/// The organization-scope email config is an organization-level action:
/// `handlers::org_scope::require_organization_principal` refuses it to any
/// caller whose own record does not live in this tenant, whatever permissions
/// it holds (B-04). `setup_db` deliberately builds an ordinary tenant, because
/// that is what the *tenant*-scope cases in this file are about.
async fn organization_scope_tenant(db: &Surreal<TestDb>, org_id: Uuid) -> Uuid {
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant::organization_scope(org_id))
        .await
        .unwrap();
    seed_permissions(db, tenant.id, PERMISSION_REGISTRY)
        .await
        .unwrap();
    seed_default_roles(db, tenant.id, PERMISSION_REGISTRY)
        .await
        .unwrap();
    tenant.id
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
                search: None,
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
        .assign_to_user(tenant_id, user.id, role.id, AssignmentScope::global())
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
        test_app!(
            $db,
            $auth,
            $authz,
            test_egress(),
            RateLimitConfig::default()
        )
    };
    ($db:expr, $auth:expr, $authz:expr, $egress:expr) => {
        test_app!($db, $auth, $authz, $egress, RateLimitConfig::default())
    };
    ($db:expr, $auth:expr, $authz:expr, $egress:expr, $rate_limit:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new($authz.clone()))
                .app_data(web::Data::new({
                    let mut state = AppState::for_test($db.clone(), $auth.clone());
                    state.mail.email_config_repo = Some(SurrealEmailConfigRepository::new(
                        $db.clone(),
                        TEST_EMAIL_KEY,
                    ));
                    state.mail.egress = $egress;
                    state
                }))
                .configure(|cfg| register_api_v1_routes::<TestDb>(cfg, &$rate_limit)),
        )
        .await
    };
}

/// Answers the test's host names from a table — the n-th question about a
/// name gets its n-th answer, the last repeats — so nothing here depends on
/// DNS (#529).
struct Names {
    table: Vec<(&'static str, Vec<&'static str>)>,
    asked: std::sync::Mutex<std::collections::HashMap<String, usize>>,
}

impl Resolver for Names {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a> {
        let index = {
            let mut asked = self.asked.lock().unwrap();
            let n = asked.entry(host.to_string()).or_insert(0);
            *n += 1;
            *n - 1
        };
        let answer = self
            .table
            .iter()
            .find(|(name, _)| *name == host)
            .map(|(_, ips)| {
                let ip: std::net::IpAddr = ips[index.min(ips.len() - 1)].parse().unwrap();
                vec![std::net::SocketAddr::new(ip, port)]
            });
        Box::pin(async move {
            answer.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown"))
        })
    }
}

fn names() -> Arc<Names> {
    Arc::new(Names {
        table: vec![
            ("smtp.example.com", vec!["93.184.216.34"]),
            ("loopback.example.test", vec!["127.0.0.1"]),
            ("metadata.example.test", vec!["169.254.169.254"]),
            ("private.example.test", vec!["10.1.2.3"]),
            // Public when the configuration is saved, loopback afterwards.
            ("rebind.example.test", vec!["93.184.216.34", "127.0.0.1"]),
        ],
        asked: Default::default(),
    })
}

/// The strict rule a deployment with nothing configured gets, over [`names`].
fn test_egress() -> EmailEgress {
    EmailEgress::default().with_resolver(names())
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
    let (db, org_id, _tenant_id) = setup_db().await;
    // Organization-level: the caller must live in the organization's own
    // reserved tenant, not merely hold the permission. See `handlers::org_scope`.
    let tenant_id = organization_scope_tenant(&db, org_id).await;
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
    let (db, org_id, _tenant_id) = setup_db().await;
    // Organization-level: the caller must live in the organization's own
    // reserved tenant, not merely hold the permission. See `handlers::org_scope`.
    let tenant_id = organization_scope_tenant(&db, org_id).await;
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
    let (db, org_id, _tenant_id) = setup_db().await;
    // Organization-level: the caller must live in the organization's own
    // reserved tenant, not merely hold the permission. See `handlers::org_scope`.
    let tenant_id = organization_scope_tenant(&db, org_id).await;
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

// -------------------------------------------------------------------------
// #529 (T-473): the outbound address policy
// -------------------------------------------------------------------------

fn smtp_body(host: &str) -> serde_json::Value {
    serde_json::json!({
        "provider": {
            "kind": "smtp",
            "host": host,
            "port": 587,
            "username": "mailer",
            "password": TEST_PASSWORD,
            "starttls": true
        }
    })
}

fn api_body(url: &str) -> serde_json::Value {
    serde_json::json!({
        "provider": { "kind": "resend", "api_key": TEST_PASSWORD, "api_url": url }
    })
}

/// `PUT` a body; the status and the response's `message`.
async fn put(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    uri: &str,
    token: &str,
    body: serde_json::Value,
) -> (u16, serde_json::Value) {
    let resp = test::call_service(
        app,
        bearer_req(test::TestRequest::put, uri, token)
            .set_json(body)
            .to_request(),
    )
    .await;
    let status = resp.status().as_u16();
    let body: serde_json::Value = test::read_body_json(resp).await;
    (status, body)
}

/// Each refused class is a `400` when saved at tenant scope: an IP literal's
/// answer names the class, a host name's is one sentence whatever the name
/// resolved to — or whether it resolved at all (P23W3-04). Nothing is stored.
#[actix_rt::test]
async fn each_refused_class_is_refused_when_a_tenant_saves_it() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let admin_id = create_admin(&db, tenant_id).await;
    let token = mint_token(&auth, admin_id, tenant_id, org_id);
    let app = test_app!(db, auth, authz);
    let uri = format!("/api/v1/tenants/{tenant_id}/email-config");

    let mut cases: Vec<(serde_json::Value, &str)> = vec![
        (smtp_body("127.0.0.1"), "loopback"),
        (smtp_body("::1"), "loopback"),
        (smtp_body("169.254.169.254"), "link-local"),
        (smtp_body("0.0.0.0"), "unspecified"),
        (smtp_body("224.0.0.1"), "multicast"),
        (smtp_body("10.1.2.3"), "private"),
        (api_body("https://127.0.0.1/v3/mail/send"), "SSRF blocked"),
        (api_body("https://169.254.169.254/latest"), "SSRF blocked"),
        (api_body("http://api.example.com/v3/mail/send"), "non-HTTPS"),
    ];
    for name in [
        "loopback.example.test",
        "metadata.example.test",
        "private.example.test",
        "nowhere.example.test",
    ] {
        cases.push((smtp_body(name), HOST_NOT_PERMITTED));
    }
    cases.push((
        api_body("https://localhost/v3/mail/send"),
        HOST_NOT_PERMITTED,
    ));

    for (body, expect) in cases {
        let (status, refusal) = put(&app, &uri, &token, body.clone()).await;
        assert_eq!(status, 400, "{body}: {refusal}");
        assert_eq!(refusal["error"], "validation_error", "{body}");
        let message = refusal["message"].as_str().unwrap_or_default();
        assert!(message.contains(expect), "{body}: {message}");
        if expect == HOST_NOT_PERMITTED {
            for leak in ["127.0.0.1", "169.254", "10.1.2.3", "loopback", "private"] {
                assert!(!message.contains(leak), "{body}: {message} names {leak}");
            }
        }
    }
    let repo = SurrealEmailConfigRepository::new(db.clone(), TEST_EMAIL_KEY);
    assert!(
        repo.get_tenant_override(tenant_id).await.unwrap().is_none(),
        "no refused provider was stored"
    );

    // A public host is accepted; an override that switches mail off is never
    // refused for its provider (switching off must always be possible).
    let (status, _) = put(&app, &uri, &token, smtp_body("smtp.example.com")).await;
    assert_eq!(status, 200);
    let mut off = smtp_body("loopback.example.test");
    off["enabled"] = false.into();
    let (status, _) = put(&app, &uri, &token, off).await;
    assert_eq!(status, 200);
}

/// The organization's configuration is held to the same rule: an
/// organization administrator is a customer, not the operator.
#[actix_rt::test]
async fn the_organization_scope_is_held_to_the_same_rule() {
    let (db, org_id, _tenant_id) = setup_db().await;
    let tenant_id = organization_scope_tenant(&db, org_id).await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let admin_id = create_admin(&db, tenant_id).await;
    let token = mint_token(&auth, admin_id, tenant_id, org_id);
    let app = test_app!(db, auth, authz);
    let uri = format!("/api/v1/organizations/{org_id}/email-config");

    for (host, expect) in [
        ("127.0.0.1", "loopback"),
        ("169.254.169.254", "link-local"),
        ("metadata.example.test", HOST_NOT_PERMITTED),
    ] {
        let mut body = sample_smtp_config_body(TEST_PASSWORD);
        body["provider"]["host"] = host.into();
        let (status, refusal) = put(&app, &uri, &token, body).await;
        assert_eq!(status, 400, "{host}: {refusal}");
        assert!(
            refusal["message"].as_str().unwrap().contains(expect),
            "{host}: {refusal}"
        );
    }
    let mut disabled = sample_smtp_config_body(TEST_PASSWORD);
    disabled["provider"]["host"] = "loopback.example.test".into();
    disabled["enabled"] = false.into();
    let (status, _) = put(&app, &uri, &token, disabled).await;
    assert_eq!(status, 200, "a disabled configuration opens no connection");
}

/// A private relay is accepted only inside the operator's allow-list
/// (`AXIAM__EMAIL__ALLOWED_PRIVATE_NETWORKS`), and the always-refused classes
/// stay refused whatever the list says.
#[actix_rt::test]
async fn a_private_relay_is_accepted_only_inside_the_operator_allow_list() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let admin_id = create_admin(&db, tenant_id).await;
    let token = mint_token(&auth, admin_id, tenant_id, org_id);
    let (networks, _) = parse_allowed_networks("10.0.0.0/8");
    let egress = EmailEgress::new(AddressPolicy::new().with_allowed_private_networks(networks))
        .with_resolver(names());
    let app = test_app!(db, auth, authz, egress);
    let uri = format!("/api/v1/tenants/{tenant_id}/email-config");

    let (status, body) = put(&app, &uri, &token, smtp_body("private.example.test")).await;
    assert_eq!(status, 200, "{body}");
    let (status, _) = put(&app, &uri, &token, smtp_body("10.1.2.3")).await;
    assert_eq!(status, 200);
    for host in ["192.168.0.10", "127.0.0.1", "169.254.169.254"] {
        let (status, _) = put(&app, &uri, &token, smtp_body(host)).await;
        assert_eq!(status, 400, "{host}");
    }
}

/// `POST …/email-config/test`
async fn run_test(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    uri: &str,
    token: &str,
    peer: &str,
) -> (u16, serde_json::Value) {
    let resp = test::call_service(
        app,
        bearer_req(test::TestRequest::post, uri, token)
            .peer_addr(peer.parse().unwrap())
            .to_request(),
    )
    .await;
    let status = resp.status().as_u16();
    let body: serde_json::Value = test::read_body_json(resp).await;
    (status, body)
}

/// The delivery self-test is held to the rule at the send, and its answer is
/// no oracle: a name re-pointed at loopback after the save (DNS rebinding) is
/// the one sentence, naming neither the address nor its class; a connection
/// that fails after the guard admitted the address is the generic `500`.
#[actix_rt::test]
async fn the_test_endpoint_answers_generically_for_a_refused_or_unreachable_provider() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let admin_id = create_admin(&db, tenant_id).await;
    let token = mint_token(&auth, admin_id, tenant_id, org_id);
    let repo = SurrealEmailConfigRepository::new(db.clone(), TEST_EMAIL_KEY);
    let mut org_config: axiam_core::models::email::SetOrgEmailConfig =
        serde_json::from_value(sample_smtp_config_body(TEST_PASSWORD)).unwrap();
    org_config.enabled = true;
    repo.set_org_config(org_id, org_config).await.unwrap();

    let app = test_app!(db, auth, authz);
    let config_uri = format!("/api/v1/tenants/{tenant_id}/email-config");
    let test_uri = format!("{config_uri}/test");

    // Saved while the name answers a public address...
    let (status, body) = put(&app, &config_uri, &token, smtp_body("rebind.example.test")).await;
    assert_eq!(status, 200, "{body}");
    // ...and refused at the send, when it answers loopback.
    let (status, refusal) = run_test(&app, &test_uri, &token, "203.0.113.40:4000").await;
    assert_eq!(status, 400, "{refusal}");
    assert_eq!(refusal["error"], "email_config_error");
    let message = refusal["message"].as_str().unwrap();
    assert!(message.contains(HOST_NOT_PERMITTED), "{message}");
    for leak in ["127.0.0.1", "loopback", "rebind"] {
        assert!(!message.contains(leak), "{message} names {leak}");
    }

    // A literal stored before #529 is refused with its class: the
    // administrator typed it.
    let literal: axiam_core::models::email::EmailConfigOverride =
        serde_json::from_value(smtp_body("169.254.169.254")).unwrap();
    repo.set_tenant_override(tenant_id, literal).await.unwrap();
    let (status, refusal) = run_test(&app, &test_uri, &token, "203.0.113.40:4000").await;
    assert_eq!(status, 400, "{refusal}");
    assert!(
        refusal["message"].as_str().unwrap().contains("link-local"),
        "{refusal}"
    );

    // Admitted but unreachable: a name that resolves (under the loopback
    // seam) to a closed port. The answer is the generic one, never the
    // socket's own words.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);
    let seam = EmailEgress::new(AddressPolicy::new().admitting_loopback_for_tests())
        .with_resolver(names());
    let app = test_app!(db, auth, authz, seam);
    let mut unreachable = smtp_body("loopback.example.test");
    unreachable["provider"]["port"] = closed_port.into();
    let (status, body) = put(&app, &config_uri, &token, unreachable).await;
    assert_eq!(status, 200, "{body}");
    let (status, failure) = run_test(&app, &test_uri, &token, "203.0.113.41:4000").await;
    assert_eq!(status, 500, "{failure}");
    let text = failure.to_string();
    for leak in ["refused", "127.0.0.1", &closed_port.to_string()] {
        assert!(!text.contains(leak), "{text} names {leak}");
    }
}

/// Each self-test route carries its own limiter from the commit that guarded
/// it (plan §7 rule 6): past `email_test_per_min` from one address it answers
/// `429`; another address, and the other route, are unaffected.
#[actix_rt::test]
async fn the_email_test_routes_are_rate_limited_per_ip() {
    const EMAIL_TEST_PER_MIN: u32 = 2;
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let admin_id = create_admin(&db, tenant_id).await;
    let token = mint_token(&auth, admin_id, tenant_id, org_id);
    let rate_limit = RateLimitConfig {
        email_test_per_min: EMAIL_TEST_PER_MIN,
        ..RateLimitConfig::default()
    };
    let app = test_app!(db, auth, authz, test_egress(), rate_limit);
    let tenant_uri = format!("/api/v1/tenants/{tenant_id}/email-config/test");

    // No configuration applies, so each admitted call is a 400 — and costs
    // the bucket all the same.
    for i in 0..EMAIL_TEST_PER_MIN {
        let (status, body) = run_test(&app, &tenant_uri, &token, "203.0.113.50:4000").await;
        assert_eq!(status, 400, "call {i} is within the limit: {body}");
    }
    let (status, _) = run_test(&app, &tenant_uri, &token, "203.0.113.50:4000").await;
    assert_eq!(status, 429);
    let (status, _) = run_test(&app, &tenant_uri, &token, "203.0.113.51:4000").await;
    assert_eq!(status, 400, "the bucket is per address");
    // The organization route has a bucket of its own (the caller is refused
    // there for its scope, after the limiter).
    let org_uri = format!("/api/v1/organizations/{org_id}/email-config/test");
    let (status, _) = run_test(&app, &org_uri, &token, "203.0.113.50:4000").await;
    assert_ne!(status, 429, "one bucket per route");
}

// -------------------------------------------------------------------------
// #525 (P23W2-05): an omitted secret follows only the same destination
// -------------------------------------------------------------------------

/// The stored SMTP password at `scope`, read past the HTTP layer (D-01).
async fn stored_smtp_password(
    db: &Surreal<TestDb>,
    scope: &str,
    org_id: Uuid,
    tenant_id: Uuid,
) -> String {
    let repo = SurrealEmailConfigRepository::new(db.clone(), TEST_EMAIL_KEY);
    let provider = if scope == "org" {
        repo.get_org_config(org_id).await.unwrap().unwrap().provider
    } else {
        repo.get_tenant_override(tenant_id)
            .await
            .unwrap()
            .unwrap()
            .provider
            .unwrap()
    };
    match provider {
        axiam_core::models::email::ProviderConfig::Smtp(smtp) => smtp.password,
        other => panic!("expected SMTP, got {other:?}"),
    }
}

/// An SMTP provider at `host`, without a password unless one is given.
fn smtp_destination(
    host: &str,
    port: u16,
    starttls: bool,
    password: Option<&str>,
) -> serde_json::Value {
    let mut provider = serde_json::json!({
        "kind": "smtp",
        "host": host,
        "port": port,
        "username": "mailer",
        "starttls": starttls
    });
    if let Some(password) = password {
        provider["password"] = password.into();
    }
    serde_json::json!({
        "enabled": true,
        "from_name": "AXIAM",
        "from_email": "noreply@example.com",
        "provider": provider
    })
}

/// Both scopes: an omitted password is kept for the same host, port and TLS
/// mode, and refused `400 validation_error` — with nothing
/// stored — when any of the three changes; a new password goes anywhere the
/// address policy allows.
async fn an_omitted_smtp_password_is_kept_only_for_the_same_server(scope: &str) {
    let (db, org_id, tenant_id) = setup_db().await;
    let tenant_id = if scope == "org" {
        organization_scope_tenant(&db, org_id).await
    } else {
        tenant_id
    };
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let admin_id = create_admin(&db, tenant_id).await;
    let token = mint_token(&auth, admin_id, tenant_id, org_id);
    let app = test_app!(db, auth, authz);
    let uri = if scope == "org" {
        format!("/api/v1/organizations/{org_id}/email-config")
    } else {
        format!("/api/v1/tenants/{tenant_id}/email-config")
    };
    const SERVER: &str = "smtp.example.com";
    const OTHER: &str = "93.184.216.35";

    let (status, body) = put(
        &app,
        &uri,
        &token,
        smtp_destination(SERVER, 587, true, Some(TEST_PASSWORD)),
    )
    .await;
    assert_eq!(status, 200, "{scope}: {body}");

    // The same server: kept.
    let (status, body) = put(
        &app,
        &uri,
        &token,
        smtp_destination(SERVER, 587, true, None),
    )
    .await;
    assert_eq!(status, 200, "{scope}: {body}");
    assert_eq!(
        stored_smtp_password(&db, scope, org_id, tenant_id).await,
        TEST_PASSWORD
    );

    // Another host, another port, another TLS mode: each refused.
    for (label, changed) in [
        ("host", smtp_destination(OTHER, 587, true, None)),
        ("port", smtp_destination(SERVER, 2525, true, None)),
        ("TLS mode", smtp_destination(SERVER, 587, false, None)),
    ] {
        let (status, body) = put(&app, &uri, &token, changed).await;
        assert_eq!(status, 400, "{scope}, {label}: {body}");
        assert_eq!(
            body["error"], "validation_error",
            "{scope}, {label}: {body}"
        );
        assert!(
            body["message"].as_str().unwrap().contains("password again"),
            "{scope}, {label}: {body}"
        );
    }
    // Nothing was written: the configuration still names the first server.
    let (status, body) = put(
        &app,
        &uri,
        &token,
        smtp_destination(SERVER, 587, true, None),
    )
    .await;
    assert_eq!(status, 200, "{scope}: {body}");
    assert_eq!(
        stored_smtp_password(&db, scope, org_id, tenant_id).await,
        TEST_PASSWORD
    );

    // With the password supplied, the server may change.
    let (status, body) = put(
        &app,
        &uri,
        &token,
        smtp_destination(OTHER, 2525, false, Some("another-placeholder")),
    )
    .await;
    assert_eq!(status, 200, "{scope}: {body}");
    assert_eq!(
        stored_smtp_password(&db, scope, org_id, tenant_id).await,
        "another-placeholder"
    );
}

#[actix_rt::test]
async fn p23w2_05_an_omitted_smtp_password_is_kept_only_for_the_same_server_org_scope() {
    an_omitted_smtp_password_is_kept_only_for_the_same_server("org").await;
}

#[actix_rt::test]
async fn p23w2_05_an_omitted_smtp_password_is_kept_only_for_the_same_server_tenant_scope() {
    an_omitted_smtp_password_is_kept_only_for_the_same_server("tenant").await;
}

/// The API-key twin: an `api_url` override is a destination too, so an
/// omitted key is kept only for the same `api_url`, or when the override is
/// dropped and the kind's own endpoint applies.
#[actix_rt::test]
async fn p23w2_05_an_omitted_api_key_is_kept_only_for_the_same_endpoint() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let admin_id = create_admin(&db, tenant_id).await;
    let token = mint_token(&auth, admin_id, tenant_id, org_id);
    let app = test_app!(db, auth, authz);
    let uri = format!("/api/v1/tenants/{tenant_id}/email-config");
    let resend = |api_url: Option<&str>, api_key: Option<&str>| {
        let mut provider = serde_json::json!({ "kind": "resend" });
        if let Some(url) = api_url {
            provider["api_url"] = url.into();
        }
        if let Some(key) = api_key {
            provider["api_key"] = key.into();
        }
        serde_json::json!({ "provider": provider })
    };
    let stored_key = || async {
        let repo = SurrealEmailConfigRepository::new(db.clone(), TEST_EMAIL_KEY);
        match repo
            .get_tenant_override(tenant_id)
            .await
            .unwrap()
            .unwrap()
            .provider
            .unwrap()
        {
            axiam_core::models::email::ProviderConfig::Resend(api) => (api.api_key, api.api_url),
            other => panic!("expected Resend, got {other:?}"),
        }
    };
    const FIRST: &str = "https://93.184.216.34/emails";
    const OTHER: &str = "https://93.184.216.35/emails";

    let (status, body) = put(&app, &uri, &token, resend(Some(FIRST), Some(TEST_PASSWORD))).await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = put(&app, &uri, &token, resend(Some(FIRST), None)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(stored_key().await.0, TEST_PASSWORD);

    let (status, body) = put(&app, &uri, &token, resend(Some(OTHER), None)).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "validation_error", "{body}");
    assert_eq!(
        stored_key().await,
        (TEST_PASSWORD.to_owned(), Some(FIRST.to_owned()))
    );

    // Back to the kind's own endpoint: kept.
    let (status, body) = put(&app, &uri, &token, resend(None, None)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(stored_key().await, (TEST_PASSWORD.to_owned(), None));
}
