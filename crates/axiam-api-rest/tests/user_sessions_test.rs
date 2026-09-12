//! Integration tests for `GET /api/v1/users/{user_id}/sessions` (T-254).
//!
//! The endpoint exists so that the refresh-replay marker is readable: a marker
//! nobody can see is not a control. Three properties are asserted here, and
//! each of them is one the endpoint could plausibly get wrong:
//!
//! 1. It carries the marker, in both of its dispositions, with the derived
//!    verdict agreeing with the counters.
//! 2. It carries **no session token, in any form** — the response is a
//!    projection, not a passthrough, and this is what keeps a future field
//!    from turning an admin read into a credential handout.
//! 3. It is scoped: own sessions with no named permission, anybody else's
//!    behind `users:admin`, and never another tenant's.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::{Amr, CreateSession};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OrganizationRepository, SessionRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::SurrealSessionRepository;
use axiam_db::{SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository};
use chrono::{Duration, Utc};
use serde_json::Value;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow
const CSRF_TOKEN: &str = "test-csrf-token";

/// The stored half of a live credential. It must never appear in a response.
const SESSION_TOKEN_HASH: &str = "a-session-token-hash-that-must-never-be-served";

fn test_auth_config() -> AuthConfig {
    let private_key = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM
-----END PRIVATE KEY-----";
    let public_key = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";
    AuthConfig {
        jwt_private_key_pem: private_key.into(),
        jwt_public_key_pem: public_key.into(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

async fn setup() -> (Surreal<TestDb>, Uuid, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Sessions Org".into(),
            slug: "sessions-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Sessions Tenant".into(),
            slug: "sessions-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "sessions-admin".into(),
            email: "sessions-admin@example.com".into(),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, org.id, tenant.id, user.id)
}

fn mint_token(auth: &AuthConfig, user_id: Uuid, tenant_id: Uuid, org_id: Uuid) -> String {
    issue_access_token(
        user_id,
        tenant_id,
        org_id,
        &[],
        auth,
        Uuid::new_v4().to_string(),
        axiam_auth::token::AUD_USER,
    )
    .unwrap()
}

macro_rules! test_app {
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(AppState::for_test(
                    $db.clone(),
                    $auth.clone(),
                )))
                .app_data(web::Data::new(
                    Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
                ))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    };
}

async fn seed_session(
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
    user_id: Uuid,
    token_hash: &str,
) -> Uuid {
    SurrealSessionRepository::new(db.clone())
        .create(CreateSession {
            tenant_id,
            user_id,
            token_hash: token_hash.into(),
            ip_address: Some("203.0.113.7".into()),
            user_agent: Some("axiam-test".into()),
            expires_at: Utc::now() + Duration::hours(1),
            authenticated_at: Utc::now() - Duration::minutes(30),
            amr: vec![Amr::Pwd, Amr::Otp, Amr::Mfa],
            browser_token_hash: None,
        })
        .await
        .unwrap()
        .id
}

fn get_sessions(uri: String, token: &str) -> test::TestRequest {
    test::TestRequest::get()
        .uri(&uri)
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
}

#[actix_web::test]
async fn a_user_reads_their_own_sessions_and_they_start_unmarked() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    seed_session(&db, tenant_id, user_id, SESSION_TOKEN_HASH).await;
    let app = test_app!(db, auth);

    let resp = test::call_service(
        &app,
        get_sessions(format!("/api/v1/users/{user_id}/sessions"), &token).to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    let rows = body.as_array().expect("an array of sessions");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["refresh_replay_verdict"], "none");
    assert_eq!(rows[0]["refresh_replay_grace_accepted"], 0);
    assert_eq!(rows[0]["refresh_replay_refused"], 0);
    assert!(rows[0]["refresh_replay_at"].is_null());
    assert_eq!(
        rows[0]["amr"],
        serde_json::json!(["pwd", "otp", "mfa"]),
        "the authentication evidence travels with the session"
    );
}

/// The projection, asserted as a projection. Nothing that could serve as a
/// credential may appear anywhere in the rendered response — not under a name
/// this test knows, and not under one a future field might invent.
#[actix_web::test]
async fn the_session_listing_never_serves_a_token_or_its_digest() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    seed_session(&db, tenant_id, user_id, SESSION_TOKEN_HASH).await;
    let app = test_app!(db, auth);

    let resp = test::call_service(
        &app,
        get_sessions(format!("/api/v1/users/{user_id}/sessions"), &token).to_request(),
    )
    .await;
    let raw = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
    assert!(
        !raw.contains(SESSION_TOKEN_HASH),
        "the stored session token digest must not be served: {raw}"
    );
    for forbidden in ["token_hash", "browser_token_hash"] {
        assert!(
            !raw.contains(forbidden),
            "no token column may reach the response; found {forbidden}"
        );
    }
}

/// T-254 — both dispositions, and the derived verdict agreeing with the
/// counters. A refusal outranks any number of honest grace retries.
#[actix_web::test]
async fn the_refresh_replay_marker_is_served_and_distinguishes_its_two_outcomes() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);

    let repo = SurrealSessionRepository::new(db.clone());
    let graced = seed_session(&db, tenant_id, user_id, "hash-graced").await;
    let refused = seed_session(&db, tenant_id, user_id, "hash-refused").await;
    repo.mark_refresh_replay(tenant_id, graced, true)
        .await
        .unwrap();
    repo.mark_refresh_replay(tenant_id, refused, true)
        .await
        .unwrap();
    repo.mark_refresh_replay(tenant_id, refused, false)
        .await
        .unwrap();

    let app = test_app!(db, auth);
    let resp = test::call_service(
        &app,
        get_sessions(format!("/api/v1/users/{user_id}/sessions"), &token).to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    let rows = body.as_array().expect("an array of sessions");

    let by_id = |id: Uuid| {
        rows.iter()
            .find(|r| r["id"] == id.to_string())
            .unwrap_or_else(|| panic!("session {id} is in the listing"))
            .clone()
    };

    let g = by_id(graced);
    assert_eq!(g["refresh_replay_verdict"], "fapi_grace_retry");
    assert_eq!(g["refresh_replay_grace_accepted"], 1);
    assert_eq!(g["refresh_replay_refused"], 0);
    assert!(!g["refresh_replay_at"].is_null());

    let r = by_id(refused);
    assert_eq!(
        r["refresh_replay_verdict"], "refused",
        "one refusal outranks an accepted grace retry on the same session"
    );
    assert_eq!(r["refresh_replay_grace_accepted"], 1);
    assert_eq!(r["refresh_replay_refused"], 1);
}

/// Reading somebody else's sessions takes the `users:admin` branch (passed
/// here by `AllowAllAuthzChecker`, refused in production by the route's
/// registry entry).
#[actix_web::test]
async fn reading_another_users_sessions_takes_the_permission_branch() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);

    let other = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id,
            username: "sessions-other".into(),
            email: "sessions-other@example.com".into(),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();
    seed_session(&db, tenant_id, other.id, "hash-other").await;

    let app = test_app!(db, auth);
    let resp = test::call_service(
        &app,
        get_sessions(format!("/api/v1/users/{}/sessions", other.id), &token).to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body.as_array().unwrap().len(), 1);
}

/// Tenant isolation, which the listing gets from `list_by_user` and must not
/// lose: a session belonging to the same user id in another tenant is not this
/// tenant's to show.
#[actix_web::test]
async fn the_listing_is_tenant_scoped() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);

    let other_tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org_id,
            kind: TenantKind::Standard,
            name: "Other Tenant".into(),
            slug: "other-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    seed_session(&db, other_tenant.id, user_id, "hash-elsewhere").await;

    let app = test_app!(db, auth);
    let resp = test::call_service(
        &app,
        get_sessions(format!("/api/v1/users/{user_id}/sessions"), &token).to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert!(
        body.as_array().unwrap().is_empty(),
        "another tenant's session must not appear here: {body}"
    );
}
