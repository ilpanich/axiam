//! Integration tests for the notification-rule management endpoints
//! (`/api/v1/notification-rules`).
//!
//! Uses an in-memory SurrealDB and the `AllowAllAuthzChecker`, so every
//! request is authenticated (real minted JWT) but authorization is stubbed —
//! the focus is the handler CRUD + validation logic, not RBAC.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::{SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository};
use serde_json::{Value, json};
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow

/// Matching CSRF header/cookie value — the double-submit middleware only
/// checks header == cookie, so any matching pair satisfies it.
const CSRF_TOKEN: &str = "test-csrf-token";

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
            name: "NR Org".into(),
            slug: "nr-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "NR Tenant".into(),
            slug: "nr-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "nr-admin".into(),
            email: "nr-admin@example.com".into(),
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

fn valid_body() -> Value {
    json!({
        "name": "Failed logins",
        "description": "Alert on repeated login failures",
        "events": ["login_failure", "account_locked"],
        "recipient_emails": ["secops@example.com"],
    })
}

#[actix_web::test]
async fn create_list_get_update_delete_roundtrip() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Create.
    let req = test::TestRequest::post()
        .uri("/api/v1/notification-rules")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(valid_body())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let created: Value = test::read_body_json(resp).await;
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["name"], "Failed logins");
    assert_eq!(created["enabled"], true);

    // List.
    let req = test::TestRequest::get()
        .uri("/api/v1/notification-rules")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let list: Value = test::read_body_json(resp).await;
    assert_eq!(list["total"], 1);

    // Get by id.
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/notification-rules/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Update (rename + disable).
    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/notification-rules/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({ "name": "Renamed", "enabled": false }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let updated: Value = test::read_body_json(resp).await;
    assert_eq!(updated["name"], "Renamed");
    assert_eq!(updated["enabled"], false);

    // Delete.
    let req = test::TestRequest::delete()
        .uri(&format!("/api/v1/notification-rules/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 204);

    // Get after delete → not found.
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/notification-rules/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

#[actix_web::test]
async fn create_rejects_invalid_payloads() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let too_many_emails: Vec<String> = (0..21).map(|i| format!("user{i}@example.com")).collect();
    let cases = vec![
        json!({ "name": "  ", "description": "d", "events": ["login_failure"], "recipient_emails": ["a@b.com"] }),
        json!({ "name": "n", "description": "d", "events": [], "recipient_emails": ["a@b.com"] }),
        json!({ "name": "n", "description": "d", "events": ["login_failure"], "recipient_emails": [] }),
        json!({ "name": "n", "description": "d", "events": ["login_failure"], "recipient_emails": too_many_emails }),
        json!({ "name": "n", "description": "d", "events": ["login_failure"], "recipient_emails": ["not-an-email"] }),
    ];

    for body in cases {
        let req = test::TestRequest::post()
            .uri("/api/v1/notification-rules")
            .insert_header(("Authorization", format!("Bearer {token}")))
            .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json(&body)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status().as_u16(),
            400,
            "expected 400 for payload {body:?}"
        );
    }
}

#[actix_web::test]
async fn update_validates_fields() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Seed a rule.
    let req = test::TestRequest::post()
        .uri("/api/v1/notification-rules")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(valid_body())
        .to_request();
    let created: Value = test::read_body_json(test::call_service(&app, req).await).await;
    let id = created["id"].as_str().unwrap().to_string();

    // Invalid update: empty events list.
    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/notification-rules/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({ "events": [] }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);

    // Invalid update: bad recipient email.
    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/notification-rules/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({ "recipient_emails": ["nope"] }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_web::test]
async fn get_missing_rule_returns_404() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/notification-rules/{}", Uuid::new_v4()))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

#[actix_web::test]
async fn unauthenticated_request_is_rejected() {
    let (db, _org_id, _tenant_id, _user_id) = setup().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri("/api/v1/notification-rules")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}
