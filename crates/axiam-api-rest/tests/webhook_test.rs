//! Integration tests for webhook management endpoints.

use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_api_rest::webhook::WebhookDeliveryService;
use axiam_auth::config::AuthConfig;
use axiam_auth::crypto::aes256gcm_decrypt;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OrganizationRepository, TenantRepository, UserRepository, WebhookRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
    SurrealWebhookRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

/// Fixed AES-256-GCM key used by tests that need a *present* webhook
/// encryption key (D-02 ciphertext-at-rest proof). Distinct from any
/// production key; never used outside this test module.
const TEST_WEBHOOK_ENC_KEY: [u8; 32] = [0x42u8; 32];

type TestDb = surrealdb::engine::local::Db;

/// Arbitrary CSRF token for the double-submit check (SEC-046). These
/// Bearer-token tests have no login/`axiam_csrf` cookie, so we send a matching
/// `axiam_csrf` cookie + `X-CSRF-Token` header; the middleware only checks they
/// are equal (no session lookup). Safe (GET) requests ignore it.
const CSRF_TOKEN: &str = "test-csrf-token";

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

async fn setup_db() -> (Surreal<TestDb>, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org = org_repo
        .create(CreateOrganization {
            name: "Test Org".into(),
            slug: "test-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Test Tenant".into(),
            slug: "test-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, org.id, tenant.id)
}

async fn create_admin_user(db: &Surreal<TestDb>, tenant_id: Uuid) -> Uuid {
    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: "admin".into(),
            email: "admin@example.com".into(),
            password: "password12345".into(),
            metadata: None,
        })
        .await
        .unwrap();
    user.id
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

macro_rules! test_app {
    ($db:expr, $auth:expr) => {
        test_app!($db, $auth, Some(TEST_WEBHOOK_ENC_KEY))
    };
    ($db:expr, $auth:expr, $enc_key:expr) => {{
        let authz: Arc<dyn AuthzChecker> = Arc::new(AllowAllAuthzChecker);
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new({
                    let mut state = AppState::for_test($db.clone(), $auth.clone());
                    state.webhook_delivery =
                        WebhookDeliveryService::new(state.webhook_repo.clone(), $enc_key);
                    state
                }))
                .app_data(web::Data::new(authz))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    }};
}

#[actix_rt::test]
async fn create_webhook_returns_201() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/webhooks")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "url": "https://example.com/hook",
            "events": ["user.created", "auth.login"],
            "secret": "my-webhook-secret"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["url"], "https://example.com/hook");
    assert_eq!(body["events"][0], "user.created");
    assert_eq!(body["events"][1], "auth.login");
    assert_eq!(body["enabled"], true);
    assert!(body["id"].is_string());
}

#[actix_rt::test]
async fn create_webhook_omits_secret() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/webhooks")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "url": "https://example.com/hook",
            "events": ["user.created"],
            "secret": "my-webhook-secret"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body.get("secret").is_none());
    assert!(body.get("secret_hash").is_none());
}

#[actix_rt::test]
async fn create_webhook_validates_empty_url() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/webhooks")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "url": "",
            "events": ["user.created"],
            "secret": "my-secret"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn create_webhook_validates_empty_events() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/webhooks")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "url": "https://example.com/hook",
            "events": [],
            "secret": "my-secret"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn list_webhooks_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Create a webhook first
    let req = test::TestRequest::post()
        .uri("/api/v1/webhooks")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "url": "https://example.com/hook",
            "events": ["user.created"],
            "secret": "my-secret"
        }))
        .to_request();
    test::call_service(&app, req).await;

    let req = test::TestRequest::get()
        .uri("/api/v1/webhooks")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["items"][0]["url"], "https://example.com/hook");
}

#[actix_rt::test]
async fn get_webhook_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/webhooks")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "url": "https://example.com/hook",
            "events": ["user.created"],
            "secret": "my-secret"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let created: serde_json::Value = test::read_body_json(resp).await;
    let id = created["id"].as_str().unwrap();

    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/webhooks/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["id"], id);
    assert_eq!(body["url"], "https://example.com/hook");
}

#[actix_rt::test]
async fn get_nonexistent_webhook_returns_404() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let fake_id = Uuid::new_v4();
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/webhooks/{fake_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

#[actix_rt::test]
async fn update_webhook_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/webhooks")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "url": "https://example.com/hook",
            "events": ["user.created"],
            "secret": "my-secret"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let created: serde_json::Value = test::read_body_json(resp).await;
    let id = created["id"].as_str().unwrap();

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/webhooks/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "url": "https://example.com/new-hook",
            "enabled": false
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["url"], "https://example.com/new-hook");
    assert_eq!(body["enabled"], false);
}

#[actix_rt::test]
async fn delete_webhook_returns_204() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/webhooks")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "url": "https://example.com/hook",
            "events": ["user.created"],
            "secret": "my-secret"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let created: serde_json::Value = test::read_body_json(resp).await;
    let id = created["id"].as_str().unwrap();

    let req = test::TestRequest::delete()
        .uri(&format!("/api/v1/webhooks/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 204);

    // Verify it's gone
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/webhooks/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

#[actix_rt::test]
async fn delete_nonexistent_webhook_returns_404() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let fake_id = Uuid::new_v4();
    let req = test::TestRequest::delete()
        .uri(&format!("/api/v1/webhooks/{fake_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

#[actix_rt::test]
async fn create_webhook_with_custom_retry_policy() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/webhooks")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "url": "https://example.com/hook",
            "events": ["user.created"],
            "secret": "my-secret",
            "retry_policy": {
                "max_retries": 3,
                "initial_delay_secs": 5,
                "backoff_multiplier": 1.5
            }
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["retry_policy"]["max_retries"], 3);
    assert_eq!(body["retry_policy"]["initial_delay_secs"], 5);
    assert_eq!(body["retry_policy"]["backoff_multiplier"], 1.5);
}

#[actix_rt::test]
async fn webhook_tenant_isolation() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);

    // Create a second tenant
    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant2 = tenant_repo
        .create(CreateTenant {
            organization_id: org_id,
            name: "Tenant 2".into(),
            slug: "tenant-2".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user2 = user_repo
        .create(CreateUser {
            tenant_id: tenant2.id,
            username: "admin2".into(),
            email: "admin2@example.com".into(),
            password: "password12345".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let token2 = mint_token(&auth, user2.id, tenant2.id, org_id);

    let app = test_app!(db, auth);

    // Create webhook in tenant 1
    let req = test::TestRequest::post()
        .uri("/api/v1/webhooks")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "url": "https://example.com/hook",
            "events": ["user.created"],
            "secret": "my-secret"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let created: serde_json::Value = test::read_body_json(resp).await;
    let id = created["id"].as_str().unwrap();

    // Tenant 2 cannot see tenant 1's webhook
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/webhooks/{id}"))
        .insert_header(("Authorization", format!("Bearer {token2}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);

    // Tenant 2's list is empty
    let req = test::TestRequest::get()
        .uri("/api/v1/webhooks")
        .insert_header(("Authorization", format!("Bearer {token2}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 0);
}

#[actix_rt::test]
async fn create_webhook_rejects_http_url() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/webhooks")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "url": "http://example.com/hook",
            "events": ["user.created"],
            "secret": "my-secret"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn create_webhook_rejects_private_ip() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    for url in [
        "https://127.0.0.1/hook",
        "https://10.0.0.1/hook",
        "https://192.168.1.1/hook",
        "https://169.254.169.254/metadata",
        "https://localhost/hook",
    ] {
        let req = test::TestRequest::post()
            .uri("/api/v1/webhooks")
            .insert_header(("Authorization", format!("Bearer {token}")))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json(serde_json::json!({
                "url": url,
                "events": ["user.created"],
                "secret": "my-secret"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 400, "expected 400 for URL: {url}");
    }
}

#[actix_rt::test]
async fn update_webhook_rejects_invalid_url() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Create a valid webhook first
    let req = test::TestRequest::post()
        .uri("/api/v1/webhooks")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "url": "https://example.com/hook",
            "events": ["user.created"],
            "secret": "my-secret"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let created: serde_json::Value = test::read_body_json(resp).await;
    let id = created["id"].as_str().unwrap();

    // Update with HTTP URL should fail
    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/webhooks/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "url": "http://example.com/hook"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);

    // Update with empty events should fail
    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/webhooks/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "events": []
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn create_webhook_rejects_invalid_retry_policy() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // max_retries too large
    let req = test::TestRequest::post()
        .uri("/api/v1/webhooks")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "url": "https://example.com/hook",
            "events": ["user.created"],
            "secret": "my-secret",
            "retry_policy": {
                "max_retries": 100,
                "initial_delay_secs": 10,
                "backoff_multiplier": 2.0
            }
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);

    // negative backoff_multiplier
    let req = test::TestRequest::post()
        .uri("/api/v1/webhooks")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "url": "https://example.com/hook",
            "events": ["user.created"],
            "secret": "my-secret",
            "retry_policy": {
                "max_retries": 3,
                "initial_delay_secs": 10,
                "backoff_multiplier": -1.0
            }
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);

    // initial_delay_secs = 0
    let req = test::TestRequest::post()
        .uri("/api/v1/webhooks")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "url": "https://example.com/hook",
            "events": ["user.created"],
            "secret": "my-secret",
            "retry_policy": {
                "max_retries": 3,
                "initial_delay_secs": 0,
                "backoff_multiplier": 2.0
            }
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

// ---------------------------------------------------------------------------
// SECFIX-03 (SEC-059/SEC-031) negative tests — D-01 fail-closed key handling
// and D-02 encrypt-on-write.
// ---------------------------------------------------------------------------

/// D-01: webhook registration must be refused (explicit error, never a
/// silent 201) when no encryption key is configured — proves the
/// fail-closed posture that replaced the old `unwrap_or([0u8; 32])`
/// all-zero fallback.
#[actix_rt::test]
async fn create_webhook_fails_closed_without_encryption_key() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    // No encryption key configured — mirrors AXIAM__PKI__ENCRYPTION_KEY unset.
    let app = test_app!(db, auth, None::<[u8; 32]>);

    let req = test::TestRequest::post()
        .uri("/api/v1/webhooks")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "url": "https://example.com/hook",
            "events": ["user.created"],
            "secret": "my-webhook-secret"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        503,
        "registration must be refused (not a silent 201) when the encryption key is absent"
    );

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "service_unavailable");
}

/// D-02: the secret persisted to the DB must be ciphertext, never the
/// submitted plaintext, and must decrypt back to the original plaintext —
/// proving encrypt-on-write plus the delivery-side decrypt round trip.
#[actix_rt::test]
async fn create_webhook_stores_ciphertext_not_plaintext() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let plaintext_secret = "my-webhook-secret";
    let req = test::TestRequest::post()
        .uri("/api/v1/webhooks")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "url": "https://example.com/hook",
            "events": ["user.created"],
            "secret": plaintext_secret
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let created: serde_json::Value = test::read_body_json(resp).await;
    let id: Uuid = created["id"].as_str().unwrap().parse().unwrap();

    // Read the persisted row directly from the repository (bypasses the
    // API response, which never serializes the secret at all).
    let webhook_repo = SurrealWebhookRepository::new(db.clone());
    let stored = webhook_repo.get_by_id(tenant_id, id).await.unwrap();

    assert_ne!(
        stored.secret, plaintext_secret,
        "stored secret must be ciphertext, not the submitted plaintext"
    );

    let decrypted_bytes = aes256gcm_decrypt(&TEST_WEBHOOK_ENC_KEY, &stored.secret)
        .expect("stored secret must decrypt with the configured key");
    let decrypted = String::from_utf8(decrypted_bytes).expect("utf8");
    assert_eq!(
        decrypted, plaintext_secret,
        "decrypting the stored ciphertext must round-trip to the original plaintext"
    );
}

// ---------------------------------------------------------------------------
// 25-02 (SECHRD-02 / D-01c) negative test — webhook delivery pins the
// resolved IP; no second DNS resolution occurs at send time.
// ---------------------------------------------------------------------------

/// Proves the exact property `webhook.rs`'s delivery loop now depends on:
/// once `axiam_federation::ssrf` resolves and validates a delivery target,
/// the actual POST is pinned to that validated `IpAddr` — a second,
/// independent DNS resolution at send time (the DNS-rebind TOCTOU
/// RESEARCH Pitfall 1 describes: "re-resolves per retry but does NOT pin
/// per send") cannot silently redirect the connection elsewhere.
///
/// Hermetic (loopback only, no live external egress): Linux routes the
/// entire `127.0.0.0/8` range to `lo`, so `127.0.0.2` is a valid, bindable
/// loopback address without any extra host configuration.
///
/// - `"localhost"` genuinely, deterministically resolves to `127.0.0.1` —
///   that's where the REAL mock server listens.
/// - `ssrf::pinned_client` is the exact mechanism `guarded_fetch` (and
///   therefore `webhook.rs`'s delivery loop) uses to build the per-attempt
///   client. Pinning it to `127.0.0.2` (deliberately NOT where "localhost"
///   truly resolves, and where nothing listens) simulates a stale/rebind-
///   immune pin: if the client independently re-resolved "localhost" at
///   send time instead of honoring the pin, the request would succeed
///   against the real listener at `127.0.0.1`. Because the override is
///   authoritative, the request instead fails against `127.0.0.2` —
///   proving no second resolution occurs.
/// - A companion positive case pins to the correct `127.0.0.1` and proves
///   delivery reaches the real listener, ruling out "the test just always
///   fails" as an explanation.
/// - Finally, the full production code path — `ssrf::guarded_fetch` used
///   exactly as `webhook.rs` uses it (resolve + validate + pin + send in
///   one call) — is exercised end-to-end and proven to reach the real
///   listener, confirming the wiring `webhook.rs` now relies on works.
#[tokio::test]
async fn webhook_pins_resolved_ip() {
    use axiam_federation::ssrf;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // The REAL destination: what "localhost" genuinely, deterministically
    // resolves to. A legitimate, correctly-pinned send lands here.
    let real_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind real listener");
    let real_port = real_listener.local_addr().expect("local_addr").port();

    let real_hit = Arc::new(AtomicBool::new(false));
    let real_hit_writer = real_hit.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = real_listener.accept().await else {
                break;
            };
            real_hit_writer.store(true, Ordering::SeqCst);
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(response).await;
        }
    });

    let url = format!("http://localhost:{real_port}/webhook");

    // --- Negative case: pin to the WRONG loopback address -----------------
    // Nothing listens on 127.0.0.2:{real_port}. If the client were to
    // independently re-resolve "localhost" at send time instead of honoring
    // the pin, this would still succeed (reaching the real listener at
    // 127.0.0.1). It must instead fail, proving the pin — not a fresh DNS
    // lookup — determines where the connection lands.
    let wrong_pin = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    let wrong_client =
        ssrf::pinned_client("localhost", wrong_pin, real_port).expect("build wrong-pin client");
    let wrong_result = wrong_client.post(&url).body("{}").send().await;
    assert!(
        wrong_result.is_err(),
        "request pinned to 127.0.0.2 (nothing listening) must fail — if it \
         succeeded, the client re-resolved \"localhost\" independently \
         instead of honoring the pin, got: {wrong_result:?}"
    );
    assert!(
        !real_hit.load(Ordering::SeqCst),
        "the real listener at 127.0.0.1 must NOT have been reached by the \
         127.0.0.2-pinned request"
    );

    // --- Positive control: pin to the CORRECT loopback address ------------
    // Proves the mechanism genuinely works (rules out "always fails").
    let correct_pin = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let correct_client = ssrf::pinned_client("localhost", correct_pin, real_port)
        .expect("build correctly-pinned client");
    let correct_result = correct_client.post(&url).body("{}").send().await;
    assert!(
        correct_result.is_ok(),
        "request pinned to 127.0.0.1 (real listener) must succeed, got: {correct_result:?}"
    );
    assert!(
        real_hit.load(Ordering::SeqCst),
        "the real listener at 127.0.0.1 must have been reached by the correctly-pinned request"
    );

    // --- End-to-end: the exact call shape webhook.rs's delivery loop uses --
    // `allow_private=true` is the documented first-hop test seam (mirrors
    // production `deliver()`'s use of `guarded_fetch`, which passes `false`
    // against real, non-loopback targets).
    let e2e_result = ssrf::guarded_fetch(&url, true, |c, u| c.post(u).body("{}")).await;
    assert!(
        e2e_result.is_ok(),
        "guarded_fetch (the exact function webhook.rs's delivery loop calls) \
         must resolve \"localhost\" to 127.0.0.1, pin it, and reach the real \
         listener, got: {e2e_result:?}"
    );
}
