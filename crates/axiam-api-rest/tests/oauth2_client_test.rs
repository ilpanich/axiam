//! Integration tests for OAuth2 client management endpoints.
//!
//! Covers CRUD operations, input validation, and tenant isolation.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

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
            kind: TenantKind::Standard,
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

/// Build a test app with all services needed for OAuth2 client + flow tests.
macro_rules! test_app {
    ($db:expr, $auth:expr) => {{
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
    }};
}

// ---------------------------------------------------------------------------
// Helper: create a client via the API and return its body
// ---------------------------------------------------------------------------

async fn create_test_client(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    token: &str,
) -> serde_json::Value {
    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Test Client",
            "redirect_uris": ["https://app.example.com/callback"],
            "grant_types": ["authorization_code"],
            "scopes": ["openid", "profile"]
        }))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    test::read_body_json(resp).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn create_oauth2_client_returns_201() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "My App",
            "redirect_uris": ["https://myapp.example.com/callback"],
            "grant_types": ["authorization_code"],
            "scopes": ["openid", "email"]
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["name"], "My App");
    assert!(body["id"].is_string(), "response must include id");
    assert!(
        body["client_id"].is_string(),
        "response must include client_id"
    );
    assert!(
        body["client_secret"].is_string(),
        "response must include one-time client_secret"
    );
    assert_eq!(
        body["redirect_uris"][0],
        "https://myapp.example.com/callback"
    );
    assert_eq!(body["grant_types"][0], "authorization_code");
    assert_eq!(body["tenant_id"], tenant_id.to_string());
}

#[actix_rt::test]
async fn create_oauth2_client_omits_secret_hash() {
    // The create response exposes the plaintext secret exactly once.
    // It must NOT expose client_secret_hash (internal field).
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Secret Test Client",
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "scopes": []
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);

    let body: serde_json::Value = test::read_body_json(resp).await;
    // client_secret_hash must never appear in any API response
    assert!(
        body.get("client_secret_hash").is_none(),
        "client_secret_hash must be omitted from API responses"
    );
    // The one-time plaintext secret is expected in the creation response
    assert!(
        body.get("client_secret").is_some(),
        "client_secret must be present in the creation response"
    );
}

#[actix_rt::test]
async fn list_oauth2_clients_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Create two clients
    create_test_client(&app, &token).await;
    create_test_client(&app, &token).await;

    let req = test::TestRequest::get()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 2);
    assert!(body["items"].is_array());
    // Listed entries must NOT expose client_secret_hash
    assert!(body["items"][0].get("client_secret_hash").is_none());
    // Listed entries must NOT expose client_secret either (only shown at creation)
    assert!(body["items"][0].get("client_secret").is_none());
}

#[actix_rt::test]
async fn get_oauth2_client_by_id_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let created = create_test_client(&app, &token).await;
    let id = created["id"].as_str().unwrap();

    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["id"], id);
    assert_eq!(body["name"], "Test Client");
    assert!(body.get("client_secret_hash").is_none());
}

#[actix_rt::test]
async fn get_nonexistent_oauth2_client_returns_404() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let fake_id = Uuid::new_v4();
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/oauth2-clients/{fake_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

#[actix_rt::test]
async fn update_oauth2_client_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let created = create_test_client(&app, &token).await;
    let id = created["id"].as_str().unwrap();

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Updated Client Name"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["name"], "Updated Client Name");
    assert_eq!(body["id"], id);
    // Redirect URIs should be unchanged
    assert_eq!(body["redirect_uris"][0], "https://app.example.com/callback");
}

#[actix_rt::test]
async fn delete_oauth2_client_returns_204() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let created = create_test_client(&app, &token).await;
    let id = created["id"].as_str().unwrap();

    let req = test::TestRequest::delete()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 204);

    // Verify it is gone
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

/// #517 — an administrator's delete revokes the client's refresh tokens
/// before it removes the row, as RFC 7592's `DELETE /oauth2/register/{id}`
/// already did. The refresh is refused either way once the row is gone; what
/// the fix adds is the revoked mark, which keeps the token dead if the
/// `client_id` ever names a row again (a CIMD client's always can —
/// `cimd_test.rs::a_deleted_cimd_client_rematerialises_without_its_refresh_tokens`).
#[actix_rt::test]
async fn deleting_a_client_revokes_its_refresh_tokens() {
    use axiam_core::models::oauth2_client::CreateRefreshToken;
    use axiam_core::repository::RefreshTokenRepository;

    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Refreshing Client",
            "redirect_uris": ["https://app.example.com/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "scopes": ["openid"]
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let created: serde_json::Value = test::read_body_json(resp).await;
    let id = created["id"].as_str().unwrap();
    let client_id = created["client_id"].as_str().unwrap();
    let secret = created["client_secret"].as_str().unwrap();

    // A refresh token as the code grant stores one.
    let raw = axiam_auth::token::generate_refresh_token();
    let hash = axiam_auth::token::hash_refresh_token(&raw);
    let refresh_repo = axiam_db::repository::SurrealRefreshTokenRepository::new(db.clone());
    refresh_repo
        .create(CreateRefreshToken {
            tenant_id,
            token_hash: hash.clone(),
            client_id: client_id.to_owned(),
            user_id: Some(user_id),
            scopes: vec!["openid".into()],
            session_id: None,
            requested_userinfo_claims: Vec::new(),
            resource: None,
            auth_time: None,
            acr: None,
            amr: Vec::new(),
            expires_at: chrono::Utc::now() + chrono::Duration::days(30),
        })
        .await
        .unwrap();
    assert!(
        refresh_repo
            .get_by_token_hash(tenant_id, &hash)
            .await
            .is_ok()
    );

    let req = test::TestRequest::delete()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 204);

    let req = test::TestRequest::post()
        .peer_addr("127.0.0.1:12345".parse().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={tenant_id}"))
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .set_payload(format!(
            "grant_type=refresh_token&refresh_token={raw}&client_id={client_id}\
             &client_secret={secret}"
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        status == 400 || status == 401,
        "a deleted client's refresh token must not refresh: {status} {body}"
    );
    assert!(body.get("access_token").is_none(), "{body}");

    // The row is marked revoked, not merely orphaned.
    let mut found = db
        .query("SELECT VALUE revoked FROM oauth2_refresh_token WHERE token_hash = $h")
        .bind(("h", hash))
        .await
        .unwrap();
    let revoked: Vec<bool> = found.take(0).unwrap();
    assert_eq!(
        revoked,
        vec![true],
        "the refresh token is revoked on delete"
    );
}

/// Seed a device grant for `client_id`, approved by `user_id`, and return the
/// raw device code. `interval_secs: 0` so a test may poll straight away.
async fn approved_device_grant(
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
    client_id: &str,
    user_id: Uuid,
) -> String {
    use axiam_core::models::oauth2_client::CreateDeviceGrant;
    use axiam_core::repository::DeviceGrantRepository;
    use axiam_oauth2::device::{generate_user_code, hash_device_code, normalize_user_code};

    let repo = axiam_db::repository::SurrealDeviceGrantRepository::new(db.clone());
    let device_code = format!("dc-{}", Uuid::new_v4().simple());
    let user_code = normalize_user_code(&generate_user_code());
    repo.create(CreateDeviceGrant {
        tenant_id,
        client_id: client_id.to_owned(),
        device_code_hash: hash_device_code(&device_code),
        user_code: user_code.clone(),
        scopes: vec!["openid".into()],
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
        interval_secs: 0,
        resource: None,
    })
    .await
    .unwrap();
    assert!(
        repo.decide(tenant_id, &user_code, true, user_id)
            .await
            .unwrap()
    );
    device_code
}

/// Poll the token endpoint with a device code: `(status, body)`.
macro_rules! poll_device {
    ($app:expr, $tenant_id:expr, $device_code:expr) => {{
        let req = test::TestRequest::post()
            .peer_addr("127.0.0.1:12345".parse().unwrap())
            .uri(&format!("/oauth2/token?tenant_id={}", $tenant_id))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload(format!(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code\
                 &device_code={}",
                $device_code
            ))
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let body: serde_json::Value = test::read_body_json(resp).await;
        (status, body)
    }};
}

/// **#610 (d).** Deleting a client voids its device grants and CIBA requests.
///
/// The device poll authenticates nothing but the device code, so an approved
/// grant outlives its client — and, for a `managed_by: cimd` client whose
/// `client_id` names its metadata document, redeems again once the next request
/// re-materialises the row. The pending CIBA request would meanwhile stay
/// listed for its user naming a client that is gone.
///
/// A grant of another client in the same tenant is the control: it still
/// redeems, so the poll below is refused for the right reason.
#[actix_rt::test]
async fn deleting_a_client_voids_its_device_grants_and_ciba_requests() {
    use axiam_core::models::ciba::{CibaDeliveryMode, CreateCibaRequest};
    use axiam_core::models::oauth2_client::{
        AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateOAuth2Client, ManagedBy,
    };
    use axiam_core::models::user::{UpdateUser, UserStatus};
    use axiam_core::repository::{
        CibaRequestRepository, DeviceGrantRepository, OAuth2ClientRepository,
    };

    const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    SurrealUserRepository::new(db.clone())
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Two device-grant clients, made through the API.
    let mut ids = Vec::new();
    for name in ["Doomed TV", "Surviving TV"] {
        let req = test::TestRequest::post()
            .uri("/api/v1/oauth2-clients")
            .insert_header(("Authorization", format!("Bearer {token}")))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json(serde_json::json!({
                "name": name,
                "redirect_uris": [],
                "grant_types": [DEVICE_GRANT],
                "scopes": ["openid"]
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 201);
        let body: serde_json::Value = test::read_body_json(resp).await;
        ids.push((
            body["id"].as_str().unwrap().to_owned(),
            body["client_id"].as_str().unwrap().to_owned(),
        ));
    }
    let (doomed_id, doomed_client) = ids[0].clone();
    let (_, surviving_client) = ids[1].clone();

    let doomed_code = approved_device_grant(&db, tenant_id, &doomed_client, user_id).await;
    let surviving_code = approved_device_grant(&db, tenant_id, &surviving_client, user_id).await;

    let ciba_repo = axiam_db::repository::SurrealCibaRequestRepository::new(db.clone(), None);
    let pending = ciba_repo
        .create(CreateCibaRequest {
            tenant_id,
            client_id: doomed_client.clone(),
            auth_req_id_hash: format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()),
            user_id: Some(user_id),
            scopes: vec!["openid".into()],
            binding_message: None,
            acr_values: Vec::new(),
            resource: None,
            delivery_mode: CibaDeliveryMode::Poll,
            ping: None,
            interval_secs: 5,
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        })
        .await
        .unwrap();
    assert_eq!(
        ciba_repo
            .list_pending_for_user(tenant_id, user_id, 10)
            .await
            .unwrap()
            .len(),
        1,
        "the request is on the approval surface before the delete"
    );

    let req = test::TestRequest::delete()
        .uri(&format!("/api/v1/oauth2-clients/{doomed_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 204);

    // The pending CIBA request is gone, and the approval surface lists nothing.
    assert!(
        ciba_repo
            .get_by_id(tenant_id, pending.id)
            .await
            .unwrap()
            .is_none(),
        "a deleted client's CIBA request is deleted"
    );
    assert!(
        ciba_repo
            .list_pending_for_user(tenant_id, user_id, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        axiam_db::repository::SurrealDeviceGrantRepository::new(db.clone())
            .get_by_device_code_hash(
                tenant_id,
                &axiam_oauth2::device::hash_device_code(&doomed_code)
            )
            .await
            .unwrap()
            .is_none(),
        "a deleted client's device grant is deleted"
    );

    // Even before anything is re-materialised the poll authenticates no client,
    // so the grant is what refuses it.
    let before_refresh = refresh_token_count(&db).await;
    let (status, body) = poll_device!(app, tenant_id, doomed_code);
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_grant")),
        "{body}"
    );

    // The client's metadata document is fetched again: the same `client_id`
    // names a row once more (the CIMD upsert is what the authorize path calls).
    let rematerialised = axiam_db::repository::SurrealOAuth2ClientRepository::new(db.clone())
        .upsert_cimd_client(
            &doomed_client,
            CreateOAuth2Client {
                tenant_id,
                name: "Doomed TV".into(),
                redirect_uris: vec![],
                grant_types: vec![DEVICE_GRANT.into()],
                scopes: vec!["openid".into()],
                post_logout_redirect_uris: Vec::new(),
                backchannel_logout_uri: None,
                require_par: false,
                profile: ClientProfile::Standard,
                token_endpoint_auth_method: ClientAuthMethod::None,
                tls_client_auth_subject_dn: None,
                tls_client_auth_san_dns: None,
                tls_client_auth_san_uri: None,
                self_signed_tls_client_auth_thumbprints: vec![],
                tls_client_certificate_bound_access_tokens: false,
                jwks: None,
                jwks_uri: None,
                dpop_bound_access_tokens: false,
                dpop_require_nonce: false,
                authn_request_params: AuthnRequestParamsMode::Ignore,
                browser_sso: false,
                allowed_resources: Vec::new(),
                managed_by: ManagedBy::Cimd,
                ciba: Default::default(),
            },
        )
        .await
        .unwrap();
    assert_eq!(rematerialised.client_id, doomed_client);
    let (status, body) = poll_device!(app, tenant_id, doomed_code);
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_grant")),
        "an approved grant must not redeem against the re-materialised client: {body}"
    );
    assert!(body.get("access_token").is_none(), "{body}");
    assert_eq!(
        refresh_token_count(&db).await,
        before_refresh,
        "no tokens were minted"
    );

    // The control: another client's approved grant is untouched.
    let (status, body) = poll_device!(app, tenant_id, surviving_code);
    assert_eq!(status, 200, "{body}");
    assert!(body["access_token"].as_str().is_some_and(|t| !t.is_empty()));
}

/// Rows in `oauth2_refresh_token`: "nothing minted" is asserted against it.
async fn refresh_token_count(db: &Surreal<TestDb>) -> u64 {
    use surrealdb::types::SurrealValue;

    let mut result = db
        .query("SELECT count() AS c FROM oauth2_refresh_token GROUP ALL")
        .await
        .unwrap();
    #[derive(SurrealValue)]
    struct Count {
        c: i64,
    }
    let rows: Vec<Count> = result.take(0).unwrap();
    rows.first().map_or(0, |r| r.c as u64)
}

#[actix_rt::test]
async fn create_oauth2_client_rejects_empty_redirect_uris() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Bad Client",
            "redirect_uris": [],
            "grant_types": ["authorization_code"],
            "scopes": []
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn create_oauth2_client_rejects_http_redirect_uri() {
    // Non-localhost HTTP redirect URIs must be rejected (HTTPS required).
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Http Client",
            "redirect_uris": ["http://example.com/callback"],
            "grant_types": ["authorization_code"],
            "scopes": []
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn create_oauth2_client_allows_http_localhost() {
    // http://localhost is explicitly allowed for development tooling.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    for uri in [
        "http://localhost:3000/callback",
        "http://127.0.0.1:8090/callback",
    ] {
        let req = test::TestRequest::post()
            .uri("/api/v1/oauth2-clients")
            .insert_header(("Authorization", format!("Bearer {token}")))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json(serde_json::json!({
                "name": "Dev Client",
                "redirect_uris": [uri],
                "grant_types": ["authorization_code"],
                "scopes": []
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status().as_u16(),
            201,
            "expected 201 for localhost URI: {uri}"
        );
    }
}

/// `http://[::1]/…` registers, which until T21.8 it could not.
///
/// `validate_redirect_uris` compared the parsed host against the bare `::1`
/// while `Url::host_str` returns an IPv6 literal with its brackets, so the
/// IPv6 loopback arm was unreachable and the refusal named `::1` as allowed in
/// the same breath. Every other loopback comparison in the stack — the redirect
/// matcher, the DCR host allow-list, the CIMD document validator — spells it
/// `[::1]`.
///
/// Both spellings of the presented URI are exercised, because a client may
/// write the literal either way and `Url` normalises to the bracketed form.
#[actix_rt::test]
async fn create_oauth2_client_allows_http_ipv6_loopback() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    for uri in ["http://[::1]/callback", "http://[::1]:49152/callback"] {
        let req = test::TestRequest::post()
            .uri("/api/v1/oauth2-clients")
            .insert_header(("Authorization", format!("Bearer {token}")))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json(serde_json::json!({
                "name": "IPv6 Dev Client",
                "redirect_uris": [uri],
                "grant_types": ["authorization_code"],
                "scopes": []
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status().as_u16(),
            201,
            "RFC 8252 §7.3 lists the IPv6 loopback beside 127.0.0.1: {uri}"
        );
    }

    // And the widening is one host, not "IPv6". A routable literal over `http`
    // is refused exactly as `http://example.com` is.
    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Routable IPv6 Client",
            "redirect_uris": ["http://[2001:db8::1]/callback"],
            "grant_types": ["authorization_code"],
            "scopes": []
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "only the loopback literal takes the http allowance"
    );
}

#[actix_rt::test]
async fn create_oauth2_client_rejects_invalid_grant_type() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Bad Grant Client",
            "redirect_uris": ["https://example.com/callback"],
            "grant_types": ["implicit"],   // not in allowed set
            "scopes": []
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn create_oauth2_client_rejects_empty_name() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "",
            "redirect_uris": ["https://example.com/callback"],
            "grant_types": ["authorization_code"],
            "scopes": []
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn tenant_isolation_oauth2_clients() {
    // A client created in tenant A must not be visible to tenant B.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);

    // Create a second tenant and user
    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant2 = tenant_repo
        .create(CreateTenant {
            organization_id: org_id,
            kind: TenantKind::Standard,
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

    // Tenant 1 creates a client
    let created = create_test_client(&app, &token).await;
    let id = created["id"].as_str().unwrap();

    // Tenant 2 cannot GET the client by ID
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token2}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);

    // Tenant 2's list must be empty
    let req = test::TestRequest::get()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token2}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 0);
}

// ---------------------------------------------------------------------------
// Additional validation branches: empty grant_types, host-less / fragment
// redirect_uris (create), and the update() validation/adding-auth-code paths.
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn create_oauth2_client_rejects_empty_grant_types() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "No Grants Client",
            "redirect_uris": [],
            "grant_types": [],
            "scopes": []
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn create_oauth2_client_rejects_redirect_uri_without_host() {
    // "urn:isbn:..." parses as an absolute URL but has no authority/host, so
    // `Url::host_str()` returns `None` -- the "must be an absolute URL with a
    // host" branch, distinct from the scheme/fragment checks below it.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Hostless Client",
            "redirect_uris": ["urn:isbn:0451450523"],
            "grant_types": ["authorization_code"],
            "scopes": []
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "a host-less redirect_uri must be rejected"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    let msg = body["error"]
        .as_str()
        .or_else(|| body["message"].as_str())
        .unwrap_or_default();
    assert!(
        msg.contains("absolute URL with a host") || !msg.is_empty(),
        "got: {body}"
    );
}

#[actix_rt::test]
async fn create_oauth2_client_rejects_redirect_uri_with_fragment() {
    // RFC 6749 §3.1.2: redirect URIs must not contain a fragment component.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Fragment Client",
            "redirect_uris": ["https://app.example.com/callback#token"],
            "grant_types": ["authorization_code"],
            "scopes": []
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "a redirect_uri with a fragment must be rejected"
    );
}

#[actix_rt::test]
async fn update_oauth2_client_rejects_empty_name() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let created = create_test_client(&app, &token).await;
    let id = created["id"].as_str().unwrap();

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "name": "" }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

/// Updating `grant_types` alone (to another already-valid, non-redirect-
/// requiring grant type) exercises `validate_grant_types` from inside
/// `update` -- distinct from the `create`-path call already covered above.
#[actix_rt::test]
async fn update_oauth2_client_grant_types_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let created = create_test_client(&app, &token).await;
    let id = created["id"].as_str().unwrap();

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "grant_types": ["client_credentials"] }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["grant_types"][0], "client_credentials");
}

/// Updating `redirect_uris` alone exercises the update-path
/// `validate_redirect_uris` dispatch (`needs_redirects` computed from the
/// request's own `grant_types`, which is `None` here so it defaults to
/// `true` -- the created client already uses `authorization_code`).
#[actix_rt::test]
async fn update_oauth2_client_redirect_uris_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let created = create_test_client(&app, &token).await;
    let id = created["id"].as_str().unwrap();

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "redirect_uris": ["https://app.example.com/new-callback"]
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["redirect_uris"][0],
        "https://app.example.com/new-callback"
    );
}

/// Adding `authorization_code` to `grant_types` in an update WITHOUT
/// supplying `redirect_uris`, when the client's stored `redirect_uris` are
/// already empty (it was created `client_credentials`-only), must be
/// rejected -- the client would otherwise end up with an authorization_code
/// grant and no redirect target.
#[actix_rt::test]
async fn update_oauth2_client_adding_auth_code_without_any_redirect_uris_returns_400() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // client_credentials-only client: redirect_uris not required at creation.
    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "M2M Client",
            "redirect_uris": [],
            "grant_types": ["client_credentials"],
            "scopes": []
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let created: serde_json::Value = test::read_body_json(resp).await;
    let id = created["id"].as_str().unwrap();

    // Now add authorization_code without providing redirect_uris.
    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "grant_types": ["client_credentials", "authorization_code"]
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "enabling authorization_code with no stored redirect_uris must be rejected"
    );
}

/// Same as above, but the client already HAS stored `redirect_uris` (supplied
/// at creation even though not required for `client_credentials`) -- adding
/// `authorization_code` without redirect_uris in the update body must succeed
/// by falling back to and validating the EXISTING stored redirect_uris.
#[actix_rt::test]
async fn update_oauth2_client_adding_auth_code_with_existing_redirect_uris_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "M2M Client With URIs",
            "redirect_uris": ["https://app.example.com/callback"],
            "grant_types": ["client_credentials"],
            "scopes": []
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let created: serde_json::Value = test::read_body_json(resp).await;
    let id = created["id"].as_str().unwrap();

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "grant_types": ["client_credentials", "authorization_code"]
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "existing stored redirect_uris satisfy the authorization_code requirement"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["grant_types"][1], "authorization_code");
}

/// A client can be registered for the device-code and token-exchange grants
/// through the admin API.
///
/// Regression: `KNOWN_GRANT_TYPES` used to list only `authorization_code`,
/// `client_credentials` and `refresh_token`, while `device_service` requires
/// `urn:ietf:params:oauth:grant-type:device_code` and `token_exchange`
/// requires `urn:ietf:params:oauth:grant-type:token-exchange`. Both flows
/// shipped, but neither could be reached through this API — every attempt was
/// rejected as "unknown grant_type". The existing tests for those flows build
/// `OAuth2Client` values directly and so never crossed this validator.
#[actix_rt::test]
async fn update_oauth2_client_accepts_device_code_and_token_exchange_grants() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let created = create_test_client(&app, &token).await;
    let id = created["id"].as_str().unwrap();

    for grant in [
        "urn:ietf:params:oauth:grant-type:device_code",
        "device_code",
        "urn:ietf:params:oauth:grant-type:token-exchange",
    ] {
        let req = test::TestRequest::put()
            .uri(&format!("/api/v1/oauth2-clients/{id}"))
            .insert_header(("Authorization", format!("Bearer {token}")))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json(serde_json::json!({ "grant_types": [grant] }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status().as_u16(),
            200,
            "grant type {grant} must be registrable through the admin API"
        );
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["grant_types"][0], grant);
    }
}

/// The impersonation capability marker stays NON-registrable through this API.
///
/// `may-impersonate` is deliberately absent from `KNOWN_GRANT_TYPES`: whether
/// an admin-API caller may confer impersonation is an open security decision.
/// This test pins the current posture so widening it has to be deliberate.
#[actix_rt::test]
async fn update_oauth2_client_rejects_the_may_impersonate_marker() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let created = create_test_client(&app, &token).await;
    let id = created["id"].as_str().unwrap();

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "grant_types": ["urn:axiam:params:oauth:grant-type:may-impersonate"]
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

// ---------------------------------------------------------------------------
// SEC-097 — `dpop_require_nonce` is refused rather than silently inert
// ---------------------------------------------------------------------------

/// The field is persisted, echoed back by `GET`, and documented in the OpenAPI
/// schema — and **nothing reads it**. The token endpoint passes
/// `require_nonce: false` unconditionally, because this deployment stores no
/// per-client nonce to compare an echoed one against.
///
/// An operator who sets a security switch, sees it persisted and echoed back,
/// and gets nothing has been told a lie by the API. Until a real nonce exists,
/// `true` is refused at the point of action. `false` still round-trips, so the
/// wire shape is unchanged for the seven SDKs.
#[actix_rt::test]
async fn create_oauth2_client_refuses_the_unimplemented_dpop_nonce_switch() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Nonce Client",
            "redirect_uris": ["https://app.example.com/callback"],
            "grant_types": ["authorization_code"],
            "scopes": ["openid"],
            "dpop_require_nonce": true
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "a switch nothing reads must not be persisted as though it worked"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        body.to_string().contains("dpop_require_nonce"),
        "the refusal must name the field: {body}"
    );
}

/// `false` — the default and the only value any stored row holds — is
/// unaffected, so no existing client or SDK sees a behaviour change.
#[actix_rt::test]
async fn create_oauth2_client_still_accepts_dpop_require_nonce_false() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Plain Client",
            "redirect_uris": ["https://app.example.com/callback"],
            "grant_types": ["authorization_code"],
            "scopes": ["openid"],
            "dpop_require_nonce": false
        }))
        .to_request();

    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 201);
}

/// The update path is the other door onto the same field.
#[actix_rt::test]
async fn update_oauth2_client_refuses_the_unimplemented_dpop_nonce_switch() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let created = create_test_client(&app, &token).await;
    let id = created["id"].as_str().unwrap();

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "dpop_require_nonce": true }))
        .to_request();

    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 400);
}

// ---------------------------------------------------------------------------
// T23.1.5 — `client_secret_basic` at registration (X7.8, matrix row M9 layer 1)
// ---------------------------------------------------------------------------
//
// `fapi::validate_registration` asks `is_strong()`, so the FAPI profile
// refuses the Basic method through the arm that already refused
// `client_secret_post`. Those are unit tests; what is pinned here is that the
// admin API actually reaches the gate on both of its doors, and that a
// `standard` client is unaffected.

/// A `standard` client may register `client_secret_basic` through the admin
/// API, and the stored row says so.
#[actix_rt::test]
async fn a_standard_client_may_register_client_secret_basic() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Basic Client",
            "redirect_uris": ["https://app.example.com/callback"],
            "grant_types": ["authorization_code"],
            "scopes": ["openid"],
            "token_endpoint_auth_method": "client_secret_basic"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let created: serde_json::Value = test::read_body_json(resp).await;
    let id = created["id"].as_str().unwrap();

    // The creation response does not echo the method; the stored row does.
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let stored: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(stored["token_endpoint_auth_method"], "client_secret_basic");
}

/// A `fapi2` client may not register `client_secret_basic`, on create. The
/// refusal names the method, which is how an operator learns why.
#[actix_rt::test]
async fn a_fapi2_client_may_not_register_client_secret_basic() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "FAPI Basic Client",
            "redirect_uris": ["https://app.example.com/callback"],
            "grant_types": ["authorization_code"],
            "scopes": ["openid"],
            "profile": "fapi2",
            "require_par": true,
            "tls_client_certificate_bound_access_tokens": true,
            "token_endpoint_auth_method": "client_secret_basic"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
    let body = test::read_body(resp).await;
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("client_secret_basic"),
        "the refusal must name the method it refused"
    );
}

/// The update path is the other door: switching an existing `standard` Basic
/// client to `fapi2`, or an existing `fapi2` client to Basic, is validated on
/// the **merged** row and refused in both directions.
#[actix_rt::test]
async fn a_patch_cannot_make_a_client_fapi2_and_client_secret_basic_at_once() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Direction 1: a Basic client is flipped to the FAPI profile.
    let basic = {
        let req = test::TestRequest::post()
            .uri("/api/v1/oauth2-clients")
            .insert_header(("Authorization", format!("Bearer {token}")))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json(serde_json::json!({
                "name": "Basic Then FAPI",
                "redirect_uris": ["https://app.example.com/callback"],
                "grant_types": ["authorization_code"],
                "scopes": ["openid"],
                "token_endpoint_auth_method": "client_secret_basic"
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 201);
        test::read_body_json::<serde_json::Value, _>(resp).await
    };
    let id = basic["id"].as_str().unwrap();
    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "profile": "fapi2",
            "require_par": true,
            "tls_client_certificate_bound_access_tokens": true
        }))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status().as_u16(),
        400,
        "flipping a client_secret_basic client to fapi2 must be refused"
    );

    // Direction 2: a client with the FAPI profile is switched to Basic. The
    // only way to hold the profile through the admin API is with a strong
    // method, so build one with `private_key_jwt`.
    let fapi = {
        let req = test::TestRequest::post()
            .uri("/api/v1/oauth2-clients")
            .insert_header(("Authorization", format!("Bearer {token}")))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json(serde_json::json!({
                "name": "FAPI Then Basic",
                "redirect_uris": ["https://app.example.com/callback"],
                "grant_types": ["authorization_code"],
                "scopes": ["openid"],
                "profile": "fapi2",
                "require_par": true,
                "tls_client_certificate_bound_access_tokens": true,
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": "{\"keys\":[]}"
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 201);
        test::read_body_json::<serde_json::Value, _>(resp).await
    };
    let id = fapi["id"].as_str().unwrap();
    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "token_endpoint_auth_method": "client_secret_basic" }))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status().as_u16(),
        400,
        "switching a fapi2 client to client_secret_basic must be refused"
    );
}

// ---------------------------------------------------------------------------
// R101W2-04 — `backchannel_logout_uri` is registered against the outbound
// endpoint rules. The logout token it receives is a signed, session-naming
// credential, delivered through `guarded_fetch_no_redirect`.
// ---------------------------------------------------------------------------

/// Addresses and shapes the registration must refuse. `http://localhost/…`
/// and `http://127.0.0.1/…` are admitted by the redirect-URI rule but could
/// never be delivered (delivery requires `https` and refuses loopback), so they
/// are refused here too.
const REFUSED_BACKCHANNEL_URIS: &[&str] = &[
    "https://10.0.0.8/logout",
    "https://172.16.4.2/logout",
    "https://192.168.1.10/logout",
    "https://127.0.0.1/logout",
    "https://[::1]/logout",
    "https://localhost/logout",
    "https://rp.internal/logout",
    "https://169.254.169.254/latest/meta-data/",
    "https://[fd00:ec2::254]/logout",
    "https://[::ffff:169.254.169.254]/logout",
    "http://rp.example.com/logout",
    "http://localhost:3000/logout",
    "http://127.0.0.1:8080/logout",
    "/relative/logout",
    "not a url",
    "https://rp.example.com/logout#frag",
    "https://user:pw@rp.example.com/logout",
];

async fn post_client_with_backchannel(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    token: &str,
    uri: &str,
) -> actix_web::dev::ServiceResponse {
    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "RP",
            "redirect_uris": ["https://app.example.com/callback"],
            "grant_types": ["authorization_code"],
            "scopes": ["openid"],
            "backchannel_logout_uri": uri,
        }))
        .to_request();
    test::call_service(app, req).await
}

async fn put_backchannel(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    token: &str,
    id: &str,
    uri: &str,
) -> actix_web::dev::ServiceResponse {
    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "backchannel_logout_uri": uri }))
        .to_request();
    test::call_service(app, req).await
}

async fn stored_backchannel_uri(db: &Surreal<TestDb>, tenant_id: Uuid, id: &str) -> Option<String> {
    use axiam_core::repository::OAuth2ClientRepository;
    axiam_db::repository::SurrealOAuth2ClientRepository::new(db.clone())
        .get_by_id(tenant_id, id.parse().unwrap())
        .await
        .unwrap()
        .backchannel_logout_uri
}

#[actix_rt::test]
async fn create_refuses_a_backchannel_logout_uri_at_a_non_public_address_or_with_a_bad_shape() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    for uri in REFUSED_BACKCHANNEL_URIS {
        let resp = post_client_with_backchannel(&app, &token, uri).await;
        assert_eq!(
            resp.status().as_u16(),
            400,
            "{uri} must be refused on create"
        );
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(
            body.to_string().contains("backchannel_logout_uri"),
            "the refusal names the field for {uri}: {body}"
        );
    }
}

#[actix_rt::test]
async fn create_accepts_a_public_https_backchannel_logout_uri_and_treats_empty_as_none() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let resp =
        post_client_with_backchannel(&app, &token, "https://rp.example.com/logout?x=1").await;
    assert_eq!(resp.status().as_u16(), 201);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        stored_backchannel_uri(&db, tenant_id, body["id"].as_str().unwrap())
            .await
            .as_deref(),
        Some("https://rp.example.com/logout?x=1")
    );

    let resp = post_client_with_backchannel(&app, &token, "").await;
    assert_eq!(resp.status().as_u16(), 201, "an empty string is `none`");
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        stored_backchannel_uri(&db, tenant_id, body["id"].as_str().unwrap()).await,
        None
    );
}

#[actix_rt::test]
async fn update_refuses_a_backchannel_logout_uri_at_a_non_public_address_and_keeps_the_stored_one()
{
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let resp = post_client_with_backchannel(&app, &token, "https://rp.example.com/logout").await;
    assert_eq!(resp.status().as_u16(), 201);
    let created: serde_json::Value = test::read_body_json(resp).await;
    let id = created["id"].as_str().unwrap();

    for uri in REFUSED_BACKCHANNEL_URIS {
        let resp = put_backchannel(&app, &token, id, uri).await;
        assert_eq!(
            resp.status().as_u16(),
            400,
            "{uri} must be refused on update"
        );
    }
    assert_eq!(
        stored_backchannel_uri(&db, tenant_id, id).await.as_deref(),
        Some("https://rp.example.com/logout"),
        "a refused update changes nothing"
    );

    // A valid replacement is accepted, and an empty string clears it.
    let resp = put_backchannel(&app, &token, id, "https://rp2.example.com/logout").await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        stored_backchannel_uri(&db, tenant_id, id).await.as_deref(),
        Some("https://rp2.example.com/logout")
    );
    let resp = put_backchannel(&app, &token, id, "").await;
    assert_eq!(resp.status().as_u16(), 200, "clearing is not validated");
    assert_eq!(stored_backchannel_uri(&db, tenant_id, id).await, None);
}

/// A row registered under 1.0.0 may hold any value. An update that does not
/// touch the field leaves it as it is (no backfill, no re-validation); delivery
/// is what refuses it (`backchannel_logout`'s unit tests).
#[actix_rt::test]
async fn an_update_that_does_not_touch_the_backchannel_logout_uri_leaves_a_legacy_value_alone() {
    use axiam_core::models::oauth2_client::{
        AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateOAuth2Client, ManagedBy,
    };
    use axiam_core::repository::OAuth2ClientRepository;

    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (legacy, _) = axiam_db::repository::SurrealOAuth2ClientRepository::new(db.clone())
        .create(CreateOAuth2Client {
            tenant_id,
            name: "legacy".into(),
            redirect_uris: vec!["https://app.example.com/callback".into()],
            grant_types: vec!["authorization_code".into()],
            scopes: vec!["openid".into()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: Some("http://169.254.169.254/latest".into()),
            require_par: false,
            profile: ClientProfile::Standard,
            token_endpoint_auth_method: ClientAuthMethod::ClientSecretPost,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: vec![],
            tls_client_certificate_bound_access_tokens: false,
            jwks: None,
            jwks_uri: None,
            dpop_bound_access_tokens: false,
            dpop_require_nonce: false,
            authn_request_params: AuthnRequestParamsMode::Ignore,
            browser_sso: false,
            allowed_resources: Vec::new(),
            managed_by: ManagedBy::Admin,
            ciba: Default::default(),
        })
        .await
        .unwrap();
    let id = legacy.id.to_string();

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "name": "renamed" }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 200);
    assert_eq!(
        stored_backchannel_uri(&db, tenant_id, &id).await.as_deref(),
        Some("http://169.254.169.254/latest"),
        "no backfill: the stored row is not rewritten"
    );
}
