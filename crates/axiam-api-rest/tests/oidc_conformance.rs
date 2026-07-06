//! OIDC Core 1.0 MUST-level conformance tests.
//!
//! Covers gap behaviors NOT exercised by oauth2_flow_test.rs:
//! - Discovery document contains all required OIDC Core fields (OIDC Discovery §3)
//! - "none" absent from id_token_signing_alg_values_supported (OIDC Discovery §3)
//! - id_token iss matches the discovery issuer (OIDC Core §3.1.3.7)
//!
//! alg:none rejection at service layer is covered by:
//!   crates/axiam-server/tests/req5_oidc_e2e.rs::oidc_rejects_alg_none (line 179)
//!
//! Harness is a copy of oauth2_flow_test.rs — house style (no shared util module).

use actix_web::{App, test, web};
use std::net::SocketAddr;

use axiam_api_rest::RateLimitConfig;

/// Loopback peer address for test requests so the rate-limiter key extractor
/// can resolve a client IP without a real socket.
const TEST_PEER: &str = "127.0.0.1:12345";

use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

/// Arbitrary CSRF token for the double-submit check (SEC-046). These
/// Bearer-token tests have no login/`axiam_csrf` cookie, so we send a matching
/// `axiam_csrf` cookie + `X-CSRF-Token` header; the middleware only checks they
/// are equal (no session lookup). Safe (GET) requests ignore it.
/// `/oauth2/*` endpoints are CSRF-exempt and intentionally receive no token.
const CSRF_TOKEN: &str = "test-csrf-token";

// ---------------------------------------------------------------------------
// Test scaffolding — mirrors oauth2_flow_test.rs exactly
// ---------------------------------------------------------------------------

// Test-only Ed25519 keypair with no real-world value. nosemgrep
fn test_auth_config() -> AuthConfig {
    AuthConfig {
        jwt_private_key_pem: concat!(
            "-----BEGIN PRIVATE KEY-----\n",
            "MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n",
            "-----END PRIVATE KEY-----"
        )
        .into(),
        jwt_public_key_pem: concat!(
            "-----BEGIN PUBLIC KEY-----\n",
            "MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n",
            "-----END PUBLIC KEY-----"
        )
        .into(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: "https://localhost".into(),
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
// Flow helpers
// ---------------------------------------------------------------------------

/// Create an OAuth2 client with openid + profile scope.
/// Returns `(client_id, client_secret, redirect_uri)`.
async fn create_oidc_client(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    token: &str,
) -> (String, String, String) {
    let redirect_uri = "https://app.example.com/callback";
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "OIDC Conformance Client",
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "scopes": ["openid", "profile"]
        }))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let body: serde_json::Value = test::read_body_json(resp).await;
    (
        body["client_id"].as_str().unwrap().to_string(),
        body["client_secret"].as_str().unwrap().to_string(),
        redirect_uri.to_string(),
    )
}

// ---------------------------------------------------------------------------
// OIDC Discovery §3 — required field completeness
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn discovery_doc_has_all_required_fields() {
    // OIDC Discovery 1.0 §3: The OP MUST provide the following metadata fields.
    let (db, _org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let _user_id = create_admin_user(&db, tenant_id).await;
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let doc: serde_json::Value = test::read_body_json(resp).await;

    // OIDC Discovery 1.0 §3: REQUIRED fields
    let required_fields = [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "response_types_supported",
        "subject_types_supported",
        "id_token_signing_alg_values_supported",
    ];

    for field in required_fields {
        assert!(
            doc.get(field).is_some() && doc[field] != serde_json::Value::Null,
            "discovery doc missing required OIDC field: {field}"
        );
    }
}

// ---------------------------------------------------------------------------
// OIDC Discovery §3 — "none" must be absent from signing alg list
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn discovery_doc_excludes_alg_none() {
    // OIDC Core 1.0 §3.1.3.7 / OIDC Discovery §3:
    // "none" MUST NOT appear in id_token_signing_alg_values_supported.
    // Allowing "none" would permit unsigned ID tokens, breaking authentication security.
    let (db, _org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let _user_id = create_admin_user(&db, tenant_id).await;
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let doc: serde_json::Value = test::read_body_json(resp).await;

    let algs = doc["id_token_signing_alg_values_supported"]
        .as_array()
        .expect("id_token_signing_alg_values_supported must be an array");

    assert!(
        !algs.iter().any(|a| a == "none"),
        "id_token_signing_alg_values_supported must NOT contain 'none'; got: {algs:?}"
    );
}

// ---------------------------------------------------------------------------
// OIDC Core §3.1.3.7 — id_token iss MUST match discovery issuer
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn id_token_iss_matches_discovery_issuer() {
    // OIDC Core 1.0 §3.1.3.7: The iss Claim Value MUST exactly match
    // the value of the iss (Issuer) Claim in the ID Token.
    // Equivalently: claims["iss"] must equal discovery_doc["issuer"].
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Create an OIDC client and run the full auth-code flow with openid scope
    let (client_id, client_secret, redirect_uri) = create_oidc_client(&app, &user_jwt).await;

    // Authorize with openid + profile scope
    let authorize_uri = format!(
        "/oauth2/authorize?response_type=code&client_id={client_id}\
         &redirect_uri={redirect_uri}&scope=openid%20profile\
         &nonce=oidc-conformance-nonce-123"
    );
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&authorize_uri)
        .insert_header(("Authorization", format!("Bearer {user_jwt}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 302);

    let location = resp
        .headers()
        .get("Location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let location_url = url::Url::parse(&location).unwrap();
    let code = location_url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .expect("authorization code not in redirect Location");

    // Exchange the code for tokens
    let form = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={redirect_uri}\
         &client_id={client_id}&client_secret={client_secret}"
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let token_body: serde_json::Value = test::read_body_json(resp).await;
    let id_token = token_body["id_token"]
        .as_str()
        .expect("id_token must be present when openid scope is requested");

    // Decode id_token payload (base64url, no signature verification needed)
    let parts: Vec<&str> = id_token.split('.').collect();
    assert_eq!(parts.len(), 3, "id_token must be a three-part JWT");
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("id_token payload must be valid base64url");
    let claims: serde_json::Value =
        serde_json::from_slice(&payload_bytes).expect("id_token payload must be valid JSON");

    // Fetch the discovery document issuer
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    let discovery: serde_json::Value = test::read_body_json(resp).await;

    // OIDC Core §3.1.3.7: iss in id_token MUST match issuer in discovery doc
    assert_eq!(
        claims["iss"], discovery["issuer"],
        "id_token iss ({}) must match discovery issuer ({})",
        claims["iss"], discovery["issuer"]
    );
}
