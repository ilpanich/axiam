//! Federation first-time SSO end-to-end test (FUNC-01, closes CQ-B40).
//!
//! Drives the PUBLIC OIDC SSO flow — `POST /api/v1/auth/federation/oidc/start`
//! then `POST /api/v1/auth/federation/oidc/callback` — against a wiremock mock
//! IdP, for a subject with NO pre-existing local account, and asserts:
//!
//! 1. The callback response sets `axiam_access`/`axiam_refresh`/`axiam_csrf`
//!    cookies (NOT JSON tokens — SsoLoginSuccessResponse carries only
//!    `user_id`/`session_id`/`expires_in`/`redirect_uri`).
//! 2. `GET /api/v1/auth/me` with those cookies returns 200 for the
//!    newly-provisioned user.
//!
//! Harness: `test_app!`/cookie-extraction conventions mirror
//! `password_reset_revokes_sessions.rs`; the wiremock mock-IdP setup (RSA
//! key generation, JWKS mounting, RS256 signing) mirrors
//! `axiam-server/tests/req5_oidc_e2e.rs`.
//!
//! ## Why this test can run against a loopback wiremock server at all
//!
//! `OidcFederationService::discover()`/`exchange_code()` route their outbound
//! fetches through the shared SSRF guard (SECHRD-02) with a test-only
//! `allow_private_networks` seam (28-05: threaded through from the SAME
//! `JwksCache` bit already used for JWKS fetches in `req5_oidc_e2e.rs`).
//! Registering `Arc::new(JwksCache::new_allow_private_networks())` as
//! app_data (below) is what makes `discover()` accept the wiremock server's
//! plain-HTTP `.well-known/openid-configuration` and `exchange_code()` reach
//! its loopback `/token` endpoint. Production always constructs
//! `JwksCache::new()` (SECHRD-02 stays fully enforced there).
//!
//! ## Metadata endpoint: RESOLVED as intentionally authenticated (Phase 28 FUNC-01)
//!
//! The plan originally asked for an assertion that the federation metadata
//! endpoint (`GET /api/v1/federation/saml/metadata`) is reachable with NO
//! auth header. Ground-truthing during 28-05 found that, despite being
//! listed in `PUBLIC_PATHS`, the handler (`saml_metadata`) unconditionally
//! requires a valid JWT via the `AuthenticatedUser` extractor (a bare `GET`
//! with zero credentials returns 401). This was routed to a human decision
//! at phase verification. Resolution (D-15): keep the endpoint JWT-gated —
//! the stale `PUBLIC_PATHS` entry was removed (see `permissions.rs`) so the
//! middleware allowlist now matches the handler, and FUNC-01's acceptance
//! criterion was reworded to reflect that metadata is admin-authenticated,
//! not public. Authenticated metadata behavior is covered by
//! `federation_test.rs::saml_metadata_returns_xml`.

use std::net::SocketAddr;
use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealFederationConfigRepository, SurrealFederationLinkRepository,
    SurrealFederationLoginStateRepository, SurrealOrganizationRepository,
    SurrealPermissionRepository, SurrealRefreshTokenRepository, SurrealRoleRepository,
    SurrealSessionRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_federation::jwks_cache::JwksCache;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12345";
const CSRF_TOKEN: &str = "test-csrf-token";
/// Test-only AES-256-GCM key (32 bytes of 0x2a) — not a secret. gitleaks:allow
const TEST_FED_ENC_KEY: [u8; 32] = [0x2a; 32];

// ---------------------------------------------------------------------------
// Mock-IdP helpers (mirrors axiam-server/tests/req5_oidc_e2e.rs)
// ---------------------------------------------------------------------------

struct TestKeys {
    private_key_pem: String,
    jwk_json: serde_json::Value,
}

impl TestKeys {
    fn generate(kid: &str) -> Self {
        let mut rng = rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");

        let private_key_pem = private_key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .expect("RSA private key to PEM")
            .to_string();

        let n = URL_SAFE_NO_PAD.encode(private_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(private_key.e().to_bytes_be());

        let jwk_json = json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": n,
            "e": e
        });

        Self {
            private_key_pem,
            jwk_json,
        }
    }

    fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_rsa_pem(self.private_key_pem.as_bytes()).expect("encoding key")
    }

    fn jwks_json(&self) -> serde_json::Value {
        json!({ "keys": [self.jwk_json.clone()] })
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn sign_jwt(payload: &serde_json::Value, key: &EncodingKey, kid: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    encode(&header, payload, key).expect("sign JWT")
}

// ---------------------------------------------------------------------------
// Test app scaffolding
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
        // Required for federation config create + the public SSO handlers (SEC-045).
        federation_encryption_key: Some(TEST_FED_ENC_KEY),
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
            slug: "sso-first-time-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Test Tenant".into(),
            slug: "sso-first-time-tenant".into(),
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

fn make_auth_service(
    db: &Surreal<TestDb>,
    auth: &AuthConfig,
) -> axiam_auth::AuthService<
    SurrealUserRepository<TestDb>,
    SurrealSessionRepository<TestDb>,
    SurrealFederationLinkRepository<TestDb>,
    SurrealRefreshTokenRepository<TestDb>,
> {
    axiam_auth::AuthService::new(
        SurrealUserRepository::new(db.clone()),
        SurrealSessionRepository::new(db.clone()),
        SurrealFederationLinkRepository::new(db.clone()),
        SurrealRefreshTokenRepository::new(db.clone()),
        auth.clone(),
        std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
    )
}

macro_rules! test_app {
    ($db:expr, $auth:expr, $jwks_cache:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(make_auth_service(&$db, &$auth)))
                .app_data(web::Data::new(SurrealOrganizationRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealTenantRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealFederationConfigRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealFederationLinkRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealFederationLoginStateRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealUserRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealRoleRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealPermissionRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealSessionRepository::new($db.clone())))
                // Note: no `Arc<dyn SessionValidator>` app_data registered
                // (mirrors federation_test.rs) — the admin bearer token is
                // minted directly via `issue_access_token`, not through a
                // real login, so it has no matching `Session` row; the
                // optional SessionValidator check would otherwise 401 it.
                .app_data(web::Data::new(SurrealRefreshTokenRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(
                    reqwest::Client::builder()
                        .redirect(reqwest::redirect::Policy::none())
                        .timeout(std::time::Duration::from_secs(10))
                        .build()
                        .unwrap(),
                ))
                // 28-05: enables discover()/exchange_code() to reach the
                // loopback wiremock IdP started by this test (see file
                // header for the full rationale).
                .app_data(web::Data::new($jwks_cache))
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

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn first_time_oidc_sso_sets_cookies_and_me_succeeds() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin_user_id = create_admin_user(&db, tenant_id).await;
    let admin_token = mint_token(&auth, admin_user_id, tenant_id, org_id);

    // --- Mock IdP setup (discovery + JWKS mounted up front; /token mounted
    // later once we know the server-generated nonce). ---
    let idp = MockServer::start().await;
    let issuer = idp.uri();
    let keys = TestKeys::generate("mock-idp-kid");
    let client_id = "mock-idp-client";

    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(keys.jwks_json()))
        .mount(&idp)
        .await;

    let discovery_doc = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
    });
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_doc))
        .mount(&idp)
        .await;

    let jwks_cache = Arc::new(JwksCache::new_allow_private_networks());
    let app = test_app!(db, auth, jwks_cache);

    // --- Step 1: create an OIDC federation config via the authenticated API. ---
    let create_req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/federation-configs")
        .insert_header(("Authorization", format!("Bearer {admin_token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({
            "provider": "MockIdP",
            "protocol": "OidcConnect",
            "metadata_url": format!("{issuer}/.well-known/openid-configuration"),
            "client_id": client_id,
            "client_secret": "mock-idp-secret",
        }))
        .to_request();
    let create_resp = test::call_service(&app, create_req).await;
    assert_eq!(
        create_resp.status().as_u16(),
        201,
        "federation config creation must succeed"
    );
    let config_body: serde_json::Value = test::read_body_json(create_resp).await;
    let config_id = config_body["id"].as_str().unwrap().to_string();

    // --- Step 2: public /oidc/start — no auth header. ---
    let start_req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/federation/oidc/start")
        .set_json(json!({
            "org_id": org_id,
            "tenant_id": tenant_id,
            "federation_config_id": config_id,
            "redirect_uri": "https://spa.example.com/callback",
        }))
        .to_request();
    let start_resp = test::call_service(&app, start_req).await;
    assert_eq!(
        start_resp.status().as_u16(),
        200,
        "oidc/start must succeed"
    );
    let start_body: serde_json::Value = test::read_body_json(start_resp).await;
    let state = start_body["state"].as_str().unwrap().to_string();
    let authorize_url = start_body["authorize_url"].as_str().unwrap();

    // The nonce stays server-side (T-04-31) — never returned in the JSON
    // body — but IS embedded in the authorize_url query string, which is
    // exactly what the caller is expected to redirect the browser to.
    let parsed_authorize_url = url::Url::parse(authorize_url).expect("valid authorize_url");
    let nonce = parsed_authorize_url
        .query_pairs()
        .find(|(k, _)| k == "nonce")
        .map(|(_, v)| v.into_owned())
        .expect("authorize_url must carry the nonce query param");

    // --- Mount /token now that the nonce is known — sign an ID token for a
    // BRAND-NEW subject (no pre-existing local account / federation link). ---
    let now = now_secs();
    let id_token_claims = json!({
        "sub": "first-time-sso-subject-001",
        "iss": issuer,
        "aud": client_id,
        "exp": now + 3600,
        "iat": now,
        "nonce": nonce,
        "email": "first-time-sso-user@example.com",
    });
    let id_token = sign_jwt(&id_token_claims, &keys.encoding_key(), "mock-idp-kid");

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "mock-idp-access-token",
            "id_token": id_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        })))
        .mount(&idp)
        .await;

    // --- Step 3: public /oidc/callback — no auth header. ---
    let callback_req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/federation/oidc/callback")
        .set_json(json!({
            "state": state,
            "code": "mock-authorization-code",
        }))
        .to_request();
    let callback_resp = test::call_service(&app, callback_req).await;
    assert_eq!(
        callback_resp.status().as_u16(),
        200,
        "oidc/callback must succeed for a first-time subject"
    );

    // Cookies, NOT JSON tokens (RESEARCH.md FUNC-01 finding — SsoLoginSuccessResponse
    // carries only user_id/session_id/expires_in/redirect_uri).
    let access_cookie = callback_resp
        .response()
        .cookies()
        .find(|c| c.name() == "axiam_access")
        .map(|c| c.value().to_owned())
        .expect("axiam_access cookie must be set");
    let refresh_cookie = callback_resp
        .response()
        .cookies()
        .find(|c| c.name() == "axiam_refresh")
        .map(|c| c.value().to_owned())
        .expect("axiam_refresh cookie must be set");
    let csrf_cookie = callback_resp
        .response()
        .cookies()
        .find(|c| c.name() == "axiam_csrf")
        .map(|c| c.value().to_owned())
        .expect("axiam_csrf cookie must be set");
    // refresh_cookie is asserted present above; unused beyond that (me only
    // needs the access + csrf cookies).
    let _ = refresh_cookie;

    let callback_body: serde_json::Value = test::read_body_json(callback_resp).await;
    assert!(
        callback_body.get("user_id").is_some(),
        "callback response must include the newly-provisioned user_id"
    );
    assert!(
        callback_body.get("session_id").is_some(),
        "callback response must include a session_id"
    );

    // --- Step 4: /auth/me with the cookies must succeed for the
    // newly-provisioned user (no pre-existing local account existed). ---
    let me_req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/me")
        .insert_header((
            "Cookie",
            format!("axiam_access={access_cookie}; axiam_csrf={csrf_cookie}"),
        ))
        .insert_header(("X-CSRF-Token", csrf_cookie.clone()))
        .to_request();
    let me_resp = test::call_service(&app, me_req).await;
    assert_eq!(
        me_resp.status().as_u16(),
        200,
        "/auth/me must succeed for the newly-provisioned first-time SSO user"
    );
    let me_body: serde_json::Value = test::read_body_json(me_resp).await;
    assert_eq!(
        me_body["user"]["email"].as_str(),
        Some("first-time-sso-user@example.com"),
        "the provisioned user's email must come from the ID token's email claim"
    );
}
