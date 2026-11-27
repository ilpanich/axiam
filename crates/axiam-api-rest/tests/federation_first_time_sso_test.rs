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
use std::sync::{Arc, Mutex};

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::reactor::{DynReactorGate, ReactorOutcome, SharedReactorGate};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_federation::jwks_cache::JwksCache;
use axiam_federation::oidc::OidcFederationService;
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
        // R-3: since the deployment-origin rule applies to all four federated
        // start paths (not only the cross-site two), a fixture whose SPA is on
        // a different origin than the issuer has to name it — exactly what a
        // real split-origin deployment does. Naming it here also keeps this
        // suite honest about the migration the change asks of operators.
        sso_spa_origins: vec!["https://spa.example.com".into()],
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
            kind: TenantKind::Standard,
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

macro_rules! test_app {
    ($db:expr, $auth:expr, $jwks_cache:expr) => {
        test_app!($db, $auth, $jwks_cache, None)
    };
    // `$gate`: a reactor gate installed on `AuthService` exactly as the
    // composition root installs one, so a test can see whether
    // `login.post_auth` was asked.
    ($db:expr, $auth:expr, $jwks_cache:expr, $gate:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new({
                    let mut state = AppState::for_test($db.clone(), $auth.clone());
                    state.http_client = reqwest::Client::builder()
                        .redirect(reqwest::redirect::Policy::none())
                        .timeout(std::time::Duration::from_secs(10))
                        .build()
                        .unwrap();
                    // 28-05: enables discover()/exchange_code() to reach the
                    // loopback wiremock IdP started by this test (see file
                    // header for the full rationale).
                    state.jwks_cache = $jwks_cache;
                    // QUAL-07: OidcFederationService is a hoisted AppState
                    // singleton; build it with the same test-only encryption
                    // key, http_client, and jwks_cache used elsewhere here.
                    state.federation.oidc_federation_service = Some(OidcFederationService::new(
                        state.federation.federation_config_repo.clone(),
                        state.federation.federation_link_repo.clone(),
                        state.user_repo.clone(),
                        state.http_client.clone(),
                        std::sync::Arc::clone(&state.jwks_cache),
                        TEST_FED_ENC_KEY,
                    )
                    // #877: as the composition root attaches it.
                    .with_tenant_admission(Arc::new(state.tenant_repo.clone())));
                    let gate: Option<SharedReactorGate> = $gate;
                    if let Some(gate) = gate {
                        state.auth_service = state.auth_service.clone().with_reactor_gate(gate);
                    }
                    state
                }))
                // Note: no `Arc<dyn SessionValidator>` app_data registered
                // (mirrors federation_test.rs) — the admin bearer token is
                // minted directly via `issue_access_token`, not through a
                // real login, so it has no matching `Session` row; the
                // optional SessionValidator check would otherwise 401 it.
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
    // T23.1.8 / D-11: per-tenant issuers on, so the federated sign-in's OP
    // cookie copies are asserted below. Nothing else in this flow reads it.
    let auth = AuthConfig {
        tenant_issuer_paths: true,
        ..test_auth_config()
    };
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
    assert_eq!(start_resp.status().as_u16(), 200, "oidc/start must succeed");
    // #837 — the start binds the sign-in to this browser; the callback must
    // carry the cookie back, as a browser (or an SDK's cookie jar) does.
    let binding = start_resp
        .response()
        .cookies()
        .find(|c| c.name() == "axiam_fed_bind" || c.name() == "__Host-axiam_fed_bind")
        .map(|c| c.into_owned())
        .expect("oidc/start must set the browser-binding cookie");
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
        .cookie(binding)
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

    // T23.1.8 / D-11 — a federated sign-in is a browser sign-in like any other:
    // the OP cookie at the bare path and at the session's own tenant path,
    // identical but for `Path`. Asserted without formatting the value.
    let ops: Vec<_> = callback_resp
        .response()
        .cookies()
        .filter(|c| c.name() == "axiam_op_session")
        .map(actix_web::cookie::Cookie::into_owned)
        .collect();
    let paths: Vec<&str> = ops.iter().filter_map(|c| c.path()).collect();
    let tenant_path = format!("/t/{tenant_id}/oauth2/authorize");
    let saml_path = format!("/saml/v2/{tenant_id}/sso");
    assert_eq!(
        paths,
        vec![
            "/oauth2/authorize",
            tenant_path.as_str(),
            saml_path.as_str()
        ]
    );
    for c in &ops {
        assert!(c.value() == ops[0].value() && !c.value().is_empty());
        assert!(c.http_only().unwrap_or(false));
        assert!(c.secure().unwrap_or(false));
        assert_eq!(c.same_site(), Some(actix_web::cookie::SameSite::Lax));
        assert_eq!(c.max_age(), ops[0].max_age());
        assert!(c.max_age().is_some());
    }

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

// ---------------------------------------------------------------------------
// Authenticated (account-linking) OIDC endpoints —
// `POST /api/v1/federation/oidc/authorize` + `.../oidc/callback`.
//
// `federation_test.rs` only ever exercises these with
// `oidc_federation_service: None` (AppState::for_test's default), so it can
// only reach the "federation encryption key not configured" branch. These
// tests reuse THIS file's `test_app!` (which wires a real
// `OidcFederationService` against the wiremock IdP, exactly like the
// first-time-SSO test above) to drive the real success/error branches:
// server-side state/nonce persistence, IdP round-trip, and error mapping.
// ---------------------------------------------------------------------------

/// Starts a wiremock IdP with discovery + JWKS mounted, and returns
/// `(MockServer, TestKeys, client_id)`. `/token` is NOT mounted — callers
/// mount it themselves once they know the server-generated nonce (mirrors
/// the first-time-SSO test above).
async fn start_mock_idp() -> (MockServer, TestKeys, &'static str) {
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

    (idp, keys, client_id)
}

/// Full happy path through the AUTHENTICATED (account-linking)
/// `/api/v1/federation/oidc/authorize` + `/api/v1/federation/oidc/callback`
/// endpoints: builds the authorize URL (persisting server-side state/nonce
/// via `FederationLoginState`), then the callback consumes that state,
/// round-trips the mock IdP, and provisions a new user.
#[actix_rt::test]
async fn oidc_authorize_and_callback_authenticated_happy_path() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin_user_id = create_admin_user(&db, tenant_id).await;
    let admin_token = mint_token(&auth, admin_user_id, tenant_id, org_id);

    let (idp, keys, client_id) = start_mock_idp().await;
    let issuer = idp.uri();

    let jwks_cache = Arc::new(JwksCache::new_allow_private_networks());
    let app = test_app!(db, auth, jwks_cache);

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
            "client_secret": Uuid::new_v4().to_string(),
        }))
        .to_request();
    let create_resp = test::call_service(&app, create_req).await;
    assert_eq!(create_resp.status().as_u16(), 201);
    let config_body: serde_json::Value = test::read_body_json(create_resp).await;
    let config_id = config_body["id"].as_str().unwrap().to_string();

    // --- authorize: builds URL + persists server-side state/nonce. ---
    let client_supplied_nonce = format!("ignored-{}", Uuid::new_v4());
    let authorize_req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/federation/oidc/authorize")
        .insert_header(("Authorization", format!("Bearer {admin_token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({
            "config_id": config_id,
            "redirect_uri": "https://rp.example.com/cb",
            "state": "client-state-1",
            "nonce": client_supplied_nonce,
        }))
        .to_request();
    let authorize_resp = test::call_service(&app, authorize_req).await;
    assert_eq!(
        authorize_resp.status().as_u16(),
        200,
        "authenticated oidc/authorize must succeed"
    );
    let authorize_body: serde_json::Value = test::read_body_json(authorize_resp).await;
    let authorize_url = authorize_body["url"].as_str().unwrap();
    let parsed = url::Url::parse(authorize_url).expect("valid authorize URL");
    // T-04-31: the client-supplied nonce is never used — a fresh server-side
    // nonce is generated and embedded instead.
    let server_nonce = parsed
        .query_pairs()
        .find(|(k, _)| k == "nonce")
        .map(|(_, v)| v.into_owned())
        .expect("authorize_url must carry a server-generated nonce");
    assert_ne!(server_nonce, client_supplied_nonce);

    let now = now_secs();
    let id_token_claims = json!({
        "sub": "account-link-subject-1",
        "iss": issuer,
        "aud": client_id,
        "exp": now + 3600,
        "iat": now,
        "nonce": server_nonce,
        "email": "account-link-user@example.com",
    });
    let id_token = sign_jwt(&id_token_claims, &keys.encoding_key(), "mock-idp-kid");
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "at",
            "id_token": id_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        })))
        .mount(&idp)
        .await;

    let callback_req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/federation/oidc/callback")
        .insert_header(("Authorization", format!("Bearer {admin_token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({
            "config_id": config_id,
            "code": "auth-code",
            "redirect_uri": "https://rp.example.com/cb",
            "state": "client-state-1",
            "nonce": client_supplied_nonce,
        }))
        .to_request();
    let callback_resp = test::call_service(&app, callback_req).await;
    assert_eq!(
        callback_resp.status().as_u16(),
        200,
        "authenticated oidc/callback must succeed"
    );
    let callback_body: serde_json::Value = test::read_body_json(callback_resp).await;
    assert_eq!(callback_body["newly_provisioned"].as_bool(), Some(true));
    assert!(callback_body.get("user_id").is_some());
    assert!(callback_body.get("federation_link_id").is_some());
}

/// The authenticated `oidc/callback` must reject a `state` value that was
/// never issued by `oidc/authorize` (or has already been consumed/expired) —
/// `federation_login_state_repo.consume_by_state` returns `None`, which maps
/// to `AuthenticationFailed` (401), not a panic or 500.
#[actix_rt::test]
async fn oidc_callback_authenticated_rejects_unknown_state() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin_user_id = create_admin_user(&db, tenant_id).await;
    let admin_token = mint_token(&auth, admin_user_id, tenant_id, org_id);

    let jwks_cache = Arc::new(JwksCache::new_allow_private_networks());
    let app = test_app!(db, auth, jwks_cache);

    let callback_req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/federation/oidc/callback")
        .insert_header(("Authorization", format!("Bearer {admin_token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({
            "config_id": Uuid::new_v4(),
            "code": "auth-code",
            "redirect_uri": "https://rp.example.com/cb",
            "state": "never-issued-state",
            "nonce": Uuid::new_v4().to_string(),
        }))
        .to_request();
    let callback_resp = test::call_service(&app, callback_req).await;
    assert_eq!(
        callback_resp.status().as_u16(),
        401,
        "unknown/expired state must be rejected as an authentication failure"
    );
}

/// When the external IdP's `/token` endpoint errors, `handle_callback`'s
/// `TokenExchangeFailed` must propagate through the authenticated
/// `oidc/callback` handler as an upstream-dependency failure (503), not a
/// 500 — exercises the handler's `map_err(AxiamError::from)` arm end to end.
#[actix_rt::test]
async fn oidc_callback_authenticated_propagates_idp_token_error() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin_user_id = create_admin_user(&db, tenant_id).await;
    let admin_token = mint_token(&auth, admin_user_id, tenant_id, org_id);

    let (idp, _keys, client_id) = start_mock_idp().await;
    let issuer = idp.uri();
    // IdP's token endpoint is broken.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&idp)
        .await;

    let jwks_cache = Arc::new(JwksCache::new_allow_private_networks());
    let app = test_app!(db, auth, jwks_cache);

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
            "client_secret": Uuid::new_v4().to_string(),
        }))
        .to_request();
    let create_resp = test::call_service(&app, create_req).await;
    assert_eq!(create_resp.status().as_u16(), 201);
    let config_body: serde_json::Value = test::read_body_json(create_resp).await;
    let config_id = config_body["id"].as_str().unwrap().to_string();

    let authorize_req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/federation/oidc/authorize")
        .insert_header(("Authorization", format!("Bearer {admin_token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({
            "config_id": config_id,
            "redirect_uri": "https://rp.example.com/cb",
            "state": "client-state-err",
            "nonce": Uuid::new_v4().to_string(),
        }))
        .to_request();
    let authorize_resp = test::call_service(&app, authorize_req).await;
    assert_eq!(authorize_resp.status().as_u16(), 200);

    let callback_req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/federation/oidc/callback")
        .insert_header(("Authorization", format!("Bearer {admin_token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({
            "config_id": config_id,
            "code": "auth-code",
            "redirect_uri": "https://rp.example.com/cb",
            "state": "client-state-err",
            "nonce": Uuid::new_v4().to_string(),
        }))
        .to_request();
    let callback_resp = test::call_service(&app, callback_req).await;
    assert_eq!(
        callback_resp.status().as_u16(),
        503,
        "an upstream IdP token-endpoint failure must surface as 503, not 500"
    );
}

/// A disabled federation config must reject the authenticated
/// `oidc/authorize` call with a validation error (400) — exercises
/// `build_authorization_url`'s `ConfigDisabled` branch end to end through
/// the handler's error mapping, using a REAL (not `None`) service.
#[actix_rt::test]
async fn oidc_authorize_authenticated_rejects_disabled_config() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin_user_id = create_admin_user(&db, tenant_id).await;
    let admin_token = mint_token(&auth, admin_user_id, tenant_id, org_id);

    let (idp, _keys, client_id) = start_mock_idp().await;
    let issuer = idp.uri();

    let jwks_cache = Arc::new(JwksCache::new_allow_private_networks());
    let app = test_app!(db, auth, jwks_cache);

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
            "client_secret": Uuid::new_v4().to_string(),
        }))
        .to_request();
    let create_resp = test::call_service(&app, create_req).await;
    assert_eq!(create_resp.status().as_u16(), 201);
    let config_body: serde_json::Value = test::read_body_json(create_resp).await;
    let config_id = config_body["id"].as_str().unwrap().to_string();

    // Disable it via the admin API.
    let disable_req = test::TestRequest::put()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/federation-configs/{config_id}"))
        .insert_header(("Authorization", format!("Bearer {admin_token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({ "enabled": false }))
        .to_request();
    let disable_resp = test::call_service(&app, disable_req).await;
    assert_eq!(disable_resp.status().as_u16(), 200);

    let authorize_req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/federation/oidc/authorize")
        .insert_header(("Authorization", format!("Bearer {admin_token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({
            "config_id": config_id,
            "redirect_uri": "https://rp.example.com/cb",
            "state": "some-state",
            "nonce": Uuid::new_v4().to_string(),
        }))
        .to_request();
    let authorize_resp = test::call_service(&app, authorize_req).await;
    assert_eq!(
        authorize_resp.status().as_u16(),
        400,
        "authorize against a disabled config must be rejected"
    );
}

/// Cross-tenant isolation: a federation config created under tenant A must
/// be invisible to an admin authenticated as tenant B — `oidc/authorize`
/// must 404 (`FederationError::ConfigNotFound` via `get_by_id`'s
/// tenant-scoped lookup), not leak the other tenant's config.
#[actix_rt::test]
async fn oidc_authorize_authenticated_rejects_cross_tenant_config() {
    let (db, org_id, tenant_a) = setup_db().await;
    let auth = test_auth_config();

    // A second, unrelated tenant under the same org.
    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant_b = tenant_repo
        .create(CreateTenant {
            organization_id: org_id,
            kind: TenantKind::Standard,
            name: "Other Tenant".into(),
            slug: "sso-first-time-tenant-b".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let admin_a = create_admin_user(&db, tenant_a).await;
    let admin_a_token = mint_token(&auth, admin_a, tenant_a, org_id);
    let admin_b = create_admin_user(&db, tenant_b.id).await;
    let admin_b_token = mint_token(&auth, admin_b, tenant_b.id, org_id);

    let jwks_cache = Arc::new(JwksCache::new_allow_private_networks());
    let app = test_app!(db, auth, jwks_cache);

    // Config created under tenant A.
    let create_req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/federation-configs")
        .insert_header(("Authorization", format!("Bearer {admin_a_token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({
            "provider": "MockIdP",
            "protocol": "OidcConnect",
            "metadata_url": "https://idp.example.com/.well-known/openid-configuration",
            "client_id": "cid",
            "client_secret": Uuid::new_v4().to_string(),
        }))
        .to_request();
    let create_resp = test::call_service(&app, create_req).await;
    assert_eq!(create_resp.status().as_u16(), 201);
    let config_body: serde_json::Value = test::read_body_json(create_resp).await;
    let config_id = config_body["id"].as_str().unwrap().to_string();

    // Tenant B's admin attempts to authorize against tenant A's config.
    let authorize_req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/federation/oidc/authorize")
        .insert_header(("Authorization", format!("Bearer {admin_b_token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({
            "config_id": config_id,
            "redirect_uri": "https://rp.example.com/cb",
            "state": "some-state",
            "nonce": Uuid::new_v4().to_string(),
        }))
        .to_request();
    let authorize_resp = test::call_service(&app, authorize_req).await;
    assert_eq!(
        authorize_resp.status().as_u16(),
        404,
        "a config from a different tenant must be invisible (404), not leaked"
    );
}

// ---------------------------------------------------------------------------
// SA-13 (N16, D-3) and #877: the federated doors refuse a suspended tenant
// before anything is written
// ---------------------------------------------------------------------------
//
// The refusal itself (`403 tenant_suspended`, no session) predates #877; what
// #877 adds is *where* it happens. The callbacks used to provision the user
// and the federation link, and ask the `login.post_auth` reactor, before the
// session step refused — so anyone the tenant's provider would authenticate
// could create accounts in a suspended tenant. These tests count what a
// refused callback left behind. The `*_answers_alike_*` tests pin the other
// half of the constraint: the check runs only once the provider's answer has
// verified, so a caller without one learns nothing about the suspension
// (SR1-8).

/// Every reactor event the gate was asked about.
type GateLog = Arc<Mutex<Vec<&'static str>>>;

/// A gate that allows everything and records what it was asked.
struct RecordingGate {
    seen: GateLog,
}

impl DynReactorGate for RecordingGate {
    fn intercept_dyn<'a>(
        &'a self,
        _tenant_id: Uuid,
        event: &'static str,
        _payload: serde_json::Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ReactorOutcome> + Send + 'a>> {
        self.seen.lock().unwrap().push(event);
        Box::pin(std::future::ready(ReactorOutcome::Allow))
    }

    // A scripted double stands in for a working transport.
    fn can_dispatch_dyn(&self) -> bool {
        true
    }
}

fn recording_gate() -> (SharedReactorGate, GateLog) {
    let seen: GateLog = Arc::new(Mutex::new(Vec::new()));
    (Arc::new(RecordingGate { seen: seen.clone() }), seen)
}

/// How often the gate was asked `login.post_auth`.
fn post_auth_calls(seen: &GateLog) -> usize {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|event| **event == "login.post_auth")
        .count()
}

/// Suspend `tenant_id`, as an operator does while the user is at the provider.
async fn suspend(db: &Surreal<TestDb>, tenant_id: Uuid) {
    use axiam_core::models::tenant::{TenantStatus, UpdateTenant};
    SurrealTenantRepository::new(db.clone())
        .update(
            tenant_id,
            UpdateTenant {
                status: Some(TenantStatus::Suspended),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

async fn count_in_tenant(db: &Surreal<TestDb>, query: &str, tenant_id: Uuid) -> u64 {
    let mut result = db
        .query(query)
        .bind(("tenant", tenant_id.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
    let rows: Vec<axiam_db::CountRow> = result.take(0).unwrap();
    rows.first().map_or(0, |r| r.total)
}

/// What a federated callback answered, and what it left behind in the tenant.
/// What a failed assertion may print about a callback answer: its status and
/// `error` code only. A response body can carry tokens or a session, and a
/// failure message is a log too, so the body itself is never printed.
fn printable(status: u16, body: &serde_json::Value) -> String {
    format!("status {status}, error {}", body["error"])
}

struct CallbackOutcome {
    status: u16,
    body: serde_json::Value,
    sets_session: bool,
    /// Users other than the administrator the fixture creates.
    users: u64,
    federation_links: u64,
    post_auth_calls: usize,
}

async fn outcome_of(
    resp: actix_web::dev::ServiceResponse,
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
    seen: &GateLog,
) -> CallbackOutcome {
    let status = resp.status().as_u16();
    let sets_session = resp
        .response()
        .cookies()
        .any(|c| c.name() == "axiam_access");
    let body =
        serde_json::from_slice(&test::read_body(resp).await).unwrap_or(serde_json::Value::Null);
    CallbackOutcome {
        status,
        body,
        sets_session,
        users: count_in_tenant(
            db,
            "SELECT count() AS total FROM user \
             WHERE tenant_id = $tenant AND username != 'admin' GROUP ALL",
            tenant_id,
        )
        .await,
        federation_links: count_in_tenant(
            db,
            "SELECT count() AS total FROM federation_link WHERE tenant_id = $tenant GROUP ALL",
            tenant_id,
        )
        .await,
        post_auth_calls: post_auth_calls(seen),
    }
}

/// Which key signs the ID token the mock IdP returns.
#[derive(Clone, Copy)]
enum IdTokenSigner {
    /// The key the IdP's JWKS publishes: a genuine sign-in.
    Idp,
    /// A key the IdP never published, under the published `kid`: an ID token
    /// nobody but its forger vouches for.
    Forger,
}

/// A public OIDC sign-in — config, `/oidc/start`, the IdP's token answer,
/// `/oidc/callback` — with the tenant suspended between start and callback
/// when `suspended`.
async fn run_oidc_callback(suspended: bool, signer: IdTokenSigner) -> CallbackOutcome {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin_token = mint_token(
        &auth,
        create_admin_user(&db, tenant_id).await,
        tenant_id,
        org_id,
    );

    let idp = MockServer::start().await;
    let issuer = idp.uri();
    let keys = TestKeys::generate("mock-idp-kid");
    let client_id = "mock-idp-client";
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(keys.jwks_json()))
        .mount(&idp)
        .await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
        })))
        .mount(&idp)
        .await;
    let (gate, seen) = recording_gate();
    let app = test_app!(
        db,
        auth,
        Arc::new(JwksCache::new_allow_private_networks()),
        Some(gate)
    );

    let create_resp = test::call_service(
        &app,
        test::TestRequest::post()
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
            .to_request(),
    )
    .await;
    assert_eq!(create_resp.status().as_u16(), 201);
    let config: serde_json::Value = test::read_body_json(create_resp).await;

    let start_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/auth/federation/oidc/start")
            .set_json(json!({
                "org_id": org_id,
                "tenant_id": tenant_id,
                "federation_config_id": config["id"],
                "redirect_uri": "https://spa.example.com/callback",
            }))
            .to_request(),
    )
    .await;
    assert_eq!(start_resp.status().as_u16(), 200);
    let binding = start_resp
        .response()
        .cookies()
        .find(|c| c.name() == "axiam_fed_bind" || c.name() == "__Host-axiam_fed_bind")
        .map(|c| c.into_owned())
        .unwrap();
    let start: serde_json::Value = test::read_body_json(start_resp).await;
    let nonce = url::Url::parse(start["authorize_url"].as_str().unwrap())
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "nonce")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    let now = now_secs();
    let signing_key = match signer {
        IdTokenSigner::Idp => keys.encoding_key(),
        IdTokenSigner::Forger => TestKeys::generate("mock-idp-kid").encoding_key(),
    };
    let id_token = sign_jwt(
        &json!({
            "sub": "suspended-tenant-subject",
            "iss": issuer,
            "aud": client_id,
            "exp": now + 3600,
            "iat": now,
            "nonce": nonce,
            "email": "suspended-sso-user@example.com",
        }),
        &signing_key,
        "mock-idp-kid",
    );
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

    if suspended {
        suspend(&db, tenant_id).await;
    }

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/auth/federation/oidc/callback")
            .cookie(binding)
            .set_json(json!({ "state": start["state"], "code": "mock-authorization-code" }))
            .to_request(),
    )
    .await;
    outcome_of(resp, &db, tenant_id, &seen).await
}

/// A public social sign-in through a GitHub-shaped plain-OAuth2 provider —
/// config, `/oauth2/start`, token exchange, userinfo, `/oauth2/callback` —
/// with the tenant suspended between start and callback when `suspended`.
/// `provider_accepts_code: false` has the provider refuse the code, so the
/// callback holds no verified identity at all.
async fn run_oauth2_callback(suspended: bool, provider_accepts_code: bool) -> CallbackOutcome {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin_token = mint_token(
        &auth,
        create_admin_user(&db, tenant_id).await,
        tenant_id,
        org_id,
    );

    let idp = MockServer::start().await;
    let base = idp.uri();
    let token_answer = if provider_accepts_code {
        ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "gho_test_access_token",
            "token_type": "bearer",
            "scope": "read:user,user:email",
        }))
    } else {
        ResponseTemplate::new(400).set_body_json(json!({ "error": "bad_verification_code" }))
    };
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(token_answer)
        .mount(&idp)
        .await;
    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 583231,
            "login": "octocat",
            "name": "The Octocat",
            "email": "octocat@users.noreply.github.com",
        })))
        .mount(&idp)
        .await;
    Mock::given(method("GET"))
        .and(path("/user/emails"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"email": "octocat@users.noreply.github.com", "verified": true, "primary": true},
        ])))
        .mount(&idp)
        .await;
    let (gate, seen) = recording_gate();
    let app = test_app!(
        db,
        auth,
        Arc::new(JwksCache::new_allow_private_networks()),
        Some(gate)
    );

    let create_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/federation-configs")
            .insert_header(("Authorization", format!("Bearer {admin_token}")))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json(json!({
                "provider": "GitHub",
                "provider_kind": "github",
                "protocol": "OAuth2",
                "client_id": "gh-client",
                "client_secret": "gh-secret",
                "authorization_endpoint": format!("{base}/login/oauth/authorize"),
                "token_endpoint": format!("{base}/token"),
                "userinfo_endpoint": format!("{base}/user"),
            }))
            .to_request(),
    )
    .await;
    assert_eq!(create_resp.status().as_u16(), 201);
    let config: serde_json::Value = test::read_body_json(create_resp).await;

    let start_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/auth/federation/oauth2/start")
            .set_json(json!({
                "org_id": org_id,
                "tenant_id": tenant_id,
                "federation_config_id": config["id"],
                "redirect_uri": "https://spa.example.com/callback",
            }))
            .to_request(),
    )
    .await;
    assert_eq!(start_resp.status().as_u16(), 200);
    let binding = start_resp
        .response()
        .cookies()
        .find(|c| c.name() == "axiam_fed_bind" || c.name() == "__Host-axiam_fed_bind")
        .map(|c| c.into_owned())
        .unwrap();
    let start: serde_json::Value = test::read_body_json(start_resp).await;

    if suspended {
        suspend(&db, tenant_id).await;
    }

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/auth/federation/oauth2/callback")
            .cookie(binding)
            .set_json(json!({ "state": start["state"], "code": "provider-code" }))
            .to_request(),
    )
    .await;
    outcome_of(resp, &db, tenant_id, &seen).await
}

/// The counts below mean something only if they see what a sign-in writes:
/// on an active tenant the same two flows provision one user and one link and
/// ask the reactor once.
#[actix_rt::test]
async fn an_active_tenants_federated_sign_in_writes_what_the_counts_measure() {
    let out = run_oidc_callback(false, IdTokenSigner::Idp).await;
    assert_eq!(out.status, 200, "{}", printable(out.status, &out.body));
    assert!(out.sets_session);
    assert_eq!(
        (out.users, out.federation_links, out.post_auth_calls),
        (1, 1, 1)
    );

    let out = run_oauth2_callback(false, true).await;
    assert_eq!(out.status, 200, "{}", printable(out.status, &out.body));
    assert!(out.sets_session);
    assert_eq!(
        (out.users, out.federation_links, out.post_auth_calls),
        (1, 1, 1)
    );
}

/// An OIDC federated sign-in whose callback arrives while the tenant is
/// suspended is refused `403 tenant_suspended`, with a valid ID token from the
/// IdP, and sets no session cookie.
///
/// #877: and it writes nothing first — no user, no federation link — and does
/// not ask the `login.post_auth` reactor about a sign-in that cannot complete.
/// Before the fix the refusal came from the session step, after the user and
/// the link had been created and the reactor asked.
#[actix_rt::test]
async fn an_oidc_sign_in_to_a_suspended_tenant_is_refused() {
    let out = run_oidc_callback(true, IdTokenSigner::Idp).await;
    let body = &out.body;
    assert!(
        !out.sets_session,
        "no session cookie for a suspended tenant: {}",
        printable(out.status, body)
    );
    assert_eq!(out.status, 403, "{}", printable(out.status, body));
    assert_eq!(
        body["error"],
        "tenant_suspended",
        "{}",
        printable(out.status, body)
    );
    assert_eq!(
        out.users, 0,
        "no user may be provisioned in a suspended tenant"
    );
    assert_eq!(
        out.federation_links, 0,
        "no federation link may be written in a suspended tenant"
    );
    assert_eq!(
        out.post_auth_calls, 0,
        "the post-auth reactor must not be asked about a refused sign-in"
    );
}

/// #877, the plain-OAuth2 ("Sign in with GitHub") callback: refused
/// `403 tenant_suspended` with no user, no federation link and no reactor
/// call, however genuine the provider's answer.
#[actix_rt::test]
async fn a_social_sign_in_to_a_suspended_tenant_provisions_nothing() {
    let out = run_oauth2_callback(true, true).await;
    let body = &out.body;
    assert!(
        !out.sets_session,
        "no session cookie for a suspended tenant: {}",
        printable(out.status, body)
    );
    assert_eq!(out.status, 403, "{}", printable(out.status, body));
    assert_eq!(
        body["error"],
        "tenant_suspended",
        "{}",
        printable(out.status, body)
    );
    assert_eq!(
        out.users, 0,
        "no user may be provisioned in a suspended tenant"
    );
    assert_eq!(
        out.federation_links, 0,
        "no federation link may be written in a suspended tenant"
    );
    assert_eq!(
        out.post_auth_calls, 0,
        "the post-auth reactor must not be asked about a refused sign-in"
    );
}

/// SR1-8, kept closed by #877: the admission runs only once the provider's ID
/// token has verified. A callback carrying a forged one answers a suspended
/// tenant exactly as it answers an active one, so it cannot be used to learn
/// which tenants are suspended.
#[actix_rt::test]
async fn an_unverified_oidc_callback_answers_alike_for_a_suspended_and_an_active_tenant() {
    let active = run_oidc_callback(false, IdTokenSigner::Forger).await;
    let suspended = run_oidc_callback(true, IdTokenSigner::Forger).await;

    assert_eq!(
        active.status,
        401,
        "{}",
        printable(active.status, &active.body)
    );
    assert_ne!(
        suspended.body["error"],
        "tenant_suspended",
        "{}",
        printable(suspended.status, &suspended.body)
    );
    assert!(
        (suspended.status, &suspended.body) == (active.status, &active.body),
        "a forged ID token must get the same answer whatever the tenant's status: {} vs {}",
        printable(suspended.status, &suspended.body),
        printable(active.status, &active.body)
    );
    for out in [&active, &suspended] {
        assert!(!out.sets_session);
        assert_eq!(
            (out.users, out.federation_links, out.post_auth_calls),
            (0, 0, 0)
        );
    }
}

/// SR1-8 on the plain-OAuth2 callback: a code the provider refuses yields no
/// identity, and the answer is the same for a suspended tenant as for an
/// active one.
#[actix_rt::test]
async fn an_unverified_social_callback_answers_alike_for_a_suspended_and_an_active_tenant() {
    let active = run_oauth2_callback(false, false).await;
    let suspended = run_oauth2_callback(true, false).await;

    assert_ne!(
        active.status,
        200,
        "{}",
        printable(active.status, &active.body)
    );
    assert_ne!(
        suspended.body["error"],
        "tenant_suspended",
        "{}",
        printable(suspended.status, &suspended.body)
    );
    assert!(
        (suspended.status, &suspended.body) == (active.status, &active.body),
        "a refused code must get the same answer whatever the tenant's status: {} vs {}",
        printable(suspended.status, &suspended.body),
        printable(active.status, &active.body)
    );
    for out in [&active, &suspended] {
        assert!(!out.sets_session);
        assert_eq!(
            (out.users, out.federation_links, out.post_auth_calls),
            (0, 0, 0)
        );
    }
}
