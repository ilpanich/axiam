//! #837 and #838 — the public federated sign-in is bound to the browser that
//! started it, and a re-authentication hop is forwarded to, and verified
//! against, the upstream provider.
//!
//! Drives the real public OIDC flow (`oidc/start` → `oidc/callback`) against a
//! wiremock IdP, with the scaffolding of `federation_first_time_sso_test.rs`,
//! and the handoff redemption against rows written through the repository.
//!
//! What is pinned:
//!
//! - the start sets `__Host-axiam_fed_bind` (`HttpOnly`, `Secure`,
//!   `SameSite=Strict`, `Path=/`), and reuses a well-formed one the browser
//!   already holds, so two sign-ins in two tabs both complete;
//! - a completion with no cookie, or another browser's, is refused **before**
//!   the provider's token endpoint is called, and burns the state;
//! - an unbound row (the account-linking path's, or a pre-v114 one) is refused
//!   by the public callback and by the handoff redemption;
//! - `reauthenticate: true` adds `prompt=login` and `max_age=0` upstream, and an
//!   ID token whose `auth_time` predates the start is refused while a fresh one
//!   is accepted; an ordinary start adds neither.

use std::net::SocketAddr;
use std::sync::Arc;

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
            slug: format!("fed-bind-org-{}", Uuid::new_v4().simple()),
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
            slug: "fed-bind-tenant".into(),
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
            // Generated per run: nothing in this suite signs in with it, and a
            // literal would read as a hard-coded credential (CodeQL).
            password: format!("pw-{}", Uuid::new_v4().simple()),
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
                    ));
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

const BINDING_COOKIE: &str = "__Host-axiam_fed_bind";
/// What a browser that already started a sign-in holds.
const WELL_FORMED: &str = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdE";

struct Idp {
    server: MockServer,
    keys: TestKeys,
    client_id: &'static str,
}

impl Idp {
    async fn start() -> Self {
        let server = MockServer::start().await;
        let keys = TestKeys::generate("mock-idp-kid");
        let issuer = server.uri();
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(keys.jwks_json()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
            })))
            .mount(&server)
            .await;
        Self {
            server,
            keys,
            client_id: "mock-idp-client",
        }
    }

    /// Answer the token exchange with an ID token for `nonce`, carrying
    /// `auth_time` when given. `expect` is how many exchanges must happen.
    async fn mount_token(&self, nonce: &str, auth_time: Option<u64>, expect: u64) {
        let now = now_secs();
        let mut claims = json!({
            "sub": "fed-bind-subject",
            "iss": self.server.uri(),
            "aud": self.client_id,
            "exp": now + 3600,
            "iat": now,
            "nonce": nonce,
            "email": "fed-bind@example.com",
        });
        if let Some(t) = auth_time {
            claims["auth_time"] = json!(t);
        }
        let id_token = sign_jwt(&claims, &self.keys.encoding_key(), "mock-idp-kid");
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "mock-idp-access-token",
                "id_token": id_token,
                "token_type": "Bearer",
                "expires_in": 3600,
            })))
            .up_to_n_times(expect.max(1))
            .expect(expect)
            .mount(&self.server)
            .await;
    }
}

/// A started sign-in: what the browser holds afterwards.
struct Started {
    state: String,
    nonce: String,
    authorize_url: url::Url,
    binding: actix_web::cookie::Cookie<'static>,
}

macro_rules! fixture {
    ($db:ident, $org_id:ident, $tenant_id:ident, $auth:ident, $app:ident, $idp:ident, $config_id:ident) => {
        let ($db, $org_id, $tenant_id) = setup_db().await;
        let $auth = test_auth_config();
        let admin = create_admin_user(&$db, $tenant_id).await;
        let admin_token = mint_token(&$auth, admin, $tenant_id, $org_id);
        let $idp = Idp::start().await;
        let jwks_cache = Arc::new(JwksCache::new_allow_private_networks());
        let $app = test_app!($db, $auth, jwks_cache);
        let create = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/federation-configs")
            .insert_header(("Authorization", format!("Bearer {admin_token}")))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json(json!({
                "provider": "MockIdP",
                "protocol": "OidcConnect",
                "metadata_url": format!("{}/.well-known/openid-configuration", $idp.server.uri()),
                "client_id": $idp.client_id,
                "client_secret": "mock-idp-secret",
            }))
            .to_request();
        let resp = test::call_service(&$app, create).await;
        assert_eq!(resp.status().as_u16(), 201, "config creation");
        let body: serde_json::Value = test::read_body_json(resp).await;
        let $config_id = body["id"].as_str().unwrap().to_string();
    };
}

async fn start<S, B>(
    app: &S,
    org_id: Uuid,
    tenant_id: Uuid,
    config_id: &str,
    presented: Option<&str>,
    reauthenticate: bool,
) -> Started
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let mut body = json!({
        "org_id": org_id,
        "tenant_id": tenant_id,
        "federation_config_id": config_id,
        "redirect_uri": "https://spa.example.com/callback",
    });
    if reauthenticate {
        body["reauthenticate"] = json!(true);
    }
    let mut req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/federation/oidc/start");
    if let Some(v) = presented {
        req = req.cookie(actix_web::cookie::Cookie::new(BINDING_COOKIE, v.to_owned()));
    }
    let resp = test::call_service(app, req.set_json(body).to_request()).await;
    assert_eq!(resp.status().as_u16(), 200, "oidc/start");
    let binding = resp
        .response()
        .cookies()
        .find(|c| c.name() == BINDING_COOKIE)
        .map(|c| c.into_owned())
        .expect("oidc/start sets the browser-binding cookie");
    let body: serde_json::Value = test::read_body_json(resp).await;
    let authorize_url = url::Url::parse(body["authorize_url"].as_str().unwrap()).unwrap();
    let nonce = authorize_url
        .query_pairs()
        .find(|(k, _)| k == "nonce")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    Started {
        state: body["state"].as_str().unwrap().to_owned(),
        nonce,
        authorize_url,
        binding,
    }
}

async fn callback<S, B>(
    app: &S,
    state: &str,
    cookie: Option<actix_web::cookie::Cookie<'static>>,
) -> (u16, String)
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let mut req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/federation/oidc/callback");
    if let Some(c) = cookie {
        req = req.cookie(c);
    }
    let resp = test::call_service(
        app,
        req.set_json(json!({ "state": state, "code": "mock-authorization-code" }))
            .to_request(),
    )
    .await;
    let status = resp.status().as_u16();
    let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
    (status, body)
}

fn query_has(url: &url::Url, key: &str, value: &str) -> bool {
    url.query_pairs().any(|(k, v)| k == key && v == value)
}

// ---------------------------------------------------------------------------
// #837 — the binding cookie
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn the_start_sets_a_host_prefixed_strict_http_only_binding_cookie() {
    fixture!(_db, org_id, tenant_id, _auth, app, _idp, config_id);
    let s = start(&app, org_id, tenant_id, &config_id, None, false).await;
    let c = &s.binding;
    assert_eq!(c.name(), BINDING_COOKIE);
    assert_eq!(c.value().len(), 43, "256 bits, base64url");
    assert_eq!(c.http_only(), Some(true));
    assert_eq!(c.secure(), Some(true), "__Host- requires Secure");
    assert_eq!(c.same_site(), Some(actix_web::cookie::SameSite::Strict));
    assert_eq!(c.path(), Some("/"), "__Host- requires Path=/");
    assert_eq!(c.domain(), None, "__Host- forbids Domain");
    assert!(c.max_age().is_some());
}

/// One value per browser: two sign-ins in two tabs must both complete.
#[actix_rt::test]
async fn a_well_formed_binding_is_reused_and_a_malformed_one_replaced() {
    fixture!(_db, org_id, tenant_id, _auth, app, _idp, config_id);
    let s = start(
        &app,
        org_id,
        tenant_id,
        &config_id,
        Some(WELL_FORMED),
        false,
    )
    .await;
    assert_eq!(s.binding.value(), WELL_FORMED);

    for junk in ["short", "not base64url but 43 characters long!!!!!!"] {
        let s = start(&app, org_id, tenant_id, &config_id, Some(junk), false).await;
        assert_ne!(s.binding.value(), junk);
        assert_eq!(s.binding.value().len(), 43);
    }
}

#[actix_rt::test]
async fn two_sign_ins_in_one_browser_both_complete() {
    fixture!(_db, org_id, tenant_id, _auth, app, idp, config_id);
    let first = start(&app, org_id, tenant_id, &config_id, None, false).await;
    let second = start(
        &app,
        org_id,
        tenant_id,
        &config_id,
        Some(first.binding.value()),
        false,
    )
    .await;
    assert_eq!(first.binding.value(), second.binding.value());

    // One exchange each, answered in order.
    idp.mount_token(&first.nonce, None, 1).await;
    idp.mount_token(&second.nonce, None, 1).await;
    for s in [&first, &second] {
        let (status, body) = callback(&app, &s.state, Some(second.binding.clone())).await;
        assert_eq!(status, 200, "{body}");
    }
}

/// The login CSRF itself: the attacker's sign-in, completed in a browser that
/// holds no binding (or the victim's own), is refused before the provider's
/// token endpoint is called, and the attacker's state is spent.
#[actix_rt::test]
async fn a_callback_from_a_browser_that_did_not_start_it_is_refused_before_the_exchange() {
    fixture!(_db, org_id, tenant_id, _auth, app, idp, config_id);
    let attacker = start(&app, org_id, tenant_id, &config_id, None, false).await;
    let victim = start(&app, org_id, tenant_id, &config_id, None, false).await;
    assert_ne!(attacker.binding.value(), victim.binding.value());
    // Zero exchanges: the refusal happens first. Verified when `idp` drops.
    idp.mount_token(&attacker.nonce, None, 0).await;

    let (status, body) = callback(&app, &attacker.state, Some(victim.binding.clone())).await;
    assert_eq!(status, 401, "another browser's binding: {body}");
    assert!(body.contains("not started in this browser"), "{body}");

    // Spent: even the right browser cannot complete it now.
    let (status, _) = callback(&app, &attacker.state, Some(attacker.binding.clone())).await;
    assert_eq!(status, 401, "the state was consumed by the refused attempt");

    // And no cookie at all is the same refusal.
    let other = start(&app, org_id, tenant_id, &config_id, None, false).await;
    let (status, body) = callback(&app, &other.state, None).await;
    assert_eq!(status, 401, "{body}");
    assert!(body.contains("not started in this browser"), "{body}");
}

/// A row with no binding — the authenticated account-linking path writes one
/// under a `state` its caller chooses — must not be completable here.
#[actix_rt::test]
async fn an_unbound_login_state_row_is_refused_by_the_public_callback() {
    use axiam_core::repository::{FederationLoginState, FederationLoginStateRepository};
    use axiam_db::repository::SurrealFederationLoginStateRepository;

    fixture!(db, org_id, tenant_id, _auth, app, idp, config_id);
    idp.mount_token("unused", None, 0).await;
    SurrealFederationLoginStateRepository::new(db.clone())
        .insert(&FederationLoginState {
            state: "attacker-chosen-state".into(),
            nonce: "n".into(),
            tenant_id,
            federation_config_id: config_id.parse().unwrap(),
            redirect_uri: "https://spa.example.com/callback".into(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
            request_id: String::new(),
            code_verifier: None,
            idp_redirect_uri: None,
            browser_binding_hash: None,
            reauthenticate_after: None,
        })
        .await
        .unwrap();
    let cookie = actix_web::cookie::Cookie::new(BINDING_COOKIE, WELL_FORMED);
    let (status, body) = callback(&app, "attacker-chosen-state", Some(cookie)).await;
    assert_eq!(status, 401, "{body}");
}

/// The handoff redemption is where a cross-site return becomes a session, so
/// it is where the binding the return carried is checked.
#[actix_rt::test]
async fn the_handoff_redemption_checks_the_binding_the_return_carried() {
    use axiam_core::repository::{SSO_HANDOFF_TTL_SECS, SsoHandoffCode, SsoHandoffCodeRepository};
    use axiam_db::repository::SurrealSsoHandoffCodeRepository;
    use sha2::{Digest, Sha256};

    let (db, _org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let jwks_cache = Arc::new(JwksCache::new_allow_private_networks());
    let app = test_app!(db, auth, jwks_cache);
    let repo = SurrealSsoHandoffCodeRepository::new(db.clone());
    let digest = |v: &str| hex::encode(Sha256::digest(v.as_bytes()));

    let mint = |code: &'static str, binding: Option<String>| {
        let repo = repo.clone();
        async move {
            repo.insert(&SsoHandoffCode {
                code_hash: digest(code),
                tenant_id,
                user_id,
                redirect_uri: "https://spa.example.com/dashboard".into(),
                expires_at: chrono::Utc::now() + chrono::Duration::seconds(SSO_HANDOFF_TTL_SECS),
                authenticated_at: None,
                browser_binding_hash: binding,
            })
            .await
            .unwrap();
        }
    };
    let redeem = |code: &str, cookie: Option<&str>| {
        let mut req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/auth/federation/handoff");
        if let Some(v) = cookie {
            req = req.cookie(actix_web::cookie::Cookie::new(BINDING_COOKIE, v.to_owned()));
        }
        req.set_json(json!({ "code": code })).to_request()
    };

    mint("code-unbound", None).await;
    let r = test::call_service(&app, redeem("code-unbound", Some(WELL_FORMED))).await;
    assert_eq!(r.status().as_u16(), 401, "a row that names no browser");

    let other = "ZZZZEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdE";
    mint("code-other", Some(digest(other))).await;
    let r = test::call_service(&app, redeem("code-other", Some(WELL_FORMED))).await;
    assert_eq!(r.status().as_u16(), 401, "another browser's code");
    let r = test::call_service(&app, redeem("code-other", Some(other))).await;
    assert_eq!(r.status().as_u16(), 401, "spent by the refused attempt");

    mint("code-none", Some(digest(WELL_FORMED))).await;
    let r = test::call_service(&app, redeem("code-none", None)).await;
    assert_eq!(r.status().as_u16(), 401, "no cookie");

    mint("code-ok", Some(digest(WELL_FORMED))).await;
    let r = test::call_service(&app, redeem("code-ok", Some(WELL_FORMED))).await;
    assert_eq!(r.status().as_u16(), 200, "the browser that started it");
}

// ---------------------------------------------------------------------------
// #838 — re-authentication forwarded upstream and verified
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn reauthentication_an_ordinary_start_asks_the_provider_for_nothing_more() {
    fixture!(_db, org_id, tenant_id, _auth, app, _idp, config_id);
    let s = start(&app, org_id, tenant_id, &config_id, None, false).await;
    assert!(!s.authorize_url.query_pairs().any(|(k, _)| k == "prompt"));
    assert!(!s.authorize_url.query_pairs().any(|(k, _)| k == "max_age"));
}

#[actix_rt::test]
async fn reauthentication_is_forwarded_as_prompt_login_and_max_age_zero() {
    fixture!(_db, org_id, tenant_id, _auth, app, _idp, config_id);
    let s = start(&app, org_id, tenant_id, &config_id, None, true).await;
    assert!(
        query_has(&s.authorize_url, "prompt", "login"),
        "{}",
        s.authorize_url
    );
    assert!(
        query_has(&s.authorize_url, "max_age", "0"),
        "{}",
        s.authorize_url
    );
}

/// The provider answered from an SSO session it established an hour ago: no
/// one re-authenticated, and the sign-in is refused before a session exists.
#[actix_rt::test]
async fn reauthentication_refuses_an_auth_time_from_before_the_start() {
    fixture!(_db, org_id, tenant_id, _auth, app, idp, config_id);
    let s = start(&app, org_id, tenant_id, &config_id, None, true).await;
    idp.mount_token(&s.nonce, Some(now_secs() - 3600), 1).await;
    let (status, body) = callback(&app, &s.state, Some(s.binding.clone())).await;
    assert_eq!(status, 401, "{body}");
    assert!(
        body.contains("did not authenticate the user again"),
        "{body}"
    );
}

#[actix_rt::test]
async fn reauthentication_accepts_an_auth_time_after_the_start() {
    fixture!(_db, org_id, tenant_id, _auth, app, idp, config_id);
    let s = start(&app, org_id, tenant_id, &config_id, None, true).await;
    idp.mount_token(&s.nonce, Some(now_secs()), 1).await;
    let (status, body) = callback(&app, &s.state, Some(s.binding.clone())).await;
    assert_eq!(status, 200, "{body}");
}

/// The same stale instant on an ordinary sign-in is no reason to refuse:
/// nothing asked for freshness, and the session is dated truthfully.
#[actix_rt::test]
async fn reauthentication_an_old_auth_time_on_an_ordinary_sign_in_is_accepted() {
    fixture!(_db, org_id, tenant_id, _auth, app, idp, config_id);
    let s = start(&app, org_id, tenant_id, &config_id, None, false).await;
    idp.mount_token(&s.nonce, Some(now_secs() - 3600), 1).await;
    let (status, body) = callback(&app, &s.state, Some(s.binding.clone())).await;
    assert_eq!(status, 200, "{body}");
}
