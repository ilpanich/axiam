//! G-A (W2.3) — native sign-in with a provider ID token, end to end through
//! the real token endpoint.
//!
//! What only exists once the grant is mounted: that an ID token a federation
//! provider issued to a *native app* — signed by the provider's key, served
//! from its JWKS — buys the client's ordinary sign-in token set, that the
//! token set behaves as every other sign-in's does (UserInfo, refresh
//! rotation, client binding, DPoP), and that every refusal is the one answer
//! the design promises. The verification rules themselves are proved one by
//! one in `axiam-federation`'s `native_login` tests; the gate, scope and
//! consent decisions in `axiam-oauth2`'s `provider_id_token` tests. This file
//! is about the seam.
//!
//! # The stub IdP
//!
//! Ed25519, served over loopback by wiremock — the harness X4's
//! `external_token_exchange_test.rs` uses, with the SSRF guard's
//! `allow_private_networks` seam so discovery and the JWKS fetch can reach it.

use std::net::SocketAddr;
use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::state::AppState;
use axiam_api_rest::{
    RateLimitConfig, RouteOptions, SessionValidator, register_api_v1_routes_with,
};
use axiam_auth::config::AuthConfig;
use axiam_core::models::audit::AuditLogEntry;
use axiam_core::models::federation::{
    CreateFederationConfig, FederationProtocol, NativeLoginTrust, ProviderKind,
};
use axiam_core::models::oauth2_client::{
    AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateOAuth2Client, ManagedBy,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::reactor::{DynReactorGate, ReactorOutcome, SharedReactorGate};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, FederationConfigRepository, OAuth2ClientRepository,
    OrganizationRepository, Pagination, TenantRepository,
};
use axiam_db::repository::{
    SurrealFederationConfigRepository, SurrealOAuth2ClientRepository,
    SurrealOrganizationRepository, SurrealSessionRepository, SurrealTenantRepository,
};
use axiam_federation::jwks_cache::JwksCache;
use axiam_federation::oidc::OidcFederationService;
use axiam_oauth2::provider_id_token::{
    NATIVE_LOGIN_AUDIT_ACTION, PROVIDER_ID_TOKEN_GRANT_TYPE, PUBLIC_REFUSAL_DESCRIPTION,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:34611";
/// Test-only AES-256-GCM key (32 bytes of 0x2b) — not a secret. gitleaks:allow
const TEST_FED_ENC_KEY: [u8; 32] = [0x2b; 32];
const ISSUER: &str = "https://id.test.example";
const KID: &str = "idp-key-1";
/// The native app's client ID at the provider — the only audience listed.
const IOS: &str = "com.example.ios";
/// The provider's web client ID: configured, but not listed for native use.
const WEB: &str = "web-client";
const SLUG: &str = "acme";
const OFF_SLUG: &str = "acme-browser-only";

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn test_auth_config(tenant_issuer_paths: bool) -> AuthConfig {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519");
    AuthConfig {
        jwt_private_key_pem: kp.serialize_pem(),
        jwt_public_key_pem: kp.public_key_pem(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: ISSUER.into(),
        sso_spa_origins: Vec::new(),
        federation_encryption_key: Some(TEST_FED_ENC_KEY),
        tenant_issuer_paths,
        ..AuthConfig::default()
    }
}

// ---------------------------------------------------------------------------
// The stub IdP and its keys
// ---------------------------------------------------------------------------

/// An Ed25519 keypair, as an encoding key and its public JWK.
struct Ed25519Key {
    encoding: EncodingKey,
    jwk: Value,
}

impl Ed25519Key {
    fn generate(kid: Option<&str>) -> Self {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519");
        let encoding = EncodingKey::from_ed_pem(kp.serialize_pem().as_bytes()).expect("key");
        let raw = kp.public_key_raw();
        let x = URL_SAFE_NO_PAD.encode(&raw[raw.len() - 32..]);
        let mut jwk = json!({ "kty": "OKP", "crv": "Ed25519", "x": x });
        if let Some(kid) = kid {
            jwk["kid"] = json!(kid);
            jwk["use"] = json!("sig");
        }
        Self { encoding, jwk }
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    db: Surreal<TestDb>,
    tenant_id: Uuid,
    provider_id: Uuid,
    issuer: String,
    key: Ed25519Key,
    /// Kept alive for the test and never dropped. `MockServer`'s `Drop`
    /// verifies expectations by blocking on the server's state, and on the
    /// single-threaded actix test runtime, with the federation HTTP client
    /// still holding a pooled connection to it, that wait can deadlock the
    /// test at teardown. Nothing here sets an expectation, so nothing is lost.
    _idp: std::mem::ManuallyDrop<MockServer>,
}

async fn setup() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let key = Ed25519Key::generate(Some(KID));
    let idp = MockServer::start().await;
    let issuer = idp.uri();
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
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [key.jwk] })))
        .mount(&idp)
        .await;

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "G-A Org".into(),
            slug: format!("org-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "G-A Tenant".into(),
            slug: "tenant-ga".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let provider = |slug: &str, native_enabled: bool| CreateFederationConfig {
        tenant_id: tenant.id,
        provider: format!("Acme ({slug})"),
        protocol: FederationProtocol::OidcConnect,
        metadata_url: Some(format!("{issuer}/.well-known/openid-configuration")),
        client_id: WEB.into(),
        client_secret: "web-secret".into(),
        attribute_map: None,
        idp_signing_cert_pem: None,
        allowed_algorithms: Some(vec!["EdDSA".into()]),
        native_login: Some(NativeLoginTrust {
            enabled: native_enabled,
            client_ids: vec![IOS.into()],
            max_token_age_secs: 300,
        }),
        token_exchange: None,
        provider_kind: Some(ProviderKind::GenericOidc),
        provider_slug: Some(slug.into()),
        allow_tenant_inheritance: None,
        scopes: None,
        authorization_endpoint: None,
        token_endpoint: None,
        userinfo_endpoint: None,
        allowed_issuer_tenants: None,
        apple_team_id: None,
        apple_key_id: None,
        require_pkce: None,
        button_icon: None,
        allow_sha1_signatures: None,
        idp_metadata_signing_cert_pem: None,
    };
    let configs = SurrealFederationConfigRepository::new(db.clone());
    let enabled = configs.create(provider(SLUG, true)).await.unwrap();
    configs.create(provider(OFF_SLUG, false)).await.unwrap();

    Fixture {
        db,
        tenant_id: tenant.id,
        provider_id: enabled.id,
        issuer,
        key,
        _idp: std::mem::ManuallyDrop::new(idp),
    }
}

/// Register an OAuth2 client; `tweak` adjusts the registration first.
async fn client(
    f: &Fixture,
    name: &str,
    method: ClientAuthMethod,
    grant_types: &[&str],
    tweak: impl FnOnce(&mut CreateOAuth2Client),
) -> (String, String) {
    let mut c = CreateOAuth2Client {
        tenant_id: f.tenant_id,
        name: name.into(),
        redirect_uris: vec!["com.example.ios:/callback".into()],
        grant_types: grant_types.iter().map(|g| (*g).to_owned()).collect(),
        scopes: vec!["openid".into(), "profile".into(), "email".into()],
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        require_par: false,
        profile: ClientProfile::Standard,
        token_endpoint_auth_method: method,
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
    };
    tweak(&mut c);
    let (row, secret) = SurrealOAuth2ClientRepository::new(f.db.clone())
        .create(c)
        .await
        .unwrap();
    (row.client_id, secret)
}

/// A public native client holding the grant and `refresh_token`.
async fn native_client(f: &Fixture, name: &str) -> String {
    client(
        f,
        name,
        ClientAuthMethod::None,
        &[PROVIDER_ID_TOKEN_GRANT_TYPE, "refresh_token"],
        |_| {},
    )
    .await
    .0
}

/// Build the app as production composes it: the OIDC federation service
/// installed, a session validator registered (so UserInfo checks `sid`), the
/// grant's bucket at `$login` per minute.
macro_rules! test_app {
    ($f:expr) => {
        test_app!($f, 19, false)
    };
    ($f:expr, $login:expr, $paths:expr) => {
        test_app!(@build $f, $login, $paths, None)
    };
    // F4-W2-01: with a reactor gate installed as the composition root
    // installs it — on `AuthService` and on the token service.
    (@gate $f:expr, $gate:expr) => {
        test_app!(@build $f, 19, false, Some($gate))
    };
    (@build $f:expr, $login:expr, $paths:expr, $gate:expr) => {{
        let auth = test_auth_config($paths);
        let jwks_cache = Arc::new(JwksCache::new_allow_private_networks());
        let mut state = AppState::for_test($f.db.clone(), auth.clone());
        state.http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        state.jwks_cache = Arc::clone(&jwks_cache);
        state.federation.oidc_federation_service = Some(OidcFederationService::new(
            state.federation.federation_config_repo.clone(),
            state.federation.federation_link_repo.clone(),
            state.user_repo.clone(),
            state.http_client.clone(),
            Arc::clone(&state.jwks_cache),
            TEST_FED_ENC_KEY,
        ));
        // X4 on as well, as production composes it, so the exchange's own
        // refusal of an ID token is what the invariant test below sees.
        assert!(state.enable_external_token_exchange());
        // Below the counter's cold-entry threshold (20), so a test's budget
        // does not depend on where in the wall-clock minute it runs.
        state.rate_limit_cfg.login_per_min = $login;
        let gate: Option<SharedReactorGate> = $gate;
        if let Some(gate) = gate {
            state.auth_service = state.auth_service.clone().with_reactor_gate(gate.clone());
            state.oauth2.token_service = state
                .oauth2
                .token_service
                .clone()
                .with_reactor_gate(gate.clone());
            state.events.reactor_gate = gate;
        }
        let sessions = Arc::new(SurrealSessionRepository::new($f.db.clone()));
        test::init_service(
            App::new()
                .app_data(web::Data::new(auth.clone()))
                .app_data(web::Data::new(state))
                .app_data(web::Data::new(sessions as Arc<dyn SessionValidator>))
                .app_data(web::Data::new(
                    Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
                ))
                .configure(|cfg| {
                    register_api_v1_routes_with::<TestDb>(
                        cfg,
                        &RateLimitConfig::default(),
                        RouteOptions {
                            tenant_issuer_paths: $paths,
                            ..RouteOptions::default()
                        },
                    )
                }),
        )
        .await
    }};
}

/// POST a form to `$uri`; returns `(status, json)`.
macro_rules! post {
    ($app:expr, $uri:expr, $body:expr, [$($header:expr),* $(,)?]) => {{
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&$uri)
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            $(.insert_header($header))*
            .set_payload($body.to_string())
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let body = test::read_body(resp).await;
        (status, serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null))
    }};
}

macro_rules! token_endpoint {
    ($app:expr, $f:expr, $body:expr) => {
        post!($app, format!("/oauth2/token?tenant_id={}", $f.tenant_id), $body, [])
    };
    ($app:expr, $f:expr, $body:expr, [$($header:expr),*]) => {
        post!(
            $app,
            format!("/oauth2/token?tenant_id={}", $f.tenant_id),
            $body,
            [$($header),*]
        )
    };
}

fn enc(s: &str) -> String {
    s.replace('%', "%25")
        .replace(':', "%3A")
        .replace('/', "%2F")
        .replace(' ', "%20")
        .replace('+', "%2B")
        .replace('=', "%3D")
        .replace('&', "%26")
}

/// The lower-case SHA-256 hex the app hands the provider's SDK (D-N16).
fn sha256_hex(raw: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(raw.as_bytes()))
}

/// A provider ID token for the native app, bound to the raw `nonce` the way
/// D-N16 requires — its `nonce` claim is the SHA-256 hex of it; `patch`
/// overrides claims (`null` removes one).
fn id_token(f: &Fixture, nonce: &str, sub: &str, patch: Value) -> String {
    let mut claims = json!({
        "iss": f.issuer,
        "aud": IOS,
        "sub": sub,
        "iat": now(),
        "exp": now() + 600,
        "nonce": sha256_hex(nonce),
        "email": format!("{sub}@example.com"),
        "email_verified": true,
        "name": "Ada Lovelace",
    });
    for (k, v) in patch.as_object().unwrap() {
        if v.is_null() {
            claims.as_object_mut().unwrap().remove(k);
        } else {
            claims[k] = v.clone();
        }
    }
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(KID.into());
    encode(&header, &claims, &f.key.encoding).expect("sign")
}

/// The grant's form body.
fn grant_body(client_id: &str, provider: &str, token: &str, nonce: &str, scope: &str) -> String {
    let mut body = format!(
        "grant_type={}&client_id={}&provider={}&id_token={token}&nonce={}",
        enc(PROVIDER_ID_TOKEN_GRANT_TYPE),
        enc(client_id),
        enc(provider),
        enc(nonce),
    );
    if !scope.is_empty() {
        body.push_str(&format!("&scope={}", enc(scope)));
    }
    body
}

fn claims_of(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("three parts");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("b64")).expect("json")
}

async fn native_login_rows(f: &Fixture) -> Vec<AuditLogEntry> {
    audit_rows(f, NATIVE_LOGIN_AUDIT_ACTION).await
}

async fn audit_rows(f: &Fixture, action: &str) -> Vec<AuditLogEntry> {
    let mut rows = axiam_db::SurrealAuditLogRepository::new(f.db.clone())
        .list(
            f.tenant_id,
            AuditLogFilter {
                action: Some(action.into()),
                ..Default::default()
            },
            Pagination::default(),
        )
        .await
        .unwrap()
        .items;
    rows.sort_by_key(|r| r.timestamp);
    rows
}

fn reason_codes(rows: &[AuditLogEntry]) -> Vec<String> {
    rows.iter()
        .map(|r| r.metadata["reason_code"].as_str().unwrap().to_owned())
        .collect()
}

fn assert_generic_invalid_grant(status: u16, body: &Value, case: &str) {
    assert_eq!(status, 400, "{case}: {body}");
    assert_eq!(body["error"], "invalid_grant", "{case}: {body}");
    assert_eq!(
        body["error_description"], PUBLIC_REFUSAL_DESCRIPTION,
        "{case}: the description must not say which check failed"
    );
}

// ===========================================================================
// The happy path
// ===========================================================================

/// A public client signs in: the token set is the code flow's — an access
/// token naming the client and a live session, a refresh token, and an AXIAM
/// ID token carrying the request's nonce. UserInfo admits the access token;
/// the refresh token rotates and stays bound to its client.
#[actix_web::test]
async fn a_public_client_signs_in_with_a_provider_id_token() {
    let f = setup().await;
    let app = test_app!(f);
    let app_client = native_client(&f, "ios-app").await;
    let other_client = native_client(&f, "another-app").await;

    let nonce = "n-0S6_WzA2Mj-ios";
    let token = id_token(&f, nonce, "ada", json!({}));
    let (status, body) = token_endpoint!(
        app,
        f,
        grant_body(&app_client, SLUG, &token, nonce, "openid profile")
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["scope"], "openid profile");
    assert_eq!(body["expires_in"], 900);

    let access = claims_of(body["access_token"].as_str().unwrap());
    assert_eq!(access["client_id"], app_client.as_str());
    assert_eq!(access["aud"], "axiam:user");
    assert_eq!(access["tenant_id"], f.tenant_id.to_string());
    let user_id = access["sub"].as_str().unwrap().to_owned();
    let sid = access["sid"].as_str().expect("the token names its session");
    assert_ne!(sid, access["jti"].as_str().unwrap());
    assert!(access.get("cnf").is_none());

    let id = claims_of(body["id_token"].as_str().expect("openid was granted"));
    assert_eq!(id["nonce"], nonce, "the app's own nonce comes back");
    assert_eq!(id["aud"], app_client.as_str());
    assert_eq!(id["sub"], user_id.as_str());
    assert_eq!(id["iss"], ISSUER);
    assert_eq!(id["sid"], sid);

    // UserInfo admits it: the session it names is live.
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/oauth2/userinfo")
        .insert_header((
            "Authorization",
            format!("Bearer {}", body["access_token"].as_str().unwrap()),
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let info: Value = test::read_body_json(resp).await;
    assert_eq!(info["sub"], user_id.as_str());

    // The refresh token rotates under the ordinary refresh grant…
    let refresh = body["refresh_token"].as_str().expect("refresh_token held");
    let (status, rotated) = token_endpoint!(
        app,
        f,
        format!(
            "grant_type=refresh_token&client_id={}&refresh_token={}",
            enc(&app_client),
            enc(refresh)
        )
    );
    assert_eq!(status, 200, "{rotated}");
    let next = rotated["refresh_token"].as_str().unwrap();
    assert_ne!(next, refresh, "rotation issues a new refresh token");
    assert_eq!(
        claims_of(rotated["access_token"].as_str().unwrap())["sid"],
        sid,
        "the rotated grant keeps the session"
    );
    let refreshed_id = claims_of(rotated["id_token"].as_str().unwrap());
    assert_eq!(refreshed_id["sub"], user_id.as_str());

    // …is single-use…
    let (status, replayed) = token_endpoint!(
        app,
        f,
        format!(
            "grant_type=refresh_token&client_id={}&refresh_token={}",
            enc(&app_client),
            enc(refresh)
        )
    );
    assert_eq!(
        (status, replayed["error"].as_str()),
        (400, Some("invalid_grant"))
    );

    // …and bound to the client it was issued to.
    let (status, stolen) = token_endpoint!(
        app,
        f,
        format!(
            "grant_type=refresh_token&client_id={}&refresh_token={}",
            enc(&other_client),
            enc(next)
        )
    );
    assert_eq!(
        (status, stolen["error"].as_str()),
        (400, Some("invalid_grant"))
    );
}

/// Without `openid` there is no ID token, and a client that does not hold
/// `refresh_token` gets no refresh token — the code flow's rules.
#[actix_web::test]
async fn the_token_set_follows_the_registration_and_the_request() {
    let f = setup().await;
    let app = test_app!(f);
    let (bare, _) = client(
        &f,
        "no-refresh",
        ClientAuthMethod::None,
        &[PROVIDER_ID_TOKEN_GRANT_TYPE],
        |_| {},
    )
    .await;

    let token = id_token(&f, "nonce-a", "grace", json!({}));
    let (status, body) = token_endpoint!(
        app,
        f,
        grant_body(&bare, SLUG, &token, "nonce-a", "profile")
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["scope"], "profile");
    assert!(body.get("id_token").is_none(), "no openid, no ID token");
    assert!(
        body.get("refresh_token").is_none(),
        "no refresh_token grant"
    );

    // A scope outside the registration is refused by name, before the token
    // is spent: the same token then signs in.
    let token = id_token(&f, "nonce-b", "grace", json!({}));
    let (status, body) = token_endpoint!(
        app,
        f,
        grant_body(&bare, SLUG, &token, "nonce-b", "openid admin")
    );
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_scope"))
    );
    let (status, body) =
        token_endpoint!(app, f, grant_body(&bare, SLUG, &token, "nonce-b", "openid"));
    assert_eq!(status, 200, "{body}");
}

/// D-N16 (Apple's documented pattern, and the only one accepted): the
/// provider signs the SHA-256 hex of the raw nonce, and the app presents the
/// raw one — which is what comes back.
#[actix_web::test]
async fn the_hashed_nonce_pattern_signs_in_and_returns_the_raw_nonce() {
    let f = setup().await;
    let app = test_app!(f);
    let app_client = native_client(&f, "apple-style").await;

    let raw = "raw-nonce-from-the-app";
    let token = id_token(&f, raw, "tim", json!({}));
    assert_eq!(claims_of(&token)["nonce"], sha256_hex(raw));
    let (status, body) =
        token_endpoint!(app, f, grant_body(&app_client, SLUG, &token, raw, "openid"));
    assert_eq!(status, 200, "{body}");
    assert_eq!(claims_of(body["id_token"].as_str().unwrap())["nonce"], raw);
}

/// F4-W2-02: the nonce a token carries is never the value to present. A
/// token whose claim equals the request's nonce (the old raw form) is
/// refused; a leaked token presented with its own claim copied into `nonce`
/// is refused — and neither attempt spends the token, so the app holding the
/// raw nonce still signs in with it.
#[actix_web::test]
async fn a_raw_or_copied_nonce_is_refused_and_does_not_spend_the_token() {
    let f = setup().await;
    let app = test_app!(f);
    let app_client = native_client(&f, "ios-app").await;

    // The raw form.
    let raw = "raw-form-nonce";
    let token = id_token(&f, raw, "ada", json!({ "nonce": raw }));
    let (status, body) =
        token_endpoint!(app, f, grant_body(&app_client, SLUG, &token, raw, "openid"));
    assert_generic_invalid_grant(status, &body, "raw form");

    // The copied claim.
    let raw = "the-apps-own-nonce";
    let token = id_token(&f, raw, "ada", json!({}));
    let copied = claims_of(&token)["nonce"].as_str().unwrap().to_owned();
    let (status, body) = token_endpoint!(
        app,
        f,
        grant_body(&app_client, SLUG, &token, &copied, "openid")
    );
    assert_generic_invalid_grant(status, &body, "copied claim");

    let (status, body) =
        token_endpoint!(app, f, grant_body(&app_client, SLUG, &token, raw, "openid"));
    assert_eq!(status, 200, "the token was not spent: {body}");
    assert_eq!(
        reason_codes(&native_login_rows(&f).await),
        ["nonce_mismatch", "nonce_mismatch", "accepted"]
    );
}

/// The first sign-in provisions the user; the next one, with another token
/// for the same provider subject, resolves the same user. Both are audited,
/// and the record says which one created the account.
#[actix_web::test]
async fn the_first_sign_in_provisions_and_the_next_resolves_the_same_user() {
    let f = setup().await;
    let app = test_app!(f);
    let app_client = native_client(&f, "ios-app").await;

    let mut users = Vec::new();
    for nonce in ["first-nonce", "second-nonce"] {
        let token = id_token(&f, nonce, "linus", json!({}));
        let (status, body) = token_endpoint!(
            app,
            f,
            grant_body(&app_client, SLUG, &token, nonce, "openid")
        );
        assert_eq!(status, 200, "{body}");
        users.push(claims_of(body["access_token"].as_str().unwrap())["sub"].clone());
    }
    assert_eq!(users[0], users[1], "one provider subject is one AXIAM user");

    let rows = native_login_rows(&f).await;
    assert_eq!(rows.len(), 2);
    let provisioned: Vec<bool> = rows
        .iter()
        .map(|r| r.metadata["newly_provisioned"].as_bool().unwrap())
        .collect();
    assert_eq!(provisioned, [true, false]);
    for row in &rows {
        assert_eq!(
            row.outcome,
            axiam_core::models::audit::AuditOutcome::Success
        );
        assert_eq!(row.actor_id.to_string(), users[0].as_str().unwrap());
        assert_eq!(row.resource_id, Some(f.provider_id));
        let meta = &row.metadata;
        assert_eq!(meta["client_id"], app_client.as_str());
        assert_eq!(meta["provider"], f.provider_id.to_string());
        assert_eq!(meta["reason_code"], "accepted");
    }
}

/// The record names the sign-in — client, provider, outcome — and never the
/// token or the nonce, on success or on refusal.
#[actix_web::test]
async fn the_audit_record_never_carries_the_token_or_the_nonce() {
    let f = setup().await;
    let app = test_app!(f);
    let app_client = native_client(&f, "ios-app").await;

    let nonce = "a-very-distinctive-nonce-value";
    let token = id_token(&f, nonce, "ken", json!({}));
    let (status, _) = token_endpoint!(
        app,
        f,
        grant_body(&app_client, SLUG, &token, nonce, "openid")
    );
    assert_eq!(status, 200);
    // And a refusal (the same token, replayed).
    let (status, _) = token_endpoint!(
        app,
        f,
        grant_body(&app_client, SLUG, &token, nonce, "openid")
    );
    assert_eq!(status, 400);

    let rows = native_login_rows(&f).await;
    assert_eq!(reason_codes(&rows), ["accepted", "replayed"]);
    let signature = token.rsplit('.').next().unwrap();
    for row in &rows {
        let text = serde_json::to_string(row).unwrap();
        assert!(!text.contains(&token), "the token reached the audit log");
        assert!(
            !text.contains(signature),
            "part of the token reached the audit log"
        );
        assert!(!text.contains(nonce), "the nonce reached the audit log");
        assert_eq!(row.ip_address.as_deref(), Some("127.0.0.1"));
    }
}

// ===========================================================================
// Step 1 — the gate
// ===========================================================================

/// A client whose registration does not list the grant is
/// `unauthorized_client`, and the token it carried is not spent: the same
/// token then signs in through a client that holds the grant.
#[actix_web::test]
async fn a_client_not_registered_for_the_grant_is_unauthorized_client() {
    let f = setup().await;
    let app = test_app!(f);
    let (web_app, _) = client(
        &f,
        "web-app",
        ClientAuthMethod::None,
        &["authorization_code", "refresh_token"],
        |_| {},
    )
    .await;
    let app_client = native_client(&f, "ios-app").await;

    let token = id_token(&f, "nonce-1", "ada", json!({}));
    let (status, body) = token_endpoint!(
        app,
        f,
        grant_body(&web_app, SLUG, &token, "nonce-1", "openid")
    );
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("unauthorized_client"))
    );
    assert!(
        native_login_rows(&f).await.is_empty(),
        "nothing reached the grant"
    );

    let (status, body) = token_endpoint!(
        app,
        f,
        grant_body(&app_client, SLUG, &token, "nonce-1", "openid")
    );
    assert_eq!(
        status, 200,
        "the refused request did not spend the token: {body}"
    );
}

/// A confidential client authenticates as at every other grant; a wrong or
/// missing secret is `invalid_client`, recorded as a client-authentication
/// failure naming this grant.
#[actix_web::test]
async fn a_confidential_client_authenticates_by_its_registered_method() {
    let f = setup().await;
    let app = test_app!(f);
    let (confidential, secret) = client(
        &f,
        "backend-for-frontend",
        ClientAuthMethod::ClientSecretPost,
        &[PROVIDER_ID_TOKEN_GRANT_TYPE],
        |_| {},
    )
    .await;

    let token = id_token(&f, "nonce-c", "ada", json!({}));
    let base = grant_body(&confidential, SLUG, &token, "nonce-c", "openid");
    for body in [format!("{base}&client_secret=wrong"), base.clone()] {
        let (status, refused) = token_endpoint!(app, f, body);
        assert_eq!(
            (status, refused["error"].as_str()),
            (401, Some("invalid_client"))
        );
    }
    // The failure audit is written off the response path (§22.3 residual 1).
    let mut failures = Vec::new();
    for _ in 0..100 {
        failures = audit_rows(&f, "oauth2.client_auth_failed").await;
        if failures.len() == 2 {
            break;
        }
        actix_web::rt::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(failures.len(), 2);
    for row in &failures {
        assert_eq!(row.metadata["grant_type"], PROVIDER_ID_TOKEN_GRANT_TYPE);
        assert_eq!(row.metadata["client_id"], confidential.as_str());
    }
    assert!(
        native_login_rows(&f).await.is_empty(),
        "nothing reached the grant"
    );

    let (status, body) = token_endpoint!(app, f, format!("{base}&client_secret={secret}"));
    assert_eq!(status, 200, "the refusals did not spend the token: {body}");
}

/// The three grant parameters are required by name, before anything is read.
#[actix_web::test]
async fn a_missing_parameter_is_invalid_request() {
    let f = setup().await;
    let app = test_app!(f);
    let app_client = native_client(&f, "ios-app").await;
    let token = id_token(&f, "nonce", "ada", json!({}));
    for (name, body) in [
        (
            "provider",
            format!(
                "grant_type={}&client_id={}&id_token={token}&nonce=nonce",
                enc(PROVIDER_ID_TOKEN_GRANT_TYPE),
                enc(&app_client)
            ),
        ),
        (
            "id_token",
            format!(
                "grant_type={}&client_id={}&provider={SLUG}&nonce=nonce",
                enc(PROVIDER_ID_TOKEN_GRANT_TYPE),
                enc(&app_client)
            ),
        ),
        (
            "nonce",
            format!(
                "grant_type={}&client_id={}&provider={SLUG}&id_token={token}",
                enc(PROVIDER_ID_TOKEN_GRANT_TYPE),
                enc(&app_client)
            ),
        ),
    ] {
        let (status, body) = token_endpoint!(app, f, body);
        assert_eq!(
            (status, body["error"].as_str()),
            (400, Some("invalid_request")),
            "{name}"
        );
        assert!(
            body["error_description"].as_str().unwrap().contains(name),
            "{name}: {body}"
        );
    }
}

// ===========================================================================
// Steps 2–7 — one answer for every refusal
// ===========================================================================

/// A provider that is not enabled for native sign-in, one that does not
/// exist, a token issued to the web client, a token bound to another nonce,
/// and a token presented twice: one `invalid_grant`, one description. The
/// audit record keeps the distinction.
#[actix_web::test]
async fn every_refusal_past_the_provider_is_one_generic_invalid_grant() {
    let f = setup().await;
    let app = test_app!(f);
    let app_client = native_client(&f, "ios-app").await;

    let good = |nonce: &str| id_token(&f, nonce, "ada", json!({}));

    let (status, body) = token_endpoint!(
        app,
        f,
        grant_body(&app_client, OFF_SLUG, &good("n1"), "n1", "openid")
    );
    assert_generic_invalid_grant(status, &body, "native sign-in off");

    let (status, body) = token_endpoint!(
        app,
        f,
        grant_body(&app_client, "no-such-provider", &good("n2"), "n2", "openid")
    );
    assert_generic_invalid_grant(status, &body, "unknown provider");

    let web_token = id_token(&f, "n3", "ada", json!({ "aud": WEB }));
    let (status, body) = token_endpoint!(
        app,
        f,
        grant_body(&app_client, SLUG, &web_token, "n3", "openid")
    );
    assert_generic_invalid_grant(status, &body, "issued to the web client");

    let (status, body) = token_endpoint!(
        app,
        f,
        grant_body(&app_client, SLUG, &good("n4"), "another-nonce", "openid")
    );
    assert_generic_invalid_grant(status, &body, "nonce mismatch");

    let once = good("n5");
    let (status, body) =
        token_endpoint!(app, f, grant_body(&app_client, SLUG, &once, "n5", "openid"));
    assert_eq!(status, 200, "{body}");
    let (status, body) =
        token_endpoint!(app, f, grant_body(&app_client, SLUG, &once, "n5", "openid"));
    assert_generic_invalid_grant(status, &body, "replayed");

    let rows = native_login_rows(&f).await;
    assert_eq!(
        reason_codes(&rows),
        [
            "provider_not_found",
            "provider_not_found",
            "wrong_audience",
            "nonce_mismatch",
            "accepted",
            "replayed",
        ]
    );
    let refused = &rows[0];
    assert_eq!(
        refused.outcome,
        axiam_core::models::audit::AuditOutcome::Failure
    );
    assert_eq!(refused.actor_id, Uuid::nil());
    assert_eq!(refused.resource_id, None);
    assert_eq!(
        refused.metadata["provider"], OFF_SLUG,
        "until a provider resolves, the record names what the request asked for"
    );
}

/// X4's invariant from the other side: the token exchange keeps refusing an
/// ID token, so this grant is the only way one becomes a sign-in.
#[actix_web::test]
async fn the_token_exchange_still_refuses_the_same_id_token() {
    let f = setup().await;
    let app = test_app!(f);
    let (exchanger, secret) = client(
        &f,
        "exchanger",
        ClientAuthMethod::ClientSecretPost,
        &[axiam_oauth2::token_exchange::TOKEN_EXCHANGE_GRANT_TYPE],
        |_| {},
    )
    .await;
    let token = id_token(&f, "nonce-x4", "ada", json!({}));
    let exchange = |token_type: &str| {
        format!(
            "grant_type={}&client_id={}&client_secret={secret}&subject_token={token}\
             &subject_token_type={}",
            enc(axiam_oauth2::token_exchange::TOKEN_EXCHANGE_GRANT_TYPE),
            enc(&exchanger),
            enc(token_type),
        )
    };
    let (status, body) = token_endpoint!(
        app,
        f,
        exchange(axiam_oauth2::token_exchange::TOKEN_TYPE_ID_TOKEN)
    );
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_request"))
    );
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .starts_with("an ID token asserts a login"),
        "{body}"
    );
    let (status, body) = token_endpoint!(
        app,
        f,
        exchange(axiam_oauth2::token_exchange::TOKEN_TYPE_JWT)
    );
    assert_ne!(
        status, 200,
        "an ID token labelled jwt is still refused: {body}"
    );
}

// ===========================================================================
// The `login.post_auth` gate (F4-W2-01, #828)
// ===========================================================================

/// A reactor gate with one fixed answer that records what it was asked — the
/// SEC-095 tests' double: what is under test is the call site.
struct FixedGate {
    outcome: ReactorOutcome,
    seen: Arc<std::sync::Mutex<Vec<(&'static str, Value)>>>,
}

impl DynReactorGate for FixedGate {
    fn intercept_dyn<'a>(
        &'a self,
        _tenant_id: Uuid,
        event: &'static str,
        payload: Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ReactorOutcome> + Send + 'a>> {
        self.seen.lock().unwrap().push((event, payload));
        Box::pin(std::future::ready(self.outcome.clone()))
    }

    fn can_dispatch_dyn(&self) -> bool {
        true
    }
}

type GateLog = Arc<std::sync::Mutex<Vec<(&'static str, Value)>>>;

fn gate(outcome: ReactorOutcome) -> (SharedReactorGate, GateLog) {
    let seen: GateLog = Arc::default();
    (
        Arc::new(FixedGate {
            outcome,
            seen: Arc::clone(&seen),
        }),
        seen,
    )
}

fn login_post_auth_calls(seen: &GateLog) -> Vec<Value> {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|(event, _)| *event == "login.post_auth")
        .map(|(_, payload)| payload.clone())
        .collect()
}

async fn session_rows(f: &Fixture) -> usize {
    let mut r = f.db.query("SELECT * FROM session").await.unwrap();
    let rows: Vec<Value> = r.take(0).unwrap();
    rows.len()
}

/// CONTRACT §22: `login.post_auth` covers every interactive sign-in. A
/// reactor that vetoes it — the embargoed-region example — refuses the native
/// grant as it refuses the password, SAML, OIDC and passkey sign-ins: the
/// generic `invalid_grant`, no token, no session, and an audit row saying why.
/// A `require_mfa` the grant cannot honour is refused the same way.
#[actix_web::test]
async fn a_login_post_auth_veto_refuses_the_native_grant() {
    for (case, outcome) in [
        (
            "deny",
            ReactorOutcome::Deny {
                reason: "login from an embargoed region".into(),
            },
        ),
        ("require_mfa", ReactorOutcome::RequireMfa),
    ] {
        let f = setup().await;
        let (gate, seen) = gate(outcome);
        let app = test_app!(@gate f, gate);
        let app_client = native_client(&f, "ios-app").await;

        let nonce = "nonce-vetoed";
        let token = id_token(&f, nonce, "ada", json!({}));
        let (status, body) = token_endpoint!(
            app,
            f,
            grant_body(&app_client, SLUG, &token, nonce, "openid")
        );
        assert_generic_invalid_grant(status, &body, case);
        assert!(body.get("access_token").is_none(), "{case}");
        assert!(body.get("refresh_token").is_none(), "{case}");
        assert_eq!(session_rows(&f).await, 0, "{case}: no session was created");

        let calls = login_post_auth_calls(&seen);
        assert_eq!(calls.len(), 1, "{case}: the gate was asked once");
        assert_eq!(calls[0]["tenant_id"], f.tenant_id.to_string(), "{case}");
        assert!(calls[0]["user_id"].is_string(), "{case}");
        assert_eq!(calls[0]["ip_address"], "127.0.0.1", "{case}");
        assert!(
            seen.lock()
                .unwrap()
                .iter()
                .all(|(event, _)| *event != "token.pre_issue"),
            "{case}: nothing was about to be issued"
        );

        let rows = native_login_rows(&f).await;
        assert_eq!(reason_codes(&rows), ["reactor_denied"], "{case}");
        assert_eq!(
            rows[0].outcome,
            axiam_core::models::audit::AuditOutcome::Failure
        );
    }
}

/// An allowing gate is consulted with the user the token signed in, and the
/// sign-in proceeds exactly as without one.
#[actix_web::test]
async fn an_allowing_login_post_auth_gate_passes_the_native_grant() {
    let f = setup().await;
    let (gate, seen) = gate(ReactorOutcome::Allow);
    let app = test_app!(@gate f, gate);
    let app_client = native_client(&f, "ios-app").await;

    let nonce = "nonce-allowed";
    let token = id_token(&f, nonce, "grace", json!({}));
    let (status, body) = token_endpoint!(
        app,
        f,
        grant_body(&app_client, SLUG, &token, nonce, "openid")
    );
    assert_eq!(status, 200, "{body}");
    let user_id = claims_of(body["access_token"].as_str().unwrap())["sub"].clone();

    let calls = login_post_auth_calls(&seen);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["user_id"], user_id);
    assert_eq!(session_rows(&f).await, 1);
    assert_eq!(reason_codes(&native_login_rows(&f).await), ["accepted"]);
}

// ===========================================================================
// Step 8 — consent and binding
// ===========================================================================

/// D-N6: a client an administrator did not register needs the user's
/// consent to act as them, and this grant cannot ask — `consent_required`.
/// A sensitive scope the tenant has switched off is `invalid_scope`, as at
/// `/authorize`.
#[actix_web::test]
async fn a_scope_that_needs_a_ceremony_is_consent_required() {
    let f = setup().await;
    let app = test_app!(f);
    let (external, _) = client(
        &f,
        "self-registered",
        ClientAuthMethod::None,
        &[PROVIDER_ID_TOKEN_GRANT_TYPE],
        |c| c.managed_by = ManagedBy::Dcr,
    )
    .await;
    let token = id_token(&f, "nonce-d", "ada", json!({}));
    let (status, body) =
        token_endpoint!(app, f, grant_body(&external, SLUG, &token, "nonce-d", ""));
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("consent_required")),
        "{body}"
    );
    assert!(body.get("access_token").is_none());

    let (sensitive, _) = client(
        &f,
        "wants-a-phone-number",
        ClientAuthMethod::None,
        &[PROVIDER_ID_TOKEN_GRANT_TYPE],
        |c| c.scopes.push("phone".into()),
    )
    .await;
    let token = id_token(&f, "nonce-e", "ada", json!({}));
    let (status, body) = token_endpoint!(
        app,
        f,
        grant_body(&sensitive, SLUG, &token, "nonce-e", "openid phone")
    );
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_scope")),
        "{body}"
    );

    assert_eq!(
        reason_codes(&native_login_rows(&f).await),
        ["consent_required", "invalid_scope"]
    );
}

/// A client registered for DPoP-bound tokens gets one — `cnf.jkt` and
/// `token_type: DPoP` — and a request without a proof is refused before the
/// provider token is looked at, so it is not spent.
#[actix_web::test]
async fn a_dpop_bound_client_gets_a_dpop_bound_token() {
    let f = setup().await;
    let app = test_app!(f);
    let (bound, _) = client(
        &f,
        "dpop-app",
        ClientAuthMethod::None,
        &[PROVIDER_ID_TOKEN_GRANT_TYPE, "refresh_token"],
        |c| c.dpop_bound_access_tokens = true,
    )
    .await;
    let token = id_token(&f, "nonce-p", "ada", json!({}));
    let body = grant_body(&bound, SLUG, &token, "nonce-p", "openid");

    let (status, refused) = token_endpoint!(app, f, body.clone());
    assert_eq!(
        (status, refused["error"].as_str()),
        (401, Some("invalid_client"))
    );
    assert!(native_login_rows(&f).await.is_empty());

    let key = Ed25519Key::generate(None);
    let parsed: jsonwebtoken::jwk::Jwk = serde_json::from_value(key.jwk.clone()).unwrap();
    let jkt = axiam_oauth2::jose::jwk_thumbprint(&parsed).unwrap();
    let header: Header = serde_json::from_value(json!({
        "typ": axiam_oauth2::dpop::DPOP_TYP,
        "alg": "EdDSA",
        "jwk": key.jwk,
    }))
    .unwrap();
    let proof = encode(
        &header,
        &json!({
            "jti": Uuid::new_v4().to_string(),
            "htm": "POST",
            "htu": format!("{ISSUER}/oauth2/token"),
            "iat": now(),
        }),
        &key.encoding,
    )
    .unwrap();

    let (status, issued) = token_endpoint!(app, f, body, [("DPoP", proof)]);
    assert_eq!(status, 200, "{issued}");
    assert_eq!(issued["token_type"], "DPoP");
    let access = claims_of(issued["access_token"].as_str().unwrap());
    assert_eq!(access["cnf"]["jkt"], jkt.as_str());
}

// ===========================================================================
// The limiter
// ===========================================================================

/// The grant has its own bucket, `oauth2_provider_id_token`, at the login
/// preset per address — one allowance whichever mount the request uses.
#[actix_web::test]
async fn the_grant_has_its_own_login_bucket_shared_by_both_mounts() {
    let f = setup().await;
    let app = test_app!(f, 2, true);
    let app_client = native_client(&f, "ios-app").await;

    // Two refusals spend the address's budget as two sign-ins would…
    for nonce in ["l1", "l2"] {
        let token = id_token(&f, nonce, "ada", json!({ "aud": WEB }));
        let (status, body) = token_endpoint!(
            app,
            f,
            grant_body(&app_client, SLUG, &token, nonce, "openid")
        );
        assert_generic_invalid_grant(status, &body, nonce);
    }
    // …and the third is refused on the per-tenant mount too, before the token
    // is looked at.
    let token = id_token(&f, "l3", "ada", json!({}));
    let (status, body) = post!(
        app,
        format!("/t/{}/oauth2/token", f.tenant_id),
        grant_body(&app_client, SLUG, &token, "l3", "openid"),
        []
    );
    assert_eq!(
        (status, body["error"].as_str()),
        (429, Some("rate_limit_exceeded")),
        "{body}"
    );
    assert_eq!(native_login_rows(&f).await.len(), 2);

    // The other grants at the endpoint are untouched by it.
    let (status, body) = token_endpoint!(
        app,
        f,
        format!(
            "grant_type=refresh_token&client_id={}&refresh_token=unknown",
            enc(&app_client)
        )
    );
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_grant"))
    );
}
