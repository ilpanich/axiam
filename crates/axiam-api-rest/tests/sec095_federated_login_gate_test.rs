//! SEC-095 — `login.post_auth` fires on federated sign-in, not only on the
//! password path.
//!
//! ## What was wrong
//!
//! The reactor gate was consulted in exactly one place: `AuthService::login`.
//! Both public SSO handlers — `POST /api/v1/auth/federation/oidc/callback` and
//! `POST /api/v1/auth/federation/saml/acs` — call
//! `AuthService::create_session_and_tokens` directly, so a federated login
//! issued a full session plus access and refresh tokens without the gate ever
//! being asked.
//!
//! Nothing scoped the event to password authentication. The registry entry
//! (`axiam_core::models::reactor::events`) reads "After credentials verify,
//! before session issuance: veto or require step-up MFA", and
//! `sdks/CONTRACT.md` §22.5 repeats that table with no carve-out. R2.5's own
//! worked example for the feature is an *embargoed-region login veto* — a
//! control that, before this fix, was bypassed by clicking "Sign in with
//! Okta".
//!
//! It was latent rather than exploitable at the time it was found only because
//! `UnavailableReactorTransport` meant no reactor reply could be produced at
//! all. That was a reason to close it before the transport merged, not a
//! reason to leave it — and R2.4 has since merged the lapin transport, which
//! makes these assertions the thing standing between a registered veto and
//! "Sign in with Okta".
//!
//! ## What this file asserts
//!
//! For **both** federated paths, driven over HTTP through the mounted routes:
//!
//! * a gate that denies `login.post_auth` refuses the sign-in, sets no session
//!   cookies, and writes no session row; and
//! * a gate that allows leaves the sign-in exactly as it was — while still
//!   being consulted, with the payload the password path sends.
//!
//! The OIDC path runs against a wiremock mock IdP (harness lifted from
//! `federation_first_time_sso_test.rs`); the SAML path runs against the
//! pre-signed `scd_valid_response.xml` fixture (harness lifted from
//! `axiam-server/tests/req5_saml_e2e.rs`).
//!
//! Every test is named after the thing it stops.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::reactor::{DynReactorGate, ReactorOutcome, SharedReactorGate};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{OrganizationRepository, TenantRepository};
use axiam_db::repository::{SurrealOrganizationRepository, SurrealTenantRepository};
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
/// Test-only AES-256-GCM key (32 bytes of 0x2a) — not a secret. gitleaks:allow
const TEST_FED_ENC_KEY: [u8; 32] = [0x2a; 32];

// ---------------------------------------------------------------------------
// The mock gate
// ---------------------------------------------------------------------------
//
// A mock rather than the real `DispatchingReactorGate`, for the same reason
// `axiam-auth/tests/reactor_login_gate_test.rs` uses one: the four outcomes a
// chain can compose are exactly the four a mock produces, and the mapping from
// a reactor-level event to one of them is tested where it lives, in
// `axiam_amqp::reactor::gate`. What is under test here is the CALL SITE — that
// there is one on each federated path at all.

type GateLog = Arc<Mutex<Vec<(&'static str, serde_json::Value)>>>;

struct FixedGate {
    outcome: ReactorOutcome,
    seen: GateLog,
}

impl DynReactorGate for FixedGate {
    fn intercept_dyn<'a>(
        &'a self,
        _tenant_id: Uuid,
        event: &'static str,
        payload: serde_json::Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ReactorOutcome> + Send + 'a>> {
        self.seen.lock().unwrap().push((event, payload));
        let outcome = self.outcome.clone();
        Box::pin(std::future::ready(outcome))
    }

    // SEC-101: a scripted test double stands in for a working
    // transport, so registrations are acceptable under it.
    fn can_dispatch_dyn(&self) -> bool {
        true
    }
}

fn gate(outcome: ReactorOutcome) -> (SharedReactorGate, GateLog) {
    let seen: GateLog = Arc::new(Mutex::new(Vec::new()));
    (
        Arc::new(FixedGate {
            outcome,
            seen: seen.clone(),
        }),
        seen,
    )
}

fn embargo_veto() -> ReactorOutcome {
    ReactorOutcome::Deny {
        reason: "login from an embargoed region".into(),
    }
}

/// Every `login.post_auth` call the gate saw, and nothing else.
fn login_calls(seen: &GateLog) -> Vec<serde_json::Value> {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|(event, _)| *event == "login.post_auth")
        .map(|(_, payload)| payload.clone())
        .collect()
}

async fn session_count(db: &Surreal<TestDb>) -> usize {
    let mut r = db.query("SELECT * FROM session").await.expect("query");
    let rows: Vec<serde_json::Value> = r.take(0).expect("take");
    rows.len()
}

// ---------------------------------------------------------------------------
// Mock-IdP helpers (mirrors federation_first_time_sso_test.rs)
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
        Self {
            private_key_pem,
            jwk_json: json!({
                "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n, "e": e
            }),
        }
    }

    fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_rsa_pem(self.private_key_pem.as_bytes()).expect("encoding key")
    }

    fn jwks_json(&self) -> serde_json::Value {
        json!({ "keys": [self.jwk_json] })
    }
}

fn sign_jwt(claims: &serde_json::Value, key: &EncodingKey, kid: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    encode(&header, claims, key).expect("sign JWT")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn test_keypair() -> (String, String) {
    let kp =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair generation");
    (kp.serialize_pem(), kp.public_key_pem())
}

fn test_auth_config() -> AuthConfig {
    let (private_key, public_key) = test_keypair();
    AuthConfig {
        jwt_private_key_pem: private_key,
        jwt_public_key_pem: public_key,
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        // R-3: since the deployment-origin rule applies to all four federated
        // start paths (not only the cross-site two), a fixture whose SPA is on
        // a different origin than the issuer has to name it — exactly what a
        // real split-origin deployment does. Naming it here also keeps this
        // suite honest about the migration the change asks of operators.
        sso_spa_origins: vec!["https://spa.example.com".into()],
        federation_encryption_key: Some(TEST_FED_ENC_KEY),
        ..AuthConfig::default()
    }
}

async fn setup_db() -> (Surreal<TestDb>, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "SEC095 Org".into(),
            slug: "sec095-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "SEC095 Tenant".into(),
            slug: "sec095-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    (db, org.id, tenant.id)
}

/// Build the `AppState` a production server builds, with the reactor gate
/// installed on `AuthService` exactly as `axiam-server`'s composition root
/// does.
fn state_with_gate(
    db: &Surreal<TestDb>,
    auth: &AuthConfig,
    gate: SharedReactorGate,
    jwks_cache: Arc<JwksCache>,
) -> AppState<TestDb> {
    let mut state = AppState::for_test(db.clone(), auth.clone());
    state.http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    state.jwks_cache = jwks_cache;
    state.federation.oidc_federation_service = Some(OidcFederationService::new(
        state.federation.federation_config_repo.clone(),
        state.federation.federation_link_repo.clone(),
        state.user_repo.clone(),
        state.http_client.clone(),
        Arc::clone(&state.jwks_cache),
        TEST_FED_ENC_KEY,
    ));
    state.auth_service = state.auth_service.clone().with_reactor_gate(gate.clone());
    state.oauth2.token_service = state
        .oauth2
        .token_service
        .clone()
        .with_reactor_gate(gate.clone());
    state.events.reactor_gate = gate;
    state
}

macro_rules! app_for {
    ($auth:expr, $state:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new($state))
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
// OIDC callback
// ---------------------------------------------------------------------------

struct OidcOutcome {
    status: u16,
    has_access_cookie: bool,
    sessions: usize,
    payloads: Vec<serde_json::Value>,
}

/// Drive a complete public OIDC SSO round trip — config, `/oidc/start`, mock
/// IdP token exchange, `/oidc/callback` — with `outcome` as the gate's verdict.
async fn run_oidc_sso(outcome: ReactorOutcome) -> OidcOutcome {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();

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

    let (g, seen) = gate(outcome);
    let state = state_with_gate(
        &db,
        &auth,
        g,
        Arc::new(JwksCache::new_allow_private_networks()),
    );
    // Seed the federation config directly — the authenticated admin API is not
    // what this test is about, and going through it would need a bearer token
    // plus CSRF headers that add nothing to the property under test.
    let config_id = Uuid::new_v4();
    db.query(
        "CREATE type::record('federation_config', $id) SET \
         tenant_id = $tenant_id, provider = 'MockIdP', protocol = 'OidcConnect', \
         metadata_url = $metadata_url, client_id = $client_id, \
         client_secret = 'mock-idp-secret', \
         attribute_map = {}, enabled = true, allowed_algorithms = ['RS256'], \
         created_at = time::now(), updated_at = time::now()",
    )
    .bind(("id", config_id.to_string()))
    .bind(("tenant_id", tenant_id.to_string()))
    .bind((
        "metadata_url",
        format!("{issuer}/.well-known/openid-configuration"),
    ))
    .bind(("client_id", client_id.to_string()))
    .await
    .expect("insert federation_config")
    .check()
    .expect("check insert");

    let app = app_for!(auth, state);

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
        "fixture precondition: oidc/start must succeed"
    );
    let start_body: serde_json::Value = test::read_body_json(start_resp).await;
    let oidc_state = start_body["state"].as_str().unwrap().to_string();
    let authorize_url = start_body["authorize_url"].as_str().unwrap();
    let nonce = url::Url::parse(authorize_url)
        .expect("valid authorize_url")
        .query_pairs()
        .find(|(k, _)| k == "nonce")
        .map(|(_, v)| v.into_owned())
        .expect("authorize_url carries the nonce");

    let now = now_secs();
    let id_token = sign_jwt(
        &json!({
            "sub": "sec095-subject-001",
            "iss": issuer,
            "aud": client_id,
            "exp": now + 3600,
            "iat": now,
            "nonce": nonce,
            "email": "sec095-user@example.com",
        }),
        &keys.encoding_key(),
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

    let callback_req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/federation/oidc/callback")
        .set_json(json!({ "state": oidc_state, "code": "mock-authorization-code" }))
        .to_request();
    let resp = test::call_service(&app, callback_req).await;

    OidcOutcome {
        status: resp.status().as_u16(),
        has_access_cookie: resp
            .response()
            .cookies()
            .any(|c| c.name() == "axiam_access"),
        sessions: session_count(&db).await,
        payloads: login_calls(&seen),
    }
}

#[actix_rt::test]
async fn a_reactor_veto_refuses_an_oidc_sso_sign_in() {
    let out = run_oidc_sso(embargo_veto()).await;

    assert_ne!(
        out.status, 200,
        "a vetoed federated login must not succeed (SEC-095)"
    );
    assert!(
        !out.has_access_cookie,
        "a vetoed federated login must not set an access cookie"
    );
    assert_eq!(
        out.sessions, 0,
        "a veto must refuse BEFORE create_session_and_tokens — a veto that arrives \
         after it is refusing a session that already exists"
    );
    assert_eq!(
        out.payloads.len(),
        1,
        "the OIDC callback must consult login.post_auth exactly once"
    );
}

#[actix_rt::test]
async fn an_allowing_reactor_leaves_an_oidc_sso_sign_in_unchanged() {
    let out = run_oidc_sso(ReactorOutcome::Allow).await;

    assert_eq!(out.status, 200, "an allow must not disturb the sign-in");
    assert!(
        out.has_access_cookie,
        "an allowed federated login still sets its cookies"
    );
    assert_eq!(
        out.sessions, 1,
        "an allowed federated login creates one session"
    );

    // The payload contract is the password path's, not a second one invented
    // here: the reactor is told who is signing in and from where — which is
    // what an embargoed-region veto runs on — and never a token or session id.
    assert_eq!(out.payloads.len(), 1);
    let payload = &out.payloads[0];
    for key in [
        "user_id",
        "username",
        "tenant_id",
        "org_id",
        "ip_address",
        "user_agent",
        "mfa_enabled",
    ] {
        assert!(
            payload.get(key).is_some(),
            "login.post_auth payload must carry `{key}` on the federated path too, \
             exactly as on the password path: {payload}"
        );
    }
    assert_eq!(
        payload["ip_address"], "127.0.0.1",
        "the federated payload must carry the real client address — the SSO handlers \
         previously did not look at the request at all: {payload}"
    );
}

/// A federated sign-in has no `MfaRequired` / `MfaSetupRequired` branch, so a
/// reactor's step-up demand cannot be honoured. It must be REFUSED, not
/// dropped: silently ignoring it would hand out a single-factor session to an
/// operator who configured a second factor and would never learn otherwise.
#[actix_rt::test]
async fn a_require_mfa_a_federated_path_cannot_honour_refuses_rather_than_proceeds() {
    let out = run_oidc_sso(ReactorOutcome::RequireMfa).await;

    assert_ne!(out.status, 200, "an unhonourable require_mfa must refuse");
    assert!(!out.has_access_cookie);
    assert_eq!(out.sessions, 0);
}

// ---------------------------------------------------------------------------
// SAML ACS
// ---------------------------------------------------------------------------

#[cfg(feature = "saml")]
mod saml {
    use super::*;
    use axiam_core::repository::{FederationLoginState, FederationLoginStateRepository};
    use base64::engine::general_purpose::STANDARD;

    const FIXTURES_DIR: &str = "../axiam-federation/tests/fixtures/saml";
    /// The `@InResponseTo` baked into `scd_valid_response.xml`.
    const FIXTURE_REQUEST_ID: &str = "_axiam-req-1";
    /// The `<Audience>` baked into the same fixture.
    const FIXTURE_SP_ENTITY_ID: &str = "https://sp.example.com";

    fn fixture(name: &str) -> String {
        let p = std::path::Path::new(FIXTURES_DIR).join(name);
        std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("failed to load SAML fixture {}: {e}", p.display()))
    }

    struct SamlOutcome {
        status: u16,
        has_access_cookie: bool,
        sessions: usize,
        payloads: Vec<serde_json::Value>,
    }

    async fn run_saml_acs(outcome: ReactorOutcome) -> SamlOutcome {
        let (db, _org_id, tenant_id) = setup_db().await;
        let auth = test_auth_config();

        let config_id = Uuid::new_v4();
        db.query(
            "CREATE type::record('federation_config', $id) SET \
             tenant_id = $tenant_id, provider = 'test-saml-idp', protocol = 'Saml', \
             metadata_url = 'https://idp.example.com/metadata', client_id = $client_id, \
             client_secret = '', attribute_map = {}, enabled = true, \
             allowed_algorithms = ['RS256'], idp_signing_cert_pem = $cert, \
             created_at = time::now(), updated_at = time::now()",
        )
        .bind(("id", config_id.to_string()))
        .bind(("tenant_id", tenant_id.to_string()))
        .bind(("client_id", FIXTURE_SP_ENTITY_ID.to_string()))
        .bind(("cert", fixture("signing_cert.pem")))
        .await
        .expect("insert federation_config")
        .check()
        .expect("check insert");

        let (g, seen) = gate(outcome);
        let state = state_with_gate(
            &db,
            &auth,
            g,
            Arc::new(JwksCache::new_allow_private_networks()),
        );

        // The relay state the ACS handler consumes, carrying the AuthnRequest
        // id the fixture's signed `@InResponseTo` names.
        let relay_state = "sec095-relay-state";
        state
            .federation
            .federation_login_state_repo
            .insert(&FederationLoginState {
                state: relay_state.into(),
                nonce: String::new(),
                tenant_id,
                federation_config_id: config_id,
                redirect_uri: "https://spa.example.com/callback".into(),
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
                request_id: FIXTURE_REQUEST_ID.into(),
                code_verifier: None,
                idp_redirect_uri: None,
            })
            .await
            .expect("seed federation_login_state");

        let app = app_for!(auth, state);
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/auth/federation/saml/acs")
            .set_json(json!({
                "relay_state": relay_state,
                "saml_response_b64": STANDARD.encode(fixture("scd_valid_response.xml")),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        SamlOutcome {
            status: resp.status().as_u16(),
            has_access_cookie: resp
                .response()
                .cookies()
                .any(|c| c.name() == "axiam_access"),
            sessions: session_count(&db).await,
            payloads: login_calls(&seen),
        }
    }

    #[actix_rt::test]
    async fn an_allowing_reactor_leaves_a_saml_acs_sign_in_unchanged() {
        let out = run_saml_acs(ReactorOutcome::Allow).await;

        assert_eq!(
            out.status, 200,
            "fixture precondition + property: an allowed SAML ACS sign-in succeeds"
        );
        assert!(out.has_access_cookie);
        assert_eq!(out.sessions, 1);
        assert_eq!(
            out.payloads.len(),
            1,
            "SAML ACS must consult login.post_auth exactly once"
        );
        assert_eq!(out.payloads[0]["ip_address"], "127.0.0.1");
    }

    #[actix_rt::test]
    async fn a_reactor_veto_refuses_a_saml_acs_sign_in() {
        let out = run_saml_acs(embargo_veto()).await;

        assert_ne!(
            out.status, 200,
            "a vetoed SAML sign-in must not succeed (SEC-095)"
        );
        assert!(!out.has_access_cookie);
        assert_eq!(
            out.sessions, 0,
            "a veto must refuse BEFORE create_session_and_tokens"
        );
        assert_eq!(out.payloads.len(), 1);
    }
}
