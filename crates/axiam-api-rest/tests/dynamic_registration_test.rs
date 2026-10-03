//! T21.4 — RFC 7591 dynamic client registration, end to end.
//!
//! The feature is one sentence: a client can create itself, without an
//! administrator, at an endpoint anybody can reach. Every test here is asking
//! one of five questions about that sentence.
//!
//! **Is it off until somebody turns it on?** This is I1, and it is the first
//! section, because it is the only one that is about every deployment rather
//! than about the deployments that want this. A tenant that changes nothing
//! gets `403` from the endpoint and a discovery document with no
//! `registration_endpoint` — the same document, member for member, that it got
//! before this task.
//!
//! **Does a real MCP client get through, and does its token work?** The
//! MCP-Inspector-shaped registration is the acceptance case: it registers, and
//! the client it produces completes a code + PKCE + `resource` flow whose token
//! carries the MCP server as its audience.
//!
//! **Does a stranger get to decide anything they should not?** D3 is the one
//! that matters — a self-registered client's audiences are the tenant's list
//! and nothing else — and the settings interlock that makes D3 real is tested
//! beside it.
//!
//! **Is the end user asked?** D4: the first authorization for a self-registered
//! client goes to the consent screen whatever scopes it asked for, and the
//! second one, after consent, does not.
//!
//! **Is the abuse surface bounded?** The per-tenant ceiling, the per-IP rate
//! limit, and every refusal's error code.
//!
//! The sweeper is not here: it lives in `axiam-server`, four layers out, and is
//! tested in `crates/axiam-server/tests/cleanup_task.rs` beside the other
//! sweeps.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::settings::{DynamicRegistrationMode, SetOrgSettings, system_defaults};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OrganizationRepository, SettingsRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealSettingsRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12345";
const CSRF_TOKEN: &str = "test-csrf-token";
const ISSUER: &str = "https://localhost";
/// The MCP server this tenant fronts, as an operator would register it.
const MCP: &str = "https://mcp.example.com/mcp";
/// What MCP Inspector actually listens on.
const INSPECTOR_CALLBACK: &str = "http://127.0.0.1:6274/oauth/callback";
const VERIFIER: &str = "a-verifier-long-enough-to-satisfy-rfc-7636-section-4.1";

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
        oauth2_issuer_url: ISSUER.into(),
        sso_spa_origins: Vec::new(),
        ..AuthConfig::default()
    }
}

struct Fixture {
    db: Surreal<TestDb>,
    auth: AuthConfig,
    org_id: Uuid,
    tenant_id: Uuid,
    user_token: String,
}

async fn setup() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "T21.4 Org".into(),
            slug: "org-t21-4".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "T21.4 Tenant".into(),
            slug: "tenant-t21-4".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "admin".into(),
            email: "admin@example.com".into(),
            // Generated rather than written down: nothing here signs in with
            // it, so a literal would be a credential in the tree buying
            // nothing.
            password: format!("pw-{}", Uuid::new_v4()),
            metadata: None,
        })
        .await
        .unwrap();

    let auth = test_auth_config();
    let user_token = issue_access_token(
        user.id,
        tenant.id,
        org.id,
        &[],
        &auth,
        Uuid::new_v4().to_string(),
        axiam_auth::token::AUD_USER,
    )
    .unwrap();

    Fixture {
        db,
        auth,
        org_id: org.id,
        tenant_id: tenant.id,
        user_token,
    }
}

/// Write an organization baseline, which every tenant inherits.
///
/// Returns the settings-repository error rather than unwrapping, so the tests
/// that are *about* a refused policy can assert on it.
async fn set_org_settings(
    f: &Fixture,
    input: SetOrgSettings,
) -> Result<(), axiam_core::error::AxiamError> {
    SurrealSettingsRepository::new(f.db.clone())
        .set_org_settings(f.org_id, input)
        .await
        .map(|_| ())
}

/// Write an organization baseline through the **admin API**, which is where
/// the T21.4 interlocks live.
///
/// The repository helper above bypasses validation, which is exactly what a
/// test wants for *setup*. The interlocks are a property of the handler — the
/// plan says "refused by the settings handler" — so a test that is about a
/// refusal has to make the request a person would make.
macro_rules! put_org_settings {
    ($app:expr, $f:expr, $input:expr) => {{
        let req = test::TestRequest::put()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!("/api/v1/organizations/{}/settings", $f.org_id))
            .insert_header(("Authorization", format!("Bearer {}", $f.user_token)))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json($input)
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let body = test::read_body(resp).await;
        (
            status,
            serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null),
        )
    }};
}

/// The baseline an operator writes to turn anonymous registration on properly:
/// a mode, a scope list, and — the part that matters — the MCP server this
/// tenant fronts.
fn anonymous_policy() -> SetOrgSettings {
    SetOrgSettings {
        dynamic_registration: DynamicRegistrationMode::Anonymous,
        dcr_allowed_scopes: vec!["openid".into(), "profile".into()],
        external_client_allowed_resources: vec![MCP.into()],
        ..system_defaults()
    }
}

/// A rate-limit configuration whose registration bucket is wide enough for a
/// test that makes a dozen attempts.
///
/// Used by every test here except the one that is *about* the limit. Five per
/// minute is the shipped default and the right one — it is the only endpoint
/// that writes for a caller holding no credential — but a table-driven test of
/// thirteen refusal codes would otherwise be measuring the governor rather
/// than the validator, and would fail differently as the table grows.
fn permissive_rate_limits() -> RateLimitConfig {
    RateLimitConfig {
        dcr_per_min: 1_000,
        ..RateLimitConfig::default()
    }
}

macro_rules! test_app {
    ($f:expr) => {
        test_app!($f, permissive_rate_limits())
    };
    ($f:expr, $limits:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($f.auth.clone()))
                .app_data(web::Data::new(AppState::for_test(
                    $f.db.clone(),
                    $f.auth.clone(),
                )))
                .app_data(web::Data::new(
                    Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
                ))
                .configure(|cfg| register_api_v1_routes::<TestDb>(cfg, &$limits)),
        )
        .await
    };
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

/// `POST /oauth2/register`, optionally with an initial access token.
macro_rules! register {
    ($app:expr, $f:expr, $body:expr) => {
        register!($app, $f, $body, None::<&str>)
    };
    ($app:expr, $f:expr, $body:expr, $bearer:expr) => {{
        let mut req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!("/oauth2/register?tenant_id={}", $f.tenant_id))
            .set_json($body);
        if let Some(token) = $bearer {
            req = req.insert_header(("Authorization", format!("Bearer {token}")));
        }
        let resp = test::call_service(&$app, req.to_request()).await;
        let status = resp.status().as_u16();
        let body = test::read_body(resp).await;
        (
            status,
            serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null),
        )
    }};
}

/// An authenticated admin call.
macro_rules! admin {
    ($app:expr, $f:expr, $method:ident, $path:expr) => {{
        let req = test::TestRequest::$method()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri($path)
            .insert_header(("Authorization", format!("Bearer {}", $f.user_token)))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let body = test::read_body(resp).await;
        (
            status,
            serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null),
        )
    }};
    ($app:expr, $f:expr, $method:ident, $path:expr, $json:expr) => {{
        let req = test::TestRequest::$method()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri($path)
            .insert_header(("Authorization", format!("Bearer {}", $f.user_token)))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json($json)
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let body = test::read_body(resp).await;
        (
            status,
            serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null),
        )
    }};
}

macro_rules! get_authorize {
    ($app:expr, $f:expr, $query:expr) => {{
        let req = test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!("/oauth2/authorize?{}", $query))
            .insert_header(("Authorization", format!("Bearer {}", $f.user_token)))
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get("Location")
            .map(|v| v.to_str().unwrap().to_owned());
        (status, location)
    }};
}

macro_rules! post_form {
    ($app:expr, $f:expr, $path:expr, $body:expr) => {{
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!("{}?tenant_id={}", $path, $f.tenant_id))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload($body.to_string())
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let body = test::read_body(resp).await;
        (
            status,
            serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null),
        )
    }};
}

/// The registration MCP Inspector actually sends, reduced to the members that
/// reach a decision.
fn inspector_registration() -> Value {
    json!({
        "client_name": "MCP Inspector",
        "redirect_uris": [INSPECTOR_CALLBACK],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": "openid profile",
    })
}

fn pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// The `aud` claim of a JWT, read without verifying anything — a test
/// assertion, not a validation primitive.
fn aud_of(jwt: &str) -> String {
    let payload = jwt.split('.').nth(1).expect("a JWT has three parts");
    let bytes = URL_SAFE_NO_PAD.decode(payload).expect("base64url payload");
    let claims: Value = serde_json::from_slice(&bytes).expect("JSON claims");
    claims["aud"]
        .as_str()
        .unwrap_or_else(|| panic!("no aud in {claims}"))
        .to_owned()
}

fn param(location: &str, key: &str) -> Option<String> {
    url::Url::parse(location)
        .ok()?
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

// ---------------------------------------------------------------------------
// I1 — absent until a tenant enables it
// ---------------------------------------------------------------------------

/// The mandatory I1 test: with the policy at its default, the feature is not
/// there. Both halves — the endpoint refuses, and discovery does not mention
/// it — because either one alone would leave the other as a way to find the
/// feature.
#[actix_rt::test]
async fn i1_a_tenant_that_changed_nothing_has_no_registration_endpoint() {
    let f = setup().await;
    let app = test_app!(f);

    let (status, body) = register!(app, f, inspector_registration());
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"], "invalid_request");

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!(
            "/.well-known/oauth-authorization-server?tenant_id={}",
            f.tenant_id
        ))
        .to_request();
    let doc: Value = test::call_and_read_body_json(&app, req).await;
    assert!(
        doc.get("registration_endpoint").is_none(),
        "the member must be ABSENT, not empty: RFC 8414 defines no default for it, so a \
         present value is one a conforming client will try. Got {doc}"
    );
}

/// The same absence for a caller that names no tenant, which is every
/// conformance run and every client written before this task.
#[actix_rt::test]
async fn i1_the_deployment_wide_document_never_advertises_registration() {
    let f = setup().await;
    // Even with the tenant switched fully on.
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/.well-known/openid-configuration")
        .to_request();
    let doc: Value = test::call_and_read_body_json(&app, req).await;
    assert!(
        doc.get("registration_endpoint").is_none(),
        "a document that names no tenant cannot say whether registration is available: {doc}"
    );
}

/// The advertisement appears, and only for the tenant that enabled it.
#[actix_rt::test]
async fn the_endpoint_is_advertised_once_the_tenant_enables_it() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!(
            "/.well-known/oauth-authorization-server?tenant_id={}",
            f.tenant_id
        ))
        .to_request();
    let doc: Value = test::call_and_read_body_json(&app, req).await;
    let endpoint = doc["registration_endpoint"].as_str().unwrap_or_default();
    assert!(
        endpoint.starts_with(&format!("{ISSUER}/oauth2/register?tenant_id=")),
        "the advertised endpoint must carry the tenant, or a client following the document \
         lands on `missing field tenant_id`: {endpoint}"
    );
}

// ---------------------------------------------------------------------------
// D3 — the interlock, which is a security control rather than a validation
// ---------------------------------------------------------------------------

/// Enabling `anonymous` with no audiences is refused, and the message names
/// D3. Without this, an open endpoint would mint clients able to ask for the
/// `axiam:user` tokens AXIAM's own APIs accept.
#[actix_rt::test]
async fn d3_anonymous_registration_cannot_be_enabled_without_audiences() {
    let f = setup().await;

    let app = test_app!(f);

    let (status, body) = put_org_settings!(
        app,
        f,
        SetOrgSettings {
            dynamic_registration: DynamicRegistrationMode::Anonymous,
            // The whole of the problem: no audiences named.
            external_client_allowed_resources: Vec::new(),
            ..system_defaults()
        }
    );
    assert_eq!(status, 400, "{body}");
    let message = body.to_string();
    assert!(
        message.contains("D3"),
        "the refusal must name D3: {message}"
    );
    assert!(
        message.contains("external_client_allowed_resources"),
        "and the field the operator has to fill in: {message}"
    );

    // Naming one makes the same policy acceptable.
    let (status, body) = put_org_settings!(app, f, anonymous_policy());
    assert_eq!(status, 200, "{body}");
}

/// `initial_access_token` mode is deliberately **not** interlocked: there an
/// administrator has already decided the registration should happen.
#[actix_rt::test]
async fn d3_does_not_bind_the_initial_access_token_mode() {
    let f = setup().await;
    let app = test_app!(f);
    let (status, body) = put_org_settings!(
        app,
        f,
        SetOrgSettings {
            dynamic_registration: DynamicRegistrationMode::InitialAccessToken,
            external_client_allowed_resources: Vec::new(),
            ..system_defaults()
        }
    );
    assert_eq!(
        status, 200,
        "a hand-issued credential is an administrator's decision: {body}"
    );
}

/// The amendment recorded on the plan: a self-registered client can never hold
/// a scope W7 gates, so an end user never answers two consent screens for one
/// authorization.
#[actix_rt::test]
async fn a_sensitive_scope_cannot_be_offered_to_self_registered_clients() {
    let f = setup().await;
    let app = test_app!(f);
    for scope in ["address", "phone"] {
        let (status, body) = put_org_settings!(
            app,
            f,
            SetOrgSettings {
                dcr_allowed_scopes: vec!["openid".into(), scope.into()],
                ..anonymous_policy()
            }
        );
        assert_eq!(status, 400, "{scope}: {body}");
        assert!(
            body.to_string().contains(scope),
            "the refusal must name the scope: {body}"
        );
    }
}

/// D3's other half, and the one a stranger would try: the registered client's
/// audiences are the **tenant's** list, whatever the request said, and the
/// request has no member that could say otherwise.
#[actix_rt::test]
async fn d3_a_registered_client_inherits_the_tenants_audiences() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);

    // A request that tries every spelling of "let me choose my audience".
    let mut body = inspector_registration();
    body["allowed_resources"] = json!(["https://elsewhere.example.com/mcp"]);
    body["resource"] = json!("https://elsewhere.example.com/mcp");
    body["audience"] = json!(["https://elsewhere.example.com/mcp"]);
    let (status, registered) = register!(app, f, body);
    assert_eq!(status, 201, "{registered}");
    let client_id = registered["client_id"].as_str().unwrap();

    // Read the stored row through the admin API: the allow-list is the
    // tenant's one entry and nothing the request named.
    let (_, list) = admin!(app, f, get, "/api/v1/oauth2-clients");
    let stored = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["client_id"] == client_id)
        .expect("the registered client is listed");
    assert_eq!(
        stored["allowed_resources"],
        json!([MCP]),
        "a self-registered client's audiences are the tenant's, never the request's"
    );

    // And the request-time consequence: naming the other one is refused. The
    // end user consents first, so that what this measures is the audience
    // refusal rather than D4's consent hop — the two are tested separately.
    let (status, _) = admin!(
        app,
        f,
        post,
        "/api/v1/account/consents/oidc-scopes",
        json!({ "client_id": client_id, "scopes": ["openid", "profile"] })
    );
    assert_eq!(status, 200);

    let challenge = pkce_challenge(VERIFIER);
    let (status, location) = get_authorize!(
        app,
        f,
        format!(
            "response_type=code&client_id={client_id}&redirect_uri={INSPECTOR_CALLBACK}\
             &scope=openid&code_challenge={challenge}&code_challenge_method=S256\
             &resource=https%3A%2F%2Felsewhere.example.com%2Fmcp"
        )
    );
    assert_eq!(status, 302);
    assert_eq!(
        param(&location.unwrap(), "error").as_deref(),
        Some("invalid_target")
    );
}

// ---------------------------------------------------------------------------
// The acceptance case: register, consent, authorize, get a bound token
// ---------------------------------------------------------------------------

/// The whole feature, in one test: an MCP-Inspector-shaped registration
/// succeeds, the client it produces passes the forced consent hop, and it then
/// completes a code + PKCE + `resource` flow whose token is addressed at the
/// MCP server rather than at AXIAM.
#[actix_rt::test]
async fn an_inspector_shaped_registration_can_complete_a_pkce_resource_flow() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);

    let (status, registered) = register!(app, f, inspector_registration());
    assert_eq!(status, 201, "{registered}");

    // RFC 7591 §3.2.1's response shape, for a public client.
    let client_id = registered["client_id"].as_str().unwrap().to_owned();
    assert!(
        registered.get("client_secret").is_none(),
        "a `none` registration mints no secret, so the member is absent rather than empty: \
         {registered}"
    );
    assert!(
        registered.get("client_secret_expires_at").is_none(),
        "§3.2.1 makes it REQUIRED only when a secret was issued: {registered}"
    );
    assert!(registered["client_id_issued_at"].as_i64().unwrap() > 0);
    assert_eq!(registered["token_endpoint_auth_method"], "none");
    assert_eq!(registered["scope"], "openid profile");
    assert_eq!(registered["response_types"], json!(["code"]));
    // T23.4.1 / RFC 7592 §3 — the management token, once, and where to use it.
    assert_eq!(
        registered["registration_access_token"]
            .as_str()
            .map(str::len),
        Some(43),
        "32 bytes, base64url, no padding: {registered}"
    );
    assert_eq!(
        registered["registration_client_uri"],
        format!(
            "{ISSUER}/oauth2/register/{client_id}?tenant_id={}",
            f.tenant_id
        )
    );

    // D4 — the first authorization is a consent hop, not a code.
    let challenge = pkce_challenge(VERIFIER);
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={INSPECTOR_CALLBACK}\
         &scope=openid+profile&code_challenge={challenge}&code_challenge_method=S256\
         &resource={MCP}"
    );
    let (status, location) = get_authorize!(app, f, query.clone());
    assert_eq!(status, 302);
    let location = location.unwrap();
    assert!(
        location.contains("consent"),
        "a client an administrator did not create must ask the end user first: {location}"
    );

    // The end user consents, through the same endpoint the account page uses.
    let (status, body) = admin!(
        app,
        f,
        post,
        "/api/v1/account/consents/oidc-scopes",
        json!({ "client_id": client_id, "scopes": ["openid", "profile"] })
    );
    assert_eq!(status, 200, "{body}");

    // Now the same request produces a code.
    let (status, location) = get_authorize!(app, f, query);
    assert_eq!(status, 302);
    let location = location.unwrap();
    let code = param(&location, "code").unwrap_or_else(|| panic!("no code in {location}"));

    // A public client redeems with no secret, and the token is addressed at
    // the MCP server.
    let (status, tokens) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=authorization_code&code={code}&redirect_uri={INSPECTOR_CALLBACK}\
             &client_id={client_id}&code_verifier={VERIFIER}&resource={MCP}"
        )
    );
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(
        aud_of(tokens["access_token"].as_str().unwrap()),
        MCP,
        "the token a self-registered client obtains is for the MCP server, not for AXIAM"
    );
}

/// D4's other direction, asserted separately because it is the property an
/// administrator's client relies on: registering through the admin API does
/// **not** force a consent hop. This is I1 for the consent gate.
#[actix_rt::test]
async fn d4_an_administrators_client_still_needs_no_consent() {
    let f = setup().await;
    let app = test_app!(f);

    let (status, created) = admin!(
        app,
        f,
        post,
        "/api/v1/oauth2-clients",
        json!({
            "name": "admin-rp",
            "redirect_uris": ["https://rp.example.com/callback"],
            "grant_types": ["authorization_code"],
            "scopes": ["openid"],
            "token_endpoint_auth_method": "none",
        })
    );
    assert_eq!(status, 201, "{created}");
    let client_id = created["client_id"].as_str().unwrap();

    let challenge = pkce_challenge(VERIFIER);
    let (status, location) = get_authorize!(
        app,
        f,
        format!(
            "response_type=code&client_id={client_id}\
             &redirect_uri=https%3A%2F%2Frp.example.com%2Fcallback&scope=openid\
             &code_challenge={challenge}&code_challenge_method=S256"
        )
    );
    assert_eq!(status, 302);
    let location = location.unwrap();
    assert!(
        param(&location, "code").is_some(),
        "an administrator's client takes the path it always took: {location}"
    );
}

/// The consent covers the scope set the user was shown, so a client that later
/// asks for more is asked again rather than inheriting.
#[actix_rt::test]
async fn d4_a_widened_scope_set_re_prompts() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);

    let (_, registered) = register!(app, f, inspector_registration());
    let client_id = registered["client_id"].as_str().unwrap().to_owned();

    // Consent to `openid` alone.
    let (status, _) = admin!(
        app,
        f,
        post,
        "/api/v1/account/consents/oidc-scopes",
        json!({ "client_id": client_id, "scopes": ["openid"] })
    );
    assert_eq!(status, 200);

    let challenge = pkce_challenge(VERIFIER);
    let (_, location) = get_authorize!(
        app,
        f,
        format!(
            "response_type=code&client_id={client_id}&redirect_uri={INSPECTOR_CALLBACK}\
             &scope=openid&code_challenge={challenge}&code_challenge_method=S256"
        )
    );
    assert!(
        param(&location.unwrap(), "code").is_some(),
        "the consented set proceeds"
    );

    let (_, location) = get_authorize!(
        app,
        f,
        format!(
            "response_type=code&client_id={client_id}&redirect_uri={INSPECTOR_CALLBACK}\
             &scope=openid+profile&code_challenge={challenge}&code_challenge_method=S256"
        )
    );
    let location = location.unwrap();
    assert!(
        location.contains("consent"),
        "asking for more than was consented to must re-prompt: {location}"
    );
}

// ---------------------------------------------------------------------------
// initial_access_token mode
// ---------------------------------------------------------------------------

fn initial_access_token_policy() -> SetOrgSettings {
    SetOrgSettings {
        dynamic_registration: DynamicRegistrationMode::InitialAccessToken,
        ..anonymous_policy()
    }
}

#[actix_rt::test]
async fn initial_access_token_mode_refuses_without_and_accepts_with() {
    let f = setup().await;
    set_org_settings(&f, initial_access_token_policy())
        .await
        .unwrap();
    let app = test_app!(f);

    // Without: refused, and with the same shape a disabled tenant answers, so
    // a caller holding nothing cannot tell the two modes apart.
    let (status, body) = register!(app, f, inspector_registration());
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"], "invalid_request");

    // An administrator mints one.
    let (status, minted) = admin!(
        app,
        f,
        post,
        "/api/v1/oauth2-clients/registration-tokens",
        json!({ "name": "inspector-demo", "expires_in_hours": 1 })
    );
    assert_eq!(status, 201, "{minted}");
    let handle = minted["initial_access_token"].as_str().unwrap().to_owned();
    assert!(
        handle.starts_with("axiam_dcr_"),
        "the prefix is what lets a secret scanner find this: {handle}"
    );

    // With: accepted.
    let (status, registered) = register!(app, f, inspector_registration(), Some(&handle));
    assert_eq!(status, 201, "{registered}");

    // And single-use: the same handle a second time is refused.
    let (status, body) = register!(app, f, inspector_registration(), Some(&handle));
    assert_eq!(
        status, 403,
        "an initial access token authorises exactly one registration: {body}"
    );

    // The list endpoint shows it spent, and never shows a handle.
    let (status, tokens) = admin!(app, f, get, "/api/v1/oauth2-clients/registration-tokens");
    assert_eq!(status, 200);
    let row = &tokens.as_array().unwrap()[0];
    assert!(row["used_at"].is_string(), "{row}");
    assert!(
        !tokens.to_string().contains("axiam_dcr_"),
        "a handle exists in plaintext exactly once, at creation: {tokens}"
    );
}

/// Three ways of failing to present a usable token, all answered identically:
/// a caller must not be able to probe which of its guesses named a real one.
#[actix_rt::test]
async fn every_unusable_initial_access_token_is_refused_the_same_way() {
    let f = setup().await;
    set_org_settings(&f, initial_access_token_policy())
        .await
        .unwrap();
    let app = test_app!(f);

    let mut answers = Vec::new();
    for bearer in [None, Some("axiam_dcr_not-a-real-handle"), Some("garbage")] {
        let (status, body) = register!(app, f, inspector_registration(), bearer);
        answers.push((status, body["error"].clone()));
    }
    assert!(
        answers.windows(2).all(|w| w[0] == w[1]),
        "absent, wrong and malformed must be indistinguishable: {answers:?}"
    );
    assert_eq!(answers[0].0, 403);
}

/// Minting a token for a tenant that would not honour it is refused, rather
/// than handing an operator a credential that does nothing.
#[actix_rt::test]
async fn a_registration_token_is_not_minted_for_a_tenant_that_would_ignore_it() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);

    let (status, body) = admin!(
        app,
        f,
        post,
        "/api/v1/oauth2-clients/registration-tokens",
        json!({ "name": "pointless" })
    );
    assert_eq!(status, 400, "{body}");
    assert!(
        body.to_string().contains("initial_access_token"),
        "the message must say what to set: {body}"
    );
}

// ---------------------------------------------------------------------------
// Metadata validation — every negative the acceptance list names
// ---------------------------------------------------------------------------

/// One table, one assertion per row: the refusal code RFC 7591 §3.2.2 defines
/// for each shape of bad metadata.
#[actix_rt::test]
async fn each_metadata_refusal_carries_the_code_the_rfc_defines() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);

    let cases: Vec<(&str, Value, &str)> = vec![
        (
            "a software statement is refused rather than ignored",
            json!({
                "redirect_uris": [INSPECTOR_CALLBACK],
                "software_statement": "eyJhbGciOiJSUzI1NiJ9.e30.sig",
            }),
            "invalid_software_statement",
        ),
        (
            "client_credentials is not a grant this endpoint issues",
            json!({
                "redirect_uris": [INSPECTOR_CALLBACK],
                "grant_types": ["authorization_code", "client_credentials"],
            }),
            "invalid_client_metadata",
        ),
        (
            "refresh_token alone would register a client that can refresh nothing",
            json!({ "redirect_uris": [INSPECTOR_CALLBACK], "grant_types": ["refresh_token"] }),
            "invalid_client_metadata",
        ),
        (
            "an mTLS auth method names a certificate the deployment must already trust",
            json!({
                "redirect_uris": [INSPECTOR_CALLBACK],
                "token_endpoint_auth_method": "tls_client_auth",
            }),
            "invalid_client_metadata",
        ),
        (
            "an unknown auth method is not guessed at",
            json!({
                "redirect_uris": [INSPECTOR_CALLBACK],
                "token_endpoint_auth_method": "client_secret_jwt",
            }),
            "invalid_client_metadata",
        ),
        (
            "a scope outside the tenant's list",
            json!({ "redirect_uris": [INSPECTOR_CALLBACK], "scope": "openid admin" }),
            "invalid_client_metadata",
        ),
        (
            "a response_type AXIAM does not implement",
            json!({ "redirect_uris": [INSPECTOR_CALLBACK], "response_types": ["token"] }),
            "invalid_client_metadata",
        ),
        (
            "both key sources at once (RFC 7591 section 2 permits at most one)",
            json!({
                "redirect_uris": [INSPECTOR_CALLBACK],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": { "keys": [] },
                "jwks_uri": "https://client.example.com/jwks",
            }),
            "invalid_client_metadata",
        ),
        (
            "no redirect URI at all",
            json!({ "redirect_uris": [] }),
            "invalid_redirect_uri",
        ),
        (
            "a redirect URI that is not absolute",
            json!({ "redirect_uris": ["/oauth/callback"] }),
            "invalid_redirect_uri",
        ),
        (
            "a redirect URI with a fragment (RFC 6749 section 3.1.2)",
            json!({ "redirect_uris": ["https://rp.example.com/cb#frag"] }),
            "invalid_redirect_uri",
        ),
        (
            "plaintext http on a host that is not loopback",
            json!({ "redirect_uris": ["http://rp.example.com/cb"] }),
            "invalid_redirect_uri",
        ),
        (
            "a host outside the tenant's glob",
            json!({ "redirect_uris": ["https://rp.example.com/cb"] }),
            "invalid_redirect_uri",
        ),
    ];

    for (why, body, expected) in cases {
        let (status, answer) = register!(app, f, body);
        assert_eq!(answer["error"], expected, "{why}: got {answer}");
        assert_eq!(status, 400, "{why}");
        assert!(
            !answer["error_description"].as_str().unwrap().is_empty(),
            "{why}: a refusal with no explanation is one nobody can act on"
        );
    }
}

/// The host glob, exercised through the endpoint rather than only as a unit:
/// the pattern admits a label and refuses a lookalike suffix.
#[actix_rt::test]
async fn the_redirect_host_glob_admits_a_label_and_refuses_a_lookalike() {
    let f = setup().await;
    set_org_settings(
        &f,
        SetOrgSettings {
            dcr_allowed_redirect_hosts: vec!["*.example.com".into()],
            ..anonymous_policy()
        },
    )
    .await
    .unwrap();
    let app = test_app!(f);

    for (uri, accepted) in [
        ("https://mcp.example.com/cb", true),
        ("https://a.b.example.com/cb", true),
        // The dot is part of the pattern, so this is not a suffix match.
        ("https://evil-example.com/cb", false),
        // The pattern says there is a label there.
        ("https://example.com/cb", false),
        ("https://example.com.attacker.test/cb", false),
    ] {
        let (status, body) = register!(
            app,
            f,
            json!({ "client_name": "glob", "redirect_uris": [uri] })
        );
        if accepted {
            assert_eq!(status, 201, "{uri} should be accepted: {body}");
        } else {
            assert_eq!(status, 400, "{uri} must not be accepted: {body}");
            assert_eq!(body["error"], "invalid_redirect_uri");
        }
    }
}

/// The loopback hosts are accepted with the tenant's glob empty, which is the
/// default and the state every desktop MCP client registers under.
#[actix_rt::test]
async fn the_loopback_hosts_need_no_glob_entry() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);

    // All three, including `http://[::1]/…`, which T21.4 recorded here as a
    // finding rather than an omission and left refused: `validate_redirect_uris`
    // compared the host against the bare `"::1"` while `url::Url::host_str`
    // returns an IPv6 literal **with** its brackets, so no `[::1]` URI could be
    // registered through either endpoint and the matcher's IPv6 arm was
    // unreachable. Closed as a bug fix, in its own commit, because a validator
    // that refuses what its own error message says it allows was never a
    // decision — see the T21.8 fix plan §6 for why that is a bug and not an I1
    // breach. Nothing in MCP depended on the gap: Claude Code registers
    // `localhost` and VS Code registers `127.0.0.1`.
    for uri in [
        "http://127.0.0.1:6274/oauth/callback",
        "http://localhost:33418/callback",
        "http://[::1]:33418/callback",
    ] {
        let (status, body) = register!(
            app,
            f,
            json!({ "client_name": "loopback", "redirect_uris": [uri] })
        );
        assert_eq!(status, 201, "{uri} must register with no glob set: {body}");
    }
}

/// RFC 7591 §2's defaults, applied rather than invented — checked through the
/// wire, because a client that omitted a member will read the same RFC to
/// decide what it got.
#[actix_rt::test]
async fn an_omitted_member_gets_the_rfc_default() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);

    let (status, registered) = register!(
        app,
        f,
        json!({ "redirect_uris": ["http://127.0.0.1:1234/cb"] })
    );
    assert_eq!(status, 201, "{registered}");
    assert_eq!(registered["grant_types"], json!(["authorization_code"]));
    assert_eq!(
        registered["token_endpoint_auth_method"],
        "client_secret_basic"
    );
    assert_eq!(
        registered["scope"], "",
        "a client that asked for nothing gets nothing"
    );
    // A confidential default means a secret, and §3.2.1's `0`.
    assert!(registered["client_secret"].is_string(), "{registered}");
    assert_eq!(registered["client_secret_expires_at"], 0);
}

/// I5 / D5 — a self-registered client can never be financial-grade, and cannot
/// claim to be an administrator's. Both are *forced* rather than validated, so
/// the test reads the stored row.
#[actix_rt::test]
async fn i5_a_registration_cannot_claim_a_profile_or_a_provenance() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);

    let mut body = inspector_registration();
    body["profile"] = json!("fapi2");
    body["managed_by"] = json!("admin");
    let (status, registered) = register!(app, f, body);
    assert_eq!(
        status, 201,
        "the members are ignored, not refused (RFC 7591 section 3.2.1 permits a server to \
         replace requested metadata): {registered}"
    );

    let client_id = registered["client_id"].as_str().unwrap();
    let (_, list) = admin!(app, f, get, "/api/v1/oauth2-clients");
    let stored = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["client_id"] == client_id)
        .expect("the registered client is listed");
    assert_eq!(
        stored["profile"], "standard",
        "a client nobody vetted cannot carry the FAPI profile"
    );
}

// ---------------------------------------------------------------------------
// Abuse controls
// ---------------------------------------------------------------------------

/// The per-tenant ceiling. Set to one so the test is about the boundary rather
/// than about twenty registrations.
#[actix_rt::test]
async fn dcr_max_clients_bounds_what_a_stranger_can_create() {
    let f = setup().await;
    set_org_settings(
        &f,
        SetOrgSettings {
            dcr_max_clients: 1,
            ..anonymous_policy()
        },
    )
    .await
    .unwrap();
    let app = test_app!(f);

    let (status, _) = register!(app, f, inspector_registration());
    assert_eq!(status, 201);

    let (status, body) = register!(app, f, inspector_registration());
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"], "invalid_request");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("limit"),
        "{body}"
    );

    // The ceiling counts self-registered clients only: an administrator can
    // still create as many as they like.
    let (status, created) = admin!(
        app,
        f,
        post,
        "/api/v1/oauth2-clients",
        json!({
            "name": "admin-rp",
            "redirect_uris": ["https://rp.example.com/cb"],
            "grant_types": ["authorization_code"],
            "scopes": ["openid"],
        })
    );
    assert_eq!(
        status, 201,
        "dcr_max_clients must not bound the admin API: {created}"
    );
}

/// The per-IP rate limit, driven until it fires. `dcr_per_min` is 5 by
/// default, which is the smallest limit in AXIAM and deliberately so: this is
/// the only endpoint that writes for a caller holding no credential.
#[actix_rt::test]
async fn the_registration_endpoint_is_rate_limited_per_ip() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    // The one test that must run on the SHIPPED limit rather than the
    // permissive one the rest of this file uses.
    let app = test_app!(f, RateLimitConfig::default());

    let default_limit = RateLimitConfig::default().dcr_per_min;
    assert_eq!(
        default_limit, 5,
        "the documented default; if this changes, the docs and this loop change with it"
    );

    // One more attempt than the limit admits. A refused registration still
    // costs a token from the bucket, which is the point: the limit bounds
    // attempts, not successes.
    let mut saw_429 = false;
    for _ in 0..=default_limit {
        let (status, _) = register!(app, f, inspector_registration());
        if status == 429 {
            saw_429 = true;
            break;
        }
    }
    assert!(
        saw_429,
        "the endpoint must answer 429 once the per-IP bucket is empty"
    );
}

// ---------------------------------------------------------------------------
// I9 — the parity the plan says is owed twice over
// ---------------------------------------------------------------------------

/// The unauthenticated route reaches its handler rather than the authorization
/// middleware. Asserted through the app rather than against `PUBLIC_PATHS`,
/// because what matters is the behaviour: a `403` with an RFC 7591 body is the
/// handler answering, and a `401` would be the middleware.
#[actix_rt::test]
async fn i9_the_registration_endpoint_is_reachable_without_a_credential() {
    let f = setup().await;
    let app = test_app!(f);

    let (status, body) = register!(app, f, inspector_registration());
    assert_eq!(
        status, 403,
        "not 401: the endpoint is public and the tenant's policy is what refuses"
    );
    assert!(
        body.get("error").is_some() && body.get("error_description").is_some(),
        "the body is RFC 7591 section 3.2.2 shaped, which only the handler produces: {body}"
    );
}

/// The body limit, which is the one hardening control on this endpoint that is
/// not visible from the handler: the route is outside the `/api/v1` scope that
/// carries a limit, so without an explicit one it would inherit actix's 2 MiB
/// default — on the one route that takes a JSON body from a caller holding no
/// credential.
#[actix_rt::test]
async fn an_oversized_registration_body_is_refused_before_the_handler() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);

    // Comfortably past 16 KiB, in a member the server would otherwise ignore.
    let mut body = inspector_registration();
    body["client_uri"] = json!("x".repeat(64 * 1024));

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/register?tenant_id={}", f.tenant_id))
        .set_json(&body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        413,
        "a body past the limit is refused by the extractor, before the policy read"
    );

    // And the limit is generous enough for a real registration carrying an
    // inline key set, which is the largest legitimate member.
    let mut with_jwks = inspector_registration();
    with_jwks["token_endpoint_auth_method"] = json!("private_key_jwt");
    with_jwks["jwks"] = json!({ "keys": [] });
    let (status, answer) = register!(app, f, with_jwks);
    assert_ne!(
        status, 413,
        "an ordinary registration must fit comfortably inside the limit: {answer}"
    );
}

/// The endpoint that MINTS a token is administrative and stays behind the
/// middleware, even though the endpoint that SPENDS one does not.
#[actix_rt::test]
async fn i9_minting_a_registration_token_still_needs_a_credential() {
    let f = setup().await;
    let app = test_app!(f);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/oauth2-clients/registration-tokens")
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({ "name": "unauthenticated" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

// ---------------------------------------------------------------------------
// T23.4.1 — RFC 7592, the client configuration endpoint
// ---------------------------------------------------------------------------

/// A client configuration request: `GET`, `PUT` or `DELETE` on `uri`, with an
/// optional `Authorization` header value and an optional JSON body. Returns
/// `(status, WWW-Authenticate, body)`.
macro_rules! manage {
    ($app:expr, $method:ident, $uri:expr, $authz:expr) => {
        manage!($app, $method, $uri, $authz, None::<Value>)
    };
    ($app:expr, $method:ident, $uri:expr, $authz:expr, $json:expr) => {{
        let mut req = test::TestRequest::$method()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri($uri);
        let authz: Option<String> = $authz;
        if let Some(value) = authz {
            req = req.insert_header(("Authorization", value));
        }
        let json: Option<Value> = $json;
        if let Some(body) = json {
            req = req.set_json(body);
        }
        let resp = test::call_service(&$app, req.to_request()).await;
        let status = resp.status().as_u16();
        let challenge = resp
            .headers()
            .get("WWW-Authenticate")
            .map(|v| v.to_str().unwrap().to_owned());
        let body = test::read_body(resp).await;
        (
            status,
            challenge,
            serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null),
        )
    }};
}

fn bearer(token: &str) -> Option<String> {
    Some(format!("Bearer {token}"))
}

/// The path-and-query of a `registration_client_uri`, for the test client.
fn config_path(registered: &Value) -> String {
    registered["registration_client_uri"]
        .as_str()
        .unwrap_or_else(|| panic!("no registration_client_uri in {registered}"))
        .strip_prefix(ISSUER)
        .expect("the URI is under the issuer")
        .to_owned()
}

fn rat(registered: &Value) -> String {
    registered["registration_access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("no registration_access_token in {registered}"))
        .to_owned()
}

/// The body a client sends back after a read: what it was told, minus the
/// four members RFC 7592 §2.2 says it MUST NOT send.
fn update_from(read: &Value) -> Value {
    let mut body = read.clone();
    let object = body.as_object_mut().unwrap();
    for member in [
        "registration_access_token",
        "registration_client_uri",
        "client_secret_expires_at",
        "client_id_issued_at",
    ] {
        object.remove(member);
    }
    body
}

/// **Acceptance: the round trip.** Register, read, replace the redirect URIs,
/// read the change back, delete, and find the registration gone.
#[actix_rt::test]
async fn rfc7592_register_read_update_delete_round_trip() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);

    let (status, registered) = register!(app, f, inspector_registration());
    assert_eq!(status, 201, "{registered}");
    let uri = config_path(&registered);
    let token = rat(&registered);
    let client_id = registered["client_id"].as_str().unwrap().to_owned();

    // Read: the registration as stored, and no secret of either kind.
    let (status, _, read) = manage!(app, get, &uri, bearer(&token));
    assert_eq!(status, 200, "{read}");
    assert_eq!(read["client_id"], client_id);
    assert_eq!(read["redirect_uris"], json!([INSPECTOR_CALLBACK]));
    assert_eq!(
        read["registration_client_uri"],
        registered["registration_client_uri"]
    );
    assert!(
        read.get("registration_access_token").is_none(),
        "a read never returns the token: {read}"
    );
    assert!(read.get("client_secret").is_none());

    // Update: a full replacement with new redirect URIs.
    let mut body = update_from(&read);
    body["redirect_uris"] = json!(["http://127.0.0.1:7000/new-callback"]);
    let (status, _, updated) = manage!(app, put, &uri, bearer(&token), Some(body));
    assert_eq!(status, 200, "{updated}");
    assert_eq!(
        updated["redirect_uris"],
        json!(["http://127.0.0.1:7000/new-callback"])
    );
    let rotated = rat(&updated);
    assert_ne!(rotated, token, "a successful update rotates the token");

    // The change reads back, under the new token.
    let (status, _, reread) = manage!(app, get, &uri, bearer(&rotated));
    assert_eq!(status, 200, "{reread}");
    assert_eq!(
        reread["redirect_uris"],
        json!(["http://127.0.0.1:7000/new-callback"])
    );

    // Delete, then nothing is there — and the answer is the same 401 a wrong
    // token gets, not a 404.
    let (status, _, body) = manage!(app, delete, &uri, bearer(&rotated));
    assert_eq!(status, 204, "{body}");
    let (status, challenge, body) = manage!(app, get, &uri, bearer(&rotated));
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], "invalid_token");
    assert_eq!(challenge.as_deref(), Some("Bearer error=\"invalid_token\""));
    let (status, _, _) = manage!(app, delete, &uri, bearer(&rotated));
    assert_eq!(status, 401, "a second DELETE finds nothing to delete");
}

/// **F4 P23W1-02.** The authentication scheme is case-insensitive (RFC 9110
/// §11.1; RFC 6750 §2.1 inherits it), so `bearer` and `BEARER` name the same
/// credential `Bearer` does — before the review a lower-case scheme was read
/// as *no* token and answered with the bare challenge, which a client follows
/// by discarding a token that was good. A scheme with no token after it, and a
/// different scheme, are still no token.
#[actix_rt::test]
async fn p23w1_02_the_bearer_scheme_is_matched_case_insensitively() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);
    let (status, registered) = register!(app, f, inspector_registration());
    assert_eq!(status, 201, "{registered}");
    let uri = config_path(&registered);
    let token = rat(&registered);

    for header in [
        format!("bearer {token}"),
        format!("BEARER {token}"),
        format!("Bearer  {token}"),
    ] {
        let (status, _, body) = manage!(app, get, &uri, Some(header.clone()));
        assert_eq!(status, 200, "{header:?}: {body}");
    }
    for header in [
        "Bearer".to_owned(),
        "Bearer ".to_owned(),
        "bearer    ".to_owned(),
        format!("Basic {token}"),
        format!("Bearer{token}"),
    ] {
        let (status, challenge, _) = manage!(app, get, &uri, Some(header.clone()));
        assert_eq!(status, 401, "{header:?}");
        assert_eq!(challenge.as_deref(), Some("Bearer"), "{header:?}");
    }
}

/// **F4 pin.** The 16 KiB body limit holds on `PUT` as it does on `POST
/// /oauth2/register`, and it is applied by the extractor — before the token is
/// looked at, so an oversized body costs no datastore read — without touching
/// the registration.
#[actix_rt::test]
async fn p23w1_an_oversized_update_is_refused_before_it_is_read() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);
    let (status, registered) = register!(app, f, inspector_registration());
    assert_eq!(status, 201, "{registered}");
    let uri = config_path(&registered);
    let token = rat(&registered);

    let mut body = update_from(&registered);
    body["client_name"] = json!("x".repeat(64 * 1024));
    let (status, _, _) = manage!(app, put, &uri, bearer(&token), Some(body));
    assert_eq!(status, 413);

    let (status, _, read) = manage!(app, get, &uri, bearer(&token));
    assert_eq!(status, 200, "the presented token was not rotated: {read}");
    assert_eq!(read["client_name"], registered["client_name"]);
}

/// **Acceptance: rotation.** After a `PUT` the presented token is dead for
/// every operation and the returned one works.
#[actix_rt::test]
async fn rfc7592_an_update_rotates_the_token_and_the_old_one_dies() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);
    let (_, registered) = register!(app, f, inspector_registration());
    let uri = config_path(&registered);
    let old = rat(&registered);

    let (_, _, read) = manage!(app, get, &uri, bearer(&old));
    let (status, _, updated) = manage!(app, put, &uri, bearer(&old), Some(update_from(&read)));
    assert_eq!(status, 200, "{updated}");
    let new = rat(&updated);

    let (status, _, _) = manage!(app, get, &uri, bearer(&old));
    assert_eq!(status, 401, "the old token cannot read");
    let (status, _, _) = manage!(app, put, &uri, bearer(&old), Some(update_from(&read)));
    assert_eq!(status, 401, "the old token cannot update");
    let (status, _, _) = manage!(app, delete, &uri, bearer(&old));
    assert_eq!(status, 401, "the old token cannot delete");
    let (status, _, _) = manage!(app, get, &uri, bearer(&new));
    assert_eq!(status, 200, "the new token can");
}

/// **Acceptance: racing updates.** Several `PUT`s presenting one token,
/// submitted together: exactly one wins, and every loser gets the `401` a
/// rotated-away token gets.
#[actix_rt::test]
async fn rfc7592_racing_updates_on_one_token_have_one_winner() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);
    let (_, registered) = register!(app, f, inspector_registration());
    let uri = config_path(&registered);
    let token = rat(&registered);
    let (_, _, read) = manage!(app, get, &uri, bearer(&token));

    let requests: Vec<_> = (0..4)
        .map(|i| {
            let mut body = update_from(&read);
            body["client_name"] = json!(format!("racer-{i}"));
            test::TestRequest::put()
                .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
                .uri(&uri)
                .insert_header(("Authorization", format!("Bearer {token}")))
                .set_json(body)
                .to_request()
        })
        .collect();
    let responses =
        futures::future::join_all(requests.into_iter().map(|r| test::call_service(&app, r))).await;
    let statuses: Vec<u16> = responses.iter().map(|r| r.status().as_u16()).collect();
    assert_eq!(
        statuses.iter().filter(|s| **s == 200).count(),
        1,
        "exactly one of four concurrent updates on one token may win; got {statuses:?}"
    );
    assert!(
        statuses.iter().all(|s| *s == 200 || *s == 401),
        "every loser is a 401, never a 500: {statuses:?}"
    );
}

/// **Acceptance: who is refused.** Another client's management token, the
/// end user's access token, a client secret, no token at all, and a token in
/// the query string.
#[actix_rt::test]
async fn rfc7592_only_this_clients_management_token_is_accepted() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);
    let (_, mine) = register!(app, f, inspector_registration());
    let (_, theirs) = register!(app, f, inspector_registration());
    let mut confidential = inspector_registration();
    confidential["token_endpoint_auth_method"] = json!("client_secret_basic");
    let (status, secret_client) = register!(app, f, confidential);
    assert_eq!(status, 201, "the confidential registration must succeed");
    let uri = config_path(&mine);

    for (label, authz) in [
        ("another client's management token", bearer(&rat(&theirs))),
        ("the end user's access token", bearer(&f.user_token)),
        (
            "a client secret presented as a bearer",
            bearer(secret_client["client_secret"].as_str().unwrap()),
        ),
        (
            "HTTP Basic client credentials",
            Some(format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!(
                    "{}:{}",
                    secret_client["client_id"].as_str().unwrap(),
                    secret_client["client_secret"].as_str().unwrap()
                ))
            )),
        ),
    ] {
        for method in ["GET", "DELETE"] {
            let (status, challenge, body) = if method == "GET" {
                manage!(app, get, &uri, authz.clone())
            } else {
                manage!(app, delete, &uri, authz.clone())
            };
            assert_eq!(status, 401, "{label} ({method}): {body}");
            assert_eq!(body["error"], "invalid_token", "{label}");
            assert!(
                challenge.unwrap_or_default().starts_with("Bearer"),
                "{label}"
            );
        }
    }

    // No token: 401, with the bare challenge RFC 6750 §3.1 asks for.
    let (status, challenge, _) = manage!(app, get, &uri, None);
    assert_eq!(status, 401);
    assert_eq!(challenge.as_deref(), Some("Bearer"));

    // In the query string: refused, even beside the right header.
    let leaked = format!("{uri}&access_token={}", rat(&mine));
    let (status, _, body) = manage!(app, get, &leaked, None);
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_request");
    let (status, _, _) = manage!(app, get, &leaked, bearer(&rat(&mine)));
    assert_eq!(
        status, 400,
        "a token in a URL is refused whatever else is presented"
    );

    // The registration survived every attempt above.
    let (status, _, _) = manage!(app, get, &uri, bearer(&rat(&mine)));
    assert_eq!(status, 200);
}

/// **Acceptance: no widening.** A `PUT` asking for a scope or a grant the
/// tenant does not offer to self-registered clients is `400
/// invalid_client_metadata`, and the token is not rotated by a refusal.
#[actix_rt::test]
async fn rfc7592_an_update_cannot_widen_beyond_the_tenants_policy() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);
    let (_, registered) = register!(app, f, inspector_registration());
    let uri = config_path(&registered);
    let token = rat(&registered);
    let (_, _, read) = manage!(app, get, &uri, bearer(&token));

    for (member, value) in [
        ("scope", json!("openid profile email")),
        (
            "grant_types",
            json!(["authorization_code", "client_credentials"]),
        ),
        (
            "grant_types",
            json!([
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:token-exchange"
            ]),
        ),
    ] {
        let mut body = update_from(&read);
        body[member] = value;
        let (status, _, refused) = manage!(app, put, &uri, bearer(&token), Some(body));
        assert_eq!(status, 400, "{member}: {refused}");
        assert_eq!(refused["error"], "invalid_client_metadata", "{member}");
    }

    // A redirect outside the host glob is the RFC 7591 redirect code.
    let mut body = update_from(&read);
    body["redirect_uris"] = json!(["https://attacker.example.net/cb"]);
    let (status, _, refused) = manage!(app, put, &uri, bearer(&token), Some(body));
    assert_eq!(status, 400);
    assert_eq!(refused["error"], "invalid_redirect_uri");

    // A body naming a member the server states, or another client.
    let mut body = update_from(&read);
    body["registration_access_token"] = json!(token);
    let (status, _, refused) = manage!(app, put, &uri, bearer(&token), Some(body));
    assert_eq!(status, 400);
    assert_eq!(refused["error"], "invalid_request");
    let mut body = update_from(&read);
    body["client_id"] = json!("oa_00000000000000000000000000000000");
    let (status, _, _) = manage!(app, put, &uri, bearer(&token), Some(body));
    assert_eq!(status, 400);

    // None of the refusals rotated anything, and none changed the row.
    let (status, _, after) = manage!(app, get, &uri, bearer(&token));
    assert_eq!(status, 200);
    assert_eq!(after["scope"], "openid profile");
    assert_eq!(
        after["grant_types"],
        json!(["authorization_code", "refresh_token"])
    );
}

/// A `PUT` can never move what a registration cannot set: the stored row's
/// profile, X7 flags, provenance and audiences stay what they were, however
/// the body asks.
#[actix_rt::test]
async fn rfc7592_an_update_cannot_change_what_a_registration_cannot_set() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);
    let (_, registered) = register!(app, f, inspector_registration());
    let uri = config_path(&registered);
    let token = rat(&registered);
    let client_id = registered["client_id"].as_str().unwrap().to_owned();
    let (_, _, read) = manage!(app, get, &uri, bearer(&token));

    let mut body = update_from(&read);
    body["profile"] = json!("fapi2");
    body["managed_by"] = json!("admin");
    body["authn_request_params"] = json!("honour");
    body["browser_sso"] = json!(true);
    body["require_par"] = json!(true);
    body["allowed_resources"] = json!(["https://elsewhere.example.com/mcp"]);
    let (status, _, updated) = manage!(app, put, &uri, bearer(&token), Some(body));
    assert_eq!(
        status, 200,
        "ignored members are ignored, not refused: {updated}"
    );

    let (_, list) = admin!(app, f, get, "/api/v1/oauth2-clients");
    let stored = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["client_id"] == client_id)
        .expect("the client is still listed")
        .clone();
    assert_eq!(stored["profile"], "standard", "{stored}");
    assert_eq!(stored["authn_request_params"], "ignore", "{stored}");
    assert_eq!(stored["browser_sso"], false, "{stored}");
    assert_eq!(stored["require_par"], false, "{stored}");
    assert_eq!(stored["managed_by"], "dcr", "{stored}");
    assert_eq!(stored["allowed_resources"], json!([MCP]), "{stored}");
}

/// **Acceptance: deletion revokes.** A refresh token issued before the
/// `DELETE` no longer refreshes after it.
#[actix_rt::test]
async fn rfc7592_deletion_revokes_an_issued_refresh_token() {
    use axiam_core::repository::RefreshTokenRepository;

    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);
    let (_, registered) = register!(app, f, inspector_registration());
    let client_id = registered["client_id"].as_str().unwrap().to_owned();

    let (status, _) = admin!(
        app,
        f,
        post,
        "/api/v1/account/consents/oidc-scopes",
        json!({ "client_id": client_id, "scopes": ["openid", "profile"] })
    );
    assert_eq!(status, 200);
    let challenge = pkce_challenge(VERIFIER);
    let (_, location) = get_authorize!(
        app,
        f,
        format!(
            "response_type=code&client_id={client_id}&redirect_uri={INSPECTOR_CALLBACK}\
             &scope=openid+profile&code_challenge={challenge}&code_challenge_method=S256\
             &resource={MCP}"
        )
    );
    let code = param(&location.unwrap(), "code").expect("a code");
    let (status, tokens) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=authorization_code&code={code}&redirect_uri={INSPECTOR_CALLBACK}\
             &client_id={client_id}&code_verifier={VERIFIER}&resource={MCP}"
        )
    );
    assert_eq!(status, 200, "{tokens}");
    let refresh = tokens["refresh_token"]
        .as_str()
        .expect("the client holds the refresh_token grant")
        .to_owned();

    let (status, _, _) = manage!(
        app,
        delete,
        &config_path(&registered),
        bearer(&rat(&registered))
    );
    assert_eq!(status, 204);

    let (status, body) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!("grant_type=refresh_token&refresh_token={refresh}&client_id={client_id}")
    );
    assert!(
        status == 400 || status == 401,
        "a deregistered client's refresh token must not refresh: {status} {body}"
    );
    assert!(body.get("access_token").is_none(), "{body}");

    // The row the refresh token names is marked revoked, not merely orphaned.
    let stored = axiam_db::repository::SurrealRefreshTokenRepository::new(f.db.clone())
        .get_by_token_hash(
            f.tenant_id,
            &axiam_auth::token::hash_refresh_token(&refresh),
        )
        .await;
    if let Ok(row) = stored {
        assert!(row.revoked, "the refresh token is revoked on delete");
    }
}

/// Deletion releases the `dcr_max_clients` slot (#471): at a quota of one, a
/// second registration succeeds once the first client deleted itself.
#[actix_rt::test]
async fn rfc7592_deletion_releases_the_registration_quota() {
    let f = setup().await;
    set_org_settings(
        &f,
        SetOrgSettings {
            dcr_max_clients: 1,
            ..anonymous_policy()
        },
    )
    .await
    .unwrap();
    let app = test_app!(f);
    let (status, first) = register!(app, f, inspector_registration());
    assert_eq!(status, 201);
    let (status, _) = register!(app, f, inspector_registration());
    assert_eq!(status, 403, "the quota is full");
    let (status, _, _) = manage!(app, delete, &config_path(&first), bearer(&rat(&first)));
    assert_eq!(status, 204);
    let (status, body) = register!(app, f, inspector_registration());
    assert_eq!(
        status, 201,
        "the deleted client's slot is free again: {body}"
    );
}

/// **Acceptance: who has no token.** An administrator's client, a CIMD shadow
/// row and a `dcr` client registered before schema v69 were never issued a
/// management token, and every route answers them as it answers an unknown
/// client: `401 invalid_token`.
#[actix_rt::test]
async fn rfc7592_clients_without_a_management_token_are_refused() {
    use axiam_core::models::oauth2_client::{
        AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateOAuth2Client, ManagedBy,
    };
    use axiam_core::repository::OAuth2ClientRepository;

    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);

    let (status, admin_client) = admin!(
        app,
        f,
        post,
        "/api/v1/oauth2-clients",
        json!({
            "name": "admin-rp",
            "redirect_uris": ["https://rp.example.com/cb"],
            "grant_types": ["authorization_code"],
            "scopes": ["openid"],
            "token_endpoint_auth_method": "none",
        })
    );
    assert_eq!(status, 201, "{admin_client}");

    let repo = axiam_db::repository::SurrealOAuth2ClientRepository::new(f.db.clone());
    let row = |managed_by| CreateOAuth2Client {
        tenant_id: f.tenant_id,
        name: "no-token".into(),
        redirect_uris: vec![INSPECTOR_CALLBACK.into()],
        grant_types: vec!["authorization_code".into()],
        scopes: vec!["openid".into()],
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        require_par: false,
        profile: ClientProfile::Standard,
        token_endpoint_auth_method: ClientAuthMethod::None,
        tls_client_auth_subject_dn: None,
        tls_client_auth_san_dns: None,
        tls_client_auth_san_uri: None,
        self_signed_tls_client_auth_thumbprints: Vec::new(),
        tls_client_certificate_bound_access_tokens: false,
        jwks: None,
        jwks_uri: None,
        dpop_bound_access_tokens: false,
        dpop_require_nonce: false,
        authn_request_params: AuthnRequestParamsMode::Ignore,
        browser_sso: false,
        allowed_resources: vec![MCP.into()],
        managed_by,
    };
    // A `dcr` row written the way every pre-v69 registration was: no digest.
    let (legacy_dcr, _) = repo.create(row(ManagedBy::Dcr)).await.unwrap();
    let cimd = repo
        .upsert_cimd_client(
            "https://publisher.example.com/client.json",
            row(ManagedBy::Cimd),
        )
        .await
        .unwrap();

    // Whatever is presented — a fresh token-shaped value, or a real token
    // belonging to some other client — the answer is the same.
    let (_, someone) = register!(app, f, inspector_registration());
    // A CIMD `client_id` is a URL, so it reaches the route only
    // percent-encoded; unencoded, its slashes miss the route altogether —
    // the same 404 for a URL that names a shadow row as for one that names
    // nothing, so that status says nothing about existence either.
    let encoded_cimd: String = cimd
        .client_id
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect();
    let token = rat(&someone);
    let raw_cimd = format!(
        "/oauth2/register/{}?tenant_id={}",
        cimd.client_id, f.tenant_id
    );
    let raw_unknown = format!(
        "/oauth2/register/https://nobody.example.com/x.json?tenant_id={}",
        f.tenant_id
    );
    assert_eq!(
        manage!(app, get, &raw_cimd, bearer(&token)).0,
        manage!(app, get, &raw_unknown, bearer(&token)).0,
        "an unencoded URL-shaped client_id is answered the same whether or not it exists"
    );
    for client_id in [
        admin_client["client_id"].as_str().unwrap(),
        legacy_dcr.client_id.as_str(),
        encoded_cimd.as_str(),
    ] {
        let uri = format!("/oauth2/register/{client_id}?tenant_id={}", f.tenant_id);
        for token in [
            axiam_oauth2::dcr::mint_registration_access_token().0,
            rat(&someone),
        ] {
            let (status, _, body) = manage!(app, get, &uri, bearer(&token));
            assert_eq!(status, 401, "{client_id}: {body}");
            assert_eq!(body["error"], "invalid_token");
            let (status, _, _) = manage!(app, delete, &uri, bearer(&token));
            assert_eq!(status, 401, "{client_id}");
        }
    }
    // And an unknown client is answered identically — no 404.
    let uri = format!(
        "/oauth2/register/oa_ffffffffffffffffffffffffffffffff?tenant_id={}",
        f.tenant_id
    );
    let (status, _, body) = manage!(app, get, &uri, bearer(&rat(&someone)));
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], "invalid_token");
}

/// **Acceptance: tenant scoping.** A token for a client in tenant A, used with
/// tenant B selected, is `401` — and so is A's own token on A's client when B
/// is the tenant the request resolved.
#[actix_rt::test]
async fn rfc7592_a_token_is_refused_under_another_tenant() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let tenant_b = SurrealTenantRepository::new(f.db.clone())
        .create(CreateTenant {
            organization_id: f.org_id,
            kind: TenantKind::Standard,
            name: "T23.4.1 Tenant B".into(),
            slug: "tenant-t23-4-1-b".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let app = test_app!(f);
    let (_, registered) = register!(app, f, inspector_registration());
    let client_id = registered["client_id"].as_str().unwrap();
    let token = rat(&registered);

    let cross = format!("/oauth2/register/{client_id}?tenant_id={}", tenant_b.id);
    let (status, _, body) = manage!(app, get, &cross, bearer(&token));
    assert_eq!(status, 401, "{body}");
    let (status, _, _) = manage!(app, delete, &cross, bearer(&token));
    assert_eq!(status, 401);
    let (status, _, _) = manage!(
        app,
        put,
        &cross,
        bearer(&token),
        Some(json!({ "client_id": client_id, "redirect_uris": [INSPECTOR_CALLBACK] }))
    );
    assert_eq!(status, 401);

    // Still alive in its own tenant.
    let (status, _, _) = manage!(app, get, &config_path(&registered), bearer(&token));
    assert_eq!(status, 200);
}

/// **Acceptance: rate limiting (plan §7 rule 6).** The three routes are behind
/// the registration limiter's preset, in one bucket: on the shipped
/// `dcr_per_min` of five, the sixth request — whichever method — is `429`.
/// Mixed methods, so a limiter wired to one of the three would not pass.
#[actix_rt::test]
async fn rfc7592_the_configuration_routes_are_rate_limited() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f, RateLimitConfig::default());
    let limit = RateLimitConfig::default().dcr_per_min;
    assert_eq!(limit, 5);

    let (status, registered) = register!(app, f, inspector_registration());
    assert_eq!(status, 201);
    let uri = config_path(&registered);
    let wrong = bearer("not-the-token");

    // Five refused requests, across all three methods, each spending a token
    // from the bucket. The limit bounds attempts, not successes.
    let mut statuses = Vec::new();
    statuses.push(manage!(app, get, &uri, wrong.clone()).0);
    statuses.push(manage!(app, put, &uri, wrong.clone(), Some(json!({}))).0);
    statuses.push(manage!(app, delete, &uri, wrong.clone()).0);
    statuses.push(manage!(app, put, &uri, wrong.clone(), Some(json!({}))).0);
    statuses.push(manage!(app, delete, &uri, wrong.clone()).0);
    assert!(statuses.iter().all(|s| *s == 401), "{statuses:?}");

    // The sixth is refused by the limiter — even with the right token.
    let (status, _, _) = manage!(app, get, &uri, bearer(&rat(&registered)));
    assert_eq!(
        status, 429,
        "the configuration routes share one per-IP bucket"
    );

    // And the registration endpoint's own bucket was not the one spent.
    let (status, _) = register!(app, f, inspector_registration());
    assert_eq!(status, 201, "a separate bucket from POST /oauth2/register");
}

/// **Acceptance: redaction.** No management token — the one registration
/// returned, nor the one an update rotated in, nor a wrong one — appears in a
/// log line or an audit row, on the served path or the refused path; and
/// every operation is audited.
#[actix_rt::test]
async fn rfc7592_the_management_token_reaches_no_log_and_no_audit_row() {
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(LogBuf(log.clone()))
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);

    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);
    let (_, registered) = register!(app, f, inspector_registration());
    let uri = config_path(&registered);
    let first = rat(&registered);
    let wrong = axiam_oauth2::dcr::mint_registration_access_token().0;

    let (_, _, read) = manage!(app, get, &uri, bearer(&first));
    let (_, _, _) = manage!(app, get, &uri, bearer(&wrong));
    let (status, _, updated) = manage!(app, put, &uri, bearer(&first), Some(update_from(&read)));
    assert_eq!(status, 200);
    let second = rat(&updated);
    let (status, _, _) = manage!(app, delete, &uri, bearer(&second));
    assert_eq!(status, 204);

    drop(guard);
    let captured = String::from_utf8_lossy(&log.lock().unwrap().clone()).into_owned();
    let (status, audit) = admin!(app, f, get, "/api/v1/audit-logs?limit=100");
    assert_eq!(status, 200, "{audit}");
    let audit_text = audit.to_string();

    for token in [&first, &second, &wrong] {
        let digest = axiam_auth::token::hash_refresh_token(token);
        for (sink, text) in [("log", &captured), ("audit", &audit_text)] {
            assert!(!text.contains(token.as_str()), "a token reached the {sink}");
            assert!(!text.contains(&digest), "a token digest reached the {sink}");
        }
    }

    let actions: Vec<&str> = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["action"].as_str())
        .collect();
    for action in [
        "oauth2.client_configuration_read",
        "oauth2.client_configuration_refused",
        "oauth2.client_configuration_updated",
        "oauth2.client_configuration_deleted",
    ] {
        assert!(
            actions.contains(&action),
            "{action} missing from {actions:?}"
        );
    }
}

#[derive(Clone)]
struct LogBuf(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuf {
    type Writer = LogBuf;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// A tenant that turned registration off still lets its clients read and
/// delete themselves, and refuses a replacement `403`, as it would refuse the
/// registration the replacement re-decides.
#[actix_rt::test]
async fn rfc7592_a_tenant_that_disabled_registration_refuses_updates_but_not_reads_or_deletes() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);
    let (_, registered) = register!(app, f, inspector_registration());
    let uri = config_path(&registered);
    let token = rat(&registered);
    let (_, _, read) = manage!(app, get, &uri, bearer(&token));

    set_org_settings(
        &f,
        SetOrgSettings {
            dynamic_registration: DynamicRegistrationMode::Disabled,
            ..anonymous_policy()
        },
    )
    .await
    .unwrap();

    let (status, _, body) = manage!(app, put, &uri, bearer(&token), Some(update_from(&read)));
    assert_eq!(status, 403, "{body}");
    let (status, _, _) = manage!(app, get, &uri, bearer(&token));
    assert_eq!(status, 200, "the token was not rotated by the refusal");
    let (status, _, _) = manage!(app, delete, &uri, bearer(&token));
    assert_eq!(status, 204);
}

/// **T23.1.5 (X7.8).** The RFC 7591 §2 default is `client_secret_basic`, and the
/// audience for that default is a third-party relying party that has read the
/// RFC and nothing of AXIAM. So the whole path is walked: register with no
/// `token_endpoint_auth_method`, take the secret the response returns, and
/// authenticate at an authenticating endpoint with an RFC 6749 §2.3.1 header.
/// The registered method then decides, in the other direction too: the same
/// secret in the form body of that client is refused.
#[actix_rt::test]
async fn a_default_registered_client_authenticates_with_its_basic_header() {
    let f = setup().await;
    set_org_settings(&f, anonymous_policy()).await.unwrap();
    let app = test_app!(f);

    let (status, registered) = register!(
        app,
        f,
        json!({ "redirect_uris": ["http://127.0.0.1:1234/cb"] })
    );
    assert_eq!(status, 201, "registration");
    assert_eq!(
        registered["token_endpoint_auth_method"],
        "client_secret_basic"
    );
    let client_id = registered["client_id"].as_str().unwrap().to_owned();
    let secret = registered["client_secret"].as_str().unwrap().to_owned();

    // The §2.3.1 spelling: each half form-urlencoded, then base64.
    let encode = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    let header = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!(
            "{}:{}",
            encode(&client_id),
            encode(&secret)
        ))
    );

    let post = |authorization: Option<String>, body: String| {
        let app = &app;
        let tenant_id = f.tenant_id;
        async move {
            let mut req = test::TestRequest::post()
                .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
                .uri(&format!("/oauth2/introspect?tenant_id={tenant_id}"))
                .insert_header(("content-type", "application/x-www-form-urlencoded"));
            if let Some(value) = authorization {
                req = req.insert_header(("Authorization", value));
            }
            let resp = test::call_service(app, req.set_payload(body).to_request()).await;
            resp.status().as_u16()
        }
    };

    assert_eq!(
        post(
            Some(header),
            format!("client_id={client_id}&token=not-a-token")
        )
        .await,
        200,
        "the header authenticates the client its registration says it is"
    );
    assert_eq!(
        post(
            None,
            format!(
                "client_id={client_id}&client_secret={}&token=not-a-token",
                encode(&secret)
            )
        )
        .await,
        401,
        "the same secret in the body of a client_secret_basic client authenticates nothing"
    );
}
