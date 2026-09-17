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
    // RFC 7592 is deferred, so neither member is promised.
    assert!(registered.get("registration_access_token").is_none());
    assert!(registered.get("registration_client_uri").is_none());

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
