//! **W7 — the `address` and `phone` sensitive scopes**
//! (`claude_dev/basic-op-gap-plan.md` §4.8 G8, tests T8.1–T8.6, matrix rows
//! M8 and M10).
//!
//! Two categories of personal data — a postal address and a telephone number —
//! that AXIAM holds for no operational reason of its own. Nothing
//! authenticates against them, nothing is sent to them, nothing is keyed by
//! them. They exist to be released to a relying party the end user has agreed
//! to, and the whole of this wave is the machinery that decides whether that
//! has happened.
//!
//! # What is asserted, and why in this order
//!
//! Four gates, and each test below closes one and then proves the others still
//! close on their own:
//!
//! 1. the tenant switch (T8.1) — off by default, and it outranks a recorded
//!    consent;
//! 2. per-client registration — no client could register these scopes before
//!    W7, which is invariant 4 for this whole gap and is asserted rather than
//!    assumed;
//! 3. consent (T8.2, T8.3, T8.4), re-read at **every** release rather than
//!    once at authorization, which is what makes withdrawal immediate;
//! 4. the `fapi2` refusal (T8.5, M10), at three layers.
//!
//! And one thing that must *not* happen anywhere: the claims must never reach
//! an ID token (T8.3), and their **values** must never reach an audit row
//! (T8.6).
//!
//! # The negative cases are the point
//!
//! This wave touches personal data, consent and erasure, so the tests are
//! weighted towards proving that nothing is released rather than that
//! something is. Every "released" assertion below has a twin that removes one
//! gate and asserts the claim disappears.

use std::net::SocketAddr;
use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token, issue_access_token_for_client};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::{Amr, CreateSession};
use axiam_core::models::settings::{SetTenantOverride, system_defaults};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{Address, CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, ConsentRepository, OrganizationRepository, Pagination,
    SessionRepository, SettingsRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealConsentRepository, SurrealOrganizationRepository,
    SurrealSessionRepository, SurrealSettingsRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12345";
const CSRF_TOKEN: &str = "test-csrf-token";
const REDIRECT_URI: &str = "https://rp.example.com/callback";
/// Test-only placeholder — not a real credential. gitleaks:allow
const PASSWORD: &str = "SensitiveScopesPassw0rdStrong";
const PHONE: &str = "+390212345678";
const STREET: &str = "Via Roma 1";

// ---------------------------------------------------------------------------
// Scaffolding
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
        refresh_token_lifetime_secs: 2_592_000,
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: "https://iam.example.com".into(),
        ..AuthConfig::default()
    }
}

fn an_address() -> Address {
    Address {
        street_address: Some(STREET.into()),
        locality: Some("Milano".into()),
        postal_code: Some("20121".into()),
        country: Some("Italia".into()),
        ..Address::default()
    }
}

struct Fixture {
    db: Surreal<TestDb>,
    org_id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
}

/// A deployment with one user who has both sensitive values on file.
///
/// The switch is **off**: `system_defaults()` says so, and every test that
/// needs it on turns it on explicitly. That is I3 as the shape of the fixture
/// rather than as a comment — a test that forgets to enable it tests the
/// refusal, which is the safe direction to be wrong in.
async fn setup() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Sensitive Org".into(),
            slug: "sensitive-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Sensitive Tenant".into(),
            slug: "sensitive-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    SurrealSettingsRepository::new(db.clone())
        .set_org_settings(org.id, system_defaults())
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();
    user_repo
        .update(
            tenant.id,
            user.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                phone_number: Some(Some(PHONE.into())),
                address: Some(Some(an_address())),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    Fixture {
        db,
        org_id: org.id,
        tenant_id: tenant.id,
        user_id: user.id,
    }
}

/// Turn the organization's sensitive-scope capability on.
///
/// At the **organization** level, because the model is disable-only: a tenant
/// may refuse a release its organization allows and may never authorise one it
/// forbade (`axiam_core::models::settings::OidcPolicy`).
async fn enable_sensitive_scopes(fx: &Fixture) {
    let mut defaults = system_defaults();
    defaults.sensitive_scopes_enabled = true;
    SurrealSettingsRepository::new(fx.db.clone())
        .set_org_settings(fx.org_id, defaults)
        .await
        .unwrap();
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

trait TestApp:
    actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >
{
}

impl<S> TestApp for S where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse,
            Error = actix_web::Error,
        >
{
}

fn admin_jwt(auth: &AuthConfig, fx: &Fixture) -> String {
    issue_access_token(
        fx.user_id,
        fx.tenant_id,
        fx.org_id,
        &[],
        auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap()
}

/// A session-backed token, so `/oauth2/authorize` sees a real authentication.
async fn session_token(fx: &Fixture, auth: &AuthConfig) -> String {
    let session = SurrealSessionRepository::new(fx.db.clone())
        .create(CreateSession {
            tenant_id: fx.tenant_id,
            user_id: fx.user_id,
            token_hash: Uuid::new_v4().to_string(),
            ip_address: None,
            user_agent: None,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            authenticated_at: chrono::Utc::now(),
            amr: vec![Amr::Pwd],
            browser_token_hash: None,
        })
        .await
        .unwrap();
    issue_access_token(
        fx.user_id,
        fx.tenant_id,
        fx.org_id,
        &[],
        auth,
        session.id.to_string(),
        AUD_USER,
    )
    .unwrap()
}

/// A UserInfo-facing access token: scopes, and the `client_id` the code flow
/// stamps (RFC 9068 §2.2).
fn userinfo_token(
    auth: &AuthConfig,
    fx: &Fixture,
    scopes: &[&str],
    client_id: Option<&str>,
) -> String {
    let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_owned()).collect();
    issue_access_token_for_client(
        fx.user_id,
        fx.tenant_id,
        fx.org_id,
        &scopes,
        auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
        None,
        None,
        client_id,
        // No session: these fixtures mint a token directly rather than through
        // an authorization, and the reader falls back to `jti`.
        None,
    )
    .unwrap()
}

async fn create_client(app: &impl TestApp, token: &str, body: serde_json::Value) -> String {
    create_client_with_secret(app, token, body).await.0
}

async fn create_client_with_secret(
    app: &impl TestApp,
    token: &str,
    body: serde_json::Value,
) -> (String, String) {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(body)
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 201, "client registration");
    let body: serde_json::Value = test::read_body_json(resp).await;
    (
        body["client_id"].as_str().unwrap().to_owned(),
        body["client_secret"].as_str().unwrap().to_owned(),
    )
}

/// Exchange an authorization code for tokens, returning the parsed response.
async fn exchange_code(
    app: &impl TestApp,
    tenant_id: Uuid,
    client_id: &str,
    client_secret: &str,
    code: &str,
) -> serde_json::Value {
    let form = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT_URI}\
         &client_id={client_id}&client_secret={client_secret}"
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "token exchange");
    test::read_body_json(resp).await
}

/// The payload of a JWT, decoded without verifying — this is a test reading
/// what a relying party would be handed, not a validator.
fn jwt_payload(token: &str) -> serde_json::Value {
    use base64::Engine;
    let payload = token.split('.').nth(1).expect("a three-part JWT");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url payload");
    serde_json::from_slice(&bytes).expect("JSON payload")
}

async fn try_create_client(
    app: &impl TestApp,
    token: &str,
    body: serde_json::Value,
) -> actix_web::dev::ServiceResponse {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(body)
        .to_request();
    test::call_service(app, req).await
}

/// A `standard` client on the honour lane, registered for both scopes.
fn sensitive_client() -> serde_json::Value {
    serde_json::json!({
        "name": "Sensitive Client",
        "redirect_uris": [REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"],
        "scopes": ["openid", "profile", "address", "phone"],
        "authn_request_params": "honour",
        "browser_sso": true,
    })
}

async fn authorize(
    app: &impl TestApp,
    token: &str,
    query: &str,
) -> actix_web::dev::ServiceResponse {
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/authorize?{query}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    test::call_service(app, req).await
}

fn base_query(client_id: &str, scope: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI}\
         &scope={scope}&state=w7-state"
    )
}

fn location(resp: &actix_web::dev::ServiceResponse) -> String {
    resp.headers()
        .get("Location")
        .expect("a Location header")
        .to_str()
        .unwrap()
        .to_owned()
}

fn query_param(url: &str, name: &str) -> Option<String> {
    // `Url::parse` needs an absolute URL; the consent redirect is a path.
    let absolute = if url.starts_with('/') {
        format!("https://iam.example.com{url}")
    } else {
        url.to_owned()
    };
    url::Url::parse(&absolute)
        .ok()?
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// Record the consent the SPA's screen would have recorded.
async fn grant_consent(app: &impl TestApp, token: &str, client_id: &str, scopes: &[&str]) -> u16 {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/account/consents/oidc-scopes")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "client_id": client_id, "scopes": scopes }))
        .to_request();
    test::call_service(app, req).await.status().as_u16()
}

async fn withdraw_consent(app: &impl TestApp, token: &str, client_id: &str) -> u16 {
    let req = test::TestRequest::delete()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/account/consents/oidc-scopes/{client_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    test::call_service(app, req).await.status().as_u16()
}

async fn userinfo(app: &impl TestApp, token: &str) -> serde_json::Value {
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/oauth2/userinfo")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "userinfo");
    test::read_body_json(resp).await
}

// ---------------------------------------------------------------------------
// Invariant 4 — the state of the world before this wave
// ---------------------------------------------------------------------------

/// **I4.** Nothing that exists today changes, and the reason is structural
/// rather than careful: the two scopes were unregistrable, so no client in any
/// existing deployment carries them, so no authorization request can name them
/// and pass step 5.
///
/// Asserted here rather than argued, in both halves: with the switch off a
/// registration carrying `address` is refused, and a request for it from a
/// client that does not have it registered gets `invalid_scope` — which is
/// what it got before W7 existed and for the same reason.
#[actix_web::test]
async fn i4_the_scopes_are_unregistrable_and_unrequestable_with_the_switch_off() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    let admin = admin_jwt(&auth, &fx);

    let refusal = try_create_client(&app, &admin, sensitive_client()).await;
    assert_eq!(
        refusal.status().as_u16(),
        400,
        "with the tenant switch off, a client may not register address/phone"
    );

    // A client that registered neither still gets today's answer.
    let ordinary = create_client(
        &app,
        &admin,
        serde_json::json!({
            "name": "Ordinary",
            "redirect_uris": [REDIRECT_URI],
            "grant_types": ["authorization_code"],
            "scopes": ["openid", "profile"],
        }),
    )
    .await;
    let token = session_token(&fx, &auth).await;
    let resp = authorize(&app, &token, &base_query(&ordinary, "openid+address")).await;
    let loc = location(&resp);
    assert_eq!(
        query_param(&loc, "error").as_deref(),
        Some("invalid_scope"),
        "an unregistered scope is refused exactly as it was before W7: {loc}"
    );
}

// ---------------------------------------------------------------------------
// T8.1 — the tenant switch
// ---------------------------------------------------------------------------

/// **T8.1.** Switch off ⇒ the scope cannot be registered, and cannot be
/// requested even by a client that has it registered.
///
/// The second half is the one that matters. The first is enforced at
/// registration, so a deployment that never enables the switch never gets such
/// a client; the second is what happens when an operator enables the switch,
/// registers a client, and then changes their mind. A design that only checked
/// at registration would keep releasing to every client registered while the
/// switch was on.
#[actix_web::test]
async fn t8_1_the_switch_refuses_registration_and_then_refuses_the_request() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    let admin = admin_jwt(&auth, &fx);

    // Off: registration refused.
    assert_eq!(
        try_create_client(&app, &admin, sensitive_client())
            .await
            .status()
            .as_u16(),
        400
    );

    // On: registration accepted.
    enable_sensitive_scopes(&fx).await;
    let client_id = create_client(&app, &admin, sensitive_client()).await;

    // Off again — the operator changed their mind. The registered client is
    // now asking for something its tenant no longer permits.
    SurrealSettingsRepository::new(fx.db.clone())
        .set_org_settings(fx.org_id, system_defaults())
        .await
        .unwrap();

    let token = session_token(&fx, &auth).await;
    let resp = authorize(&app, &token, &base_query(&client_id, "openid+address")).await;
    let loc = location(&resp);
    assert_eq!(
        query_param(&loc, "error").as_deref(),
        Some("invalid_scope"),
        "the switch must refuse a request from a client registered while it was on: {loc}"
    );
}

/// A **tenant** may switch the capability off for itself while its
/// organization leaves it on, and the request is then refused for that tenant.
/// The reverse — a tenant enabling what its organization forbade — is refused
/// by the settings model and asserted there.
#[actix_web::test]
async fn a_tenant_may_switch_the_capability_off_for_itself() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    let admin = admin_jwt(&auth, &fx);
    enable_sensitive_scopes(&fx).await;
    let client_id = create_client(&app, &admin, sensitive_client()).await;

    let settings = SurrealSettingsRepository::new(fx.db.clone());
    settings
        .set_tenant_override(
            fx.tenant_id,
            SetTenantOverride {
                sensitive_scopes_enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let token = session_token(&fx, &auth).await;
    let resp = authorize(&app, &token, &base_query(&client_id, "openid+phone")).await;
    assert_eq!(
        query_param(&location(&resp), "error").as_deref(),
        Some("invalid_scope")
    );
}

// ---------------------------------------------------------------------------
// T8.2 — consent, and prompt=none
// ---------------------------------------------------------------------------

/// **T8.2.** The first authorization for a client and scope set sends the
/// browser to the consent screen; `prompt=none` gets `consent_required`.
///
/// The consent redirect is to `/consent`, not `/login`, and carries no
/// `reauth`: the end user is signed in, and asking them for a password again
/// answers no question about what they are willing to share.
#[actix_web::test]
async fn t8_2_a_first_authorization_asks_and_prompt_none_is_refused() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    let admin = admin_jwt(&auth, &fx);
    enable_sensitive_scopes(&fx).await;
    let client_id = create_client(&app, &admin, sensitive_client()).await;
    let token = session_token(&fx, &auth).await;

    let resp = authorize(&app, &token, &base_query(&client_id, "openid+address")).await;
    assert_eq!(resp.status().as_u16(), 302);
    let loc = location(&resp);
    assert!(
        loc.starts_with("/consent?"),
        "the consent question goes to its own page, not the sign-in page: {loc}"
    );
    assert!(
        !loc.contains("reauth"),
        "a consent hop must not demand re-authentication: {loc}"
    );
    let return_to = query_param(&loc, "return_to").expect("a return_to");
    assert!(
        return_to.starts_with("/oauth2/authorize?"),
        "the hop must come back to the same authorization request: {return_to}"
    );

    // `prompt=none` forbids the interaction, so the relying party is told so
    // in the code OIDC Core §3.1.2.6 defines.
    let silent = authorize(
        &app,
        &token,
        &format!("{}&prompt=none", base_query(&client_id, "openid+address")),
    )
    .await;
    assert_eq!(
        query_param(&location(&silent), "error").as_deref(),
        Some("consent_required")
    );
}

/// The chain is bounded at one hop. A request that has already been to the
/// consent screen and comes back without a consent record is **answered**, not
/// sent again — `access_denied`, which is what a user who declined means.
#[actix_web::test]
async fn a_return_leg_without_consent_is_access_denied_rather_than_a_second_redirect() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    let admin = admin_jwt(&auth, &fx);
    enable_sensitive_scopes(&fx).await;
    let client_id = create_client(&app, &admin, sensitive_client()).await;
    let token = session_token(&fx, &auth).await;

    let resp = authorize(
        &app,
        &token,
        &format!(
            "{}&axiam_consent_hop=1",
            base_query(&client_id, "openid+address")
        ),
    )
    .await;
    let loc = location(&resp);
    assert!(
        loc.starts_with(REDIRECT_URI),
        "the answer goes to the relying party, not back to the consent page: {loc}"
    );
    assert_eq!(
        query_param(&loc, "error").as_deref(),
        Some("access_denied"),
        "{loc}"
    );
    assert_eq!(query_param(&loc, "state").as_deref(), Some("w7-state"));
}

/// A request asking for nothing sensitive is untouched by any of this: no
/// consent screen, no settings read that changes the answer, a code.
#[actix_web::test]
async fn a_request_without_sensitive_scopes_gets_a_code_as_before() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    let admin = admin_jwt(&auth, &fx);
    enable_sensitive_scopes(&fx).await;
    let client_id = create_client(&app, &admin, sensitive_client()).await;
    let token = session_token(&fx, &auth).await;

    let resp = authorize(&app, &token, &base_query(&client_id, "openid+profile")).await;
    let loc = location(&resp);
    assert!(loc.starts_with(REDIRECT_URI), "{loc}");
    assert!(query_param(&loc, "code").is_some(), "{loc}");
}

/// Consent is per scope **set**: a client that later widens its request
/// re-prompts rather than inheriting the narrower consent.
#[actix_web::test]
async fn widening_the_scope_set_asks_again() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    let admin = admin_jwt(&auth, &fx);
    enable_sensitive_scopes(&fx).await;
    let client_id = create_client(&app, &admin, sensitive_client()).await;
    let token = session_token(&fx, &auth).await;

    assert_eq!(
        grant_consent(&app, &token, &client_id, &["phone"]).await,
        200
    );

    // The consented set is served.
    let ok = authorize(&app, &token, &base_query(&client_id, "openid+phone")).await;
    assert!(query_param(&location(&ok), "code").is_some());

    // A wider one is not.
    let wider = authorize(
        &app,
        &token,
        &base_query(&client_id, "openid+phone+address"),
    )
    .await;
    assert!(
        location(&wider).starts_with("/consent?"),
        "adding a scope must re-prompt"
    );
}

/// Consent is per relying party: consenting for one client says nothing about
/// another, even for the same scopes and the same user.
#[actix_web::test]
async fn consent_does_not_carry_from_one_relying_party_to_another() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    let admin = admin_jwt(&auth, &fx);
    enable_sensitive_scopes(&fx).await;
    let first = create_client(&app, &admin, sensitive_client()).await;
    let mut other = sensitive_client();
    other["name"] = serde_json::json!("Second Client");
    let second = create_client(&app, &admin, other).await;
    let token = session_token(&fx, &auth).await;

    assert_eq!(grant_consent(&app, &token, &first, &["phone"]).await, 200);

    let resp = authorize(&app, &token, &base_query(&second, "openid+phone")).await;
    assert!(
        location(&resp).starts_with("/consent?"),
        "the second client must ask for itself"
    );
}

// ---------------------------------------------------------------------------
// T8.3 — release, from userinfo only
// ---------------------------------------------------------------------------

/// **T8.3.** With consent recorded, UserInfo returns the claims — and the ID
/// token does not carry them.
///
/// The ID token half is asserted by running the whole code flow and decoding
/// what came back, rather than by inspecting the claim-building function: the
/// question is what a relying party receives.
#[actix_web::test]
async fn t8_3_userinfo_releases_the_claims_and_the_id_token_does_not() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    let admin = admin_jwt(&auth, &fx);
    enable_sensitive_scopes(&fx).await;
    let (client_id, secret) = create_client_with_secret(&app, &admin, sensitive_client()).await;
    let token = session_token(&fx, &auth).await;
    assert_eq!(
        grant_consent(&app, &token, &client_id, &["address", "phone"]).await,
        200
    );

    // The authorization now proceeds to a code, and the code is spent — so
    // what is asserted below is what a relying party actually receives,
    // through the real token endpoint, rather than what a claim-builder would
    // have produced if called.
    let resp = authorize(
        &app,
        &token,
        &base_query(&client_id, "openid+address+phone"),
    )
    .await;
    let loc = location(&resp);
    let code = query_param(&loc, "code").expect("a consented request must earn a code");

    let tokens = exchange_code(&app, fx.tenant_id, &client_id, &secret, &code).await;
    let id_token = jwt_payload(tokens["id_token"].as_str().expect("an id_token"));
    for claim in ["phone_number", "phone_number_verified", "address"] {
        assert!(
            id_token.get(claim).is_none(),
            "the ID token must not carry {claim} — OIDC Core §5.4 puts scope \
             claims at UserInfo for the code flow, and an ID token is a \
             long-lived artefact relying parties log: {id_token}"
        );
    }
    let serialised = id_token.to_string();
    assert!(!serialised.contains(PHONE), "{serialised}");
    assert!(!serialised.contains(STREET), "{serialised}");

    // The same exchange stamped the access token with its relying party
    // (RFC 9068 §2.2), which is what lets UserInfo find the consent record.
    let access = tokens["access_token"].as_str().expect("an access_token");
    assert_eq!(
        jwt_payload(access)["client_id"].as_str(),
        Some(client_id.as_str())
    );

    let claims = userinfo(&app, access).await;
    assert_eq!(claims["phone_number"].as_str(), Some(PHONE));
    assert_eq!(claims["phone_number_verified"].as_bool(), Some(false));
    assert_eq!(claims["address"]["street_address"].as_str(), Some(STREET));
}

/// Only the consented scopes are released. A token carrying `phone` alone gets
/// a telephone number and no address, even though the subject has both on file
/// and consented to both.
#[actix_web::test]
async fn only_the_scopes_the_token_carries_are_released() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    let admin = admin_jwt(&auth, &fx);
    enable_sensitive_scopes(&fx).await;
    let client_id = create_client(&app, &admin, sensitive_client()).await;
    let token = session_token(&fx, &auth).await;
    assert_eq!(
        grant_consent(&app, &token, &client_id, &["phone"]).await,
        200
    );

    let access = userinfo_token(&auth, &fx, &["openid", "phone"], Some(&client_id));
    let claims = userinfo(&app, &access).await;
    assert_eq!(claims["phone_number"].as_str(), Some(PHONE));
    assert!(claims.get("address").is_none(), "{claims}");
}

/// A token that names **no** relying party — every token issued before W7, and
/// every token minted by a login rather than by the code flow — releases
/// nothing, because there is no consent record it could be matched against.
///
/// This is the fail-closed direction, and the alternative is the interesting
/// one: matching "any consent this subject ever gave" would hand a postal
/// address to a client the subject consented to a *different* client
/// receiving.
#[actix_web::test]
async fn a_token_naming_no_client_releases_nothing() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    let admin = admin_jwt(&auth, &fx);
    enable_sensitive_scopes(&fx).await;
    let client_id = create_client(&app, &admin, sensitive_client()).await;
    let token = session_token(&fx, &auth).await;
    assert_eq!(
        grant_consent(&app, &token, &client_id, &["address", "phone"]).await,
        200
    );

    let anonymous = userinfo_token(&auth, &fx, &["openid", "address", "phone"], None);
    let claims = userinfo(&app, &anonymous).await;
    assert!(claims.get("phone_number").is_none(), "{claims}");
    assert!(claims.get("address").is_none(), "{claims}");
    assert_eq!(
        claims["sub"].as_str(),
        Some(fx.user_id.to_string().as_str()),
        "the rest of the response is unaffected"
    );
}

/// The tenant switch outranks a recorded consent at the moment of release, not
/// only at the moment of authorization. An operator who turns the capability
/// off stops the release for tokens already in relying parties' hands.
#[actix_web::test]
async fn turning_the_switch_off_stops_release_for_tokens_already_issued() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    let admin = admin_jwt(&auth, &fx);
    enable_sensitive_scopes(&fx).await;
    let client_id = create_client(&app, &admin, sensitive_client()).await;
    let token = session_token(&fx, &auth).await;
    assert_eq!(
        grant_consent(&app, &token, &client_id, &["phone"]).await,
        200
    );

    let access = userinfo_token(&auth, &fx, &["openid", "phone"], Some(&client_id));
    assert!(userinfo(&app, &access).await.get("phone_number").is_some());

    SurrealSettingsRepository::new(fx.db.clone())
        .set_org_settings(fx.org_id, system_defaults())
        .await
        .unwrap();

    let after = userinfo(&app, &access).await;
    assert!(
        after.get("phone_number").is_none(),
        "the same token must stop releasing when the capability is withdrawn: {after}"
    );
}

// ---------------------------------------------------------------------------
// T8.4 — withdrawal is immediate
// ---------------------------------------------------------------------------

/// **T8.4.** Consent withdrawn ⇒ UserInfo omits the claims on the next call
/// **with the same access token**.
///
/// This is the property the whole release design exists for. An access token
/// lives fifteen minutes and the refresh behind it thirty days, so a decision
/// taken when the token was minted would leave a withdrawal ineffective for
/// most of a month. The release gate therefore re-reads the record on every
/// call, and this test asserts it by using the byte-identical token before and
/// after.
#[actix_web::test]
async fn t8_4_withdrawal_takes_effect_on_the_next_call_with_the_same_token() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    let admin = admin_jwt(&auth, &fx);
    enable_sensitive_scopes(&fx).await;
    let client_id = create_client(&app, &admin, sensitive_client()).await;
    let token = session_token(&fx, &auth).await;
    assert_eq!(
        grant_consent(&app, &token, &client_id, &["address", "phone"]).await,
        200
    );

    let access = userinfo_token(
        &auth,
        &fx,
        &["openid", "address", "phone"],
        Some(&client_id),
    );
    let before = userinfo(&app, &access).await;
    assert_eq!(before["phone_number"].as_str(), Some(PHONE));
    assert!(before.get("address").is_some());

    assert_eq!(withdraw_consent(&app, &token, &client_id).await, 200);

    let after = userinfo(&app, &access).await;
    assert!(
        after.get("phone_number").is_none(),
        "withdrawal must take effect on the next call, not the next token: {after}"
    );
    assert!(after.get("address").is_none(), "{after}");
    assert_eq!(
        after["sub"], before["sub"],
        "and nothing else about the response changes"
    );
}

/// Withdrawal removes every scope set consented to for that relying party, not
/// one of them. "Stop giving my address to this app" does not mean "stop under
/// the two-scope record and carry on under the one-scope one".
#[actix_web::test]
async fn withdrawal_removes_every_scope_set_for_that_client() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    let admin = admin_jwt(&auth, &fx);
    enable_sensitive_scopes(&fx).await;
    let client_id = create_client(&app, &admin, sensitive_client()).await;
    let token = session_token(&fx, &auth).await;
    assert_eq!(
        grant_consent(&app, &token, &client_id, &["phone"]).await,
        200
    );
    assert_eq!(
        grant_consent(&app, &token, &client_id, &["address", "phone"]).await,
        200
    );

    assert_eq!(withdraw_consent(&app, &token, &client_id).await, 200);

    for scopes in [vec!["openid", "phone"], vec!["openid", "address", "phone"]] {
        let access = userinfo_token(&auth, &fx, &scopes, Some(&client_id));
        let claims = userinfo(&app, &access).await;
        assert!(claims.get("phone_number").is_none(), "{scopes:?}: {claims}");
    }
}

/// Withdrawing when there was nothing to withdraw is not an error, and says
/// so. A subject who clicks twice is not told off.
#[actix_web::test]
async fn withdrawing_nothing_is_not_an_error() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    let token = session_token(&fx, &auth).await;
    assert_eq!(withdraw_consent(&app, &token, "no-such-client").await, 200);
}

/// The withdrawal endpoint cannot reach a `terms_of_service` row, whatever it
/// is asked to withdraw — the namespace guard is in the repository, so no
/// caller can be the one that gets it wrong. Registration's proof-of-consent
/// invariant (threat T-5-consent-gap) is untouched by W7.
#[actix_web::test]
async fn withdrawal_cannot_reach_the_registration_consent() {
    let fx = setup().await;
    let consents = SurrealConsentRepository::new(fx.db.clone());

    let err = consents
        .withdraw(fx.tenant_id, fx.user_id, "terms_of_service")
        .await
        .expect_err("a type outside the namespace must be refused, not silently matched");
    assert!(
        err.to_string().contains("oidc_scope_release:"),
        "the refusal must name the namespace: {err}"
    );
}

// ---------------------------------------------------------------------------
// T8.5 / M8 / M10 — the fapi2 refusals
// ---------------------------------------------------------------------------

/// **T8.5, M8 layer 1.** A `fapi2` client may not register the scopes, on
/// create — even with the tenant switch on.
#[actix_web::test]
async fn t8_5_a_fapi2_client_may_not_register_a_sensitive_scope() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    let admin = admin_jwt(&auth, &fx);
    enable_sensitive_scopes(&fx).await;

    let resp = try_create_client(
        &app,
        &admin,
        serde_json::json!({
            "name": "FAPI Client",
            "redirect_uris": [REDIRECT_URI],
            "grant_types": ["authorization_code"],
            "scopes": ["openid", "address"],
            "profile": "fapi2",
            "require_par": true,
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": "{\"keys\":[]}",
            "tls_client_certificate_bound_access_tokens": true,
        }),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = test::read_body_json(resp).await;
    let message = body.to_string();
    assert!(
        message.contains("address"),
        "the refusal must name the scope: {message}"
    );
}

/// **M10.** A `fapi2`-issued access token gets no `phone_number` and no
/// `address` at UserInfo, regardless of scope, switch or consent record.
///
/// The token is minted directly, naming the `fapi2` client, because the point
/// is precisely the case the other two gates cannot reach: a token that
/// already exists, presented at an endpoint where no authorization request is
/// in hand. This is the third and last place the FAPI profile is asked about,
/// and it is the one that has to hold when the row was edited past the others.
#[actix_web::test]
async fn m10_a_fapi2_issued_token_releases_nothing_at_userinfo() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    let admin = admin_jwt(&auth, &fx);
    enable_sensitive_scopes(&fx).await;

    // A legal `fapi2` registration — no sensitive scopes, so it passes.
    let fapi_id = create_client(
        &app,
        &admin,
        serde_json::json!({
            "name": "FAPI Client",
            "redirect_uris": [REDIRECT_URI],
            "grant_types": ["authorization_code"],
            "scopes": ["openid"],
            "profile": "fapi2",
            "require_par": true,
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": "{\"keys\":[]}",
            "tls_client_certificate_bound_access_tokens": true,
        }),
    )
    .await;

    // Consent recorded for it anyway, by hand — the record cannot be created
    // through the API for a client with no such scope registered, which is
    // itself a gate, so this is the strongest form of the test: everything
    // else says yes and the profile still says no.
    SurrealConsentRepository::new(fx.db.clone())
        .create(axiam_core::models::gdpr::CreateConsent {
            tenant_id: fx.tenant_id,
            user_id: fx.user_id,
            consent_type: format!("oidc_scope_release:{fapi_id}"),
            version: "address phone".into(),
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap();

    let access = userinfo_token(&auth, &fx, &["openid", "address", "phone"], Some(&fapi_id));
    let claims = userinfo(&app, &access).await;
    assert!(claims.get("phone_number").is_none(), "{claims}");
    assert!(claims.get("address").is_none(), "{claims}");
}

/// The consent endpoint refuses a scope the client has not registered, so a
/// consent record cannot be created for a release the client could never have
/// been authorised for.
#[actix_web::test]
async fn consent_cannot_be_recorded_for_a_scope_the_client_never_registered() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    let admin = admin_jwt(&auth, &fx);
    enable_sensitive_scopes(&fx).await;
    let narrow = create_client(
        &app,
        &admin,
        serde_json::json!({
            "name": "Phone Only",
            "redirect_uris": [REDIRECT_URI],
            "grant_types": ["authorization_code"],
            "scopes": ["openid", "phone"],
        }),
    )
    .await;
    let token = session_token(&fx, &auth).await;

    assert_eq!(grant_consent(&app, &token, &narrow, &["phone"]).await, 200);
    assert_eq!(
        grant_consent(&app, &token, &narrow, &["address"]).await,
        400,
        "consenting to a scope the client cannot request authorises nothing"
    );
    assert_eq!(
        grant_consent(&app, &token, &narrow, &["openid"]).await,
        400,
        "only the two sensitive scopes belong in this namespace"
    );
}

/// The consent endpoint refuses while the capability is off, so consent
/// collected in advance cannot sit waiting for somebody to turn it on.
#[actix_web::test]
async fn consent_cannot_be_recorded_while_the_capability_is_off() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    let admin = admin_jwt(&auth, &fx);
    enable_sensitive_scopes(&fx).await;
    let client_id = create_client(&app, &admin, sensitive_client()).await;
    SurrealSettingsRepository::new(fx.db.clone())
        .set_org_settings(fx.org_id, system_defaults())
        .await
        .unwrap();

    let token = session_token(&fx, &auth).await;
    assert_eq!(
        grant_consent(&app, &token, &client_id, &["phone"]).await,
        400
    );
}

// ---------------------------------------------------------------------------
// T8.6 — the audit row carries names, never values
// ---------------------------------------------------------------------------

/// **T8.6.** A release writes `userinfo.sensitive_claims_released`, and the row
/// names the claims without carrying their values.
///
/// The audit log is append-only and exported to subjects under Art. 15, so a
/// row carrying the telephone number would be a second copy of the personal
/// data in a store that cannot be erased. The assertion is therefore in two
/// halves — the row exists and names the claims, and neither value appears
/// anywhere in the serialised row.
#[actix_web::test]
async fn t8_6_the_release_is_audited_by_claim_name_and_never_by_value() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    let admin = admin_jwt(&auth, &fx);
    enable_sensitive_scopes(&fx).await;
    let client_id = create_client(&app, &admin, sensitive_client()).await;
    let token = session_token(&fx, &auth).await;
    assert_eq!(
        grant_consent(&app, &token, &client_id, &["address", "phone"]).await,
        200
    );

    let access = userinfo_token(
        &auth,
        &fx,
        &["openid", "address", "phone"],
        Some(&client_id),
    );
    assert!(userinfo(&app, &access).await.get("phone_number").is_some());

    let page = SurrealAuditLogRepository::new(fx.db.clone())
        .list(
            fx.tenant_id,
            AuditLogFilter {
                action: Some("userinfo.sensitive_claims_released".into()),
                ..Default::default()
            },
            Pagination::default(),
        )
        .await
        .unwrap();
    let entry = page.items.first().expect("a release must be audited");

    let serialised = serde_json::to_string(&entry).unwrap();
    assert!(
        serialised.contains("phone_number") && serialised.contains("address"),
        "the row must name the claims released: {serialised}"
    );
    assert!(
        serialised.contains(&client_id),
        "the row must name the relying party: {serialised}"
    );
    assert!(
        !serialised.contains(PHONE),
        "the telephone number must never reach the audit log: {serialised}"
    );
    assert!(
        !serialised.contains(STREET),
        "the postal address must never reach the audit log: {serialised}"
    );
}

/// A call that releases nothing writes no release row. An audit trail that
/// records every UserInfo request as a disclosure would make the rows that are
/// disclosures impossible to find.
#[actix_web::test]
async fn a_call_that_releases_nothing_writes_no_release_row() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    enable_sensitive_scopes(&fx).await;

    let access = userinfo_token(&auth, &fx, &["openid", "profile"], None);
    userinfo(&app, &access).await;

    let page = SurrealAuditLogRepository::new(fx.db.clone())
        .list(
            fx.tenant_id,
            AuditLogFilter {
                action: Some("userinfo.sensitive_claims_released".into()),
                ..Default::default()
            },
            Pagination::default(),
        )
        .await
        .unwrap();
    assert!(page.items.is_empty(), "{:?}", page.items);
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// The discovery document advertises the two scopes only for a tenant that has
/// them, and a caller that names no tenant gets the document W6 served.
///
/// Plan §6 assumed a tenant-scoped document; there is not one, so the
/// parameter is new and its absence is the pre-W7 behaviour.
#[actix_web::test]
async fn discovery_advertises_the_scopes_only_for_a_tenant_that_has_them() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);

    let fetch = |uri: String| {
        let app = &app;
        async move {
            let req = test::TestRequest::get()
                .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
                .uri(&uri)
                .to_request();
            let resp = test::call_service(app, req).await;
            assert_eq!(resp.status().as_u16(), 200);
            test::read_body_json::<serde_json::Value, _>(resp).await
        }
    };

    let scopes_of = |doc: &serde_json::Value| -> Vec<String> {
        doc["scopes_supported"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    };

    // No tenant named, capability off: the pre-W7 document.
    let anonymous = fetch("/.well-known/openid-configuration".into()).await;
    assert!(!scopes_of(&anonymous).contains(&"address".to_string()));
    assert!(
        !anonymous["claims_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "phone_number")
    );

    // Tenant named, capability still off: still nothing.
    let off = fetch(format!(
        "/.well-known/openid-configuration?tenant_id={}",
        fx.tenant_id
    ))
    .await;
    assert!(!scopes_of(&off).contains(&"address".to_string()));

    // Capability on, tenant named: both scopes and all three claims.
    enable_sensitive_scopes(&fx).await;
    let on = fetch(format!(
        "/.well-known/openid-configuration?tenant_id={}",
        fx.tenant_id
    ))
    .await;
    let scopes = scopes_of(&on);
    assert!(scopes.contains(&"address".to_string()), "{scopes:?}");
    assert!(scopes.contains(&"phone".to_string()), "{scopes:?}");
    for claim in ["phone_number", "phone_number_verified", "address"] {
        assert!(
            on["claims_supported"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c == claim),
            "claims_supported must carry {claim}"
        );
    }

    // Capability on but no tenant named: still omitted, because the server
    // cannot say which tenant the caller means.
    let still_anonymous = fetch("/.well-known/openid-configuration".into()).await;
    assert!(!scopes_of(&still_anonymous).contains(&"address".to_string()));

    // An unknown tenant is answered with the deployment-wide document rather
    // than a 404, so discovery is not a tenant-enumeration oracle.
    let unknown_tenant = Uuid::new_v4();
    let unknown = fetch(format!(
        "/.well-known/openid-configuration?tenant_id={unknown_tenant}"
    ))
    .await;
    assert!(!scopes_of(&unknown).contains(&"address".to_string()));

    // The two documents are no longer byte-identical: discovery now publishes
    // the tenant in the endpoint URLs it advertises, so that a relying party
    // that reads the document and uses the URLs verbatim is not refused for a
    // missing `tenant_id`. The echoed value is the one the *caller* supplied,
    // so it says nothing about whether that tenant exists.
    //
    // Strip that one caller-supplied value and the documents must still be
    // identical. That is the property worth asserting — a difference anywhere
    // else is the server telling an anonymous caller whether a tenant is real,
    // which is exactly the oracle answering unknown tenants at all is meant to
    // deny.
    let normalised: serde_json::Value = serde_json::from_str(
        &serde_json::to_string(&unknown)
            .expect("the discovery document round-trips")
            .replace(&format!("?tenant_id={unknown_tenant}"), ""),
    )
    .expect("the discovery document round-trips");
    assert_eq!(
        normalised, still_anonymous,
        "an unknown tenant must be indistinguishable from no tenant, except \
         for the tenant_id the caller supplied"
    );
}

// ---------------------------------------------------------------------------
// The self-service consent list
// ---------------------------------------------------------------------------

/// The list the plan assumed existed. It shows the registration consent as
/// non-withdrawable — that is an erasure, with its own endpoint and its own
/// grace period — and the scope-release consents as withdrawable.
#[actix_web::test]
async fn the_consent_list_marks_only_the_scope_releases_withdrawable() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    let admin = admin_jwt(&auth, &fx);
    enable_sensitive_scopes(&fx).await;
    let client_id = create_client(&app, &admin, sensitive_client()).await;
    let token = session_token(&fx, &auth).await;

    SurrealConsentRepository::new(fx.db.clone())
        .create(axiam_core::models::gdpr::CreateConsent {
            tenant_id: fx.tenant_id,
            user_id: fx.user_id,
            consent_type: "terms_of_service".into(),
            version: "current".into(),
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap();
    assert_eq!(
        grant_consent(&app, &token, &client_id, &["phone"]).await,
        200
    );

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/account/consents")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let rows: Vec<serde_json::Value> = test::read_body_json(resp).await;

    let terms = rows
        .iter()
        .find(|r| r["consent_type"] == "terms_of_service")
        .expect("the registration consent");
    assert_eq!(terms["withdrawable"].as_bool(), Some(false));

    let release = rows
        .iter()
        .find(|r| r["consent_type"] == format!("oidc_scope_release:{client_id}"))
        .expect("the scope-release consent");
    assert_eq!(release["withdrawable"].as_bool(), Some(true));
    assert_eq!(release["version"].as_str(), Some("phone"));
}

/// A request needing **both** ceremonies gets both, in order, and the login
/// marker is not mistaken for a consent one.
///
/// `prompt=consent` sends the browser to the sign-in page first — that is W4's
/// treatment of it, and W7 does not change it, because a fresh credential check
/// is still the only ceremony `prompt=consent` alone can be given when nothing
/// consent-gated was requested. The leg that comes back carries
/// `axiam_login_hop` and nobody has been asked about a postal address. Read as
/// a consent leg it would be `access_denied` for somebody who was never shown
/// the question; read correctly it is the consent screen.
#[actix_web::test]
async fn a_login_hop_marker_is_not_mistaken_for_a_consent_one() {
    let fx = setup().await;
    let auth = test_auth_config();
    let app = test_app!(fx.db, auth);
    let admin = admin_jwt(&auth, &fx);
    enable_sensitive_scopes(&fx).await;
    let client_id = create_client(&app, &admin, sensitive_client()).await;
    let token = session_token(&fx, &auth).await;

    // Leg 1: `prompt=consent` is an interaction, so the sign-in page.
    let first = authorize(
        &app,
        &token,
        &format!(
            "{}&prompt=consent",
            base_query(&client_id, "openid+address")
        ),
    )
    .await;
    let login = location(&first);
    assert!(login.starts_with("/login?"), "{login}");
    let leg2 = query_param(&login, "return_to").expect("a return_to");
    assert!(leg2.contains("axiam_login_hop=1"), "{leg2}");
    assert!(!leg2.contains("axiam_consent_hop"), "{leg2}");

    // Leg 2: back from the sign-in page. The consent question has still not
    // been asked, so it is asked now — not answered `access_denied`.
    let second = authorize(&app, &token, leg2.split('?').nth(1).unwrap()).await;
    let consent = location(&second);
    assert!(
        consent.starts_with("/consent?"),
        "a login return leg must still reach the consent screen: {consent}"
    );
    let leg3 = query_param(&consent, "return_to").expect("a return_to");
    assert!(leg3.contains("axiam_consent_hop=1"), "{leg3}");

    // Leg 3: back from the consent page with nothing recorded — now it is a
    // decline, and the chain stops.
    let third = authorize(&app, &token, leg3.split('?').nth(1).unwrap()).await;
    let final_location = location(&third);
    assert!(final_location.starts_with(REDIRECT_URI), "{final_location}");
    assert_eq!(
        query_param(&final_location, "error").as_deref(),
        Some("access_denied"),
        "{final_location}"
    );
}
