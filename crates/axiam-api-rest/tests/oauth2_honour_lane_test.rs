//! **W4 — the honour lane** (`claude_dev/basic-op-gap-plan.md` §4.2/§4.3/§4.4,
//! tests T1.*, T2.*, T3.* and the request halves of matrix rows M1–M4).
//!
//! W1 parsed `prompt`, `max_age`, `acr_values`, `claims.id_token.acr` and
//! `id_token_hint` and acted on none of them. W2 recorded, on every session,
//! the evidence needed to answer them. W3 built the browser login hop, so that
//! "authenticate the user again" became something the authorization endpoint
//! could do. This file is where the three become one feature — **for a client
//! registered `authn_request_params: honour`, and for nobody else**.
//!
//! Two properties are asserted throughout, and they are the wave:
//!
//! 1. A relying party that asks for a security property either gets it or is
//!    told it cannot have it. Never a token that quietly does not have it.
//! 2. A client on the `ignore` lane — which is every client registered today —
//!    is answered exactly as it was before any of this existed. Every negative
//!    test here carries that twin.

use std::net::SocketAddr;
use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::{Amr, CreateSession};
use axiam_core::models::settings::system_defaults;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, SessionRepository, SettingsRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealSessionRepository, SurrealSettingsRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12345";
const CSRF_TOKEN: &str = "test-csrf-token";
const REDIRECT_URI: &str = "https://rp.example.com/callback";
/// Test-only placeholder — not a real credential. gitleaks:allow
const PASSWORD: &str = "HonourLanePassw0rdStrong";
const ACR_1FA: &str = "urn:axiam:acr:1fa";
const ACR_MFA: &str = "urn:axiam:acr:mfa";

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

async fn setup_db() -> (Surreal<TestDb>, Uuid, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Honour Org".into(),
            slug: "honour-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Honour Tenant".into(),
            slug: "honour-tenant".into(),
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
                ..Default::default()
            },
        )
        .await
        .unwrap();

    (db, org.id, tenant.id, user.id)
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

fn admin_jwt(auth: &AuthConfig, user_id: Uuid, tenant_id: Uuid, org_id: Uuid) -> String {
    issue_access_token(
        user_id,
        tenant_id,
        org_id,
        &[],
        auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap()
}

/// Register a client, returning `(client_id, client_secret)`.
async fn create_client(
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

/// The registration shape this file is about: a client that asked for the
/// parameters to mean something, and can be reached by a browser.
fn honour_client() -> serde_json::Value {
    serde_json::json!({
        "name": "Honour Lane Client",
        "redirect_uris": [REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"],
        "scopes": ["openid", "profile"],
        "authn_request_params": "honour",
        "browser_sso": true,
    })
}

/// The registration shape every client in every deployment actually has.
fn ignore_client() -> serde_json::Value {
    serde_json::json!({
        "name": "Ignore Lane Client",
        "redirect_uris": [REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"],
        "scopes": ["openid", "profile"],
        "browser_sso": true,
    })
}

/// Create a session row with an authentication event of our choosing, and mint
/// an access token that arrives *as* that session.
///
/// `jti` = session id is the D-15 convention the authorize handler reads, and
/// it is what lets these tests control `authenticated_at` and `amr` — the two
/// inputs every decision in this wave is made from — without sleeping or
/// enrolling a second factor.
async fn session_token(
    db: &Surreal<TestDb>,
    auth: &AuthConfig,
    org_id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
    age: chrono::Duration,
    amr: Vec<Amr>,
) -> (Uuid, String) {
    let session = SurrealSessionRepository::new(db.clone())
        .create(CreateSession {
            tenant_id,
            user_id,
            token_hash: Uuid::new_v4().to_string(),
            ip_address: None,
            user_agent: None,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            authenticated_at: chrono::Utc::now() - age,
            amr,
            browser_token_hash: None,
        })
        .await
        .expect("session");
    let token = issue_access_token(
        user_id,
        tenant_id,
        org_id,
        &[],
        auth,
        session.id.to_string(),
        AUD_USER,
    )
    .unwrap();
    (session.id, token)
}

/// `GET /oauth2/authorize` with a bearer token.
async fn authorize(
    app: &impl TestApp,
    token: &str,
    extra: &str,
) -> actix_web::dev::ServiceResponse {
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/authorize?{extra}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    test::call_service(app, req).await
}

/// `GET /oauth2/authorize` with no credentials but the cookies given.
async fn anonymous_authorize(
    app: &impl TestApp,
    query: &str,
    cookies: Option<&str>,
) -> actix_web::dev::ServiceResponse {
    let mut req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/authorize?{query}"));
    if let Some(cookies) = cookies {
        req = req.insert_header(("Cookie", cookies.to_owned()));
    }
    test::call_service(app, req.to_request()).await
}

fn base_query(client_id: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI}\
         &scope=openid&state=w4-state"
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
    url::Url::parse(url)
        .ok()?
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// Exchange a code for tokens.
async fn token_exchange(
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
    assert_eq!(resp.status().as_u16(), 200, "token exchange must succeed");
    test::read_body_json(resp).await
}

/// Authorize and exchange in one step, returning the decoded ID-token claims.
async fn id_token_claims(
    app: &impl TestApp,
    tenant_id: Uuid,
    token: &str,
    client_id: &str,
    client_secret: &str,
    extra: &str,
) -> serde_json::Value {
    let resp = authorize(app, token, &format!("{}{extra}", base_query(client_id))).await;
    assert_eq!(resp.status().as_u16(), 302, "authorize must redirect");
    let loc = location(&resp);
    let code = query_param(&loc, "code").unwrap_or_else(|| panic!("a code in {loc}"));
    let tokens = token_exchange(app, tenant_id, client_id, client_secret, &code).await;
    claims_of(tokens["id_token"].as_str().expect("an ID token"))
}

/// Decode a JWT's claims without verifying — the signature has its own suite.
fn claims_of(jwt: &str) -> serde_json::Value {
    let payload = jwt.split('.').nth(1).expect("a JWT has three parts");
    let bytes = URL_SAFE_NO_PAD.decode(payload).expect("base64url payload");
    serde_json::from_slice(&bytes).expect("the payload is JSON")
}

fn error_of(resp: &actix_web::dev::ServiceResponse) -> String {
    let loc = location(resp);
    query_param(&loc, "error").unwrap_or_else(|| panic!("an error in {loc}"))
}

// ---------------------------------------------------------------------------
// T1.* — prompt
// ---------------------------------------------------------------------------

/// **T1.1 and T1.7.** `prompt=none` with no session is answered
/// `login_required`, **redirected to the relying party**, carrying `state` and
/// `iss` and no code.
///
/// T1.7 — "an iframe-shaped request" — is the same request without a cookie,
/// which is what a cross-site iframe produces: `axiam_op_session` is `Lax`, so
/// a sub-frame navigation never carries it and the OP sees exactly this.
#[actix_rt::test]
async fn t1_1_and_t1_7_prompt_none_without_a_session_is_login_required_at_the_relying_party() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, honour_client()).await;

    let resp = anonymous_authorize(
        &app,
        &format!(
            "{}&tenant_id={tenant_id}&prompt=none",
            base_query(&client_id)
        ),
        None,
    )
    .await;

    assert_eq!(resp.status().as_u16(), 302);
    let loc = location(&resp);
    assert!(
        loc.starts_with(REDIRECT_URI),
        "the refusal goes to the relying party, not to a sign-in page: {loc}"
    );
    assert_eq!(
        query_param(&loc, "error").as_deref(),
        Some("login_required")
    );
    assert_eq!(query_param(&loc, "state").as_deref(), Some("w4-state"));
    assert!(
        query_param(&loc, "iss").is_some(),
        "RFC 9207 — the error response names its issuer too: {loc}"
    );
    assert!(query_param(&loc, "code").is_none(), "no code: {loc}");
}

/// **T1.1's I4 twin.** The same request against the client every deployment
/// actually holds takes W3's path, unchanged: `prompt=none` is dropped and the
/// browser is sent to sign in.
#[actix_rt::test]
async fn t1_1_i4_twin_an_ignore_lane_client_still_gets_the_login_hop() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, ignore_client()).await;

    let resp = anonymous_authorize(
        &app,
        &format!(
            "{}&tenant_id={tenant_id}&prompt=none",
            base_query(&client_id)
        ),
        None,
    )
    .await;

    assert_eq!(resp.status().as_u16(), 302);
    let loc = location(&resp);
    assert!(
        loc.starts_with("/login?return_to="),
        "an ignore-lane client's prompt=none is dropped, exactly as in W3: {loc}"
    );
}

/// **T1.2.** `prompt=none` with a session that satisfies the request is a code
/// and no interaction — and the ID token carries the evidence that says so.
#[actix_rt::test]
async fn t1_2_prompt_none_with_a_session_yields_a_code() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, secret) = create_client(&app, &jwt, honour_client()).await;
    let (_, token) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::seconds(30),
        vec![Amr::Pwd],
    )
    .await;

    let claims =
        id_token_claims(&app, tenant_id, &token, &client_id, &secret, "&prompt=none").await;
    assert!(claims["auth_time"].is_i64(), "{claims}");
    assert_eq!(claims["acr"], serde_json::json!(ACR_1FA));
    assert_eq!(claims["amr"], serde_json::json!(["pwd"]));
}

/// **T1.3.** A `prompt` on the query string beside a `request_uri` is refused:
/// a browser may not top up somebody's pushed request with a parameter that
/// changes what it means.
#[actix_rt::test]
async fn t1_3_an_inline_parameter_beside_a_request_uri_is_invalid_request() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, secret) = create_client(&app, &jwt, honour_client()).await;
    let (_, token) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::seconds(30),
        vec![Amr::Pwd],
    )
    .await;

    // Push a request the honest way.
    let form = format!(
        "response_type=code&client_id={client_id}&client_secret={secret}\
         &redirect_uri={REDIRECT_URI}&scope=openid&state=w4-state"
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/par?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201, "PAR must accept the push");
    let pushed: serde_json::Value = test::read_body_json(resp).await;
    let request_uri = pushed["request_uri"].as_str().unwrap().to_owned();
    let encoded: String = url::form_urlencoded::byte_serialize(request_uri.as_bytes()).collect();

    let resp = authorize(
        &app,
        &token,
        &format!("client_id={client_id}&request_uri={encoded}&prompt=none"),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    assert_eq!(error_of(&resp), "invalid_request");
}

/// **T1.4.** `prompt=none login` is contradictory (OIDC Core §3.1.2.1) and is
/// refused on the honour lane…
#[actix_rt::test]
async fn t1_4_prompt_none_combined_with_another_value_is_invalid_request() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, honour_client()).await;
    let (_, token) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::seconds(30),
        vec![Amr::Pwd],
    )
    .await;

    let resp = authorize(
        &app,
        &token,
        &format!("{}&prompt=none%20login", base_query(&client_id)),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    assert_eq!(error_of(&resp), "invalid_request");
}

/// …**and its I4 twin**: the same contradiction from a client registered today
/// is dropped, and the code is issued exactly as it always was.
#[actix_rt::test]
async fn t1_4_i4_twin_a_contradictory_prompt_is_still_dropped_on_the_ignore_lane() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, ignore_client()).await;
    let (_, token) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::seconds(30),
        vec![Amr::Pwd],
    )
    .await;

    let resp = authorize(
        &app,
        &token,
        &format!("{}&prompt=none%20login", base_query(&client_id)),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    let loc = location(&resp);
    assert!(query_param(&loc, "code").is_some(), "{loc}");
}

/// **T1.5.** `prompt=login` sends the browser to the sign-in page in `reauth`
/// mode, and the token issued after the return leg carries a strictly later
/// `auth_time` than one issued before it (mirrors `OIDCCPromptLogin`).
#[actix_rt::test]
async fn t1_5_prompt_login_reauthenticates_and_moves_auth_time_forward() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, secret) = create_client(&app, &jwt, honour_client()).await;

    // An hour-old session, and the token it earns without `prompt=login`.
    let (_, token) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::hours(1),
        vec![Amr::Pwd],
    )
    .await;
    let before = id_token_claims(&app, tenant_id, &token, &client_id, &secret, "").await;
    let before_auth_time = before["auth_time"].as_i64().expect("auth_time");

    // The same session, asked to sign in again.
    let resp = authorize(
        &app,
        &token,
        &format!("{}&prompt=login", base_query(&client_id)),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    let loc = location(&resp);
    assert!(
        loc.starts_with("/login?return_to="),
        "prompt=login must send the browser to the sign-in page: {loc}"
    );
    assert!(loc.contains("&reauth=1"), "…in reauth mode: {loc}");
    assert!(
        !loc.contains("&acr="),
        "…demanding no particular factor: {loc}"
    );
    assert!(
        resp.headers()
            .get("Cache-Control")
            .unwrap()
            .to_str()
            .unwrap()
            == "no-store",
        "the redirect carries the whole authorization request"
    );

    // The sign-in the page performs, and the return leg it navigates to.
    let (_, fresh) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::zero(),
        vec![Amr::Pwd],
    )
    .await;
    let after = id_token_claims(
        &app,
        tenant_id,
        &fresh,
        &client_id,
        &secret,
        "&prompt=login&axiam_login_hop=1",
    )
    .await;
    assert!(
        after["auth_time"].as_i64().expect("auth_time") > before_auth_time,
        "the reauthentication must move auth_time forward: {before} → {after}"
    );
}

/// A `prompt=login` request that has already been through the sign-in page is
/// answered rather than sent there again. Without this the deployment loops.
#[actix_rt::test]
async fn the_return_leg_of_a_prompt_login_hop_does_not_hop_again() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, honour_client()).await;
    let (_, token) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::zero(),
        vec![Amr::Pwd],
    )
    .await;

    let resp = authorize(
        &app,
        &token,
        &format!("{}&prompt=login&axiam_login_hop=1", base_query(&client_id)),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    let loc = location(&resp);
    assert!(
        loc.starts_with(REDIRECT_URI) && query_param(&loc, "code").is_some(),
        "the interaction has happened; a second one would be the loop: {loc}"
    );
}

/// The W4 seam. `prompt=consent` has no consent screen to render until W7, and
/// the two available answers were *ignore it* — the silent downgrade this lane
/// exists to prevent — or refuse. It is treated as `login`: an interaction
/// happens, the end user performs it, and nothing is asserted about consent.
/// See `axiam_oauth2::honour::evaluate` for the argument.
#[actix_rt::test]
async fn prompt_consent_interacts_rather_than_being_silently_dropped() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, honour_client()).await;
    let (_, token) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::zero(),
        vec![Amr::Pwd],
    )
    .await;

    let resp = authorize(
        &app,
        &token,
        &format!("{}&prompt=consent", base_query(&client_id)),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    assert!(
        location(&resp).starts_with("/login?return_to="),
        "prompt=consent must not be dropped"
    );
}

// ---------------------------------------------------------------------------
// T2.* — max_age and auth_time
// ---------------------------------------------------------------------------

/// **T2.1.** `max_age=0` against a one-second-old session reauthenticates, and
/// never issues a code.
///
/// The comparison is `elapsed >= max_age` (plan §4.3), so `max_age=0` is a
/// request no authentication can satisfy: it is always stale by the time it is
/// evaluated. What the relying party gets is an interaction and then a refusal,
/// which is the honest answer to "authenticate them zero seconds ago".
#[actix_rt::test]
async fn t2_1_max_age_zero_always_reauthenticates_and_never_yields_a_code() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, honour_client()).await;
    let (_, token) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::seconds(1),
        vec![Amr::Pwd],
    )
    .await;

    let resp = authorize(
        &app,
        &token,
        &format!("{}&max_age=0", base_query(&client_id)),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    let loc = location(&resp);
    assert!(loc.starts_with("/login?return_to="), "{loc}");
    assert!(loc.contains("&reauth=1"), "{loc}");
    assert!(
        !loc.contains("code="),
        "a one-second-old session must not satisfy max_age=0: {loc}"
    );

    // …and the reauthentication it produces cannot satisfy it either, so the
    // chain terminates with a refusal rather than a second hop.
    let (_, fresh) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::zero(),
        vec![Amr::Pwd],
    )
    .await;
    let resp = authorize(
        &app,
        &fresh,
        &format!("{}&max_age=0&axiam_login_hop=1", base_query(&client_id)),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    let loc = location(&resp);
    assert!(loc.starts_with(REDIRECT_URI), "{loc}");
    assert_eq!(
        query_param(&loc, "error").as_deref(),
        Some("login_required")
    );
    assert!(query_param(&loc, "code").is_none(), "{loc}");
}

/// **T2.1's I4 twin.** `max_age=0` from a client registered today is dropped
/// and the code is issued, exactly as it has always been.
#[actix_rt::test]
async fn t2_1_i4_twin_max_age_zero_is_dropped_on_the_ignore_lane() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, secret) = create_client(&app, &jwt, ignore_client()).await;
    let (_, token) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::hours(9),
        vec![Amr::Pwd],
    )
    .await;

    let claims = id_token_claims(&app, tenant_id, &token, &client_id, &secret, "&max_age=0").await;
    for absent in ["auth_time", "acr", "amr"] {
        assert!(
            claims.get(absent).is_none(),
            "an ignore-lane client must receive no {absent}: {claims}"
        );
    }
}

/// **T2.2.** A session older than `max_age` reauthenticates; the token issued
/// after the return leg carries a fresh `auth_time`.
#[actix_rt::test]
async fn t2_2_an_expired_max_age_reauthenticates_and_the_second_token_is_fresh() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, secret) = create_client(&app, &jwt, honour_client()).await;

    let (_, stale) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::seconds(120),
        vec![Amr::Pwd],
    )
    .await;
    let resp = authorize(
        &app,
        &stale,
        &format!("{}&max_age=60", base_query(&client_id)),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    assert!(location(&resp).starts_with("/login?return_to="));

    let (_, fresh) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::zero(),
        vec![Amr::Pwd],
    )
    .await;
    let claims = id_token_claims(
        &app,
        tenant_id,
        &fresh,
        &client_id,
        &secret,
        "&max_age=60&axiam_login_hop=1",
    )
    .await;
    let auth_time = claims["auth_time"].as_i64().expect("auth_time");
    let now = chrono::Utc::now().timestamp();
    assert!(
        (now - auth_time) < 300,
        "the reauthenticated token's auth_time must be recent: {claims}"
    );
}

/// **T2.3.** A `max_age` the session already satisfies asks for nothing, and
/// two requests with different (satisfied) bounds report the same `auth_time`
/// and the same `sub` — mirrors `OIDCCMaxAge10000`.
#[actix_rt::test]
async fn t2_3_a_satisfied_max_age_does_not_reauthenticate() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, secret) = create_client(&app, &jwt, honour_client()).await;
    let (_, token) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::seconds(60),
        vec![Amr::Pwd],
    )
    .await;

    let first = id_token_claims(
        &app,
        tenant_id,
        &token,
        &client_id,
        &secret,
        "&max_age=15000",
    )
    .await;
    let second = id_token_claims(
        &app,
        tenant_id,
        &token,
        &client_id,
        &secret,
        "&max_age=10000",
    )
    .await;

    assert_eq!(first["auth_time"], second["auth_time"]);
    assert_eq!(first["sub"], second["sub"]);
    assert!(first["auth_time"].is_i64(), "{first}");
}

/// **T2.4.** A refreshed ID token's `auth_time` equals the original's
/// (OIDC Core §12.2; `OIDCCRefreshToken` compares them).
#[actix_rt::test]
async fn t2_4_a_refreshed_id_token_carries_the_original_auth_time() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, secret) = create_client(&app, &jwt, honour_client()).await;
    let (_, token) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::minutes(20),
        vec![Amr::Pwd, Amr::Otp, Amr::Mfa],
    )
    .await;

    let resp = authorize(&app, &token, &base_query(&client_id)).await;
    let loc = location(&resp);
    let code = query_param(&loc, "code").expect("a code");
    let tokens = token_exchange(&app, tenant_id, &client_id, &secret, &code).await;
    let original = claims_of(tokens["id_token"].as_str().unwrap());
    let refresh_token = tokens["refresh_token"].as_str().expect("a refresh token");

    let form = format!(
        "grant_type=refresh_token&refresh_token={refresh_token}\
         &client_id={client_id}&client_secret={secret}"
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "refresh must succeed");
    let refreshed: serde_json::Value = test::read_body_json(resp).await;
    let reissued = claims_of(refreshed["id_token"].as_str().expect("an ID token"));

    assert_eq!(
        reissued["auth_time"], original["auth_time"],
        "a refresh is not an authentication event: {original} → {reissued}"
    );
    assert_eq!(reissued["amr"], original["amr"]);
    assert_eq!(reissued["sub"], original["sub"]);
}

/// **T2.4's I4 twin.** A refreshed ID token for a client registered today
/// carries none of the three claims, exactly as before.
#[actix_rt::test]
async fn t2_4_i4_twin_a_refreshed_ignore_lane_token_carries_no_evidence() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, secret) = create_client(&app, &jwt, ignore_client()).await;
    let (_, token) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::minutes(20),
        vec![Amr::Pwd, Amr::Mfa],
    )
    .await;

    let resp = authorize(&app, &token, &base_query(&client_id)).await;
    let code = query_param(&location(&resp), "code").expect("a code");
    let tokens = token_exchange(&app, tenant_id, &client_id, &secret, &code).await;
    let refresh_token = tokens["refresh_token"].as_str().expect("a refresh token");

    let form = format!(
        "grant_type=refresh_token&refresh_token={refresh_token}\
         &client_id={client_id}&client_secret={secret}"
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let refreshed: serde_json::Value = test::read_body_json(resp).await;
    let claims = claims_of(refreshed["id_token"].as_str().unwrap());
    for absent in ["auth_time", "acr", "amr"] {
        assert!(claims.get(absent).is_none(), "{absent} in {claims}");
    }
}

/// **T2.7.** A malformed value is `invalid_request` on the honour lane…
#[actix_rt::test]
async fn t2_7_a_malformed_value_is_invalid_request_on_the_honour_lane() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, honour_client()).await;
    let (_, token) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::seconds(30),
        vec![Amr::Pwd],
    )
    .await;

    for bad in ["max_age=-1", "max_age=abc", "prompt=teleport"] {
        let resp = authorize(&app, &token, &format!("{}&{bad}", base_query(&client_id))).await;
        assert_eq!(resp.status().as_u16(), 302, "{bad}");
        assert_eq!(error_of(&resp), "invalid_request", "{bad}");
    }
}

/// …**and its I4 twin**: dropped, with a code issued, for a client registered
/// today. `max_age=tomorrow` has always produced a code and still does.
#[actix_rt::test]
async fn t2_7_i4_twin_a_malformed_value_is_still_dropped_on_the_ignore_lane() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, ignore_client()).await;
    let (_, token) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::seconds(30),
        vec![Amr::Pwd],
    )
    .await;

    for bad in ["max_age=-1", "max_age=abc", "prompt=teleport"] {
        let resp = authorize(&app, &token, &format!("{}&{bad}", base_query(&client_id))).await;
        assert_eq!(resp.status().as_u16(), 302, "{bad}");
        let loc = location(&resp);
        assert!(query_param(&loc, "code").is_some(), "{bad}: {loc}");
    }
}

// ---------------------------------------------------------------------------
// T3.* — acr
// ---------------------------------------------------------------------------

/// **T3.1 and T3.3.** The classic ACR-deception bug, as a test.
///
/// A relying party asks for multi-factor authentication over a password-only
/// session. It is offered a step-up, naming the factor; when the step-up does
/// not happen, the token it receives says `1fa` — what the session actually
/// proved — and never the `mfa` it asked for.
#[actix_rt::test]
async fn t3_1_and_t3_3_an_acr_request_is_never_echoed_into_the_claim() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, secret) = create_client(&app, &jwt, honour_client()).await;
    let (_, token) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::seconds(30),
        vec![Amr::Pwd],
    )
    .await;

    // The step-up, naming the one factor the sign-in page must demand.
    let resp = authorize(
        &app,
        &token,
        &format!("{}&acr_values={ACR_MFA}", base_query(&client_id)),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    let loc = location(&resp);
    assert!(loc.starts_with("/login?return_to="), "{loc}");
    assert!(loc.ends_with("&acr=urn%3Aaxiam%3Aacr%3Amfa"), "{loc}");

    // Declined (or unavailable): the token tells the truth.
    let claims = id_token_claims(
        &app,
        tenant_id,
        &token,
        &client_id,
        &secret,
        &format!("&acr_values={ACR_MFA}&axiam_login_hop=1"),
    )
    .await;
    assert_eq!(
        claims["acr"],
        serde_json::json!(ACR_1FA),
        "the request must never decide the claim: {claims}"
    );
    assert_eq!(claims["amr"], serde_json::json!(["pwd"]));
}

/// **T3.2.** An *essential* ACR the end user cannot reach is refused with
/// `unmet_authentication_requirements`, and never with a token.
#[actix_rt::test]
async fn t3_2_an_unmet_essential_acr_is_refused_rather_than_downgraded() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, honour_client()).await;
    let (_, token) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::seconds(30),
        vec![Amr::Pwd],
    )
    .await;

    let claims_param: String = url::form_urlencoded::byte_serialize(
        br#"{"id_token":{"acr":{"essential":true,"values":["urn:axiam:acr:mfa"]}}}"#,
    )
    .collect();

    // First leg: a step-up is offered.
    let resp = authorize(
        &app,
        &token,
        &format!("{}&claims={claims_param}", base_query(&client_id)),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    assert!(location(&resp).starts_with("/login?return_to="));

    // Return leg: the user has no second factor, so the answer is a refusal.
    let resp = authorize(
        &app,
        &token,
        &format!(
            "{}&claims={claims_param}&axiam_login_hop=1",
            base_query(&client_id)
        ),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    let loc = location(&resp);
    assert!(loc.starts_with(REDIRECT_URI), "{loc}");
    assert_eq!(
        query_param(&loc, "error").as_deref(),
        Some("unmet_authentication_requirements")
    );
    assert!(query_param(&loc, "code").is_none(), "never a token: {loc}");
}

/// **T3.4.** Most-preferred *satisfied* value, in the relying party's order —
/// not the highest class achieved. An MFA session asked for `[1fa, mfa]`
/// reports `1fa`, because that is the class the relying party asked about
/// first and the session satisfies it.
#[actix_rt::test]
async fn t3_4_the_reported_class_is_the_most_preferred_one_that_is_satisfied() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, secret) = create_client(&app, &jwt, honour_client()).await;
    let (_, token) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::seconds(30),
        vec![Amr::Pwd, Amr::Otp, Amr::Mfa],
    )
    .await;

    let claims = id_token_claims(
        &app,
        tenant_id,
        &token,
        &client_id,
        &secret,
        &format!("&acr_values={ACR_1FA}%20{ACR_MFA}"),
    )
    .await;
    assert_eq!(claims["acr"], serde_json::json!(ACR_1FA), "{claims}");

    // The other order selects the other satisfied value.
    let claims = id_token_claims(
        &app,
        tenant_id,
        &token,
        &client_id,
        &secret,
        &format!("&acr_values={ACR_MFA}%20{ACR_1FA}"),
    )
    .await;
    assert_eq!(claims["acr"], serde_json::json!(ACR_MFA), "{claims}");
}

/// **T3.5 / M3's I4 twin.** `acr_values` on a client registered today is
/// ignored, and its ID token carries no `acr` at all.
#[actix_rt::test]
async fn t3_5_acr_values_on_an_ignore_lane_client_produces_no_claim() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, secret) = create_client(&app, &jwt, ignore_client()).await;
    let (_, token) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::seconds(30),
        vec![Amr::Pwd],
    )
    .await;

    let claims = id_token_claims(
        &app,
        tenant_id,
        &token,
        &client_id,
        &secret,
        &format!("&acr_values={ACR_MFA}"),
    )
    .await;
    for absent in ["auth_time", "acr", "amr"] {
        assert!(claims.get(absent).is_none(), "{absent} in {claims}");
    }
}

/// A satisfied ACR request asks for no interaction at all, and reports the
/// class that satisfied it.
#[actix_rt::test]
async fn a_satisfied_acr_request_proceeds_straight_to_a_code() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, secret) = create_client(&app, &jwt, honour_client()).await;
    let (_, token) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::seconds(30),
        vec![Amr::Hwk, Amr::User],
    )
    .await;

    let claims = id_token_claims(
        &app,
        tenant_id,
        &token,
        &client_id,
        &secret,
        &format!("&acr_values={ACR_MFA}"),
    )
    .await;
    assert_eq!(claims["acr"], serde_json::json!(ACR_MFA), "{claims}");
    assert_eq!(claims["amr"], serde_json::json!(["hwk", "user"]));
}

// ---------------------------------------------------------------------------
// id_token_hint (M4's request half, and its I4 twin)
// ---------------------------------------------------------------------------

/// An `id_token_hint` naming this end user and this client asks for nothing;
/// one naming somebody else sends the browser to sign in again.
#[actix_rt::test]
async fn an_id_token_hint_is_honoured_and_a_mismatched_one_reauthenticates() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, secret) = create_client(&app, &jwt, honour_client()).await;
    let (_, token) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::seconds(30),
        vec![Amr::Pwd],
    )
    .await;

    // A genuine ID token for this user and this client, obtained the ordinary
    // way, is a hint that matches.
    let resp = authorize(&app, &token, &base_query(&client_id)).await;
    let code = query_param(&location(&resp), "code").expect("a code");
    let tokens = token_exchange(&app, tenant_id, &client_id, &secret, &code).await;
    let hint = tokens["id_token"].as_str().expect("an ID token").to_owned();

    let resp = authorize(
        &app,
        &token,
        &format!("{}&id_token_hint={hint}", base_query(&client_id)),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    let loc = location(&resp);
    assert!(query_param(&loc, "code").is_some(), "{loc}");

    // A hint that does not verify names somebody else, and is never dropped.
    let resp = authorize(
        &app,
        &token,
        &format!("{}&id_token_hint=not.a.jwt", base_query(&client_id)),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    assert!(
        location(&resp).starts_with("/login?return_to="),
        "an unverifiable hint must not be treated as an absent one"
    );

    // …and under `prompt=none`, where nothing can be asked of the end user, it
    // is a refusal rather than a code.
    let resp = authorize(
        &app,
        &token,
        &format!(
            "{}&prompt=none&id_token_hint=not.a.jwt",
            base_query(&client_id)
        ),
    )
    .await;
    assert_eq!(error_of(&resp), "login_required");
}

/// **M4's I4 twin.** The same unverifiable hint against a client registered
/// today is dropped, and the code is issued.
#[actix_rt::test]
async fn m4_i4_twin_an_id_token_hint_is_ignored_on_the_ignore_lane() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, ignore_client()).await;
    let (_, token) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::seconds(30),
        vec![Amr::Pwd],
    )
    .await;

    let resp = authorize(
        &app,
        &token,
        &format!("{}&id_token_hint=not.a.jwt", base_query(&client_id)),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    let loc = location(&resp);
    assert!(query_param(&loc, "code").is_some(), "{loc}");
}

// ---------------------------------------------------------------------------
// The registration gate (M1–M4, layer 1) as the admin API answers it
// ---------------------------------------------------------------------------

/// **M1–M4, layer 1, through HTTP.** A `fapi2` client cannot register
/// `authn_request_params: honour` — on create or on update — which is what
/// makes "a `fapi2` ID token never carries `acr`" a property of the data rather
/// than of the request path.
#[actix_rt::test]
async fn m1_to_m4_registration_refuses_the_honour_lane_on_a_fapi2_client() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);

    let fapi = serde_json::json!({
        "name": "FAPI Client",
        "redirect_uris": [REDIRECT_URI],
        "grant_types": ["authorization_code"],
        "scopes": ["openid"],
        "profile": "fapi2",
        "require_par": true,
        "token_endpoint_auth_method": "tls_client_auth",
        "tls_client_auth_san_dns": "rp.example.com",
        "tls_client_certificate_bound_access_tokens": true,
    });

    // On create.
    let mut with_honour = fapi.clone();
    with_honour["authn_request_params"] = serde_json::json!("honour");
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {jwt}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(&with_honour)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "a fapi2 client must not be registrable on the honour lane"
    );

    // On update, against a row that was created honestly.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {jwt}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(&fapi)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let created: serde_json::Value = test::read_body_json(resp).await;

    let req = test::TestRequest::put()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!(
            "/api/v1/oauth2-clients/{}",
            created["id"].as_str().unwrap()
        ))
        .insert_header(("Authorization", format!("Bearer {jwt}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "authn_request_params": "honour" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "…nor editable onto it afterwards"
    );
}
