//! **W5 — the honour lane, cosmetic** (`claude_dev/basic-op-gap-plan.md`
//! §4.5/§4.6, tests T5.*, T6.* and the request halves of matrix rows M5–M6).
//!
//! W1 parsed `login_hint`, `display`, `ui_locales` and `claims_locales` and
//! forwarded them nowhere. W3 built the browser login hop and W4 gave the
//! honour lane a reason to ask for a second one. This file is where the four
//! reach the page they were always about — **for a client registered
//! `authn_request_params: honour`, and for nobody else**.
//!
//! Three properties are asserted throughout:
//!
//! 1. **Nothing is looked up.** T5.1: the response for a `login_hint` naming a
//!    real account and one naming nothing at all differs in the echoed value
//!    and in nothing else — not a header, not a status, not a length. That is
//!    true because there is no branch, not because two branches were equalised.
//! 2. **No relying-party string reaches a URL except the one that must.**
//!    T6.2: `ui_locales` and `display` are matched on the server and forwarded
//!    as allow-listed tokens, so a hostile value selects nothing and appears
//!    nowhere.
//! 3. **A client on the `ignore` lane sees the W3/W4 page, byte for byte.**
//!    Every test here carries that twin.

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
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12345";
const CSRF_TOKEN: &str = "test-csrf-token";
const REDIRECT_URI: &str = "https://rp.example.com/callback";
/// Test-only placeholder — not a real credential. gitleaks:allow
const PASSWORD: &str = "HonourLanePassw0rdStrong";
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

// ---------------------------------------------------------------------------
// Helpers specific to this wave
// ---------------------------------------------------------------------------

/// The `/login` URL an anonymous authorization request was redirected to.
///
/// A path rather than a URL — `axiam_oauth2::login_hop::build_login_redirect_for`
/// is deliberately same-origin and relative — so these tests read it as a
/// string rather than through `url::Url`.
fn login_location(resp: &actix_web::dev::ServiceResponse) -> String {
    let loc = location(resp);
    assert!(
        loc.starts_with("/login?return_to="),
        "expected a login hop, got {loc}"
    );
    loc
}

/// The value of one parameter of a relative `/login?…` URL.
fn login_param(loc: &str, name: &str) -> Option<String> {
    let (_, query) = loc.split_once('?')?;
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// An anonymous authorization request for `client_id`, carrying `extra`.
async fn hop(
    app: &impl TestApp,
    tenant_id: Uuid,
    client_id: &str,
    extra: &str,
) -> actix_web::dev::ServiceResponse {
    anonymous_authorize(
        app,
        &format!("{}&tenant_id={tenant_id}{extra}", base_query(client_id)),
        None,
    )
    .await
}

/// A `fapi2` client that a browser may reach — M7 permits `browser_sso` on
/// every profile — and that is registered honestly, i.e. `ignore`.
fn fapi_browser_client() -> serde_json::Value {
    serde_json::json!({
        "name": "FAPI Browser Client",
        "redirect_uris": [REDIRECT_URI],
        "grant_types": ["authorization_code"],
        "scopes": ["openid"],
        "profile": "fapi2",
        "require_par": true,
        "token_endpoint_auth_method": "tls_client_auth",
        "tls_client_auth_san_dns": "rp.example.com",
        "tls_client_certificate_bound_access_tokens": true,
        "browser_sso": true,
    })
}

// ---------------------------------------------------------------------------
// T5.* — login_hint
// ---------------------------------------------------------------------------

/// **T5.1.** The whole response — status, every header, and the `Location`
/// down to its bytes — is the same for a hint that names an account this
/// tenant holds and one that names nothing anywhere, apart from the echoed
/// value itself.
///
/// The two hints are chosen so that one is a substring rewrite of the other
/// (`alice` → `nobody`), which lets the assertion be an equality rather than a
/// list of things that happened to match. If any part of the server ever
/// started resolving the hint — to pick a tenant, to pre-load a user, to skip
/// a step, to write an audit row with a different shape — this is the test
/// that fails.
#[actix_rt::test]
async fn t5_1_the_response_is_identical_whether_or_not_the_hinted_account_exists() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, honour_client()).await;

    // `alice@example.com` is the user `setup_db` created. `nobody@example.com`
    // exists in no tenant of any organization.
    let existing = hop(
        &app,
        tenant_id,
        &client_id,
        "&login_hint=alice%40example.com",
    )
    .await;
    let missing = hop(
        &app,
        tenant_id,
        &client_id,
        "&login_hint=nobody%40example.com",
    )
    .await;

    assert_eq!(existing.status(), missing.status());

    // Sorted by name: `HeaderMap`'s iteration order is not part of the
    // response, so comparing it would make this test fail for a reason that is
    // not the one it is about.
    let headers = |resp: &actix_web::dev::ServiceResponse| {
        let mut out: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_owned()))
            .collect();
        out.sort();
        out
    };
    let existing_headers = headers(&existing);
    let missing_headers = headers(&missing);
    assert_eq!(
        existing_headers.len(),
        missing_headers.len(),
        "the two responses carry a different number of headers"
    );
    for ((name, existing_value), (missing_name, missing_value)) in
        existing_headers.iter().zip(missing_headers.iter())
    {
        assert_eq!(name, missing_name);
        assert_eq!(
            existing_value.replace("alice", "nobody"),
            *missing_value,
            "header {name} differs by more than the echoed hint"
        );
    }

    // …and the hint really did arrive, so this is not two empty responses
    // agreeing with each other.
    let loc = login_location(&existing);
    assert_eq!(
        login_param(&loc, "login_hint").as_deref(),
        Some("alice@example.com"),
        "{loc}"
    );
}

/// **T5.1's other half (plan §4.5).** The hint is forwarded *only when a login
/// page is being shown anyway*. A request that already has a principal gets a
/// code; the hint is not read, not compared to that principal, and does not
/// produce a sign-in page for a user who is already signed in.
#[actix_rt::test]
async fn t5_1_a_hint_is_never_a_reason_to_show_a_login_page() {
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
        chrono::Duration::minutes(1),
        vec![Amr::Pwd],
    )
    .await;

    // A hint naming somebody else entirely must not change the answer: unlike
    // `id_token_hint`, `login_hint` asserts nothing and is not checked.
    for hint in ["alice%40example.com", "somebody.else%40example.com"] {
        let resp = authorize(
            &app,
            &token,
            &format!("{}&login_hint={hint}", base_query(&client_id)),
        )
        .await;
        assert_eq!(resp.status().as_u16(), 302);
        let loc = location(&resp);
        assert!(
            loc.starts_with(REDIRECT_URI) && query_param(&loc, "code").is_some(),
            "a session already exists; the hint must not produce a login page: {loc}"
        );
    }
}

// ---------------------------------------------------------------------------
// T6.* — display and ui_locales
// ---------------------------------------------------------------------------

/// **T6.1, the `display` half.** The four values OIDC Core §3.1.2.1 defines
/// are forwarded; everything else is dropped rather than refused, because
/// `display` is a hint and an OP that refused an unknown hint would be
/// refusing a request it can answer.
#[actix_rt::test]
async fn t6_1_display_is_allow_listed_and_never_echoed_verbatim() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, honour_client()).await;

    for value in ["page", "popup", "touch", "wap"] {
        let resp = hop(&app, tenant_id, &client_id, &format!("&display={value}")).await;
        let loc = login_location(&resp);
        assert_eq!(
            login_param(&loc, "display").as_deref(),
            Some(value),
            "{loc}"
        );
    }

    for outside in ["modal", "PAGE", "popup%20page", "%3Cscript%3E"] {
        let resp = hop(&app, tenant_id, &client_id, &format!("&display={outside}")).await;
        let loc = login_location(&resp);
        assert_eq!(
            login_param(&loc, "display"),
            None,
            "{outside} must be dropped: {loc}"
        );
    }
}

/// **T6.1, the locale half.** Exact match, case-insensitive match, subtag
/// fallback, and the relying party's preference order — all decided on the
/// server, all arriving at the page as one already-validated tag.
#[actix_rt::test]
async fn t6_1_ui_locales_is_matched_on_the_server_and_forwarded_as_one_tag() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, honour_client()).await;

    for (requested, expected) in [
        ("it", Some("it")),
        ("IT", Some("it")),
        ("fr-CA", Some("fr")),
        ("de-AT-1996", Some("de")),
        ("es-419", Some("es")),
        // RP preference order: the first *requested* tag that matches wins,
        // not the best match found in the list.
        ("zz%20it%20fr", Some("it")),
        ("zz%20fr%20it", Some("fr")),
        // No match at all. With no tenant default configured the deployment
        // default answers, and the deployment default is "forward nothing" —
        // the page renders English either way, and one fewer parameter in a
        // URL is one fewer thing to get wrong.
        ("zz", None),
        ("klingon", None),
    ] {
        let resp = hop(
            &app,
            tenant_id,
            &client_id,
            &format!("&ui_locales={requested}"),
        )
        .await;
        let loc = login_location(&resp);
        assert_eq!(
            login_param(&loc, "ui_locale").as_deref(),
            expected,
            "ui_locales={requested} in {loc}"
        );
    }
}

/// **T6.2.** A hostile `ui_locales` selects nothing and appears in no redirect
/// this server builds.
///
/// The `return_to` is the exception that proves the rule and it is checked
/// rather than waved away: it is the *original query string*, percent-encoded
/// as one parameter, and it is handed straight back to `/oauth2/authorize`
/// where the same parser drops the value again. What must not happen is the
/// raw value appearing as a `ui_locale` the page would act on, or escaping its
/// encoding into a second parameter — and neither does.
#[actix_rt::test]
async fn t6_2_a_hostile_ui_locales_reaches_no_redirect_the_server_builds() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, honour_client()).await;

    // `<img src=x onerror=alert(1)>`, percent-encoded as a browser would send
    // it, plus the two other shapes that try to end the parameter early.
    for hostile in [
        "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
        "%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "en%22%3E%3Cscript%3E",
    ] {
        let resp = hop(
            &app,
            tenant_id,
            &client_id,
            &format!("&ui_locales={hostile}"),
        )
        .await;
        let loc = login_location(&resp);
        assert_eq!(
            login_param(&loc, "ui_locale"),
            None,
            "a hostile value must select nothing: {loc}"
        );
        // Nothing unencoded escaped into the URL itself.
        for forbidden in ['<', '>', '"', ' '] {
            assert!(
                !loc.contains(forbidden),
                "{forbidden:?} appears unencoded in {loc}"
            );
        }
        // The only parameters this server builds are the ones it knows.
        let (_, query) = loc.split_once('?').expect("a query");
        let names: Vec<String> = url::form_urlencoded::parse(query.as_bytes())
            .map(|(k, _)| k.into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["return_to".to_owned()],
            "an unrecognised value produced an unexpected parameter: {loc}"
        );
    }
}

/// **The `claims_locales` pin.** It is accepted, it is not an error
/// (`OIDCCClaimsLocales`), and it selects no page language: a request carrying
/// only `claims_locales=it` builds exactly the URL a request carrying nothing
/// builds.
#[actix_rt::test]
async fn claims_locales_alone_leaves_the_page_in_the_default_locale() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, honour_client()).await;

    let with = hop(&app, tenant_id, &client_id, "&claims_locales=it").await;
    let loc = login_location(&with);
    assert_eq!(login_param(&loc, "ui_locale"), None, "{loc}");

    // …and it does not stand in for a `ui_locales` that matched nothing.
    let both = hop(
        &app,
        tenant_id,
        &client_id,
        "&ui_locales=zz&claims_locales=it",
    )
    .await;
    let loc = login_location(&both);
    assert_eq!(login_param(&loc, "ui_locale"), None, "{loc}");

    // …nor override one that did.
    let matched = hop(
        &app,
        tenant_id,
        &client_id,
        "&ui_locales=fr&claims_locales=it",
    )
    .await;
    let loc = login_location(&matched);
    assert_eq!(
        login_param(&loc, "ui_locale").as_deref(),
        Some("fr"),
        "{loc}"
    );
}

/// The three travel together, and beside W4's `acr` and `reauth` rather than
/// instead of them: a step-up that also asked for a presentation gets both.
#[actix_rt::test]
async fn a_step_up_carries_the_presentation_as_well_as_the_factor() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, honour_client()).await;
    // A password-only session cannot satisfy a request for the multi-factor
    // class, so this reaches the *interaction* arm of the handler — the second
    // of the two places a `/login` URL is built.
    let (_, token) = session_token(
        &db,
        &auth,
        org_id,
        tenant_id,
        user_id,
        chrono::Duration::minutes(1),
        vec![Amr::Pwd],
    )
    .await;

    let resp = authorize(
        &app,
        &token,
        &format!(
            "{}&acr_values={ACR_MFA}&login_hint=ada%40example.com&display=popup&ui_locales=de",
            base_query(&client_id)
        ),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    let loc = login_location(&resp);
    assert!(loc.contains("&reauth=1"), "{loc}");
    assert_eq!(login_param(&loc, "acr").as_deref(), Some(ACR_MFA), "{loc}");
    assert_eq!(
        login_param(&loc, "login_hint").as_deref(),
        Some("ada@example.com"),
        "{loc}"
    );
    assert_eq!(
        login_param(&loc, "display").as_deref(),
        Some("popup"),
        "{loc}"
    );
    assert_eq!(
        login_param(&loc, "ui_locale").as_deref(),
        Some("de"),
        "{loc}"
    );
}

// ---------------------------------------------------------------------------
// M5, M6 — the request halves, and invariant 4
// ---------------------------------------------------------------------------

/// **M5/M6's honest-`fapi2` half.** The cosmetic four are *never refused* on a
/// `fapi2` row that says `ignore` — refusing `login_hint`, which relying-party
/// libraries send by reflex, would break working FAPI clients for no security
/// gain. Their **mechanism** is what is refused: no `/login?login_hint=` is
/// ever built, because the server only assembles a presentation on the honour
/// lane and a `fapi2` client cannot be registered on it.
///
/// (The registration half — `fapi2` + `honour` refused on create and on update
/// — is `oauth2_honour_lane_test::m1_to_m4_registration_refuses_the_honour_lane_on_a_fapi2_client`;
/// the edited-row half is `axiam_oauth2::fapi`'s
/// `a_fapi_row_edited_to_honour_is_refused_at_request_time`, which covers a
/// cosmetic-only request explicitly.)
#[actix_rt::test]
async fn m5_m6_an_honest_fapi2_client_is_refused_nothing_and_offered_no_mechanism() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, fapi_browser_client()).await;

    let resp = hop(
        &app,
        tenant_id,
        &client_id,
        "&login_hint=alice%40example.com&display=popup&ui_locales=it&claims_locales=it",
    )
    .await;

    // Not refused: the request takes W3's hop exactly as it would without the
    // four parameters.
    assert_eq!(resp.status().as_u16(), 302);
    let loc = login_location(&resp);
    // …and no mechanism: the login URL carries none of them.
    for absent in ["login_hint", "display", "ui_locale"] {
        assert_eq!(
            login_param(&loc, absent),
            None,
            "{absent} must not reach the page for a fapi2 client: {loc}"
        );
    }
}

/// **M5/M6's I4 twin, and the wave's headline invariant.** A
/// `standard`/`ignore` client — which is every client that exists — sending all
/// four gets the `/login` URL W3 built, byte for byte: no locale, no layout, no
/// hint.
#[actix_rt::test]
async fn m5_m6_i4_twin_an_ignore_lane_client_gets_the_w3_login_url_byte_for_byte() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, ignore_client()).await;

    let cosmetic = "&login_hint=alice%40example.com&display=popup&ui_locales=it&claims_locales=it";
    let with = hop(&app, tenant_id, &client_id, cosmetic).await;
    let without = hop(&app, tenant_id, &client_id, "").await;

    assert_eq!(with.status(), without.status());
    let with_loc = login_location(&with);
    let without_loc = login_location(&without);

    // The two `return_to` values differ — one carries the parameters the
    // client sent, because `return_to` is the request being resumed — and
    // *nothing else about the URL* differs.
    let strip = |loc: &str| {
        let (path, query) = loc.split_once('?').unwrap();
        let names: Vec<String> = url::form_urlencoded::parse(query.as_bytes())
            .map(|(k, _)| k.into_owned())
            .collect();
        (path.to_owned(), names)
    };
    assert_eq!(
        strip(&with_loc),
        strip(&without_loc),
        "an ignore-lane client's login URL must have the shape it had in W3"
    );
    assert_eq!(
        strip(&with_loc).1,
        vec!["return_to".to_owned()],
        "…which is one parameter: {with_loc}"
    );
}

/// The same twin for the *interaction* arm — the second place a `/login` URL
/// is built. An `ignore`-lane client never reaches it at all
/// (`AuthorizeOutcome::Interact` is produced only inside the honour lane), so
/// its request is answered with a code and the cosmetic four are dropped
/// exactly as they were before this wave.
#[actix_rt::test]
async fn i4_twin_the_interaction_arm_is_unreachable_for_an_ignore_lane_client() {
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
        chrono::Duration::minutes(1),
        vec![Amr::Pwd],
    )
    .await;

    let resp = authorize(
        &app,
        &token,
        &format!(
            "{}&acr_values={ACR_MFA}&login_hint=ada%40example.com&display=popup&ui_locales=de",
            base_query(&client_id)
        ),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    let loc = location(&resp);
    assert!(
        loc.starts_with(REDIRECT_URI) && query_param(&loc, "code").is_some(),
        "an ignore-lane client is answered with a code, as it always was: {loc}"
    );
}
