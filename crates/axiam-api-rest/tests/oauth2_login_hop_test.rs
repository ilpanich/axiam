//! **W3 / Gap 0** — the browser login hop and the OP session cookie
//! (`claude_dev/basic-op-gap-plan.md` §4.0, tests T0.1–T0.6 and matrix row M7).
//!
//! Until this wave `/oauth2/authorize` could not answer an anonymous browser at
//! all. It required an access token — the `axiam_access` cookie or a
//! `Bearer`/`DPoP` header — and answered anything else with a 401 JSON body;
//! and because `axiam_access` is `SameSite=Strict`, the cross-site top-level
//! navigation that *is* a relying party's redirect never carried it. A
//! signed-in user arrived anonymous, every time.
//!
//! What lands here is one path out of that, opt-in per client, and this file's
//! job is to prove both halves of "opt-in":
//!
//! - the hop happens for a client registered `browser_sso` (T0.2, T0.4, and the
//!   end-to-end sign-in below), and
//! - **nothing at all** happens for a client that is not — which is every client
//!   registered today (T0.1, T0.5, and the golden 401 pin).
//!
//! No authentication-request parameter is honoured by any of this. A
//! `browser_sso` client that sends `prompt=none` gets exactly what it got
//! before; reading those parameters is W4.

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
use axiam_core::models::settings::system_defaults;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, SettingsRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealPushedAuthRequestRepository, SurrealSettingsRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12345";
const CSRF_TOKEN: &str = "test-csrf-token";
/// Test-only placeholder — not a real credential. gitleaks:allow
const PASSWORD: &str = "LoginHopPassw0rdStrong";
const REDIRECT_URI: &str = "https://rp.example.com/callback";

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
            name: "Hop Org".into(),
            slug: "hop-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Hop Tenant".into(),
            slug: "hop-tenant".into(),
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

/// The shipped limits with the browser-endpoint preset (`end_session_per_min`,
/// which sizes the `oauth2_authorize` bucket) lifted out of reach. The shared
/// counter pro-rates a peer first seen partway through a minute, so at the
/// shipped 30 a test that starts late in the minute is refused after as few as
/// three authorization requests (#532). The limit is pinned by
/// `oauth2_tenant_path_sso_test::p23w3_09_authorize_is_rate_limited_on_both_mounts`.
fn permissive_rate_limits() -> RateLimitConfig {
    RateLimitConfig {
        end_session_per_min: 100_000,
        ..RateLimitConfig::default()
    }
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
                .configure(|cfg| register_api_v1_routes::<TestDb>(cfg, &permissive_rate_limits())),
        )
        .await
    }};
}

/// The in-process app under test.
///
/// A trait with a blanket impl rather than a `dyn` alias: `Service` has an
/// associated `Future` that `init_service`'s concrete type supplies and that a
/// trait object would have to name.
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

/// Register a client, returning its `client_id`.
async fn create_client(app: &impl TestApp, token: &str, body: serde_json::Value) -> String {
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
    body["client_id"].as_str().unwrap().to_string()
}

fn plain_client(browser_sso: bool) -> serde_json::Value {
    serde_json::json!({
        "name": "Hop Test Client",
        "redirect_uris": [REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"],
        "scopes": ["openid", "profile"],
        "browser_sso": browser_sso,
    })
}

/// Sign in over HTTP and return the raw `axiam_op_session` cookie value.
async fn sign_in(app: &impl TestApp, org_id: Uuid, tenant_id: Uuid) -> String {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": PASSWORD,
        }))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "login must succeed");
    resp.response()
        .cookies()
        .find(|c| c.name() == "axiam_op_session")
        .map(|c| c.value().to_owned())
        .expect("a browser login must set axiam_op_session")
}

/// `GET /oauth2/authorize` with no credentials at all beyond the cookies given.
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

fn inline_query(client_id: &str, tenant_id: Uuid) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI}\
         &scope=openid&state=hop-state&tenant_id={tenant_id}"
    )
}

// ---------------------------------------------------------------------------
// T0.1 — the answer for every client that exists today, byte for byte
// ---------------------------------------------------------------------------

/// **T0.1 and the golden 401 pin (invariant 4).**
///
/// The whole wave is opt-in, and this is the assertion that says so in the one
/// form that cannot rot: the exact bytes of the response body a
/// `browser_sso = false` client's unauthenticated authorization request gets.
/// Every client registered today is such a client.
///
/// The literal is spelled out rather than compared against a helper, because a
/// helper that changed would change both sides of the comparison and the pin
/// would keep passing while the behaviour moved.
#[actix_rt::test]
async fn t0_1_an_unauthenticated_request_for_a_non_browser_sso_client_is_todays_401() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, plain_client(false)).await;

    for query in [
        inline_query(&client_id, tenant_id),
        // …with the tenant omitted, which is what a client registered today
        // actually sends, since the parameter did not exist before this wave.
        format!(
            "response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI}\
             &scope=openid&state=hop-state"
        ),
        // …and with every W1 parameter attached, none of which changes the
        // answer, because none of them is read.
        format!(
            "{}&prompt=none&max_age=0&login_hint=alice",
            inline_query(&client_id, tenant_id)
        ),
    ] {
        let resp = anonymous_authorize(&app, &query, None).await;
        assert_eq!(resp.status().as_u16(), 401, "query: {query}");
        assert!(
            resp.headers().get("Location").is_none(),
            "an opt-out client must never be redirected anywhere: {query}"
        );
        let body = test::read_body(resp).await;
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "{\"error\":\"authentication_failed\",\
             \"message\":\"Authentication failed: missing authentication credentials\"}",
            "the 401 body must be byte-identical to the one AXIAM has always \
             sent; query: {query}"
        );
    }
}

/// **T0.5** — the cookie is not merely unused for an opt-out client, it is
/// unread.
///
/// The distinction matters. A browser that has signed in to the admin UI is
/// carrying `axiam_op_session` on every navigation to this path, for every
/// client. If the endpoint resolved it first and consulted `browser_sso`
/// afterwards, a deployment would be one refactor away from honouring the
/// cookie for clients that never asked for it.
#[actix_rt::test]
async fn t0_5_the_op_session_cookie_is_not_honoured_for_a_client_that_did_not_opt_in() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, plain_client(false)).await;

    let op_cookie = sign_in(&app, org_id, tenant_id).await;
    let resp = anonymous_authorize(
        &app,
        &inline_query(&client_id, tenant_id),
        Some(&format!("axiam_op_session={op_cookie}")),
    )
    .await;

    assert_eq!(
        resp.status().as_u16(),
        401,
        "a live OP session must not authorize a client that did not opt in"
    );
    let body = test::read_body(resp).await;
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        "{\"error\":\"authentication_failed\",\
         \"message\":\"Authentication failed: missing authentication credentials\"}",
        "and the refusal is the same one, so the response cannot be used to \
         tell a signed-in browser from a signed-out one"
    );
}

/// The tenant is what makes the client loadable at all, and a request without
/// one is answered exactly as before — which is also why adding the parameter
/// cannot have changed anything for a client registered today.
#[actix_rt::test]
async fn without_a_tenant_an_anonymous_request_gets_todays_401_even_for_a_browser_sso_client() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, plain_client(true)).await;

    let resp = anonymous_authorize(
        &app,
        &format!(
            "response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI}&scope=openid"
        ),
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 401);
}

/// An anonymous caller must not be able to learn which client ids exist. The
/// unknown-client answer is the same 401 as the opted-out one — the only thing
/// the response distinguishes is whether the named client opted into the hop.
#[actix_rt::test]
async fn an_unknown_client_id_is_refused_the_same_way_as_one_that_did_not_opt_in() {
    let (db, _org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let resp = anonymous_authorize(
        &app,
        &inline_query("oa_0000000000000000000000000000dead", tenant_id),
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 401);
    let body = test::read_body(resp).await;
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        "{\"error\":\"authentication_failed\",\
         \"message\":\"Authentication failed: missing authentication credentials\"}"
    );
}

// ---------------------------------------------------------------------------
// T0.2 — the hop itself
// ---------------------------------------------------------------------------

/// **T0.2** — an anonymous request for a `browser_sso` client is redirected to
/// the sign-in page with a **path-only** `return_to`.
#[actix_rt::test]
async fn t0_2_an_anonymous_browser_sso_request_is_sent_to_the_login_page() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, plain_client(true)).await;

    let resp = anonymous_authorize(&app, &inline_query(&client_id, tenant_id), None).await;
    assert_eq!(resp.status().as_u16(), 302);

    let location = resp
        .headers()
        .get("Location")
        .expect("a Location header")
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        location.starts_with("/login?return_to="),
        "the login page is same-origin and named by path: {location}"
    );
    assert!(
        !location.contains("&reauth=1"),
        "nothing was stale — this browser presented no OP cookie: {location}"
    );

    let return_to = urlencoding_decode(location.trim_start_matches("/login?return_to="));
    assert!(
        return_to.starts_with("/oauth2/authorize?"),
        "return_to must be the authorization endpoint, as a path: {return_to}"
    );
    // The *path* is what decides where the browser goes; the query legitimately
    // carries an absolute `redirect_uri` for the relying party, which is why
    // this looks at the part before the `?` rather than at the whole value.
    let (path, _query) = return_to.split_once('?').expect("a query");
    assert_eq!(
        path, "/oauth2/authorize",
        "return_to must name the authorization endpoint and nothing else"
    );
    assert!(
        !return_to.starts_with("//") && !return_to.starts_with("/\\"),
        "return_to must not be scheme-relative: {return_to}"
    );
    assert!(
        return_to.contains("axiam_login_hop=1"),
        "return_to must carry the loop guard's marker: {return_to}"
    );
    assert!(
        return_to.contains(&format!("client_id={client_id}")),
        "the original request must survive the hop: {return_to}"
    );
    // The redirect carries the whole authorization request in its URL.
    assert_eq!(
        resp.headers()
            .get("Cache-Control")
            .unwrap()
            .to_str()
            .unwrap(),
        "no-store"
    );
    assert_eq!(
        resp.headers()
            .get("Referrer-Policy")
            .unwrap()
            .to_str()
            .unwrap(),
        "no-referrer"
    );
}

/// The whole hop, end to end: anonymous → login page → sign in → back to the
/// authorization endpoint carrying the cookie → an authorization code.
///
/// This is the property Gap 0 exists for. Before this wave the third step
/// could not happen at all.
#[actix_rt::test]
async fn a_browser_sso_client_completes_the_hop_and_receives_a_code() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, plain_client(true)).await;

    // Leg 1: anonymous.
    let first = anonymous_authorize(&app, &inline_query(&client_id, tenant_id), None).await;
    assert_eq!(first.status().as_u16(), 302);
    let return_to = urlencoding_decode(
        first
            .headers()
            .get("Location")
            .unwrap()
            .to_str()
            .unwrap()
            .trim_start_matches("/login?return_to="),
    );

    // The sign-in the login page performs.
    let op_cookie = sign_in(&app, org_id, tenant_id).await;

    // Leg 2: the SPA navigates to `return_to`, and the browser now carries the
    // path-scoped Lax cookie on a top-level navigation.
    let second = anonymous_authorize(
        &app,
        return_to.trim_start_matches("/oauth2/authorize?"),
        Some(&format!("axiam_op_session={op_cookie}")),
    )
    .await;
    assert_eq!(second.status().as_u16(), 302, "the code redirect");
    let location = second.headers().get("Location").unwrap().to_str().unwrap();
    assert!(
        location.starts_with(REDIRECT_URI),
        "the browser must be sent to the registered redirect_uri: {location}"
    );
    assert!(location.contains("code="), "with a code: {location}");
    assert!(
        location.contains("state=hop-state"),
        "and the relying party's state: {location}"
    );
}

// ---------------------------------------------------------------------------
// T0.4 / M7 — the return leg re-runs every gate
// ---------------------------------------------------------------------------

/// **T0.4 / M7.** The hop caches nothing and skips nothing. A `require_par`
/// client that arrives back from the login page with its parameters inline is
/// refused for exactly the reason it would be refused without a hop: the
/// setting exists to stop those parameters travelling through the browser, and
/// a login page in the middle does not make the browser more trustworthy.
#[actix_rt::test]
async fn t0_4_the_return_leg_still_refuses_a_require_par_client_sending_inline_parameters() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);

    let mut body = plain_client(true);
    body["require_par"] = serde_json::Value::Bool(true);
    let client_id = create_client(&app, &jwt, body).await;

    let op_cookie = sign_in(&app, org_id, tenant_id).await;
    let resp = anonymous_authorize(
        &app,
        &format!("{}&axiam_login_hop=1", inline_query(&client_id, tenant_id)),
        Some(&format!("axiam_op_session={op_cookie}")),
    )
    .await;

    assert_eq!(
        resp.status().as_u16(),
        400,
        "PAR-required must still be enforced on the return leg"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_request");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("must use pushed authorization requests"),
        "{body}"
    );
}

// ---------------------------------------------------------------------------
// The loop guard
// ---------------------------------------------------------------------------

/// The terminating case. A request that comes back from the login page still
/// carrying no session is answered, not redirected again.
///
/// Without this the deployment has a redirect loop: authorize sees no
/// principal, sends the browser to `/login`, the browser signs in (or fails to,
/// or stores no cookie, or signs into another tenant), comes back, and
/// authorize sees no principal again. The marker in `return_to` is what makes
/// the second visit distinguishable from the first, and this test is the proof
/// that the second visit ends the chain.
#[actix_rt::test]
async fn the_loop_guard_answers_the_return_leg_instead_of_redirecting_again() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, plain_client(true)).await;

    let resp = anonymous_authorize(
        &app,
        &format!("{}&axiam_login_hop=1", inline_query(&client_id, tenant_id)),
        None,
    )
    .await;

    assert_eq!(resp.status().as_u16(), 400);
    assert!(
        resp.headers().get("Location").is_none(),
        "the guard must not produce a third leg"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["error"], "login_required",
        "the answer names what is missing rather than blaming the request"
    );
}

/// A browser holding a cookie that no longer resolves is asked to sign in
/// **again** — `reauth=1` — and the dead cookie is removed on the way out.
///
/// This is the state that would otherwise loop: the browser believes it is
/// signed in, the SPA agrees with it, and nothing new happens. `reauth` is what
/// makes the next leg different from the last one.
#[actix_rt::test]
async fn a_stale_op_cookie_produces_a_reauth_hop_and_is_cleared() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, plain_client(true)).await;

    let resp = anonymous_authorize(
        &app,
        &inline_query(&client_id, tenant_id),
        Some("axiam_op_session=this-value-names-no-session"),
    )
    .await;

    assert_eq!(resp.status().as_u16(), 302);
    let location = resp.headers().get("Location").unwrap().to_str().unwrap();
    assert!(
        location.ends_with("&reauth=1"),
        "a stale cookie must ask for a fresh authentication: {location}"
    );
    let removal = resp
        .response()
        .cookies()
        .find(|c| c.name() == "axiam_op_session")
        .expect("the dead cookie must be cleared");
    assert_eq!(removal.value(), "");
    assert_eq!(removal.path(), Some("/oauth2/authorize"));
}

// ---------------------------------------------------------------------------
// The PAR window (F10)
// ---------------------------------------------------------------------------

/// A pushed request lives sixty seconds. A user who takes longer than that to
/// type a password comes back to a handle that is gone — and must be told
/// something they can act on.
///
/// The pair of assertions is the point: the recoverable code is used **only**
/// on a return leg, so an ordinary authorization request with a dead handle
/// still gets exactly the refusal it got before this wave.
#[actix_rt::test]
async fn a_pushed_request_that_expired_during_the_hop_fails_with_invalid_request_uri() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, plain_client(true)).await;
    let op_cookie = sign_in(&app, org_id, tenant_id).await;

    let dead_handle = "urn:ietf:params:oauth:request_uri:0000000000000000000000000000dead";

    // On the return leg: the recoverable answer.
    let resp = anonymous_authorize(
        &app,
        &format!(
            "client_id={client_id}&request_uri={}&tenant_id={tenant_id}&axiam_login_hop=1",
            urlencoding_encode(dead_handle)
        ),
        Some(&format!("axiam_op_session={op_cookie}")),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_request_uri");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("60 seconds"),
        "the description must say what expired and for how long it lived: {body}"
    );

    // Off the return leg: unchanged, because changing it would change
    // behaviour for a client registered today.
    let resp = anonymous_authorize(
        &app,
        &format!(
            "client_id={client_id}&request_uri={}&tenant_id={tenant_id}",
            urlencoding_encode(dead_handle)
        ),
        Some(&format!("axiam_op_session={op_cookie}")),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["error"], "invalid_request",
        "an ordinary request with a dead handle keeps today's answer"
    );
}

// ---------------------------------------------------------------------------
// A dead `request_uri` is refused BEFORE the sign-in page
// ---------------------------------------------------------------------------
//
// `/oauth2/authorize` cannot consume a pushed request while answering an
// anonymous browser: the handle is single-use and is spent in the handler,
// after a principal exists. So a request presenting a handle that was already
// used, expired, or issued to a different client used to be sent to `/login`
// without the handle being looked at at all — the person signed in for a
// request that had been dead before they started, and the refusal arrived on
// the way back.
//
// `ParService::peek` is the non-consuming read that closes that. These tests
// pin both directions: what it refuses, and — the one that is easy to break —
// what it must NOT refuse.

/// Store a pushed request directly, so a test can choose its exact state.
///
/// Through the repository rather than through `POST /oauth2/par` because the
/// endpoint authenticates the client, and what is under test here is the
/// authorization endpoint's behaviour for a handle in a given state, not the
/// push that produced it.
async fn push_handle(
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
    client_id: &str,
    lifetime_secs: i64,
) -> String {
    use axiam_core::models::oauth2_client::{CreatePushedAuthRequest, PushedAuthParams};
    use axiam_core::repository::PushedAuthRequestRepository;

    let request_uri = axiam_oauth2::par::generate_request_uri();
    SurrealPushedAuthRequestRepository::new(db.clone())
        .create(CreatePushedAuthRequest {
            tenant_id,
            client_id: client_id.to_owned(),
            request_uri_hash: axiam_oauth2::par::hash_request_uri(&request_uri),
            params: PushedAuthParams {
                response_type: "code".into(),
                redirect_uri: REDIRECT_URI.into(),
                scope: Some("openid".into()),
                ..Default::default()
            },
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(lifetime_secs),
        })
        .await
        .expect("the pushed request must store");
    request_uri
}

fn location(resp: &actix_web::dev::ServiceResponse) -> String {
    resp.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

/// **The module this exists for.**
/// `fapi2-security-profile-final-par-attempt-reuse-request_uri` re-sends the
/// browser to `/oauth2/authorize` with a `request_uri` that has already been
/// spent, and its condition asks for the error to come back to the client or
/// for an error page. Before this refusal the browser was sent to `/login`, so
/// the evidence the run produced was a screenshot of a sign-in form.
///
/// Redirected rather than rendered because the request names a `redirect_uri`
/// this client registered (RFC 6749 §4.1.2.1), and the code is OIDC Core
/// §3.1.2.6's `invalid_request_uri`: the relying party can act on that — push
/// again and restart — where `invalid_request` describes a client bug that did
/// not happen.
#[actix_rt::test]
async fn a_spent_request_uri_is_refused_before_the_login_hop() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, plain_client(true)).await;

    let handle = push_handle(&db, tenant_id, &client_id, 60).await;
    // Spend it, exactly as a completed authorization would.
    {
        use axiam_core::repository::PushedAuthRequestRepository;
        SurrealPushedAuthRequestRepository::new(db.clone())
            .consume(tenant_id, &axiam_oauth2::par::hash_request_uri(&handle))
            .await
            .unwrap()
            .expect("the handle must have been spendable once");
    }

    let resp = anonymous_authorize(
        &app,
        &format!(
            "client_id={client_id}&request_uri={}&redirect_uri={REDIRECT_URI}\
             &response_type=code&scope=openid&state=reuse-state&tenant_id={tenant_id}",
            urlencoding_encode(&handle)
        ),
        None,
    )
    .await;

    assert_eq!(resp.status().as_u16(), 302, "the refusal is redirected");
    let location = location(&resp);
    assert!(
        location.starts_with(REDIRECT_URI),
        "the error must go to the registered redirect_uri, not to /login: {location}"
    );
    assert!(
        location.contains("error=invalid_request_uri"),
        "OIDF's EnsureInvalidRequestUriError accepts this code and no other: {location}"
    );
    assert!(
        location.contains("state=reuse-state"),
        "an error response carries the request's own state: {location}"
    );
    assert!(
        !location.contains("/login"),
        "nobody may be asked to sign in for a request that is already dead: {location}"
    );
}

/// The same refusal with nowhere to send it is rendered for the person.
///
/// A refusal is not a licence to send a browser somewhere the client never
/// registered, so an absent or unregistered `redirect_uri` keeps the answer
/// this endpoint gave before the redirect existed — and keeps
/// `invalid_request`'s wording, because `invalid_request_uri` says nothing
/// useful to somebody who did not send the parameter.
#[actix_rt::test]
async fn a_spent_request_uri_with_nowhere_to_report_is_answered_directly() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, plain_client(true)).await;

    let dead = "urn:ietf:params:oauth:request_uri:0000000000000000000000000000dead";
    for query in [
        // No redirect_uri at all.
        format!(
            "client_id={client_id}&request_uri={}&tenant_id={tenant_id}",
            urlencoding_encode(dead)
        ),
        // One this client never registered.
        format!(
            "client_id={client_id}&request_uri={}&redirect_uri=https://attacker.example/steal\
             &tenant_id={tenant_id}",
            urlencoding_encode(dead)
        ),
    ] {
        let resp = anonymous_authorize(&app, &query, None).await;
        assert_eq!(resp.status().as_u16(), 400, "query: {query}");
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], "invalid_request", "query: {query}");
        assert!(
            body["error_description"]
                .as_str()
                .unwrap()
                .contains("unknown, expired, or used"),
            "the refusal keeps ParService's wording: {body}"
        );
    }
}

/// A handle issued to another client is refused too, and keeps its **own**
/// answer rather than collapsing into the "gone" one.
///
/// The distinction is deliberate in `axiam_oauth2::par` and is preserved here:
/// a client spending someone else's handle is a different failure from a
/// handle that no longer exists, and telling the two apart is what makes the
/// audit trail worth reading.
#[actix_rt::test]
async fn another_clients_request_uri_is_refused_before_the_login_hop() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let first = create_client(&app, &jwt, plain_client(true)).await;
    let second = create_client(&app, &jwt, plain_client(true)).await;

    let handle = push_handle(&db, tenant_id, &first, 60).await;

    let resp = anonymous_authorize(
        &app,
        &format!(
            "client_id={second}&request_uri={}&redirect_uri={REDIRECT_URI}\
             &response_type=code&scope=openid&tenant_id={tenant_id}",
            urlencoding_encode(&handle)
        ),
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    let location = location(&resp);
    assert!(
        location.contains("error=invalid_request"),
        "a wrong-client refusal keeps invalid_request: {location}"
    );
    assert!(
        !location.contains("invalid_request_uri"),
        "and must NOT be remapped to the gone-handle code: {location}"
    );
    assert!(!location.contains("/login"), "{location}");
}

/// **The regression this refusal is most likely to cause.**
///
/// `fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-\
/// completion-succeeds` presents ONE `request_uri` twice, before any
/// authorization has completed, and requires the login page both times — its
/// condition says so in as many words. A peek that refused an unconsumed handle,
/// or that spent it on the way past, would break that module while fixing the
/// other one.
///
/// So: two anonymous requests with the same live handle, both hopping to
/// `/login`, and the handle still spendable afterwards.
#[actix_rt::test]
async fn an_unconsumed_request_uri_still_reaches_the_login_page_twice() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, plain_client(true)).await;

    let handle = push_handle(&db, tenant_id, &client_id, 60).await;
    let query = format!(
        "client_id={client_id}&request_uri={}&redirect_uri={REDIRECT_URI}\
         &response_type=code&scope=openid&tenant_id={tenant_id}",
        urlencoding_encode(&handle)
    );

    for attempt in 1..=2 {
        let resp = anonymous_authorize(&app, &query, None).await;
        assert_eq!(
            resp.status().as_u16(),
            302,
            "visit {attempt} must hop to the sign-in page"
        );
        let location = location(&resp);
        assert!(
            location.starts_with("/login?return_to="),
            "visit {attempt} must reach the login page, not a refusal: {location}"
        );
    }

    // The peek is a read. Spending must still be possible, and must still be
    // the handler's decision.
    use axiam_core::repository::PushedAuthRequestRepository;
    assert!(
        SurrealPushedAuthRequestRepository::new(db.clone())
            .consume(tenant_id, &axiam_oauth2::par::hash_request_uri(&handle))
            .await
            .unwrap()
            .is_some(),
        "two login hops must leave the handle spendable"
    );
}

/// A `request_uri` that is not a PAR handle is a request object by reference,
/// and keeps the OIDC Core §3.1.2.6 code that goes with it.
///
/// The peek deliberately does not answer for this shape: `request_uri_not_\
/// supported` is more specific than `invalid_request`, a conformance suite
/// matches on it, and `classify_request_object` in the handler already owns it.
#[actix_rt::test]
async fn a_request_object_by_reference_keeps_its_own_refusal() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, plain_client(true)).await;
    let op_cookie = sign_in(&app, org_id, tenant_id).await;

    let resp = anonymous_authorize(
        &app,
        &format!(
            "client_id={client_id}&request_uri={}&redirect_uri={REDIRECT_URI}\
             &response_type=code&scope=openid&tenant_id={tenant_id}",
            urlencoding_encode("https://attacker.example/request.jwt")
        ),
        Some(&format!("axiam_op_session={op_cookie}")),
    )
    .await;
    let status = resp.status().as_u16();
    let location = location(&resp);
    assert!(
        location.contains("request_uri_not_supported") || status == 400,
        "status {status}, location {location}"
    );
    assert!(
        !location.contains("error=invalid_request&"),
        "the peek must not have swallowed the by-reference refusal: {location}"
    );
}

// ---------------------------------------------------------------------------
// T0.6 — the cookie, as the browser receives it
// ---------------------------------------------------------------------------

/// **T0.6.** The attributes are unit-pinned in
/// `axiam_api_rest::middleware::csrf`; what this adds is that the login
/// response actually carries them, and that the three API cookies beside it are
/// untouched.
#[actix_rt::test]
async fn t0_6_a_browser_login_sets_the_op_session_cookie_with_its_intended_attributes() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": PASSWORD,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let cookies: Vec<_> = resp.response().cookies().collect();
    let op = cookies
        .iter()
        .find(|c| c.name() == "axiam_op_session")
        .expect("axiam_op_session");
    assert_eq!(op.same_site(), Some(actix_web::cookie::SameSite::Lax));
    assert_eq!(op.path(), Some("/oauth2/authorize"));
    assert!(op.http_only().unwrap_or(false));
    assert!(!op.value().is_empty());

    // The API cookies keep the posture SEC-046 gave them. A second cookie was
    // added precisely so that these three did not have to change.
    for name in ["axiam_access", "axiam_refresh", "axiam_csrf"] {
        let c = cookies
            .iter()
            .find(|c| c.name() == name)
            .unwrap_or_else(|| panic!("{name} must still be set"));
        assert_eq!(
            c.same_site(),
            Some(actix_web::cookie::SameSite::Strict),
            "{name} must remain SameSite=Strict"
        );
    }

    // …and the OP cookie is a credential of its own, not a copy of one.
    let access = cookies.iter().find(|c| c.name() == "axiam_access").unwrap();
    let refresh = cookies
        .iter()
        .find(|c| c.name() == "axiam_refresh")
        .unwrap();
    // `assert_ne!` would print both credentials on failure, so the comparison
    // is made first and only its result is asserted.
    assert!(
        op.value() != access.value(),
        "the OP cookie must be its own bytes, not a copy of the access token"
    );
    assert!(
        op.value() != refresh.value(),
        "the OP cookie must be its own bytes, not a copy of the refresh token"
    );
}

/// Logging out takes the OP session with it. Otherwise a user who signed out
/// through the admin UI would still be recognised, silently, by the next
/// relying party that redirected them here.
#[actix_rt::test]
async fn logging_out_clears_the_op_session_cookie_and_the_session_it_names() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, plain_client(true)).await;

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": PASSWORD,
        }))
        .to_request();
    let login = test::call_service(&app, req).await;
    let cookies: Vec<_> = login.response().cookies().collect();
    let op_cookie = cookies
        .iter()
        .find(|c| c.name() == "axiam_op_session")
        .unwrap()
        .value()
        .to_owned();
    let access = cookies
        .iter()
        .find(|c| c.name() == "axiam_access")
        .unwrap()
        .value()
        .to_owned();
    let csrf = cookies
        .iter()
        .find(|c| c.name() == "axiam_csrf")
        .unwrap()
        .value()
        .to_owned();

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/logout")
        .insert_header((
            "Cookie",
            format!("axiam_access={access}; axiam_csrf={csrf}"),
        ))
        .insert_header(("X-CSRF-Token", csrf.clone()))
        .to_request();
    let out = test::call_service(&app, req).await;
    assert_eq!(out.status().as_u16(), 204);
    let removal = out
        .response()
        .cookies()
        .find(|c| c.name() == "axiam_op_session")
        .expect("logout must clear the OP cookie");
    assert_eq!(removal.value(), "");
    assert_eq!(removal.path(), Some("/oauth2/authorize"));

    // And the value it held names nothing any more, whatever the browser kept.
    let resp = anonymous_authorize(
        &app,
        &inline_query(&client_id, tenant_id),
        Some(&format!("axiam_op_session={op_cookie}")),
    )
    .await;
    assert_eq!(
        resp.status().as_u16(),
        302,
        "the revoked session cannot authorize; the browser is asked to sign in"
    );
}

// ---------------------------------------------------------------------------
// The authenticated path is untouched
// ---------------------------------------------------------------------------

/// A request carrying an access token behaves exactly as it did, and the
/// `tenant_id` parameter is ignored for it — the token's tenant is the tenant
/// it acts in, and letting a query string move that would be a tenant-crossing
/// primitive handed to whoever holds the browser.
#[actix_rt::test]
async fn a_token_bearing_request_is_unaffected_and_ignores_the_tenant_parameter() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, plain_client(false)).await;

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!(
            "/oauth2/authorize?response_type=code&client_id={client_id}\
             &redirect_uri={REDIRECT_URI}&scope=openid&state=hop-state\
             &tenant_id={}",
            Uuid::new_v4()
        ))
        .insert_header(("Authorization", format!("Bearer {jwt}")))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status().as_u16(), 302);
    let location = resp.headers().get("Location").unwrap().to_str().unwrap();
    assert!(
        location.starts_with(REDIRECT_URI) && location.contains("code="),
        "a foreign tenant_id must not have moved the request: {location}"
    );
}

// ---------------------------------------------------------------------------
// T23.1.3 — the independent audit of X7.3
// ---------------------------------------------------------------------------
//
// Everything below was written by an audit of the shipped hop against
// `basic-op-gap-plan.md` §4.0 and T-237/T-238/T-255. Each test pins a property
// the plan or the threat model states and that no test above asserted. The
// first one failed against the tree the audit started from.

/// **The defect the audit found.** An OP session outlives a change to the
/// account it acts for, unless the account is re-read when the session is.
///
/// Before this, a user an administrator locked or deactivated after they had
/// signed in kept a cookie that bought authorization codes — and with them
/// access and refresh tokens at every `browser_sso` relying party — for the
/// whole of the session's lifetime (`refresh_token_lifetime_secs`, thirty days
/// here). `PUT /api/v1/users/{id}` with a non-active `status` does not revoke
/// sessions; it relies on the refresh path re-reading `check_user_status`, and
/// `/oauth2/authorize` was the one session-accepting path that did not.
///
/// The cookie now resolves to a principal only while the account would be
/// allowed to sign in, by the same rule the refresh path applies. A browser
/// whose account was suspended is treated exactly like one whose session was
/// revoked: asked to sign in again (`reauth`, cookie cleared), and answered
/// `login_required` on the return leg rather than issued a code.
#[actix_rt::test]
async fn an_op_session_stops_authorizing_once_its_account_is_suspended_or_removed() {
    for status in [
        UserStatus::Locked,
        UserStatus::Inactive,
        UserStatus::Deleted,
        UserStatus::Anonymized,
    ] {
        let (db, org_id, tenant_id, user_id) = setup_db().await;
        let auth = test_auth_config();
        let app = test_app!(db, auth);
        let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
        let client_id = create_client(&app, &jwt, plain_client(true)).await;
        let op_cookie = sign_in(&app, org_id, tenant_id).await;
        let cookie = format!("axiam_op_session={op_cookie}");

        // Control: while the account is active the cookie authorizes, so the
        // refusal below is about the account and nothing else.
        let live =
            anonymous_authorize(&app, &inline_query(&client_id, tenant_id), Some(&cookie)).await;
        assert_eq!(live.status().as_u16(), 302, "{status:?}: control");
        assert!(
            location(&live).starts_with(REDIRECT_URI) && location(&live).contains("code="),
            "{status:?}: an active account's cookie must authorize: {}",
            location(&live)
        );

        SurrealUserRepository::new(db.clone())
            .update(
                tenant_id,
                user_id,
                UpdateUser {
                    status: Some(status.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let resp =
            anonymous_authorize(&app, &inline_query(&client_id, tenant_id), Some(&cookie)).await;
        assert_eq!(resp.status().as_u16(), 302, "{status:?}");
        let loc = location(&resp);
        assert!(
            loc.starts_with("/login?return_to=") && !loc.contains("code="),
            "{status:?}: a suspended account's session must not buy a code: {loc}"
        );
        assert!(
            loc.contains("&reauth=1"),
            "{status:?}: the browser believes it is signed in and is not: {loc}"
        );
        let removal = resp
            .response()
            .cookies()
            .find(|c| c.name() == "axiam_op_session")
            .unwrap_or_else(|| panic!("{status:?}: the cookie must be cleared"));
        assert_eq!(removal.value(), "");

        // The return leg is terminal, and still not a code.
        let back = anonymous_authorize(
            &app,
            &format!("{}&axiam_login_hop=1", inline_query(&client_id, tenant_id)),
            Some(&cookie),
        )
        .await;
        assert_eq!(back.status().as_u16(), 400, "{status:?}");
        assert!(back.headers().get("Location").is_none(), "{status:?}");
        let body: serde_json::Value = test::read_body_json(back).await;
        assert_eq!(body["error"], "login_required", "{status:?}");
    }
}

/// **F4 P23W1-03.** A `PendingVerification` account keeps its OP session,
/// whatever the grace period says.
///
/// T23.1.3 first applied the password sign-in rule here, grace period
/// included, and so refused this cookie once the period ended. But
/// `UserRepository::create` writes `PendingVerification` for every new row and
/// federation provisioning never moves a federated user off it (there is
/// nothing for AXIAM to verify), so **every federated account is pending for
/// life**: browser sign-on stopped working for the whole federated population
/// a day after each account was provisioned, and the hop sent them round
/// `/login` and back to `login_required`. The grace period is a rule about
/// signing in with a password, which this session has already done; the
/// statuses that mean "this account must not be used" are the four
/// `an_op_session_stops_authorizing_once_its_account_is_suspended_or_removed`
/// pins — the rule T-160 already applies to the token-exchange path.
#[actix_rt::test]
async fn p23w1_03_an_op_session_survives_a_pending_verification_status() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    // No grace period, so a pending account is one whose grace has ended.
    let auth = AuthConfig {
        email_verification_grace_period_hours: 0,
        ..test_auth_config()
    };
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, plain_client(true)).await;
    let op_cookie = sign_in(&app, org_id, tenant_id).await;

    SurrealUserRepository::new(db.clone())
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                status: Some(UserStatus::PendingVerification),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let resp = anonymous_authorize(
        &app,
        &inline_query(&client_id, tenant_id),
        Some(&format!("axiam_op_session={op_cookie}")),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    let loc = location(&resp);
    assert!(
        loc.starts_with(REDIRECT_URI) && loc.contains("code="),
        "a pending account's live session must still authorize: {loc}"
    );
}

/// A cookie is a session **in one tenant**. Presented with another tenant's
/// `tenant_id` it names nothing — so the browser is asked to sign in, rather
/// than issued a code in a tenant the session was never authenticated in — and
/// it still authorizes in its own.
///
/// The repository read is tenant-scoped (`axiam-db`'s
/// `the_op_browser_session_resolves_only_a_live_row_in_the_right_tenant`); this
/// is the same property through the endpoint, where the tenant comes from a
/// query parameter the browser controls.
#[actix_rt::test]
async fn an_op_cookie_minted_in_one_tenant_never_authorizes_in_another() {
    let (db, org_id, tenant_a, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let tenant_b = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org_id,
            kind: TenantKind::Standard,
            name: "Other Tenant".into(),
            slug: "other-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    let client_a = create_client(
        &app,
        &admin_jwt(&auth, user_id, tenant_a, org_id),
        plain_client(true),
    )
    .await;
    let client_b = create_client(
        &app,
        &admin_jwt(&auth, user_id, tenant_b, org_id),
        plain_client(true),
    )
    .await;

    let cookie = format!("axiam_op_session={}", sign_in(&app, org_id, tenant_a).await);

    let crossed =
        anonymous_authorize(&app, &inline_query(&client_b, tenant_b), Some(&cookie)).await;
    assert_eq!(crossed.status().as_u16(), 302);
    let loc = location(&crossed);
    assert!(
        loc.starts_with("/login?return_to=") && !loc.contains("code="),
        "tenant A's session must not authorize in tenant B: {loc}"
    );

    // …and tenant A's client cannot be reached by naming tenant B either: the
    // client is loaded in the tenant the query names, and it is not there.
    let wrong_tenant =
        anonymous_authorize(&app, &inline_query(&client_a, tenant_b), Some(&cookie)).await;
    assert_eq!(wrong_tenant.status().as_u16(), 401);

    let home = anonymous_authorize(&app, &inline_query(&client_a, tenant_a), Some(&cookie)).await;
    assert!(
        location(&home).starts_with(REDIRECT_URI) && location(&home).contains("code="),
        "the same cookie still authorizes in its own tenant: {}",
        location(&home)
    );
}

/// **Session fixation.** A sign-in mints a new browser-session value every
/// time and never adopts one the browser presents.
///
/// The attack this pins is the classic one: a value the attacker chose is
/// planted in the victim's browser before they sign in, and the attacker then
/// rides the session it comes to name. That works only if authentication
/// upgrades the presented identifier; here the presented value is never read
/// by the login handler, so it names nothing before the sign-in and nothing
/// after it.
#[actix_rt::test]
async fn a_sign_in_never_adopts_an_op_cookie_the_browser_already_holds() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, plain_client(true)).await;

    let planted = "planted-by-an-attacker-0123456789abcdefghijk";
    let login = |cookie: String| {
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/auth/login")
            .insert_header(("Cookie", cookie))
            .set_json(serde_json::json!({
                "tenant_id": tenant_id,
                "org_id": org_id,
                "username_or_email": "alice",
                "password": PASSWORD,
            }))
            .to_request()
    };
    let minted_by = |resp: &actix_web::dev::ServiceResponse| {
        resp.response()
            .cookies()
            .find(|c| c.name() == "axiam_op_session")
            .map(|c| c.value().to_owned())
            .expect("a browser login must set axiam_op_session")
    };

    let first = test::call_service(&app, login(format!("axiam_op_session={planted}"))).await;
    assert_eq!(first.status().as_u16(), 200);
    let minted = minted_by(&first);
    assert!(
        minted != planted,
        "the login must mint its own value, not adopt the presented one"
    );
    assert_eq!(
        minted.len(),
        43,
        "256 bits, base64url without padding: the value is the server's"
    );

    // The planted value names no session, after the sign-in as before it.
    let resp = anonymous_authorize(
        &app,
        &inline_query(&client_id, tenant_id),
        Some(&format!("axiam_op_session={planted}")),
    )
    .await;
    assert!(
        location(&resp).starts_with("/login?return_to="),
        "{}",
        location(&resp)
    );

    // Every authentication mints afresh — including one that presents the
    // value the previous authentication minted.
    let second = test::call_service(&app, login(format!("axiam_op_session={minted}"))).await;
    assert_eq!(second.status().as_u16(), 200);
    assert!(
        minted_by(&second) != minted,
        "a second sign-in must not reuse the first one's value"
    );
}

/// The cookie is issued by a **completed** authentication only. A password step
/// that still owes a second factor answers `202` with a challenge, and must set
/// no OP session — otherwise a password alone would buy authorization codes at
/// every `browser_sso` relying party, skipping the factor the account demands.
#[actix_rt::test]
async fn a_password_step_that_still_owes_a_second_factor_sets_no_op_session() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    SurrealUserRepository::new(db.clone())
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                mfa_enabled: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": PASSWORD,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 202, "a second factor is owed");
    assert!(
        resp.response()
            .cookies()
            .all(|c| c.name() != "axiam_op_session"),
        "the password step alone must not establish an OP session"
    );
}

/// When an access token and an OP cookie arrive together, the token decides who
/// the request is for, and the cookie cannot move it to somebody else.
///
/// Bob's bearer token with Alice's OP cookie: the code is Bob's. The two are
/// never merged and the cookie is not consulted at all once the token
/// resolves, so a browser cannot be made to act for one user by carrying
/// another's cookie.
#[actix_rt::test]
async fn an_access_token_wins_over_the_op_cookie_and_the_two_never_cross_users() {
    let (db, org_id, tenant_id, alice) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, alice, tenant_id, org_id);
    let (client_id, secret) = create_client_with_secret(&app, &jwt, plain_client(true)).await;

    let users = SurrealUserRepository::new(db.clone());
    let bob = users
        .create(CreateUser {
            tenant_id,
            username: "bob".into(),
            email: "bob@example.com".into(),
            password: PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    users
        .update(
            tenant_id,
            bob,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let alice_cookie = sign_in(&app, org_id, tenant_id).await;
    let bob_token = admin_jwt(&auth, bob, tenant_id, org_id);

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!(
            "/oauth2/authorize?{}",
            inline_query(&client_id, tenant_id)
        ))
        .insert_header(("Authorization", format!("Bearer {bob_token}")))
        .insert_header(("Cookie", format!("axiam_op_session={alice_cookie}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 302);
    let code = query_param(&location(&resp), "code").expect("a code");

    let sub = id_token_subject(&app, tenant_id, &client_id, &secret, &code).await;
    assert_eq!(sub, bob.to_string(), "the token's subject decides");
    assert_ne!(sub, alice.to_string());
}

/// `Path=/oauth2/authorize` scopes the cookie to one endpoint, and the endpoint
/// is `GET` only. A `POST` — the form-post shape a `SameSite=Lax` cookie is
/// *not* sent on cross-site, but which a same-site page could still produce —
/// is not routed at all, so no state-changing request is ever answered with the
/// OP session (G11 was declined; plan §4.9).
#[actix_rt::test]
async fn the_op_session_reaches_no_endpoint_but_get_authorize() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, plain_client(true)).await;
    let cookie = format!(
        "axiam_op_session={}",
        sign_in(&app, org_id, tenant_id).await
    );

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/oauth2/authorize")
        .insert_header(("Cookie", cookie.clone()))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(inline_query(&client_id, tenant_id))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        matches!(resp.status().as_u16(), 404 | 405),
        "POST /oauth2/authorize must not be routed: {}",
        resp.status()
    );
    assert!(resp.headers().get("Location").is_none());

    // The cookie is not an API credential either: the API answers it as it
    // answers no credential at all.
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/me")
        .insert_header(("Cookie", cookie))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 401);
}

/// The hop reflects nothing. The `302` carries no body at all, and the
/// loop guard's terminal answer — the one arm of the hop rendered as a page,
/// for a browser that asks for HTML — echoes neither the request's parameters
/// nor a `return_to` somebody appended to them.
#[actix_rt::test]
async fn the_login_hop_reflects_no_request_parameter_into_a_body() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, plain_client(true)).await;
    // `inline_query` without its `state`, which is replaced by a hostile one:
    // a repeated parameter is a query error, not a reflection test.
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI}&scope=openid\
         &tenant_id={tenant_id}&state=%3Cscript%3Ealert(1)%3C%2Fscript%3E\
         &return_to=https%3A%2F%2Fevil.example%2F"
    );

    let hop = anonymous_authorize(&app, &query, None).await;
    assert_eq!(hop.status().as_u16(), 302);
    let loc = location(&hop);
    assert!(loc.starts_with("/login?return_to="), "{loc}");
    // The appended `return_to` is carried inside the encoded authorization
    // request, never promoted to the SPA's own parameter.
    assert_eq!(loc.matches("return_to=").count(), 1, "{loc}");
    assert!(test::read_body(hop).await.is_empty(), "a 302 with no body");

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/authorize?{query}&axiam_login_hop=1"))
        .insert_header(("Accept", "text/html"))
        .to_request();
    let page = test::call_service(&app, req).await;
    assert_eq!(page.status().as_u16(), 400);
    let body = String::from_utf8(test::read_body(page).await.to_vec()).unwrap();
    assert!(body.contains("login_required"), "{body}");
    for echoed in ["<script", "alert(1)", "evil.example", &client_id] {
        assert!(!body.contains(echoed), "{echoed:?} reflected into {body}");
    }
}

// ---------------------------------------------------------------------------
// The error path delivers only to a registered redirect_uri (T-255, T-259)
// ---------------------------------------------------------------------------

/// The sign-in page's Cancel returns `access_denied` to the relying party — to
/// a `redirect_uri` this client registered, with its `state` — and to nowhere
/// else. An unregistered target, or a `return_to` appended to the request, is
/// answered in place; and a live OP cookie does not turn the refusal into a
/// grant.
#[actix_rt::test]
async fn a_declined_sign_in_is_reported_only_to_a_registered_redirect_uri() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, plain_client(true)).await;
    let cookie = format!(
        "axiam_op_session={}",
        sign_in(&app, org_id, tenant_id).await
    );

    for cookies in [None, Some(cookie.as_str())] {
        let resp = anonymous_authorize(
            &app,
            &format!(
                "{}&axiam_login_hop=1&axiam_user_declined=1",
                inline_query(&client_id, tenant_id)
            ),
            cookies,
        )
        .await;
        assert_eq!(resp.status().as_u16(), 302, "cookie: {cookies:?}");
        let loc = location(&resp);
        assert!(loc.starts_with(REDIRECT_URI), "{loc}");
        assert!(loc.contains("error=access_denied"), "{loc}");
        assert!(loc.contains("state=hop-state"), "{loc}");
        assert!(!loc.contains("code="), "a refusal is never a code: {loc}");
    }

    for redirect_uri in [
        "https%3A%2F%2Fevil.example%2Fcb",
        // A prefix of the registered one is not the registered one.
        "https%3A%2F%2Frp.example.com%2Fcallback%2F..%2Fevil",
    ] {
        let resp = anonymous_authorize(
            &app,
            &format!(
                "response_type=code&client_id={client_id}&redirect_uri={redirect_uri}\
                 &scope=openid&state=hop-state&tenant_id={tenant_id}\
                 &return_to=https%3A%2F%2Fevil.example%2F\
                 &axiam_login_hop=1&axiam_user_declined=1"
            ),
            None,
        )
        .await;
        assert_eq!(resp.status().as_u16(), 400, "{redirect_uri}");
        assert!(
            resp.headers().get("Location").is_none(),
            "an unregistered target is never redirected to: {redirect_uri}"
        );
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], "access_denied");
    }
}

/// Every redirectable error the anonymous path raises goes to the registered
/// `redirect_uri` or nowhere — never to a `return_to` the request carried,
/// which the authorization endpoint does not read at all.
#[actix_rt::test]
async fn an_anonymous_refusal_never_redirects_to_a_return_to_the_request_carried() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, plain_client(true)).await;

    // `response_type` missing: decided before the hop (T-270), redirected to
    // the registered URI.
    let resp = anonymous_authorize(
        &app,
        &format!(
            "client_id={client_id}&redirect_uri={REDIRECT_URI}&scope=openid&state=hop-state\
             &tenant_id={tenant_id}&return_to=https%3A%2F%2Fevil.example%2F"
        ),
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    let loc = location(&resp);
    assert!(
        loc.starts_with(REDIRECT_URI) && loc.contains("error=invalid_request"),
        "{loc}"
    );
    assert!(!loc.contains("evil.example"), "{loc}");

    // The same with an unregistered target: answered in place.
    let resp = anonymous_authorize(
        &app,
        &format!(
            "client_id={client_id}&redirect_uri=https%3A%2F%2Fevil.example%2Fcb&scope=openid\
             &tenant_id={tenant_id}&return_to=https%3A%2F%2Fevil.example%2F"
        ),
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 400);
    assert!(resp.headers().get("Location").is_none());
}

// ---------------------------------------------------------------------------
// M7 — a `fapi2` client may hop, and the return leg skips none of FAPI's gates
// ---------------------------------------------------------------------------

/// A `fapi2` client a browser may reach. `browser_sso` is the one Basic-lane
/// field the two-layer gate permits on `fapi2` (plan §3.1, D2).
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

/// **M7, first half.** `fapi2` + `browser_sso` + `require_par`: the return leg
/// of a hop, carrying a live OP session and its parameters inline, is refused
/// `ParRequired` exactly as a request that never hopped would be. A sign-in
/// page in the middle does not make the browser a trustworthy carrier.
#[actix_rt::test]
async fn m7_a_fapi2_return_leg_with_inline_parameters_is_par_required() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, fapi_browser_client()).await;
    let cookie = format!(
        "axiam_op_session={}",
        sign_in(&app, org_id, tenant_id).await
    );

    let resp = anonymous_authorize(
        &app,
        &format!(
            "{}&code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256&axiam_login_hop=1",
            inline_query(&client_id, tenant_id)
        ),
        Some(&cookie),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 400);
    assert!(
        resp.headers().get("Location").is_none(),
        "ParRequired is answered in place: the redirect_uri arrived by the forbidden channel"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_request");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("must use pushed authorization requests"),
        "{body}"
    );
}

/// **M7, second half.** The same client's pushed request without a
/// `code_challenge`, presented on the return leg with a live OP session, gets
/// the FAPI 2.0 §5.3.1.2 PKCE refusal — not a code. The same handle shape
/// *with* a challenge is the control: it is PKCE, and only PKCE, that is
/// refused.
#[actix_rt::test]
async fn m7_a_fapi2_return_leg_without_pkce_gets_the_fapi_pkce_refusal() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, fapi_browser_client()).await;
    let cookie = format!(
        "axiam_op_session={}",
        sign_in(&app, org_id, tenant_id).await
    );

    let without = push_handle(&db, tenant_id, &client_id, 60).await;
    let resp = anonymous_authorize(
        &app,
        &format!(
            "client_id={client_id}&request_uri={}&tenant_id={tenant_id}&axiam_login_hop=1",
            urlencoding_encode(&without)
        ),
        Some(&cookie),
    )
    .await;
    let loc = location(&resp);
    assert!(!loc.contains("code="), "no PKCE, no code: {loc}");
    assert!(
        loc.starts_with(REDIRECT_URI) && loc.contains("error=invalid_request"),
        "the refusal goes to the pushed, registered redirect_uri: {loc}"
    );
    let description = query_param(&loc, "error_description").unwrap_or_default();
    assert!(
        description.contains("PKCE") && description.contains("fapi2"),
        "the FAPI PKCE refusal, by name: {description}"
    );

    let with = push_handle_with_pkce(&db, tenant_id, &client_id).await;
    let resp = anonymous_authorize(
        &app,
        &format!(
            "client_id={client_id}&request_uri={}&tenant_id={tenant_id}&axiam_login_hop=1",
            urlencoding_encode(&with)
        ),
        Some(&cookie),
    )
    .await;
    let loc = location(&resp);
    assert!(
        loc.starts_with(REDIRECT_URI) && loc.contains("code="),
        "control: the same pushed request with PKCE is authorized: {loc}"
    );
}

/// **#524 (P23W2-03).** An anonymous browser sending a `require_par` client's
/// parameters inline is refused `ParRequired` before the login hop, in place:
/// `400`, no `Location` (neither `/login` nor the inline `redirect_uri`) and
/// the PAR wording — as a page for a browser and as the JSON object otherwise.
/// Until #524 it was sent to `/login`, and refused only on the return leg.
/// The control: the same client's pushed request still takes the hop.
#[actix_rt::test]
async fn p23w2_03_an_anonymous_unpushed_request_of_a_require_par_client_is_refused_before_the_hop()
{
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let client_id = create_client(&app, &jwt, fapi_browser_client()).await;
    let inline = format!(
        "{}&code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        inline_query(&client_id, tenant_id)
    );

    // A browser: the page, not a sign-in.
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/authorize?{inline}"))
        .insert_header(("Accept", "text/html,application/xhtml+xml"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
    assert!(
        resp.headers().get("Location").is_none(),
        "refused in place, never sent to /login: {}",
        location(&resp)
    );
    let page = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
    assert!(
        page.contains(
            "this client must use pushed authorization requests (RFC 9126); \
             send parameters to /oauth2/par first"
        ),
        "{page}"
    );

    // Not a browser: the same refusal as the JSON object.
    let resp = anonymous_authorize(&app, &inline, None).await;
    assert_eq!(resp.status().as_u16(), 400);
    assert!(resp.headers().get("Location").is_none());
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_request");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("must use pushed authorization requests (RFC 9126)"),
        "{body}"
    );

    // Control: a pushed request is what this client may send, and it hops.
    let pushed = push_handle_with_pkce(&db, tenant_id, &client_id).await;
    let resp = anonymous_authorize(
        &app,
        &format!(
            "client_id={client_id}&request_uri={}&tenant_id={tenant_id}",
            urlencoding_encode(&pushed)
        ),
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    assert!(
        location(&resp).starts_with("/login?"),
        "{}",
        location(&resp)
    );
}

/// A valid S256 challenge (RFC 7636 Appendix B).
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// [`push_handle`], with a PKCE challenge.
async fn push_handle_with_pkce(db: &Surreal<TestDb>, tenant_id: Uuid, client_id: &str) -> String {
    use axiam_core::models::oauth2_client::{CreatePushedAuthRequest, PushedAuthParams};
    use axiam_core::repository::PushedAuthRequestRepository;

    let request_uri = axiam_oauth2::par::generate_request_uri();
    SurrealPushedAuthRequestRepository::new(db.clone())
        .create(CreatePushedAuthRequest {
            tenant_id,
            client_id: client_id.to_owned(),
            request_uri_hash: axiam_oauth2::par::hash_request_uri(&request_uri),
            params: PushedAuthParams {
                response_type: "code".into(),
                redirect_uri: REDIRECT_URI.into(),
                scope: Some("openid".into()),
                code_challenge: Some(PKCE_CHALLENGE.into()),
                code_challenge_method: Some("S256".into()),
                ..Default::default()
            },
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(60),
        })
        .await
        .expect("the pushed request must store");
    request_uri
}

/// [`create_client`], also returning the secret.
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

/// Exchange `code` and return the ID token's `sub`, unverified — the signature
/// has its own suite.
async fn id_token_subject(
    app: &impl TestApp,
    tenant_id: Uuid,
    client_id: &str,
    client_secret: &str,
    code: &str,
) -> String {
    use base64::Engine;
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(format!(
            "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT_URI}\
             &client_id={client_id}&client_secret={client_secret}"
        ))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "token exchange must succeed");
    let tokens: serde_json::Value = test::read_body_json(resp).await;
    let payload = tokens["id_token"]
        .as_str()
        .expect("an ID token")
        .split('.')
        .nth(1)
        .expect("a JWT has three parts")
        .to_owned();
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("base64url payload"),
    )
    .expect("the payload is JSON");
    claims["sub"].as_str().expect("a subject").to_owned()
}

fn query_param(url: &str, name: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()?
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn urlencoding_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("v={s}").as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

fn urlencoding_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
