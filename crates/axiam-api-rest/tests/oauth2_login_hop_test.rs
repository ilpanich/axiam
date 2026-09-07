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
    SurrealOrganizationRepository, SurrealSettingsRepository, SurrealTenantRepository,
    SurrealUserRepository,
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
