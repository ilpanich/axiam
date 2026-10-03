//! **T23.1.8 / D-11** — browser SSO on a T21.6 per-tenant issuer path.
//!
//! The OP browser-session cookie `axiam_op_session` is `Path=/oauth2/authorize`,
//! which is not a prefix of `/t/{tenant_id}/oauth2/authorize`: the browser never
//! sent it there, and the login hop on a per-tenant issuer always ended in
//! `login_required`. D-11 (taken by the maintainer on issue #516, option 1)
//! mints a second, path-scoped copy at `/t/{tenant_id}/oauth2/authorize` for
//! the session's own tenant — same name, value, attributes and lifetime — and
//! has every logout clear every copy.
//!
//! This file holds that to three things:
//!
//! 1. **The copy is minted, and only for the session's tenant** — with the
//!    same attributes as the bare cookie but for `Path`.
//! 2. **The tenant path resolves it under exactly the bare path's rules.** The
//!    T23.1.3 audit list (`oauth2_login_hop_test.rs`, "T23.1.3") re-run on
//!    `/t/{tenant_id}/oauth2/authorize`: a code from the cookie alone, session
//!    fixation, cross-user and cross-tenant use, no cookie from a password step
//!    that still owes a factor, `POST` unrouted, nothing reflected, the decline
//!    arm's delivery rule, M7, the account re-read, the honour lane.
//! 3. **Every logout clears every copy, and ends the session it names** —
//!    including `end_session` without an `id_token_hint` `sid` (F4 P23W1-10),
//!    which reaches the cookie through the `/logout` sub-path of the
//!    authorization endpoint.
//!
//! Assertion messages never format a cookie value, a token or a digest: they
//! name the case instead (CodeQL `rust/cleartext-logging`).

use std::net::SocketAddr;
use std::sync::Arc;

use actix_web::cookie::{Cookie, SameSite, time::Duration};
use actix_web::{App, test, web};
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::state::AppState;
use axiam_api_rest::{RateLimitConfig, RouteOptions, register_api_v1_routes_with};
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
    SurrealOrganizationRepository, SurrealPushedAuthRequestRepository, SurrealSessionRepository,
    SurrealSettingsRepository, SurrealTenantRepository, SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12345";
const CSRF_TOKEN: &str = "test-csrf-token";
/// Test-only placeholder — not a real credential. gitleaks:allow
const PASSWORD: &str = "TenantPathSsoPassw0rd";
const REDIRECT_URI: &str = "https://rp.example.com/callback";
const POST_LOGOUT_URI: &str = "https://rp.example.com/signed-out";
const ROOT_ISSUER: &str = "https://iam.example.com";
const SESSION_SECS: u64 = 2_592_000;

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
        refresh_token_lifetime_secs: SESSION_SECS,
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: ROOT_ISSUER.into(),
        tenant_issuer_paths: true,
        ..AuthConfig::default()
    }
}

/// One tenant with one active user called `username`.
async fn create_tenant_with_user(
    db: &Surreal<TestDb>,
    org_id: Uuid,
    slug: &str,
    username: &str,
) -> (Uuid, Uuid) {
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org_id,
            kind: TenantKind::Standard,
            name: format!("D-11 {slug}"),
            slug: slug.into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user_id = create_user(db, tenant.id, username).await;
    (tenant.id, user_id)
}

async fn create_user(db: &Surreal<TestDb>, tenant_id: Uuid, username: &str) -> Uuid {
    let users = SurrealUserRepository::new(db.clone());
    let user = users
        .create(CreateUser {
            tenant_id,
            username: username.into(),
            email: format!("{username}@example.com"),
            password: PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();
    users
        .update(
            tenant_id,
            user.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    user.id
}

/// An organization with tenant A holding `alice`.
async fn setup_db() -> (Surreal<TestDb>, Uuid, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "D-11 Org".into(),
            slug: "d11-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    SurrealSettingsRepository::new(db.clone())
        .set_org_settings(org.id, system_defaults())
        .await
        .unwrap();
    let (tenant_id, user_id) = create_tenant_with_user(&db, org.id, "d11-tenant-a", "alice").await;
    (db, org.id, tenant_id, user_id)
}

/// The app, with per-tenant issuer paths on and the tenant-scope resolver the
/// production server registers — what makes `X-Axiam-Tenant` work for an
/// organization-level principal. No session validator: the admin tokens these
/// tests register clients with name no session row, as in
/// `oauth2_login_hop_test.rs`.
macro_rules! test_app {
    ($db:expr, $auth:expr) => {
        test_app!($db, $auth, RateLimitConfig::default())
    };
    ($db:expr, $auth:expr, $limits:expr) => {{
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(AppState::for_test(
                    $db.clone(),
                    $auth.clone(),
                )))
                .app_data(web::Data::new(
                    Arc::new(SurrealTenantRepository::new($db.clone()))
                        as Arc<dyn axiam_api_rest::TenantScopeResolver>,
                ))
                .app_data(web::Data::new(
                    Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
                ))
                .configure(|cfg| {
                    register_api_v1_routes_with::<TestDb>(
                        cfg,
                        &$limits,
                        RouteOptions {
                            tenant_issuer_paths: true,
                            ..RouteOptions::default()
                        },
                    )
                }),
        )
        .await
    }};
}

/// The in-process app under test (see `oauth2_login_hop_test.rs`).
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
) -> (String, Option<String>) {
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
        body["client_secret"].as_str().map(str::to_owned),
    )
}

fn plain_client(browser_sso: bool) -> serde_json::Value {
    serde_json::json!({
        "name": "D-11 Client",
        "redirect_uris": [REDIRECT_URI],
        "post_logout_redirect_uris": [POST_LOGOUT_URI],
        "grant_types": ["authorization_code", "refresh_token"],
        "scopes": ["openid", "profile"],
        "browser_sso": browser_sso,
    })
}

fn login_request(org_id: Uuid, tenant_id: Uuid, username: &str) -> test::TestRequest {
    test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": username,
            "password": PASSWORD,
        }))
}

/// Every `axiam_op_session` `Set-Cookie` a response carries, in order.
fn op_cookies(resp: &actix_web::dev::ServiceResponse) -> Vec<Cookie<'static>> {
    resp.response()
        .cookies()
        .filter(|c| c.name() == "axiam_op_session")
        .map(Cookie::into_owned)
        .collect()
}

/// The paths of [`op_cookies`], which is all a failure message may name.
fn op_paths(resp: &actix_web::dev::ServiceResponse) -> Vec<String> {
    op_cookies(resp)
        .iter()
        .map(|c| c.path().unwrap_or_default().to_owned())
        .collect()
}

fn tenant_path(tenant_id: Uuid) -> String {
    format!("/t/{tenant_id}/oauth2/authorize")
}

/// Sign `username` in to `tenant_id` over HTTP; return the OP cookie's value.
///
/// Asserts the copies the sign-in set are exactly the bare one and this
/// tenant's, so every test that signs in re-checks the minting rule.
async fn sign_in_as(app: &impl TestApp, org_id: Uuid, tenant_id: Uuid, username: &str) -> String {
    let resp =
        test::call_service(app, login_request(org_id, tenant_id, username).to_request()).await;
    assert_eq!(resp.status().as_u16(), 200, "login must succeed");
    assert_eq!(
        op_paths(&resp),
        vec!["/oauth2/authorize".to_owned(), tenant_path(tenant_id)],
        "a sign-in mints the bare copy and its own tenant's copy, and no other"
    );
    let cookies = op_cookies(&resp);
    assert!(
        cookies[0].value() == cookies[1].value(),
        "both copies name the same session"
    );
    cookies[0].value().to_owned()
}

async fn sign_in(app: &impl TestApp, org_id: Uuid, tenant_id: Uuid) -> String {
    sign_in_as(app, org_id, tenant_id, "alice").await
}

/// `GET /t/{tenant_id}/oauth2/authorize?{query}`, carrying only `cookies`.
async fn tenant_authorize(
    app: &impl TestApp,
    tenant_id: Uuid,
    query: &str,
    cookies: Option<&str>,
) -> actix_web::dev::ServiceResponse {
    let mut req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("{}?{query}", tenant_path(tenant_id)));
    if let Some(cookies) = cookies {
        req = req.insert_header(("Cookie", cookies.to_owned()));
    }
    test::call_service(app, req.to_request()).await
}

/// An authorization request as a client that discovered the tenant issuer
/// sends it: no `tenant_id` parameter — the tenant is the path.
fn tenant_query(client_id: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI}\
         &scope=openid&state=hop-state"
    )
}

fn op(value: &str) -> String {
    format!("axiam_op_session={value}")
}

fn location(resp: &actix_web::dev::ServiceResponse) -> String {
    resp.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

fn query_param(url: &str, name: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()?
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

fn is_code_for_rp(loc: &str) -> bool {
    loc.starts_with(REDIRECT_URI) && loc.contains("code=")
}

fn is_login_hop(loc: &str) -> bool {
    loc.starts_with("/login?return_to=") && !loc.contains("code=")
}

fn urlencoding_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("v={s}").as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// 1. Minting
// ---------------------------------------------------------------------------

/// **Acceptance: the password sign-in sets both cookies, identical but for
/// `Path`.** Asserted attribute by attribute rather than by presence: the
/// tenant copy is the bare cookie's threat argument (`csrf.rs`,
/// `op_session_cookie`) carried to a second path, and it holds only if every
/// attribute that argument relies on is the same.
#[actix_rt::test]
async fn d11_a_password_sign_in_sets_the_bare_and_the_tenant_cookie_identically_but_for_path() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let resp =
        test::call_service(&app, login_request(org_id, tenant_id, "alice").to_request()).await;
    assert_eq!(resp.status().as_u16(), 200);

    let cookies = op_cookies(&resp);
    assert_eq!(
        cookies.len(),
        2,
        "the bare copy and the tenant copy: {:?}",
        op_paths(&resp)
    );
    let (bare, tenant) = (&cookies[0], &cookies[1]);
    assert_eq!(bare.path(), Some("/oauth2/authorize"));
    assert_eq!(tenant.path(), Some(tenant_path(tenant_id).as_str()));
    for (which, c) in [("bare", bare), ("tenant", tenant)] {
        assert_eq!(c.same_site(), Some(SameSite::Lax), "{which}: SameSite=Lax");
        assert!(c.http_only().unwrap_or(false), "{which}: HttpOnly");
        assert!(c.secure().unwrap_or(false), "{which}: Secure");
        assert_eq!(
            c.max_age(),
            Some(Duration::seconds(SESSION_SECS as i64)),
            "{which}: the session's lifetime"
        );
        assert_eq!(c.domain(), None, "{which}: host-only");
        assert!(!c.value().is_empty(), "{which}: carries a value");
    }
    assert!(
        bare.value() == tenant.value(),
        "the two copies carry one value and so name one session"
    );

    // The raw headers too: the attribute set is the whole header, not only the
    // parts a parser exposes, so the two differ in their `Path` and nothing
    // else.
    let headers: Vec<String> = resp
        .headers()
        .get_all("Set-Cookie")
        .filter_map(|v| v.to_str().ok())
        .filter(|h| h.starts_with("axiam_op_session="))
        .map(|h| {
            h.split(';')
                .skip(1)
                .map(str::trim)
                .filter(|a| !a.starts_with("Path="))
                .collect::<Vec<_>>()
                .join("; ")
        })
        .collect();
    assert_eq!(headers.len(), 2);
    assert_eq!(
        headers[0], headers[1],
        "the attributes other than Path are identical"
    );
}

// ---------------------------------------------------------------------------
// 2. Resolution on /t/{tenant_id}/oauth2/authorize — the T23.1.3 list, re-run
// ---------------------------------------------------------------------------

/// **The property D-11 exists for.** A `browser_sso` client's request on the
/// tenant issuer path is issued a code from the tenant cookie alone — no access
/// token, no bare-path cookie — and the authorization response names the
/// tenant issuer (RFC 9207), the one the client discovered.
#[actix_rt::test]
async fn d11_a_browser_sso_client_is_issued_a_code_from_the_tenant_cookie_alone() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, plain_client(true)).await;
    let value = sign_in(&app, org_id, tenant_id).await;

    let resp = tenant_authorize(
        &app,
        tenant_id,
        &tenant_query(&client_id),
        Some(&op(&value)),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    let loc = location(&resp);
    assert!(
        is_code_for_rp(&loc),
        "the tenant cookie alone buys a code: {loc}"
    );
    assert_eq!(query_param(&loc, "state").as_deref(), Some("hop-state"));
    assert_eq!(
        query_param(&loc, "iss"),
        Some(format!("{ROOT_ISSUER}/t/{tenant_id}")),
        "the response names the tenant issuer"
    );

    // Control: the same request with no cookie is sent to sign in, so the code
    // above came from the cookie and nothing else.
    let anon = tenant_authorize(&app, tenant_id, &tenant_query(&client_id), None).await;
    assert!(is_login_hop(&location(&anon)), "{}", location(&anon));
}

/// **The whole hop on the tenant path, end to end** — and the defect this task
/// found on the way: the `return_to` was built from the query string *after*
/// `TenantPathScope` had appended `tenant_id`, so the return leg carried a
/// `tenant_id` parameter on a tenant path and was refused `invalid_request` by
/// the very middleware that added it. D-11's cookie had hidden it, because the
/// return leg could not have resolved a principal anyway.
#[actix_rt::test]
async fn d11_the_login_hop_on_the_tenant_path_completes_end_to_end() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, plain_client(true)).await;

    // Leg 1: anonymous, on the tenant path.
    let first = tenant_authorize(&app, tenant_id, &tenant_query(&client_id), None).await;
    assert_eq!(first.status().as_u16(), 302);
    let loc = location(&first);
    assert!(is_login_hop(&loc), "{loc}");
    assert!(
        !loc.contains("&reauth=1"),
        "nothing stale was presented: {loc}"
    );
    let return_to = urlencoding_decode(loc.trim_start_matches("/login?return_to="));
    let (path, query) = return_to.split_once('?').expect("a query");
    assert_eq!(
        path,
        tenant_path(tenant_id),
        "the browser comes back where it left"
    );
    assert!(
        query.split('&').all(|p| !p.starts_with("tenant_id=")),
        "the return leg must not carry the tenant the middleware added: {return_to}"
    );
    assert!(query.contains("axiam_login_hop=1"), "{return_to}");
    assert!(
        axiam_oauth2::login_hop::validate_return_to_at(&return_to, &tenant_path(tenant_id)).is_ok(),
        "{return_to}"
    );

    // The sign-in the login page performs, then the return leg carrying the
    // tenant copy — the one the browser sends to this path.
    let value = sign_in(&app, org_id, tenant_id).await;
    let second = tenant_authorize(&app, tenant_id, query, Some(&op(&value))).await;
    assert_eq!(second.status().as_u16(), 302, "the code redirect");
    let loc = location(&second);
    assert!(is_code_for_rp(&loc), "{loc}");
    assert_eq!(
        query_param(&loc, "iss"),
        Some(format!("{ROOT_ISSUER}/t/{tenant_id}"))
    );
}

/// **Cross-tenant refusal, both directions.** A session in tenant A presented
/// at `/t/B/oauth2/authorize` resolves to nothing — the browser is sent to sign
/// in, never issued a code in B — and the same holds from B to A. The browser
/// would not send the copy there (its path is A's); the server's half is what
/// is under test, so the value is presented explicitly.
///
/// "Even when the digest matches a row in A": the value presented at B's path
/// is exactly the one that names a live session in A, and the lookup is keyed
/// by the tenant the *path* names, so the row is not found.
#[actix_rt::test]
async fn d11_a_tenant_cookie_never_resolves_on_another_tenants_path_in_either_direction() {
    let (db, org_id, tenant_a, alice) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let (tenant_b, bob) = create_tenant_with_user(&db, org_id, "d11-tenant-b", "bob").await;
    let (client_a, _) = create_client(
        &app,
        &admin_jwt(&auth, alice, tenant_a, org_id),
        plain_client(true),
    )
    .await;
    let (client_b, _) = create_client(
        &app,
        &admin_jwt(&auth, bob, tenant_b, org_id),
        plain_client(true),
    )
    .await;

    let in_a = sign_in_as(&app, org_id, tenant_a, "alice").await;
    let in_b = sign_in_as(&app, org_id, tenant_b, "bob").await;

    for (label, path_tenant, client, foreign) in [
        ("A's session at B's path", tenant_b, &client_b, &in_a),
        ("B's session at A's path", tenant_a, &client_a, &in_b),
    ] {
        let resp =
            tenant_authorize(&app, path_tenant, &tenant_query(client), Some(&op(foreign))).await;
        assert_eq!(resp.status().as_u16(), 302, "{label}");
        let loc = location(&resp);
        assert!(is_login_hop(&loc), "{label}: must not buy a code: {loc}");
        assert!(
            loc.contains("&reauth=1"),
            "{label}: the presented copy is stale here"
        );
        // …and the removal is for this path's copy, not the other tenant's.
        assert_eq!(
            op_paths(&resp),
            vec![tenant_path(path_tenant)],
            "{label}: only the copy this path could carry is cleared"
        );

        // The return leg is terminal and still not a code.
        let back = tenant_authorize(
            &app,
            path_tenant,
            &format!("{}&axiam_login_hop=1", tenant_query(client)),
            Some(&op(foreign)),
        )
        .await;
        assert_eq!(back.status().as_u16(), 400, "{label}");
        let body: serde_json::Value = test::read_body_json(back).await;
        assert_eq!(body["error"], "login_required", "{label}");
    }

    // Each session still authorizes on its own tenant's path: the refusals
    // above were about the tenant and nothing else.
    for (label, tenant, client, own) in [
        ("A at A", tenant_a, &client_a, &in_a),
        ("B at B", tenant_b, &client_b, &in_b),
    ] {
        let resp = tenant_authorize(&app, tenant, &tenant_query(client), Some(&op(own))).await;
        assert!(
            is_code_for_rp(&location(&resp)),
            "{label}: {}",
            location(&resp)
        );
    }

    // A's client is not reachable through B's path either: the client is
    // loaded in the tenant the path names, and it is not there.
    let wrong = tenant_authorize(&app, tenant_b, &tenant_query(&client_a), Some(&op(&in_a))).await;
    assert_eq!(wrong.status().as_u16(), 401);
}

/// **Session fixation on the tenant path.** A value planted before sign-in —
/// at the tenant path, where it would be read — is never adopted: the sign-in
/// mints its own value at both paths, and the planted one names nothing,
/// before or after.
#[actix_rt::test]
async fn d11_a_sign_in_never_adopts_a_cookie_planted_at_the_tenant_path() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, plain_client(true)).await;

    let planted = "planted-by-an-attacker-0123456789abcdefghijk";
    let before = tenant_authorize(
        &app,
        tenant_id,
        &tenant_query(&client_id),
        Some(&op(planted)),
    )
    .await;
    assert!(is_login_hop(&location(&before)), "{}", location(&before));

    let login = login_request(org_id, tenant_id, "alice")
        .insert_header(("Cookie", op(planted)))
        .to_request();
    let resp = test::call_service(&app, login).await;
    assert_eq!(resp.status().as_u16(), 200);
    let minted = op_cookies(&resp);
    assert_eq!(minted.len(), 2, "{:?}", op_paths(&resp));
    for c in &minted {
        assert!(c.value() != planted, "the sign-in must mint its own value");
        assert_eq!(
            c.value().len(),
            43,
            "256 bits, base64url: the server's value"
        );
    }

    let after = tenant_authorize(
        &app,
        tenant_id,
        &tenant_query(&client_id),
        Some(&op(planted)),
    )
    .await;
    assert!(
        is_login_hop(&location(&after)),
        "the planted value names no session after the sign-in either: {}",
        location(&after)
    );

    // A second sign-in, presenting the first one's value at the tenant path,
    // mints afresh.
    let first = minted[0].value().to_owned();
    let again = login_request(org_id, tenant_id, "alice")
        .insert_header(("Cookie", op(&first)))
        .to_request();
    let resp = test::call_service(&app, again).await;
    assert!(
        op_cookies(&resp).iter().all(|c| c.value() != first),
        "a second sign-in must not reuse the first one's value"
    );
}

/// **Cross-user use.** Bob's access token with Alice's tenant cookie, on the
/// tenant path: the token decides, and the code is Bob's.
#[actix_rt::test]
async fn d11_an_access_token_wins_over_the_tenant_cookie_and_the_two_never_cross_users() {
    let (db, org_id, tenant_id, alice) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, alice, tenant_id, org_id);
    let (client_id, secret) = create_client(&app, &jwt, plain_client(true)).await;
    let secret = secret.expect("a confidential client");
    let bob = create_user(&db, tenant_id, "bob").await;

    let alice_cookie = sign_in(&app, org_id, tenant_id).await;
    let bob_token = admin_jwt(&auth, bob, tenant_id, org_id);

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!(
            "{}?{}",
            tenant_path(tenant_id),
            tenant_query(&client_id)
        ))
        .insert_header(("Authorization", format!("Bearer {bob_token}")))
        .insert_header(("Cookie", op(&alice_cookie)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 302);
    let code = query_param(&location(&resp), "code").expect("a code");

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/t/{tenant_id}/oauth2/token"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(format!(
            "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT_URI}\
             &client_id={client_id}&client_secret={secret}"
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "token exchange");
    let tokens: serde_json::Value = test::read_body_json(resp).await;
    let claims = claims_of(tokens["id_token"].as_str().expect("an ID token"));
    assert!(
        claims["sub"] == serde_json::json!(bob.to_string()),
        "the token's subject decides"
    );
    assert!(claims["sub"] != serde_json::json!(alice.to_string()));
}

fn claims_of(jwt: &str) -> serde_json::Value {
    use base64::Engine;
    let payload = jwt.split('.').nth(1).expect("a JWT has three parts");
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("base64url payload"),
    )
    .expect("the payload is JSON")
}

/// **No cookie from a password step that still owes a factor** — neither
/// copy.
#[actix_rt::test]
async fn d11_a_password_step_that_still_owes_a_factor_sets_no_copy() {
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

    let resp =
        test::call_service(&app, login_request(org_id, tenant_id, "alice").to_request()).await;
    assert_eq!(resp.status().as_u16(), 202, "a second factor is owed");
    assert!(
        op_cookies(&resp).is_empty(),
        "the password step alone sets no OP cookie at any path: {:?}",
        op_paths(&resp)
    );
}

/// **`POST /t/{tenant_id}/oauth2/authorize` is unrouted**, as on the bare path,
/// and the tenant copy is no API credential.
#[actix_rt::test]
async fn d11_the_tenant_copy_reaches_no_endpoint_but_get_authorize() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, plain_client(true)).await;
    let cookie = op(&sign_in(&app, org_id, tenant_id).await);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&tenant_path(tenant_id))
        .insert_header(("Cookie", cookie.clone()))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(tenant_query(&client_id))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        matches!(resp.status().as_u16(), 404 | 405),
        "POST on the tenant authorize path must not be routed: {}",
        resp.status()
    );
    assert!(resp.headers().get("Location").is_none());

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/me")
        .insert_header(("Cookie", cookie))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 401);
}

/// **Nothing reflected** — the hop's `302` has no body, an appended
/// `return_to` is never promoted to the SPA's own parameter, and the loop
/// guard's rendered answer echoes nothing the request carried.
#[actix_rt::test]
async fn d11_the_tenant_path_hop_reflects_no_request_parameter() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, plain_client(true)).await;
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI}&scope=openid\
         &state=%3Cscript%3Ealert(1)%3C%2Fscript%3E&return_to=https%3A%2F%2Fevil.example%2F"
    );

    let hop = tenant_authorize(&app, tenant_id, &query, None).await;
    assert_eq!(hop.status().as_u16(), 302);
    let loc = location(&hop);
    assert!(is_login_hop(&loc), "{loc}");
    assert_eq!(loc.matches("return_to=").count(), 1, "{loc}");
    assert!(test::read_body(hop).await.is_empty(), "a 302 with no body");

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!(
            "{}?{query}&axiam_login_hop=1",
            tenant_path(tenant_id)
        ))
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

/// **The decline arm's delivery rule** on the tenant path: `access_denied` to
/// a registered `redirect_uri` with the request's `state` — whether or not a
/// live tenant cookie is presented — and to nowhere else.
#[actix_rt::test]
async fn d11_a_declined_sign_in_on_the_tenant_path_goes_only_to_a_registered_redirect_uri() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, plain_client(true)).await;
    let cookie = op(&sign_in(&app, org_id, tenant_id).await);

    for cookies in [None, Some(cookie.as_str())] {
        let label = if cookies.is_some() {
            "with the tenant cookie"
        } else {
            "without"
        };
        let resp = tenant_authorize(
            &app,
            tenant_id,
            &format!(
                "{}&axiam_login_hop=1&axiam_user_declined=1",
                tenant_query(&client_id)
            ),
            cookies,
        )
        .await;
        assert_eq!(resp.status().as_u16(), 302, "{label}");
        let loc = location(&resp);
        assert!(loc.starts_with(REDIRECT_URI), "{label}: {loc}");
        assert!(loc.contains("error=access_denied"), "{label}: {loc}");
        assert!(loc.contains("state=hop-state"), "{label}: {loc}");
        assert!(!loc.contains("code="), "{label}: a refusal is never a code");
    }

    let resp = tenant_authorize(
        &app,
        tenant_id,
        &format!(
            "response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Fevil.example%2Fcb\
             &scope=openid&state=hop-state&return_to=https%3A%2F%2Fevil.example%2F\
             &axiam_login_hop=1&axiam_user_declined=1"
        ),
        Some(&cookie),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 400);
    assert!(resp.headers().get("Location").is_none());
}

/// A `fapi2` client a browser may reach (M7).
fn fapi_browser_client() -> serde_json::Value {
    serde_json::json!({
        "name": "D-11 FAPI Browser Client",
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

/// A valid S256 challenge (RFC 7636 Appendix B).
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// Store a pushed request directly (see `oauth2_login_hop_test.rs`).
async fn push_handle(
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
    client_id: &str,
    code_challenge: Option<&str>,
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
                code_challenge: code_challenge.map(str::to_owned),
                code_challenge_method: code_challenge.map(|_| "S256".to_owned()),
                ..Default::default()
            },
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(60),
        })
        .await
        .expect("the pushed request must store");
    request_uri
}

fn urlencoding_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// **M7, both halves, on the tenant path.** A `fapi2` + `browser_sso` client's
/// return leg with a live tenant cookie skips none of FAPI's gates: inline
/// parameters are `ParRequired` (answered in place), a pushed request without
/// PKCE gets the FAPI PKCE refusal, and the same pushed request with PKCE is
/// the control that does get a code.
#[actix_rt::test]
async fn d11_m7_a_fapi2_return_leg_on_the_tenant_path_skips_no_gate() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, fapi_browser_client()).await;
    let cookie = op(&sign_in(&app, org_id, tenant_id).await);

    let inline = tenant_authorize(
        &app,
        tenant_id,
        &format!(
            "{}&code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256&axiam_login_hop=1",
            tenant_query(&client_id)
        ),
        Some(&cookie),
    )
    .await;
    assert_eq!(inline.status().as_u16(), 400);
    assert!(inline.headers().get("Location").is_none());
    let body: serde_json::Value = test::read_body_json(inline).await;
    assert_eq!(body["error"], "invalid_request");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("must use pushed authorization requests"),
        "{body}"
    );

    let without = push_handle(&db, tenant_id, &client_id, None).await;
    let resp = tenant_authorize(
        &app,
        tenant_id,
        &format!(
            "client_id={client_id}&request_uri={}&axiam_login_hop=1",
            urlencoding_encode(&without)
        ),
        Some(&cookie),
    )
    .await;
    let loc = location(&resp);
    assert!(!loc.contains("code="), "no PKCE, no code: {loc}");
    assert!(
        loc.starts_with(REDIRECT_URI) && loc.contains("error=invalid_request"),
        "{loc}"
    );
    let description = query_param(&loc, "error_description").unwrap_or_default();
    assert!(
        description.contains("PKCE") && description.contains("fapi2"),
        "{description}"
    );

    let with = push_handle(&db, tenant_id, &client_id, Some(PKCE_CHALLENGE)).await;
    let resp = tenant_authorize(
        &app,
        tenant_id,
        &format!(
            "client_id={client_id}&request_uri={}&axiam_login_hop=1",
            urlencoding_encode(&with)
        ),
        Some(&cookie),
    )
    .await;
    assert!(
        is_code_for_rp(&location(&resp)),
        "control: {}",
        location(&resp)
    );
}

/// **The account re-read, on the tenant path.** A locked, deactivated, deleted
/// or anonymised account's tenant cookie buys nothing (stale: `reauth`, the
/// tenant copy cleared, the return leg terminal); a `PendingVerification` one —
/// every federated account, for life (T-160, P23W1-03) — still authorizes.
#[actix_rt::test]
async fn d11_a_suspended_accounts_tenant_cookie_buys_nothing_and_a_pending_one_still_works() {
    for status in [
        UserStatus::Locked,
        UserStatus::Inactive,
        UserStatus::Deleted,
        UserStatus::Anonymized,
        UserStatus::PendingVerification,
    ] {
        let (db, org_id, tenant_id, user_id) = setup_db().await;
        let auth = AuthConfig {
            // No grace period: a pending account is one whose grace has ended.
            email_verification_grace_period_hours: 0,
            ..test_auth_config()
        };
        let app = test_app!(db, auth);
        let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
        let (client_id, _) = create_client(&app, &jwt, plain_client(true)).await;
        let cookie = op(&sign_in(&app, org_id, tenant_id).await);

        let live =
            tenant_authorize(&app, tenant_id, &tenant_query(&client_id), Some(&cookie)).await;
        assert!(is_code_for_rp(&location(&live)), "{status:?}: control");

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
            tenant_authorize(&app, tenant_id, &tenant_query(&client_id), Some(&cookie)).await;
        let loc = location(&resp);
        if status == UserStatus::PendingVerification {
            assert!(
                is_code_for_rp(&loc),
                "{status:?}: a pending account still authorizes: {loc}"
            );
            continue;
        }
        assert!(is_login_hop(&loc), "{status:?}: must not buy a code: {loc}");
        assert!(loc.contains("&reauth=1"), "{status:?}");
        assert_eq!(op_paths(&resp), vec![tenant_path(tenant_id)], "{status:?}");
        let back = tenant_authorize(
            &app,
            tenant_id,
            &format!("{}&axiam_login_hop=1", tenant_query(&client_id)),
            Some(&cookie),
        )
        .await;
        assert_eq!(back.status().as_u16(), 400, "{status:?}");
        let body: serde_json::Value = test::read_body_json(back).await;
        assert_eq!(body["error"], "login_required", "{status:?}");
    }
}

/// **A non-`browser_sso` client never reads the tenant cookie** — including a
/// `fapi2` client that did not opt in. The answer is the golden 401, byte for
/// byte, so a signed-in browser cannot be told from a signed-out one.
#[actix_rt::test]
async fn d11_a_client_that_did_not_opt_in_never_reads_the_tenant_cookie() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (plain, _) = create_client(&app, &jwt, plain_client(false)).await;
    let mut fapi = fapi_browser_client();
    fapi["browser_sso"] = serde_json::Value::Bool(false);
    let (fapi, _) = create_client(&app, &jwt, fapi).await;
    let cookie = op(&sign_in(&app, org_id, tenant_id).await);

    for (label, client) in [("plain", &plain), ("fapi2", &fapi)] {
        for cookies in [None, Some(cookie.as_str())] {
            let resp = tenant_authorize(&app, tenant_id, &tenant_query(client), cookies).await;
            assert_eq!(resp.status().as_u16(), 401, "{label}");
            assert!(resp.headers().get("Location").is_none(), "{label}");
            assert!(
                op_cookies(&resp).is_empty(),
                "{label}: the cookie is not even cleared"
            );
            let body = test::read_body(resp).await;
            assert_eq!(
                std::str::from_utf8(&body).unwrap(),
                "{\"error\":\"authentication_failed\",\
                 \"message\":\"Authentication failed: missing authentication credentials\"}",
                "{label}: the same golden 401 with and without the cookie"
            );
        }
    }
}

/// A copy that no longer resolves is cleared **at its own path**: on the tenant
/// path, the removal is for `/t/{tenant_id}/oauth2/authorize`, the copy the
/// browser sent — a bare-path removal would not match it and the stale copy
/// would be presented again on the next leg.
#[actix_rt::test]
async fn d11_a_stale_tenant_cookie_is_cleared_at_the_tenant_path() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, plain_client(true)).await;

    let resp = tenant_authorize(
        &app,
        tenant_id,
        &tenant_query(&client_id),
        Some("axiam_op_session=this-value-names-no-session"),
    )
    .await;
    assert!(
        location(&resp).ends_with("&reauth=1"),
        "{}",
        location(&resp)
    );
    let removal = op_cookies(&resp);
    assert_eq!(removal.len(), 1);
    assert_eq!(removal[0].value(), "");
    assert_eq!(removal[0].path(), Some(tenant_path(tenant_id).as_str()));
    assert_eq!(removal[0].same_site(), Some(SameSite::Lax));
    assert!(removal[0].secure().unwrap_or(false));
    assert!(removal[0].http_only().unwrap_or(false));
    assert_eq!(removal[0].max_age(), Some(Duration::seconds(0)));
}

/// **The `return_to` hostile list, when the hop starts from the tenant path.**
/// Whatever the request carries, the `return_to` the server emits is its own
/// — the tenant authorization path plus the client's query — and the
/// validator for that path refuses every member of T23.1.3's hostile list
/// (the full list is unit-tested in `axiam_oauth2::login_hop`; these are its
/// families).
#[actix_rt::test]
async fn d11_the_return_to_from_the_tenant_path_is_the_servers_own_and_validated() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, plain_client(true)).await;
    let path = tenant_path(tenant_id);

    for hostile in [
        "https%3A%2F%2Fevil.example%2F",
        "%2F%2Fevil.example%2Foauth2%2Fauthorize%3Fa%3D1",
        "%2F%5Cevil.example",
        "%2Foauth2%2Fauthorize%2F..%2F..%2Fadmin%3Fa%3D1",
    ] {
        let resp = tenant_authorize(
            &app,
            tenant_id,
            &format!("{}&return_to={hostile}", tenant_query(&client_id)),
            None,
        )
        .await;
        let loc = location(&resp);
        assert!(is_login_hop(&loc), "{hostile}: {loc}");
        let return_to = urlencoding_decode(loc.trim_start_matches("/login?return_to="));
        assert!(
            return_to.starts_with(&format!("{path}?")),
            "{hostile}: the emitted return_to is the tenant authorize path: {return_to}"
        );
        assert!(
            axiam_oauth2::login_hop::validate_return_to_at(&return_to, &path).is_ok(),
            "{hostile}"
        );
    }

    for candidate in [
        "https://evil.example/t/x/oauth2/authorize?a=1".to_owned(),
        "//evil.example/oauth2/authorize?a=1".to_owned(),
        "/\\evil.example/oauth2/authorize?a=1".to_owned(),
        format!("{path}/../../admin?a=1"),
        format!("{path}?a=1#frag"),
        format!("{path}?a=1\r\nSet-Cookie:x=y"),
        "/oauth2/authorize?a=1".to_owned(),
        format!("{}?a=1", tenant_path(Uuid::new_v4())),
        path.clone(),
    ] {
        assert!(
            axiam_oauth2::login_hop::validate_return_to_at(&candidate, &path).is_err(),
            "{candidate:?} must be refused against the tenant path"
        );
    }
}

// ---------------------------------------------------------------------------
// The honour lane on the tenant path
// ---------------------------------------------------------------------------

fn honour_client() -> serde_json::Value {
    serde_json::json!({
        "name": "D-11 Honour Lane Client",
        "redirect_uris": [REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"],
        "scopes": ["openid", "profile"],
        "authn_request_params": "honour",
        "browser_sso": true,
    })
}

/// **`prompt=none` with and without the tenant cookie.** Without it: the
/// refusal is `login_required` at the relying party, naming the tenant issuer,
/// with no sign-in page. With it: a code, and no interaction.
#[actix_rt::test]
async fn d11_prompt_none_on_the_tenant_path_with_and_without_the_tenant_cookie() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, honour_client()).await;
    let query = format!("{}&prompt=none", tenant_query(&client_id));

    let resp = tenant_authorize(&app, tenant_id, &query, None).await;
    assert_eq!(resp.status().as_u16(), 302);
    let loc = location(&resp);
    assert!(loc.starts_with(REDIRECT_URI), "to the relying party: {loc}");
    assert_eq!(
        query_param(&loc, "error").as_deref(),
        Some("login_required")
    );
    assert_eq!(query_param(&loc, "state").as_deref(), Some("hop-state"));
    assert_eq!(
        query_param(&loc, "iss"),
        Some(format!("{ROOT_ISSUER}/t/{tenant_id}"))
    );
    assert!(query_param(&loc, "code").is_none());

    let cookie = op(&sign_in(&app, org_id, tenant_id).await);
    let resp = tenant_authorize(&app, tenant_id, &query, Some(&cookie)).await;
    assert_eq!(resp.status().as_u16(), 302);
    assert!(is_code_for_rp(&location(&resp)), "{}", location(&resp));
}

/// **The interaction hop on the tenant path.** `prompt=login` with a live
/// tenant cookie interacts, and its `return_to` — like the login hop's — names
/// the tenant authorization path and carries no `tenant_id` parameter, so the
/// return leg is not refused by the tenant scope.
#[actix_rt::test]
async fn d11_an_interaction_hop_on_the_tenant_path_returns_to_the_tenant_path() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, honour_client()).await;
    let cookie = op(&sign_in(&app, org_id, tenant_id).await);

    let resp = tenant_authorize(
        &app,
        tenant_id,
        &format!("{}&prompt=login", tenant_query(&client_id)),
        Some(&cookie),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    let loc = location(&resp);
    assert!(is_login_hop(&loc), "prompt=login interacts: {loc}");
    let return_to = urlencoding_decode(
        loc.trim_start_matches("/login?return_to=")
            .split('&')
            .next()
            .unwrap_or_default(),
    );
    let (path, query) = return_to.split_once('?').expect("a query");
    assert_eq!(path, tenant_path(tenant_id));
    assert!(
        query.split('&').all(|p| !p.starts_with("tenant_id=")),
        "{return_to}"
    );

    // The return leg reaches the handler rather than the scope's refusal.
    let back = tenant_authorize(&app, tenant_id, query, Some(&cookie)).await;
    assert_ne!(
        back.status().as_u16(),
        400,
        "the return leg must not be refused as a second tenant selector"
    );
}

// ---------------------------------------------------------------------------
// 3. Clearing — logout, end_session, revocation, and P23W1-10
// ---------------------------------------------------------------------------

/// A completed sign-in: the OP value, the API cookies and the session id.
struct SignedIn {
    op: String,
    access: String,
    csrf: String,
    session_id: Uuid,
}

async fn sign_in_full(app: &impl TestApp, org_id: Uuid, tenant_id: Uuid) -> SignedIn {
    let resp =
        test::call_service(app, login_request(org_id, tenant_id, "alice").to_request()).await;
    assert_eq!(resp.status().as_u16(), 200, "login must succeed");
    let value = |name: &str| {
        resp.response()
            .cookies()
            .find(|c| c.name() == name)
            .map(|c| c.value().to_owned())
            .unwrap_or_else(|| panic!("the login must set {name}"))
    };
    let (op, access, csrf) = (
        value("axiam_op_session"),
        value("axiam_access"),
        value("axiam_csrf"),
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    SignedIn {
        op,
        access,
        csrf,
        session_id: Uuid::parse_str(body["session_id"].as_str().expect("session_id")).unwrap(),
    }
}

async fn session_is_live(db: &Surreal<TestDb>, tenant_id: Uuid, session_id: Uuid) -> bool {
    use axiam_core::repository::SessionRepository;
    SurrealSessionRepository::new(db.clone())
        .get_by_id(tenant_id, session_id)
        .await
        .is_ok()
}

/// Assert `resp` clears **both** OP copies for `tenant_id`, each removal
/// mirroring its setter: empty value, `Max-Age=0`, `HttpOnly`, `Secure`,
/// `SameSite=Lax`, at the copy's own path.
fn assert_clears_both_copies(resp: &actix_web::dev::ServiceResponse, tenant_id: Uuid, label: &str) {
    let removals = op_cookies(resp);
    assert_eq!(
        op_paths(resp),
        vec!["/oauth2/authorize".to_owned(), tenant_path(tenant_id)],
        "{label}: one removal per copy the sign-in minted"
    );
    for c in &removals {
        let path = c.path().unwrap_or_default();
        assert_eq!(c.value(), "", "{label} {path}: an empty value");
        assert_eq!(
            c.max_age(),
            Some(Duration::seconds(0)),
            "{label} {path}: Max-Age=0"
        );
        assert!(c.http_only().unwrap_or(false), "{label} {path}: HttpOnly");
        assert!(c.secure().unwrap_or(false), "{label} {path}: Secure");
        assert_eq!(
            c.same_site(),
            Some(SameSite::Lax),
            "{label} {path}: SameSite=Lax"
        );
    }
    // The raw header carries the same attributes the parser saw.
    let headers: Vec<&str> = resp
        .headers()
        .get_all("Set-Cookie")
        .filter_map(|v| v.to_str().ok())
        .filter(|h| h.starts_with("axiam_op_session="))
        .collect();
    for h in headers {
        for attribute in ["HttpOnly", "Secure", "SameSite=Lax", "Max-Age=0"] {
            assert!(h.contains(attribute), "{label}: removal lacks {attribute}");
        }
    }
}

/// **Logout clears both copies, and the value then names nothing.** The
/// removal `Set-Cookie`s are asserted attribute by attribute; the tenant value
/// presented again afterwards — as a browser that ignored the removal would —
/// is stale on the tenant path and on the bare one.
#[actix_rt::test]
async fn d11_logout_clears_both_copies_and_the_tenant_value_then_resolves_to_nothing() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, plain_client(true)).await;
    let s = sign_in_full(&app, org_id, tenant_id).await;

    let live = tenant_authorize(&app, tenant_id, &tenant_query(&client_id), Some(&op(&s.op))).await;
    assert!(is_code_for_rp(&location(&live)), "control");

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/logout")
        .insert_header((
            "Cookie",
            format!("axiam_access={}; axiam_csrf={}", s.access, s.csrf),
        ))
        .insert_header(("X-CSRF-Token", s.csrf.clone()))
        .to_request();
    let out = test::call_service(&app, req).await;
    assert_eq!(out.status().as_u16(), 204);
    assert_clears_both_copies(&out, tenant_id, "logout");
    assert!(
        !session_is_live(&db, tenant_id, s.session_id).await,
        "the row is gone"
    );

    let resp = tenant_authorize(&app, tenant_id, &tenant_query(&client_id), Some(&op(&s.op))).await;
    let loc = location(&resp);
    assert!(
        is_login_hop(&loc) && loc.contains("&reauth=1"),
        "tenant path: {loc}"
    );
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!(
            "/oauth2/authorize?{}&tenant_id={tenant_id}",
            tenant_query(&client_id)
        ))
        .insert_header(("Cookie", op(&s.op)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        is_login_hop(&location(&resp)),
        "bare path: {}",
        location(&resp)
    );
}

/// **The defect the clearing work found.** An organization-level principal
/// that has switched to a child tenant — the admin UI sends `X-Axiam-Tenant` on
/// every request, logout included — logged out in the *acted-upon* tenant: the
/// tenant-scoped `DELETE` matched no row, the answer was `204`, and the session
/// stayed live with every OP copy naming it. Logout now revokes, and clears,
/// in the principal's own tenant, where the session and its cookies live.
#[actix_rt::test]
async fn d11_logout_by_an_org_level_principal_acting_on_a_child_tenant_ends_its_session() {
    let (db, org_id, child_tenant, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let org_tenant = SurrealTenantRepository::new(db.clone())
        .create(axiam_core::models::tenant::CreateTenant::organization_scope(org_id))
        .await
        .unwrap()
        .id;
    let admin = create_user(&db, org_tenant, "org-admin").await;
    let _ = admin;

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/auth/login")
            .set_json(serde_json::json!({
                "org_id": org_id,
                "username_or_email": "org-admin",
                "password": PASSWORD,
            }))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200, "an organization-scope sign-in");
    assert_eq!(
        op_paths(&resp),
        vec!["/oauth2/authorize".to_owned(), tenant_path(org_tenant)],
        "the copies are minted for the session's own (organization) tenant"
    );
    let cookie = |name: &str| {
        resp.response()
            .cookies()
            .find(|c| c.name() == name)
            .map(|c| c.value().to_owned())
            .unwrap()
    };
    let (access, csrf) = (cookie("axiam_access"), cookie("axiam_csrf"));
    let body: serde_json::Value = test::read_body_json(resp).await;
    let session_id = Uuid::parse_str(body["session_id"].as_str().unwrap()).unwrap();

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/logout")
        .insert_header((
            "Cookie",
            format!("axiam_access={access}; axiam_csrf={csrf}"),
        ))
        .insert_header(("X-CSRF-Token", csrf.clone()))
        .insert_header((
            axiam_api_rest::ACTIVE_TENANT_HEADER,
            child_tenant.to_string(),
        ))
        .to_request();
    let out = test::call_service(&app, req).await;
    assert_eq!(out.status().as_u16(), 204);
    assert!(
        !session_is_live(&db, org_tenant, session_id).await,
        "the session must end although the request acted on a child tenant"
    );
    assert_clears_both_copies(&out, org_tenant, "org-level logout");
}

/// An ID token naming `session_id`, as the relying party holds it.
fn id_token_hint(auth: &AuthConfig, user_id: Uuid, client_id: &str, session_id: Uuid) -> String {
    axiam_auth::token::issue_id_token(
        user_id,
        client_id,
        None,
        None,
        &["openid".to_string()],
        auth,
        Some(session_id),
        &axiam_auth::token::IdTokenEvidence::NONE,
    )
    .unwrap()
}

/// **`end_session` with a hint, bare and per-tenant, clears both copies** —
/// on the allow-listed redirect and on AXIAM's own page — and ends the session.
#[actix_rt::test]
async fn d11_end_session_on_the_bare_and_the_tenant_path_clears_both_copies() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, plain_client(true)).await;

    for (label, base) in [
        (
            "bare",
            format!("/oauth2/end_session?tenant_id={tenant_id}&"),
        ),
        ("tenant", format!("/t/{tenant_id}/oauth2/end_session?")),
    ] {
        for (arm, extra, expected) in [
            (
                "redirect",
                format!("&post_logout_redirect_uri={POST_LOGOUT_URI}&state=st"),
                302,
            ),
            ("page", String::new(), 200),
        ] {
            let s = sign_in_full(&app, org_id, tenant_id).await;
            let hint = id_token_hint(&auth, user_id, &client_id, s.session_id);
            let req = test::TestRequest::get()
                .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
                .uri(&format!("{base}id_token_hint={hint}{extra}"))
                .to_request();
            let resp = test::call_service(&app, req).await;
            let case = format!("{label} end_session, {arm}");
            assert_eq!(resp.status().as_u16(), expected, "{case}");
            if expected == 302 {
                assert!(location(&resp).starts_with(POST_LOGOUT_URI), "{case}");
            }
            assert_clears_both_copies(&resp, tenant_id, &case);
            assert!(
                !session_is_live(&db, tenant_id, s.session_id).await,
                "{case}"
            );
        }
    }
}

/// **P23W1-10, closed.** `end_session` without an `id_token_hint` used to clear
/// the OP cookie it could not read and leave the session row live. It now
/// bounces to the `/logout` sub-path of the authorization endpoint the request
/// came through — bare or per-tenant — which receives the copy scoped there,
/// revokes the row it names, clears both copies and continues to the
/// allow-listed `post_logout_redirect_uri` with the relying party's `state`.
#[actix_rt::test]
async fn p23w1_10_end_session_without_a_hint_revokes_the_session_the_op_cookie_names() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, plain_client(true)).await;
    let continuation = format!(
        "client_id={client_id}&post_logout_redirect_uri={}&state=rp-state",
        urlencoding_encode(POST_LOGOUT_URI)
    );

    for (label, end_session, hop_path) in [
        (
            "bare",
            format!("/oauth2/end_session?tenant_id={tenant_id}&{continuation}"),
            "/oauth2/authorize/logout".to_owned(),
        ),
        (
            "tenant",
            format!("/t/{tenant_id}/oauth2/end_session?{continuation}"),
            format!("{}/logout", tenant_path(tenant_id)),
        ),
    ] {
        let s = sign_in_full(&app, org_id, tenant_id).await;

        // The RP's navigation. The browser's OP copies are scoped to the
        // authorization endpoint, so it carries none of them here.
        let req = test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&end_session)
            .to_request();
        let bounce = test::call_service(&app, req).await;
        assert_eq!(bounce.status().as_u16(), 302, "{label}");
        let hop = location(&bounce);
        let (path, query) = hop.split_once('?').expect("a continuation");
        assert_eq!(
            path, hop_path,
            "{label}: the hop is under the cookie's own path"
        );
        assert_eq!(
            query.split('&').any(|p| p.starts_with("tenant_id=")),
            label == "bare",
            "{label}: the tenant travels as a parameter only where the path does not name it"
        );
        assert!(
            op_cookies(&bounce).is_empty(),
            "{label}: the bounce clears nothing yet"
        );
        assert_eq!(
            bounce
                .headers()
                .get("Cache-Control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        assert!(
            session_is_live(&db, tenant_id, s.session_id).await,
            "{label}: not yet"
        );

        // The browser follows, and RFC 6265 path-match now sends the copy.
        let req = test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&hop)
            .insert_header(("Cookie", op(&s.op)))
            .to_request();
        let done = test::call_service(&app, req).await;
        assert_eq!(done.status().as_u16(), 302, "{label}");
        let loc = location(&done);
        assert!(loc.starts_with(POST_LOGOUT_URI), "{label}: {loc}");
        assert_eq!(
            query_param(&loc, "state").as_deref(),
            Some("rp-state"),
            "{label}"
        );
        assert_clears_both_copies(&done, tenant_id, label);
        assert!(
            !session_is_live(&db, tenant_id, s.session_id).await,
            "{label}: the row the cookie named is revoked"
        );
        let after =
            tenant_authorize(&app, tenant_id, &tenant_query(&client_id), Some(&op(&s.op))).await;
        assert!(
            is_login_hop(&location(&after)),
            "{label}: the value names nothing now"
        );
    }
}

/// The cookie hop never crosses tenants: tenant A's copy presented at tenant
/// B's hop names no session there (the read is keyed by the path's tenant), so
/// A's session survives; and a hop with no cookie at all ends nothing.
#[actix_rt::test]
async fn p23w1_10_the_cookie_hop_never_ends_another_tenants_session() {
    let (db, org_id, tenant_a, _alice) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let (tenant_b, _bob) = create_tenant_with_user(&db, org_id, "d11-tenant-b", "bob").await;
    let s = sign_in_full(&app, org_id, tenant_a).await;

    for (label, uri, cookie) in [
        (
            "A's copy at B's hop",
            format!("/t/{tenant_b}/oauth2/authorize/logout"),
            Some(op(&s.op)),
        ),
        (
            "A's value at the bare hop naming B",
            format!("/oauth2/authorize/logout?tenant_id={tenant_b}"),
            Some(op(&s.op)),
        ),
        (
            "no cookie at A's hop",
            format!("/t/{tenant_a}/oauth2/authorize/logout"),
            None,
        ),
    ] {
        let mut req = test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&uri);
        if let Some(cookie) = cookie {
            req = req.insert_header(("Cookie", cookie));
        }
        let resp = test::call_service(&app, req.to_request()).await;
        assert_eq!(resp.status().as_u16(), 200, "{label}: AXIAM's page");
        assert!(
            session_is_live(&db, tenant_a, s.session_id).await,
            "{label}: tenant A's session must survive"
        );
    }
}

/// **The hop is no open redirect.** Navigated to directly, with a continuation
/// it did not get from `end_session`: an unregistered target, a prefix of the
/// registered one, a client from another tenant, and no client at all are all
/// answered with AXIAM's page and no `Location` — and the RP's `state` is not
/// reflected into it.
#[actix_rt::test]
async fn p23w1_10_the_cookie_hop_validates_its_continuation_as_end_session_does() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, plain_client(true)).await;
    let (tenant_b, bob) = create_tenant_with_user(&db, org_id, "d11-tenant-b", "bob").await;
    let (foreign_client, _) = create_client(
        &app,
        &admin_jwt(&auth, bob, tenant_b, org_id),
        plain_client(true),
    )
    .await;
    let hop = tenant_path(tenant_id) + "/logout";

    for (label, query) in [
        (
            "an unregistered target",
            format!(
                "client_id={client_id}&post_logout_redirect_uri={}",
                urlencoding_encode("https://evil.example/cb")
            ),
        ),
        (
            "a prefix of the registered target",
            format!(
                "client_id={client_id}&post_logout_redirect_uri={}",
                urlencoding_encode(&format!("{POST_LOGOUT_URI}.evil.example"))
            ),
        ),
        (
            "another tenant's client",
            format!(
                "client_id={foreign_client}&post_logout_redirect_uri={}",
                urlencoding_encode(POST_LOGOUT_URI)
            ),
        ),
        (
            "no client",
            format!(
                "post_logout_redirect_uri={}",
                urlencoding_encode(POST_LOGOUT_URI)
            ),
        ),
    ] {
        let req = test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!("{hop}?{query}&state=zzmarkerzz"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 200, "{label}");
        assert!(
            resp.headers().get("Location").is_none(),
            "{label}: never redirected"
        );
        let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        assert!(
            !body.contains("zzmarkerzz"),
            "{label}: state is not reflected"
        );
        assert!(
            !body.contains("evil.example"),
            "{label}: the target is not reflected"
        );
    }

    // A `tenant_id` parameter on the tenant hop is refused by the scope, as on
    // every tenant path: one tenant selector per request.
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("{hop}?tenant_id={tenant_b}"))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 400);
}

/// **The hop is GET-only, public and rate-limited** (§7 rule 6: a limiter that
/// forgets a route is the Keycloak 26.7 lesson). `POST` is not routed; an
/// unauthenticated `GET` is answered rather than `401`; and the
/// `end_session` preset bounds it — here set to one request a minute, so the
/// second is `429`, on either mount, since both draw on one allowance.
#[actix_rt::test]
async fn p23w1_10_the_cookie_hop_is_get_only_public_and_rate_limited() {
    let (db, _org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    for uri in [
        format!("/oauth2/authorize/logout?tenant_id={tenant_id}"),
        format!("{}/logout", tenant_path(tenant_id)),
    ] {
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&uri)
            .to_request();
        let status = test::call_service(&app, req).await.status().as_u16();
        assert!(
            matches!(status, 404 | 405),
            "POST {uri} must not be routed: {status}"
        );

        let req = test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&uri)
            .to_request();
        assert_eq!(
            test::call_service(&app, req).await.status().as_u16(),
            200,
            "GET {uri}"
        );
    }

    let limits = RateLimitConfig {
        end_session_per_min: 1,
        ..RateLimitConfig::default()
    };
    let limited = test_app!(db, auth, limits);
    let call = |uri: String| {
        test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&uri)
            .to_request()
    };
    let bare = format!("/oauth2/authorize/logout?tenant_id={tenant_id}");
    let tenant = format!("{}/logout", tenant_path(tenant_id));
    assert_eq!(
        test::call_service(&limited, call(bare.clone()))
            .await
            .status()
            .as_u16(),
        200
    );
    assert_eq!(
        test::call_service(&limited, call(bare))
            .await
            .status()
            .as_u16(),
        429,
        "the end_session preset must bound the hop"
    );
    // One allowance across both mounts: the shared counter is registered under
    // one name by the bare and the tenant scope, so alternating paths buys
    // nothing (see `server::oauth2_scope`).
    assert_eq!(
        test::call_service(&limited, call(tenant))
            .await
            .status()
            .as_u16(),
        429,
        "the tenant mount draws on the same allowance"
    );
}

/// **Server-side revocation of somebody else's session** cannot clear that
/// browser's cookies — it is not the browser on the line. What it guarantees
/// instead is that the copy resolves to nothing once the row is gone. Here
/// browser 2 changes the password, which revokes every other session: browser
/// 1's tenant copy is then stale on the tenant path, while browser 2's own
/// still authorizes.
#[actix_rt::test]
async fn d11_a_revoked_sessions_tenant_cookie_resolves_to_nothing() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let jwt = admin_jwt(&auth, user_id, tenant_id, org_id);
    let (client_id, _) = create_client(&app, &jwt, plain_client(true)).await;
    let browser_1 = sign_in_full(&app, org_id, tenant_id).await;
    let browser_2 = sign_in_full(&app, org_id, tenant_id).await;

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/password/change")
        .insert_header((
            "Cookie",
            format!(
                "axiam_access={}; axiam_csrf={}",
                browser_2.access, browser_2.csrf
            ),
        ))
        .insert_header(("X-CSRF-Token", browser_2.csrf.clone()))
        .set_json(serde_json::json!({
            "current_password": PASSWORD,
            "new_password": "TenantPathSsoPassw0rd-Rotated!",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_success(),
        "password change: {}",
        resp.status()
    );
    assert!(!session_is_live(&db, tenant_id, browser_1.session_id).await);

    let stale = tenant_authorize(
        &app,
        tenant_id,
        &tenant_query(&client_id),
        Some(&op(&browser_1.op)),
    )
    .await;
    let loc = location(&stale);
    assert!(is_login_hop(&loc) && loc.contains("&reauth=1"), "{loc}");

    let own = tenant_authorize(
        &app,
        tenant_id,
        &tenant_query(&client_id),
        Some(&op(&browser_2.op)),
    )
    .await;
    assert!(is_code_for_rp(&location(&own)), "{}", location(&own));
}
