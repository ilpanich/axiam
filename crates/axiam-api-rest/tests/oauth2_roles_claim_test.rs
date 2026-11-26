//! SA-18 (N15, D-1) — the `roles` scope and the access token's `roles` claim.
//!
//! N15: three SDKs read the OAuth2 `scope` claim as the caller's roles, so
//! `require_role("admin")` passed for any user whose client registered a scope
//! named `admin`. D-1 makes the SDKs read a dedicated `roles` claim and fail
//! closed without it; this file pins the server half: the claim exists, it is
//! emitted only for a granted `roles` scope, and it carries the names of the
//! subject's **global** role assignments in the token's tenant — direct and
//! group-inherited, sorted and de-duplicated, resource-scoped assignments
//! excluded.
//!
//! Every token is driven through the mounted endpoints, so the wiring of the
//! role source into each grant is under test, not only the claim arithmetic.

use actix_web::{App, test, web};
use std::net::SocketAddr;
use std::sync::Arc;

use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token, issue_client_credentials_token};
use axiam_core::models::group::CreateGroup;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::resource::CreateResource;
use axiam_core::models::role::{AssignmentScope, CreateRole};
use axiam_core::models::service_account::CreateServiceAccount;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    GroupRepository, OrganizationRepository, ResourceRepository, RoleRepository,
    ServiceAccountRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealResourceRepository,
    SurrealRoleRepository, SurrealServiceAccountRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use axiam_oauth2::token_exchange::{TOKEN_EXCHANGE_GRANT_TYPE, TOKEN_TYPE_ACCESS_TOKEN};
use serde_json::Value;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12346";
const CSRF_TOKEN: &str = "test-csrf-token";
const REDIRECT_URI: &str = "https://app.example.com/callback";

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
        oauth2_issuer_url: "https://localhost".into(),
        sso_spa_origins: Vec::new(),
        ..AuthConfig::default()
    }
}

struct Fixture {
    db: Surreal<TestDb>,
    auth: AuthConfig,
    org_id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
}

async fn setup() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Roles Org".into(),
            slug: "roles-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Roles Tenant".into(),
            slug: "roles-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: "password12345".into(),
            metadata: None,
        })
        .await
        .unwrap();
    Fixture {
        db,
        auth: test_auth_config(),
        org_id: org.id,
        tenant_id: tenant.id,
        user_id: user.id,
    }
}

macro_rules! test_app {
    ($f:expr) => {
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
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(
                        cfg,
                        &RateLimitConfig {
                            end_session_per_min: 100_000,
                            ..RateLimitConfig::default()
                        },
                    )
                }),
        )
        .await
    };
}

trait TestApp:
    actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >
{
}
impl<T> TestApp for T where
    T: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse,
            Error = actix_web::Error,
        >
{
}

fn roles(f: &Fixture) -> SurrealRoleRepository<TestDb> {
    SurrealRoleRepository::new(f.db.clone())
}

async fn role(f: &Fixture, name: &str, is_global: bool) -> Uuid {
    roles(f)
        .create(CreateRole {
            tenant_id: f.tenant_id,
            name: name.into(),
            description: String::new(),
            is_global,
        })
        .await
        .unwrap()
        .id
}

async fn assign_user(f: &Fixture, role_id: Uuid, scope: AssignmentScope) {
    roles(f)
        .assign_to_user(f.tenant_id, f.user_id, role_id, scope)
        .await
        .unwrap();
}

async fn group_with_role(f: &Fixture, name: &str, role_id: Uuid) -> Uuid {
    let group = SurrealGroupRepository::new(f.db.clone())
        .create(CreateGroup {
            tenant_id: f.tenant_id,
            name: name.into(),
            description: String::new(),
            metadata: None,
        })
        .await
        .unwrap();
    roles(f)
        .assign_to_group(f.tenant_id, group.id, role_id, AssignmentScope::global())
        .await
        .unwrap();
    group.id
}

/// The user's assignments every claim test reads:
///
/// * `zeta-admin` — a global role, assigned directly **and** through a group
///   (must appear once);
/// * `beta` — an ordinary role assigned with no resource (a global
///   assignment);
/// * `alpha` — inherited only through group membership;
/// * `resource-only` — assigned on one resource (must be absent).
async fn seed_user_roles(f: &Fixture) {
    let zeta = role(f, "zeta-admin", true).await;
    let beta = role(f, "beta", false).await;
    let alpha = role(f, "alpha", false).await;
    let scoped = role(f, "resource-only", false).await;

    assign_user(f, zeta, AssignmentScope::global()).await;
    assign_user(f, beta, AssignmentScope::global()).await;

    let resource = SurrealResourceRepository::new(f.db.clone())
        .create(CreateResource {
            tenant_id: f.tenant_id,
            name: "orders".into(),
            resource_type: "service".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();
    assign_user(f, scoped, AssignmentScope::resource(resource.id)).await;

    let groups = SurrealGroupRepository::new(f.db.clone());
    let g1 = group_with_role(f, "engineers", alpha).await;
    roles(f)
        .assign_to_group(f.tenant_id, g1, zeta, AssignmentScope::global())
        .await
        .unwrap();
    groups.add_member(f.tenant_id, f.user_id, g1).await.unwrap();
}

const EXPECTED_USER_ROLES: [&str; 3] = ["alpha", "beta", "zeta-admin"];

fn admin_jwt(f: &Fixture) -> String {
    issue_access_token(
        f.user_id,
        f.tenant_id,
        f.org_id,
        &[],
        &f.auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap()
}

async fn create_client(app: &impl TestApp, f: &Fixture, body: Value) -> (String, String) {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {}", admin_jwt(f))))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(body)
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 201, "client registration");
    let body: Value = test::read_body_json(resp).await;
    (
        body["client_id"].as_str().unwrap().to_owned(),
        body["client_secret"].as_str().unwrap().to_owned(),
    )
}

/// A code-flow client registered for `scopes`.
async fn code_client(app: &impl TestApp, f: &Fixture, scopes: &[&str]) -> (String, String) {
    create_client(
        app,
        f,
        serde_json::json!({
            "name": "Roles Client",
            "redirect_uris": [REDIRECT_URI],
            "grant_types": ["authorization_code", "refresh_token"],
            "scopes": scopes,
        }),
    )
    .await
}

async fn authorize(app: &impl TestApp, f: &Fixture, client_id: &str, scope: &str) -> String {
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!(
            "/oauth2/authorize?response_type=code&client_id={client_id}\
             &redirect_uri={REDIRECT_URI}&scope={scope}&state=sa18&nonce=sa18-nonce"
        ))
        .insert_header(("Authorization", format!("Bearer {}", admin_jwt(f))))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 302, "authorize redirects");
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

async fn token_post(app: &impl TestApp, f: &Fixture, form: String) -> (u16, Value) {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={}", f.tenant_id))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    (status, test::read_body_json(resp).await)
}

/// Authorize with `scope` and redeem the code.
async fn code_grant(
    app: &impl TestApp,
    f: &Fixture,
    client: &(String, String),
    scope: &str,
) -> Value {
    let location = authorize(app, f, &client.0, scope).await;
    let code = query_param(&location, "code")
        .unwrap_or_else(|| panic!("authorize did not issue a code: {location}"));
    let (status, body) = token_post(
        app,
        f,
        format!(
            "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT_URI}\
             &client_id={}&client_secret={}",
            client.0, client.1
        ),
    )
    .await;
    assert_eq!(status, 200, "code redemption: {body}");
    body
}

fn jwt_payload(token: &str) -> Value {
    use base64::Engine;
    let payload = token.split('.').nth(1).expect("a three-part JWT");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url payload");
    serde_json::from_slice(&bytes).expect("JSON payload")
}

fn access_claims(body: &Value) -> Value {
    jwt_payload(body["access_token"].as_str().expect("an access token"))
}

fn names(list: &[&str]) -> Value {
    serde_json::json!(list)
}

// ---------------------------------------------------------------------------
// Scope absent → claim absent
// ---------------------------------------------------------------------------

/// Without the `roles` scope the claim is **absent**, not `[]` — so an SDK can
/// tell "not requested" from "no roles". The client is allowed the scope; it
/// simply did not ask.
#[actix_web::test]
async fn n15_without_the_roles_scope_the_access_token_has_no_roles_claim() {
    let f = setup().await;
    seed_user_roles(&f).await;
    let app = test_app!(f);
    let client = code_client(&app, &f, &["openid", "profile", "roles"]).await;

    let body = code_grant(&app, &f, &client, "openid%20profile").await;
    let claims = access_claims(&body);
    assert!(
        claims.get("roles").is_none(),
        "a token whose grant lacks the roles scope must carry no roles claim: {claims}"
    );
}

// ---------------------------------------------------------------------------
// Scope granted → exact global role names
// ---------------------------------------------------------------------------

/// The granted scope carries exactly the names of the user's global role
/// assignments: direct and group-inherited, sorted, de-duplicated, with the
/// resource-scoped assignment excluded. The ID token and UserInfo never carry
/// it.
#[actix_web::test]
async fn n15_the_roles_scope_carries_exactly_the_global_role_names() {
    let f = setup().await;
    seed_user_roles(&f).await;
    let app = test_app!(f);
    let client = code_client(&app, &f, &["openid", "profile", "roles"]).await;

    let body = code_grant(&app, &f, &client, "openid%20roles").await;
    let claims = access_claims(&body);
    assert_eq!(
        claims["roles"],
        names(&EXPECTED_USER_ROLES),
        "the roles claim must list the global role names, sorted and de-duplicated: {claims}"
    );

    let id_token = jwt_payload(body["id_token"].as_str().expect("an id_token for openid"));
    assert!(
        id_token.get("roles").is_none(),
        "an ID token never carries roles: {id_token}"
    );

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/oauth2/userinfo")
        .insert_header((
            "Authorization",
            format!("Bearer {}", body["access_token"].as_str().unwrap()),
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "userinfo");
    let info: Value = test::read_body_json(resp).await;
    assert!(
        info.get("roles").is_none(),
        "UserInfo never releases roles: {info}"
    );
}

/// A user holding no global role, granted the scope, gets an empty array —
/// "requested, and there are none" — which is what lets the absent claim mean
/// "not requested".
#[actix_web::test]
async fn n15_the_roles_scope_with_no_global_roles_is_an_empty_array() {
    let f = setup().await;
    let app = test_app!(f);
    let client = code_client(&app, &f, &["openid", "roles"]).await;

    let body = code_grant(&app, &f, &client, "roles").await;
    assert_eq!(access_claims(&body)["roles"], names(&[]));
}

// ---------------------------------------------------------------------------
// Client not allowed the scope → refused
// ---------------------------------------------------------------------------

/// Nothing is granted by default: a client that did not register `roles` is
/// refused it as it is refused any other unregistered scope.
#[actix_web::test]
async fn n15_a_client_not_allowed_the_roles_scope_is_refused() {
    let f = setup().await;
    seed_user_roles(&f).await;
    let app = test_app!(f);
    let client = code_client(&app, &f, &["openid", "profile"]).await;

    let location = authorize(&app, &f, &client.0, "openid%20roles").await;
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("invalid_scope"),
        "an unregistered roles scope must be refused like any other: {location}"
    );
    assert!(query_param(&location, "code").is_none());
}

// ---------------------------------------------------------------------------
// Refresh recomputes
// ---------------------------------------------------------------------------

/// The claim is a snapshot taken at mint time, and a refresh is a mint: a role
/// granted and a role withdrawn after the first token show in the next one.
#[actix_web::test]
async fn n15_a_refresh_after_a_role_change_reflects_it() {
    let f = setup().await;
    let first = role(&f, "first", false).await;
    assign_user(&f, first, AssignmentScope::global()).await;
    let app = test_app!(f);
    let client = code_client(&app, &f, &["openid", "roles"]).await;

    let body = code_grant(&app, &f, &client, "openid%20roles").await;
    assert_eq!(access_claims(&body)["roles"], names(&["first"]));

    let second = role(&f, "second", true).await;
    assign_user(&f, second, AssignmentScope::global()).await;
    roles(&f)
        .unassign_from_user(f.tenant_id, f.user_id, first, None)
        .await
        .unwrap();

    let refresh = body["refresh_token"].as_str().expect("a refresh token");
    let (status, refreshed) = token_post(
        &app,
        &f,
        format!(
            "grant_type=refresh_token&refresh_token={refresh}\
             &client_id={}&client_secret={}",
            client.0, client.1
        ),
    )
    .await;
    assert_eq!(status, 200, "refresh: {refreshed}");
    assert_eq!(
        access_claims(&refreshed)["roles"],
        names(&["second"]),
        "a refreshed token must recompute the roles claim"
    );
}

// ---------------------------------------------------------------------------
// Token exchange
// ---------------------------------------------------------------------------

fn enc(s: &str) -> String {
    s.replace(':', "%3A").replace('/', "%2F")
}

/// An exchange keeps the claim only while `roles` survives the narrowing, and
/// recomputes it when it does.
#[actix_web::test]
async fn n15_an_exchange_drops_the_claim_when_narrowing_drops_the_scope() {
    let f = setup().await;
    seed_user_roles(&f).await;
    let app = test_app!(f);
    let (client_id, secret) = create_client(
        &app,
        &f,
        serde_json::json!({
            "name": "Exchanger",
            "redirect_uris": ["https://orders.internal"],
            "grant_types": [TOKEN_EXCHANGE_GRANT_TYPE],
            "scopes": ["read", "roles"],
        }),
    )
    .await;

    let subject = issue_access_token(
        f.user_id,
        f.tenant_id,
        f.org_id,
        &["read".to_owned(), "roles".to_owned()],
        &f.auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap();
    let actor = issue_client_credentials_token(
        &client_id,
        f.tenant_id,
        f.org_id,
        &["read".to_owned()],
        &f.auth,
    )
    .unwrap();
    let exchange = |scope: &str| {
        format!(
            "grant_type={}&client_id={client_id}&client_secret={secret}\
             &subject_token={subject}&subject_token_type={tt}\
             &actor_token={actor}&actor_token_type={tt}&scope={scope}",
            enc(TOKEN_EXCHANGE_GRANT_TYPE),
            tt = enc(TOKEN_TYPE_ACCESS_TOKEN),
        )
    };

    let (status, narrowed) = token_post(&app, &f, exchange("read")).await;
    assert_eq!(status, 200, "narrowing exchange: {narrowed}");
    let claims = access_claims(&narrowed);
    assert!(
        claims.get("roles").is_none(),
        "an exchange that narrows roles away must drop the claim: {claims}"
    );

    let (status, kept) = token_post(&app, &f, exchange("read%20roles")).await;
    assert_eq!(status, 200, "exchange keeping roles: {kept}");
    assert_eq!(access_claims(&kept)["roles"], names(&EXPECTED_USER_ROLES));
}

// ---------------------------------------------------------------------------
// Service accounts
// ---------------------------------------------------------------------------

/// A service-account token carries the claim on the same terms: its global
/// role names, direct and group-inherited, when it asked for `roles`; nothing
/// when it did not.
#[actix_web::test]
async fn n15_a_service_account_token_carries_its_global_roles() {
    let f = setup().await;
    let (sa, secret) = SurrealServiceAccountRepository::new(f.db.clone())
        .create(CreateServiceAccount {
            tenant_id: f.tenant_id,
            name: "billing-bot".into(),
            description: None,
        })
        .await
        .unwrap();
    let reader = role(&f, "svc-reader", false).await;
    let fleet = role(&f, "svc-fleet", true).await;
    roles(&f)
        .assign_to_service_account(f.tenant_id, sa.id, reader, AssignmentScope::global())
        .await
        .unwrap();
    let group = group_with_role(&f, "fleet", fleet).await;
    SurrealGroupRepository::new(f.db.clone())
        .add_service_account_member(f.tenant_id, sa.id, group)
        .await
        .unwrap();
    let app = test_app!(f);

    let form = |scope: &str| {
        format!(
            "grant_type=client_credentials&client_id={}&client_secret={secret}{scope}",
            sa.client_id
        )
    };

    let (status, plain) = token_post(&app, &f, form("")).await;
    assert_eq!(status, 200, "service-account token: {plain}");
    assert!(access_claims(&plain).get("roles").is_none());

    let (status, with_roles) = token_post(&app, &f, form("&scope=roles")).await;
    assert_eq!(
        status, 200,
        "service-account token with roles: {with_roles}"
    );
    assert_eq!(
        access_claims(&with_roles)["roles"],
        names(&["svc-fleet", "svc-reader"])
    );
    assert_eq!(with_roles["scope"], "roles");
}

/// A service account may ask for `roles` and nothing else: every other scope
/// is still refused, as before.
#[actix_web::test]
async fn n15_a_service_account_is_still_refused_any_other_scope() {
    let f = setup().await;
    let (sa, secret) = SurrealServiceAccountRepository::new(f.db.clone())
        .create(CreateServiceAccount {
            tenant_id: f.tenant_id,
            name: "billing-bot".into(),
            description: None,
        })
        .await
        .unwrap();
    let app = test_app!(f);
    let (status, body) = token_post(
        &app,
        &f,
        format!(
            "grant_type=client_credentials&client_id={}&client_secret={secret}\
             &scope=roles%20admin",
            sa.client_id
        ),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_scope");
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn n15_discovery_advertises_the_roles_scope_and_claim() {
    let f = setup().await;
    let app = test_app!(f);
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let doc: Value = test::read_body_json(resp).await;
    assert!(
        doc["scopes_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s == "roles"),
        "scopes_supported must list roles: {doc}"
    );
    assert!(
        doc["claims_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s == "roles"),
        "claims_supported must list roles: {doc}"
    );
}
