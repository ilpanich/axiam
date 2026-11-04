//! **G-B — `axiam_idp_hint` and a client's `default_idp`** (#817,
//! `claude_dev/social-login-gap-plan-2026-10-30.md` §3.2, threats T-493 and
//! T-494).
//!
//! An authorization request may name the federation provider the sign-in page
//! should start with, by its UUID, its `provider_slug` or — for a branded
//! provider, when exactly one of that kind is offered — its kind name
//! (`google`, `apple`, …; D-N24), and a client may register a default. Both are resolved on the server against the request
//! tenant's **effective, enabled** provider list — the list
//! `GET /api/v1/auth/federation/providers` already shows that page — and the
//! page receives the matched provider's id (`idp=<uuid>`) or nothing.
//!
//! Three properties are asserted throughout:
//!
//! 1. **An ignored hint is no hint.** A hint naming nothing, a disabled
//!    provider, a non-inheritable organization provider, another tenant's
//!    provider or a URL produces a response byte-identical to the request
//!    without it, apart from the request's own query string echoed inside
//!    `return_to` (the T5.1 shape).
//! 2. **Nothing becomes enumerable.** A hint resolves exactly when it names a
//!    provider of the public listing, so the endpoint answers no question the
//!    listing does not already answer.
//! 3. **The registration decides.** `default_idp` must name a provider the
//!    tenant can sign in with, on create and on update (T-241); a hint
//!    overrides it; a default whose provider has gone is ignored, not an
//!    error.

use std::net::SocketAddr;
use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_core::models::federation::{
    CreateFederationConfig, FederationProtocol, ProviderKind, UpdateFederationConfig,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::{Amr, CreateSession};
use axiam_core::models::settings::system_defaults;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    FederationConfigRepository, OrganizationRepository, SessionRepository, SettingsRepository,
    TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealFederationConfigRepository, SurrealOrganizationRepository, SurrealSessionRepository,
    SurrealSettingsRepository, SurrealTenantRepository, SurrealUserRepository,
};
use serde_json::{Value, json};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12345";
const CSRF_TOKEN: &str = "test-csrf-token";
const REDIRECT_URI: &str = "https://rp.example.com/callback";

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

/// One organization with its organization-scope tenant, the tenant the tests
/// sign into, a second (foreign) tenant of the same organization, and five
/// providers covering every way a provider can be invisible to a tenant.
struct Fixture {
    db: Surreal<TestDb>,
    org_id: Uuid,
    org_tenant_id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
    /// Tenant's own, enabled, `generic_oidc` slug `corp-okta`.
    own: Uuid,
    /// Tenant's own, **disabled**, `generic_oidc` slug `old-okta`.
    own_disabled: Uuid,
    /// The organization's Google, inheritable: offered to the tenant.
    org_inherited: Uuid,
    /// The organization's `generic_oidc` slug `org-private`, not inheritable.
    org_private: Uuid,
    /// The foreign tenant's own `generic_oidc` slug `partner-sso`.
    foreign: Uuid,
}

async fn provider(
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
    kind: ProviderKind,
    slug: Option<&str>,
    inheritable: bool,
) -> Uuid {
    SurrealFederationConfigRepository::new(db.clone())
        .create(CreateFederationConfig {
            tenant_id,
            provider: format!("{} {}", kind.as_str(), slug.unwrap_or("")),
            protocol: FederationProtocol::OidcConnect,
            metadata_url: Some("https://idp.example.com/.well-known/openid-configuration".into()),
            client_id: "cid".into(),
            client_secret: "unused".into(),
            attribute_map: None,
            idp_signing_cert_pem: None,
            allowed_algorithms: None,
            token_exchange: None,
            native_login: None,
            provider_kind: Some(kind),
            provider_slug: slug.map(str::to_owned),
            allow_tenant_inheritance: Some(inheritable),
            scopes: None,
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            allowed_issuer_tenants: None,
            apple_team_id: None,
            apple_key_id: None,
            require_pkce: None,
            button_icon: None,
            allow_sha1_signatures: None,
            idp_metadata_signing_cert_pem: None,
        })
        .await
        .expect("provider")
        .id
}

async fn disable(db: &Surreal<TestDb>, tenant_id: Uuid, id: Uuid) {
    SurrealFederationConfigRepository::new(db.clone())
        .update(
            tenant_id,
            id,
            UpdateFederationConfig {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .expect("disable");
}

async fn setup() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Hint Org".into(),
            slug: "hint-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenants = SurrealTenantRepository::new(db.clone());
    let org_tenant = tenants
        .create(CreateTenant::organization_scope(org.id))
        .await
        .unwrap();
    let tenant = tenants
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Hint Tenant".into(),
            slug: "hint-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let foreign_tenant = tenants
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Other Tenant".into(),
            slug: "other-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    SurrealSettingsRepository::new(db.clone())
        .set_org_settings(org.id, system_defaults())
        .await
        .unwrap();

    let users = SurrealUserRepository::new(db.clone());
    let user = users
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: axiam_test_support::test_password(),
            metadata: None,
        })
        .await
        .unwrap();
    users
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

    let own = provider(
        &db,
        tenant.id,
        ProviderKind::GenericOidc,
        Some("corp-okta"),
        false,
    )
    .await;
    let own_disabled = provider(
        &db,
        tenant.id,
        ProviderKind::GenericOidc,
        Some("old-okta"),
        false,
    )
    .await;
    disable(&db, tenant.id, own_disabled).await;
    let org_inherited = provider(&db, org_tenant.id, ProviderKind::Google, None, true).await;
    let org_private = provider(
        &db,
        org_tenant.id,
        ProviderKind::GenericOidc,
        Some("org-private"),
        false,
    )
    .await;
    let foreign = provider(
        &db,
        foreign_tenant.id,
        ProviderKind::GenericOidc,
        Some("partner-sso"),
        false,
    )
    .await;

    Fixture {
        db,
        org_id: org.id,
        org_tenant_id: org_tenant.id,
        tenant_id: tenant.id,
        user_id: user.id,
        own,
        own_disabled,
        org_inherited,
        org_private,
        foreign,
    }
}

/// The browser-endpoint preset lifted out of reach: these tests drive many
/// authorizations from one peer (#532).
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

fn admin_jwt(auth: &AuthConfig, f: &Fixture) -> String {
    issue_access_token(
        f.user_id,
        f.tenant_id,
        f.org_id,
        &[],
        auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap()
}

/// `POST /api/v1/oauth2-clients`, returning `(status, body)`.
async fn post_client(app: &impl TestApp, token: &str, body: Value) -> (u16, Value) {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(body)
        .to_request();
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    (status, test::read_body_json(resp).await)
}

/// `PUT /api/v1/oauth2-clients/{id}`, returning `(status, body)`.
async fn put_client(app: &impl TestApp, token: &str, id: &str, body: Value) -> (u16, Value) {
    let req = test::TestRequest::put()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(body)
        .to_request();
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    (status, test::read_body_json(resp).await)
}

/// `GET /api/v1/oauth2-clients/{id}`.
async fn get_client(app: &impl TestApp, token: &str, id: &str) -> Value {
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    test::read_body_json(resp).await
}

/// A browser-reachable client on the `ignore` lane — the registration every
/// client has — with `extra` merged in. Returns `(id, client_id)`.
async fn client(app: &impl TestApp, token: &str, extra: Value) -> (String, String) {
    let mut body = json!({
        "name": "Hint Client",
        "redirect_uris": [REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"],
        "scopes": ["openid", "profile"],
        "browser_sso": true,
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    let (status, created) = post_client(app, token, body).await;
    assert_eq!(status, 201, "client registration: {created}");
    (
        created["id"].as_str().unwrap().to_owned(),
        created["client_id"].as_str().unwrap().to_owned(),
    )
}

fn base_query(client_id: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI}\
         &scope=openid&state=g-b-state"
    )
}

/// An anonymous authorization request: `base_query`, the tenant, then
/// `extra` — so a hint in `extra` is the **last** parameter of the query the
/// server echoes into `return_to`.
async fn hop(
    app: &impl TestApp,
    tenant_id: Uuid,
    client_id: &str,
    extra: &str,
) -> actix_web::dev::ServiceResponse {
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!(
            "/oauth2/authorize?{}&tenant_id={tenant_id}{extra}",
            base_query(client_id)
        ))
        .to_request();
    test::call_service(app, req).await
}

/// Everything a response carries, as bytes: status, headers sorted by name
/// (`HeaderMap` order is not part of the response), body.
async fn snapshot(resp: actix_web::dev::ServiceResponse) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let status = resp.status().as_u16();
    let mut headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_owned()))
        .collect();
    headers.sort();
    let body = test::read_body(resp).await.to_vec();
    (status, headers, body)
}

/// The query-string echo of `&axiam_idp_hint=<raw>` as it appears inside the
/// `/login` URL's percent-encoded `return_to` — the one difference T5.1's
/// shape allows between a hinted request and the same request without a hint.
fn echo_of(raw: &str) -> String {
    url::form_urlencoded::byte_serialize(format!("&axiam_idp_hint={raw}").as_bytes()).collect()
}

/// [`snapshot`] with the hint's echo removed from `Location`.
fn without_echo(
    mut snap: (u16, Vec<(String, String)>, Vec<u8>),
    raw: &str,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let echo = echo_of(raw);
    for (name, value) in &mut snap.1 {
        if name == "location" {
            assert!(
                value.contains(&echo),
                "the request's own query is echoed in return_to: {value}"
            );
            *value = value.replacen(&echo, "", 1);
        }
    }
    snap
}

fn location(resp: &actix_web::dev::ServiceResponse) -> String {
    resp.headers()
        .get("Location")
        .expect("a Location header")
        .to_str()
        .unwrap()
        .to_owned()
}

/// The `idp` parameter of a relative `/login?…` URL.
fn idp_of(loc: &str) -> Option<Uuid> {
    assert!(loc.starts_with("/login?return_to="), "a login hop: {loc}");
    let (_, query) = loc.split_once('?')?;
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == "idp")
        .map(|(_, v)| Uuid::parse_str(&v).expect("idp is a UUID"))
}

/// The ids `GET /api/v1/auth/federation/providers` offers the tenant's
/// sign-in page.
async fn public_listing(app: &impl TestApp, f: &Fixture) -> Vec<Uuid> {
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!(
            "/api/v1/auth/federation/providers?org_id={}&tenant_id={}",
            f.org_id, f.tenant_id
        ))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    body["providers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| Uuid::parse_str(p["id"].as_str().unwrap()).unwrap())
        .collect()
}

/// `(id, provider_kind)` for every button the public listing offers the
/// tenant's sign-in page — the kind is part of that unauthenticated response.
async fn public_listing_kinds(app: &impl TestApp, f: &Fixture) -> Vec<(Uuid, String)> {
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!(
            "/api/v1/auth/federation/providers?org_id={}&tenant_id={}",
            f.org_id, f.tenant_id
        ))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    body["providers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                Uuid::parse_str(p["id"].as_str().unwrap()).unwrap(),
                p["provider_kind"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

/// Asserts that `raw` is ignored: the hinted response equals the unhinted one
/// byte for byte, apart from the hint's own echo in `return_to`.
async fn assert_ignored(app: &impl TestApp, f: &Fixture, client_id: &str, raw: &str) {
    let baseline = snapshot(hop(app, f.tenant_id, client_id, "").await).await;
    let hinted = snapshot(
        hop(
            app,
            f.tenant_id,
            client_id,
            &format!("&axiam_idp_hint={raw}"),
        )
        .await,
    )
    .await;
    assert_eq!(
        without_echo(hinted, raw),
        baseline,
        "an ignored hint ({raw}) must leave no trace but its own echo"
    );
}

/// The `idp` an anonymous request hinted with `raw` reaches the login page with.
async fn hinted_idp(app: &impl TestApp, f: &Fixture, client_id: &str, raw: &str) -> Option<Uuid> {
    let resp = hop(
        app,
        f.tenant_id,
        client_id,
        &format!("&axiam_idp_hint={raw}"),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    idp_of(&location(&resp))
}

// ---------------------------------------------------------------------------
// The hint
// ---------------------------------------------------------------------------

/// A hint naming an offered provider — by slug, by UUID in any spelling
/// `Uuid` accepts, or an inherited organization provider by UUID — reaches the
/// sign-in page as that provider's id, and as nothing else.
#[actix_rt::test]
async fn a_known_hint_reaches_the_login_page_as_a_typed_id() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);
    let jwt = admin_jwt(&auth, &f);
    let (_, client_id) = client(&app, &jwt, json!({})).await;

    let upper = f.own.to_string().to_uppercase();
    for (hint, expected) in [
        ("corp-okta".to_owned(), f.own),
        (f.own.to_string(), f.own),
        (upper, f.own),
        (f.own.simple().to_string(), f.own),
        (f.org_inherited.to_string(), f.org_inherited),
    ] {
        let resp = hop(
            &app,
            f.tenant_id,
            &client_id,
            &format!("&axiam_idp_hint={hint}"),
        )
        .await;
        assert_eq!(resp.status().as_u16(), 302);
        let loc = location(&resp);
        assert_eq!(idp_of(&loc), Some(expected), "{hint}: {loc}");
        assert!(
            loc.ends_with(&format!("&idp={expected}")),
            "the typed id is the page's only new parameter: {loc}"
        );
    }
}

/// **T-493.** A hint the server ignores produces the response a request
/// without it produces — status, every header, `Location` down to its bytes
/// apart from the request's own query echoed in `return_to`, and the body.
///
/// Every way a provider can be absent from the tenant's list is covered, plus
/// the shapes a hostile hint takes: another tenant's provider by slug and by
/// UUID, a disabled one, a non-inheritable organization provider, a random
/// UUID, nonsense, a URL, and a value over the length bound.
#[actix_rt::test]
async fn t493_an_ignored_hint_is_byte_identical_to_no_hint() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);
    let jwt = admin_jwt(&auth, &f);
    let (_, client_id) = client(&app, &jwt, json!({})).await;

    let baseline = snapshot(hop(&app, f.tenant_id, &client_id, "").await).await;
    assert_eq!(baseline.0, 302);

    let too_long = "a".repeat(axiam_oauth2::authn_params::MAX_HINT_LEN + 1);
    let ignored = [
        "partner-sso".to_owned(),
        f.foreign.to_string(),
        "old-okta".to_owned(),
        f.own_disabled.to_string(),
        "org-private".to_owned(),
        f.org_private.to_string(),
        Uuid::new_v4().to_string(),
        "no-such-provider".to_owned(),
        "https%3A%2F%2Fevil.example%2Fsso".to_owned(),
        too_long,
    ];
    for raw in ignored {
        let hinted = snapshot(
            hop(
                &app,
                f.tenant_id,
                &client_id,
                &format!("&axiam_idp_hint={raw}"),
            )
            .await,
        )
        .await;
        assert_eq!(
            without_echo(hinted, &raw),
            baseline,
            "an ignored hint ({raw}) must leave no trace but its own echo"
        );
    }
}

/// F4-W3-08 — a repeated `axiam_idp_hint` is refused exactly as a repeated
/// `login_hint` is: by the query parser, before any hint is read (RFC 6749
/// §3.1 forbids repeated parameters). The one way the hint parameter changes the
/// outcome, and it turns on the repetition, never on a value — a repeat of two
/// providers the tenant lists is answered the same as a repeat of nonsense.
#[actix_rt::test]
async fn a_repeated_hint_is_refused_like_a_repeated_login_hint() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);
    let jwt = admin_jwt(&auth, &f);
    let (_, client_id) = client(&app, &jwt, json!({})).await;

    let login_hint =
        snapshot(hop(&app, f.tenant_id, &client_id, "&login_hint=a&login_hint=b").await).await;
    assert_ne!(
        login_hint.0, 302,
        "a repeated parameter is not a sign-in hop"
    );
    for extra in [
        "&axiam_idp_hint=a&axiam_idp_hint=b".to_owned(),
        format!(
            "&axiam_idp_hint={}&axiam_idp_hint={}",
            f.own, f.org_inherited
        ),
    ] {
        let repeated = snapshot(hop(&app, f.tenant_id, &client_id, &extra).await).await;
        assert_eq!(
            repeated, login_hint,
            "a repeated hint ({extra}) is answered as a repeated login_hint"
        );
    }
}

/// **T-493, the enumeration property.** The lookup is permissible only because
/// the list it consults is already public for the tenant: the endpoint must
/// answer no question the providers listing does not already answer. Stated
/// exactly — a hint naming a provider (by id or by slug) resolves **if and only
/// if** that provider is in the public listing, and what it resolves to is a
/// listed id.
#[actix_rt::test]
async fn t493_a_hint_resolves_exactly_when_the_public_listing_shows_the_provider() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);
    let jwt = admin_jwt(&auth, &f);
    let (_, client_id) = client(&app, &jwt, json!({})).await;

    let listed = public_listing(&app, &f).await;
    assert_eq!(listed.len(), 2, "own corp-okta and the inherited Google");

    let candidates = [
        (f.own, Some("corp-okta")),
        (f.own_disabled, Some("old-okta")),
        (f.org_inherited, None),
        (f.org_private, Some("org-private")),
        (f.foreign, Some("partner-sso")),
    ];
    for (id, slug) in candidates {
        let id_hint = id.to_string();
        let hints = std::iter::once(id_hint.as_str()).chain(slug);
        for hint in hints {
            let resp = hop(
                &app,
                f.tenant_id,
                &client_id,
                &format!("&axiam_idp_hint={hint}"),
            )
            .await;
            let resolved = idp_of(&location(&resp));
            assert_eq!(
                resolved.is_some(),
                listed.contains(&id),
                "{hint}: resolves iff the listing shows it"
            );
            if let Some(resolved) = resolved {
                assert_eq!(resolved, id);
                assert!(listed.contains(&resolved));
            }
        }
    }
}

/// The hint is AXIAM's own parameter, not one of the nine OIDC parameters the
/// `authn_request_params` lane governs, so it works for the `ignore` lane —
/// every client that exists — and for `honour` alike. A client that sends no
/// hint and has no default still gets the W3 URL, byte for byte.
#[actix_rt::test]
async fn the_hint_is_read_on_both_lanes_and_absent_it_changes_nothing() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);
    let jwt = admin_jwt(&auth, &f);
    let (_, ignore) = client(&app, &jwt, json!({})).await;
    let (_, honour) = client(&app, &jwt, json!({"authn_request_params": "honour"})).await;

    for client_id in [&ignore, &honour] {
        let resp = hop(&app, f.tenant_id, client_id, "&axiam_idp_hint=corp-okta").await;
        assert_eq!(idp_of(&location(&resp)), Some(f.own));
    }

    let plain = location(&hop(&app, f.tenant_id, &ignore, "").await);
    let expected_return_to = format!(
        "/oauth2/authorize?{}&tenant_id={}&axiam_login_hop=1",
        base_query(&ignore),
        f.tenant_id
    );
    assert_eq!(
        plain,
        format!(
            "/login?return_to={}",
            url::form_urlencoded::byte_serialize(expected_return_to.as_bytes()).collect::<String>()
        ),
        "no hint, no default: the pre-G-B URL"
    );
}

/// With a live OP session there is no sign-in page, so the hint selects
/// nothing: the request is answered with a code, as without it.
#[actix_rt::test]
async fn with_a_live_session_the_hint_is_moot() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);
    let jwt = admin_jwt(&auth, &f);
    let (_, client_id) = client(&app, &jwt, json!({"default_idp": f.own})).await;
    let token = session_token(&f, &auth, chrono::Duration::minutes(1)).await;

    let resp = authorize_as(
        &app,
        &token,
        &format!("{}&axiam_idp_hint=corp-okta", base_query(&client_id)),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    let loc = location(&resp);
    assert!(
        loc.starts_with(REDIRECT_URI) && loc.contains("code="),
        "a session exists; neither hint nor default produces a login page: {loc}"
    );
}

/// A re-authentication hop (`prompt=login` on the honour lane) shows a
/// sign-in page to a signed-in user, so the hint applies there exactly as on
/// the first leg.
#[actix_rt::test]
async fn a_reauthentication_hop_carries_the_resolved_provider() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);
    let jwt = admin_jwt(&auth, &f);
    let (_, client_id) = client(
        &app,
        &jwt,
        json!({"authn_request_params": "honour", "default_idp": f.org_inherited}),
    )
    .await;
    let token = session_token(&f, &auth, chrono::Duration::minutes(1)).await;

    let hinted = authorize_as(
        &app,
        &token,
        &format!(
            "{}&prompt=login&axiam_idp_hint=corp-okta",
            base_query(&client_id)
        ),
    )
    .await;
    let loc = location(&hinted);
    assert!(loc.contains("&reauth=1"), "{loc}");
    assert_eq!(idp_of(&loc), Some(f.own), "the hint overrides the default");

    let defaulted = authorize_as(
        &app,
        &token,
        &format!("{}&prompt=login", base_query(&client_id)),
    )
    .await;
    assert_eq!(idp_of(&location(&defaulted)), Some(f.org_inherited));
}

// ---------------------------------------------------------------------------
// Kind names (D-N24)
// ---------------------------------------------------------------------------

/// **D-N24.** A branded kind name names the one offered provider of that kind
/// — here the organization's inherited Google — in any ASCII case, because the
/// listing's kind names are lower-case canonical (surrounding whitespace is
/// trimmed by the parameter parse, as for every form). Nothing else is folded, a
/// branded kind nobody offers is no hint, and the generic kinds are not hint
/// names at all: the tenant offers exactly one `generic_oidc` provider, and
/// `generic_oidc` still does not reach it.
#[actix_rt::test]
async fn d_n24_a_kind_name_resolves_to_the_only_provider_of_that_kind() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);
    let jwt = admin_jwt(&auth, &f);
    let (_, client_id) = client(&app, &jwt, json!({})).await;

    for hint in ["google", "Google", "GOOGLE", "%20google"] {
        let resp = hop(
            &app,
            f.tenant_id,
            &client_id,
            &format!("&axiam_idp_hint={hint}"),
        )
        .await;
        let loc = location(&resp);
        assert_eq!(idp_of(&loc), Some(f.org_inherited), "{hint}: {loc}");
        assert!(
            loc.ends_with(&format!("&idp={}", f.org_inherited)),
            "the typed id, never the name, reaches the page: {loc}"
        );
    }

    for raw in [
        "github",
        "apple",
        "microsoft",
        "facebook",
        "generic_oidc",
        "GENERIC_OIDC",
        "generic-oidc",
        "generic_saml",
        "goo%20gle",
        "googl",
    ] {
        assert_ignored(&app, &f, &client_id, raw).await;
    }
}

/// **D-N24, the enumeration property.** The kind is already public: the
/// providers listing carries `provider_kind` for every button. A kind-name
/// hint resolves **if and only if** the listing shows exactly one provider of
/// that kind and the kind is branded, and it resolves to that listed id — so
/// the endpoint answers nothing the listing does not.
#[actix_rt::test]
async fn d_n24_a_kind_name_resolves_exactly_when_the_listing_shows_one_of_that_kind() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);
    let jwt = admin_jwt(&auth, &f);
    let (_, client_id) = client(&app, &jwt, json!({})).await;

    // A second offered Apple makes one branded kind ambiguous on the listing.
    provider(&f.db, f.tenant_id, ProviderKind::Apple, None, false).await;
    provider(&f.db, f.tenant_id, ProviderKind::Apple, None, false).await;

    let listed = public_listing_kinds(&app, &f).await;
    assert!(
        listed
            .iter()
            .any(|(id, kind)| *id == f.org_inherited && kind == "google"),
        "the listing already shows the inherited provider's kind: {listed:?}"
    );

    for kind in ProviderKind::ALL {
        let of_kind: Vec<Uuid> = listed
            .iter()
            .filter(|(_, k)| k == kind.as_str())
            .map(|(id, _)| *id)
            .collect();
        let resolved = hinted_idp(&app, &f, &client_id, kind.as_str()).await;
        let expected = (!kind.uses_slug() && of_kind.len() == 1).then(|| of_kind[0]);
        assert_eq!(resolved, expected, "{kind:?}: listed {of_kind:?}");
    }
}

/// **D-N24, ambiguity.** An organization's Google and the tenant's own Google
/// never both count — the tenant's shadows the organization's, so `google`
/// names the tenant's. Two Google configs of the tenant's own are two offered
/// providers of one kind: `google` is ambiguous and ignored, byte-identically,
/// exactly like a slug two providers share. The UUID still names either.
#[actix_rt::test]
async fn d_n24_a_kind_two_offered_providers_share_is_ignored() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);
    let jwt = admin_jwt(&auth, &f);
    let (_, client_id) = client(&app, &jwt, json!({})).await;

    let own_google = provider(&f.db, f.tenant_id, ProviderKind::Google, None, false).await;
    assert_eq!(
        hinted_idp(&app, &f, &client_id, "google").await,
        Some(own_google),
        "the tenant's Google shadows the organization's: one Google is offered"
    );

    let second_google = provider(&f.db, f.tenant_id, ProviderKind::Google, None, false).await;
    for raw in ["google", "Google"] {
        assert_ignored(&app, &f, &client_id, raw).await;
    }
    assert_eq!(
        hinted_idp(&app, &f, &client_id, &second_google.to_string()).await,
        Some(second_google)
    );
}

/// **D-N24, precedence.** A slug is the operator's explicit word for one
/// provider; a kind name is a category. With a generic provider slugged
/// `google` beside the inherited Google, `google` names the slugged provider,
/// and `Google` — the same word in another case — is ignored rather than
/// silently reaching the other provider. Only offered providers' slugs count:
/// once the slugged provider is disabled, `google` is the kind name again, as
/// the listing (which no longer shows it) would lead anyone to expect.
#[actix_rt::test]
async fn d_n24_a_slug_wins_over_a_kind_name() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);
    let jwt = admin_jwt(&auth, &f);
    let (_, client_id) = client(&app, &jwt, json!({})).await;

    let slugged = provider(
        &f.db,
        f.tenant_id,
        ProviderKind::GenericOidc,
        Some("google"),
        false,
    )
    .await;
    assert_eq!(
        hinted_idp(&app, &f, &client_id, "google").await,
        Some(slugged),
        "the slug, not the kind"
    );
    for raw in ["Google", "GOOGLE"] {
        assert_ignored(&app, &f, &client_id, raw).await;
    }
    assert_eq!(
        hinted_idp(&app, &f, &client_id, &f.org_inherited.to_string()).await,
        Some(f.org_inherited),
        "the branded Google is still reachable by its id"
    );

    disable(&f.db, f.tenant_id, slugged).await;
    assert_eq!(
        hinted_idp(&app, &f, &client_id, "google").await,
        Some(f.org_inherited)
    );
}

/// **D-N24, disabled.** A kind name whose only provider is disabled names
/// nothing the tenant is offered, and is ignored byte-identically — with the
/// client default then applying exactly as it would without the hint.
#[actix_rt::test]
async fn d_n24_a_kind_name_of_a_disabled_provider_is_ignored() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);
    let jwt = admin_jwt(&auth, &f);
    let (_, plain) = client(&app, &jwt, json!({})).await;
    let (_, defaulted) = client(&app, &jwt, json!({"default_idp": f.own})).await;

    disable(&f.db, f.org_tenant_id, f.org_inherited).await;
    for raw in ["google", "Google"] {
        assert_ignored(&app, &f, &plain, raw).await;
        assert_ignored(&app, &f, &defaulted, raw).await;
    }
    assert_eq!(
        hinted_idp(&app, &f, &defaulted, "google").await,
        Some(f.own),
        "the default applies, as without a hint"
    );
}

// ---------------------------------------------------------------------------
// PAR
// ---------------------------------------------------------------------------

/// Store a pushed request directly (see `oauth2_login_hop_test.rs`).
async fn push_handle(f: &Fixture, client_id: &str, hint: Option<&str>) -> String {
    use axiam_core::models::oauth2_client::{CreatePushedAuthRequest, PushedAuthParams};
    use axiam_core::repository::PushedAuthRequestRepository;

    let request_uri = axiam_oauth2::par::generate_request_uri();
    axiam_db::repository::SurrealPushedAuthRequestRepository::new(f.db.clone())
        .create(CreatePushedAuthRequest {
            tenant_id: f.tenant_id,
            client_id: client_id.to_owned(),
            request_uri_hash: axiam_oauth2::par::hash_request_uri(&request_uri),
            params: PushedAuthParams {
                response_type: "code".into(),
                redirect_uri: REDIRECT_URI.into(),
                scope: Some("openid".into()),
                axiam_idp_hint: hint.map(str::to_owned),
                ..Default::default()
            },
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(60),
        })
        .await
        .expect("the pushed request must store");
    request_uri
}

/// For a pushed request the pushed hint is the hint (RFC 9126 §4): it reaches
/// the first leg's sign-in page and overrides the client default, and a
/// query-string copy beside the `request_uri` is ignored.
#[actix_rt::test]
async fn a_pushed_hint_is_honoured_and_a_query_copy_beside_it_is_not() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);
    let jwt = admin_jwt(&auth, &f);
    let (_, client_id) = client(&app, &jwt, json!({"default_idp": f.org_inherited})).await;

    let par_hop = |request_uri: String, extra: &'static str| {
        let query = format!(
            "client_id={client_id}&request_uri={}&tenant_id={}{extra}",
            url::form_urlencoded::byte_serialize(request_uri.as_bytes()).collect::<String>(),
            f.tenant_id
        );
        test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!("/oauth2/authorize?{query}"))
            .to_request()
    };

    let pushed = push_handle(&f, &client_id, Some("corp-okta")).await;
    let resp = test::call_service(&app, par_hop(pushed, "")).await;
    assert_eq!(
        idp_of(&location(&resp)),
        Some(f.own),
        "the pushed hint, over the default"
    );

    let plain = push_handle(&f, &client_id, None).await;
    let resp = test::call_service(&app, par_hop(plain, "&axiam_idp_hint=corp-okta")).await;
    assert_eq!(
        idp_of(&location(&resp)),
        Some(f.org_inherited),
        "the query copy is not the request; the default applies"
    );
}

/// **D-N24 under PAR.** A pushed kind name resolves like a query one: it
/// reaches the first leg's sign-in page as the provider's id and overrides
/// the default; a pushed kind name nobody offers is no hint.
#[actix_rt::test]
async fn a_pushed_kind_name_is_resolved_like_a_query_one() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);
    let jwt = admin_jwt(&auth, &f);
    let (_, client_id) = client(&app, &jwt, json!({"default_idp": f.own})).await;

    let par_hop = |request_uri: String| {
        let query = format!(
            "client_id={client_id}&request_uri={}&tenant_id={}",
            url::form_urlencoded::byte_serialize(request_uri.as_bytes()).collect::<String>(),
            f.tenant_id
        );
        test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!("/oauth2/authorize?{query}"))
            .to_request()
    };

    let pushed = push_handle(&f, &client_id, Some("Google")).await;
    let resp = test::call_service(&app, par_hop(pushed)).await;
    assert_eq!(
        idp_of(&location(&resp)),
        Some(f.org_inherited),
        "the pushed kind name, over the default"
    );

    let pushed = push_handle(&f, &client_id, Some("apple")).await;
    let resp = test::call_service(&app, par_hop(pushed)).await;
    assert_eq!(
        idp_of(&location(&resp)),
        Some(f.own),
        "no Apple is offered: no hint, so the default"
    );
}

// ---------------------------------------------------------------------------
// The client default
// ---------------------------------------------------------------------------

/// No hint: the default applies. A hint that names a provider overrides it.
/// A hint that is ignored is no hint, so the default applies — and the
/// response is byte-identical to the unhinted one.
#[actix_rt::test]
async fn the_default_applies_without_a_hint_and_a_hint_overrides_it() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);
    let jwt = admin_jwt(&auth, &f);
    let (_, client_id) = client(&app, &jwt, json!({"default_idp": f.org_inherited})).await;

    let unhinted = hop(&app, f.tenant_id, &client_id, "").await;
    assert_eq!(idp_of(&location(&unhinted)), Some(f.org_inherited));
    let baseline = snapshot(unhinted).await;

    let hinted = hop(&app, f.tenant_id, &client_id, "&axiam_idp_hint=corp-okta").await;
    assert_eq!(idp_of(&location(&hinted)), Some(f.own));

    let raw = f.foreign.to_string();
    let ignored = snapshot(
        hop(
            &app,
            f.tenant_id,
            &client_id,
            &format!("&axiam_idp_hint={raw}"),
        )
        .await,
    )
    .await;
    assert_eq!(
        without_echo(ignored, &raw),
        baseline,
        "an ignored hint falls back to the default exactly as no hint does"
    );
}

/// A default that was valid at registration and whose provider has since been
/// disabled is ignored at the authorization endpoint — never an error — and
/// the response is the one a client with no default gets.
#[actix_rt::test]
async fn a_default_whose_provider_was_disabled_is_ignored_byte_identically() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);
    let jwt = admin_jwt(&auth, &f);
    let (_, with_default) = client(&app, &jwt, json!({"default_idp": f.own})).await;
    let (_, without_default) = client(&app, &jwt, json!({})).await;

    assert_eq!(
        idp_of(&location(&hop(&app, f.tenant_id, &with_default, "").await)),
        Some(f.own)
    );
    disable(&f.db, f.tenant_id, f.own).await;

    let stale = snapshot(hop(&app, f.tenant_id, &with_default, "").await).await;
    let none = snapshot(hop(&app, f.tenant_id, &without_default, "").await).await;
    let mut stale = stale;
    for (_, value) in &mut stale.1 {
        *value = value.replace(&with_default, &without_default);
    }
    assert_eq!(stale, none);
}

// ---------------------------------------------------------------------------
// Registration (T-494)
// ---------------------------------------------------------------------------

/// **T-494, create.** `default_idp` must name a provider the tenant can sign in
/// with. Another tenant's provider, a disabled one, a non-inheritable
/// organization provider and an id that names nothing are `400`; the tenant's
/// own enabled provider and an inherited organization one are accepted and
/// read back.
#[actix_rt::test]
async fn t494_create_accepts_only_a_provider_the_tenant_can_see() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);
    let jwt = admin_jwt(&auth, &f);

    for refused in [f.foreign, f.own_disabled, f.org_private, Uuid::new_v4()] {
        let (status, body) = post_client(
            &app,
            &jwt,
            json!({
                "name": "Refused",
                "redirect_uris": [REDIRECT_URI],
                "grant_types": ["authorization_code"],
                "scopes": ["openid"],
                "default_idp": refused,
            }),
        )
        .await;
        assert_eq!(status, 400, "{refused}: {body}");
        assert!(
            body.to_string().contains("default_idp"),
            "the refusal names the field: {body}"
        );
    }

    for accepted in [f.own, f.org_inherited] {
        let (id, _) = client(&app, &jwt, json!({"default_idp": accepted})).await;
        let read = get_client(&app, &jwt, &id).await;
        assert_eq!(read["default_idp"], json!(accepted));
    }

    let (id, _) = client(&app, &jwt, json!({})).await;
    assert!(
        get_client(&app, &jwt, &id)
            .await
            .get("default_idp")
            .is_none(),
        "absent when unset"
    );
}

/// **T-494, update (the T-241 lesson).** The update path runs the same rule:
/// a `PUT` cannot set what a `POST` could not, and a refused `PUT` leaves the
/// row as it was. `null` clears. A `PUT` that does not touch the field is not
/// refused because the provider of an earlier, valid default has since been
/// disabled — the endpoint already ignores such a default.
#[actix_rt::test]
async fn t494_update_holds_the_same_rule_and_null_clears() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);
    let jwt = admin_jwt(&auth, &f);
    let (id, _) = client(&app, &jwt, json!({"default_idp": f.own})).await;

    for refused in [f.foreign, f.own_disabled, f.org_private, Uuid::new_v4()] {
        let (status, body) = put_client(&app, &jwt, &id, json!({"default_idp": refused})).await;
        assert_eq!(status, 400, "{refused}: {body}");
        assert_eq!(
            get_client(&app, &jwt, &id).await["default_idp"],
            json!(f.own),
            "a refused patch writes nothing"
        );
    }

    let (status, body) = put_client(&app, &jwt, &id, json!({"default_idp": f.org_inherited})).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["default_idp"], json!(f.org_inherited));

    let (status, body) = put_client(&app, &jwt, &id, json!({"name": "Renamed"})).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["default_idp"],
        json!(f.org_inherited),
        "omitted leaves it"
    );

    let (status, body) = put_client(&app, &jwt, &id, json!({"default_idp": null})).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("default_idp").is_none(), "null clears: {body}");

    // A default whose provider is disabled after the fact does not block an
    // unrelated edit.
    let (status, _) = put_client(&app, &jwt, &id, json!({"default_idp": f.own})).await;
    assert_eq!(status, 200);
    disable(&f.db, f.tenant_id, f.own).await;
    let (status, body) = put_client(&app, &jwt, &id, json!({"name": "Renamed again"})).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["default_idp"], json!(f.own), "echoed as stored");
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

/// A session row authenticated `age` ago, and an access token that arrives as
/// it (`jti` = session id, D-15).
async fn session_token(f: &Fixture, auth: &AuthConfig, age: chrono::Duration) -> String {
    let session = SurrealSessionRepository::new(f.db.clone())
        .create(CreateSession {
            tenant_id: f.tenant_id,
            user_id: f.user_id,
            token_hash: Uuid::new_v4().to_string(),
            ip_address: None,
            user_agent: None,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            authenticated_at: chrono::Utc::now() - age,
            amr: vec![Amr::Pwd],
            browser_token_hash: None,
            lineage_id: None,
        })
        .await
        .expect("session");
    issue_access_token(
        f.user_id,
        f.tenant_id,
        f.org_id,
        &[],
        auth,
        session.id.to_string(),
        AUD_USER,
    )
    .unwrap()
}

/// `GET /oauth2/authorize` with a bearer token.
async fn authorize_as(
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

/// The audit rows of the administrator's writes to the client `client_id`
/// (#834), oldest first.
async fn client_write_rows(f: &Fixture, client_id: &str) -> Vec<Value> {
    use axiam_api_rest::handlers::oauth2_clients::{
        CLIENT_CREATED_ACTION, CLIENT_DELETED_ACTION, CLIENT_UPDATED_ACTION,
    };
    let mut result =
        f.db.query(
            "SELECT action, outcome, actor_id, actor_type, tenant_id, resource_id, metadata, \
             timestamp FROM audit_log \
             WHERE action IN $actions AND metadata.client_id = $client_id \
             ORDER BY timestamp ASC",
        )
        .bind((
            "actions",
            vec![
                CLIENT_CREATED_ACTION.to_owned(),
                CLIENT_UPDATED_ACTION.to_owned(),
                CLIENT_DELETED_ACTION.to_owned(),
            ],
        ))
        .bind(("client_id", client_id.to_owned()))
        .await
        .unwrap();
    result.take(0).unwrap()
}

/// **T-494, the record (#834, F4-W3-05, D-N27).** Every administrator write to
/// a client leaves one audit row — created, updated, deleted — naming the
/// actor, the tenant and the client. An update names the members it changed,
/// measured against the stored row, and records the new `default_idp` (a
/// tenant-public provider id) when it moved: set, and cleared to `null`. A
/// refused write leaves no row, and no row ever carries the one-time secret or
/// the stored secret hash.
#[actix_rt::test]
async fn t494_client_writes_are_audited_by_field_name_and_never_carry_a_secret() {
    use axiam_api_rest::handlers::oauth2_clients::{
        CLIENT_CREATED_ACTION, CLIENT_DELETED_ACTION, CLIENT_UPDATED_ACTION,
    };
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);
    let jwt = admin_jwt(&auth, &f);

    let (status, created) = post_client(
        &app,
        &jwt,
        json!({
            "name": "Audited Client",
            "redirect_uris": [REDIRECT_URI],
            "grant_types": ["authorization_code", "refresh_token"],
            "scopes": ["openid"],
            "browser_sso": true,
            "default_idp": f.own,
        }),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let id = created["id"].as_str().unwrap().to_owned();
    let client_id = created["client_id"].as_str().unwrap().to_owned();
    let secret = created["client_secret"].as_str().unwrap().to_owned();
    assert!(!secret.is_empty());
    let mut hash =
        f.db.query("SELECT VALUE client_secret_hash FROM oauth2_client WHERE client_id = $c")
            .bind(("c", client_id.clone()))
            .await
            .unwrap();
    let hash: Vec<String> = hash.take(0).unwrap();
    let hash = hash.into_iter().next().expect("the stored row");
    assert!(!hash.is_empty());

    // Set to another provider, together with a rename.
    let (status, body) = put_client(
        &app,
        &jwt,
        &id,
        json!({"default_idp": f.org_inherited, "name": "Renamed"}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    // Cleared.
    let (status, body) = put_client(&app, &jwt, &id, json!({"default_idp": null})).await;
    assert_eq!(status, 200, "{body}");
    // A member repeated unchanged changes nothing, and is not listed.
    let (status, body) = put_client(&app, &jwt, &id, json!({"name": "Renamed"})).await;
    assert_eq!(status, 200, "{body}");
    // Refused: no row.
    let (status, body) = put_client(&app, &jwt, &id, json!({"default_idp": f.foreign})).await;
    assert_eq!(status, 400, "{body}");

    let req = test::TestRequest::delete()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {jwt}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 204);

    let rows = client_write_rows(&f, &client_id).await;
    let actions: Vec<&str> = rows.iter().map(|r| r["action"].as_str().unwrap()).collect();
    assert_eq!(
        actions,
        [
            CLIENT_CREATED_ACTION,
            CLIENT_UPDATED_ACTION,
            CLIENT_UPDATED_ACTION,
            CLIENT_UPDATED_ACTION,
            CLIENT_DELETED_ACTION,
        ],
        "one row per successful write, none for the refused one: {rows:?}"
    );
    for row in &rows {
        assert_eq!(row["outcome"], "Success", "{row}");
        assert_eq!(row["actor_id"], json!(f.user_id.to_string()), "{row}");
        assert_eq!(row["actor_type"], "User", "{row}");
        assert_eq!(row["tenant_id"], json!(f.tenant_id.to_string()), "{row}");
        assert_eq!(row["resource_id"], json!(id), "{row}");
        assert_eq!(row["metadata"]["client_id"], json!(client_id), "{row}");
        let text = row.to_string();
        assert!(!text.contains(&secret), "no row carries the secret: {row}");
        assert!(
            !text.contains(&hash),
            "no row carries the secret hash: {row}"
        );
        assert!(!text.contains("secret_hash"), "{row}");
    }

    assert_eq!(rows[0]["metadata"]["default_idp"], json!(f.own));
    assert_eq!(rows[0]["metadata"]["name"], "Audited Client");

    let mut set: Vec<&str> = rows[1]["metadata"]["changed_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    set.sort_unstable();
    assert_eq!(set, ["default_idp", "name"]);
    assert_eq!(rows[1]["metadata"]["default_idp"], json!(f.org_inherited));

    assert_eq!(
        rows[2]["metadata"]["changed_fields"],
        json!(["default_idp"])
    );
    assert!(
        rows[2]["metadata"]
            .as_object()
            .unwrap()
            .get("default_idp")
            .is_some_and(Value::is_null),
        "a cleared default is recorded as null: {}",
        rows[2]
    );

    assert_eq!(rows[3]["metadata"]["changed_fields"], json!([]));
    assert!(
        rows[3]["metadata"].get("default_idp").is_none(),
        "an unchanged default is not restated: {}",
        rows[3]
    );

    assert_eq!(rows[4]["metadata"]["name"], "Renamed");
}
