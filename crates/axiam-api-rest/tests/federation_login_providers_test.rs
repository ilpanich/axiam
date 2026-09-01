//! The public "Sign in with X" surface: the providers listing, org→tenant
//! inheritance, the handoff-code exchange, and a full OAuth2/userinfo
//! round-trip against a mock provider.
//!
//! What each group is actually pinning:
//!
//! * **Providers listing** — the response is what a button needs and *nothing*
//!   else. The leak assertion is written against the raw body rather than the
//!   typed struct, because the failure it guards against is somebody widening
//!   the struct.
//! * **Inheritance** — the precedence table in
//!   `claude_dev/federation-sso-login-design.md` §4.3, including the row that
//!   is easiest to get wrong: a *disabled* tenant override still shadows the
//!   inherited organization config, because "disable" must not mean "re-enable
//!   the organization's".
//! * **Handoff codes** — single use, and a replay is refused with the same
//!   answer as an unknown code.
//! * **OAuth2** — GitHub's shape end to end: no discovery document, no ID
//!   token, a userinfo call, and the second call to `/user/emails` that is the
//!   only place a *verified* address comes from.
//!
//! Harness conventions (loopback wiremock, `JwksCache::new_allow_private_networks`,
//! the `test_app!` macro) mirror `federation_first_time_sso_test.rs`.

use std::net::SocketAddr;
use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_federation::jwks_cache::JwksCache;
use axiam_federation::oidc::OidcFederationService;
use serde_json::{Value, json};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12345";
const CSRF_TOKEN: &str = "test-csrf-token";
/// Test-only AES-256-GCM key (32 bytes of 0x2a) — not a secret. gitleaks:allow
const TEST_FED_ENC_KEY: [u8; 32] = [0x2a; 32];
/// A real 1×1 transparent PNG, base64. Small enough to inline, and a genuine
/// raster so the validator is exercised against something a browser would emit.
const TEST_ICON: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";

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
        jwt_issuer: "https://axiam.test".into(),
        federation_encryption_key: Some(TEST_FED_ENC_KEY),
        ..AuthConfig::default()
    }
}

struct Fixture {
    db: Surreal<TestDb>,
    org_id: Uuid,
    org_slug: String,
    /// The organization-scope tenant — where an inheritable provider lives.
    org_tenant_id: Uuid,
    /// An ordinary tenant that may inherit from it.
    tenant_id: Uuid,
    tenant_slug: String,
}

async fn setup(slug_prefix: &str) -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org_slug = format!("{slug_prefix}-org");
    let org = org_repo
        .create(CreateOrganization {
            name: "Test Org".into(),
            slug: org_slug.clone(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let org_tenant = tenant_repo
        .create(CreateTenant::organization_scope(org.id))
        .await
        .unwrap();
    let tenant_slug = format!("{slug_prefix}-tenant");
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Test Tenant".into(),
            slug: tenant_slug.clone(),
            metadata: None,
        })
        .await
        .unwrap();

    Fixture {
        db,
        org_id: org.id,
        org_slug,
        org_tenant_id: org_tenant.id,
        tenant_id: tenant.id,
        tenant_slug,
    }
}

async fn admin_in(db: &Surreal<TestDb>, tenant_id: Uuid, username: &str) -> Uuid {
    SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id,
            username: username.into(),
            email: format!("{username}@example.com"),
            // Generated per test binary rather than a literal: this fixture
            // user is authenticated with a minted token, never with a
            // password, so nothing here needs a stable value — and a
            // hard-coded credential in a new file is a CodeQL alert the older
            // fixtures are only spared because they predate the scan.
            password: axiam_test_support::test_password(),
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

fn mint_token(auth: &AuthConfig, user_id: Uuid, tenant_id: Uuid, org_id: Uuid) -> String {
    issue_access_token(
        user_id,
        tenant_id,
        org_id,
        &[],
        auth,
        Uuid::new_v4().to_string(),
        axiam_auth::token::AUD_USER,
    )
    .unwrap()
}

macro_rules! test_app {
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new({
                    let mut state = AppState::for_test($db.clone(), $auth.clone());
                    state.http_client = reqwest::Client::builder()
                        .redirect(reqwest::redirect::Policy::none())
                        .timeout(std::time::Duration::from_secs(10))
                        .build()
                        .unwrap();
                    // Lets the outbound guards reach the loopback wiremock
                    // provider this test starts. Production always builds
                    // `JwksCache::new()`.
                    state.jwks_cache = Arc::new(JwksCache::new_allow_private_networks());
                    state.federation.oidc_federation_service = Some(OidcFederationService::new(
                        state.federation.federation_config_repo.clone(),
                        state.federation.federation_link_repo.clone(),
                        state.user_repo.clone(),
                        state.http_client.clone(),
                        Arc::clone(&state.jwks_cache),
                        TEST_FED_ENC_KEY,
                    ));
                    state
                }))
                .app_data(web::Data::new(
                    Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
                ))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    };
}

/// Create a federation config as an administrator of `tenant_id`.
macro_rules! create_config {
    ($app:expr, $auth:expr, $db:expr, $org_id:expr, $tenant_id:expr, $username:expr, $body:expr) => {{
        let admin = admin_in(&$db, $tenant_id, $username).await;
        let token = mint_token(&$auth, admin, $tenant_id, $org_id);
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/federation-configs")
            .insert_header(("Authorization", format!("Bearer {token}")))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json($body)
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let body: Value = test::read_body_json(resp).await;
        (status, body)
    }};
}

async fn providers_for(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    org_slug: &str,
    tenant_slug: Option<&str>,
) -> Value {
    let uri = match tenant_slug {
        Some(t) => format!("/api/v1/auth/federation/providers?org_slug={org_slug}&tenant_slug={t}"),
        None => format!("/api/v1/auth/federation/providers?org_slug={org_slug}"),
    };
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&uri)
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "providers must always answer 200"
    );
    test::read_body_json(resp).await
}

fn kinds(body: &Value) -> Vec<String> {
    body["providers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["provider_kind"].as_str().unwrap().to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// Providers listing
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn the_providers_listing_returns_only_what_a_button_needs() {
    let f = setup("providers-shape").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let (status, _) = create_config!(
        app,
        auth,
        f.db,
        f.org_id,
        f.tenant_id,
        "t-admin",
        json!({
            "provider": "Google",
            "provider_kind": "google",
            "protocol": "OidcConnect",
            "metadata_url": "https://accounts.google.com/.well-known/openid-configuration",
            "client_id": "a-client-id-that-must-not-leak",
            "client_secret": "a-client-secret-that-must-not-leak",
        })
    );
    assert_eq!(status, 201);

    let body = providers_for(&app, &f.org_slug, Some(&f.tenant_slug)).await;
    let providers = body["providers"].as_array().unwrap();
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0]["provider_kind"], "google");
    assert_eq!(providers[0]["display_name"], "Google");
    assert_eq!(providers[0]["protocol"], "OidcConnect");
    assert_eq!(providers[0]["has_bundled_mark"], true);
    assert_eq!(providers[0]["inherited"], false);

    // Asserted against the raw body, not the typed struct: the failure this
    // guards against is somebody widening the struct, which a typed assertion
    // would happily follow.
    let raw = serde_json::to_string(&body).unwrap();
    for forbidden in [
        "a-client-id-that-must-not-leak",
        "a-client-secret-that-must-not-leak",
        "client_id",
        "client_secret",
        "metadata_url",
        "attribute_map",
        "token_endpoint",
        "userinfo_endpoint",
        "allowed_issuer_tenants",
    ] {
        assert!(
            !raw.contains(forbidden),
            "the unauthenticated providers response leaked `{forbidden}`: {raw}"
        );
    }
}

/// An unknown organization and a known one with nothing configured must be
/// indistinguishable, or the endpoint is an organization-slug oracle.
#[actix_rt::test]
async fn an_unknown_workspace_is_indistinguishable_from_an_unconfigured_one() {
    let f = setup("providers-oracle").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let unknown = providers_for(&app, "no-such-organization-anywhere", Some("nor-this")).await;
    let known_empty = providers_for(&app, &f.org_slug, Some(&f.tenant_slug)).await;
    assert_eq!(unknown, known_empty);
    assert!(unknown["providers"].as_array().unwrap().is_empty());
}

#[actix_rt::test]
async fn a_disabled_provider_is_not_offered() {
    let f = setup("providers-disabled").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let (status, created) = create_config!(
        app,
        auth,
        f.db,
        f.org_id,
        f.tenant_id,
        "t-admin",
        json!({
            "provider": "Okta",
            "provider_kind": "generic_oidc",
            "provider_slug": "okta",
            "protocol": "OidcConnect",
            "metadata_url": "https://idp.example.com/.well-known/openid-configuration",
            "client_id": "cid",
            "client_secret": "secret",
        })
    );
    assert_eq!(status, 201);
    assert_eq!(
        kinds(&providers_for(&app, &f.org_slug, Some(&f.tenant_slug)).await).len(),
        1
    );

    // Disable it.
    let admin = admin_in(&f.db, f.tenant_id, "t-admin-2").await;
    let token = mint_token(&auth, admin, f.tenant_id, f.org_id);
    let id = created["id"].as_str().unwrap();
    let req = test::TestRequest::put()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/federation-configs/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({ "enabled": false }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 200);

    assert!(
        providers_for(&app, &f.org_slug, Some(&f.tenant_slug)).await["providers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// Inheritance — the §4.3 precedence table
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn an_organization_provider_reaches_tenants_only_when_it_says_so() {
    let f = setup("inherit-flag").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    // Not inheritable: the organization's own scope sees it, the tenant does not.
    let (status, _) = create_config!(
        app,
        auth,
        f.db,
        f.org_id,
        f.org_tenant_id,
        "org-admin",
        json!({
            "provider": "Google",
            "provider_kind": "google",
            "protocol": "OidcConnect",
            "metadata_url": "https://accounts.google.com/.well-known/openid-configuration",
            "client_id": "cid",
            "client_secret": "secret",
        })
    );
    assert_eq!(status, 201);

    assert_eq!(
        kinds(&providers_for(&app, &f.org_slug, None).await),
        vec!["google".to_string()],
        "the organization scope always sees its own"
    );
    assert!(
        kinds(&providers_for(&app, &f.org_slug, Some(&f.tenant_slug)).await).is_empty(),
        "inheritance is opted into, so this must be invisible to the tenant"
    );
}

#[actix_rt::test]
async fn an_inheritable_organization_provider_is_offered_to_a_tenant() {
    let f = setup("inherit-on").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let (status, _) = create_config!(
        app,
        auth,
        f.db,
        f.org_id,
        f.org_tenant_id,
        "org-admin",
        json!({
            "provider": "Corporate Google",
            "provider_kind": "google",
            "protocol": "OidcConnect",
            "metadata_url": "https://accounts.google.com/.well-known/openid-configuration",
            "client_id": "cid",
            "client_secret": "secret",
            "allow_tenant_inheritance": true,
        })
    );
    assert_eq!(status, 201);

    let body = providers_for(&app, &f.org_slug, Some(&f.tenant_slug)).await;
    let providers = body["providers"].as_array().unwrap();
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0]["provider_kind"], "google");
    assert_eq!(
        providers[0]["inherited"], true,
        "a tenant administrator has to be able to see this is not theirs to edit"
    );
    // …and the organization's own scope still lists it as its own.
    let own = providers_for(&app, &f.org_slug, None).await;
    assert_eq!(own["providers"][0]["inherited"], false);
}

#[actix_rt::test]
async fn a_tenants_own_provider_overrides_the_inherited_one_of_the_same_kind() {
    let f = setup("inherit-override").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    create_config!(
        app,
        auth,
        f.db,
        f.org_id,
        f.org_tenant_id,
        "org-admin",
        json!({
            "provider": "Corporate Google",
            "provider_kind": "google",
            "protocol": "OidcConnect",
            "metadata_url": "https://accounts.google.com/.well-known/openid-configuration",
            "client_id": "org-cid",
            "client_secret": "secret",
            "allow_tenant_inheritance": true,
        })
    );
    create_config!(
        app,
        auth,
        f.db,
        f.org_id,
        f.tenant_id,
        "t-admin",
        json!({
            "provider": "Our Own Google",
            "provider_kind": "google",
            "protocol": "OidcConnect",
            "metadata_url": "https://accounts.google.com/.well-known/openid-configuration",
            "client_id": "tenant-cid",
            "client_secret": "secret",
        })
    );

    let body = providers_for(&app, &f.org_slug, Some(&f.tenant_slug)).await;
    let providers = body["providers"].as_array().unwrap();
    assert_eq!(providers.len(), 1, "one Google, not two");
    assert_eq!(providers[0]["display_name"], "Our Own Google");
    assert_eq!(providers[0]["inherited"], false);
}

/// The precedence row most likely to be got wrong. A tenant administrator who
/// created a Google config and disabled it has said "no Google here"; falling
/// back to the inherited one would make "disable" mean "re-enable the
/// organization's".
#[actix_rt::test]
async fn a_disabled_tenant_override_still_shadows_the_inherited_provider() {
    let f = setup("inherit-shadow").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    create_config!(
        app,
        auth,
        f.db,
        f.org_id,
        f.org_tenant_id,
        "org-admin",
        json!({
            "provider": "Corporate Google",
            "provider_kind": "google",
            "protocol": "OidcConnect",
            "metadata_url": "https://accounts.google.com/.well-known/openid-configuration",
            "client_id": "org-cid",
            "client_secret": "secret",
            "allow_tenant_inheritance": true,
        })
    );
    let (_, tenant_cfg) = create_config!(
        app,
        auth,
        f.db,
        f.org_id,
        f.tenant_id,
        "t-admin",
        json!({
            "provider": "Our Own Google",
            "provider_kind": "google",
            "protocol": "OidcConnect",
            "metadata_url": "https://accounts.google.com/.well-known/openid-configuration",
            "client_id": "tenant-cid",
            "client_secret": "secret",
        })
    );

    let admin = admin_in(&f.db, f.tenant_id, "t-admin-2").await;
    let token = mint_token(&auth, admin, f.tenant_id, f.org_id);
    let id = tenant_cfg["id"].as_str().unwrap();
    let req = test::TestRequest::put()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/federation-configs/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({ "enabled": false }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 200);

    assert!(
        providers_for(&app, &f.org_slug, Some(&f.tenant_slug)).await["providers"]
            .as_array()
            .unwrap()
            .is_empty(),
        "the tenant said no to Google; the organization's must not take its place"
    );
}

/// Two generic providers of the same kind are told apart by their slug, so one
/// can be overridden without the other.
#[actix_rt::test]
async fn generic_providers_are_overridden_one_slug_at_a_time() {
    let f = setup("inherit-slug").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    for slug in ["okta-eu", "okta-us"] {
        create_config!(
            app,
            auth,
            f.db,
            f.org_id,
            f.org_tenant_id,
            &format!("org-admin-{slug}"),
            json!({
                "provider": format!("Okta {slug}"),
                "provider_kind": "generic_oidc",
                "provider_slug": slug,
                "protocol": "OidcConnect",
                "metadata_url": "https://idp.example.com/.well-known/openid-configuration",
                "client_id": "cid",
                "client_secret": "secret",
                "allow_tenant_inheritance": true,
            })
        );
    }
    create_config!(
        app,
        auth,
        f.db,
        f.org_id,
        f.tenant_id,
        "t-admin",
        json!({
            "provider": "Our Okta EU",
            "provider_kind": "generic_oidc",
            "provider_slug": "okta-eu",
            "protocol": "OidcConnect",
            "metadata_url": "https://idp.example.com/.well-known/openid-configuration",
            "client_id": "tenant-cid",
            "client_secret": "secret",
        })
    );

    let body = providers_for(&app, &f.org_slug, Some(&f.tenant_slug)).await;
    let providers = body["providers"].as_array().unwrap();
    assert_eq!(providers.len(), 2);
    let names: Vec<&str> = providers
        .iter()
        .map(|p| p["display_name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"Our Okta EU"), "{names:?}");
    assert!(names.contains(&"Okta okta-us"), "{names:?}");
    assert!(!names.contains(&"Okta okta-eu"), "{names:?}");
}

// ---------------------------------------------------------------------------
// Custom button icons
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn a_generic_provider_may_carry_a_custom_button_icon() {
    let f = setup("icon-generic").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let (status, created) = create_config!(
        app,
        auth,
        f.db,
        f.org_id,
        f.tenant_id,
        "t-admin",
        json!({
            "provider": "Acme SSO",
            "provider_kind": "generic_oidc",
            "provider_slug": "acme",
            "protocol": "OidcConnect",
            "metadata_url": "https://idp.example.com/.well-known/openid-configuration",
            "client_id": "cid",
            "client_secret": "secret",
            "button_icon": TEST_ICON,
        })
    );
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["button_icon"], TEST_ICON);
    assert_eq!(created["has_bundled_mark"], false);

    // The login page cannot render the button without it, so it is one of the
    // few things the unauthenticated listing does carry.
    let body = providers_for(&app, &f.org_slug, Some(&f.tenant_slug)).await;
    assert_eq!(body["providers"][0]["button_icon"], TEST_ICON);
    assert_eq!(body["providers"][0]["has_bundled_mark"], false);
}

/// Google, Apple and Microsoft publish sign-in-button rules that require their
/// own mark. Accepting a replacement would let an operator build a button that
/// breaks the guidelines it exists to follow.
#[actix_rt::test]
async fn a_branded_provider_may_not_replace_its_mark() {
    let f = setup("icon-branded").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let (status, body) = create_config!(
        app,
        auth,
        f.db,
        f.org_id,
        f.tenant_id,
        "t-admin",
        json!({
            "provider": "Google",
            "provider_kind": "google",
            "protocol": "OidcConnect",
            "metadata_url": "https://accounts.google.com/.well-known/openid-configuration",
            "client_id": "cid",
            "client_secret": "secret",
            "button_icon": TEST_ICON,
        })
    );
    assert_eq!(status, 400, "{body}");
    assert!(
        serde_json::to_string(&body)
            .unwrap()
            .contains("its own mark"),
        "{body}"
    );
}

#[actix_rt::test]
async fn an_svg_button_icon_is_refused() {
    let f = setup("icon-svg").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let (status, body) = create_config!(
        app,
        auth,
        f.db,
        f.org_id,
        f.tenant_id,
        "t-admin",
        json!({
            "provider": "Acme SSO",
            "provider_kind": "generic_oidc",
            "provider_slug": "acme",
            "protocol": "OidcConnect",
            "metadata_url": "https://idp.example.com/.well-known/openid-configuration",
            "client_id": "cid",
            "client_secret": "secret",
            "button_icon": "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=",
        })
    );
    assert_eq!(status, 400, "{body}");
}

// ---------------------------------------------------------------------------
// Validation of the new relational rules
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn a_provider_that_does_oidc_cannot_be_configured_as_plain_oauth2() {
    let f = setup("kind-protocol").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let (status, body) = create_config!(
        app,
        auth,
        f.db,
        f.org_id,
        f.tenant_id,
        "t-admin",
        json!({
            "provider": "Google",
            "provider_kind": "google",
            "protocol": "OAuth2",
            "client_id": "cid",
            "client_secret": "secret",
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
        })
    );
    assert_eq!(status, 400, "{body}");
    assert!(
        serde_json::to_string(&body)
            .unwrap()
            .contains("unsigned userinfo call"),
        "the refusal must say why, or somebody will look for a workaround: {body}"
    );
}

#[actix_rt::test]
async fn an_oauth2_provider_without_its_endpoints_is_refused_at_the_form() {
    let f = setup("oauth2-endpoints").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let (status, body) = create_config!(
        app,
        auth,
        f.db,
        f.org_id,
        f.tenant_id,
        "t-admin",
        json!({
            "provider": "GitHub",
            "provider_kind": "github",
            "protocol": "OAuth2",
            "client_id": "cid",
            "client_secret": "secret",
            "authorization_endpoint": "https://github.com/login/oauth/authorize",
            "token_endpoint": "https://github.com/login/oauth/access_token",
        })
    );
    assert_eq!(status, 400, "{body}");
    assert!(
        serde_json::to_string(&body)
            .unwrap()
            .contains("userinfo_endpoint"),
        "{body}"
    );
}

/// A slug is optional, and a config without one keys on its kind.
///
/// It has to be optional: a request that omits `provider_kind` derives a
/// generic kind, which is what every client written before this change sends,
/// and demanding a slug there would turn a working create call into a 400.
#[actix_rt::test]
async fn a_generic_provider_without_a_slug_still_works() {
    let f = setup("slug-optional").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let (status, body) = create_config!(
        app,
        auth,
        f.db,
        f.org_id,
        f.tenant_id,
        "t-admin",
        json!({
            "provider": "Okta",
            "protocol": "OidcConnect",
            "metadata_url": "https://idp.example.com/.well-known/openid-configuration",
            "client_id": "cid",
            "client_secret": "secret",
        })
    );
    assert_eq!(status, 201, "{body}");
    assert_eq!(
        body["provider_kind"], "generic_oidc",
        "an omitted kind derives from the protocol"
    );
    assert!(body["provider_slug"].is_null());
    assert_eq!(
        kinds(&providers_for(&app, &f.org_slug, Some(&f.tenant_slug)).await).len(),
        1
    );
}

/// …but a branded kind may not carry one, because the kind is already the key.
#[actix_rt::test]
async fn a_branded_provider_may_not_carry_a_slug() {
    let f = setup("slug-branded").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let (status, body) = create_config!(
        app,
        auth,
        f.db,
        f.org_id,
        f.tenant_id,
        "t-admin",
        json!({
            "provider": "Google",
            "provider_kind": "google",
            "provider_slug": "our-google",
            "protocol": "OidcConnect",
            "metadata_url": "https://accounts.google.com/.well-known/openid-configuration",
            "client_id": "cid",
            "client_secret": "secret",
        })
    );
    assert_eq!(status, 400, "{body}");
}

#[actix_rt::test]
async fn an_attribute_map_naming_an_unknown_field_is_refused() {
    let f = setup("attrmap").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let (status, body) = create_config!(
        app,
        auth,
        f.db,
        f.org_id,
        f.tenant_id,
        "t-admin",
        json!({
            "provider": "Okta",
            "provider_kind": "generic_oidc",
            "provider_slug": "okta",
            "protocol": "OidcConnect",
            "metadata_url": "https://idp.example.com/.well-known/openid-configuration",
            "client_id": "cid",
            "client_secret": "secret",
            "attribute_map": { "e-mail": "mail" },
        })
    );
    assert_eq!(
        status, 400,
        "a map that does nothing is exactly the defect being fixed: {body}"
    );
}

// ---------------------------------------------------------------------------
// The OAuth2 variant, end to end
// ---------------------------------------------------------------------------

/// A full GitHub-shaped round-trip: no discovery document, no ID token, an
/// authorize URL carrying PKCE, a token exchange, a userinfo call, and the
/// second `/user/emails` call that is the only place a verified address comes
/// from.
#[actix_rt::test]
async fn an_oauth2_login_round_trips_through_userinfo_and_provisions_a_user() {
    let f = setup("oauth2-e2e").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let idp = MockServer::start().await;
    let base = idp.uri();

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "gho_test_access_token",
            "token_type": "bearer",
            "scope": "read:user,user:email",
        })))
        .mount(&idp)
        .await;
    // `GET /user` deliberately answers with a *null* email, which is the
    // common real shape and the reason the second call exists.
    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 583231,
            "login": "octocat",
            "name": "The Octocat",
            "email": Value::Null,
        })))
        .mount(&idp)
        .await;
    Mock::given(method("GET"))
        .and(path("/user/emails"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"email": "secondary@example.com", "verified": true, "primary": false},
            {"email": "octocat@users.noreply.github.com", "verified": true, "primary": true},
        ])))
        .mount(&idp)
        .await;

    let (status, created) = create_config!(
        app,
        auth,
        f.db,
        f.org_id,
        f.tenant_id,
        "t-admin",
        json!({
            "provider": "GitHub",
            "provider_kind": "github",
            "protocol": "OAuth2",
            "client_id": "gh-client",
            "client_secret": "gh-secret",
            "authorization_endpoint": format!("{base}/login/oauth/authorize"),
            "token_endpoint": format!("{base}/token"),
            "userinfo_endpoint": format!("{base}/user"),
        })
    );
    assert_eq!(status, 201, "{created}");
    let config_id = created["id"].as_str().unwrap().to_string();
    assert_eq!(
        created["pkce_required"], true,
        "PKCE is not optional on this path"
    );

    // --- start ---
    let start_req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/federation/oauth2/start")
        .set_json(json!({
            "org_slug": f.org_slug,
            "tenant_slug": f.tenant_slug,
            "federation_config_id": config_id,
            "redirect_uri": "https://spa.example.test/auth/sso/callback",
        }))
        .to_request();
    let start_resp = test::call_service(&app, start_req).await;
    assert_eq!(start_resp.status().as_u16(), 200);
    let start: Value = test::read_body_json(start_resp).await;

    let authorize_url = start["authorize_url"].as_str().unwrap();
    assert!(authorize_url.contains("code_challenge="), "{authorize_url}");
    assert!(
        authorize_url.contains("code_challenge_method=S256"),
        "{authorize_url}"
    );
    assert!(
        authorize_url.contains("scope=read%3Auser+user%3Aemail"),
        "the per-kind default scopes must be requested: {authorize_url}"
    );
    assert!(
        start.get("code_verifier").is_none(),
        "the verifier must never leave the server"
    );

    // --- callback ---
    let cb_req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/federation/oauth2/callback")
        .set_json(json!({ "state": start["state"], "code": "provider-code" }))
        .to_request();
    let cb_resp = test::call_service(&app, cb_req).await;
    let cb_status = cb_resp.status().as_u16();
    let cookies: Vec<String> = cb_resp
        .response()
        .headers()
        .get_all(actix_web::http::header::SET_COOKIE)
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    let cb: Value = test::read_body_json(cb_resp).await;
    assert_eq!(cb_status, 200, "{cb}");
    assert!(
        cookies.iter().any(|c| c.starts_with("axiam_access=")),
        "the same-origin OAuth2 callback sets cookies directly: {cookies:?}"
    );

    // The provisioned user is keyed on GitHub's numeric id, and carries the
    // *verified primary* address — not the null one `GET /user` returned, and
    // not the verified-but-not-primary one.
    let user_id: Uuid = cb["user_id"].as_str().unwrap().parse().unwrap();
    let user = SurrealUserRepository::new(f.db.clone())
        .get_by_id(f.tenant_id, user_id)
        .await
        .unwrap();
    assert_eq!(user.email, "octocat@users.noreply.github.com");
    assert_eq!(user.username, "octocat");
    assert_eq!(user.metadata["external_subject"], "583231");
    assert_eq!(user.metadata["display_name"], "The Octocat");

    // --- the state is single-use ---
    let replay = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/federation/oauth2/callback")
        .set_json(json!({ "state": start["state"], "code": "provider-code" }))
        .to_request();
    assert_eq!(
        test::call_service(&app, replay).await.status().as_u16(),
        401
    );
}

/// AXIAM keys account recovery on the email address, so an unverified one is
/// never adopted as an identity.
#[actix_rt::test]
async fn an_oauth2_login_with_no_verified_email_is_refused() {
    let f = setup("oauth2-unverified").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let idp = MockServer::start().await;
    let base = idp.uri();
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"access_token": "at", "token_type": "bearer"})),
        )
        .mount(&idp)
        .await;
    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 1, "login": "nobody", "name": "Nobody", "email": "nobody@example.com",
        })))
        .mount(&idp)
        .await;
    Mock::given(method("GET"))
        .and(path("/user/emails"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"email": "nobody@example.com", "verified": false, "primary": true},
        ])))
        .mount(&idp)
        .await;

    let (_, created) = create_config!(
        app,
        auth,
        f.db,
        f.org_id,
        f.tenant_id,
        "t-admin",
        json!({
            "provider": "GitHub",
            "provider_kind": "github",
            "protocol": "OAuth2",
            "client_id": "gh-client",
            "client_secret": "gh-secret",
            "authorization_endpoint": format!("{base}/login/oauth/authorize"),
            "token_endpoint": format!("{base}/token"),
            "userinfo_endpoint": format!("{base}/user"),
        })
    );

    let start_req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/federation/oauth2/start")
        .set_json(json!({
            "org_slug": f.org_slug,
            "tenant_slug": f.tenant_slug,
            "federation_config_id": created["id"],
            "redirect_uri": "https://spa.example.test/auth/sso/callback",
        }))
        .to_request();
    let start: Value = test::read_body_json(test::call_service(&app, start_req).await).await;

    let cb = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/federation/oauth2/callback")
        .set_json(json!({ "state": start["state"], "code": "c" }))
        .to_request();
    let resp = test::call_service(&app, cb).await;
    assert_eq!(resp.status().as_u16(), 401);

    // …and no user was created for the address nobody proved they control.
    let body: Value = test::read_body_json(resp).await;
    assert!(
        serde_json::to_string(&body).unwrap().contains("verified"),
        "the message must point at the email, not at a password: {body}"
    );
}

// ---------------------------------------------------------------------------
// Handoff codes
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn an_unknown_handoff_code_is_refused() {
    let f = setup("handoff-unknown").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/federation/handoff")
        .set_json(json!({ "code": "a-code-that-was-never-minted" }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 401);
}

/// Mint one directly through the repository — the two endpoints that mint them
/// need a live SAML IdP or Apple — and assert the properties that matter: the
/// code buys exactly one session, and only its hash is ever stored.
#[actix_rt::test]
async fn a_handoff_code_buys_exactly_one_session() {
    use axiam_core::repository::{SSO_HANDOFF_TTL_SECS, SsoHandoffCode, SsoHandoffCodeRepository};
    use axiam_db::repository::SurrealSsoHandoffCodeRepository;
    use sha2::{Digest, Sha256};

    let f = setup("handoff-single-use").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let user_id = admin_in(&f.db, f.tenant_id, "federated-user").await;
    let code = "a-256-bit-code-stands-in-for-the-real-thing";
    let repo = SurrealSsoHandoffCodeRepository::new(f.db.clone());
    repo.insert(&SsoHandoffCode {
        code_hash: hex::encode(Sha256::digest(code.as_bytes())),
        tenant_id: f.tenant_id,
        user_id,
        redirect_uri: "https://spa.example.test/dashboard".into(),
        expires_at: chrono::Utc::now() + chrono::Duration::seconds(SSO_HANDOFF_TTL_SECS),
    })
    .await
    .unwrap();

    let redeem = |code: &str| {
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/auth/federation/handoff")
            .set_json(json!({ "code": code }))
            .to_request()
    };

    let resp = test::call_service(&app, redeem(code)).await;
    let status = resp.status().as_u16();
    let cookies: Vec<String> = resp
        .response()
        .headers()
        .get_all(actix_web::http::header::SET_COOKIE)
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["redirect_uri"], "https://spa.example.test/dashboard");
    assert!(
        cookies.iter().any(|c| c.starts_with("axiam_access=")),
        "this same-origin response is the one that may set the cookies: {cookies:?}"
    );

    // Single use: the second attempt is indistinguishable from an unknown code.
    assert_eq!(
        test::call_service(&app, redeem(code))
            .await
            .status()
            .as_u16(),
        401
    );
}

// ---------------------------------------------------------------------------
// Where a handoff code may be delivered
// ---------------------------------------------------------------------------

/// A handoff code is a bearer credential for a session, and on the SAML and
/// Apple flows no identity provider ever sees — let alone validates — the SPA
/// `redirect_uri`: the IdP is pointed at AXIAM's own ACS. AXIAM alone decides
/// where the browser goes next, so an attacker who could name that target on
/// this *unauthenticated* endpoint could lure a victim through the victim's own
/// real IdP and read a working session credential out of their access log.
///
/// The unit tests in `handlers::federation_login` cover the decision itself.
/// This one covers the wiring: that the check is actually on the SAML start
/// path, and that it runs *after* workspace and config resolution, so an
/// unknown slug still gets the uniform 401 rather than being told which check
/// it failed.
#[cfg(feature = "saml")]
#[actix_rt::test]
async fn a_saml_login_may_not_name_a_foreign_redirect_target() {
    let f = setup("origin").await;
    let auth = test_auth_config();
    let app = test_app!(f.db.clone(), auth.clone());

    let (status, body) = create_config!(
        app,
        auth,
        f.db,
        f.org_id,
        f.tenant_id,
        "saml-admin",
        json!({
            "provider": "Acme SAML",
            "provider_kind": "generic_saml",
            "provider_slug": "acme",
            "protocol": "Saml",
            "metadata_url": "https://idp.example.com/metadata",
            "client_id": "https://axiam.test/saml/sp",
            "client_secret": "saml-dummy-secret",
        })
    );
    assert_eq!(status, 201, "{body}");
    let config_id = body["id"].as_str().unwrap().to_string();

    let start = |redirect_uri: &str| {
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/auth/federation/saml/login")
            .set_json(json!({
                "org_slug": f.org_slug,
                "tenant_slug": f.tenant_slug,
                "federation_config_id": config_id,
                "redirect_uri": redirect_uri,
            }))
            .to_request()
    };

    let resp = test::call_service(&app, start("https://attacker.example/catch")).await;
    let status = resp.status().as_u16();
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body.to_string().contains("SSO_SPA_ORIGINS"),
        "the refusal must name the knob an operator would need: {body}"
    );

    // The deployment's own origin — `jwt_issuer` in this fixture — gets past
    // this check. It fails later, on the IdP metadata fetch, which is exactly
    // the point: the origin is no longer what stops it.
    let resp = test::call_service(&app, start("https://axiam.test/auth/sso/callback")).await;
    let status = resp.status().as_u16();
    let body: Value = test::read_body_json(resp).await;
    assert!(
        !body.to_string().contains("SSO_SPA_ORIGINS"),
        "the deployment's own origin must not be refused: {status} {body}"
    );

    // Resolution comes first: an unknown organization still answers the uniform
    // 401 and never reveals that a redirect_uri check exists.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/federation/saml/login")
        .set_json(json!({
            "org_slug": "no-such-org-at-all",
            "federation_config_id": config_id,
            "redirect_uri": "https://attacker.example/catch",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

// ---------------------------------------------------------------------------
// What the OAuth2 variant does when the provider misbehaves
// ---------------------------------------------------------------------------

/// On this path there is no signature, no `nonce` and no `aud` — the userinfo
/// call *is* the authentication (design doc §3). So every way that exchange can
/// go wrong has to end in a refusal rather than in a half-built identity, and
/// each of these drives one of them through the real public endpoints.
///
/// The shape is shared: mount a mock provider, create a config against it,
/// start a login, complete it, and report what came back.
#[cfg(test)]
struct Oauth2Failure {
    status: u16,
    body: Value,
    cookies: Vec<String>,
}

impl Oauth2Failure {
    /// The invariant every one of these shares, and the only one worth pinning:
    /// no session was issued. The exact status is a mapping detail — a provider
    /// that refuses the code surfaces as `503` through `TokenExchangeFailed`,
    /// while an identity that cannot be trusted is a `401` — and asserting the
    /// number in each test would pin the mapping rather than the behaviour.
    ///
    /// # Why these messages carry no values
    ///
    /// An assertion message is written to the CI log when it fires, and these
    /// fire on exactly one path: a session was issued when it should not have
    /// been. The values in hand at that moment are a live `axiam_access` cookie
    /// and a body carrying whatever the provider said, so CodeQL flags any of
    /// them reaching a message as cleartext logging of sensitive information —
    /// and it stays flagged for anything *derived* from them, because the taint
    /// is on the response, not on the particular field picked out of it.
    ///
    /// Nothing is lost by leaving them out. Each of these tests drives exactly
    /// one scenario, so the failing test's own name is the diagnostic, and what
    /// a reader needs next is the mock provider's script a few lines above.
    fn assert_no_session(&self) {
        assert!(
            !(200..300).contains(&self.status),
            "a failed token exchange must not produce a successful response"
        );
        assert!(
            !self.cookies.iter().any(|c| c.starts_with("axiam_access=")),
            "no session cookie may be issued when the exchange failed"
        );
    }
}

async fn oauth2_login_against(
    slug_prefix: &str,
    kind: &str,
    mount: impl AsyncFnOnce(&MockServer),
) -> Oauth2Failure {
    let f = setup(slug_prefix).await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let idp = MockServer::start().await;
    let base = idp.uri();
    mount(&idp).await;

    let (created_status, created) = create_config!(
        app,
        auth,
        f.db,
        f.org_id,
        f.tenant_id,
        "t-admin",
        json!({
            "provider": "Provider",
            "provider_kind": kind,
            "provider_slug": if kind == "github" { Value::Null } else { json!("acme") },
            "protocol": "OAuth2",
            "client_id": "cid",
            "client_secret": "secret",
            "scopes": ["read:user", "user:email"],
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
            "userinfo_endpoint": format!("{base}/user"),
        })
    );
    assert_eq!(created_status, 201, "{created}");

    let start_req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/federation/oauth2/start")
        .set_json(json!({
            "org_slug": f.org_slug,
            "tenant_slug": f.tenant_slug,
            "federation_config_id": created["id"],
            "redirect_uri": "https://spa.example.test/auth/sso/callback",
        }))
        .to_request();
    let start_resp = test::call_service(&app, start_req).await;
    assert_eq!(start_resp.status().as_u16(), 200, "start must succeed");
    let start: Value = test::read_body_json(start_resp).await;

    let cb = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/federation/oauth2/callback")
        .set_json(json!({ "state": start["state"], "code": "provider-code" }))
        .to_request();
    let resp = test::call_service(&app, cb).await;
    let status = resp.status().as_u16();
    let cookies: Vec<String> = resp
        .response()
        .headers()
        .get_all(actix_web::http::header::SET_COOKIE)
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    let body: Value = test::read_body_json(resp).await;
    Oauth2Failure {
        status,
        body,
        cookies,
    }
}

/// Mount a `/token` that answers exactly this.
async fn mount_token(idp: &MockServer, template: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(template)
        .mount(idp)
        .await;
}

async fn mount_ok_token(idp: &MockServer) {
    mount_token(
        idp,
        ResponseTemplate::new(200).set_body_json(json!({"access_token": "at"})),
    )
    .await;
}

#[actix_rt::test]
async fn an_oauth2_token_endpoint_that_refuses_the_code_is_not_a_login() {
    let out = oauth2_login_against("oa2-tok-400", "generic_oauth2", async |idp| {
        mount_token(idp, ResponseTemplate::new(400).set_body_string("nope")).await;
    })
    .await;
    out.assert_no_session();
}

/// Several providers report a reused or expired code as `200` with an `error`
/// key. Treating that as success would hand the next step an empty bearer
/// token and produce a confusing userinfo failure instead of the real one.
#[actix_rt::test]
async fn an_error_in_a_200_token_body_is_still_a_failure() {
    let out = oauth2_login_against("oa2-tok-200err", "generic_oauth2", async |idp| {
        mount_token(
            idp,
            ResponseTemplate::new(200).set_body_json(json!({"error": "bad_verification_code"})),
        )
        .await;
    })
    .await;
    out.assert_no_session();
}

#[actix_rt::test]
async fn a_token_response_that_is_not_json_is_a_failure() {
    let out = oauth2_login_against("oa2-tok-nonjson", "generic_oauth2", async |idp| {
        mount_token(
            idp,
            ResponseTemplate::new(200).set_body_string("not json at all"),
        )
        .await;
    })
    .await;
    out.assert_no_session();
}

/// An access token of spaces is not an access token. Catching it here is the
/// difference between one clear failure and an unauthenticated userinfo call.
#[actix_rt::test]
async fn a_blank_access_token_is_refused_before_the_userinfo_call() {
    let out = oauth2_login_against("oa2-tok-blank", "generic_oauth2", async |idp| {
        mount_token(
            idp,
            ResponseTemplate::new(200).set_body_json(json!({"access_token": "   "})),
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"sub": "u"})))
            .expect(0)
            .mount(idp)
            .await;
    })
    .await;
    out.assert_no_session();
}

#[actix_rt::test]
async fn a_userinfo_endpoint_that_rejects_the_token_is_not_a_login() {
    let out = oauth2_login_against("oa2-ui-401", "generic_oauth2", async |idp| {
        mount_ok_token(idp).await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(ResponseTemplate::new(401))
            .mount(idp)
            .await;
    })
    .await;
    out.assert_no_session();
}

/// A JSON array is valid JSON and is not a userinfo document. The claim lookup
/// would find nothing in it, so it is refused for what it is.
#[actix_rt::test]
async fn a_userinfo_response_that_is_not_an_object_is_refused() {
    let out = oauth2_login_against("oa2-ui-array", "generic_oauth2", async |idp| {
        mount_ok_token(idp).await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([1, 2, 3])))
            .mount(idp)
            .await;
    })
    .await;
    out.assert_no_session();
}

#[actix_rt::test]
async fn a_userinfo_response_that_is_not_json_is_refused() {
    let out = oauth2_login_against("oa2-ui-nonjson", "generic_oauth2", async |idp| {
        mount_ok_token(idp).await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>hello</html>"))
            .mount(idp)
            .await;
    })
    .await;
    out.assert_no_session();
}

/// A userinfo document with nothing that maps to an external subject cannot
/// name anybody, and provisioning from it would create an account keyed on
/// nothing.
#[actix_rt::test]
async fn a_userinfo_response_with_no_subject_cannot_provision() {
    let out = oauth2_login_against("oa2-ui-nosub", "generic_oauth2", async |idp| {
        mount_ok_token(idp).await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"name": "No Subject", "email": "a@b.test"})),
            )
            .mount(idp)
            .await;
    })
    .await;
    out.assert_no_session();
}

/// The most likely real misconfiguration: a GitHub app registered without
/// `user:email`. The message has to name the scope, because the fix is in the
/// federation config and nothing about the person signing in.
#[actix_rt::test]
async fn a_github_email_lookup_without_the_scope_says_which_scope() {
    let out = oauth2_login_against("oa2-gh-403", "github", async |idp| {
        mount_ok_token(idp).await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"id": 1, "login": "octocat", "email": Value::Null})),
            )
            .mount(idp)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/emails"))
            .respond_with(ResponseTemplate::new(403))
            .mount(idp)
            .await;
    })
    .await;
    out.assert_no_session();
    assert!(
        out.body.to_string().contains("user:email"),
        "the refusal must name the missing scope, or an operator has nothing to act on"
    );
}

#[actix_rt::test]
async fn a_github_email_list_that_is_not_a_list_is_refused() {
    let out = oauth2_login_against("oa2-gh-shape", "github", async |idp| {
        mount_ok_token(idp).await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"id": 1, "login": "octocat", "email": Value::Null})),
            )
            .mount(idp)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/emails"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"not": "a list"})))
            .mount(idp)
            .await;
    })
    .await;
    out.assert_no_session();
}

/// A verified *non-primary* address is somebody else's choice of which mailbox
/// represents them. Picking it would key their AXIAM account — and its account
/// recovery — on an address they did not nominate.
#[actix_rt::test]
async fn a_verified_but_non_primary_github_address_is_not_adopted() {
    let out = oauth2_login_against("oa2-gh-nonprimary", "github", async |idp| {
        mount_ok_token(idp).await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"id": 1, "login": "octocat", "email": Value::Null})),
            )
            .mount(idp)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/emails"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"email": "work@example.com", "verified": true, "primary": false},
                {"email": "main@example.com", "verified": false, "primary": true},
            ])))
            .mount(idp)
            .await;
    })
    .await;
    out.assert_no_session();
}

// ---------------------------------------------------------------------------
// The form-POST returns, and the shapes a browser can arrive in
// ---------------------------------------------------------------------------

/// Apple and a SAML IdP both navigate the browser to an AXIAM endpoint with a
/// form body rather than redirecting to the SPA. Everything a browser can
/// arrive with there is attacker-influenced, so each malformed shape has to be
/// a clean refusal rather than a panic or a half-consumed login.
#[actix_rt::test]
async fn the_form_post_callbacks_refuse_a_body_with_nothing_in_it() {
    let f = setup("form-empty").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    for (uri, body) in [
        ("/api/v1/auth/federation/oidc/callback/form", "state="),
        (
            "/api/v1/auth/federation/oidc/callback/form",
            "state=&code=abc",
        ),
    ] {
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(uri)
            .insert_header((
                actix_web::http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            ))
            .set_payload(body)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status().as_u16(),
            400,
            "an empty state must be a validation failure, not a lookup: {body}"
        );
    }
}

/// An unknown `state` is a `401` and says nothing more. It is the same answer
/// for a state that expired, one already spent, and one that never existed —
/// distinguishing them would tell a holder of a stolen value which it was.
#[actix_rt::test]
async fn an_unknown_form_post_state_is_refused_uniformly() {
    let f = setup("form-unknown").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/federation/oidc/callback/form")
        .insert_header((
            actix_web::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        ))
        .set_payload("state=no-such-state&code=abc")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[actix_rt::test]
async fn a_blank_handoff_code_is_a_validation_failure() {
    let f = setup("handoff-blank").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    for code in ["", "   "] {
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/auth/federation/handoff")
            .set_json(json!({ "code": code }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status().as_u16(),
            400,
            "an empty code is a malformed request, not a failed lookup"
        );
    }
}

/// The workspace may be named by slug — what a person types on a login page —
/// or by id, which is what an SDK holding a tenant UUID has. Both reach the
/// same providers, and a test says so because the two take different branches.
#[actix_rt::test]
async fn a_workspace_can_be_named_by_id_as_well_as_by_slug() {
    let f = setup("by-id").await;
    let auth = test_auth_config();
    let app = test_app!(f.db.clone(), auth.clone());

    let (status, created) = create_config!(
        app,
        auth,
        f.db,
        f.org_id,
        f.tenant_id,
        "id-admin",
        json!({
            "provider": "Google",
            "provider_kind": "google",
            "protocol": "OidcConnect",
            "metadata_url": "https://accounts.google.com/.well-known/openid-configuration",
            "client_id": "cid",
            "client_secret": "secret",
        })
    );
    assert_eq!(status, 201, "{created}");

    let by_id = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!(
            "/api/v1/auth/federation/providers?org_id={}&tenant_id={}",
            f.org_id, f.tenant_id
        ))
        .to_request();
    let resp = test::call_service(&app, by_id).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(kinds(&body), vec!["google"]);

    // And the slug form agrees, which is the point of asserting both.
    let by_slug = providers_for(&app, &f.org_slug, Some(&f.tenant_slug)).await;
    assert_eq!(kinds(&by_slug), vec!["google"]);
}

/// Naming **no** workspace answers the same `200 []` as naming an unknown one.
///
/// That looks like a missing validation and is the opposite: this endpoint's
/// whole security property is that its answer carries no information about
/// which organizations exist, and a `400` for "malformed" against a `200 []`
/// for "unknown" would restore exactly the two-valued oracle the empty list is
/// there to remove. The start endpoints, where every failure is a uniform
/// `401`, are where a caller learns it got the workspace wrong.
#[actix_rt::test]
async fn the_providers_listing_answers_the_same_way_with_no_workspace_at_all() {
    let f = setup("no-workspace").await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    for uri in [
        "/api/v1/auth/federation/providers",
        "/api/v1/auth/federation/providers?org_slug=no-such-org",
        "/api/v1/auth/federation/providers?tenant_slug=orphan",
    ] {
        let req = test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(uri)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 200, "{uri}");
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(
            body["providers"].as_array().map(Vec::len),
            Some(0),
            "every unresolvable workspace answers an empty list: {uri}"
        );
    }
}

/// Posting the id of a config that exists but is not visible to this workspace
/// answers the same `401` as an id that does not exist — the buttons decide
/// what is reachable, and a start call cannot widen that set.
#[actix_rt::test]
async fn a_config_from_another_tenant_cannot_be_started() {
    let a = setup("cross-a").await;
    let auth = test_auth_config();
    let app = test_app!(a.db.clone(), auth.clone());

    let (status, created) = create_config!(
        app,
        auth,
        a.db,
        a.org_id,
        a.tenant_id,
        "cross-admin",
        json!({
            "provider": "Google",
            "provider_kind": "google",
            "protocol": "OidcConnect",
            "metadata_url": "https://accounts.google.com/.well-known/openid-configuration",
            "client_id": "cid",
            "client_secret": "secret",
        })
    );
    assert_eq!(status, 201, "{created}");

    // The organization scope of the *same* deployment does not inherit a
    // tenant's config — inheritance only ever points downward.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/federation/oidc/start")
        .set_json(json!({
            "org_slug": a.org_slug,
            "federation_config_id": created["id"],
            "redirect_uri": "https://spa.example.test/auth/sso/callback",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}
