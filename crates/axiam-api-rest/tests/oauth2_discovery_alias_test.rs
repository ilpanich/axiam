//! T21.1 — RFC 8414 well-known path is an alias of OIDC discovery.
//!
//! `GET /.well-known/oauth-authorization-server` must return the exact same
//! document as `GET /.well-known/openid-configuration`, built by the exact
//! same handler, with the same optional `?tenant_id=` — with and without it —
//! and carry the same `Cache-Control` and `Content-Type` headers. Both routes
//! are wired to `handlers::oauth2::discovery` in `server.rs`, so this test
//! proves that wiring rather than re-deriving discovery's own field-shape
//! assertions (`oidc_conformance.rs` already owns those, and I1 requires them
//! to keep passing unchanged).
//!
//! Harness is a copy of `oidc_conformance.rs` — house style (no shared util
//! module).

use actix_web::{App, test, web};
use std::net::SocketAddr;

use axiam_api_rest::RateLimitConfig;

/// Loopback peer address for test requests so the rate-limiter key extractor
/// can resolve a client IP without a real socket.
const TEST_PEER: &str = "127.0.0.1:12345";

use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{OrganizationRepository, TenantRepository};
use axiam_db::repository::{SurrealOrganizationRepository, SurrealTenantRepository};
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const OIDC_PATH: &str = "/.well-known/openid-configuration";
const RFC8414_PATH: &str = "/.well-known/oauth-authorization-server";

// ---------------------------------------------------------------------------
// Test scaffolding — mirrors oidc_conformance.rs exactly
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
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: "https://localhost".into(),
        sso_spa_origins: Vec::new(),
        ..AuthConfig::default()
    }
}

async fn setup_db() -> (Surreal<TestDb>, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org = org_repo
        .create(CreateOrganization {
            name: "Test Org".into(),
            slug: "test-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Test Tenant".into(),
            slug: "test-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, org.id, tenant.id)
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

async fn get(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    uri: &str,
) -> actix_web::dev::ServiceResponse {
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(uri)
        .to_request();
    test::call_service(app, req).await
}

// ---------------------------------------------------------------------------
// Byte-identical JSON, with and without ?tenant_id=
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn alias_is_byte_identical_without_tenant_id() {
    let (db, _org_id, _tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let oidc_resp = get(&app, OIDC_PATH).await;
    assert_eq!(oidc_resp.status().as_u16(), 200);
    let oidc_body = test::read_body(oidc_resp).await;

    let alias_resp = get(&app, RFC8414_PATH).await;
    assert_eq!(alias_resp.status().as_u16(), 200);
    let alias_body = test::read_body(alias_resp).await;

    assert_eq!(
        oidc_body, alias_body,
        "RFC 8414 path must return the byte-identical document as OIDC discovery"
    );
}

#[actix_rt::test]
async fn alias_is_byte_identical_with_tenant_id() {
    let (db, _org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let oidc_resp = get(&app, &format!("{OIDC_PATH}?tenant_id={tenant_id}")).await;
    assert_eq!(oidc_resp.status().as_u16(), 200);
    let oidc_body = test::read_body(oidc_resp).await;

    let alias_resp = get(&app, &format!("{RFC8414_PATH}?tenant_id={tenant_id}")).await;
    assert_eq!(alias_resp.status().as_u16(), 200);
    let alias_body = test::read_body(alias_resp).await;

    assert_eq!(
        oidc_body, alias_body,
        "RFC 8414 path must return the byte-identical document as OIDC discovery, \
         including the tenant_id-scoped fields"
    );

    // The tenant-scoped document must differ from the deployment-wide one (its
    // endpoints carry `?tenant_id=`, per `tenant_scoped` in
    // `axiam-oauth2/src/oidc.rs`) — otherwise this test would pass even if
    // `?tenant_id=` were silently ignored by one of the two paths.
    let deployment_wide = test::read_body(get(&app, OIDC_PATH).await).await;
    assert_ne!(
        oidc_body, deployment_wide,
        "a tenant_id-scoped document must differ from the deployment-wide one, \
         or the comparison above proves nothing"
    );
}

// ---------------------------------------------------------------------------
// Headers — Cache-Control and Content-Type identical to the OIDC path
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn alias_headers_match_oidc_discovery() {
    let (db, _org_id, _tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let oidc_resp = get(&app, OIDC_PATH).await;
    let oidc_content_type = oidc_resp
        .headers()
        .get("Content-Type")
        .cloned()
        .expect("OIDC discovery must carry a Content-Type header");
    let oidc_cache_control = oidc_resp.headers().get("Cache-Control").cloned();

    let alias_resp = get(&app, RFC8414_PATH).await;
    let alias_content_type = alias_resp
        .headers()
        .get("Content-Type")
        .cloned()
        .expect("RFC 8414 alias must carry a Content-Type header");
    let alias_cache_control = alias_resp.headers().get("Cache-Control").cloned();

    assert_eq!(oidc_content_type, alias_content_type);
    assert_eq!(
        oidc_cache_control, alias_cache_control,
        "the alias must carry the exact same Cache-Control posture as OIDC \
         discovery today, present or absent"
    );
}
