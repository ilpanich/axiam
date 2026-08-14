//! Integration tests for RFC 9126 pushed authorization requests (B5).
//!
//! The generation and hashing arithmetic is unit-tested in `axiam-oauth2`.
//! What this file exercises is what only exists once the endpoint is mounted:
//! that `/oauth2/par` is routed and authenticates its caller, that the
//! `request_uri` it mints is single-use and short-lived, that the authorize
//! endpoint honours it, and that the two parameter channels do not mix.
//!
//! Every test is named after the thing it stops.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_core::models::oauth2_client::{CreateOAuth2Client, UpdateOAuth2Client};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OAuth2ClientRepository, OrganizationRepository, PushedAuthRequestRepository, TenantRepository,
    UserRepository,
};
use axiam_db::repository::{
    SurrealOAuth2ClientRepository, SurrealOrganizationRepository,
    SurrealPushedAuthRequestRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_oauth2::par::{REQUEST_URI_PREFIX, hash_request_uri};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow
const TEST_PEER: &str = "127.0.0.1:34567";
const REDIRECT_URI: &str = "https://rp.test.example/callback";

fn test_keypair() -> (String, String) {
    let kp =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair generation");
    (kp.serialize_pem(), kp.public_key_pem())
}

fn test_auth_config() -> AuthConfig {
    let (private_key, public_key) = test_keypair();
    AuthConfig {
        jwt_private_key_pem: private_key,
        jwt_public_key_pem: public_key,
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: "https://id.test.example".into(),
        ..AuthConfig::default()
    }
}

struct Fixture {
    db: Surreal<TestDb>,
    auth: AuthConfig,
    tenant_id: Uuid,
    org_id: Uuid,
    user_id: Uuid,
    client_uuid: Uuid,
    client_id: String,
    client_secret: String,
    /// A second registered client, for the cross-client theft test.
    other_client_id: String,
    other_client_secret: String,
}

async fn setup() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "PAR Org".into(),
            slug: "org-par".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "PAR Tenant".into(),
            slug: "tenant-par".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "par-user".into(),
            email: "par-user@example.com".into(),
            password: TEST_PASSWORD.into(),
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

    let client_repo = SurrealOAuth2ClientRepository::new(db.clone());
    let (client, secret) = client_repo
        .create(CreateOAuth2Client {
            tenant_id: tenant.id,
            name: "web-rp".into(),
            redirect_uris: vec![REDIRECT_URI.into()],
            grant_types: vec!["authorization_code".into()],
            scopes: vec!["openid".into(), "profile".into()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
            profile: axiam_core::models::oauth2_client::ClientProfile::Standard,
            token_endpoint_auth_method:
                axiam_core::models::oauth2_client::ClientAuthMethod::ClientSecretPost,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: vec![],
            tls_client_certificate_bound_access_tokens: false,
        })
        .await
        .unwrap();
    let (other, other_secret) = client_repo
        .create(CreateOAuth2Client {
            tenant_id: tenant.id,
            name: "other-rp".into(),
            redirect_uris: vec![REDIRECT_URI.into()],
            grant_types: vec!["authorization_code".into()],
            scopes: vec!["openid".into()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
            profile: axiam_core::models::oauth2_client::ClientProfile::Standard,
            token_endpoint_auth_method:
                axiam_core::models::oauth2_client::ClientAuthMethod::ClientSecretPost,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: vec![],
            tls_client_certificate_bound_access_tokens: false,
        })
        .await
        .unwrap();

    Fixture {
        db,
        auth: test_auth_config(),
        tenant_id: tenant.id,
        org_id: org.id,
        user_id: user.id,
        client_uuid: client.id,
        client_id: client.client_id,
        client_secret: secret,
        other_client_id: other.client_id,
        other_client_secret: other_secret,
    }
}

fn user_token(f: &Fixture) -> String {
    issue_access_token(
        f.user_id,
        f.tenant_id,
        f.org_id,
        &["openid".to_string()],
        &f.auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap()
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
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    };
}

fn enc(s: &str) -> String {
    s.replace(':', "%3A").replace('/', "%2F")
}

/// POST a pushed authorization request.
macro_rules! par {
    ($app:expr, $f:expr, $client_id:expr, $secret:expr, $extra:expr) => {{
        let body = format!(
            "client_id={}&client_secret={}&response_type=code&redirect_uri={}{}",
            $client_id,
            $secret,
            enc(REDIRECT_URI),
            $extra
        );
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!("/oauth2/par?tenant_id={}", $f.tenant_id))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload(body)
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let json: Value = test::read_body_json(resp).await;
        (status, json)
    }};
}

/// GET the authorize endpoint as the seeded user.
macro_rules! authorize {
    ($app:expr, $f:expr, $query:expr) => {{
        let req = test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!("/oauth2/authorize?{}", $query))
            .insert_header(("Authorization", format!("Bearer {}", user_token($f))))
            .to_request();
        let resp = test::call_service(&$app, req).await;
        resp.status().as_u16()
    }};
}

// ---------------------------------------------------------------------------
// The endpoint exists and authenticates
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn par_is_mounted_and_returns_a_prefixed_request_uri() {
    let f = setup().await;
    let app = test_app!(f);
    let (status, body) = par!(app, f, f.client_id, f.client_secret, "");

    // 201, not 200 — RFC 9126 §2.2 specifies Created.
    assert_eq!(status, 201, "body: {body}");
    let uri = body["request_uri"].as_str().expect("request_uri");
    assert!(
        uri.starts_with(REQUEST_URI_PREFIX),
        "request_uri must carry the RFC URN prefix, got {uri}"
    );
    assert!(body["expires_in"].as_i64().unwrap() > 0);
}

#[actix_web::test]
async fn par_refuses_a_wrong_client_secret() {
    let f = setup().await;
    let app = test_app!(f);
    let (status, body) = par!(app, f, f.client_id, "not-the-secret", "");
    assert_eq!(status, 401, "body: {body}");
    assert_eq!(body["error"], "invalid_client");
}

#[actix_web::test]
async fn par_refuses_an_unregistered_redirect_uri() {
    // Validated at push time, while the client is authenticated, rather than
    // deferred to authorize — so the browser never receives a request_uri
    // standing for a request that was going to fail.
    let f = setup().await;
    let app = test_app!(f);
    let body = format!(
        "client_id={}&client_secret={}&response_type=code&redirect_uri={}",
        f.client_id,
        f.client_secret,
        enc("https://attacker.example/steal")
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/par?tenant_id={}", f.tenant_id))
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .set_payload(body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

// ---------------------------------------------------------------------------
// Single use, and the storage posture behind it
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn a_request_uri_works_once_and_then_never_again() {
    // The rule the whole feature rests on: a replayable request_uri is a
    // replayable authorization request.
    let f = setup().await;
    let app = test_app!(f);
    let (_, body) = par!(app, f, f.client_id, f.client_secret, "");
    let uri = body["request_uri"].as_str().unwrap().to_string();

    let query = format!("client_id={}&request_uri={}", f.client_id, enc(&uri));
    let first = authorize!(app, &f, query);
    assert_eq!(first, 302, "first use must redirect with a code");

    let second = authorize!(app, &f, query);
    assert_eq!(second, 400, "second use of the same request_uri must fail");
}

#[actix_web::test]
async fn the_plaintext_request_uri_is_never_stored() {
    // For the 60 s it lives the request_uri is a bearer credential; a database
    // read must not hand an attacker a usable one.
    let f = setup().await;
    let app = test_app!(f);
    let (_, body) = par!(app, f, f.client_id, f.client_secret, "");
    let uri = body["request_uri"].as_str().unwrap();
    let component = uri.strip_prefix(REQUEST_URI_PREFIX).unwrap();

    let repo = SurrealPushedAuthRequestRepository::new(f.db.clone());
    // Consuming by the hash proves the stored key is the hash: if the
    // plaintext had been stored, this lookup would miss.
    let found = repo
        .consume(f.tenant_id, &hash_request_uri(uri))
        .await
        .unwrap();
    let found = found.expect("stored under the hash of the request_uri");
    assert_ne!(found.request_uri_hash, component);
    assert_eq!(found.request_uri_hash.len(), 64);
}

#[actix_web::test]
async fn an_unknown_request_uri_is_refused() {
    let f = setup().await;
    let app = test_app!(f);
    let bogus = format!("{REQUEST_URI_PREFIX}aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let query = format!("client_id={}&request_uri={}", f.client_id, enc(&bogus));
    assert_eq!(authorize!(app, &f, query), 400);
}

#[actix_web::test]
async fn a_value_without_the_urn_prefix_is_refused() {
    let f = setup().await;
    let app = test_app!(f);
    let query = format!("client_id={}&request_uri={}", f.client_id, "just-a-string");
    assert_eq!(authorize!(app, &f, query), 400);
}

// ---------------------------------------------------------------------------
// The pushed request belongs to the client that pushed it
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn another_client_cannot_spend_a_request_uri() {
    // Without this check a second client could redeem the first's pushed
    // request and receive a code minted against the first's registration.
    let f = setup().await;
    let app = test_app!(f);
    let (_, body) = par!(app, f, f.client_id, f.client_secret, "");
    let uri = body["request_uri"].as_str().unwrap().to_string();

    let query = format!("client_id={}&request_uri={}", f.other_client_id, enc(&uri));
    assert_eq!(authorize!(app, &f, query), 400);
    // The other client's secret is registered and valid — this is a
    // request_uri ownership failure, not an authentication one.
    assert!(!f.other_client_secret.is_empty());
}

// ---------------------------------------------------------------------------
// The two parameter channels do not mix
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn request_uri_combined_with_inline_params_is_refused() {
    // Merging is where parameter confusion lives: the attacker supplies the
    // inline value they want and lets the pushed copy satisfy whatever check
    // reads the other one. So both-present is an error, not a merge.
    let f = setup().await;
    let app = test_app!(f);
    let (_, body) = par!(app, f, f.client_id, f.client_secret, "");
    let uri = body["request_uri"].as_str().unwrap().to_string();

    for extra in [
        "&response_type=code",
        &format!("&redirect_uri={}", enc(REDIRECT_URI)),
        "&scope=openid",
        "&code_challenge=abc",
    ] {
        let query = format!(
            "client_id={}&request_uri={}{}",
            f.client_id,
            enc(&uri),
            extra
        );
        assert_eq!(
            authorize!(app, &f, query),
            400,
            "inline param {extra} must not be accepted alongside request_uri"
        );
    }
}

#[actix_web::test]
async fn authorize_without_request_uri_still_requires_its_parameters() {
    // The parameters became optional so a PAR request could omit them; that
    // must not make them optional for everyone else.
    let f = setup().await;
    let app = test_app!(f);
    let query = format!("client_id={}", f.client_id);
    assert_eq!(authorize!(app, &f, query), 400);
}

// ---------------------------------------------------------------------------
// require_par
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn a_require_par_client_cannot_authorize_directly() {
    let f = setup().await;
    let app = test_app!(f);
    SurrealOAuth2ClientRepository::new(f.db.clone())
        .update(
            f.tenant_id,
            f.client_uuid,
            UpdateOAuth2Client {
                require_par: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let query = format!(
        "client_id={}&response_type=code&redirect_uri={}",
        f.client_id,
        enc(REDIRECT_URI)
    );
    let status = authorize!(app, &f, query);
    // 400 and NOT 302: redirecting would bounce the user agent to a
    // redirect_uri that arrived by the very channel this setting forbids,
    // before that URI had been validated.
    assert_eq!(status, 400, "require_par refusal must not redirect");
}

#[actix_web::test]
async fn a_require_par_client_can_still_authorize_via_par() {
    let f = setup().await;
    let app = test_app!(f);
    let (_, body) = par!(app, f, f.client_id, f.client_secret, "");
    let uri = body["request_uri"].as_str().unwrap().to_string();

    SurrealOAuth2ClientRepository::new(f.db.clone())
        .update(
            f.tenant_id,
            f.client_uuid,
            UpdateOAuth2Client {
                require_par: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let query = format!("client_id={}&request_uri={}", f.client_id, enc(&uri));
    assert_eq!(authorize!(app, &f, query), 302);
}

// ---------------------------------------------------------------------------
// The pushed values are the ones that count
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn the_pushed_state_is_used_not_a_query_string_copy() {
    // `state` was the client's to choose at push time; honouring a
    // query-string copy would let the browser substitute its own.
    let f = setup().await;
    let app = test_app!(f);
    let (_, body) = par!(app, f, f.client_id, f.client_secret, "&state=pushed-state");
    let uri = body["request_uri"].as_str().unwrap().to_string();

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!(
            "/oauth2/authorize?client_id={}&request_uri={}",
            f.client_id,
            enc(&uri)
        ))
        .insert_header(("Authorization", format!("Bearer {}", user_token(&f))))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 302);
    let location = resp
        .headers()
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        location.contains("state=pushed-state"),
        "the pushed state must reach the redirect, got {location}"
    );
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn discovery_advertises_the_par_endpoint() {
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
        doc["pushed_authorization_request_endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/oauth2/par")
    );
    // The server-wide default is false: PAR is available to every client but
    // demanded of none. Per-client enforcement is not discoverable.
    assert_eq!(doc["require_pushed_authorization_requests"], false);
}
