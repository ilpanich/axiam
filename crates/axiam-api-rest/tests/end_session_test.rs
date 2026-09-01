//! Integration tests for OIDC RP-Initiated Logout and Back-Channel Logout (B5).
//!
//! Logout-token shape and the redirect allow-list arithmetic are unit-tested
//! in `axiam-oauth2`; target selection is unit-tested in
//! `axiam_api_rest::backchannel_logout`. What this file exercises is what only
//! exists once the endpoint is mounted: that `/oauth2/end_session` is routed
//! and public, that it ends the session named by a *signed* hint and no other,
//! that the redirect allow-list is honoured end to end, and that participation
//! is recorded by the authorize endpoint so the fan-out has something to
//! iterate.
//!
//! Every test is named after the thing it stops.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token, issue_id_token};
use axiam_core::models::oauth2_client::CreateOAuth2Client;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::CreateSession;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OAuth2ClientRepository, OrganizationRepository, SessionClientRepository, SessionRepository,
    TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOAuth2ClientRepository, SurrealOrganizationRepository, SurrealSessionClientRepository,
    SurrealSessionRepository, SurrealTenantRepository, SurrealUserRepository,
};
use chrono::{Duration, Utc};
use std::net::SocketAddr;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow
const TEST_PEER: &str = "127.0.0.1:34567";
const POST_LOGOUT_URI: &str = "https://rp.test.example/signed-out";

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
        sso_spa_origins: Vec::new(),
        ..AuthConfig::default()
    }
}

struct Fixture {
    db: Surreal<TestDb>,
    auth: AuthConfig,
    tenant_id: Uuid,
    org_id: Uuid,
    user_id: Uuid,
    client_id: String,
    /// Registered with no `post_logout_redirect_uris`.
    bare_client_id: String,
}

async fn setup() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Logout Org".into(),
            slug: "org-logout".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Logout Tenant".into(),
            slug: "tenant-logout".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "logout-user".into(),
            email: "logout-user@example.com".into(),
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
    let (client, _) = client_repo
        .create(CreateOAuth2Client {
            tenant_id: tenant.id,
            name: "web-rp".into(),
            redirect_uris: vec!["https://rp.test.example/callback".into()],
            grant_types: vec!["authorization_code".into()],
            scopes: vec!["openid".into()],
            post_logout_redirect_uris: vec![POST_LOGOUT_URI.into()],
            backchannel_logout_uri: Some("https://rp.test.example/backchannel".into()),
            require_par: false,
            profile: axiam_core::models::oauth2_client::ClientProfile::Standard,
            token_endpoint_auth_method:
                axiam_core::models::oauth2_client::ClientAuthMethod::ClientSecretPost,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: vec![],
            tls_client_certificate_bound_access_tokens: false,
            jwks: None,
            jwks_uri: None,
            dpop_bound_access_tokens: false,
            dpop_require_nonce: false,
        })
        .await
        .unwrap();
    let (bare, _) = client_repo
        .create(CreateOAuth2Client {
            tenant_id: tenant.id,
            name: "bare-rp".into(),
            redirect_uris: vec!["https://bare.test.example/callback".into()],
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
            jwks: None,
            jwks_uri: None,
            dpop_bound_access_tokens: false,
            dpop_require_nonce: false,
        })
        .await
        .unwrap();

    Fixture {
        db,
        auth: test_auth_config(),
        tenant_id: tenant.id,
        org_id: org.id,
        user_id: user.id,
        client_id: client.client_id,
        bare_client_id: bare.client_id,
    }
}

/// Create a live session and return its id.
async fn new_session(f: &Fixture) -> Uuid {
    SurrealSessionRepository::new(f.db.clone())
        .create(CreateSession {
            tenant_id: f.tenant_id,
            user_id: f.user_id,
            token_hash: Uuid::new_v4().to_string(),
            ip_address: None,
            user_agent: None,
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .unwrap()
        .id
}

fn id_token_for(f: &Fixture, client_id: &str, session_id: Option<Uuid>) -> String {
    issue_id_token(
        f.user_id,
        f.tenant_id,
        f.org_id,
        client_id,
        None,
        None,
        None,
        &["openid".to_string()],
        &f.auth,
        session_id,
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

/// Call `/oauth2/end_session` and return `(status, Location header)`.
macro_rules! end_session {
    ($app:expr, $f:expr, $query:expr) => {{
        let req = test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!(
                "/oauth2/end_session?tenant_id={}{}",
                $f.tenant_id, $query
            ))
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get("Location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        (status, location)
    }};
}

async fn session_is_live(f: &Fixture, session_id: Uuid) -> bool {
    SurrealSessionRepository::new(f.db.clone())
        .get_by_id(f.tenant_id, session_id)
        .await
        .is_ok()
}

// ---------------------------------------------------------------------------
// Reachability
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn end_session_is_mounted_and_public() {
    // Necessarily public: a user whose session already expired must still be
    // able to complete a logout. If this ever returns 401 the endpoint has
    // been swallowed by the authz middleware, exactly as B2's
    // /oauth2/device_authorization was.
    let f = setup().await;
    let app = test_app!(f);
    let (status, _) = end_session!(app, &f, "");
    assert_ne!(status, 401, "end_session must not require authentication");
    assert_eq!(status, 200, "no hint, no redirect: AXIAM's own page");
}

#[actix_web::test]
async fn end_session_accepts_post_as_well_as_get() {
    let f = setup().await;
    let app = test_app!(f);
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/end_session?tenant_id={}", f.tenant_id))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
}

// ---------------------------------------------------------------------------
// Session precision
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn a_signed_hint_ends_exactly_the_session_it_names() {
    // The property the whole feature rests on: a user with a phone and a
    // laptop who logs out on the laptop keeps the phone signed in.
    let f = setup().await;
    let app = test_app!(f);
    let laptop = new_session(&f).await;
    let phone = new_session(&f).await;

    let hint = id_token_for(&f, &f.client_id, Some(laptop));
    let (status, _) = end_session!(app, &f, format!("&id_token_hint={hint}"));
    assert_eq!(status, 200);

    assert!(!session_is_live(&f, laptop).await, "named session must end");
    assert!(
        session_is_live(&f, phone).await,
        "the user's other session must survive"
    );
}

#[actix_web::test]
async fn an_unverifiable_hint_ends_nothing() {
    // Without a valid signature there is nothing authenticated to act on.
    // Falling back to "end everything for the named subject" would hand a
    // denial-of-service primitive to anyone who knows a user id.
    let f = setup().await;
    let app = test_app!(f);
    let session = new_session(&f).await;

    // Signed by a different key.
    let other = test_auth_config();
    let forged = issue_id_token(
        f.user_id,
        f.tenant_id,
        f.org_id,
        &f.client_id,
        None,
        None,
        None,
        &["openid".to_string()],
        &other,
        Some(session),
    )
    .unwrap();

    let (status, _) = end_session!(app, &f, format!("&id_token_hint={forged}"));
    assert_eq!(status, 200);
    assert!(
        session_is_live(&f, session).await,
        "a forged hint must not end a session"
    );
}

#[actix_web::test]
async fn garbage_in_the_hint_is_not_an_error() {
    // Treated as an absent hint per RP-Initiated Logout 1.0 §2, not a 400:
    // the user asked to log out.
    let f = setup().await;
    let app = test_app!(f);
    let (status, _) = end_session!(app, &f, "&id_token_hint=not-a-jwt");
    assert_eq!(status, 200);
}

// ---------------------------------------------------------------------------
// Client identification
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn a_hint_and_client_id_that_disagree_are_refused() {
    // Resolving in favour of either is wrong: the signed one silently ignores
    // what the caller asked, the unsigned one lets a parameter override a
    // signature.
    let f = setup().await;
    let app = test_app!(f);
    let session = new_session(&f).await;
    let hint = id_token_for(&f, &f.client_id, Some(session));

    let (status, _) = end_session!(
        app,
        &f,
        format!("&id_token_hint={hint}&client_id={}", f.bare_client_id)
    );
    assert_eq!(status, 400);
    assert!(
        session_is_live(&f, session).await,
        "a refused request must not have ended the session"
    );
}

#[actix_web::test]
async fn a_hint_agreeing_with_client_id_is_accepted() {
    let f = setup().await;
    let app = test_app!(f);
    let session = new_session(&f).await;
    let hint = id_token_for(&f, &f.client_id, Some(session));
    let (status, _) = end_session!(
        app,
        &f,
        format!("&id_token_hint={hint}&client_id={}", f.client_id)
    );
    assert_eq!(status, 200);
    assert!(!session_is_live(&f, session).await);
}

// ---------------------------------------------------------------------------
// The redirect allow-list
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn an_allow_listed_uri_redirects_and_echoes_state() {
    let f = setup().await;
    let app = test_app!(f);
    let session = new_session(&f).await;
    let hint = id_token_for(&f, &f.client_id, Some(session));

    let (status, location) = end_session!(
        app,
        &f,
        format!(
            "&id_token_hint={hint}&post_logout_redirect_uri={}&state=abc123",
            enc(POST_LOGOUT_URI)
        )
    );
    assert_eq!(status, 302);
    let location = location.expect("Location header");
    assert!(location.starts_with(POST_LOGOUT_URI), "got {location}");
    assert!(location.contains("state=abc123"), "got {location}");
}

#[actix_web::test]
async fn a_uri_not_on_the_allow_list_still_logs_out_but_never_redirects() {
    // Two assertions, and the second is the one that matters: an open
    // redirect here would be on an unauthenticated endpoint. But refusing to
    // log the user out because their RP sent a bad parameter would be the
    // wrong failure.
    let f = setup().await;
    let app = test_app!(f);
    let session = new_session(&f).await;
    let hint = id_token_for(&f, &f.client_id, Some(session));

    let (status, location) = end_session!(
        app,
        &f,
        format!(
            "&id_token_hint={hint}&post_logout_redirect_uri={}&state=abc123",
            enc("https://attacker.example/steal")
        )
    );
    assert_eq!(status, 200, "renders AXIAM's page, does not redirect");
    assert!(location.is_none(), "no Location header, got {location:?}");
    assert!(!session_is_live(&f, session).await, "still logged out");
}

/// The three logout removal cookies must carry the same attributes as the
/// cookies they clear. A removal is a `Set-Cookie` in its own right: emitted
/// bare, it leaves an empty-valued replacement that is weaker than the value
/// it replaced, and a non-`Secure` removal cannot overwrite a `Secure` cookie
/// from an insecure origin at all. `cookie_secure` is `true` here via
/// `AuthConfig::default()`, exactly as in production.
#[actix_web::test]
async fn logout_removal_cookies_carry_the_same_flags_as_the_cookies_they_clear() {
    let f = setup().await;
    let app = test_app!(f);

    // Both branches of `end_session` clear cookies: the allow-listed redirect
    // and AXIAM's own rendered page. Neither may skip the attributes.
    for (query_suffix, expected_status) in [
        (
            format!("&post_logout_redirect_uri={}", enc(POST_LOGOUT_URI)),
            302,
        ),
        (String::new(), 200),
    ] {
        let session = new_session(&f).await;
        let hint = id_token_for(&f, &f.client_id, Some(session));
        let req = test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!(
                "/oauth2/end_session?tenant_id={}&id_token_hint={hint}{query_suffix}",
                f.tenant_id
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), expected_status);

        let set_cookies: Vec<String> = resp
            .headers()
            .get_all("Set-Cookie")
            .filter_map(|v| v.to_str().ok())
            .map(str::to_owned)
            .collect();

        for (name, http_only, path) in [
            ("axiam_access", true, "/"),
            ("axiam_refresh", true, "/api/v1/auth/refresh"),
            // D-07: the CSRF cookie is deliberately JS-readable, and its
            // removal mirrors that rather than silently hardening it.
            ("axiam_csrf", false, "/"),
        ] {
            let header = set_cookies
                .iter()
                .find(|c| c.starts_with(&format!("{name}=")))
                .unwrap_or_else(|| panic!("no Set-Cookie for {name} in {set_cookies:?}"));

            assert!(
                header.contains("Secure"),
                "{name}: missing Secure in {header}"
            );
            assert!(
                header.contains("SameSite=Strict"),
                "{name}: missing SameSite=Strict in {header}"
            );
            assert_eq!(
                header.contains("HttpOnly"),
                http_only,
                "{name}: HttpOnly must match the setter's in {header}"
            );
            assert!(
                header.contains(&format!("Path={path}")),
                "{name}: a removal on a different path does not match the cookie: {header}"
            );
            assert!(
                header.contains("Max-Age=0"),
                "{name}: removal must still expire the cookie: {header}"
            );
        }
    }
}

#[actix_web::test]
async fn a_prefix_of_an_allow_listed_uri_does_not_redirect() {
    let f = setup().await;
    let app = test_app!(f);
    let session = new_session(&f).await;
    let hint = id_token_for(&f, &f.client_id, Some(session));

    let (status, location) = end_session!(
        app,
        &f,
        format!(
            "&id_token_hint={hint}&post_logout_redirect_uri={}",
            enc(&format!("{POST_LOGOUT_URI}.attacker.example"))
        )
    );
    assert_eq!(status, 200);
    assert!(location.is_none());
}

#[actix_web::test]
async fn a_client_with_no_allow_list_never_redirects() {
    let f = setup().await;
    let app = test_app!(f);
    let session = new_session(&f).await;
    let hint = id_token_for(&f, &f.bare_client_id, Some(session));

    let (status, location) = end_session!(
        app,
        &f,
        format!(
            "&id_token_hint={hint}&post_logout_redirect_uri={}",
            enc(POST_LOGOUT_URI)
        )
    );
    assert_eq!(status, 200);
    assert!(location.is_none());
}

#[actix_web::test]
async fn state_without_a_redirect_is_not_reflected_anywhere() {
    // An RP-controlled string must not reach a page served from AXIAM's own
    // origin.
    let f = setup().await;
    let app = test_app!(f);
    let marker = "zzmarkerzz";
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!(
            "/oauth2/end_session?tenant_id={}&state={marker}",
            f.tenant_id
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body = test::read_body(resp).await;
    let body = String::from_utf8_lossy(&body);
    assert!(
        !body.contains(marker),
        "state must not be reflected: {body}"
    );
}

// ---------------------------------------------------------------------------
// Participation, which is what back-channel logout iterates
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn authorizing_records_the_client_as_a_session_participant() {
    // Without this row the fan-out has nothing to iterate and a logged-out
    // user stays signed in at the RP — the failure the feature exists to
    // prevent.
    let f = setup().await;
    let app = test_app!(f);

    // `AuthenticatedUser::session_id` is the access token's `jti`, so minting
    // the token with a real session's id is what ties the request to it.
    let session = new_session(&f).await;
    let token = issue_access_token(
        f.user_id,
        f.tenant_id,
        f.org_id,
        &["openid".to_string()],
        &f.auth,
        session.to_string(),
        AUD_USER,
    )
    .unwrap();

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!(
            "/oauth2/authorize?client_id={}&response_type=code&redirect_uri={}",
            f.client_id,
            enc("https://rp.test.example/callback")
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 302);
    // A 302 alone is not success: `build_error_redirect` also answers 302, so
    // asserting only the status would let a failed authorization pass as a
    // working one — which is exactly how a mis-named table in the migration
    // hid behind this test the first time it was written.
    let location = resp
        .headers()
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        location.contains("code=") && !location.contains("error="),
        "authorize must issue a code, got {location}"
    );

    let rows = SurrealSessionClientRepository::new(f.db.clone())
        .list_for_session(f.tenant_id, session)
        .await
        .unwrap();
    assert!(
        rows.iter().any(|r| r.client_id == f.client_id),
        "the authorizing client must be recorded as a participant, got {rows:?}"
    );
}

#[actix_web::test]
async fn ending_a_session_clears_its_participation_rows() {
    // The rows are consumed by the fan-out, then dropped — leaving them would
    // let a later logout of a recycled session id notify clients that had
    // nothing to do with it.
    let f = setup().await;
    let app = test_app!(f);
    let session = new_session(&f).await;

    SurrealSessionClientRepository::new(f.db.clone())
        .record(axiam_core::models::oauth2_client::CreateSessionClient {
            tenant_id: f.tenant_id,
            session_id: session,
            client_id: f.client_id.clone(),
            user_id: f.user_id,
        })
        .await
        .unwrap();

    let hint = id_token_for(&f, &f.client_id, Some(session));
    let (status, _) = end_session!(app, &f, format!("&id_token_hint={hint}"));
    assert_eq!(status, 200);

    let rows = SurrealSessionClientRepository::new(f.db.clone())
        .list_for_session(f.tenant_id, session)
        .await
        .unwrap();
    assert!(rows.is_empty(), "participation rows must be cleared");
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn discovery_advertises_the_logout_endpoints() {
    let f = setup().await;
    let app = test_app!(f);
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let doc: serde_json::Value = test::read_body_json(resp).await;

    assert!(
        doc["end_session_endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/oauth2/end_session")
    );
    assert_eq!(doc["backchannel_logout_supported"], true);
    // The claim that AXIAM puts `sid` in its logout tokens — which it does,
    // unconditionally. An RP reads this to know it can end one session rather
    // than every session it holds for the subject.
    assert_eq!(doc["backchannel_logout_session_supported"], true);
}
