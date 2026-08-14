//! Integration tests for the Device Authorization Grant's REST surface (B2).
//!
//! The state machine itself is covered by `axiam-oauth2`'s own tests. What
//! this file exercises is the part that only exists once the endpoints are
//! mounted: that the token endpoint routes the device-code grant to the right
//! service, that every RFC 8628 §3.5 answer reaches the wire with the right
//! error code, that the verification endpoints refuse anonymous callers, and
//! that none of the three endpoints leaks which user codes exist.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_core::models::oauth2_client::{CreateDeviceGrant, CreateOAuth2Client, DeviceGrantStatus};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    DeviceGrantRepository, OAuth2ClientRepository, OrganizationRepository, TenantRepository,
    UserRepository,
};
use axiam_db::repository::{
    SurrealDeviceGrantRepository, SurrealOAuth2ClientRepository, SurrealOrganizationRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_oauth2::device::{
    DEFAULT_EXPIRES_IN_SECS, generate_user_code, hash_device_code, normalize_user_code,
};
use axiam_oauth2::device_service::DEVICE_CODE_GRANT_TYPE;
use chrono::{Duration, Utc};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow
const CSRF_TOKEN: &str = "test-csrf-token";
/// Every device endpoint sits behind a per-IP governor, and the governor's key
/// extractor fails the request outright when there is no peer address —
/// `TestRequest` supplies none by default. Same constant/pattern as
/// `auth_test.rs`.
const TEST_PEER: &str = "127.0.0.1:34567";

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
    client_id: String,
}

async fn setup() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Device Org".into(),
            slug: "org-device".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "Device Tenant".into(),
            slug: "tenant-device".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "device-user".into(),
            email: "device-user@example.com".into(),
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

    let (client, _secret) = SurrealOAuth2ClientRepository::new(db.clone())
        .create(CreateOAuth2Client {
            tenant_id: tenant.id,
            name: "living-room-tv".into(),
            redirect_uris: vec![],
            grant_types: vec![DEVICE_CODE_GRANT_TYPE.into()],
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
    }
}

fn mint_token(f: &Fixture) -> String {
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

/// Seed a grant directly, so a test can start from any state in the machine
/// without driving the whole ceremony. Returns the raw device code.
async fn seed_grant(
    f: &Fixture,
    status: DeviceGrantStatus,
    expires_in_secs: i64,
) -> (String, String) {
    seed_grant_with_interval(f, status, expires_in_secs, 5).await
}

/// As [`seed_grant`], with control over the poll interval.
///
/// `interval_secs: 0` disables RFC 8628 §3.5 poll-interval enforcement for a
/// test that needs two polls back to back. Without it the second poll is
/// answered `slow_down` — correctly, since the interval is checked *before*
/// the grant's state — which is the right product behaviour and the wrong
/// thing for a test isolating single-use redemption.
async fn seed_grant_with_interval(
    f: &Fixture,
    status: DeviceGrantStatus,
    expires_in_secs: i64,
    interval_secs: u64,
) -> (String, String) {
    let repo = SurrealDeviceGrantRepository::new(f.db.clone());
    let device_code = format!("dc-{}", Uuid::new_v4().simple());
    // Generate through the real generator rather than inventing a string. The
    // user-code alphabet is unambiguous CONSONANTS only (no vowels, no
    // digits), so a hand-written "TEST1000" survives neither the charset nor
    // normalisation.
    //
    // Two forms, exactly as `DeviceAuthorizationService::authorize` keeps
    // them: the DISPLAY form (dashed, what a human reads off a screen) is
    // returned to the caller, and the NORMALISED form is what gets stored,
    // because every lookup normalises what the user typed before querying.
    // Storing the dashed form would make every verification lookup miss.
    let user_code_display = generate_user_code();
    let user_code = normalize_user_code(&user_code_display);
    repo.create(CreateDeviceGrant {
        tenant_id: f.tenant_id,
        client_id: f.client_id.clone(),
        device_code_hash: hash_device_code(&device_code),
        user_code: user_code.clone(),
        scopes: vec!["openid".into()],
        expires_at: Utc::now() + Duration::seconds(expires_in_secs),
        interval_secs,
    })
    .await
    .unwrap();

    if status != DeviceGrantStatus::Pending {
        let approved = status == DeviceGrantStatus::Approved;
        assert!(
            repo.decide(f.tenant_id, &user_code, approved, f.user_id)
                .await
                .unwrap(),
            "seeding a {status:?} grant should transition from pending"
        );
    }
    (device_code, user_code_display)
}

/// POST a form body to the token endpoint and read back `(status, json)`.
///
/// A macro rather than a generic function: `test::init_service` returns an
/// opaque `Service` whose body type depends on the middleware stack, so
/// spelling the bound out here would break every time a wrapper is added.
macro_rules! post_token {
    ($app:expr, $tenant_id:expr, $body:expr) => {{
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!("/oauth2/token?tenant_id={}", $tenant_id))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload($body.to_string())
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let body: Value = test::read_body_json(resp).await;
        (status, body)
    }};
}

// ---------------------------------------------------------------------------
// /oauth2/device_authorization
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn device_authorization_issues_both_codes_and_a_verification_uri() {
    let f = setup().await;
    let app = test_app!(f);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!(
            "/oauth2/device_authorization?tenant_id={}",
            f.tenant_id
        ))
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .set_payload(format!("client_id={}", f.client_id))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;

    assert!(body["device_code"].as_str().unwrap().len() >= 32);
    assert!(!body["user_code"].as_str().unwrap().is_empty());
    // The verification URI must live on the issuer's own origin — a code typed
    // on a different origin from the issuer is the phishing shape.
    assert!(
        body["verification_uri"]
            .as_str()
            .unwrap()
            .starts_with("https://id.test.example/device"),
        "verification_uri was {:?}",
        body["verification_uri"]
    );
    // §3.3.1: the pre-filled variant is what turns eight typed characters
    // into a scanned QR code.
    assert!(
        body["verification_uri_complete"]
            .as_str()
            .unwrap()
            .contains(body["user_code"].as_str().unwrap())
    );
    assert_eq!(
        body["expires_in"].as_u64().unwrap(),
        DEFAULT_EXPIRES_IN_SECS
    );
    assert!(body["interval"].as_u64().unwrap() >= 1);
}

#[actix_web::test]
async fn device_authorization_rejects_an_unknown_client() {
    let f = setup().await;
    let app = test_app!(f);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!(
            "/oauth2/device_authorization?tenant_id={}",
            f.tenant_id
        ))
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .set_payload("client_id=not-a-real-client")
        .to_request();
    let resp = test::call_service(&app, req).await;
    // Without this check any string could mint pending grants and exhaust the
    // user-code space — a denial of service against every real device at once.
    assert!(
        resp.status().is_client_error(),
        "unknown client was accepted"
    );
}

// ---------------------------------------------------------------------------
// The token endpoint's device_code arm — RFC 8628 §3.5's answer table
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn polling_without_a_device_code_is_invalid_request() {
    let f = setup().await;
    let app = test_app!(f);
    let (status, body) = post_token!(
        app,
        f.tenant_id,
        format!("grant_type={}", urlencoding(DEVICE_CODE_GRANT_TYPE))
    );
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_request");
}

#[actix_web::test]
async fn polling_a_pending_grant_answers_authorization_pending() {
    let f = setup().await;
    let app = test_app!(f);
    let (device_code, _) = seed_grant(&f, DeviceGrantStatus::Pending, 600).await;

    let (status, body) = post_token!(
        app,
        f.tenant_id,
        format!(
            "grant_type={}&device_code={device_code}",
            urlencoding(DEVICE_CODE_GRANT_TYPE)
        )
    );
    // This is the NORMAL answer for most of a device flow's life, and it is
    // still an HTTP 400 with an OAuth2 error body per the RFC.
    assert_eq!(status, 400);
    assert_eq!(body["error"], "authorization_pending");
}

#[actix_web::test]
async fn polling_a_denied_grant_answers_access_denied_so_the_device_can_stop() {
    let f = setup().await;
    let app = test_app!(f);
    let (device_code, _) = seed_grant(&f, DeviceGrantStatus::Denied, 600).await;

    let (status, body) = post_token!(
        app,
        f.tenant_id,
        format!(
            "grant_type={}&device_code={device_code}",
            urlencoding(DEVICE_CODE_GRANT_TYPE)
        )
    );
    assert_eq!(status, 400);
    // Distinct from `authorization_pending` on purpose: a device that has
    // been refused should stop immediately rather than poll out the full
    // grant lifetime.
    assert_eq!(body["error"], "access_denied");
}

#[actix_web::test]
async fn polling_an_expired_grant_answers_expired_token() {
    let f = setup().await;
    let app = test_app!(f);
    let (device_code, _) = seed_grant(&f, DeviceGrantStatus::Pending, -1).await;

    let (status, body) = post_token!(
        app,
        f.tenant_id,
        format!(
            "grant_type={}&device_code={device_code}",
            urlencoding(DEVICE_CODE_GRANT_TYPE)
        )
    );
    assert_eq!(status, 400);
    assert_eq!(body["error"], "expired_token");
}

#[actix_web::test]
async fn an_unknown_device_code_is_invalid_grant() {
    let f = setup().await;
    let app = test_app!(f);
    let (status, body) = post_token!(
        app,
        f.tenant_id,
        format!(
            "grant_type={}&device_code=nothing-like-a-real-code",
            urlencoding(DEVICE_CODE_GRANT_TYPE)
        )
    );
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_grant");
}

#[actix_web::test]
async fn an_approved_grant_mints_tokens_exactly_once() {
    let f = setup().await;
    let app = test_app!(f);
    let (device_code, _) = seed_grant_with_interval(&f, DeviceGrantStatus::Approved, 600, 0).await;

    let body_str = format!(
        "grant_type={}&device_code={device_code}",
        urlencoding(DEVICE_CODE_GRANT_TYPE)
    );
    let (status, body) = post_token!(app, f.tenant_id, body_str);
    assert_eq!(status, 200, "approved poll returned {body:?}");
    assert!(!body["access_token"].as_str().unwrap().is_empty());
    assert!(!body["refresh_token"].as_str().unwrap().is_empty());
    assert_eq!(body["token_type"], "Bearer");

    // Single use: the second poll on the same code must not mint a second
    // token set from one human approval.
    //
    // The assertion is "no tokens", not a specific error code. A device that
    // polls twice in quick succession can legitimately be answered
    // `slow_down` instead of `invalid_grant` — interval enforcement runs
    // BEFORE the grant's state is examined, by design — and pinning the code
    // would make this test a function of how fast the machine ran it. What
    // must never happen is a second token set, and that is what is checked.
    let (status2, body2) = post_token!(app, f.tenant_id, body_str);
    assert_eq!(status2, 400, "second poll returned {body2:?}");
    assert!(
        body2.get("access_token").is_none(),
        "one approval minted a second token set: {body2:?}"
    );
    assert!(
        matches!(
            body2["error"].as_str(),
            Some("invalid_grant") | Some("slow_down")
        ),
        "unexpected refusal for a redeemed code: {body2:?}"
    );
}

// ---------------------------------------------------------------------------
// The verification endpoints
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn verification_endpoints_refuse_anonymous_callers() {
    let f = setup().await;
    let app = test_app!(f);

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/device/verify?user_code=ANYTHING")
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 401);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/device/decide")
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .set_json(serde_json::json!({"user_code": "ANYTHING", "approved": true}))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 401);
}

#[actix_web::test]
async fn verify_returns_the_pending_grants_client_and_scopes() {
    let f = setup().await;
    let app = test_app!(f);
    let (_, user_code) = seed_grant(&f, DeviceGrantStatus::Pending, 600).await;
    let token = mint_token(&f);

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/device/verify?user_code={user_code}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["found"], true);
    assert_eq!(body["client_id"], f.client_id);
    assert_eq!(body["scopes"][0], "openid");
}

#[actix_web::test]
async fn verify_answers_identically_for_unknown_expired_and_decided_codes() {
    let f = setup().await;
    let app = test_app!(f);
    let token = mint_token(&f);
    let (_, expired) = seed_grant(&f, DeviceGrantStatus::Pending, -1).await;
    let (_, denied) = seed_grant(&f, DeviceGrantStatus::Denied, 600).await;

    // The three failure modes must be indistinguishable. Anything else turns
    // this page into an oracle for which of the small, human-typable codes an
    // attacker is guessing are live.
    for code in [expired.as_str(), denied.as_str(), "ZZZZ9999"] {
        let req = test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!("/api/v1/device/verify?user_code={code}"))
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 200, "code {code}");
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["found"], false, "code {code} leaked its state");
        assert!(
            body.get("client_id").is_none(),
            "code {code} leaked a client"
        );
    }
}

#[actix_web::test]
async fn approving_lets_the_device_collect_its_tokens() {
    let f = setup().await;
    let app = test_app!(f);
    let (device_code, user_code) = seed_grant(&f, DeviceGrantStatus::Pending, 600).await;
    let token = mint_token(&f);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/device/decide")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .set_json(serde_json::json!({"user_code": user_code, "approved": true}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["ok"], true);

    // End to end: the poll that was answering `authorization_pending` a moment
    // ago now returns tokens.
    let (status, tokens) = post_token!(
        app,
        f.tenant_id,
        format!(
            "grant_type={}&device_code={device_code}",
            urlencoding(DEVICE_CODE_GRANT_TYPE)
        )
    );
    assert_eq!(status, 200, "post-approval poll returned {tokens:?}");
    assert!(!tokens["access_token"].as_str().unwrap().is_empty());
}

#[actix_web::test]
async fn deciding_twice_reports_failure_rather_than_overwriting() {
    let f = setup().await;
    let app = test_app!(f);
    let (_, user_code) = seed_grant(&f, DeviceGrantStatus::Pending, 600).await;
    let token = mint_token(&f);

    let decide = |approved: bool| {
        let token = token.clone();
        let user_code = user_code.clone();
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/device/decide")
            .insert_header(("Authorization", format!("Bearer {token}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .set_json(serde_json::json!({"user_code": user_code, "approved": approved}))
            .to_request()
    };

    let body: Value = test::read_body_json(test::call_service(&app, decide(false)).await).await;
    assert_eq!(body["ok"], true);
    // A refusal is final. Re-deciding must not flip it to an approval.
    let body: Value = test::read_body_json(test::call_service(&app, decide(true)).await).await;
    assert_eq!(body["ok"], false);
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn discovery_advertises_the_device_endpoint_and_grant() {
    let f = setup().await;
    let app = test_app!(f);

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;

    // A device that can read discovery is precisely the client that cannot be
    // told the URL out of band.
    assert_eq!(
        body["device_authorization_endpoint"],
        "https://id.test.example/oauth2/device_authorization"
    );
    let grants: Vec<String> =
        serde_json::from_value(body["grant_types_supported"].clone()).unwrap();
    assert!(
        grants.iter().any(|g| g == DEVICE_CODE_GRANT_TYPE),
        "discovery advertises {grants:?}, missing {DEVICE_CODE_GRANT_TYPE}"
    );
}

/// Minimal `application/x-www-form-urlencoded` escaping for the one value in
/// these tests that needs it — the grant-type URN's colons.
fn urlencoding(s: &str) -> String {
    s.replace(':', "%3A")
}
