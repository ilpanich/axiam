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
use axiam_core::models::oauth2_client::{
    AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateDeviceGrant, CreateOAuth2Client,
    DeviceGrantStatus,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
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
            kind: TenantKind::Standard,
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

    // A television: public (`token_endpoint_auth_method: none`), the client
    // RFC 8628 was written for and the shape every SDK's device flow drives.
    let (client_id, _) = create_device_client(
        &db,
        tenant.id,
        "living-room-tv",
        ClientAuthMethod::None,
        |_| {},
    )
    .await;

    Fixture {
        db,
        auth: test_auth_config(),
        tenant_id: tenant.id,
        org_id: org.id,
        user_id: user.id,
        client_id,
    }
}

/// Register a client for the device grant directly in the store, as `name`,
/// authenticating by `method`; `edit` adjusts the row before it is written
/// (binding flags, profile, keys). Returns `(client_id, client_secret)`.
async fn create_device_client(
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
    name: &str,
    method: ClientAuthMethod,
    edit: impl FnOnce(&mut CreateOAuth2Client),
) -> (String, String) {
    let mut input = CreateOAuth2Client {
        tenant_id,
        name: name.into(),
        redirect_uris: vec![],
        grant_types: vec![DEVICE_CODE_GRANT_TYPE.into()],
        scopes: vec!["openid".into()],
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        require_par: false,
        profile: ClientProfile::Standard,
        token_endpoint_auth_method: method,
        tls_client_auth_subject_dn: None,
        tls_client_auth_san_dns: None,
        tls_client_auth_san_uri: None,
        self_signed_tls_client_auth_thumbprints: vec![],
        tls_client_certificate_bound_access_tokens: false,
        jwks: None,
        jwks_uri: None,
        dpop_bound_access_tokens: false,
        dpop_require_nonce: false,
        authn_request_params: AuthnRequestParamsMode::Ignore,
        browser_sso: false,
        allowed_resources: Vec::new(),
        managed_by: axiam_core::models::oauth2_client::ManagedBy::Admin,
        ciba: Default::default(),
    };
    edit(&mut input);
    let (client, secret) = SurrealOAuth2ClientRepository::new(db.clone())
        .create(input)
        .await
        .unwrap();
    (client.client_id, secret)
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

/// [`test_app!`] over a state the test has adjusted (the `private_key_jwt`
/// verifier `axiam-server` wires, for the FAPI test).
macro_rules! test_app_with_state {
    ($f:expr, $state:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($f.auth.clone()))
                .app_data(web::Data::new($state))
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
    seed_grant_for(f, &f.client_id, status, expires_in_secs, interval_secs).await
}

/// As [`seed_grant_with_interval`], for a client other than the fixture's.
async fn seed_grant_for(
    f: &Fixture,
    client_id: &str,
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
        client_id: client_id.to_owned(),
        device_code_hash: hash_device_code(&device_code),
        user_code: user_code.clone(),
        scopes: vec!["openid".into()],
        expires_at: Utc::now() + Duration::seconds(expires_in_secs),
        interval_secs,
        resource: None,
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

/// The form body of a device's poll: the grant, the device code and — RFC
/// 8628 §3.4, required since #635 — the client it was issued to.
fn poll_body(client_id: &str, device_code: &str) -> String {
    format!(
        "grant_type={}&device_code={device_code}&client_id={client_id}",
        urlencoding(DEVICE_CODE_GRANT_TYPE)
    )
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
        format!(
            "grant_type={}&client_id={}",
            urlencoding(DEVICE_CODE_GRANT_TYPE),
            f.client_id
        )
    );
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_request");
}

#[actix_web::test]
async fn polling_a_pending_grant_answers_authorization_pending() {
    let f = setup().await;
    let app = test_app!(f);
    let (device_code, _) = seed_grant(&f, DeviceGrantStatus::Pending, 600).await;

    let (status, body) = post_token!(app, f.tenant_id, poll_body(&f.client_id, &device_code));
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

    let (status, body) = post_token!(app, f.tenant_id, poll_body(&f.client_id, &device_code));
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

    let (status, body) = post_token!(app, f.tenant_id, poll_body(&f.client_id, &device_code));
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
        poll_body(&f.client_id, "nothing-like-a-real-code")
    );
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_grant");
}

#[actix_web::test]
async fn an_approved_grant_mints_tokens_exactly_once() {
    let f = setup().await;
    let app = test_app!(f);
    let (device_code, _) = seed_grant_with_interval(&f, DeviceGrantStatus::Approved, 600, 0).await;

    let body_str = poll_body(&f.client_id, &device_code);
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

/// Rows in `oauth2_refresh_token`: "nothing minted" is asserted against the
/// store, not only against the response body.
async fn refresh_token_rows(f: &Fixture) -> u64 {
    use surrealdb::types::SurrealValue;

    #[derive(SurrealValue)]
    struct CountRow {
        total: u64,
    }
    let mut res =
        f.db.query("SELECT count() AS total FROM oauth2_refresh_token GROUP ALL")
            .await
            .unwrap();
    let rows: Vec<CountRow> = res.take(0).unwrap();
    rows.first().map(|r| r.total).unwrap_or(0)
}

/// Approve a device grant, let `change` happen to the approving user, then
/// poll twice. R1W1-06 / #604: the account is asked `account_may_act` and
/// the lockout question (CIBA's `user_may_be_subject`) after the approval is
/// spent, so a user who stopped being a valid subject between approval and
/// the device's next poll gets `invalid_grant`, no access token and no
/// refresh-token row, and the grant stays consumed.
async fn assert_redemption_refused_after<F, Fut>(change: F)
where
    F: FnOnce(SurrealUserRepository<TestDb>, Uuid, Uuid) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let f = setup().await;
    let app = test_app!(f);
    let (device_code, _) = seed_grant_with_interval(&f, DeviceGrantStatus::Approved, 600, 0).await;
    change(
        SurrealUserRepository::new(f.db.clone()),
        f.tenant_id,
        f.user_id,
    )
    .await;

    let body_str = poll_body(&f.client_id, &device_code);
    let (status, body) = post_token!(app, f.tenant_id, body_str);
    assert_eq!(status, 400, "poll after the change returned {body:?}");
    assert_eq!(body["error"], "invalid_grant", "{body:?}");
    assert!(body.get("access_token").is_none(), "minted: {body:?}");
    assert!(body.get("refresh_token").is_none(), "minted: {body:?}");
    assert_eq!(
        refresh_token_rows(&f).await,
        0,
        "a refused redemption must leave no refresh-token row"
    );

    // The approval is spent: the grant is consumed, so a further poll is
    // refused as a used code and still mints nothing.
    let stored = SurrealDeviceGrantRepository::new(f.db.clone())
        .get_by_device_code_hash(f.tenant_id, &hash_device_code(&device_code))
        .await
        .unwrap()
        .expect("the grant row survives");
    assert_eq!(stored.status, DeviceGrantStatus::Redeemed);
    let (status2, body2) = post_token!(app, f.tenant_id, body_str);
    assert_eq!(status2, 400, "second poll returned {body2:?}");
    // `slow_down` is as good an answer as `invalid_grant` here: interval
    // enforcement runs before the grant's state is read (see
    // `an_approved_grant_mints_tokens_exactly_once`). The `Redeemed` status
    // above is what proves consumption; this proves nothing was minted.
    assert!(
        matches!(
            body2["error"].as_str(),
            Some("invalid_grant") | Some("slow_down")
        ),
        "unexpected refusal for a consumed code: {body2:?}"
    );
    assert!(body2.get("access_token").is_none(), "minted: {body2:?}");
    assert_eq!(refresh_token_rows(&f).await, 0);
}

/// Approve, suspend, poll: `invalid_grant`, nothing minted.
#[actix_web::test]
async fn a_user_suspended_after_approval_gets_no_tokens() {
    assert_redemption_refused_after(|users, tenant_id, user_id| async move {
        users
            .update(
                tenant_id,
                user_id,
                UpdateUser {
                    status: Some(UserStatus::Inactive),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    })
    .await;
}

/// The lockout half of the predicate: brute-force lockout is read by the
/// device grant exactly as it is by CIBA (`ciba_test.rs`,
/// `a_lockout_after_approval_refuses_the_redemption`).
#[actix_web::test]
async fn a_user_locked_out_after_approval_gets_no_tokens() {
    assert_redemption_refused_after(|users, tenant_id, user_id| async move {
        users
            .update(
                tenant_id,
                user_id,
                UpdateUser {
                    locked_until: Some(Some(Utc::now() + Duration::minutes(15))),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    })
    .await;
}

/// A deleted user is a tombstone row (`status = Deleted`), which the re-read
/// returns; it must not be a subject either.
#[actix_web::test]
async fn a_user_deleted_after_approval_gets_no_tokens() {
    assert_redemption_refused_after(|users, tenant_id, user_id| async move {
        users.delete(tenant_id, user_id).await.unwrap();
    })
    .await;
}

// ---------------------------------------------------------------------------
// #635 (R101W3-01) — the grant authenticates its client
// ---------------------------------------------------------------------------

/// POST a form to `path` with extra headers: `(status, json)`.
macro_rules! post_form_with {
    ($app:expr, $path:expr, $tenant_id:expr, $body:expr, [$($header:expr),* $(,)?]) => {{
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!("{}?tenant_id={}", $path, $tenant_id))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            $(.insert_header($header))*
            .set_payload($body.to_string())
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let body = test::read_body(resp).await;
        (
            status,
            serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null),
        )
    }};
}

/// The stored grant behind a device code.
async fn stored_grant(
    f: &Fixture,
    device_code: &str,
) -> axiam_core::models::oauth2_client::DeviceGrant {
    SurrealDeviceGrantRepository::new(f.db.clone())
        .get_by_device_code_hash(f.tenant_id, &hash_device_code(device_code))
        .await
        .unwrap()
        .expect("the grant row exists")
}

/// The grant is exactly as it was approved: not spent, and no poll recorded
/// (a recorded poll is what would make the real device's next one
/// `slow_down`).
async fn assert_untouched(f: &Fixture, device_code: &str, status: DeviceGrantStatus) {
    let grant = stored_grant(f, device_code).await;
    assert_eq!(grant.status, status, "the grant's state changed");
    assert!(
        grant.last_polled_at.is_none(),
        "a refused poll was recorded against the grant"
    );
}

/// RFC 8628 §3.4: the token request names its client. A poll without
/// `client_id` is `invalid_request`, decided before the grant is read, so the
/// device that then sends it still collects its tokens.
#[actix_web::test]
async fn a_poll_without_a_client_id_is_invalid_request_and_spends_nothing() {
    let f = setup().await;
    let app = test_app!(f);
    let (device_code, _) = seed_grant(&f, DeviceGrantStatus::Approved, 600).await;

    let (status, body) = post_token!(
        app,
        f.tenant_id,
        format!(
            "grant_type={}&device_code={device_code}",
            urlencoding(DEVICE_CODE_GRANT_TYPE)
        )
    );
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_request")),
        "{body}"
    );
    assert_untouched(&f, &device_code, DeviceGrantStatus::Approved).await;

    let (status, body) = post_token!(app, f.tenant_id, poll_body(&f.client_id, &device_code));
    assert_eq!(status, 200, "{body}");
}

/// A confidential client's device grant needs the client's secret at both
/// endpoints (RFC 8628 §3.1 and §3.4 → RFC 6749 §3.2.1). Without it, or with
/// a wrong one, the start is refused and the poll is refused **before the
/// grant is touched**: the approval is neither spent nor slowed, and the
/// client holding its secret then redeems it. An unknown client and a wrong
/// secret get one answer.
#[actix_web::test]
async fn a_confidential_clients_device_grant_needs_its_secret_at_the_poll() {
    let f = setup().await;
    let app = test_app!(f);
    let (client_id, secret) = create_device_client(
        &f.db,
        f.tenant_id,
        "kiosk",
        ClientAuthMethod::ClientSecretPost,
        |_| {},
    )
    .await;

    // The start: refused without the secret and with a wrong one; served with
    // it.
    for credential in [String::new(), "&client_secret=wrong".to_owned()] {
        let (status, body) = post_form_with!(
            app,
            "/oauth2/device_authorization",
            f.tenant_id,
            format!("client_id={client_id}&scope=openid{credential}"),
            []
        );
        assert_eq!(
            (status, body["error"].as_str()),
            (401, Some("invalid_client")),
            "{body}"
        );
    }
    let (status, body) = post_form_with!(
        app,
        "/oauth2/device_authorization",
        f.tenant_id,
        format!("client_id={client_id}&scope=openid&client_secret={secret}"),
        []
    );
    assert_eq!(status, 200, "{body}");
    let device_code = body["device_code"].as_str().unwrap().to_owned();
    let user_code = normalize_user_code(body["user_code"].as_str().unwrap());
    assert!(
        SurrealDeviceGrantRepository::new(f.db.clone())
            .decide(f.tenant_id, &user_code, true, f.user_id)
            .await
            .unwrap()
    );

    // The poll: the device code alone, a wrong secret and an unknown client
    // are one refusal, and none of them touches the approved grant.
    let unknown_client = poll_body("oa_nobody", &device_code) + "&client_secret=wrong";
    let mut refusals = Vec::new();
    for body in [
        poll_body(&client_id, &device_code),
        poll_body(&client_id, &device_code) + "&client_secret=wrong",
        unknown_client,
    ] {
        let (status, body) = post_token!(app, f.tenant_id, body);
        assert_eq!(status, 401, "{body}");
        assert!(body.get("access_token").is_none(), "{body}");
        refusals.push(body);
    }
    assert_eq!(
        refusals[1], refusals[2],
        "a wrong secret and an unknown client must answer alike"
    );
    assert_eq!(refusals[0]["error"], "invalid_client");
    assert_untouched(&f, &device_code, DeviceGrantStatus::Approved).await;

    let (status, body) = post_token!(
        app,
        f.tenant_id,
        poll_body(&client_id, &device_code) + &format!("&client_secret={secret}")
    );
    assert_eq!(status, 200, "{body}");
    assert!(!body["access_token"].as_str().unwrap().is_empty());
}

/// A poll naming a client other than the grant's is `invalid_grant` — the
/// answer an unknown code gets — whatever the grant's state, so a caller who
/// holds a leaked device code and a client of its own learns nothing about
/// the grant, records no poll against it and cannot redeem it. The device's
/// own poll, inside the interval the foreign one would have started, still
/// redeems.
#[actix_web::test]
async fn a_foreign_client_id_is_invalid_grant_and_leaves_the_grant_untouched() {
    let f = setup().await;
    let app = test_app!(f);
    let (other, _) = create_device_client(
        &f.db,
        f.tenant_id,
        "attacker-tv",
        ClientAuthMethod::None,
        |_| {},
    )
    .await;

    for state in [
        DeviceGrantStatus::Pending,
        DeviceGrantStatus::Denied,
        DeviceGrantStatus::Approved,
    ] {
        let (device_code, _) = seed_grant(&f, state, 600).await;
        let (status, body) = post_token!(app, f.tenant_id, poll_body(&other, &device_code));
        assert_eq!(
            (status, body["error"].as_str()),
            (400, Some("invalid_grant")),
            "{state:?}: {body}"
        );
        assert_eq!(
            body["error_description"], "unknown device code",
            "{state:?}: a foreign client is told what an unknown code is told"
        );
        assert_untouched(&f, &device_code, state).await;

        if state == DeviceGrantStatus::Approved {
            let (status, body) =
                post_token!(app, f.tenant_id, poll_body(&f.client_id, &device_code));
            assert_eq!(status, 200, "the device's own poll: {body}");
        }
    }
}

/// Removing the device grant from a client refuses a grant its user already
/// approved (`invalid_client`), without spending it; a client that is gone is
/// refused the same way. Put back, the grant redeems.
#[actix_web::test]
async fn removing_the_grant_type_refuses_an_already_approved_grant() {
    let f = setup().await;
    let app = test_app!(f);
    let (device_code, _) = seed_grant_with_interval(&f, DeviceGrantStatus::Approved, 600, 0).await;
    let set_grants = |grants: Vec<&'static str>| {
        let db = f.db.clone();
        let client_id = f.client_id.clone();
        async move {
            db.query("UPDATE oauth2_client SET grant_types = $g WHERE client_id = $c")
                .bind(("g", grants))
                .bind(("c", client_id))
                .await
                .unwrap()
                .check()
                .unwrap();
        }
    };

    set_grants(vec!["authorization_code"]).await;
    let (status, body) = post_token!(app, f.tenant_id, poll_body(&f.client_id, &device_code));
    assert_eq!(
        (status, body["error"].as_str()),
        (401, Some("invalid_client")),
        "{body}"
    );
    assert_eq!(
        stored_grant(&f, &device_code).await.status,
        DeviceGrantStatus::Approved
    );
    assert_eq!(refresh_token_rows(&f).await, 0);

    set_grants(vec![DEVICE_CODE_GRANT_TYPE]).await;
    let (status, body) = post_token!(app, f.tenant_id, poll_body(&f.client_id, &device_code));
    assert_eq!(status, 200, "{body}");
}

/// A tombstoned tenant's client gets no user code and its approved grant does
/// not redeem: the client's authentication reads the tenant, so both answer
/// the `invalid_client` every other grant answers (#641 (a), (b)), and the
/// poll no longer reaches the `server_error` its own tenant read gave.
#[actix_web::test]
async fn a_tombstoned_tenants_device_client_is_refused_at_both_endpoints() {
    let f = setup().await;
    let app = test_app!(f);
    let (device_code, _) = seed_grant_with_interval(&f, DeviceGrantStatus::Approved, 600, 0).await;
    SurrealTenantRepository::new(f.db.clone())
        .delete(f.tenant_id)
        .await
        .unwrap();

    let (status, body) = post_form_with!(
        app,
        "/oauth2/device_authorization",
        f.tenant_id,
        format!("client_id={}&scope=openid", f.client_id),
        []
    );
    assert_eq!(
        (status, body["error"].as_str()),
        (401, Some("invalid_client")),
        "{body}"
    );
    let (status, body) = post_token!(app, f.tenant_id, poll_body(&f.client_id, &device_code));
    assert_eq!(
        (status, body["error"].as_str()),
        (401, Some("invalid_client")),
        "{body}"
    );
    assert!(body.get("access_token").is_none(), "{body}");
}

/// #641 (W3.7, c): tombstoning a tenant deletes its `device_grant` rows in the
/// deletion's own transaction, as it does its CIBA requests, rather than
/// leaving them to the purge: an approved grant is a bearer for an access
/// token, and a user code is the tenant's own. Another tenant's grant stays.
#[actix_web::test]
async fn tombstoning_a_tenant_deletes_its_device_grants_and_no_other_tenants() {
    let f = setup().await;
    let (device_code, _) = seed_grant_with_interval(&f, DeviceGrantStatus::Approved, 600, 0).await;
    seed_grant_with_interval(&f, DeviceGrantStatus::Pending, 600, 5).await;
    let bystander = Uuid::new_v4();
    SurrealDeviceGrantRepository::new(f.db.clone())
        .create(CreateDeviceGrant {
            tenant_id: bystander,
            client_id: f.client_id.clone(),
            device_code_hash: hash_device_code("a-bystanders-device-code"),
            user_code: normalize_user_code(&generate_user_code()),
            scopes: vec!["openid".into()],
            expires_at: Utc::now() + Duration::seconds(600),
            interval_secs: 5,
            resource: None,
        })
        .await
        .unwrap();
    let rows = |tenant: Uuid| {
        let db = f.db.clone();
        async move {
            let mut r = db
                .query(
                    "SELECT count() AS total FROM device_grant \
                     WHERE tenant_id = $tenant GROUP ALL",
                )
                .bind(("tenant", tenant.to_string()))
                .await
                .unwrap();
            let r: Vec<axiam_db::CountRow> = r.take(0).unwrap();
            r.first().map_or(0, |r| r.total)
        }
    };
    assert_eq!(rows(f.tenant_id).await, 2);

    SurrealTenantRepository::new(f.db.clone())
        .delete(f.tenant_id)
        .await
        .unwrap();

    // Before any purge: the row is gone, so there is no grant left to redeem
    // and no user code left to approve, whatever the tenant read does.
    assert_eq!(rows(f.tenant_id).await, 0, "the tombstoned tenant's grants");
    assert_eq!(rows(bystander).await, 1, "another tenant's grant");
    let app = test_app!(f);
    let (status, body) = post_token!(app, f.tenant_id, poll_body(&f.client_id, &device_code));
    assert_eq!(
        (status, body["error"].as_str()),
        (401, Some("invalid_client")),
        "{body}"
    );
}

/// A public client that presents a credential is refused, at the start and at
/// the poll, as at every other endpoint (T21.2): its registration names none
/// to check it against.
#[actix_web::test]
async fn a_public_device_client_presenting_a_secret_is_refused() {
    let f = setup().await;
    let app = test_app!(f);
    let (device_code, _) = seed_grant_with_interval(&f, DeviceGrantStatus::Approved, 600, 0).await;

    let (status, body) = post_form_with!(
        app,
        "/oauth2/device_authorization",
        f.tenant_id,
        format!("client_id={}&client_secret=anything", f.client_id),
        []
    );
    assert_eq!(
        (status, body["error"].as_str()),
        (401, Some("invalid_client")),
        "{body}"
    );
    let (status, body) = post_token!(
        app,
        f.tenant_id,
        poll_body(&f.client_id, &device_code) + "&client_secret=anything"
    );
    assert_eq!(
        (status, body["error"].as_str()),
        (401, Some("invalid_client")),
        "{body}"
    );
    assert_untouched(&f, &device_code, DeviceGrantStatus::Approved).await;
}

/// An Ed25519 keypair, its public JWK and that JWK's RFC 7638 thumbprint.
struct ProofKey {
    encoding: jsonwebtoken::EncodingKey,
    jwk: Value,
    jkt: String,
}

fn proof_key() -> ProofKey {
    use base64::Engine;
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("generate Ed25519");
    let encoding = jsonwebtoken::EncodingKey::from_ed_pem(kp.serialize_pem().as_bytes())
        .expect("encoding key");
    let raw = kp.public_key_raw();
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw[raw.len() - 32..]);
    let jwk = serde_json::json!({ "kty": "OKP", "crv": "Ed25519", "x": x });
    let parsed: jsonwebtoken::jwk::Jwk =
        serde_json::from_value(jwk.clone()).expect("a well-formed OKP JWK");
    let jkt = axiam_oauth2::jose::jwk_thumbprint(&parsed).expect("thumbprint");
    ProofKey { encoding, jwk, jkt }
}

/// A DPoP proof for the token endpoint (RFC 9449 §4.2).
fn dpop_proof(key: &ProofKey) -> String {
    let header: jsonwebtoken::Header = serde_json::from_value(serde_json::json!({
        "typ": axiam_oauth2::dpop::DPOP_TYP,
        "alg": "EdDSA",
        "jwk": key.jwk,
    }))
    .expect("proof header");
    let claims = serde_json::json!({
        "jti": Uuid::new_v4().to_string(),
        "htm": "POST",
        "htu": "https://id.test.example/oauth2/token",
        "iat": Utc::now().timestamp(),
    });
    jsonwebtoken::encode(&header, &claims, &key.encoding).expect("sign the proof")
}

/// A client registered for DPoP-bound access tokens gets one from the device
/// grant too: `cnf.jkt` names the proof's key and the token is announced as
/// `DPoP`. Without a proof the poll is refused rather than downgraded to a
/// bearer token, and the grant is not spent.
#[actix_web::test]
async fn a_dpop_bound_clients_device_token_carries_cnf_jkt() {
    let f = setup().await;
    let app = test_app!(f);
    let (client_id, _) = create_device_client(
        &f.db,
        f.tenant_id,
        "bound-tv",
        ClientAuthMethod::None,
        |c| c.dpop_bound_access_tokens = true,
    )
    .await;
    let (device_code, _) =
        seed_grant_for(&f, &client_id, DeviceGrantStatus::Approved, 600, 0).await;

    let (status, body) = post_token!(app, f.tenant_id, poll_body(&client_id, &device_code));
    assert_eq!(
        (status, body["error"].as_str()),
        (401, Some("invalid_client")),
        "{body}"
    );
    assert_untouched(&f, &device_code, DeviceGrantStatus::Approved).await;

    let key = proof_key();
    let (status, body) = post_form_with!(
        app,
        "/oauth2/token",
        f.tenant_id,
        poll_body(&client_id, &device_code),
        [("DPoP", dpop_proof(&key))]
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["token_type"], "DPoP", "{body}");
    let claims = decode_unverified(body["access_token"].as_str().unwrap());
    assert_eq!(
        claims["cnf"]["jkt"].as_str(),
        Some(key.jkt.as_str()),
        "{claims}"
    );
}

/// An unbound client's device token is exactly what it always was: `Bearer`,
/// no `cnf`.
#[actix_web::test]
async fn an_unbound_clients_device_token_stays_a_bearer_token() {
    let f = setup().await;
    let app = test_app!(f);
    let (device_code, _) = seed_grant_with_interval(&f, DeviceGrantStatus::Approved, 600, 0).await;
    let (status, body) = post_token!(app, f.tenant_id, poll_body(&f.client_id, &device_code));
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["token_type"], "Bearer");
    let claims = decode_unverified(body["access_token"].as_str().unwrap());
    assert!(claims.get("cnf").is_none(), "{claims}");
}

const ISSUER: &str = "https://id.test.example";

/// A `private_key_jwt` client assertion for `client_id`.
fn client_assertion(key: &ProofKey, client_id: &str) -> String {
    let header: jsonwebtoken::Header =
        serde_json::from_value(serde_json::json!({ "alg": "EdDSA" })).unwrap();
    let now = Utc::now().timestamp();
    let assertion = jsonwebtoken::encode(
        &header,
        &serde_json::json!({
            "iss": client_id, "sub": client_id, "aud": ISSUER,
            "iat": now, "exp": now + 60, "jti": Uuid::new_v4().to_string(),
        }),
        &key.encoding,
    )
    .unwrap();
    format!(
        "&client_assertion_type={}&client_assertion={assertion}",
        urlencoding("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
    )
}

/// FAPI 2.0: a `fapi2` device client must meet `fapi::enforce_token_request`
/// at the poll as at every other grant — strong client authentication
/// (`private_key_jwt` here), and the sender constraint its registration names
/// (a DPoP proof, refused `invalid_dpop_proof` without one, the grant not
/// spent). A `fapi2` row edited onto a shared secret is refused even with the
/// right secret.
#[actix_web::test]
async fn a_fapi2_device_client_must_meet_the_profile_at_the_poll() {
    let f = setup().await;
    let mut state = AppState::for_test(f.db.clone(), f.auth.clone());
    state.oauth2.token_service =
        state
            .oauth2
            .token_service
            .clone()
            .with_assertion_verifier(Arc::new(
                axiam_oauth2::private_key_jwt::JwksAssertionVerifier::new(
                    axiam_federation::jwks_cache::JwksCache::new(),
                    reqwest::Client::new(),
                    axiam_db::repository::SurrealProofReplayRepository::new(f.db.clone()),
                    ISSUER.into(),
                    vec![format!("{ISSUER}/oauth2/token")],
                ),
            ));
    let app = test_app_with_state!(f, state);

    let signing = proof_key();
    let jwks = serde_json::json!({ "keys": [signing.jwk.clone()] }).to_string();
    let (client_id, _) = create_device_client(
        &f.db,
        f.tenant_id,
        "fapi-terminal",
        ClientAuthMethod::PrivateKeyJwt,
        |c| {
            c.profile = ClientProfile::Fapi2;
            c.jwks = Some(jwks);
            c.dpop_bound_access_tokens = true;
        },
    )
    .await;

    // The start authenticates the assertion.
    let (status, body) = post_form_with!(
        app,
        "/oauth2/device_authorization",
        f.tenant_id,
        format!("client_id={client_id}&scope=openid"),
        []
    );
    assert_eq!(
        (status, body["error"].as_str()),
        (401, Some("invalid_client")),
        "{body}"
    );
    let (status, body) = post_form_with!(
        app,
        "/oauth2/device_authorization",
        f.tenant_id,
        format!(
            "client_id={client_id}&scope=openid{}",
            client_assertion(&signing, &client_id)
        ),
        []
    );
    assert_eq!(status, 200, "{body}");
    let device_code = body["device_code"].as_str().unwrap().to_owned();
    let user_code = normalize_user_code(body["user_code"].as_str().unwrap());
    let repo = SurrealDeviceGrantRepository::new(f.db.clone());
    assert!(
        repo.decide(f.tenant_id, &user_code, true, f.user_id)
            .await
            .unwrap()
    );

    // Authenticated, but without the DPoP proof the profile requires.
    let (status, body) = post_token!(
        app,
        f.tenant_id,
        poll_body(&client_id, &device_code) + &client_assertion(&signing, &client_id)
    );
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_dpop_proof")),
        "{body}"
    );
    assert_untouched(&f, &device_code, DeviceGrantStatus::Approved).await;

    // Everything the profile asks for: a sender-constrained token.
    let key = proof_key();
    let (status, body) = post_form_with!(
        app,
        "/oauth2/token",
        f.tenant_id,
        poll_body(&client_id, &device_code) + &client_assertion(&signing, &client_id),
        [("DPoP", dpop_proof(&key))]
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["token_type"], "DPoP");
    let claims = decode_unverified(body["access_token"].as_str().unwrap());
    assert_eq!(
        claims["cnf"]["jkt"].as_str(),
        Some(key.jkt.as_str()),
        "{claims}"
    );

    // A `fapi2` row on a shared secret — which registration validation never
    // admits — is refused at the poll even with its secret and a proof.
    let (edited, secret) = create_device_client(
        &f.db,
        f.tenant_id,
        "edited-terminal",
        ClientAuthMethod::ClientSecretPost,
        |c| {
            c.profile = ClientProfile::Fapi2;
            c.dpop_bound_access_tokens = true;
        },
    )
    .await;
    let (device_code, _) = seed_grant_for(&f, &edited, DeviceGrantStatus::Approved, 600, 0).await;
    let (status, body) = post_form_with!(
        app,
        "/oauth2/token",
        f.tenant_id,
        poll_body(&edited, &device_code) + &format!("&client_secret={secret}"),
        [("DPoP", dpop_proof(&key))]
    );
    assert_eq!(
        (status, body["error"].as_str()),
        (401, Some("invalid_client")),
        "{body}"
    );
    assert_untouched(&f, &device_code, DeviceGrantStatus::Approved).await;
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
    let (status, tokens) = post_token!(app, f.tenant_id, poll_body(&f.client_id, &device_code));
    assert_eq!(status, 200, "the post-approval poll returns tokens");
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

/// A relying party that holds a user's access token — one AXIAM minted for it
/// through the authorization-code grant — starts a device authorization for a
/// device client it controls, so it knows the user code. That token is not a
/// console sign-in: it can neither read the grant nor approve or refuse it
/// (T-447, the rule the CIBA approval routes apply). The user's own console
/// sign-in still can.
#[actix_web::test]
async fn a_token_minted_for_a_client_cannot_verify_or_approve_a_device() {
    let f = setup().await;
    let app = test_app!(f);
    let console = mint_token(&f);
    let client_held = redeem_code_grant_token(&f, &app, &console).await;

    let (_, user_code) = seed_grant(&f, DeviceGrantStatus::Pending, 600).await;
    let verify = |token: &str| {
        test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!("/api/v1/device/verify?user_code={user_code}"))
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_request()
    };
    let decide = |token: &str, approved: bool| {
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/device/decide")
            .insert_header(("Authorization", format!("Bearer {token}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .set_json(serde_json::json!({"user_code": user_code, "approved": approved}))
            .to_request()
    };

    let resp = test::call_service(&app, verify(&client_held)).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "a client's token read the grant"
    );
    for approved in [true, false] {
        let resp = test::call_service(&app, decide(&client_held, approved)).await;
        assert_eq!(
            resp.status().as_u16(),
            403,
            "a client's token decided approved={approved}"
        );
    }

    // The grant is untouched: the console sign-in still finds it pending and
    // approves it.
    let body: Value = test::read_body_json(test::call_service(&app, verify(&console)).await).await;
    assert_eq!(body["found"], true);
    let body: Value =
        test::read_body_json(test::call_service(&app, decide(&console, true)).await).await;
    assert_eq!(body["ok"], true);
}

/// Register a confidential authorization-code client, authorize it with the
/// user's console sign-in and redeem the code: the access token AXIAM mints
/// for that client in the user's name.
async fn redeem_code_grant_token(
    f: &Fixture,
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    console: &str,
) -> String {
    let redirect_uri = "https://rp.example.com/callback";
    let (client, secret) = SurrealOAuth2ClientRepository::new(f.db.clone())
        .create(CreateOAuth2Client {
            tenant_id: f.tenant_id,
            name: "relying-party".into(),
            redirect_uris: vec![redirect_uri.into()],
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
            authn_request_params: AuthnRequestParamsMode::Ignore,
            browser_sso: false,
            allowed_resources: Vec::new(),
            managed_by: axiam_core::models::oauth2_client::ManagedBy::Admin,
            ciba: Default::default(),
        })
        .await
        .unwrap();

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!(
            "/oauth2/authorize?response_type=code&client_id={}&redirect_uri={redirect_uri}&scope=openid",
            client.client_id
        ))
        .insert_header(("Authorization", format!("Bearer {console}")))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 302, "authorize must redirect");
    let location = resp.headers().get("Location").unwrap().to_str().unwrap();
    let code = url::Url::parse(location)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .expect("a code in the redirect");

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={}", f.tenant_id))
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .set_payload(format!(
            "grant_type=authorization_code&code={code}&redirect_uri={redirect_uri}\
             &client_id={}&client_secret={secret}",
            client.client_id
        ))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "the code redeems");
    let body: Value = test::read_body_json(resp).await;
    let token = body["access_token"].as_str().unwrap().to_owned();
    assert_eq!(
        decode_unverified(&token)["client_id"],
        client.client_id,
        "the token is the relying party's"
    );
    token
}

fn decode_unverified(jwt: &str) -> Value {
    use base64::Engine;
    let payload = jwt.split('.').nth(1).expect("a JWT has a payload");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
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

// ---------------------------------------------------------------------------
// The public-client bucket behind a reverse proxy (T21.2, R110W3-01)
// ---------------------------------------------------------------------------

/// The public-client bucket's allowance in these tests. The route limiters
/// keep the shipped `token_per_min` (they are built from
/// `RateLimitConfig::default()` in [`test_app_with_state!`]), so a `429` below
/// can only be the handler's bucket.
const PUBLIC_BUCKET_PER_MIN: u32 = 3;

/// A forwarded address the flood comes from, and another a device sits at.
/// Both reach the server through the same reverse proxy, [`TEST_PEER`].
const ADDRESS_A: &str = "198.51.100.9";
const ADDRESS_B: &str = "203.0.113.7";

/// An app whose handler-side `token_per_min` is [`PUBLIC_BUCKET_PER_MIN`].
macro_rules! public_bucket_app {
    ($f:expr) => {{
        let mut state = AppState::for_test($f.db.clone(), $f.auth.clone());
        state.rate_limit_cfg.token_per_min = PUBLIC_BUCKET_PER_MIN;
        test_app_with_state!($f, state)
    }};
}

/// As [`post_token!`], through the proxy at [`TEST_PEER`], which appended
/// `xff` (`X-Forwarded-For`, exactly as received by the server).
macro_rules! post_token_via_proxy {
    ($app:expr, $tenant_id:expr, $body:expr, $xff:expr) => {{
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!("/oauth2/token?tenant_id={}", $tenant_id))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .insert_header(("X-Forwarded-For", $xff))
            .set_payload($body.to_string())
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let body: Value = test::read_body_json(resp).await;
        (status, body)
    }};
}

/// A token request naming the fixture's public client and carrying no
/// credential: what an unauthenticated caller can send for any public client.
fn credential_less_body(client_id: &str) -> String {
    format!("grant_type=authorization_code&code=guess&code_verifier=guess&client_id={client_id}")
}

/// T21.2: a credential-less flood from one address meets `429 slow_down`
/// once it has spent the public-client bucket, still, behind a proxy.
#[actix_web::test]
async fn a_credential_less_flood_from_one_address_meets_slow_down() {
    let f = setup().await;
    let app = public_bucket_app!(f);
    for _ in 0..PUBLIC_BUCKET_PER_MIN {
        let (status, _) = post_token_via_proxy!(
            app,
            f.tenant_id,
            credential_less_body(&f.client_id),
            ADDRESS_A
        );
        assert_eq!(status, 400);
    }
    let (status, body) = post_token_via_proxy!(
        app,
        f.tenant_id,
        credential_less_body(&f.client_id),
        ADDRESS_A
    );
    assert_eq!((status, body["error"].as_str()), (429, Some("slow_down")));
}

/// R110W3-01: behind one proxy, an address that fills the public client's
/// bucket fills its own bucket only — another address's device poll and code
/// exchange for the same client are answered by their grants, not `429`.
#[actix_web::test]
async fn a_flood_from_one_address_does_not_slow_down_another_addresss_device() {
    let f = setup().await;
    let app = public_bucket_app!(f);
    for _ in 0..=PUBLIC_BUCKET_PER_MIN {
        post_token_via_proxy!(
            app,
            f.tenant_id,
            credential_less_body(&f.client_id),
            ADDRESS_A
        );
    }
    let (status, body) = post_token_via_proxy!(
        app,
        f.tenant_id,
        credential_less_body(&f.client_id),
        ADDRESS_A
    );
    assert_eq!(
        (status, body["error"].as_str()),
        (429, Some("slow_down")),
        "the flooding address is slowed down"
    );

    let (device_code, _) = seed_grant(&f, DeviceGrantStatus::Pending, 600).await;
    let (status, body) = post_token_via_proxy!(
        app,
        f.tenant_id,
        poll_body(&f.client_id, &device_code),
        ADDRESS_B
    );
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("authorization_pending")),
        "the device at another address polls through"
    );
    let (status, body) = post_token_via_proxy!(
        app,
        f.tenant_id,
        credential_less_body(&f.client_id),
        ADDRESS_B
    );
    assert_ne!(
        status, 429,
        "a code exchange from another address reaches its grant: {body}"
    );
}

/// R110W3-01: under the shipped `trusted_hops = 0`, an `X-Forwarded-For`
/// entry the caller wrote itself — to the left of the one the proxy appended —
/// does not choose the bucket. Naming the device's address does not charge
/// the flood to it.
#[actix_web::test]
async fn a_forged_forwarded_entry_does_not_charge_another_addresss_bucket() {
    let f = setup().await;
    let app = public_bucket_app!(f);
    let forged = format!("{ADDRESS_B}, {ADDRESS_A}");
    for _ in 0..PUBLIC_BUCKET_PER_MIN {
        let (status, _) = post_token_via_proxy!(
            app,
            f.tenant_id,
            credential_less_body(&f.client_id),
            forged.as_str()
        );
        assert_eq!(status, 400);
    }

    let (device_code, _) = seed_grant(&f, DeviceGrantStatus::Pending, 600).await;
    let (status, body) = post_token_via_proxy!(
        app,
        f.tenant_id,
        poll_body(&f.client_id, &device_code),
        ADDRESS_B
    );
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("authorization_pending")),
        "the device whose address was forged polls through"
    );
    let (status, body) = post_token_via_proxy!(
        app,
        f.tenant_id,
        credential_less_body(&f.client_id),
        ADDRESS_A
    );
    assert_eq!(
        (status, body["error"].as_str()),
        (429, Some("slow_down")),
        "the forged requests were charged to the address that sent them"
    );
}
