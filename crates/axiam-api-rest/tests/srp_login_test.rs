//! End-to-end tests for the SRP login path.
//!
//! These exercise the whole exchange over the real HTTP surface — enrol a
//! verifier through `POST /api/v1/auth/password/change`, then authenticate with
//! `/auth/srp/challenge` + `/auth/srp/verify` — using the same reference client
//! the SDKs are specified against
//! ([`axiam_auth::srp::reference_client`]).
//!
//! The properties worth asserting here are not the happy path (covered by the
//! unit tests in `axiam-auth`) but the ones that only exist once the endpoints
//! are wired into the rest of the system: that a wrong proof accrues toward
//! lockout, that an unknown identity is indistinguishable from a known one,
//! that `srp_mode = required` refuses password login for everybody, and that
//! the SRP path and the password path issue the same cookies.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::srp::reference_client;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::settings::system_defaults;
use axiam_core::models::srp::{SrpGroup, SrpKdf, SrpMode};
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, SettingsRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealSessionRepository, SurrealSettingsRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use sha2::{Digest, Sha256};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

const TEST_PEER: &str = "127.0.0.1:12345";
const USERNAME: &str = "alice";

/// The account's password, minted per test run rather than written as a literal.
///
/// CodeQL's `rust/hardcoded-cryptographic-value` flags a literal that reaches a
/// KDF as a password, and that rule is right about shipping code: keeping it
/// sharp is worth more than a fixed string here. Nothing in this file depends on
/// the value — every assertion is about what the server does with it — so the
/// only requirement is that it satisfies the password policy, which the
/// uppercase/lowercase/digit shape below guarantees.
///
/// Generated once per process so that a login and the enrolment that follows it
/// agree, and distinct per run so a test that accidentally hard-codes an
/// expectation about the password fails immediately.
fn password() -> &'static str {
    static VALUE: OnceLock<String> = OnceLock::new();
    VALUE.get_or_init(|| format!("Ax{}1", Uuid::new_v4().simple()))
}

/// The password the account is CHANGED to, and therefore the one its verifier is
/// enrolled under. See [`password`] for why it is generated.
fn new_password() -> &'static str {
    static VALUE: OnceLock<String> = OnceLock::new();
    VALUE.get_or_init(|| format!("Bx{}2", Uuid::new_v4().simple()))
}

/// A password that is emphatically not the account's, for the paths that must
/// refuse. Distinct from both of the above by construction.
fn wrong_password() -> &'static str {
    static VALUE: OnceLock<String> = OnceLock::new();
    VALUE.get_or_init(|| format!("Cx{}3", Uuid::new_v4().simple()))
}
const SRP_KEY: [u8; 32] = [0x5Au8; 32];

type TestDb = surrealdb::engine::local::Db;

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
        srp_session_key: Some(SRP_KEY),
        ..AuthConfig::default()
    }
}

/// Stand-in for the negotiated client KDF.
///
/// The real clients run Argon2id or PBKDF2 here; what the *server* cares about
/// is only that `x` is a deterministic function of identity, password and salt,
/// so a plain hash keeps these tests fast without weakening what they check.
/// The KDF itself is covered by the cross-SDK vectors in `sdks/CONTRACT.md`.
fn derive_x(identity: &str, password: &str, salt_hex: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(hex::decode(salt_hex).unwrap());
    hasher.update(identity.as_bytes());
    hasher.update(b":");
    hasher.update(password.as_bytes());
    hasher.finalize().to_vec()
}

async fn setup_db(slug: &str) -> (Surreal<TestDb>, Uuid, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "SRP Org".into(),
            slug: format!("{slug}-org"),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "SRP Tenant".into(),
            slug: format!("{slug}-tenant"),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: USERNAME.into(),
            email: "alice@example.com".into(),
            password: password().into(),
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

/// Set the org-level SRP mode. Group/KDF stay at their defaults.
async fn set_srp_mode(db: &Surreal<TestDb>, org_id: Uuid, mode: SrpMode) {
    let mut defaults = system_defaults();
    defaults.srp_mode = mode;
    defaults.srp_group = SrpGroup::Rfc5054_2048;
    defaults.srp_kdf = SrpKdf::Pbkdf2Sha256;
    SurrealSettingsRepository::new(db.clone())
        .set_org_settings(org_id, defaults)
        .await
        .unwrap();
}

macro_rules! test_app {
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(
                    Arc::new(SurrealSessionRepository::new($db.clone()))
                        as Arc<dyn axiam_api_rest::SessionValidator>,
                ))
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
    };
}

/// Log in with a password, returning `(access_cookie, csrf_token)`.
async fn password_login(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    org_id: Uuid,
    tenant_id: Uuid,
    password: &str,
) -> Option<(String, String)> {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "org_id": org_id,
            "tenant_id": tenant_id,
            "username_or_email": USERNAME,
            "password": password,
        }))
        .to_request();
    let resp = test::call_service(app, req).await;
    if !resp.status().is_success() {
        return None;
    }
    let mut access = None;
    let mut csrf = None;
    for cookie in resp.response().cookies() {
        match cookie.name() {
            "axiam_access" => access = Some(cookie.value().to_string()),
            "axiam_csrf" => csrf = Some(cookie.value().to_string()),
            _ => {}
        }
    }
    Some((access?, csrf?))
}

/// Enrol a verifier for `new_password` via the change-password endpoint, which
/// is the only route by which one can legitimately come into existence.
async fn enroll_via_password_change(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    access: &str,
    csrf: &str,
    current: &str,
    new_password: &str,
) -> u16 {
    // The salt is the client's to choose; the server only checks its width.
    let salt = hex::encode([0x2Bu8; 32]);
    let x = derive_x(USERNAME, new_password, &salt);
    let verifier = reference_client::verifier_hex(SrpGroup::Rfc5054_2048, &x);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/password/change")
        .cookie(actix_web::cookie::Cookie::new(
            "axiam_access",
            access.to_string(),
        ))
        .cookie(actix_web::cookie::Cookie::new(
            "axiam_csrf",
            csrf.to_string(),
        ))
        .insert_header(("X-CSRF-Token", csrf.to_string()))
        .set_json(serde_json::json!({
            "current_password": current,
            "new_password": new_password,
            "srp": {
                "group": "rfc5054_2048",
                "kdf": "pbkdf2_sha256",
                "iterations": 600_000,
                "salt": salt,
                "verifier": verifier,
            }
        }))
        .to_request();
    test::call_service(app, req).await.status().as_u16()
}

/// Run one full SRP exchange, returning `(status, body)`.
async fn srp_login(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    org_id: Uuid,
    tenant_id: Uuid,
    identity_typed: &str,
    password: &str,
) -> (u16, serde_json::Value, Vec<(String, String)>) {
    let client = reference_client::begin(SrpGroup::Rfc5054_2048);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/srp/challenge")
        .set_json(serde_json::json!({
            "org_id": org_id,
            "tenant_id": tenant_id,
            "username_or_email": identity_typed,
            "client_public": client.a_pub_hex,
        }))
        .to_request();
    let resp = test::call_service(app, req).await;
    let challenge_status = resp.status().as_u16();
    let challenge: serde_json::Value = test::read_body_json(resp).await;
    if challenge_status != 200 {
        return (challenge_status, challenge, Vec::new());
    }

    // The canonical identity comes from the server, never from what was typed.
    let identity = challenge["identity"].as_str().unwrap();
    let salt = challenge["salt"].as_str().unwrap();
    let x = derive_x(identity, password, salt);
    let (m1, _expected_m2) = client
        .finish(identity, salt, challenge["b_pub"].as_str().unwrap(), &x)
        .unwrap();

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/srp/verify")
        .set_json(serde_json::json!({
            "srp_session": challenge["srp_session"].as_str().unwrap(),
            "client_proof": m1,
        }))
        .to_request();
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    let cookies: Vec<(String, String)> = resp
        .response()
        .cookies()
        .map(|c| (c.name().to_string(), c.value().to_string()))
        .collect();
    let body: serde_json::Value = test::read_body_json(resp).await;
    (status, body, cookies)
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[actix_web::test]
async fn a_full_srp_exchange_issues_the_same_cookies_as_a_password_login() {
    let (db, org_id, tenant_id, _user_id) = setup_db("srp-happy").await;
    set_srp_mode(&db, org_id, SrpMode::Optional).await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let (access, csrf) = password_login(&app, org_id, tenant_id, password())
        .await
        .expect("password login should work before SRP is enrolled");
    assert_eq!(
        enroll_via_password_change(&app, &access, &csrf, password(), new_password()).await,
        204
    );

    let (status, body, cookies) =
        srp_login(&app, org_id, tenant_id, USERNAME, new_password()).await;
    assert_eq!(status, 200, "SRP login failed: {body}");

    // Mutual authentication: the client can verify the server too.
    assert!(
        body["server_proof"].as_str().is_some_and(|p| p.len() == 64),
        "server_proof missing or wrong width: {body}"
    );

    // The session it produces is the ordinary one — same three cookies, same
    // body shape — so a client needs one result handler for both login paths.
    let names: Vec<&str> = cookies.iter().map(|(n, _)| n.as_str()).collect();
    for expected in ["axiam_access", "axiam_refresh", "axiam_csrf"] {
        assert!(names.contains(&expected), "missing {expected} in {names:?}");
    }
    assert!(body["user"]["username"] == USERNAME, "{body}");
    assert!(body["session_id"].is_string(), "{body}");
}

#[actix_web::test]
async fn a_user_may_authenticate_by_email_because_the_server_names_the_identity() {
    // The verifier binds `username`, but a human may type their email. The
    // challenge response carries the canonical identity precisely so this
    // works; a client that used what was typed would derive the wrong x.
    let (db, org_id, tenant_id, _user_id) = setup_db("srp-email").await;
    set_srp_mode(&db, org_id, SrpMode::Optional).await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let (access, csrf) = password_login(&app, org_id, tenant_id, password())
        .await
        .unwrap();
    enroll_via_password_change(&app, &access, &csrf, password(), new_password()).await;

    let (status, body, _) =
        srp_login(&app, org_id, tenant_id, "alice@example.com", new_password()).await;
    assert_eq!(status, 200, "{body}");
}

#[actix_web::test]
async fn a_wrong_password_is_refused_and_moves_the_lockout_counter() {
    // The security property: SRP must not be a way around brute-force
    // protection. Five wrong proofs must lock the account exactly as five
    // wrong passwords on /auth/login would.
    let (db, org_id, tenant_id, user_id) = setup_db("srp-lockout").await;
    set_srp_mode(&db, org_id, SrpMode::Optional).await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let (access, csrf) = password_login(&app, org_id, tenant_id, password())
        .await
        .unwrap();
    enroll_via_password_change(&app, &access, &csrf, password(), new_password()).await;

    let user_repo = SurrealUserRepository::new(db.clone());
    let before = user_repo.get_by_id(tenant_id, user_id).await.unwrap();

    let (status, _, _) = srp_login(&app, org_id, tenant_id, USERNAME, wrong_password()).await;
    assert_eq!(status, 401);

    let after = user_repo.get_by_id(tenant_id, user_id).await.unwrap();
    assert!(
        after.failed_login_attempts > before.failed_login_attempts,
        "a failed SRP proof did not accrue toward lockout ({} -> {})",
        before.failed_login_attempts,
        after.failed_login_attempts
    );
}

#[actix_web::test]
async fn an_unknown_identity_is_indistinguishable_from_a_known_one() {
    let (db, org_id, tenant_id, _user_id) = setup_db("srp-enum").await;
    set_srp_mode(&db, org_id, SrpMode::Optional).await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let (access, csrf) = password_login(&app, org_id, tenant_id, password())
        .await
        .unwrap();
    enroll_via_password_change(&app, &access, &csrf, password(), new_password()).await;

    let client = reference_client::begin(SrpGroup::Rfc5054_2048);
    let mut shapes = Vec::new();
    for identity in [USERNAME, "nobody-at-all", "also@not.real"] {
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/auth/srp/challenge")
            .set_json(serde_json::json!({
                "org_id": org_id,
                "tenant_id": tenant_id,
                "username_or_email": identity,
                "client_public": client.a_pub_hex,
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status().as_u16(),
            200,
            "identity {identity} leaked via status"
        );
        let body: serde_json::Value = test::read_body_json(resp).await;
        shapes.push((
            body["salt"].as_str().unwrap().len(),
            body["b_pub"].as_str().unwrap().len(),
            body["group"].as_str().unwrap().to_string(),
            body["kdf"].as_str().unwrap().to_string(),
            body["iterations"].as_u64().unwrap(),
        ));
    }
    assert_eq!(shapes[0], shapes[1], "unknown identity is distinguishable");
    assert_eq!(shapes[0], shapes[2], "unknown identity is distinguishable");

    // An unknown identity can never complete, whatever proof is offered.
    let (status, _, _) = srp_login(&app, org_id, tenant_id, "nobody-at-all", new_password()).await;
    assert_eq!(status, 401);
}

#[actix_web::test]
async fn a_probe_for_an_unknown_identity_returns_a_stable_salt() {
    // A fresh random salt per attempt would announce non-existence as loudly
    // as a 404 would.
    let (db, org_id, tenant_id, _user_id) = setup_db("srp-stable-salt").await;
    set_srp_mode(&db, org_id, SrpMode::Optional).await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let mut salts = Vec::new();
    for _ in 0..2 {
        let client = reference_client::begin(SrpGroup::Rfc5054_2048);
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/auth/srp/challenge")
            .set_json(serde_json::json!({
                "org_id": org_id,
                "tenant_id": tenant_id,
                "username_or_email": "ghost",
                "client_public": client.a_pub_hex,
            }))
            .to_request();
        let body: serde_json::Value =
            test::read_body_json(test::call_service(&app, req).await).await;
        salts.push(body["salt"].as_str().unwrap().to_string());
    }
    assert_eq!(salts[0], salts[1]);
}

#[actix_web::test]
async fn srp_disabled_hides_the_endpoint_entirely() {
    let (db, org_id, tenant_id, _user_id) = setup_db("srp-off").await;
    set_srp_mode(&db, org_id, SrpMode::Disabled).await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let client = reference_client::begin(SrpGroup::Rfc5054_2048);
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/srp/challenge")
        .set_json(serde_json::json!({
            "org_id": org_id,
            "tenant_id": tenant_id,
            "username_or_email": USERNAME,
            "client_public": client.a_pub_hex,
        }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 404);

    // ...and password login still works, unchanged.
    assert!(
        password_login(&app, org_id, tenant_id, password())
            .await
            .is_some()
    );
}

#[actix_web::test]
async fn srp_required_refuses_password_login_for_everyone_with_a_distinct_code() {
    // Uniform refusal is what stops this from being an enumeration oracle:
    // enrolled and unenrolled users get the identical answer, and the answer
    // is a property of the tenant rather than of any account.
    let (db, org_id, tenant_id, _user_id) = setup_db("srp-required").await;
    set_srp_mode(&db, org_id, SrpMode::Required).await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    for (label, password) in [
        ("right password", password()),
        ("wrong password", wrong_password()),
    ] {
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/auth/login")
            .set_json(serde_json::json!({
                "org_id": org_id,
                "tenant_id": tenant_id,
                "username_or_email": USERNAME,
                "password": password,
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 403, "{label}");
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(
            body["error"], "srp_required",
            "clients need a machine-readable code to switch protocols: {body}"
        );
    }

    // An unknown user gets the same answer — no oracle.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "org_id": org_id,
            "tenant_id": tenant_id,
            "username_or_email": "no-such-person",
            "password": password(),
        }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 403);
}

#[actix_web::test]
async fn a_verifier_is_refused_when_the_tenant_has_srp_disabled() {
    // Silently dropping it would let a client believe SRP is active while the
    // very next login is a password login.
    let (db, org_id, tenant_id, _user_id) = setup_db("srp-reject-off").await;
    set_srp_mode(&db, org_id, SrpMode::Disabled).await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let (access, csrf) = password_login(&app, org_id, tenant_id, password())
        .await
        .unwrap();
    assert_eq!(
        enroll_via_password_change(&app, &access, &csrf, password(), new_password()).await,
        400
    );
}

#[actix_web::test]
async fn renaming_a_user_drops_the_verifier_bound_to_the_old_name() {
    // x is derived over `username ":" password`, so a stale verifier would
    // answer challenges no client could satisfy — "invalid credentials" for a
    // password that is entirely correct.
    let (db, org_id, tenant_id, user_id) = setup_db("srp-rename").await;
    set_srp_mode(&db, org_id, SrpMode::Optional).await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let (access, csrf) = password_login(&app, org_id, tenant_id, password())
        .await
        .unwrap();
    enroll_via_password_change(&app, &access, &csrf, password(), new_password()).await;

    // Confirm it works before the rename.
    let (status, _, _) = srp_login(&app, org_id, tenant_id, USERNAME, new_password()).await;
    assert_eq!(status, 200);

    let req = test::TestRequest::put()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/users/{user_id}"))
        .cookie(actix_web::cookie::Cookie::new(
            "axiam_access",
            access.clone(),
        ))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", csrf.clone()))
        .insert_header(("X-CSRF-Token", csrf.clone()))
        .set_json(serde_json::json!({ "username": "alice-renamed" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_success(),
        "rename failed: {:?}",
        resp.status()
    );

    let repo = axiam_db::SurrealSrpCredentialRepository::new(db.clone());
    use axiam_core::repository::SrpCredentialRepository;
    assert!(
        repo.get_by_user(tenant_id, user_id).await.is_err(),
        "the verifier survived a rename and would now reject every correct password"
    );
}

#[actix_web::test]
async fn a_client_public_value_congruent_to_zero_is_refused_over_http() {
    // The classic SRP break, asserted at the HTTP boundary rather than only in
    // the unit tests, because this is the value an attacker actually controls.
    let (db, org_id, tenant_id, _user_id) = setup_db("srp-zero-a").await;
    set_srp_mode(&db, org_id, SrpMode::Optional).await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    for a in ["00", &"0".repeat(512)] {
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/auth/srp/challenge")
            .set_json(serde_json::json!({
                "org_id": org_id,
                "tenant_id": tenant_id,
                "username_or_email": USERNAME,
                "client_public": a,
            }))
            .to_request();
        let status = test::call_service(&app, req).await.status().as_u16();
        assert_eq!(status, 401, "A={a} was accepted");
    }
}

#[actix_web::test]
async fn a_session_cannot_be_replayed_against_a_different_exchange() {
    let (db, org_id, tenant_id, _user_id) = setup_db("srp-replay").await;
    set_srp_mode(&db, org_id, SrpMode::Optional).await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let (access, csrf) = password_login(&app, org_id, tenant_id, password())
        .await
        .unwrap();
    enroll_via_password_change(&app, &access, &csrf, password(), new_password()).await;

    // Two challenges, then cross the proof of one with the session of the other.
    let mut sessions = Vec::new();
    let mut proofs = Vec::new();
    for _ in 0..2 {
        let client = reference_client::begin(SrpGroup::Rfc5054_2048);
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/auth/srp/challenge")
            .set_json(serde_json::json!({
                "org_id": org_id,
                "tenant_id": tenant_id,
                "username_or_email": USERNAME,
                "client_public": client.a_pub_hex,
            }))
            .to_request();
        let body: serde_json::Value =
            test::read_body_json(test::call_service(&app, req).await).await;
        let identity = body["identity"].as_str().unwrap().to_string();
        let salt = body["salt"].as_str().unwrap().to_string();
        let x = derive_x(&identity, new_password(), &salt);
        let (m1, _) = client
            .finish(&identity, &salt, body["b_pub"].as_str().unwrap(), &x)
            .unwrap();
        sessions.push(body["srp_session"].as_str().unwrap().to_string());
        proofs.push(m1);
    }
    assert_ne!(sessions[0], sessions[1], "B must be fresh per exchange");

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/srp/verify")
        .set_json(serde_json::json!({
            "srp_session": sessions[1],
            "client_proof": proofs[0],
        }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 401);
}
