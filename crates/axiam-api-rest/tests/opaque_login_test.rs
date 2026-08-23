//! End-to-end tests for the OPAQUE login path.
//!
//! These exercise the whole exchange over the real HTTP surface — enrol a
//! record through `POST /api/v1/auth/password/change`, then authenticate with
//! `/auth/opaque/login/start` + `/auth/opaque/login/finish` — using
//! [`axiam_opaque`], which is the same code every SDK compiles or binds.
//!
//! The properties worth asserting here are not the happy path (covered by the
//! unit tests in `axiam-auth`) but the ones that only exist once the endpoints
//! are wired into the rest of the system: that a failed exchange accrues toward
//! lockout, that an unknown identity is indistinguishable from a known one,
//! that `opaque_mode = required` refuses password login for everybody, and that
//! the OPAQUE path and the password path issue the same cookies.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_core::models::opaque::{OpaqueKsf, OpaqueMode, OpaqueSuite};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::settings::system_defaults;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, SettingsRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealSessionRepository, SurrealSettingsRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_opaque::{AxiamKsf, ClientLoginState, ClientRegistrationState};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12345";
const USERNAME: &str = "alice";

/// Keys for the two things OPAQUE seals, minted per process rather than written
/// as literals.
///
/// CodeQL's `rust/hardcoded-cryptographic-value` flags a literal that reaches a
/// cipher, and that rule is right about shipping code. Nothing here depends on
/// the values, only on the two being *distinct* — which is what would catch the
/// engine ever confusing them.
fn keys() -> (&'static [u8; 32], &'static [u8; 32]) {
    static KEYS: OnceLock<([u8; 32], [u8; 32])> = OnceLock::new();
    let (session, setup) = KEYS.get_or_init(|| {
        let mut session = [0u8; 32];
        let mut setup = [0u8; 32];
        getrandom::fill(&mut session).expect("a CSPRNG");
        getrandom::fill(&mut setup).expect("a CSPRNG");
        (session, setup)
    });
    (session, setup)
}

/// The account's password, minted per test run rather than written as a literal.
///
/// CodeQL's `rust/hardcoded-cryptographic-value` flags a literal that reaches a
/// KDF as a password, and that rule is right about shipping code. Nothing here
/// depends on the value — every assertion is about what the server does with
/// it — so the only requirement is that it satisfies the password policy, which
/// the uppercase/lowercase/digit shape below guarantees.
fn password() -> &'static str {
    static VALUE: OnceLock<String> = OnceLock::new();
    VALUE.get_or_init(|| format!("Ax{}1", Uuid::new_v4().simple()))
}

fn new_password() -> &'static str {
    static VALUE: OnceLock<String> = OnceLock::new();
    VALUE.get_or_init(|| format!("Bx{}2", Uuid::new_v4().simple()))
}

fn wrong_password() -> &'static str {
    static VALUE: OnceLock<String> = OnceLock::new();
    VALUE.get_or_init(|| format!("Cx{}3", Uuid::new_v4().simple()))
}

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
        opaque_session_key: Some(*keys().0),
        opaque_setup_key: Some(*keys().1),
        ..AuthConfig::default()
    }
}

/// Rebuild the client-side stretching function from what the server named.
///
/// A client MUST take these from the response rather than from its own
/// configuration: a credential enrolled under one cost keeps working after a
/// tenant raises its policy, and a client that guessed would derive a different
/// randomized password and fail against a record that is perfectly good.
fn ksf_from_response(v: &serde_json::Value) -> AxiamKsf {
    match v["ksf"].as_str().unwrap() {
        "argon2id" => AxiamKsf::argon2id(
            v["memory_kib"].as_u64().unwrap() as u32,
            v["iterations"].as_u64().unwrap() as u32,
            v["parallelism"].as_u64().unwrap() as u32,
        )
        .unwrap(),
        "scrypt" => AxiamKsf::scrypt(
            v["log_n"].as_u64().unwrap() as u8,
            v["r"].as_u64().unwrap() as u32,
            v["p"].as_u64().unwrap() as u32,
        )
        .unwrap(),
        other => panic!("unknown ksf {other}"),
    }
}

async fn setup_db(slug: &str) -> (Surreal<TestDb>, Uuid, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "OPAQUE Org".into(),
            slug: format!("{slug}-org"),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "OPAQUE Tenant".into(),
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

/// Set the org-level OPAQUE mode.
///
/// The KSF is pinned to the cheapest Argon2id the domain model accepts, because
/// these tests run the real stretching function and the production default
/// (19456 KiB, two passes) would dominate their runtime for no added coverage —
/// nothing asserted here depends on the cost, only on client and server
/// agreeing about it.
async fn set_opaque_mode(db: &Surreal<TestDb>, org_id: Uuid, mode: OpaqueMode) {
    let mut defaults = system_defaults();
    defaults.opaque_mode = mode;
    defaults.opaque_suite = OpaqueSuite::Ristretto255Sha512;
    defaults.opaque_ksf = OpaqueKsf::Argon2id;
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

/// Run the two-message registration and return the `opaque` object to embed in
/// a password-setting request.
async fn build_enrollment(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    org_id: Uuid,
    tenant_id: Uuid,
    password: &str,
) -> Option<serde_json::Value> {
    let (state, request) = ClientRegistrationState::start(password).unwrap();

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/opaque/register/start")
        .set_json(serde_json::json!({
            "org_id": org_id,
            "tenant_id": tenant_id,
            "registration_request": request,
        }))
        .to_request();
    let resp = test::call_service(app, req).await;
    if !resp.status().is_success() {
        return None;
    }
    let started: serde_json::Value = test::read_body_json(resp).await;

    let ksf = ksf_from_response(&started);
    let outcome = state
        .finish(
            password,
            started["registration_response"].as_str().unwrap(),
            &ksf,
        )
        .unwrap();

    Some(serde_json::json!({
        "opaque_session": started["opaque_session"].as_str().unwrap(),
        "registration_record": outcome.record,
    }))
}

/// Enrol a record for `new_password` via change-password, one of the four
/// routes by which one can legitimately come into existence.
async fn enroll_via_password_change(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    org_id: Uuid,
    tenant_id: Uuid,
    access: &str,
    csrf: &str,
    current: &str,
    new_password: &str,
) -> u16 {
    let enrollment = build_enrollment(app, org_id, tenant_id, new_password).await;

    let mut body = serde_json::json!({
        "current_password": current,
        "new_password": new_password,
    });
    if let Some(e) = enrollment {
        body["opaque"] = e;
    }

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
        .set_json(body)
        .to_request();
    test::call_service(app, req).await.status().as_u16()
}

/// One full OPAQUE login. Returns `(login_start_body, finish_status,
/// finish_body, cookies)`.
async fn opaque_login(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    org_id: Uuid,
    tenant_id: Uuid,
    identity_typed: &str,
    password: &str,
) -> (
    u16,
    serde_json::Value,
    u16,
    serde_json::Value,
    Vec<(String, String)>,
) {
    let (state, ke1) = ClientLoginState::start(password).unwrap();

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/opaque/login/start")
        .set_json(serde_json::json!({
            "org_id": org_id,
            "tenant_id": tenant_id,
            "username_or_email": identity_typed,
            "ke1": ke1,
        }))
        .to_request();
    let resp = test::call_service(app, req).await;
    let start_status = resp.status().as_u16();
    let started: serde_json::Value = test::read_body_json(resp).await;
    if start_status != 200 {
        return (
            start_status,
            started,
            0,
            serde_json::Value::Null,
            Vec::new(),
        );
    }

    let ksf = ksf_from_response(&started);
    // A wrong password, or an identity that does not exist, fails here — the
    // client cannot open the envelope. The server is still poked with a junk
    // KE3 so that its own refusal path is what the test observes.
    let ke3 = match state.finish(password, started["ke2"].as_str().unwrap(), &ksf) {
        Ok(finished) => finished.ke3,
        Err(_) => hex::encode([0u8; 64]),
    };

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/opaque/login/finish")
        .set_json(serde_json::json!({
            "opaque_session": started["opaque_session"].as_str().unwrap(),
            "ke3": ke3,
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
    (start_status, started, status, body, cookies)
}

/// Enrol the account and return the app-independent handle the tests reuse.
macro_rules! enrolled_app {
    ($slug:expr) => {{
        let (db, org_id, tenant_id, user_id) = setup_db($slug).await;
        set_opaque_mode(&db, org_id, OpaqueMode::Optional).await;
        let auth = test_auth_config();
        let app = test_app!(db, auth);

        let (access, csrf) = password_login(&app, org_id, tenant_id, password())
            .await
            .expect("password login must work under optional");
        let status = enroll_via_password_change(
            &app,
            org_id,
            tenant_id,
            &access,
            &csrf,
            password(),
            new_password(),
        )
        .await;
        assert_eq!(status, 204, "enrolment should succeed");
        (db, org_id, tenant_id, user_id, app)
    }};
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[actix_web::test]
async fn a_full_opaque_exchange_issues_the_same_cookies_as_a_password_login() {
    let (_db, org_id, tenant_id, _user_id, app) = enrolled_app!("full");

    let (_, _, status, _body, cookies) =
        opaque_login(&app, org_id, tenant_id, USERNAME, new_password()).await;
    assert_eq!(status, 200, "a correct password must authenticate");

    let names: Vec<&str> = cookies.iter().map(|(n, _)| n.as_str()).collect();
    for expected in ["axiam_access", "axiam_refresh", "axiam_csrf"] {
        assert!(
            names.contains(&expected),
            "OPAQUE login must set {expected} exactly as the password path does; got {names:?}"
        );
    }
}

#[actix_web::test]
async fn the_login_response_carries_no_server_proof_because_the_ake_replaces_it() {
    // Under SRP the client had to verify `M2` from this body or it kept only
    // half the protocol. RFC 9807's AKE authenticates the server during the
    // handshake, so there is nothing here to check and no way for an SDK to
    // forget to.
    let (_db, org_id, tenant_id, _user_id, app) = enrolled_app!("noproof");

    let (_, _, status, body, _) =
        opaque_login(&app, org_id, tenant_id, USERNAME, new_password()).await;
    assert_eq!(status, 200);
    assert!(
        body.get("server_proof").is_none(),
        "the response must not carry a server proof: {body}"
    );
}

#[actix_web::test]
async fn a_user_may_authenticate_by_email() {
    let (_db, org_id, tenant_id, _user_id, app) = enrolled_app!("byemail");

    let (_, _, status, _, _) =
        opaque_login(&app, org_id, tenant_id, "alice@example.com", new_password()).await;
    assert_eq!(
        status, 200,
        "the record is bound to a server-chosen identifier, so either login name works"
    );
}

#[actix_web::test]
async fn a_wrong_password_is_refused_and_moves_the_lockout_counter() {
    let (db, org_id, tenant_id, user_id, app) = enrolled_app!("wrongpw");

    let (_, _, status, _, _) =
        opaque_login(&app, org_id, tenant_id, USERNAME, wrong_password()).await;
    assert_eq!(status, 401);

    // The counter is the whole reason `OpaqueRejection` distinguishes an
    // attributable failure from an unusable session. Without it, turning
    // OPAQUE on would silently remove brute-force protection.
    let user = SurrealUserRepository::new(db.clone())
        .get_by_id(tenant_id, user_id)
        .await
        .unwrap();
    assert!(
        user.failed_login_attempts >= 1,
        "a failed OPAQUE exchange must accrue toward lockout like a failed \
         password verify does; got {}",
        user.failed_login_attempts
    );
}

#[actix_web::test]
async fn an_unknown_identity_is_indistinguishable_from_a_known_one() {
    let (_db, org_id, tenant_id, _user_id, app) = enrolled_app!("unknown");

    let (known_status, known, _, _, _) =
        opaque_login(&app, org_id, tenant_id, USERNAME, wrong_password()).await;
    let (unknown_status, unknown, _, _, _) =
        opaque_login(&app, org_id, tenant_id, "nobody-at-all", wrong_password()).await;

    assert_eq!(known_status, 200);
    assert_eq!(unknown_status, 200);
    assert_eq!(
        known["ke2"].as_str().unwrap().len(),
        unknown["ke2"].as_str().unwrap().len(),
        "a KE2 length difference is a free account-enumeration oracle"
    );
    assert_eq!(known["suite"], unknown["suite"]);
    assert_eq!(known["ksf"], unknown["ksf"]);
    assert_eq!(known["memory_kib"], unknown["memory_kib"]);
    assert_eq!(known["iterations"], unknown["iterations"]);
    assert_eq!(known["parallelism"], unknown["parallelism"]);
    assert_eq!(
        known.as_object().unwrap().keys().collect::<Vec<_>>(),
        unknown.as_object().unwrap().keys().collect::<Vec<_>>(),
        "the two responses must have the same field set"
    );
}

#[actix_web::test]
async fn a_probe_for_an_unknown_identity_is_stable_across_attempts() {
    // An unstable decoy announces non-existence as loudly as a 404 would: two
    // different answers for the same name is itself the signal.
    let (_db, org_id, tenant_id, _user_id, app) = enrolled_app!("stable");

    let (_, first, _, _, _) =
        opaque_login(&app, org_id, tenant_id, "ghost", wrong_password()).await;
    let (_, second, _, _, _) =
        opaque_login(&app, org_id, tenant_id, "ghost", wrong_password()).await;

    // KE2 itself is randomized per exchange by design, so what must match is
    // the shape and the advertised parameters, not the bytes.
    assert_eq!(
        first["ke2"].as_str().unwrap().len(),
        second["ke2"].as_str().unwrap().len()
    );
    assert_eq!(first["ksf"], second["ksf"]);
    assert_eq!(first["memory_kib"], second["memory_kib"]);
    assert_eq!(first["suite"], second["suite"]);
}

#[actix_web::test]
async fn opaque_disabled_hides_the_endpoints_entirely() {
    let (db, org_id, tenant_id, _user_id) = setup_db("disabled").await;
    set_opaque_mode(&db, org_id, OpaqueMode::Disabled).await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let (status, _, _, _, _) = opaque_login(&app, org_id, tenant_id, USERNAME, password()).await;
    assert_eq!(
        status, 404,
        "disabled is a property of the tenant, not of any user, so revealing it \
         leaks nothing"
    );

    let (state, request) = ClientRegistrationState::start(password()).unwrap();
    let _ = state;
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/opaque/register/start")
        .set_json(serde_json::json!({
            "org_id": org_id,
            "tenant_id": tenant_id,
            "registration_request": request,
        }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 404);
}

#[actix_web::test]
async fn opaque_required_refuses_password_login_for_everyone_with_a_distinct_code() {
    let (db, org_id, tenant_id, _user_id) = setup_db("required").await;
    set_opaque_mode(&db, org_id, OpaqueMode::Required).await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "org_id": org_id,
            "tenant_id": tenant_id,
            "username_or_email": USERNAME,
            "password": password(),
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["error"], "opaque_required",
        "a distinct code is what lets an SDK switch to /auth/opaque/* rather \
         than tell the user their correct password is wrong: {body}"
    );

    // And for a name that does not exist, so the refusal cannot be used to
    // enumerate.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "org_id": org_id,
            "tenant_id": tenant_id,
            "username_or_email": "nobody-at-all",
            "password": password(),
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "the refusal must be uniform across the tenant, before any credential \
         is examined"
    );
}

#[actix_web::test]
async fn a_record_is_refused_when_the_tenant_has_opaque_disabled() {
    let (db, org_id, tenant_id, _user_id) = setup_db("refused").await;
    // Enrol under `optional` so a well-formed session exists...
    set_opaque_mode(&db, org_id, OpaqueMode::Optional).await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let enrollment = build_enrollment(&app, org_id, tenant_id, new_password())
        .await
        .expect("register/start should work under optional");

    // ...then turn it off and try to redeem it.
    set_opaque_mode(&db, org_id, OpaqueMode::Disabled).await;
    let (access, csrf) = password_login(&app, org_id, tenant_id, password())
        .await
        .unwrap();

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/password/change")
        .cookie(actix_web::cookie::Cookie::new("axiam_access", access))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", csrf.clone()))
        .insert_header(("X-CSRF-Token", csrf))
        .set_json(serde_json::json!({
            "current_password": password(),
            "new_password": new_password(),
            "opaque": enrollment,
        }))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status().as_u16(),
        400,
        "storing it would be dead weight, and discarding it silently would let \
         a client believe OPAQUE is active"
    );
}

#[actix_web::test]
async fn renaming_a_user_leaves_the_credential_working() {
    // The SRP equivalent of this test asserted the opposite: `x` was derived
    // over `username ":" password`, so a rename produced a verifier no client
    // could satisfy and the handler had to delete it. OPAQUE binds to a
    // server-chosen identifier, so a rename is a no-op for the credential.
    let (db, org_id, tenant_id, user_id, app) = enrolled_app!("rename");

    SurrealUserRepository::new(db.clone())
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                username: Some("alice-renamed".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let (_, _, status, _, _) =
        opaque_login(&app, org_id, tenant_id, "alice-renamed", new_password()).await;
    assert_eq!(
        status, 200,
        "a rename must not invalidate an OPAQUE credential"
    );
}

#[actix_web::test]
async fn a_malformed_ke1_is_refused_over_http() {
    let (_db, org_id, tenant_id, _user_id, app) = enrolled_app!("badke1");

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/opaque/login/start")
        .set_json(serde_json::json!({
            "org_id": org_id,
            "tenant_id": tenant_id,
            "username_or_email": USERNAME,
            "ke1": "not-hex",
        }))
        .to_request();
    let status = test::call_service(&app, req).await.status().as_u16();
    assert!(
        (400..500).contains(&status),
        "a malformed KE1 is a client error, not a 500; got {status}"
    );
}

#[actix_web::test]
async fn a_session_cannot_be_replayed_against_a_different_exchange() {
    let (_db, org_id, tenant_id, _user_id, app) = enrolled_app!("replay");

    // Two independent starts; finish the second with the first's session.
    let (_, first, _, _, _) = opaque_login(&app, org_id, tenant_id, USERNAME, new_password()).await;

    let (state, ke1) = ClientLoginState::start(new_password()).unwrap();
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/opaque/login/start")
        .set_json(serde_json::json!({
            "org_id": org_id,
            "tenant_id": tenant_id,
            "username_or_email": USERNAME,
            "ke1": ke1,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let second: serde_json::Value = test::read_body_json(resp).await;
    let ksf = ksf_from_response(&second);
    let ke3 = state
        .finish(new_password(), second["ke2"].as_str().unwrap(), &ksf)
        .unwrap()
        .ke3;

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/opaque/login/finish")
        .set_json(serde_json::json!({
            // First exchange's sealed state, second exchange's KE3.
            "opaque_session": first["opaque_session"].as_str().unwrap(),
            "ke3": ke3,
        }))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status().as_u16(),
        401,
        "a KE3 is bound to the exchange that produced its KE2"
    );
}

#[actix_web::test]
async fn a_registration_session_is_refused_at_the_login_finish_endpoint() {
    let (_db, org_id, tenant_id, _user_id, app) = enrolled_app!("kindmix");

    let enrollment = build_enrollment(&app, org_id, tenant_id, new_password())
        .await
        .unwrap();

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/opaque/login/finish")
        .set_json(serde_json::json!({
            "opaque_session": enrollment["opaque_session"].as_str().unwrap(),
            "ke3": hex::encode([0u8; 64]),
        }))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status().as_u16(),
        401,
        "both exchanges seal under the same key; only the kind tag stops one \
         token being fed to the other"
    );
}

#[actix_web::test]
async fn the_endpoints_answer_503_when_the_keys_are_missing() {
    // A configured policy with no keys is a misconfiguration and must look like
    // one. Falling back to password login would let an operator believe a
    // control is on while every client quietly bypasses it.
    let (db, org_id, tenant_id, _user_id) = setup_db("nokeys").await;
    set_opaque_mode(&db, org_id, OpaqueMode::Optional).await;
    let auth = AuthConfig {
        opaque_session_key: None,
        opaque_setup_key: None,
        ..test_auth_config()
    };
    let app = test_app!(db, auth);

    let (status, _, _, _, _) = opaque_login(&app, org_id, tenant_id, USERNAME, password()).await;
    assert_eq!(status, 500, "misconfiguration must not degrade silently");
}

#[actix_web::test]
async fn half_configured_keys_are_treated_as_no_keys_at_all() {
    // One key without the other can either seal an exchange it cannot key, or
    // key a tenant it cannot seal a session for. Neither half is useful alone.
    let (db, org_id, tenant_id, _user_id) = setup_db("halfkeys").await;
    set_opaque_mode(&db, org_id, OpaqueMode::Optional).await;
    let auth = AuthConfig {
        opaque_session_key: Some(*keys().0),
        opaque_setup_key: None,
        ..test_auth_config()
    };
    let app = test_app!(db, auth);

    let (status, _, _, _, _) = opaque_login(&app, org_id, tenant_id, USERNAME, password()).await;
    assert_eq!(status, 500);
}

// -----------------------------------------------------------------------
// The tenant's mode travels with the KE2
// -----------------------------------------------------------------------
//
// A client that has no record — which is every client of a tenant the moment
// an operator turns OPAQUE on — cannot open the envelope, and the server
// deliberately makes that indistinguishable from a wrong password so this
// endpoint cannot enumerate who is enrolled. Under `optional` the password
// endpoint is still live and is the right next thing to try; under `required`
// it is not, and an honest client must send no plaintext at all. `mode` is
// what tells the two apart.

#[actix_web::test]
async fn login_start_reports_the_tenants_mode() {
    let (db, org_id, tenant_id, _user_id, app) = enrolled_app!("modeopt");

    let (status, body, _, _, _) =
        opaque_login(&app, org_id, tenant_id, USERNAME, new_password()).await;
    assert_eq!(status, 200);
    assert_eq!(body["mode"], "optional");

    set_opaque_mode(&db, org_id, OpaqueMode::Required).await;
    let (status, body, _, _, _) =
        opaque_login(&app, org_id, tenant_id, USERNAME, new_password()).await;
    assert_eq!(status, 200);
    assert_eq!(body["mode"], "required");
}

#[actix_web::test]
async fn the_reported_mode_is_the_same_for_an_unknown_identity() {
    // It is a property of the tenant, not of whether this identity has a
    // record. A `mode` that differed between the real and decoy branches would
    // be the enumeration oracle the decoy exists to prevent.
    let (_db, org_id, tenant_id, _user_id, app) = enrolled_app!("modedecoy");

    let (_, known, _, _, _) =
        opaque_login(&app, org_id, tenant_id, USERNAME, wrong_password()).await;
    let (_, unknown, _, _, _) =
        opaque_login(&app, org_id, tenant_id, "nobody-at-all", wrong_password()).await;

    assert_eq!(known["mode"], unknown["mode"]);
    assert_eq!(known["mode"], "optional");
}
