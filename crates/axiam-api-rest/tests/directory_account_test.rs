//! Directory accounts over HTTP (G-3, T23.3.2): sign-in through the injected
//! directory authenticator, and every local password door refused.
//!
//! The directory is a stub `DirectoryAuthenticator` (the LDAP client has its
//! own live-server tests in `axiam-directory`). The doors tested here are the
//! HTTP routes:
//!
//! - `POST /api/v1/auth/login` — signs a directory account in, through the
//!   directory only;
//! - `POST /api/v1/auth/password/change` — refused, with or without an OPAQUE
//!   record attached;
//! - `POST /api/v1/auth/reset` — answered exactly as an unknown address;
//! - `POST /api/v1/auth/reset/confirm` — refused, nothing written;
//! - `POST /api/v1/auth/opaque/login/start` and `/finish` — decoy, then 401;
//! - `POST` and `PUT /api/v1/users` — cannot set or clear the marker.
//!
//! Assertion messages name the case; none formats a password, a token, a body
//! carrying one, or an identifier.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_core::models::directory::{
    DirectoryAuthError, DirectoryAuthenticator, DirectoryIdentity,
};
use axiam_core::models::opaque::{OpaqueKsf, OpaqueMode, OpaqueSuite};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::password_reset::CreatePasswordResetToken;
use axiam_core::models::settings::system_defaults;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OpaqueCredentialRepository, OrganizationRepository, PasswordResetTokenRepository,
    SettingsRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOpaqueCredentialRepository, SurrealOrganizationRepository,
    SurrealPasswordResetTokenRepository, SurrealSessionRepository, SurrealSettingsRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_opaque::{AxiamKsf, ClientLoginState, ClientRegistrationState};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12345";
const ENTRY: &str = "6f9619ff-8b86-d011-b42d-00c04fc964ff";

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

/// Minted per run, never a literal (CodeQL `rust/hardcoded-cryptographic-value`).
fn password() -> &'static str {
    static VALUE: OnceLock<String> = OnceLock::new();
    VALUE.get_or_init(|| format!("Ax{}1", Uuid::new_v4().simple()))
}

fn new_password() -> &'static str {
    static VALUE: OnceLock<String> = OnceLock::new();
    VALUE.get_or_init(|| format!("Bx{}2", Uuid::new_v4().simple()))
}

fn auth_config() -> AuthConfig {
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

/// A directory that accepts every bind as the entry `ENTRY`.
struct AcceptingDirectory;

impl DirectoryAuthenticator for AcceptingDirectory {
    fn authenticate<'a>(
        &'a self,
        _tenant_id: Uuid,
        _login_name: &'a str,
        _password: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<DirectoryIdentity, DirectoryAuthError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async {
            Ok(DirectoryIdentity {
                external_id: ENTRY.into(),
                dn: "uid=alice,ou=people,dc=example,dc=com".into(),
                username: Some("alice".into()),
                email: Some("alice@example.com".into()),
                display_name: None,
            })
        })
    }
}

struct Ids {
    org_id: Uuid,
    tenant_id: Uuid,
    alice: Uuid,
}

/// Org, tenant, and `alice` — a local, active account with `password()`.
async fn setup(slug: &str) -> (Surreal<TestDb>, Ids) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Directory Org".into(),
            slug: format!("{slug}-org"),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Directory Tenant".into(),
            slug: format!("{slug}-tenant"),
            metadata: None,
        })
        .await
        .unwrap();
    let users = SurrealUserRepository::new(db.clone());
    let alice = users
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: password().into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    users
        .update(
            tenant.id,
            alice,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let mut defaults = system_defaults();
    defaults.opaque_mode = OpaqueMode::Optional;
    defaults.opaque_suite = OpaqueSuite::Ristretto255Sha512;
    defaults.opaque_ksf = OpaqueKsf::Argon2id;
    SurrealSettingsRepository::new(db.clone())
        .set_org_settings(org.id, defaults)
        .await
        .unwrap();
    (
        db,
        Ids {
            org_id: org.id,
            tenant_id: tenant.id,
            alice,
        },
    )
}

async fn mark_alice(db: &Surreal<TestDb>, ids: &Ids) {
    SurrealUserRepository::new(db.clone())
        .mark_directory_account(ids.tenant_id, ids.alice, ENTRY)
        .await
        .unwrap();
}

macro_rules! app {
    ($db:expr) => {{
        let auth = auth_config();
        let mut state = AppState::for_test($db.clone(), auth.clone());
        state.auth_service = state
            .auth_service
            .clone()
            .with_directory_authenticator(Arc::new(AcceptingDirectory));
        test::init_service(
            App::new()
                .app_data(web::Data::new(auth.clone()))
                .app_data(web::Data::new(
                    Arc::new(SurrealSessionRepository::new($db.clone()))
                        as Arc<dyn axiam_api_rest::SessionValidator>,
                ))
                .app_data(web::Data::new(state))
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

fn post(uri: &str, body: serde_json::Value) -> test::TestRequest {
    test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(uri)
        .set_json(body)
}

fn with_session(req: test::TestRequest, session: &(String, String)) -> test::TestRequest {
    req.cookie(actix_web::cookie::Cookie::new(
        "axiam_access",
        session.0.clone(),
    ))
    .cookie(actix_web::cookie::Cookie::new(
        "axiam_csrf",
        session.1.clone(),
    ))
    .insert_header(("X-CSRF-Token", session.1.clone()))
}

/// `POST /auth/login`, returning `(access_cookie, csrf_token)` on success.
async fn login(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    ids: &Ids,
    username: &str,
    password: &str,
) -> Option<(String, String)> {
    let resp = test::call_service(
        app,
        post(
            "/api/v1/auth/login",
            serde_json::json!({
                "org_id": ids.org_id,
                "tenant_id": ids.tenant_id,
                "username_or_email": username,
                "password": password,
            }),
        )
        .to_request(),
    )
    .await;
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

fn ksf_from_response(v: &serde_json::Value) -> AxiamKsf {
    AxiamKsf::argon2id(
        v["memory_kib"].as_u64().unwrap() as u32,
        v["iterations"].as_u64().unwrap() as u32,
        v["parallelism"].as_u64().unwrap() as u32,
    )
    .unwrap()
}

/// The `opaque` object a password-setting request carries.
async fn enrollment(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    ids: &Ids,
    password: &str,
) -> serde_json::Value {
    let (state, request) = ClientRegistrationState::start(password).unwrap();
    let resp = test::call_service(
        app,
        post(
            "/api/v1/auth/opaque/register/start",
            serde_json::json!({
                "org_id": ids.org_id,
                "tenant_id": ids.tenant_id,
                "registration_request": request,
            }),
        )
        .to_request(),
    )
    .await;
    assert!(resp.status().is_success(), "register/start must answer");
    let started: serde_json::Value = test::read_body_json(resp).await;
    let outcome = state
        .finish(
            password,
            started["registration_response"].as_str().unwrap(),
            &ksf_from_response(&started),
        )
        .unwrap();
    serde_json::json!({
        "opaque_session": started["opaque_session"].as_str().unwrap(),
        "registration_record": outcome.record,
    })
}

async fn stored_hash(db: &Surreal<TestDb>, ids: &Ids) -> String {
    SurrealUserRepository::new(db.clone())
        .get_by_id(ids.tenant_id, ids.alice)
        .await
        .unwrap()
        .password_hash
}

async fn has_opaque_record(db: &Surreal<TestDb>, ids: &Ids) -> bool {
    SurrealOpaqueCredentialRepository::new(db.clone())
        .get_by_user(ids.tenant_id, ids.alice)
        .await
        .is_ok()
}

fn is_directory_refusal(status: u16, body: &serde_json::Value) -> bool {
    status == 400
        && body["error"] == "validation_error"
        && body["message"]
            .as_str()
            .is_some_and(|m| m.contains("directory"))
}

/// A directory account signs in over `POST /auth/login` through the directory
/// and cannot change its password — not with a record attached, either.
#[actix_web::test]
async fn a_directory_account_signs_in_and_cannot_change_its_password() {
    let (db, ids) = setup("dir-change").await;
    mark_alice(&db, &ids).await;
    let app = app!(db);

    let session = login(&app, &ids, "alice", "the-directory-password")
        .await
        .expect("a directory account signs in through the directory");
    let before = stored_hash(&db, &ids).await;

    let opaque = enrollment(&app, &ids, new_password()).await;
    let resp = test::call_service(
        &app,
        with_session(
            post(
                "/api/v1/auth/password/change",
                serde_json::json!({
                    "current_password": "the-directory-password",
                    "new_password": new_password(),
                    "opaque": opaque,
                }),
            ),
            &session,
        )
        .to_request(),
    )
    .await;
    let status = resp.status().as_u16();
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        is_directory_refusal(status, &body),
        "password change must be refused"
    );
    assert_eq!(
        stored_hash(&db, &ids).await,
        before,
        "no hash may be written"
    );
    assert!(
        !has_opaque_record(&db, &ids).await,
        "no OPAQUE record may be written"
    );
}

/// `POST /auth/reset` answers a directory account exactly as an unknown
/// address, and mints no token.
#[actix_web::test]
async fn a_reset_request_answers_a_directory_account_like_an_unknown_address() {
    let (db, ids) = setup("dir-reset").await;
    mark_alice(&db, &ids).await;
    let app = app!(db);

    let mut answers = Vec::new();
    for email in ["alice@example.com", "nobody@example.com"] {
        let resp = test::call_service(
            &app,
            post(
                "/api/v1/auth/reset",
                serde_json::json!({ "tenant_id": ids.tenant_id, "email": email }),
            )
            .to_request(),
        )
        .await;
        let status = resp.status().as_u16();
        let body: serde_json::Value = test::read_body_json(resp).await;
        answers.push((status, body));
    }
    assert_eq!(
        answers[0], answers[1],
        "a directory account and an unknown address must be answered alike"
    );
    let tokens = SurrealPasswordResetTokenRepository::new(db.clone());
    assert_eq!(
        tokens.count_today(ids.tenant_id, ids.alice).await.unwrap(),
        0
    );
}

/// `POST /auth/reset/confirm` with a token minted before the account became a
/// directory account: refused, and nothing is written — no hash, no record.
#[actix_web::test]
async fn a_reset_confirm_for_a_directory_account_writes_nothing() {
    let (db, ids) = setup("dir-confirm").await;
    let raw = axiam_auth::token::generate_refresh_token();
    SurrealPasswordResetTokenRepository::new(db.clone())
        .create(CreatePasswordResetToken {
            tenant_id: ids.tenant_id,
            user_id: ids.alice,
            token_hash: axiam_auth::token::hash_refresh_token(&raw),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        })
        .await
        .unwrap();
    mark_alice(&db, &ids).await;
    let app = app!(db);
    let before = stored_hash(&db, &ids).await;

    let opaque = enrollment(&app, &ids, new_password()).await;
    let resp = test::call_service(
        &app,
        post(
            "/api/v1/auth/reset/confirm",
            serde_json::json!({
                "tenant_id": ids.tenant_id,
                "token": raw,
                "new_password": new_password(),
                "opaque": opaque,
            }),
        )
        .to_request(),
    )
    .await;
    let status = resp.status().as_u16();
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        is_directory_refusal(status, &body),
        "reset confirm must be refused"
    );
    assert_eq!(
        stored_hash(&db, &ids).await,
        before,
        "no hash may be written"
    );
    assert!(
        !has_opaque_record(&db, &ids).await,
        "no OPAQUE record may be written"
    );
}

/// OPAQUE never authenticates a directory account — even with a valid record
/// written behind the marking. `login/start` serves the decoy (so the client
/// cannot open it), and `login/finish` refuses a KE3 that verified anyway.
#[actix_web::test]
async fn opaque_never_authenticates_a_directory_account() {
    let (db, ids) = setup("dir-opaque").await;
    let app = app!(db);

    // While alice is local, enrol a record for `new_password()` the ordinary
    // way: a password change carrying one.
    let session = login(&app, &ids, "alice", password())
        .await
        .expect("local password login");
    let opaque = enrollment(&app, &ids, new_password()).await;
    let resp = test::call_service(
        &app,
        with_session(
            post(
                "/api/v1/auth/password/change",
                serde_json::json!({
                    "current_password": password(),
                    "new_password": new_password(),
                    "opaque": opaque,
                }),
            ),
            &session,
        )
        .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 204, "local enrolment must succeed");
    let record = SurrealOpaqueCredentialRepository::new(db.clone())
        .get_by_user(ids.tenant_id, ids.alice)
        .await
        .unwrap();

    // Start a real exchange while the record is served...
    let (state, ke1) = ClientLoginState::start(new_password()).unwrap();
    let resp = test::call_service(
        &app,
        post(
            "/api/v1/auth/opaque/login/start",
            serde_json::json!({
                "org_id": ids.org_id,
                "tenant_id": ids.tenant_id,
                "username_or_email": "alice",
                "ke1": ke1,
            }),
        )
        .to_request(),
    )
    .await;
    let started: serde_json::Value = test::read_body_json(resp).await;
    let finished = state
        .finish(
            new_password(),
            started["ke2"].as_str().unwrap(),
            &ksf_from_response(&started),
        )
        .expect("the real record opens");

    // ...then make alice a directory account, and put the record back behind
    // the marking's back.
    mark_alice(&db, &ids).await;
    SurrealOpaqueCredentialRepository::new(db.clone())
        .upsert(axiam_core::models::opaque::CreateOpaqueCredential {
            tenant_id: ids.tenant_id,
            user_id: ids.alice,
            credential_identifier: record.credential_identifier.clone(),
            suite: record.suite,
            ksf_params: record.ksf_params,
            record: record.record.clone(),
        })
        .await
        .unwrap();

    // The finish door: a KE3 that verifies is still refused.
    let resp = test::call_service(
        &app,
        post(
            "/api/v1/auth/opaque/login/finish",
            serde_json::json!({
                "opaque_session": started["opaque_session"].as_str().unwrap(),
                "ke3": finished.ke3,
            }),
        )
        .to_request(),
    )
    .await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "login/finish must refuse a directory account"
    );
    assert_eq!(resp.response().cookies().count(), 0);

    // The start door: a fresh exchange is served the decoy, which the client
    // cannot open even with the right password.
    let (state, ke1) = ClientLoginState::start(new_password()).unwrap();
    let resp = test::call_service(
        &app,
        post(
            "/api/v1/auth/opaque/login/start",
            serde_json::json!({
                "org_id": ids.org_id,
                "tenant_id": ids.tenant_id,
                "username_or_email": "alice",
                "ke1": ke1,
            }),
        )
        .to_request(),
    )
    .await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "login/start answers every identity alike"
    );
    let started: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        state
            .finish(
                new_password(),
                started["ke2"].as_str().unwrap(),
                &ksf_from_response(&started),
            )
            .is_err(),
        "login/start must serve a directory account the decoy"
    );
}

/// The marker is not part of the admin user API: a create or update that
/// names it neither sets nor clears it.
#[actix_web::test]
async fn the_admin_user_api_cannot_set_or_clear_the_marker() {
    let (db, ids) = setup("dir-admin").await;
    mark_alice(&db, &ids).await;
    let app = app!(db);
    let session = login(&app, &ids, "alice", "the-directory-password")
        .await
        .expect("directory sign-in");
    let users = SurrealUserRepository::new(db.clone());

    let resp = test::call_service(
        &app,
        with_session(
            post(
                "/api/v1/users",
                serde_json::json!({
                    "username": "mallory",
                    "email": "mallory@example.com",
                    "password": new_password(),
                    "directory_external_id": ENTRY,
                }),
            ),
            &session,
        )
        .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 201, "the create itself succeeds");
    let created: serde_json::Value = test::read_body_json(resp).await;
    assert!(created.get("directory_external_id").is_none());
    let created_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
    assert!(
        !users
            .get_by_id(ids.tenant_id, created_id)
            .await
            .unwrap()
            .is_directory_account(),
        "a create must not set the marker"
    );

    for (target, value) in [
        (created_id, serde_json::json!(ENTRY)),
        (ids.alice, serde_json::Value::Null),
    ] {
        let resp = test::call_service(
            &app,
            with_session(
                test::TestRequest::put()
                    .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
                    .uri(&format!("/api/v1/users/{target}"))
                    .set_json(serde_json::json!({
                        "metadata": { "note": "edited" },
                        "directory_external_id": value,
                    })),
                &session,
            )
            .to_request(),
        )
        .await;
        assert!(resp.status().is_success(), "the update itself succeeds");
    }
    assert!(
        !users
            .get_by_id(ids.tenant_id, created_id)
            .await
            .unwrap()
            .is_directory_account(),
        "an update must not set the marker"
    );
    assert_eq!(
        users
            .get_by_id(ids.tenant_id, ids.alice)
            .await
            .unwrap()
            .directory_external_id
            .as_deref(),
        Some(ENTRY),
        "an update must not clear the marker"
    );
}
