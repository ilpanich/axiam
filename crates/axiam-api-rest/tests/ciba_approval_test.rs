//! The CIBA approval API over HTTP (T23.7.2, G-7, D-68): the signed-in user's
//! half of a backchannel authentication request.
//!
//! `GET /api/v1/ciba/requests/{id}`, `POST …/approve`, `POST …/deny` — under
//! the user's own session, behind the CSRF check, every route in a rate-limit
//! bucket of its own, every refusal that would reveal whose a request is a
//! plain `404`, and both decisions audited without the client's
//! `binding_message`.
//!
//! No credential literal appears here: client secrets come from the
//! repository, passwords from `axiam_test_support`, keys from `rcgen`.
//!
//! The application state is held as a shared `web::Data` and never as a
//! by-value local, so the test futures stay small (the SAML suites' lesson).

use std::net::SocketAddr;
use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::state::AppState;
use axiam_api_rest::{RateLimitConfig, register_api_v1_routes};
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_core::error::AxiamResult;
use axiam_core::models::ciba::{
    CIBA_GRANT_TYPE, CibaClientMetadata, CibaDeliveryMode, CibaRequestStatus,
};
use axiam_core::models::mail::{MailType, OutboundMailMessage};
use axiam_core::models::oauth2_client::{
    AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateOAuth2Client, ManagedBy,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::{Amr, CreateSession};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, CibaRequestRepository, MailPublisher,
    OAuth2ClientRepository, OrganizationRepository, Pagination, SessionRepository,
    TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOAuth2ClientRepository, SurrealOrganizationRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use axiam_oauth2::ciba::hash_auth_req_id;
use chrono::{Duration, Utc};
use serde_json::Value;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

type TestDb = Db;

const TEST_PEER: &str = "127.0.0.1:34567";
const CSRF_TOKEN: &str = "test-csrf-token";
const MFA: &str = "urn:axiam:acr:mfa";
/// The client's `binding_message`: personal-data-shaped on purpose, so a test
/// can assert it is in no audit row.
const BINDING: &str = "Confirm J.Doe 42 EUR";

/// The mail queue, as the notifier sees it: records what is published.
#[derive(Clone, Default)]
struct RecordingMail {
    sent: Arc<std::sync::Mutex<Vec<OutboundMailMessage>>>,
}

impl MailPublisher for RecordingMail {
    async fn publish(&self, msg: OutboundMailMessage) -> AxiamResult<()> {
        self.sent.lock().unwrap().push(msg);
        Ok(())
    }
}

struct CibaClient {
    client_id: String,
    secret: String,
}

struct World {
    db: Surreal<TestDb>,
    auth: AuthConfig,
    state: web::Data<AppState<TestDb>>,
    tenant_id: Uuid,
    org_id: Uuid,
    alice: Uuid,
    bob: Uuid,
    client: CibaClient,
}

fn auth_config() -> AuthConfig {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair");
    AuthConfig {
        jwt_private_key_pem: kp.serialize_pem(),
        jwt_public_key_pem: kp.public_key_pem(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: "https://id.test.example".into(),
        sso_spa_origins: Vec::new(),
        ..AuthConfig::default()
    }
}

fn limits() -> RateLimitConfig {
    RateLimitConfig {
        token_per_min: 10_000,
        bc_authorize_per_min: 10_000,
        ciba_approval_per_min: 10_000,
        ..RateLimitConfig::default()
    }
}

async fn active_user(db: &Surreal<TestDb>, tenant_id: Uuid, name: &str) -> Uuid {
    let users = SurrealUserRepository::new(db.clone());
    let user = users
        .create(CreateUser {
            tenant_id,
            username: name.into(),
            email: format!("{name}@example.com"),
            password: axiam_test_support::test_password(),
            metadata: None,
        })
        .await
        .unwrap();
    users
        .update(
            tenant_id,
            user.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    user.id
}

async fn world_db() -> (Surreal<TestDb>, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "ciba approval org".into(),
            slug: "org-ciba-approval".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "ciba approval tenant".into(),
            slug: "tenant-ciba-approval".into(),
            metadata: None,
        })
        .await
        .unwrap();
    (db, org.id, tenant.id)
}

async fn ciba_client(db: &Surreal<TestDb>, tenant_id: Uuid) -> CibaClient {
    let (client, secret) = SurrealOAuth2ClientRepository::new(db.clone())
        .create(CreateOAuth2Client {
            tenant_id,
            name: "Call Centre".into(),
            redirect_uris: vec!["https://rp.test.example/cb".into()],
            grant_types: vec![CIBA_GRANT_TYPE.to_owned(), "refresh_token".to_owned()],
            scopes: vec!["openid".into(), "profile".into()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
            profile: ClientProfile::Standard,
            token_endpoint_auth_method: ClientAuthMethod::ClientSecretPost,
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
            managed_by: ManagedBy::Admin,
            ciba: CibaClientMetadata {
                backchannel_token_delivery_mode: Some(CibaDeliveryMode::Poll),
                ..Default::default()
            },
        })
        .await
        .unwrap();
    CibaClient {
        client_id: client.client_id,
        secret,
    }
}

fn shared_state(db: &Surreal<TestDb>, auth: &AuthConfig) -> web::Data<AppState<TestDb>> {
    let mut state = AppState::for_test(db.clone(), auth.clone());
    state.rate_limit_cfg = limits();
    web::Data::new(state)
}

/// A state whose notifier is the production one, over `mail`.
fn mailing_state(
    db: &Surreal<TestDb>,
    auth: &AuthConfig,
    mail: RecordingMail,
) -> web::Data<AppState<TestDb>> {
    let mut state = AppState::for_test(db.clone(), auth.clone());
    state.rate_limit_cfg = limits();
    state.oauth2.ciba_notifier = Arc::new(axiam_oauth2::ciba_notifier::CibaMailNotifier::new(
        SurrealUserRepository::new(db.clone()),
        SurrealTenantRepository::new(db.clone()),
        mail,
        &auth.oauth2_issuer_url,
    ));
    web::Data::new(state)
}

async fn world() -> World {
    let (db, org_id, tenant_id) = Box::pin(world_db()).await;
    let alice = Box::pin(active_user(&db, tenant_id, "alice")).await;
    let bob = Box::pin(active_user(&db, tenant_id, "bob")).await;
    let client = Box::pin(ciba_client(&db, tenant_id)).await;
    let auth = auth_config();
    let state = shared_state(&db, &auth);
    World {
        db,
        auth,
        state,
        tenant_id,
        org_id,
        alice,
        bob,
        client,
    }
}

macro_rules! app {
    ($w:expr, $limits:expr) => {{
        let limits: RateLimitConfig = $limits;
        test::init_service(
            App::new()
                .app_data(web::Data::new($w.auth.clone()))
                .app_data($w.state.clone())
                .app_data(web::Data::new(
                    Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
                ))
                .configure(|cfg| register_api_v1_routes::<TestDb>(cfg, &limits)),
        )
        .await
    }};
}

/// A session for `user` that authenticated with `amr`, and the bearer token the
/// console would hold for it (`jti` = the session id).
async fn session_token(w: &World, user: Uuid, amr: Vec<Amr>) -> String {
    let session = w
        .state
        .session_repo
        .create(CreateSession {
            tenant_id: w.tenant_id,
            user_id: user,
            token_hash: Uuid::new_v4().simple().to_string(),
            ip_address: None,
            user_agent: None,
            expires_at: Utc::now() + Duration::hours(1),
            authenticated_at: Utc::now() - Duration::seconds(20),
            amr,
            browser_token_hash: None,
        })
        .await
        .unwrap();
    issue_access_token(
        user,
        w.tenant_id,
        w.org_id,
        &[],
        &w.auth,
        session.id.to_string(),
        AUD_USER,
    )
    .unwrap()
}

/// A token whose `jti` names no session row: what a machine or a stale token
/// looks like to the approval routes.
fn sessionless_token(w: &World, user: Uuid) -> String {
    issue_access_token(
        user,
        w.tenant_id,
        w.org_id,
        &[],
        &w.auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap()
}

fn peer() -> SocketAddr {
    TEST_PEER.parse().unwrap()
}

fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

async fn form_post(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    path: &str,
    body: String,
) -> (u16, Value) {
    let req = test::TestRequest::post()
        .peer_addr(peer())
        .uri(path)
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .set_payload(body)
        .to_request();
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    let bytes = test::read_body(resp).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// `bc-authorize` as the world's client; returns `(auth_req_id, record id)`.
async fn start(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    w: &World,
    login_hint: &str,
    extra: &str,
) -> (String, Uuid) {
    start_as(app, w, &w.client, login_hint, extra).await
}

/// `bc-authorize` as `client`.
async fn start_as(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    w: &World,
    client: &CibaClient,
    login_hint: &str,
    extra: &str,
) -> (String, Uuid) {
    let (status, body) = form_post(
        app,
        &format!("/oauth2/bc-authorize?tenant_id={}", w.tenant_id),
        format!(
            "client_id={}&client_secret={}&scope=openid%20profile&login_hint={login_hint}\
             &binding_message={}{extra}",
            client.client_id,
            client.secret,
            enc(BINDING)
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let auth_req_id = body["auth_req_id"].as_str().unwrap().to_owned();
    let row = w
        .state
        .oauth2
        .ciba_service
        .requests()
        .get_by_hash(w.tenant_id, &hash_auth_req_id(&auth_req_id))
        .await
        .unwrap()
        .expect("stored");
    (auth_req_id, row.id)
}

async fn poll(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    w: &World,
    auth_req_id: &str,
) -> (u16, Value) {
    // Outside the polling interval, without sleeping five seconds.
    w.db.query(
        "UPDATE ciba_request SET last_polled_at = time::now() - 1m \
         WHERE auth_req_id_hash = $hash",
    )
    .bind(("hash", hash_auth_req_id(auth_req_id)))
    .await
    .unwrap();
    form_post(
        app,
        &format!("/oauth2/token?tenant_id={}", w.tenant_id),
        format!(
            "grant_type={}&client_id={}&client_secret={}&auth_req_id={}",
            enc(CIBA_GRANT_TYPE),
            w.client.client_id,
            w.client.secret,
            enc(auth_req_id)
        ),
    )
    .await
}

async fn get_page(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    id: Uuid,
    token: &str,
) -> (u16, Value) {
    let req = test::TestRequest::get()
        .peer_addr(peer())
        .uri(&format!("/api/v1/ciba/requests/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    let bytes = test::read_body(resp).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn decide(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    id: Uuid,
    verb: &str,
    version: u64,
    token: &str,
) -> (u16, Value) {
    let req = test::TestRequest::post()
        .peer_addr(peer())
        .uri(&format!("/api/v1/ciba/requests/{id}/{verb}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .set_json(serde_json::json!({ "version": version }))
        .to_request();
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    let bytes = test::read_body(resp).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn row(w: &World, id: Uuid) -> axiam_core::models::ciba::CibaRequest {
    w.state
        .oauth2
        .ciba_service
        .requests()
        .get_by_id(w.tenant_id, id)
        .await
        .unwrap()
        .expect("the request row")
}

async fn audit_rows(w: &World, action: &str) -> Vec<axiam_core::models::audit::AuditLogEntry> {
    AuditLogRepository::list(
        &axiam_db::SurrealAuditLogRepository::new(w.db.clone()),
        w.tenant_id,
        AuditLogFilter {
            action: Some(action.into()),
            ..Default::default()
        },
        Pagination::default(),
    )
    .await
    .unwrap()
    .items
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

/// The signed-in user opens the request, approves it, and the client's poll
/// gets tokens that name the approving session. The page shows the client's
/// name, the scopes and the binding message — and never the `auth_req_id`.
#[actix_web::test]
async fn the_signed_in_user_approves_and_the_clients_poll_gets_tokens() {
    let w = world().await;
    let app = app!(w, limits());
    let (auth_req_id, id) = start(&app, &w, "alice", "").await;
    let token = session_token(&w, w.alice, vec![Amr::Pwd]).await;

    // Pending until she decides.
    let (status, body) = poll(&app, &w, &auth_req_id).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("authorization_pending"))
    );

    let (status, page) = get_page(&app, id, &token).await;
    assert_eq!(status, 200, "{page}");
    assert_eq!(page["client_name"], "Call Centre");
    assert_eq!(page["client_id"], w.client.client_id);
    assert_eq!(page["scopes"], serde_json::json!(["openid", "profile"]));
    assert_eq!(page["binding_message"], BINDING);
    assert_eq!(page["step_up_required"], Value::Null);
    assert_eq!(page["requested_acr"], serde_json::json!([]));
    assert!(page["expires_at"].is_string());
    let rendered = page.to_string();
    assert!(
        !rendered.contains(&auth_req_id) && !rendered.contains("auth_req_id"),
        "the page never carries the auth_req_id"
    );
    let version = page["version"].as_u64().unwrap();

    let (status, done) = decide(&app, id, "approve", version, &token).await;
    assert_eq!(status, 200, "{done}");
    assert_eq!(done["decision"], "approved");
    assert_eq!(row(&w, id).await.status, CibaRequestStatus::Approved);

    let (status, tokens) = poll(&app, &w, &auth_req_id).await;
    assert_eq!(status, 200, "{tokens}");
    let id_token = decode_unverified(tokens["id_token"].as_str().unwrap());
    assert_eq!(id_token["sub"], w.alice.to_string());
    let access = decode_unverified(tokens["access_token"].as_str().unwrap());
    let evidence = row(&w, id).await.approval.expect("evidence");
    assert_eq!(
        access["sid"],
        evidence.session_id.to_string(),
        "the tokens are bound to the approving session (D-67)"
    );
    assert_eq!(evidence.amr, vec![Amr::Pwd]);

    // A request already decided is gone from the page.
    assert_eq!(get_page(&app, id, &token).await.0, 404);
}

#[actix_web::test]
async fn the_signed_in_user_denies_and_the_clients_poll_gets_access_denied() {
    let w = world().await;
    let app = app!(w, limits());
    let (auth_req_id, id) = start(&app, &w, "alice", "").await;
    let token = session_token(&w, w.alice, vec![Amr::Pwd]).await;
    let (_, page) = get_page(&app, id, &token).await;

    let (status, done) = decide(&app, id, "deny", page["version"].as_u64().unwrap(), &token).await;
    assert_eq!(status, 200, "{done}");
    assert_eq!(done["decision"], "denied");
    assert_eq!(row(&w, id).await.status, CibaRequestStatus::Denied);

    let (status, body) = poll(&app, &w, &auth_req_id).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("access_denied"))
    );
}

/// Another user's request is indistinguishable from an unknown id — on the
/// page, on approve and on deny — and is left exactly as it was.
#[actix_web::test]
async fn another_users_request_is_a_404_identical_to_an_unknown_id() {
    let w = world().await;
    let app = app!(w, limits());
    let (_, id) = start(&app, &w, "alice", "").await;
    let alice = session_token(&w, w.alice, vec![Amr::Pwd]).await;
    let bob = session_token(&w, w.bob, vec![Amr::Pwd, Amr::Otp, Amr::Mfa]).await;
    let version = get_page(&app, id, &alice).await.1["version"]
        .as_u64()
        .unwrap();
    let unknown = Uuid::new_v4();

    let theirs = get_page(&app, id, &bob).await;
    let nobodys = get_page(&app, unknown, &bob).await;
    assert_eq!(theirs.0, 404);
    assert_eq!(
        theirs, nobodys,
        "one answer for 'not yours' and 'not there'"
    );
    for verb in ["approve", "deny"] {
        let theirs = decide(&app, id, verb, version, &bob).await;
        let nobodys = decide(&app, unknown, verb, version, &bob).await;
        assert_eq!(theirs.0, 404, "{verb}");
        assert_eq!(theirs, nobodys, "{verb}: one answer");
    }
    let still = row(&w, id).await;
    assert_eq!(still.status, CibaRequestStatus::Pending, "untouched");
    assert_eq!(still.version, version as u64);
    assert!(audit_rows(&w, "ciba.approved").await.is_empty());
    assert!(audit_rows(&w, "ciba.denied").await.is_empty());
}

/// A request for a hint that named nobody has no user: nobody can see or
/// decide it, and it answers like any unknown id.
#[actix_web::test]
async fn a_decoy_request_for_nobody_cannot_be_opened_by_anyone() {
    let w = world().await;
    let app = app!(w, limits());
    let (_, id) = start(&app, &w, "nobody-by-this-name", "").await;
    let token = session_token(&w, w.alice, vec![Amr::Pwd]).await;
    assert_eq!(get_page(&app, id, &token).await.0, 404);
    assert_eq!(decide(&app, id, "approve", 1, &token).await.0, 404);
}

/// A request that asks for MFA, from a password session: the page says so up
/// front, `approve` is refused with the class to step up to and changes
/// nothing, and a session that did multi-factor then approves it.
#[actix_web::test]
async fn a_request_for_mfa_needs_a_step_up_and_then_approves() {
    let w = world().await;
    let app = app!(w, limits());
    let (auth_req_id, id) = start(&app, &w, "alice", &format!("&acr_values={}", enc(MFA))).await;
    let weak = session_token(&w, w.alice, vec![Amr::Pwd]).await;

    let (status, page) = get_page(&app, id, &weak).await;
    assert_eq!(status, 200, "{page}");
    assert_eq!(page["requested_acr"], serde_json::json!([MFA]));
    assert_eq!(page["step_up_required"], MFA);
    let version = page["version"].as_u64().unwrap();

    let (status, refused) = decide(&app, id, "approve", version, &weak).await;
    assert_eq!(status, 403, "{refused}");
    assert_eq!(refused["error"], "step_up_required");
    assert_eq!(refused["required_acr"], MFA);
    assert_eq!(row(&w, id).await.status, CibaRequestStatus::Pending);
    assert!(audit_rows(&w, "ciba.approved").await.is_empty());

    // Refusing needs no step-up.
    // (Not done here: it would end the request; see the deny test above.)

    // The step-up: the same request, a session that did a second factor. The
    // request was not consumed by the weak attempt, so the page reads it fresh.
    let strong = session_token(&w, w.alice, vec![Amr::Pwd, Amr::Otp, Amr::Mfa]).await;
    let (status, page) = get_page(&app, id, &strong).await;
    assert_eq!(status, 200, "{page}");
    assert_eq!(page["step_up_required"], Value::Null);
    let (status, done) = decide(
        &app,
        id,
        "approve",
        page["version"].as_u64().unwrap(),
        &strong,
    )
    .await;
    assert_eq!(status, 200, "{done}");

    let (status, tokens) = poll(&app, &w, &auth_req_id).await;
    assert_eq!(status, 200, "{tokens}");
    let id_token = decode_unverified(tokens["id_token"].as_str().unwrap());
    assert_eq!(id_token["acr"], MFA);
}

#[actix_web::test]
async fn refusing_needs_no_step_up() {
    let w = world().await;
    let app = app!(w, limits());
    let (_, id) = start(&app, &w, "alice", &format!("&acr_values={}", enc(MFA))).await;
    let weak = session_token(&w, w.alice, vec![Amr::Pwd]).await;
    let (_, page) = get_page(&app, id, &weak).await;
    let (status, done) = decide(&app, id, "deny", page["version"].as_u64().unwrap(), &weak).await;
    assert_eq!(status, 200, "{done}");
    assert_eq!(row(&w, id).await.status, CibaRequestStatus::Denied);
}

#[actix_web::test]
async fn an_expired_request_is_refused_on_the_page_and_on_both_decisions() {
    let w = world().await;
    let app = app!(w, limits());
    let (_, id) = start(&app, &w, "alice", "").await;
    let token = session_token(&w, w.alice, vec![Amr::Pwd]).await;
    let version = get_page(&app, id, &token).await.1["version"]
        .as_u64()
        .unwrap();

    w.db.query("UPDATE ciba_request SET expires_at = time::now() - 1m")
        .await
        .unwrap();

    assert_eq!(get_page(&app, id, &token).await.0, 404);
    assert_eq!(decide(&app, id, "approve", version, &token).await.0, 404);
    assert_eq!(decide(&app, id, "deny", version, &token).await.0, 404);
    assert_ne!(row(&w, id).await.status, CibaRequestStatus::Approved);
    assert!(audit_rows(&w, "ciba.approved").await.is_empty());
}

/// D-68: a decision is conditional on the version the page read.
#[actix_web::test]
async fn a_decision_on_a_stale_version_is_refused() {
    let w = world().await;
    let app = app!(w, limits());
    let (_, id) = start(&app, &w, "alice", "").await;
    let token = session_token(&w, w.alice, vec![Amr::Pwd]).await;
    let version = get_page(&app, id, &token).await.1["version"]
        .as_u64()
        .unwrap();
    for stale in [version + 1, version + 7] {
        for verb in ["approve", "deny"] {
            assert_eq!(decide(&app, id, verb, stale, &token).await.0, 404, "{verb}");
        }
    }
    assert_eq!(row(&w, id).await.status, CibaRequestStatus::Pending);
    assert_eq!(decide(&app, id, "approve", version, &token).await.0, 200);
    // And a second decision on the decided request is the same 404.
    assert_eq!(decide(&app, id, "deny", version, &token).await.0, 404);
}

/// Approval and refusal are audited — the user, the request, the client and
/// the mode, and for an approval the `acr` — and never the binding message.
#[actix_web::test]
async fn both_decisions_are_audited_without_the_binding_message() {
    let w = world().await;
    let app = app!(w, limits());
    let (_, approved) = start(&app, &w, "alice", "").await;
    let (_, denied) = start(&app, &w, "alice", "").await;
    let token = session_token(&w, w.alice, vec![Amr::Pwd, Amr::Otp, Amr::Mfa]).await;
    for (id, verb) in [(approved, "approve"), (denied, "deny")] {
        let version = get_page(&app, id, &token).await.1["version"]
            .as_u64()
            .unwrap();
        assert_eq!(decide(&app, id, verb, version, &token).await.0, 200);
    }

    let yes = audit_rows(&w, "ciba.approved").await;
    let no = audit_rows(&w, "ciba.denied").await;
    assert_eq!((yes.len(), no.len()), (1, 1));
    assert_eq!(yes[0].actor_id, w.alice);
    assert_eq!(yes[0].resource_id, Some(approved));
    assert_eq!(no[0].actor_id, w.alice);
    assert_eq!(no[0].resource_id, Some(denied));
    let metadata = yes[0].metadata.clone();
    assert_eq!(metadata["client_id"], w.client.client_id);
    assert_eq!(metadata["delivery_mode"], "poll");
    assert_eq!(metadata["acr"], MFA);
    for entry in yes.iter().chain(no.iter()) {
        let rendered = serde_json::to_string(entry).unwrap();
        assert!(
            !rendered.contains("J.Doe") && !rendered.contains("42 EUR"),
            "the binding message is never in the audit log"
        );
    }
}

#[actix_web::test]
async fn the_routes_need_a_session_and_a_csrf_token() {
    let w = world().await;
    let app = app!(w, limits());
    let (_, id) = start(&app, &w, "alice", "").await;

    // No credential at all.
    let req = test::TestRequest::get()
        .peer_addr(peer())
        .uri(&format!("/api/v1/ciba/requests/{id}"))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 401);

    // A token for the right user whose session is not in the store: refused,
    // by every route, and nothing is decided.
    let sessionless = sessionless_token(&w, w.alice);
    assert_eq!(get_page(&app, id, &sessionless).await.0, 403);
    assert_eq!(decide(&app, id, "approve", 1, &sessionless).await.0, 403);
    assert_eq!(decide(&app, id, "deny", 1, &sessionless).await.0, 403);
    assert_eq!(row(&w, id).await.status, CibaRequestStatus::Pending);

    // A browser's session is a cookie, so a decision without the CSRF header
    // is a cross-site POST: refused, and nothing is decided. (A bearer token is
    // no ambient credential and is not subject to the check.)
    let token = session_token(&w, w.alice, vec![Amr::Pwd]).await;
    let version = get_page(&app, id, &token).await.1["version"]
        .as_u64()
        .unwrap();
    let req = test::TestRequest::post()
        .peer_addr(peer())
        .uri(&format!("/api/v1/ciba/requests/{id}/approve"))
        .insert_header((
            "Cookie",
            format!("axiam_access={token}; axiam_csrf={CSRF_TOKEN}"),
        ))
        .set_json(serde_json::json!({ "version": version }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 403);
    assert_eq!(row(&w, id).await.status, CibaRequestStatus::Pending);

    // The same request with the header the console's client adds is decided.
    let req = test::TestRequest::post()
        .peer_addr(peer())
        .uri(&format!("/api/v1/ciba/requests/{id}/approve"))
        .insert_header((
            "Cookie",
            format!("axiam_access={token}; axiam_csrf={CSRF_TOKEN}"),
        ))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "version": version }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 200);
    assert_eq!(row(&w, id).await.status, CibaRequestStatus::Approved);
}

/// Each route has its own bucket, and the limiter counts it: with an allowance
/// of two, the third call to a route is `429` while the other two routes still
/// have theirs.
#[actix_web::test]
async fn each_route_has_a_rate_limit_bucket_of_its_own() {
    let w = world().await;
    let tight = RateLimitConfig {
        ciba_approval_per_min: 2,
        ..limits()
    };
    let app = app!(w, tight);
    let token = session_token(&w, w.alice, vec![Amr::Pwd]).await;
    let unknown = Uuid::new_v4();

    let mut reads = Vec::new();
    for _ in 0..4 {
        reads.push(get_page(&app, unknown, &token).await.0);
    }
    assert_eq!(reads, [404, 404, 429, 429], "the page route is counted");

    // The decision routes did not spend the page's allowance, nor each other's.
    for verb in ["approve", "deny"] {
        let mut seen = Vec::new();
        for _ in 0..4 {
            seen.push(decide(&app, unknown, verb, 1, &token).await.0);
        }
        assert_eq!(seen, [404, 404, 429, 429], "{verb} has its own bucket");
    }
}

#[actix_web::test]
async fn the_shipped_allowance_is_thirty_a_minute_per_route() {
    assert_eq!(RateLimitConfig::default().ciba_approval_per_min, 30);
}

/// The two registered clients' names reach the page; a deleted client falls
/// back to its id rather than failing the page.
#[actix_web::test]
async fn a_deleted_client_falls_back_to_its_id_on_the_page() {
    let w = world().await;
    let app = app!(w, limits());
    let (_, id) = start(&app, &w, "alice", "").await;
    let token = session_token(&w, w.alice, vec![Amr::Pwd]).await;
    let repo = SurrealOAuth2ClientRepository::new(w.db.clone());
    let client = repo
        .get_by_client_id(w.tenant_id, &w.client.client_id)
        .await
        .unwrap();
    repo.delete(w.tenant_id, client.id).await.unwrap();
    let (status, page) = get_page(&app, id, &token).await;
    assert_eq!(status, 200, "{page}");
    assert_eq!(page["client_name"], w.client.client_id);
}

// ---------------------------------------------------------------------------
// T-424: the sign-in prompt flood
// ---------------------------------------------------------------------------

/// Do not straddle a minute boundary: the per-user budget is per minute.
async fn avoid_the_minute_boundary() {
    use chrono::Timelike;
    let second = Utc::now().second();
    if second >= 54 {
        tokio::time::sleep(std::time::Duration::from_secs(u64::from(61 - second))).await;
    }
}

async fn settled(mail: &RecordingMail) -> Vec<OutboundMailMessage> {
    // The notifications are detached from the responses: wait until the count
    // has stopped moving.
    let mut last = usize::MAX;
    let mut stable = 0;
    for _ in 0..200 {
        let now = mail.sent.lock().unwrap().len();
        if now == last {
            stable += 1;
            if stable >= 15 {
                break;
            }
        } else {
            stable = 0;
            last = now;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    mail.sent.lock().unwrap().clone()
}

/// A flood of `bc-authorize` for one user, from two clients, cannot produce more
/// than the budgeted mails — three a minute — while every request is still
/// stored and answered like any other, so the throttle reveals nothing about the
/// user (D-63, D-70). The mail that does go carries the binding message and a
/// link, and never the `auth_req_id`.
#[actix_web::test]
async fn a_flood_of_requests_for_one_user_sends_at_most_three_mails_a_minute() {
    avoid_the_minute_boundary().await;
    let mut w = world().await;
    let mail = RecordingMail::default();
    w.state = mailing_state(&w.db, &w.auth, mail.clone());
    let second_client = ciba_client(&w.db, w.tenant_id).await;
    let app = app!(w, limits());

    let mut auth_req_ids = Vec::new();
    for i in 0..12 {
        let (id, _) = start_as(
            &app,
            &w,
            if i % 2 == 0 {
                &w.client
            } else {
                &second_client
            },
            "alice",
            "",
        )
        .await;
        auth_req_ids.push(id);
    }
    assert_eq!(
        auth_req_ids.len(),
        12,
        "every request was stored and answered"
    );

    let sent = settled(&mail).await;
    assert_eq!(
        sent.len(),
        3,
        "twelve requests, three mails: the per-user budget no preset moves"
    );
    for message in &sent {
        assert_eq!(message.mail_type, MailType::CibaApproval);
        assert_eq!(message.user_id, w.alice);
        let ctx = message.template_context.as_object().unwrap();
        assert_eq!(ctx["binding_message"], BINDING);
        assert!(
            ctx["action_url"]
                .as_str()
                .unwrap()
                .starts_with("https://id.test.example/ciba/approve?request_id="),
        );
        let rendered = serde_json::to_string(message).unwrap();
        for auth_req_id in &auth_req_ids {
            assert!(
                !rendered.contains(auth_req_id.as_str()),
                "no auth_req_id in a mail"
            );
        }
    }

    // Another user has a budget of their own.
    let (_, _) = start_as(&app, &w, &w.client, "bob", "").await;
    let sent = settled(&mail).await;
    assert_eq!(sent.len(), 4);
    assert_eq!(sent[3].user_id, w.bob);
}

/// A user who is unknown, or who may not sign in, is mailed nothing — and the
/// response is the same, so the mail cannot be used to find them.
#[actix_web::test]
async fn a_request_for_nobody_sends_no_mail() {
    let mut w = world().await;
    let mail = RecordingMail::default();
    w.state = mailing_state(&w.db, &w.auth, mail.clone());
    let app = app!(w, limits());
    let _ = start(&app, &w, "nobody-by-this-name", "").await;
    assert!(settled(&mail).await.is_empty());
}
