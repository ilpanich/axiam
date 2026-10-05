//! CIBA over HTTP (T23.7.1, G-7): `POST /oauth2/bc-authorize`, the
//! `auth_req_id` lifecycle through the approval service API, and the CIBA
//! grant at the token endpoint.
//!
//! What only exists once the routes are mounted: client authentication at
//! `bc-authorize` exactly as at the token endpoint (and its audit), every CIBA
//! Core §13 refusal on the wire, the user-oracle resistance of the hint, poll
//! back-off, every token-endpoint answer of §11, tokens carrying the approval's
//! evidence, single use under concurrency, the rate limits that must count this
//! grant (the Keycloak 26.7.x class), lockout, discovery in both issuer forms,
//! and the admin and RFC 7591 registration of the metadata.
//!
//! No credential literal appears here: client secrets come from the
//! repository, passwords from `axiam_test_support`, keys from `rcgen`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use actix_web::{App, test, web};
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::state::AppState;
use axiam_api_rest::{RateLimitConfig, RouteOptions, register_api_v1_routes_with};
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, IdTokenEvidence, issue_access_token, issue_id_token};
use axiam_core::models::ciba::{
    CIBA_GRANT_TYPE, CibaClientMetadata, CibaDeliveryMode, CibaNotifyFuture, CibaRequestStatus,
    CibaUserNotification, CibaUserNotifier,
};
use axiam_core::models::oauth2_client::{
    AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateOAuth2Client, ManagedBy,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::Amr;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, CibaRequestRepository, OAuth2ClientRepository,
    OrganizationRepository, Pagination, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOAuth2ClientRepository, SurrealOrganizationRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use axiam_oauth2::ciba::{CibaApproval, CibaDecisionOutcome, hash_auth_req_id};
use chrono::{Duration, Utc};
use serde_json::Value;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem, SurrealKv};
use uuid::Uuid;

type TestDb = Db;

const TEST_PEER: &str = "127.0.0.1:34567";
const CSRF_TOKEN: &str = "test-csrf-token";

fn test_auth_config() -> AuthConfig {
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

/// A notifier that records what it was asked to send.
#[derive(Default)]
struct RecordingNotifier {
    sent: Mutex<Vec<CibaUserNotification>>,
}

impl CibaUserNotifier for RecordingNotifier {
    fn notify(&self, notification: CibaUserNotification) -> CibaNotifyFuture<'_> {
        self.sent.lock().unwrap().push(notification);
        Box::pin(async { Ok(()) })
    }
}

struct CibaClient {
    client_id: String,
    secret: String,
}

struct Fixture {
    db: Surreal<TestDb>,
    auth: AuthConfig,
    state: AppState<TestDb>,
    notifier: Arc<RecordingNotifier>,
    tenant_id: Uuid,
    org_id: Uuid,
    user_id: Uuid,
    /// A poll-mode CIBA client with the refresh grant.
    ciba: CibaClient,
    /// A second poll-mode CIBA client in the same tenant.
    other: CibaClient,
    /// A confidential client without the CIBA grant.
    plain: CibaClient,
}

fn create_input(
    tenant_id: Uuid,
    name: &str,
    grants: &[&str],
    ciba: CibaClientMetadata,
) -> CreateOAuth2Client {
    CreateOAuth2Client {
        tenant_id,
        name: name.into(),
        redirect_uris: vec!["https://rp.test.example/cb".into()],
        grant_types: grants.iter().map(|g| (*g).to_owned()).collect(),
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
        ciba,
    }
}

fn poll_mode() -> CibaClientMetadata {
    CibaClientMetadata {
        backchannel_token_delivery_mode: Some(CibaDeliveryMode::Poll),
        backchannel_client_notification_endpoint: None,
    }
}

async fn create_client(
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
    name: &str,
    grants: &[&str],
    ciba: CibaClientMetadata,
) -> CibaClient {
    let (client, secret) = SurrealOAuth2ClientRepository::new(db.clone())
        .create(create_input(tenant_id, name, grants, ciba))
        .await
        .unwrap();
    CibaClient {
        client_id: client.client_id,
        secret,
    }
}

async fn tenant_with_user(db: &Surreal<TestDb>, slug: &str) -> (Uuid, Uuid, Uuid) {
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: format!("{slug} org"),
            slug: format!("org-{slug}"),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: format!("{slug} tenant"),
            slug: format!("tenant-{slug}"),
            metadata: None,
        })
        .await
        .unwrap();
    let users = SurrealUserRepository::new(db.clone());
    let user = users
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: axiam_test_support::test_password(),
            metadata: None,
        })
        .await
        .unwrap();
    users
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
    (org.id, tenant.id, user.id)
}

async fn setup_on(db: Surreal<TestDb>) -> Fixture {
    let (org_id, tenant_id, user_id) = tenant_with_user(&db, "ciba").await;
    let ciba = create_client(
        &db,
        tenant_id,
        "call-centre",
        &[CIBA_GRANT_TYPE, "refresh_token"],
        poll_mode(),
    )
    .await;
    let other = create_client(&db, tenant_id, "other", &[CIBA_GRANT_TYPE], poll_mode()).await;
    let plain = create_client(
        &db,
        tenant_id,
        "plain",
        &["authorization_code"],
        CibaClientMetadata::default(),
    )
    .await;
    let auth = test_auth_config();
    let notifier = Arc::new(RecordingNotifier::default());
    let mut state = AppState::for_test(db.clone(), auth.clone());
    state.oauth2.ciba_notifier = notifier.clone();
    Fixture {
        db,
        auth,
        state,
        notifier,
        tenant_id,
        org_id,
        user_id,
        ciba,
        other,
        plain,
    }
}

async fn setup() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    setup_on(db).await
}

fn permissive() -> RateLimitConfig {
    RateLimitConfig {
        token_per_min: 10_000,
        bc_authorize_per_min: 10_000,
        ..RateLimitConfig::default()
    }
}

macro_rules! app {
    ($f:expr, $limits:expr) => {
        app!($f, $limits, false)
    };
    ($f:expr, $limits:expr, $paths:expr) => {{
        let limits: RateLimitConfig = $limits;
        let mut state = $f.state.clone();
        state.rate_limit_cfg = limits.clone();
        test::init_service(
            App::new()
                .app_data(web::Data::new($f.auth.clone()))
                .app_data(web::Data::new(state))
                .app_data(web::Data::new(
                    Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
                ))
                .configure(|cfg| {
                    register_api_v1_routes_with::<TestDb>(
                        cfg,
                        &limits,
                        RouteOptions {
                            tenant_issuer_paths: $paths,
                            ..RouteOptions::default()
                        },
                    )
                }),
        )
        .await
    }};
}

fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// POST `bc-authorize` with `body` (form-encoded, credentials included by the
/// caller), on the root path or a tenant path.
async fn post_form(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    path: &str,
    body: String,
) -> (u16, Value) {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(path)
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .set_payload(body)
        .to_request();
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    let bytes = test::read_body(resp).await;
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

fn bc_body(client: &CibaClient, extra: &str) -> String {
    format!(
        "client_id={}&client_secret={}&scope=openid%20profile{extra}",
        client.client_id, client.secret
    )
}

fn token_body(client: &CibaClient, auth_req_id: &str) -> String {
    format!(
        "grant_type={}&client_id={}&client_secret={}&auth_req_id={}",
        enc(CIBA_GRANT_TYPE),
        client.client_id,
        client.secret,
        enc(auth_req_id)
    )
}

macro_rules! bc_authorize {
    ($app:expr, $f:expr, $client:expr, $extra:expr) => {
        post_form(
            &$app,
            &format!("/oauth2/bc-authorize?tenant_id={}", $f.tenant_id),
            bc_body($client, $extra),
        )
        .await
    };
}

macro_rules! token {
    ($app:expr, $f:expr, $client:expr, $id:expr) => {
        post_form(
            &$app,
            &format!("/oauth2/token?tenant_id={}", $f.tenant_id),
            token_body($client, $id),
        )
        .await
    };
}

/// Move a request's last poll into the past, so the next token request is
/// outside its interval (the test does not sleep five seconds).
async fn age_poll(f: &Fixture, auth_req_id: &str) {
    f.db.query(
        "UPDATE ciba_request SET last_polled_at = time::now() - 1m \
         WHERE auth_req_id_hash = $hash",
    )
    .bind(("hash", hash_auth_req_id(auth_req_id)))
    .await
    .unwrap();
}

async fn stored(f: &Fixture, auth_req_id: &str) -> axiam_core::models::ciba::CibaRequest {
    f.state
        .oauth2
        .ciba_service
        .requests()
        .get_by_hash(f.tenant_id, &hash_auth_req_id(auth_req_id))
        .await
        .unwrap()
        .expect("the request is stored")
}

fn approval(user_id: Uuid, session_id: Uuid, amr: Vec<Amr>) -> CibaApproval {
    CibaApproval {
        user_id,
        session_id,
        auth_time: Utc::now() - Duration::seconds(30),
        amr,
    }
}

async fn approve(f: &Fixture, auth_req_id: &str, session_id: Uuid) {
    let row = stored(f, auth_req_id).await;
    let outcome = f
        .state
        .oauth2
        .ciba_service
        .approve(
            f.tenant_id,
            row.id,
            row.version,
            approval(f.user_id, session_id, vec![Amr::Pwd, Amr::Otp, Amr::Mfa]),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, CibaDecisionOutcome::Recorded(_)));
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
// bc-authorize: the happy path, and every refusal
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn bc_authorize_validates_stores_and_notifies() {
    let f = setup().await;
    let app = app!(f, permissive());
    let (status, body) = bc_authorize!(
        app,
        f,
        &f.ciba,
        "&login_hint=alice&binding_message=W4SCT&acr_values=urn%3Aaxiam%3Aacr%3Amfa"
    );
    assert_eq!(status, 200, "{body}");
    let id = body["auth_req_id"].as_str().expect("auth_req_id");
    assert_eq!(id.len(), 43, "256 bits, base64url");
    assert_eq!(body["expires_in"], 300);
    assert_eq!(body["interval"], 5);

    let row = stored(&f, id).await;
    assert_eq!(row.user_id, Some(f.user_id));
    assert_eq!(row.status, CibaRequestStatus::Pending);
    assert_eq!(row.scopes, ["openid", "profile"]);
    assert_eq!(row.binding_message.as_deref(), Some("W4SCT"));
    assert_eq!(row.acr_values, ["urn:axiam:acr:mfa"]);
    assert_ne!(row.auth_req_id_hash, id, "only the digest is stored");

    // The notification is detached; wait for it.
    let mut sent = Vec::new();
    for _ in 0..100 {
        sent = f.notifier.sent.lock().unwrap().clone();
        if !sent.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].user_id, f.user_id);
    assert_eq!(sent[0].request_id, row.id);
    assert_eq!(sent[0].binding_message.as_deref(), Some("W4SCT"));

    // An e-mail hint resolves too, and the request is attributable.
    let (status, _) = bc_authorize!(app, f, &f.ciba, "&login_hint=alice%40example.com");
    assert_eq!(status, 200);
    let mut rows = Vec::new();
    for _ in 0..100 {
        rows = AuditLogRepository::list(
            &axiam_db::SurrealAuditLogRepository::new(f.db.clone()),
            f.tenant_id,
            AuditLogFilter {
                action: Some("oauth2.ciba_initiated".into()),
                ..Default::default()
            },
            Pagination::default(),
        )
        .await
        .unwrap()
        .items;
        if rows.len() == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(rows.len(), 2, "every stored request is audited");
}

#[actix_web::test]
async fn bc_authorize_refuses_each_malformed_request_with_its_section_13_code() {
    let f = setup().await;
    let app = app!(f, permissive());
    let cases: [(String, &str); 12] = [
        // scope without openid, and an unregistered scope
        (
            format!(
                "client_id={}&client_secret={}&scope=profile&login_hint=alice",
                f.ciba.client_id, f.ciba.secret
            ),
            "invalid_request",
        ),
        (
            format!(
                "client_id={}&client_secret={}&scope=openid%20admin&login_hint=alice",
                f.ciba.client_id, f.ciba.secret
            ),
            "invalid_scope",
        ),
        // no hint, two hints, an unsupported hint
        (bc_body(&f.ciba, ""), "invalid_request"),
        (
            bc_body(&f.ciba, "&login_hint=alice&id_token_hint=eyJ.x.y"),
            "invalid_request",
        ),
        (bc_body(&f.ciba, "&login_hint_token=abc"), "invalid_request"),
        // binding message too long, and with a control character
        (
            bc_body(
                &f.ciba,
                &format!("&login_hint=alice&binding_message={}", "x".repeat(65)),
            ),
            "invalid_binding_message",
        ),
        (
            bc_body(&f.ciba, "&login_hint=alice&binding_message=a%0Ab"),
            "invalid_binding_message",
        ),
        // requested_expiry out of bounds
        (
            bc_body(&f.ciba, "&login_hint=alice&requested_expiry=9999"),
            "invalid_request",
        ),
        // a signed request, and a user code
        (
            bc_body(&f.ciba, "&login_hint=alice&request=eyJ.x.y"),
            "invalid_request",
        ),
        (
            bc_body(&f.ciba, "&login_hint=alice&user_code=1234"),
            "invalid_request",
        ),
        // an id_token_hint this server never issued
        (
            bc_body(&f.ciba, "&id_token_hint=eyJhbGciOiJFZERTQSJ9.e30.c2ln"),
            "invalid_request",
        ),
        // a resource the client may not address
        (
            bc_body(
                &f.ciba,
                "&login_hint=alice&resource=https%3A%2F%2Fapi.example.com",
            ),
            "invalid_target",
        ),
    ];
    for (body, expected) in cases {
        let (status, json) = post_form(
            &app,
            &format!("/oauth2/bc-authorize?tenant_id={}", f.tenant_id),
            body,
        )
        .await;
        assert_eq!(status, 400, "{json}");
        assert_eq!(json["error"], expected, "{json}");
    }

    // A client without the grant is `unauthorized_client`; a wrong secret is
    // `invalid_client` (401).
    let (status, json) = bc_authorize!(app, f, &f.plain, "&login_hint=alice");
    assert_eq!(
        (status, json["error"].as_str()),
        (400, Some("unauthorized_client"))
    );
    let wrong = CibaClient {
        client_id: f.ciba.client_id.clone(),
        secret: "0".repeat(64),
    };
    let (status, json) = bc_authorize!(app, f, &wrong, "&login_hint=alice");
    assert_eq!(
        (status, json["error"].as_str()),
        (401, Some("invalid_client"))
    );
    // Nothing was stored for any of them.
    let mut count =
        f.db.query("SELECT count() AS n FROM ciba_request GROUP ALL")
            .await
            .unwrap();
    let n: Option<i64> = count.take("n").unwrap();
    assert_eq!(n.unwrap_or(0), 0);
}

/// D-63 — a hint naming nobody, or naming a user who may not be the grant's
/// subject (inactive, or under brute-force lockout), is answered exactly like
/// a real one; nobody is notified and nothing can approve it.
#[actix_web::test]
async fn bc_authorize_is_not_a_user_oracle() {
    let f = setup().await;
    let app = app!(f, permissive());
    let (real_status, real) = bc_authorize!(app, f, &f.ciba, "&login_hint=alice");
    let (ghost_status, ghost) = bc_authorize!(app, f, &f.ciba, "&login_hint=nobody-here");
    assert_eq!((real_status, ghost_status), (200, 200));
    let keys = |v: &Value| {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    assert_eq!(keys(&real), keys(&ghost));
    assert_eq!(real["expires_in"], ghost["expires_in"]);
    assert_eq!(real["interval"], ghost["interval"]);

    let ghost_id = ghost["auth_req_id"].as_str().unwrap();
    let row = stored(&f, ghost_id).await;
    assert_eq!(row.user_id, None, "a request for nobody has no subject");
    // The client is told `authorization_pending`, as for a real request.
    let (status, json) = token!(app, f, &f.ciba, ghost_id);
    assert_eq!(
        (status, json["error"].as_str()),
        (400, Some("authorization_pending"))
    );

    // A user under brute-force lockout is nobody, for CIBA (Keycloak 26.7.x).
    SurrealUserRepository::new(f.db.clone())
        .update(
            f.tenant_id,
            f.user_id,
            UpdateUser {
                locked_until: Some(Some(Utc::now() + Duration::minutes(15))),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (status, locked) = bc_authorize!(app, f, &f.ciba, "&login_hint=alice");
    assert_eq!(status, 200);
    let row = stored(&f, locked["auth_req_id"].as_str().unwrap()).await;
    assert_eq!(row.user_id, None, "a locked-out user is not a CIBA subject");

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        f.notifier.sent.lock().unwrap().len(),
        1,
        "only the real, unlocked user was notified"
    );
}

#[actix_web::test]
async fn an_id_token_hint_must_be_one_this_server_issued_to_this_client() {
    let f = setup().await;
    let app = app!(f, permissive());
    let hint = |client_id: &str| {
        issue_id_token(
            f.user_id,
            client_id,
            None,
            Some("alice"),
            &["openid".to_string()],
            &f.auth,
            None,
            &IdTokenEvidence::NONE,
        )
        .unwrap()
    };
    let (status, body) = bc_authorize!(
        app,
        f,
        &f.ciba,
        &format!("&id_token_hint={}", hint(&f.ciba.client_id))
    );
    assert_eq!(status, 200, "{body}");
    let row = stored(&f, body["auth_req_id"].as_str().unwrap()).await;
    assert_eq!(row.user_id, Some(f.user_id));

    // Issued to another client: refused, whoever it names.
    let (status, body) = bc_authorize!(
        app,
        f,
        &f.ciba,
        &format!("&id_token_hint={}", hint(&f.other.client_id))
    );
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_request"))
    );

    // Signed by another key: refused.
    let foreign = test_auth_config();
    let forged = issue_id_token(
        f.user_id,
        &f.ciba.client_id,
        None,
        None,
        &["openid".to_string()],
        &foreign,
        None,
        &IdTokenEvidence::NONE,
    )
    .unwrap();
    let (status, body) = bc_authorize!(app, f, &f.ciba, &format!("&id_token_hint={forged}"));
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_request"))
    );
}

// ---------------------------------------------------------------------------
// The token endpoint: §11's answers, back-off, evidence, single use
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn pending_then_slow_down_then_tokens_with_the_approvals_evidence() {
    let f = setup().await;
    let app = app!(f, permissive());
    let (_, body) = bc_authorize!(
        app,
        f,
        &f.ciba,
        "&login_hint=alice&acr_values=urn%3Aaxiam%3Aacr%3Amfa"
    );
    let id = body["auth_req_id"].as_str().unwrap().to_owned();

    let (status, json) = token!(app, f, &f.ciba, &id);
    assert_eq!(
        (status, json["error"].as_str()),
        (400, Some("authorization_pending"))
    );
    // Polling again at once is too fast: slow_down, and the interval grows.
    let (status, json) = token!(app, f, &f.ciba, &id);
    assert_eq!((status, json["error"].as_str()), (400, Some("slow_down")));
    assert_eq!(stored(&f, &id).await.interval_secs, 10);
    let (status, json) = token!(app, f, &f.ciba, &id);
    assert_eq!((status, json["error"].as_str()), (400, Some("slow_down")));
    assert_eq!(stored(&f, &id).await.interval_secs, 15);

    // A session that achieved only one factor cannot approve an MFA request.
    let row = stored(&f, &id).await;
    let outcome = f
        .state
        .oauth2
        .ciba_service
        .approve(
            f.tenant_id,
            row.id,
            row.version,
            approval(f.user_id, Uuid::new_v4(), vec![Amr::Pwd]),
        )
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        CibaDecisionOutcome::StepUpRequired { .. }
    ));

    let session = Uuid::new_v4();
    approve(&f, &id, session).await;
    age_poll(&f, &id).await;
    let (status, json) = token!(app, f, &f.ciba, &id);
    assert_eq!(status, 200, "{json}");
    assert_eq!(json["token_type"], "Bearer");
    assert_eq!(json["scope"], "openid profile");
    assert!(
        json["refresh_token"].is_string(),
        "the client holds refresh_token"
    );

    let id_token = decode_unverified(json["id_token"].as_str().unwrap());
    assert_eq!(id_token["sub"], f.user_id.to_string());
    assert_eq!(id_token["aud"], f.ciba.client_id);
    assert_eq!(id_token["acr"], "urn:axiam:acr:mfa");
    assert_eq!(id_token["amr"], serde_json::json!(["pwd", "otp", "mfa"]));
    assert!(id_token["auth_time"].as_i64().unwrap() <= Utc::now().timestamp() - 29);
    assert_eq!(id_token["sid"], session.to_string());

    let access = decode_unverified(json["access_token"].as_str().unwrap());
    assert_eq!(
        access["sid"],
        session.to_string(),
        "the token names the approving session"
    );
    assert_eq!(access["client_id"], f.ciba.client_id);

    // Redeemed once: the next request is `invalid_grant`.
    age_poll(&f, &id).await;
    let (status, json) = token!(app, f, &f.ciba, &id);
    assert_eq!(
        (status, json["error"].as_str()),
        (400, Some("invalid_grant"))
    );
    assert_eq!(stored(&f, &id).await.status, CibaRequestStatus::Redeemed);
}

#[actix_web::test]
async fn denied_is_access_denied_and_expired_is_expired_token() {
    let f = setup().await;
    let app = app!(f, permissive());

    let (_, body) = bc_authorize!(app, f, &f.ciba, "&login_hint=alice");
    let denied = body["auth_req_id"].as_str().unwrap().to_owned();
    let row = stored(&f, &denied).await;
    // Another user cannot deny it; the request's user can.
    assert_eq!(
        f.state
            .oauth2
            .ciba_service
            .deny(f.tenant_id, row.id, row.version, Uuid::new_v4())
            .await
            .unwrap(),
        CibaDecisionOutcome::NotDecidable
    );
    assert!(matches!(
        f.state
            .oauth2
            .ciba_service
            .deny(f.tenant_id, row.id, row.version, f.user_id)
            .await
            .unwrap(),
        CibaDecisionOutcome::Recorded(_)
    ));
    let (status, json) = token!(app, f, &f.ciba, &denied);
    assert_eq!(
        (status, json["error"].as_str()),
        (400, Some("access_denied"))
    );

    let (_, body) = bc_authorize!(app, f, &f.ciba, "&login_hint=alice&requested_expiry=30");
    let expired = body["auth_req_id"].as_str().unwrap().to_owned();
    approve(&f, &expired, Uuid::new_v4()).await;
    f.db.query(
        "UPDATE ciba_request SET expires_at = time::now() - 1s WHERE auth_req_id_hash = $hash",
    )
    .bind(("hash", hash_auth_req_id(&expired)))
    .await
    .unwrap();
    let (status, json) = token!(app, f, &f.ciba, &expired);
    assert_eq!(
        (status, json["error"].as_str()),
        (400, Some("expired_token"))
    );
    assert_eq!(
        stored(&f, &expired).await.status,
        CibaRequestStatus::Expired,
        "the expiry is recorded, conditionally"
    );
    // And an expired request cannot be approved after the fact.
    let (_, body) = bc_authorize!(app, f, &f.ciba, "&login_hint=alice");
    let late = body["auth_req_id"].as_str().unwrap().to_owned();
    let row = stored(&f, &late).await;
    f.db.query("UPDATE ciba_request SET expires_at = time::now() - 1s WHERE auth_req_id_hash = $h")
        .bind(("h", hash_auth_req_id(&late)))
        .await
        .unwrap();
    assert_eq!(
        f.state
            .oauth2
            .ciba_service
            .approve(
                f.tenant_id,
                row.id,
                row.version,
                approval(f.user_id, Uuid::new_v4(), vec![Amr::Pwd])
            )
            .await
            .unwrap(),
        CibaDecisionOutcome::NotDecidable
    );
}

/// Another client's — or another tenant's — `auth_req_id` is `invalid_grant`,
/// exactly like an unknown one, and nothing is written for it.
#[actix_web::test]
async fn another_clients_or_tenants_auth_req_id_is_invalid_grant() {
    let f = setup().await;
    let app = app!(f, permissive());
    let (_, body) = bc_authorize!(app, f, &f.ciba, "&login_hint=alice");
    let id = body["auth_req_id"].as_str().unwrap().to_owned();
    approve(&f, &id, Uuid::new_v4()).await;

    let (status, json) = token!(app, f, &f.other, &id);
    assert_eq!(
        (status, json["error"].as_str()),
        (400, Some("invalid_grant"))
    );
    assert!(
        stored(&f, &id).await.last_polled_at.is_none(),
        "a foreign client's request writes nothing to the row"
    );

    // A second tenant with its own CIBA client.
    let (_, tenant_b, _) = tenant_with_user(&f.db, "ciba-b").await;
    let client_b = create_client(&f.db, tenant_b, "b", &[CIBA_GRANT_TYPE], poll_mode()).await;
    let (status, json) = post_form(
        &app,
        &format!("/oauth2/token?tenant_id={tenant_b}"),
        token_body(&client_b, &id),
    )
    .await;
    assert_eq!(
        (status, json["error"].as_str()),
        (400, Some("invalid_grant"))
    );
    // An unknown one, for comparison.
    let (status, json) = token!(app, f, &f.ciba, "never-issued");
    assert_eq!(
        (status, json["error"].as_str()),
        (400, Some("invalid_grant"))
    );

    // The owner still redeems it.
    let (status, _) = token!(app, f, &f.ciba, &id);
    assert_eq!(status, 200);
}

/// The account is re-read after redemption: a user locked out between approval
/// and redemption gets no tokens (the approval is spent).
#[actix_web::test]
async fn a_lockout_after_approval_refuses_the_redemption() {
    let f = setup().await;
    let app = app!(f, permissive());
    let (_, body) = bc_authorize!(app, f, &f.ciba, "&login_hint=alice");
    let id = body["auth_req_id"].as_str().unwrap().to_owned();
    approve(&f, &id, Uuid::new_v4()).await;
    SurrealUserRepository::new(f.db.clone())
        .update(
            f.tenant_id,
            f.user_id,
            UpdateUser {
                locked_until: Some(Some(Utc::now() + Duration::minutes(15))),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (status, json) = token!(app, f, &f.ciba, &id);
    assert_eq!(
        (status, json["error"].as_str()),
        (400, Some("invalid_grant"))
    );
    assert_eq!(stored(&f, &id).await.status, CibaRequestStatus::Redeemed);
}

/// Two concurrent token requests for one approved request: exactly one gets
/// tokens, on the engine production runs.
#[actix_web::test]
async fn concurrent_redemptions_yield_exactly_one_token_set() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let db = Surreal::new::<SurrealKv>(dir.path().join("ciba.db").to_string_lossy().into_owned())
        .await
        .unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let f = setup_on(db).await;
    let app = app!(f, permissive());

    for round in 0..6 {
        let (_, body) = bc_authorize!(app, f, &f.ciba, "&login_hint=alice");
        let id = body["auth_req_id"].as_str().unwrap().to_owned();
        approve(&f, &id, Uuid::new_v4()).await;
        let path = format!("/oauth2/token?tenant_id={}", f.tenant_id);
        let (a, b) = tokio::join!(
            post_form(&app, &path, token_body(&f.ciba, &id)),
            post_form(&app, &path, token_body(&f.ciba, &id))
        );
        let winners = [&a, &b].iter().filter(|(s, _)| *s == 200).count();
        assert_eq!(winners, 1, "round {round}: {a:?} / {b:?}");
        for (status, json) in [a, b] {
            if status != 200 {
                assert_eq!(status, 400);
                assert!(
                    matches!(json["error"].as_str(), Some("invalid_grant" | "slow_down")),
                    "the loser is refused, never served: {json}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The limiter and the lockout: the Keycloak 26.7.x class
// ---------------------------------------------------------------------------

/// `bc-authorize` has its own bucket, and it counts.
#[actix_web::test]
async fn the_limiter_counts_bc_authorize() {
    let f = setup().await;
    let limits = RateLimitConfig {
        bc_authorize_per_min: 3,
        token_per_min: 10_000,
        ..RateLimitConfig::default()
    };
    let app = app!(f, limits);
    let mut statuses = Vec::new();
    for _ in 0..5 {
        statuses.push(bc_authorize!(app, f, &f.ciba, "&login_hint=alice").0);
    }
    assert_eq!(&statuses[..3], &[200, 200, 200]);
    assert!(statuses[3..].iter().all(|s| *s == 429), "{statuses:?}");
}

/// The CIBA grant at the token endpoint is counted by the token endpoint's
/// limiter like every other grant.
#[actix_web::test]
async fn the_limiter_counts_the_ciba_grant() {
    let f = setup().await;
    let limits = RateLimitConfig {
        bc_authorize_per_min: 10_000,
        token_per_min: 3,
        ..RateLimitConfig::default()
    };
    let app = app!(f, limits);
    let (_, body) = bc_authorize!(app, f, &f.ciba, "&login_hint=alice");
    let id = body["auth_req_id"].as_str().unwrap().to_owned();
    let mut statuses = Vec::new();
    for _ in 0..5 {
        statuses.push(token!(app, f, &f.ciba, &id).0);
    }
    assert!(statuses[..3].iter().all(|s| *s == 400), "{statuses:?}");
    assert!(statuses[3..].iter().all(|s| *s == 429), "{statuses:?}");
}

/// A failed CIBA client authentication — at `bc-authorize` and at the token
/// endpoint — meets the token endpoint's brute-force machinery: the uniform
/// `invalid_client`, the `oauth2.client_auth_failed` audit row, and the same
/// bucket that ends in `429` whatever the credential.
#[actix_web::test]
async fn ciba_client_authentication_failures_meet_the_same_lockout() {
    let f = setup().await;
    let limits = RateLimitConfig {
        bc_authorize_per_min: 4,
        token_per_min: 4,
        ..RateLimitConfig::default()
    };
    let app = app!(f, limits);
    let wrong = CibaClient {
        client_id: f.ciba.client_id.clone(),
        secret: "0".repeat(64),
    };
    let (status, json) = bc_authorize!(app, f, &wrong, "&login_hint=alice");
    assert_eq!(
        (status, json["error"].as_str()),
        (401, Some("invalid_client"))
    );
    let (status, json) = token!(app, f, &wrong, "anything");
    assert_eq!(
        (status, json["error"].as_str()),
        (401, Some("invalid_client"))
    );

    // Both failures are audited as the token endpoint's are.
    let mut rows = Vec::new();
    for _ in 0..100 {
        rows = AuditLogRepository::list(
            &axiam_db::SurrealAuditLogRepository::new(f.db.clone()),
            f.tenant_id,
            AuditLogFilter {
                action: Some("oauth2.client_auth_failed".into()),
                ..Default::default()
            },
            Pagination::default(),
        )
        .await
        .unwrap()
        .items;
        if rows.len() == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(rows.len(), 2);
    for row in &rows {
        let meta = &row.metadata;
        assert_eq!(meta["grant_type"], CIBA_GRANT_TYPE);
        assert_eq!(meta["client_id"], f.ciba.client_id);
    }

    // Guessing spends the bucket: once it is empty, even the right secret is
    // refused, at both endpoints.
    for _ in 0..4 {
        bc_authorize!(app, f, &wrong, "&login_hint=alice");
        token!(app, f, &wrong, "anything");
    }
    assert_eq!(bc_authorize!(app, f, &f.ciba, "&login_hint=alice").0, 429);
    assert_eq!(token!(app, f, &f.ciba, "anything").0, 429);
}

// ---------------------------------------------------------------------------
// Both issuer forms, discovery, registration
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn discovery_lists_exactly_what_is_implemented_in_both_issuer_forms() {
    let mut f = setup().await;
    f.auth.tenant_issuer_paths = true;
    f.state.auth_config.tenant_issuer_paths = true;
    let app = app!(f, permissive(), true);
    for (path, issuer) in [
        (
            format!(
                "/.well-known/openid-configuration?tenant_id={}",
                f.tenant_id
            ),
            "https://id.test.example".to_owned(),
        ),
        (
            format!("/t/{}/.well-known/openid-configuration", f.tenant_id),
            format!("https://id.test.example/t/{}", f.tenant_id),
        ),
    ] {
        let req = test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&path)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 200, "{path}");
        let doc: Value = test::read_body_json(resp).await;
        assert_eq!(doc["issuer"], issuer);
        let endpoint = doc["backchannel_authentication_endpoint"].as_str().unwrap();
        assert!(
            endpoint.starts_with(&format!("{issuer}/oauth2/bc-authorize")),
            "{endpoint}"
        );
        assert_eq!(
            doc["backchannel_token_delivery_modes_supported"],
            serde_json::json!(["poll", "ping"])
        );
        assert_eq!(doc["backchannel_user_code_parameter_supported"], false);
        assert!(
            doc.get("backchannel_authentication_request_signing_alg_values_supported")
                .is_none()
        );
        assert!(
            doc["grant_types_supported"]
                .as_array()
                .unwrap()
                .iter()
                .any(|g| g == CIBA_GRANT_TYPE)
        );
    }

    // And the tenant-path endpoint is served: a CIBA flow on it mints tokens
    // under the tenant issuer.
    let (status, body) = post_form(
        &app,
        &format!("/t/{}/oauth2/bc-authorize", f.tenant_id),
        bc_body(&f.ciba, "&login_hint=alice"),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let id = body["auth_req_id"].as_str().unwrap().to_owned();
    approve(&f, &id, Uuid::new_v4()).await;
    let (status, json) = post_form(
        &app,
        &format!("/t/{}/oauth2/token", f.tenant_id),
        token_body(&f.ciba, &id),
    )
    .await;
    assert_eq!(status, 200, "{json}");
    let id_token = decode_unverified(json["id_token"].as_str().unwrap());
    assert_eq!(
        id_token["iss"],
        format!("https://id.test.example/t/{}", f.tenant_id)
    );
}

fn admin_token(f: &Fixture) -> String {
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

async fn admin_create(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    f: &Fixture,
    body: Value,
) -> (u16, Value) {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {}", admin_token(f))))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(body)
        .to_request();
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    let bytes = test::read_body(resp).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The admin API accepts and validates the CIBA metadata; the read-back
/// echoes it.
#[actix_web::test]
async fn admin_registration_accepts_and_validates_the_ciba_metadata() {
    let f = setup().await;
    let app = app!(f, permissive());
    let base = |extra: Value| {
        let mut body = serde_json::json!({
            "name": "ciba",
            "redirect_uris": [],
            "grant_types": [CIBA_GRANT_TYPE],
            "scopes": ["openid"],
            "token_endpoint_auth_method": "client_secret_basic",
        });
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        body
    };
    let (status, created) = admin_create(
        &app,
        &f,
        base(serde_json::json!({
            "backchannel_token_delivery_mode": "ping",
            "backchannel_client_notification_endpoint": "https://rp.example.com/ciba/notify",
        })),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let stored = SurrealOAuth2ClientRepository::new(f.db.clone())
        .get_by_id(
            f.tenant_id,
            created["id"].as_str().unwrap().parse().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        stored.ciba.backchannel_token_delivery_mode,
        Some(CibaDeliveryMode::Ping)
    );

    for (extra, why) in [
        (serde_json::json!({}), "no delivery mode"),
        (
            serde_json::json!({"backchannel_token_delivery_mode": "push"}),
            "push",
        ),
        (
            serde_json::json!({"backchannel_token_delivery_mode": "ping"}),
            "ping without endpoint",
        ),
        (
            serde_json::json!({
                "backchannel_token_delivery_mode": "ping",
                "backchannel_client_notification_endpoint": "https://169.254.169.254/x",
            }),
            "metadata address",
        ),
        (
            serde_json::json!({
                "backchannel_token_delivery_mode": "poll",
                "backchannel_authentication_request_signing_alg": "PS256",
            }),
            "signed requests",
        ),
        (
            serde_json::json!({
                "backchannel_token_delivery_mode": "poll",
                "backchannel_user_code_parameter": true,
            }),
            "user code",
        ),
        (
            serde_json::json!({
                "backchannel_token_delivery_mode": "poll",
                "token_endpoint_auth_method": "none",
            }),
            "public client",
        ),
    ] {
        let (status, body) = admin_create(&app, &f, base(extra)).await;
        assert_eq!(status, 400, "{why}: {body}");
    }
}

/// RFC 7591: the CIBA grant needs an initial access token — an anonymous
/// registration naming it is refused with `invalid_client_metadata` (the
/// accept-and-echo half is `axiam_oauth2::dcr`'s unit tests, through the same
/// `validate`).
#[actix_web::test]
async fn an_anonymous_registration_cannot_obtain_the_ciba_grant() {
    use axiam_core::models::settings::{DynamicRegistrationMode, SetOrgSettings, system_defaults};
    use axiam_core::repository::SettingsRepository;

    let f = setup().await;
    let app = app!(
        f,
        RateLimitConfig {
            dcr_per_min: 1_000,
            ..permissive()
        }
    );
    axiam_db::repository::SurrealSettingsRepository::new(f.db.clone())
        .set_org_settings(
            f.org_id,
            SetOrgSettings {
                dynamic_registration: DynamicRegistrationMode::Anonymous,
                dcr_allowed_scopes: vec!["openid".into()],
                external_client_allowed_resources: vec!["https://mcp.example.com/mcp".into()],
                ..system_defaults()
            },
        )
        .await
        .unwrap();

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/register?tenant_id={}", f.tenant_id))
        .set_json(serde_json::json!({
            "client_name": "call centre",
            "grant_types": [CIBA_GRANT_TYPE],
            "token_endpoint_auth_method": "client_secret_basic",
            "scope": "openid",
            "backchannel_token_delivery_mode": "poll",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    let json: Value = test::read_body_json(resp).await;
    assert_eq!(status, 400, "{json}");
    assert_eq!(json["error"], "invalid_client_metadata");
}

/// The registration gates are not the only line (D-17's shape): a CIBA row
/// edited in the datastore to a public client, or to the `fapi2` profile, is
/// refused at `bc-authorize` too.
#[actix_web::test]
async fn a_row_edited_to_public_or_fapi2_is_refused_at_bc_authorize() {
    let f = setup().await;
    let app = app!(f, permissive());
    f.db.query("UPDATE oauth2_client SET token_endpoint_auth_method = 'none' WHERE client_id = $c")
        .bind(("c", f.other.client_id.clone()))
        .await
        .unwrap();
    let body = format!(
        "client_id={}&scope=openid&login_hint=alice",
        f.other.client_id
    );
    let (status, json) = post_form(
        &app,
        &format!("/oauth2/bc-authorize?tenant_id={}", f.tenant_id),
        body,
    )
    .await;
    assert_eq!((status, json["error"].as_str()), (401, Some("invalid_client")));

    f.db.query("UPDATE oauth2_client SET profile = 'fapi2' WHERE client_id = $c")
        .bind(("c", f.ciba.client_id.clone()))
        .await
        .unwrap();
    let (status, json) = bc_authorize!(app, f, &f.ciba, "&login_hint=alice");
    assert_eq!(status, 401, "{json}");
    // D-17 answers first for a fapi2 row on a shared secret; either way the
    // request is refused and nothing is stored.
    let mut count = f
        .db
        .query("SELECT count() AS n FROM ciba_request GROUP ALL")
        .await
        .unwrap();
    let n: Option<i64> = count.take("n").unwrap();
    assert_eq!(n.unwrap_or(0), 0);
}
