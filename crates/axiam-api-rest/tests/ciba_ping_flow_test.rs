//! CIBA ping mode, end to end through the HTTP surface (T23.7.3, G-7, D-65,
//! D-36): `bc-authorize`, the user's approval or refusal on the approval route,
//! the ping that reaches the client's endpoint, and the client's redemption at
//! the token endpoint.
//!
//! Why this is a Rust test and not a Playwright one: a ping is an HTTPS call
//! from the server to a receiver the client registered, through the outbound
//! address guard (`https`, every resolved address publicly routable, no redirect
//! followed) over a TLS client that trusts only the Mozilla roots. No receiver a
//! CI job can start satisfies all three without weakening that guard or adding a
//! trust-anchor setting to production code, so the compose e2e suite
//! (`frontend/e2e/ciba.spec.ts`) covers poll mode and this file covers the ping.
//!
//! What is real: the REST routes (`/oauth2/bc-authorize`, the approval routes
//! under a session and a CSRF token, `/oauth2/token`), the request and client
//! repositories on an in-memory database with a sealing key, `CibaService`, and
//! the production `CibaPingDeliverer`. What is stood in: the AMQP dispatcher is
//! replaced by an inline one that runs the deliverer on the queued message, and
//! the deliverer's hidden seam lets its first hop reach a loopback receiver over
//! plain `http`. The address guard itself is pinned by
//! `axiam-oauth2/tests/ciba_ping_test.rs`, which builds the deliverer without
//! the seam.
//!
//! No credential literal appears here: the client's notification token and the
//! sealing key are generated at run time, passwords come from
//! `axiam_test_support`, keys from `rcgen`, and no assertion formats a token or
//! an `auth_req_id` into its message.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use actix_web::{App, test, web};
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::state::AppState;
use axiam_api_rest::{RateLimitConfig, register_api_v1_routes};
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_core::models::ciba::{
    CIBA_GRANT_TYPE, CibaClientMetadata, CibaDeliveryMode, CibaRequestStatus,
};
use axiam_core::models::oauth2_client::{
    AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateOAuth2Client, ManagedBy,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::{Amr, CreateSession};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::outbound::{
    DeliveryOutcome, OutboundDeliverer, OutboundError, OutboundFuture, OutboundMessage,
    OutboundPublisher,
};
use axiam_core::repository::{
    CibaRequestRepository, OAuth2ClientRepository, OrganizationRepository, SessionRepository,
    TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealCibaRequestRepository, SurrealOAuth2ClientRepository, SurrealOrganizationRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_oauth2::ciba::{CibaService, hash_auth_req_id};
use axiam_oauth2::ciba_ping::CibaPingDeliverer;
use chrono::{Duration, Utc};
use serde_json::Value;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

type TestDb = Db;
type Requests = SurrealCibaRequestRepository<Db>;
type Clients = SurrealOAuth2ClientRepository<Db>;

const TEST_PEER: &str = "127.0.0.1:34567";
const CSRF_VALUE: &str = "csrf-double-submit-value";

// ---------------------------------------------------------------------------
// A loopback receiver
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Recorded {
    method: String,
    headers: HashMap<String, String>,
    body: String,
}

struct Receiver {
    port: u16,
    seen: Arc<Mutex<Vec<Recorded>>>,
}

impl Receiver {
    /// A listener that answers every request `status` with no body.
    async fn start(status: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let for_task = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let seen = for_task.clone();
                tokio::spawn(async move {
                    let mut raw = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let (head, mut body) = loop {
                        let n = socket.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        raw.extend_from_slice(&chunk[..n]);
                        if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                            let body = raw.split_off(at + 4);
                            break (String::from_utf8_lossy(&raw).into_owned(), body);
                        }
                    };
                    let mut lines = head.lines();
                    let method = lines
                        .next()
                        .and_then(|l| l.split(' ').next())
                        .unwrap_or_default()
                        .to_owned();
                    let headers: HashMap<String, String> = lines
                        .filter_map(|l| l.split_once(':'))
                        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
                        .collect();
                    let wanted: usize = headers
                        .get("content-length")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    while body.len() < wanted {
                        let n = socket.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        body.extend_from_slice(&chunk[..n]);
                    }
                    seen.lock().unwrap().push(Recorded {
                        method,
                        headers,
                        body: String::from_utf8_lossy(&body).into_owned(),
                    });
                    let out = format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = socket.write_all(out.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Self { port, seen }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/ciba/notify", self.port)
    }

    fn requests(&self) -> Vec<Recorded> {
        self.seen.lock().unwrap().clone()
    }

    /// Wait (bounded) until `n` requests have arrived.
    async fn wait_for(&self, n: usize) -> Vec<Recorded> {
        for _ in 0..500 {
            let seen = self.requests();
            if seen.len() >= n {
                return seen;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        self.requests()
    }
}

/// The dispatcher, inline: an enqueued ping is delivered at once by the
/// production deliverer, and what it reported is kept for the test to read.
struct InlineDispatcher {
    deliverer: Arc<CibaPingDeliverer<Requests, Clients>>,
    outcomes: Arc<Mutex<Vec<DeliveryOutcome>>>,
}

impl OutboundPublisher for InlineDispatcher {
    fn enqueue<'a>(
        &'a self,
        msg: &'a OutboundMessage,
    ) -> OutboundFuture<'a, Result<(), OutboundError>> {
        let deliverer = self.deliverer.clone();
        let outcomes = self.outcomes.clone();
        let msg = msg.clone();
        Box::pin(async move {
            tokio::spawn(async move {
                if let Ok(outcome) = deliverer.deliver_attempt(&msg).await {
                    outcomes.lock().unwrap().push(outcome);
                }
            });
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

struct World {
    db: Surreal<TestDb>,
    auth: AuthConfig,
    state: web::Data<AppState<TestDb>>,
    tenant_id: Uuid,
    org_id: Uuid,
    alice: Uuid,
    client_id: String,
    client_credential: String,
    /// What the client supplies at `bc-authorize` and the server presents at the ping.
    notification_token: String,
    outcomes: Arc<Mutex<Vec<DeliveryOutcome>>>,
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

fn run_time_sealing_key() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    out
}

fn fresh_notification_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn ping_client(tenant_id: Uuid, endpoint: &str) -> CreateOAuth2Client {
    CreateOAuth2Client {
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
            backchannel_token_delivery_mode: Some(CibaDeliveryMode::Ping),
            backchannel_client_notification_endpoint: Some(endpoint.to_owned()),
            ..Default::default()
        },
    }
}

/// A world whose ping client is registered with `endpoint`, and whose
/// application state decides a ping through the inline dispatcher.
async fn world(endpoint: &str) -> World {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "ciba ping org".into(),
            slug: "org-ciba-ping".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "ciba ping tenant".into(),
            slug: "tenant-ciba-ping".into(),
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
            password: axiam_test_support::test_password(),
            metadata: None,
        })
        .await
        .unwrap();
    users
        .update(
            tenant.id,
            alice.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let clients: Clients = SurrealOAuth2ClientRepository::new(db.clone());
    let (client, credential) = clients
        .create(ping_client(tenant.id, endpoint))
        .await
        .unwrap();

    // The request store holds the sealing key a deployment with
    // `pki_encryption_key` has; without it a ping-mode request is refused.
    let requests: Requests =
        SurrealCibaRequestRepository::new(db.clone(), Some(run_time_sealing_key()));
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    let deliverer = Arc::new(
        CibaPingDeliverer::new(requests.clone(), clients).admitting_private_networks_for_tests(),
    );
    let auth = auth_config();
    let service = CibaService::new(requests, users, auth.jwt_public_key_pem.clone())
        .with_ping_publisher(Arc::new(InlineDispatcher {
            deliverer,
            outcomes: outcomes.clone(),
        }));
    let mut state = AppState::for_test(db.clone(), auth.clone());
    state.rate_limit_cfg = limits();
    state.oauth2.ciba_service = service;
    World {
        db,
        auth,
        state: web::Data::new(state),
        tenant_id: tenant.id,
        org_id: org.id,
        alice: alice.id,
        client_id: client.client_id,
        client_credential: credential,
        notification_token: fresh_notification_token(),
        outcomes,
    }
}

impl World {
    /// Wait (bounded) until the deliverer has reported. The receiver records a
    /// ping before it answers, so the ping arriving does not mean the
    /// deliverer has read the answer and reported yet.
    async fn wait_for_outcome(&self) -> Vec<DeliveryOutcome> {
        for _ in 0..500 {
            let reported = self.outcomes.lock().unwrap().clone();
            if !reported.is_empty() {
                return reported;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        self.outcomes.lock().unwrap().clone()
    }
}

macro_rules! app {
    ($w:expr) => {{
        let limits: RateLimitConfig = limits();
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

// ---------------------------------------------------------------------------
// The calls
// ---------------------------------------------------------------------------

fn peer() -> SocketAddr {
    TEST_PEER.parse().unwrap()
}

fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

async fn call(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    req: actix_http::Request,
) -> (u16, Value) {
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    let bytes = test::read_body(resp).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
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
    call(app, req).await
}

/// `bc-authorize` as the ping client; returns `(auth_req_id, record id)`.
async fn start(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    w: &World,
) -> (String, Uuid) {
    let (status, body) = form_post(
        app,
        &format!("/oauth2/bc-authorize?tenant_id={}", w.tenant_id),
        format!(
            "client_id={}&client_secret={}&scope=openid%20profile&login_hint=alice\
             &binding_message={}&client_notification_token={}",
            w.client_id,
            w.client_credential,
            enc("Confirm J.Doe 42 EUR"),
            w.notification_token
        ),
    )
    .await;
    assert_eq!(status, 200, "bc-authorize in ping mode");
    let auth_req_id = body["auth_req_id"].as_str().unwrap().to_owned();
    let row = w
        .state
        .oauth2
        .ciba_service
        .requests()
        .get_by_hash(w.tenant_id, &hash_auth_req_id(&auth_req_id))
        .await
        .unwrap()
        .expect("the request is stored");
    (auth_req_id, row.id)
}

/// One token request, outside the polling interval (the test does not sleep).
async fn poll(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    w: &World,
    auth_req_id: &str,
) -> (u16, Value) {
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
            w.client_id,
            w.client_credential,
            enc(auth_req_id)
        ),
    )
    .await
}

/// A session for alice that authenticated with a password, and the bearer jwt
/// the console would hold for it.
async fn session_jwt(w: &World) -> (Uuid, String) {
    let session = w
        .state
        .session_repo
        .create(CreateSession {
            tenant_id: w.tenant_id,
            user_id: w.alice,
            token_hash: Uuid::new_v4().simple().to_string(),
            ip_address: None,
            user_agent: None,
            expires_at: Utc::now() + Duration::hours(1),
            authenticated_at: Utc::now() - Duration::seconds(20),
            amr: vec![Amr::Pwd],
            browser_token_hash: None,
        })
        .await
        .unwrap();
    let jwt = issue_access_token(
        w.alice,
        w.tenant_id,
        w.org_id,
        &[],
        &w.auth,
        session.id.to_string(),
        AUD_USER,
    )
    .unwrap();
    (session.id, jwt)
}

/// The version the approval page reads, then the decision, as the console does.
async fn decide(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    id: Uuid,
    verb: &str,
    jwt: &str,
) -> (u16, Value) {
    let read = test::TestRequest::get()
        .peer_addr(peer())
        .uri(&format!("/api/v1/ciba/requests/{id}"))
        .insert_header(("Authorization", format!("Bearer {jwt}")))
        .to_request();
    let (status, page) = call(app, read).await;
    assert_eq!(status, 200, "the approval page reads the request");
    let req = test::TestRequest::post()
        .peer_addr(peer())
        .uri(&format!("/api/v1/ciba/requests/{id}/{verb}"))
        .insert_header(("Authorization", format!("Bearer {jwt}")))
        .insert_header(("X-CSRF-Token", CSRF_VALUE))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_VALUE}")))
        .set_json(serde_json::json!({ "version": page["version"].as_u64().unwrap() }))
        .to_request();
    call(app, req).await
}

fn decode_unverified(jwt: &str) -> Value {
    use base64::Engine;
    let payload = jwt.split('.').nth(1).expect("a JWT has a payload");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// What the ping must be: a `POST` carrying the client's own notification token
/// as a bearer and a JSON body naming the `auth_req_id` and nothing else.
fn assert_is_the_ping(seen: &Recorded, w: &World, auth_req_id: &str) {
    assert_eq!(seen.method, "POST");
    // No message on these two: they would print the token and the id.
    let bearer = seen
        .headers
        .get("authorization")
        .cloned()
        .unwrap_or_default();
    assert!(bearer == format!("Bearer {}", w.notification_token));
    assert_eq!(
        seen.headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    let body: Value = serde_json::from_str(&seen.body).expect("the ping body is JSON");
    assert!(body == serde_json::json!({ "auth_req_id": auth_req_id }));
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

/// Poll mode's twin: nothing is sent until the user decides; the approval then
/// pings the client's endpoint once, and the client's redemption gets tokens
/// bound to the approving session — and only once.
#[actix_web::test]
async fn an_approval_pings_the_client_which_then_redeems_once() {
    let receiver = Receiver::start(204).await;
    let w = Box::pin(world(&receiver.url())).await;
    let app = app!(w);
    let (auth_req_id, id) = start(&app, &w).await;

    // Pending: a poll says so, and no ping has been sent.
    let (status, body) = poll(&app, &w, &auth_req_id).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("authorization_pending"))
    );
    assert!(receiver.requests().is_empty(), "no ping before a decision");

    // The signed-in user approves on the approval route.
    let (session_id, jwt) = session_jwt(&w).await;
    let (status, done) = decide(&app, id, "approve", &jwt).await;
    assert_eq!(status, 200, "{done}");
    assert_eq!(done["decision"], "approved");

    // Exactly one ping reaches the endpoint, and it is the contract's.
    let pings = receiver.wait_for(1).await;
    assert_eq!(pings.len(), 1, "one ping per decision");
    assert_is_the_ping(&pings[0], &w, &auth_req_id);
    let reported = w.wait_for_outcome().await;
    assert_eq!(
        reported,
        vec![DeliveryOutcome::Delivered {
            response_status: Some(204)
        }]
    );

    // The client, pinged, redeems at the token endpoint and gets its tokens.
    let (status, issued) = poll(&app, &w, &auth_req_id).await;
    assert_eq!(status, 200, "{issued}");
    assert_eq!(issued["token_type"], "Bearer");
    let id_token = decode_unverified(issued["id_token"].as_str().unwrap());
    assert_eq!(id_token["sub"], w.alice.to_string());
    assert_eq!(id_token["aud"], w.client_id);
    let access = decode_unverified(issued["access_token"].as_str().unwrap());
    assert_eq!(
        access["sid"],
        session_id.to_string(),
        "the tokens name the approving session"
    );

    // And the request is spent: a second redemption is refused, no second ping.
    let (status, again) = poll(&app, &w, &auth_req_id).await;
    assert_eq!(
        (status, again["error"].as_str()),
        (400, Some("invalid_grant"))
    );
    assert_eq!(receiver.requests().len(), 1);
}

/// A refusal sends the very same ping: the client learns that the request was
/// decided, never how, and finds out at the token endpoint.
#[actix_web::test]
async fn a_refusal_sends_the_same_ping_and_the_client_is_told_access_denied() {
    let receiver = Receiver::start(200).await;
    let w = Box::pin(world(&receiver.url())).await;
    let app = app!(w);
    let (auth_req_id, id) = start(&app, &w).await;
    let (_, jwt) = session_jwt(&w).await;

    let (status, done) = decide(&app, id, "deny", &jwt).await;
    assert_eq!(status, 200, "{done}");
    assert_eq!(done["decision"], "denied");

    let pings = receiver.wait_for(1).await;
    assert_eq!(pings.len(), 1);
    assert_is_the_ping(&pings[0], &w, &auth_req_id);

    let (status, body) = poll(&app, &w, &auth_req_id).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("access_denied"))
    );
    assert!(body["access_token"].is_null());
}

/// A ping that cannot be delivered neither fails the user's decision nor stops
/// the client: it polls and gets its tokens (contract §33.7 rule 6).
#[actix_web::test]
async fn a_ping_that_cannot_be_delivered_does_not_stop_the_client_polling() {
    // A port nothing listens on: bind, note the port, drop the listener.
    let dead_port = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };
    let w = Box::pin(world(&format!("http://127.0.0.1:{dead_port}/ciba/notify"))).await;
    let app = app!(w);
    let (auth_req_id, id) = start(&app, &w).await;
    let (_, jwt) = session_jwt(&w).await;

    let (status, done) = decide(&app, id, "approve", &jwt).await;
    assert_eq!(
        status, 200,
        "{done}: the decision stands whatever the ping does"
    );

    // The deliverer reports a retry (the dispatcher would redeliver).
    let reported = w.wait_for_outcome().await;
    assert_eq!(reported.len(), 1);
    assert!(
        matches!(reported[0], DeliveryOutcome::Retry { .. }),
        "an unreachable endpoint is retried, not dead-lettered"
    );

    // The client does not wait for a ping that is not coming.
    let (status, issued) = poll(&app, &w, &auth_req_id).await;
    assert_eq!(status, 200, "{issued}");
    assert!(issued["id_token"].is_string());
    let row = w
        .state
        .oauth2
        .ciba_service
        .requests()
        .get_by_id(w.tenant_id, id)
        .await
        .unwrap()
        .expect("the row");
    assert_eq!(row.status, CibaRequestStatus::Redeemed);
}
