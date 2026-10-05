//! **T23.7.2** — CIBA ping mode on the shared outbound dispatcher (G-7, D-65,
//! D-36): what a decision queues, and what the deliverer sends.
//!
//! The real request and client repositories on an in-memory database, the
//! production deliverer (with the hidden seam that lets its first hop reach
//! `127.0.0.1` over plain `http`, as the SSF and SCIM suites do) against a
//! loopback receiver, and the real [`CibaService`] enqueuing through a recording
//! publisher. The tests that pin the address guard build the deliverer
//! **without** the seam.
//!
//! Tokens and identifiers are generated at run time; no assertion or panic
//! message formats a token or an `auth_req_id`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axiam_core::models::ciba::{
    CIBA_GRANT_TYPE, CibaClientMetadata, CibaDeliveryMode, CibaPingCredentials, CibaRequest,
    CibaRequestStatus, CreateCibaRequest,
};
use axiam_core::models::oauth2_client::{
    AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateOAuth2Client, ManagedBy,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::Amr;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::outbound::{
    DeliveryOutcome, OutboundDeliverer, OutboundError, OutboundFuture, OutboundKind,
    OutboundMessage, OutboundPublisher,
};
use axiam_core::repository::{
    CibaRequestRepository, OAuth2ClientRepository, OrganizationRepository, TenantRepository,
    UserRepository,
};
use axiam_db::repository::{
    SurrealCibaRequestRepository, SurrealOAuth2ClientRepository, SurrealOrganizationRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_oauth2::ciba::{CibaApproval, CibaDecisionOutcome, CibaService, hash_auth_req_id};
use axiam_oauth2::ciba_ping::{CibaPingDeliverer, ping_message};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

type Requests = SurrealCibaRequestRepository<Db>;
type Clients = SurrealOAuth2ClientRepository<Db>;
type Service = CibaService<Requests, SurrealUserRepository<Db>>;

fn sealing() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    out
}

/// A token as a client would choose one: long, visible ASCII, run-time random.
fn fresh_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

// ---------------------------------------------------------------------------
// A loopback receiver
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
}

impl Reply {
    fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
        }
    }
}

#[derive(Clone)]
struct Recorded {
    method: String,
    headers: HashMap<String, String>,
    body: String,
}

struct Receiver {
    port: u16,
    reply: Arc<Mutex<Reply>>,
    seen: Arc<Mutex<Vec<Recorded>>>,
}

impl Receiver {
    async fn start(status: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let reply = Arc::new(Mutex::new(Reply::status(status)));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (reply_for_task, seen_for_task) = (reply.clone(), seen.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let (reply, seen) = (reply_for_task.clone(), seen_for_task.clone());
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
                    let reply = reply.lock().unwrap().clone();
                    let mut out = format!(
                        "HTTP/1.1 {} X\r\nContent-Length: 0\r\nConnection: close\r\n",
                        reply.status
                    );
                    for (name, value) in &reply.headers {
                        out.push_str(&format!("{name}: {value}\r\n"));
                    }
                    out.push_str("\r\n");
                    let _ = socket.write_all(out.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Self { port, reply, seen }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/ciba/notify", self.port)
    }

    fn set_reply(&self, reply: Reply) {
        *self.reply.lock().unwrap() = reply;
    }

    fn requests(&self) -> Vec<Recorded> {
        self.seen.lock().unwrap().clone()
    }
}

/// A publisher that records what the decision path queues.
#[derive(Default)]
struct RecordingPublisher {
    queued: Mutex<Vec<OutboundMessage>>,
    fail: bool,
}

impl OutboundPublisher for RecordingPublisher {
    fn enqueue<'a>(
        &'a self,
        msg: &'a OutboundMessage,
    ) -> OutboundFuture<'a, Result<(), OutboundError>> {
        Box::pin(async move {
            if self.fail {
                return Err(OutboundError::Enqueue("the broker is down".into()));
            }
            self.queued.lock().unwrap().push(msg.clone());
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

struct World {
    db: Surreal<Db>,
    tenant_id: Uuid,
    user_id: Uuid,
    requests: Requests,
    clients: Clients,
    publisher: Arc<RecordingPublisher>,
    service: Service,
    /// The ping-mode client's id; its endpoint is whatever the test set.
    client_id: String,
}

fn client_input(tenant_id: Uuid, ciba: CibaClientMetadata) -> CreateOAuth2Client {
    CreateOAuth2Client {
        tenant_id,
        name: "Call Centre".into(),
        redirect_uris: vec!["https://rp.test.example/cb".into()],
        grant_types: vec![CIBA_GRANT_TYPE.to_owned()],
        scopes: vec!["openid".into()],
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

fn ping_to(endpoint: &str) -> CibaClientMetadata {
    CibaClientMetadata {
        backchannel_token_delivery_mode: Some(CibaDeliveryMode::Ping),
        backchannel_client_notification_endpoint: Some(endpoint.to_owned()),
        ..Default::default()
    }
}

async fn world_with(publisher: RecordingPublisher, endpoint: &str) -> World {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "org".into(),
            slug: "org-ping".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "tenant".into(),
            slug: "tenant-ping".into(),
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
            password: format!("{}Aa1!", Uuid::new_v4().simple()),
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
    let clients = SurrealOAuth2ClientRepository::new(db.clone());
    let (client, _secret) = clients
        .create(client_input(tenant.id, ping_to(endpoint)))
        .await
        .unwrap();
    let requests = SurrealCibaRequestRepository::new(db.clone(), Some(sealing()));
    let publisher = Arc::new(publisher);
    let service = CibaService::new(requests.clone(), users, "unused".into())
        .with_ping_publisher(publisher.clone());
    World {
        db,
        tenant_id: tenant.id,
        user_id: user.id,
        requests,
        clients,
        publisher,
        service,
        client_id: client.client_id,
    }
}

/// A request in ping mode, with the credentials the client supplied.
struct Pinged {
    request: CibaRequest,
    auth_req_id: String,
    token: String,
}

impl World {
    async fn ping_request(&self, mode: CibaDeliveryMode) -> Pinged {
        let auth_req_id = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let token = fresh_token();
        let request = self
            .requests
            .create(CreateCibaRequest {
                tenant_id: self.tenant_id,
                client_id: self.client_id.clone(),
                auth_req_id_hash: hash_auth_req_id(&auth_req_id),
                user_id: Some(self.user_id),
                scopes: vec!["openid".into()],
                binding_message: Some("W4SCT".into()),
                acr_values: Vec::new(),
                resource: None,
                delivery_mode: mode,
                ping: (mode == CibaDeliveryMode::Ping).then(|| CibaPingCredentials {
                    auth_req_id: auth_req_id.clone(),
                    client_notification_token: token.clone(),
                }),
                interval_secs: 5,
                expires_at: Utc::now() + Duration::seconds(300),
            })
            .await
            .unwrap();
        Pinged {
            request,
            auth_req_id,
            token,
        }
    }

    async fn approve(&self, request: &CibaRequest) -> CibaDecisionOutcome {
        self.service
            .approve(
                self.tenant_id,
                request.id,
                request.version,
                CibaApproval {
                    user_id: self.user_id,
                    session_id: Uuid::new_v4(),
                    auth_time: Utc::now(),
                    amr: vec![Amr::Pwd],
                },
            )
            .await
            .unwrap()
    }

    async fn deny(&self, request: &CibaRequest) -> CibaDecisionOutcome {
        self.service
            .deny(self.tenant_id, request.id, request.version, self.user_id)
            .await
            .unwrap()
    }

    fn deliverer(&self) -> CibaPingDeliverer<Requests, Clients> {
        CibaPingDeliverer::new(self.requests.clone(), self.clients.clone())
            .admitting_private_networks_for_tests()
    }

    fn production_deliverer(&self) -> CibaPingDeliverer<Requests, Clients> {
        CibaPingDeliverer::new(self.requests.clone(), self.clients.clone())
    }

    fn queued(&self) -> Vec<OutboundMessage> {
        self.publisher.queued.lock().unwrap().clone()
    }

    async fn attempt(&self, request: &CibaRequest) -> DeliveryOutcome {
        self.deliverer()
            .deliver_attempt(&ping_message(self.tenant_id, request.id))
            .await
            .unwrap()
    }
}

fn reason_of(outcome: &DeliveryOutcome) -> &str {
    match outcome {
        DeliveryOutcome::Retry { reason } | DeliveryOutcome::DeadLetter { reason } => reason,
        DeliveryOutcome::Delivered { .. } => "",
    }
}

// ---------------------------------------------------------------------------
// What a decision queues
// ---------------------------------------------------------------------------

/// After approval **and** after denial, a ping-mode request queues exactly one
/// message: the record id and the tenant — never the `auth_req_id` or the
/// notification token (T-433).
#[tokio::test]
async fn a_decision_queues_a_message_with_nothing_secret_in_it() {
    let receiver = Receiver::start(204).await;
    let w = world_with(RecordingPublisher::default(), &receiver.url()).await;

    let approved = w.ping_request(CibaDeliveryMode::Ping).await;
    assert!(matches!(
        w.approve(&approved.request).await,
        CibaDecisionOutcome::Recorded(_)
    ));
    let denied = w.ping_request(CibaDeliveryMode::Ping).await;
    assert!(matches!(
        w.deny(&denied.request).await,
        CibaDecisionOutcome::Recorded(_)
    ));

    let queued = w.queued();
    assert_eq!(queued.len(), 2, "one per decision");
    assert_eq!(queued[0].target_id, approved.request.id);
    assert_eq!(queued[1].target_id, denied.request.id);
    for (message, pinged) in queued.iter().zip([&approved, &denied]) {
        assert_eq!(message.kind, OutboundKind::CibaPing);
        assert_eq!(message.tenant_id, w.tenant_id);
        assert_eq!(message.attempt, 0);
        assert!(message.payload.is_null(), "the payload is empty");
        let wire = serde_json::to_string(message).unwrap();
        assert!(
            !wire.contains(&pinged.auth_req_id) && !wire.contains(&pinged.token),
            "no credential is in the queued message"
        );
    }
}

#[tokio::test]
async fn a_poll_mode_request_queues_nothing() {
    let receiver = Receiver::start(204).await;
    let w = world_with(RecordingPublisher::default(), &receiver.url()).await;
    let poll = w.ping_request(CibaDeliveryMode::Poll).await;
    assert!(matches!(
        w.approve(&poll.request).await,
        CibaDecisionOutcome::Recorded(_)
    ));
    assert!(w.queued().is_empty());
}

/// A request that was not recorded (another user's, a stale version) queues
/// nothing, and a broker that is down never turns a recorded decision into an
/// error.
#[tokio::test]
async fn only_a_recorded_decision_queues_and_a_broker_outage_does_not_fail_it() {
    let receiver = Receiver::start(204).await;
    let w = world_with(RecordingPublisher::default(), &receiver.url()).await;
    let pinged = w.ping_request(CibaDeliveryMode::Ping).await;
    let stale = w
        .service
        .deny(
            w.tenant_id,
            pinged.request.id,
            pinged.request.version + 1,
            w.user_id,
        )
        .await
        .unwrap();
    assert_eq!(stale, CibaDecisionOutcome::NotDecidable);
    let stranger = w
        .service
        .deny(
            w.tenant_id,
            pinged.request.id,
            pinged.request.version,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert_eq!(stranger, CibaDecisionOutcome::NotDecidable);
    assert!(w.queued().is_empty(), "nothing was decided, nothing queued");

    let down = world_with(
        RecordingPublisher {
            fail: true,
            ..Default::default()
        },
        &receiver.url(),
    )
    .await;
    let pinged = down.ping_request(CibaDeliveryMode::Ping).await;
    assert!(matches!(
        down.approve(&pinged.request).await,
        CibaDecisionOutcome::Recorded(_)
    ));
    let row = down
        .requests
        .get_by_id(down.tenant_id, pinged.request.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, CibaRequestStatus::Approved);
}

// ---------------------------------------------------------------------------
// What the deliverer sends
// ---------------------------------------------------------------------------

/// CIBA Core §10.2: after approval, `POST {"auth_req_id": …}` to the client's
/// endpoint with `Authorization: Bearer <client_notification_token>`.
#[tokio::test]
async fn the_ping_after_an_approval_carries_the_bearer_token_and_the_auth_req_id() {
    let receiver = Receiver::start(204).await;
    let w = world_with(RecordingPublisher::default(), &receiver.url()).await;
    let pinged = w.ping_request(CibaDeliveryMode::Ping).await;
    w.approve(&pinged.request).await;

    let outcome = w.attempt(&pinged.request).await;
    assert_eq!(
        outcome,
        DeliveryOutcome::Delivered {
            response_status: Some(204)
        }
    );
    let seen = receiver.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "POST");
    assert_eq!(
        seen[0].headers.get("authorization").map(String::as_str),
        Some(format!("Bearer {}", pinged.token).as_str())
    );
    assert_eq!(
        seen[0].headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    let body: serde_json::Value = serde_json::from_str(&seen[0].body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({ "auth_req_id": pinged.auth_req_id }),
        "the body is the auth_req_id and nothing else (the outcome is learnt at the token endpoint)"
    );
}

/// And after a denial: the same ping — the client learns that the request was
/// decided, never how.
#[tokio::test]
async fn the_ping_after_a_denial_is_the_same_ping() {
    let receiver = Receiver::start(200).await;
    let w = world_with(RecordingPublisher::default(), &receiver.url()).await;
    let pinged = w.ping_request(CibaDeliveryMode::Ping).await;
    w.deny(&pinged.request).await;

    let outcome = w.attempt(&pinged.request).await;
    assert!(matches!(outcome, DeliveryOutcome::Delivered { .. }));
    let seen = receiver.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].headers.get("authorization").map(String::as_str),
        Some(format!("Bearer {}", pinged.token).as_str())
    );
    let body: serde_json::Value = serde_json::from_str(&seen[0].body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({ "auth_req_id": pinged.auth_req_id })
    );
}

/// The queued message, fed to the deliverer, is all it needs: the end-to-end of
/// "decide → queue → deliver" with nothing carried but the record id.
#[tokio::test]
async fn the_queued_message_alone_drives_a_delivery() {
    let receiver = Receiver::start(204).await;
    let w = world_with(RecordingPublisher::default(), &receiver.url()).await;
    let pinged = w.ping_request(CibaDeliveryMode::Ping).await;
    w.approve(&pinged.request).await;
    let message = w.queued().remove(0);
    let outcome = w.deliverer().deliver_attempt(&message).await.unwrap();
    assert!(matches!(outcome, DeliveryOutcome::Delivered { .. }));
    assert_eq!(receiver.requests().len(), 1);
}

/// A redirect is never followed (T-433): the bearer token cannot reach a host
/// the client did not register. The attempt is a retry.
#[tokio::test]
async fn a_redirect_is_not_followed() {
    let sink = Receiver::start(204).await;
    let receiver = Receiver::start(307).await;
    receiver.set_reply(Reply {
        status: 307,
        headers: vec![("Location".into(), sink.url())],
    });
    let w = world_with(RecordingPublisher::default(), &receiver.url()).await;
    let pinged = w.ping_request(CibaDeliveryMode::Ping).await;
    w.approve(&pinged.request).await;

    let outcome = w.attempt(&pinged.request).await;
    assert!(matches!(outcome, DeliveryOutcome::Retry { .. }));
    assert!(reason_of(&outcome).contains("redirect"));
    assert_eq!(receiver.requests().len(), 1);
    assert!(
        sink.requests().is_empty(),
        "the redirect target saw nothing — in particular not the bearer token"
    );
}

/// 5xx, 408 and 429 are retried; every other 4xx is dead-lettered.
#[tokio::test]
async fn server_errors_are_retried_and_other_client_errors_are_dead_lettered() {
    let receiver = Receiver::start(500).await;
    let w = world_with(RecordingPublisher::default(), &receiver.url()).await;
    let pinged = w.ping_request(CibaDeliveryMode::Ping).await;
    w.approve(&pinged.request).await;

    for status in [408u16, 429, 500, 502, 503, 504] {
        receiver.set_reply(Reply::status(status));
        let outcome = w.attempt(&pinged.request).await;
        assert!(matches!(outcome, DeliveryOutcome::Retry { .. }), "{status}");
        assert!(reason_of(&outcome).contains(&status.to_string()));
    }
    for status in [400u16, 401, 403, 404, 410, 422] {
        receiver.set_reply(Reply::status(status));
        let outcome = w.attempt(&pinged.request).await;
        assert!(
            matches!(outcome, DeliveryOutcome::DeadLetter { .. }),
            "{status}"
        );
        assert_eq!(reason_of(&outcome), format!("HTTP {status}"));
    }
}

#[tokio::test]
async fn no_connection_is_retried() {
    let closed = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    let w = world_with(
        RecordingPublisher::default(),
        &format!("http://127.0.0.1:{closed}/ciba/notify"),
    )
    .await;
    let pinged = w.ping_request(CibaDeliveryMode::Ping).await;
    w.approve(&pinged.request).await;
    let outcome = w.attempt(&pinged.request).await;
    assert!(matches!(outcome, DeliveryOutcome::Retry { .. }));
}

/// The production deliverer — `guarded_fetch_no_redirect` with `allow_private =
/// false` — refuses an endpoint that resolves to an internal address, by literal
/// and by name, and nothing reaches the listener; a plaintext endpoint is
/// refused before anything resolves.
#[tokio::test]
async fn the_address_guard_refuses_an_internal_endpoint_at_delivery() {
    let receiver = Receiver::start(204).await;
    let w = world_with(RecordingPublisher::default(), &receiver.url()).await;
    let pinged = w.ping_request(CibaDeliveryMode::Ping).await;
    w.approve(&pinged.request).await;
    let message = ping_message(w.tenant_id, pinged.request.id);

    // The registered endpoint is an administrator-writable value: move it onto
    // internal addresses and ask the production deliverer to ping.
    let client = w
        .clients
        .get_by_client_id(w.tenant_id, &w.client_id)
        .await
        .unwrap();
    for endpoint in [
        format!("https://127.0.0.1:{}/ciba/notify", receiver.port),
        format!("https://localhost:{}/ciba/notify", receiver.port),
        "https://169.254.169.254/latest/meta-data".to_owned(),
        "https://10.0.0.5/ciba/notify".to_owned(),
    ] {
        set_endpoint(&w, client.id, &endpoint).await;
        let outcome = w
            .production_deliverer()
            .deliver_attempt(&message)
            .await
            .unwrap();
        assert!(
            matches!(outcome, DeliveryOutcome::Retry { .. }),
            "{endpoint}"
        );
        let reason = reason_of(&outcome);
        assert!(reason.contains("does not connect") || reason.contains("did not resolve"));
    }
    set_endpoint(&w, client.id, &receiver.url()).await;
    let outcome = w
        .production_deliverer()
        .deliver_attempt(&message)
        .await
        .unwrap();
    assert!(matches!(outcome, DeliveryOutcome::DeadLetter { .. }));
    assert!(
        receiver.requests().is_empty(),
        "nothing reached the loopback listener"
    );
}

async fn set_endpoint(w: &World, client_row_id: Uuid, endpoint: &str) {
    w.db.query(
        "UPDATE oauth2_client SET backchannel_client_notification_endpoint = $e, \
         updated_at = time::now() WHERE meta::id(id) = $id",
    )
    .bind(("e", endpoint.to_owned()))
    .bind(("id", client_row_id.to_string()))
    .await
    .unwrap();
}

/// The audit-visible reasons are a fixed vocabulary: never a token, an
/// `auth_req_id`, the endpoint or a transport error's text.
#[tokio::test]
async fn no_reason_carries_a_credential_or_the_endpoint() {
    let receiver = Receiver::start(500).await;
    let w = world_with(RecordingPublisher::default(), &receiver.url()).await;
    let pinged = w.ping_request(CibaDeliveryMode::Ping).await;
    w.approve(&pinged.request).await;
    let mut reasons = Vec::new();
    for status in [500u16, 307, 400, 401] {
        receiver.set_reply(Reply::status(status));
        reasons.push(reason_of(&w.attempt(&pinged.request).await).to_owned());
    }
    for reason in reasons {
        assert!(!reason.contains(&pinged.token), "{reason}");
        assert!(!reason.contains(&pinged.auth_req_id), "{reason}");
        assert!(!reason.contains("127.0.0.1"), "{reason}");
    }
}

// ---------------------------------------------------------------------------
// The request as it is at the attempt
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_undecided_expired_gone_or_poll_mode_request_is_not_pinged() {
    let receiver = Receiver::start(204).await;
    let w = world_with(RecordingPublisher::default(), &receiver.url()).await;

    // Pending: nothing was decided.
    let pending = w.ping_request(CibaDeliveryMode::Ping).await;
    let outcome = w.attempt(&pending.request).await;
    assert!(matches!(outcome, DeliveryOutcome::DeadLetter { .. }));

    // Poll mode: the client asked for no ping.
    let poll = w.ping_request(CibaDeliveryMode::Poll).await;
    w.approve(&poll.request).await;
    let outcome = w.attempt(&poll.request).await;
    assert!(matches!(outcome, DeliveryOutcome::DeadLetter { .. }));

    // Expired after the decision.
    let lapsed = w.ping_request(CibaDeliveryMode::Ping).await;
    w.approve(&lapsed.request).await;
    w.db.query("UPDATE ciba_request SET status = 'expired' WHERE meta::id(id) = $id")
        .bind(("id", lapsed.request.id.to_string()))
        .await
        .unwrap();
    let outcome = w.attempt(&lapsed.request).await;
    assert!(matches!(outcome, DeliveryOutcome::DeadLetter { .. }));

    // Swept.
    let gone = ping_message(w.tenant_id, Uuid::new_v4());
    let outcome = w.deliverer().deliver_attempt(&gone).await.unwrap();
    assert!(matches!(outcome, DeliveryOutcome::DeadLetter { .. }));

    assert!(receiver.requests().is_empty(), "no ping was sent");
}

/// Level-triggered: a request the client has already collected has nothing left
/// to say, so it is delivered without a call.
#[tokio::test]
async fn a_request_already_redeemed_is_acknowledged_without_a_call() {
    let receiver = Receiver::start(204).await;
    let w = world_with(RecordingPublisher::default(), &receiver.url()).await;
    let pinged = w.ping_request(CibaDeliveryMode::Ping).await;
    w.approve(&pinged.request).await;
    w.requests
        .redeem(
            w.tenant_id,
            &hash_auth_req_id(&pinged.auth_req_id),
            &w.client_id,
        )
        .await
        .unwrap()
        .expect("redeemed");
    let outcome = w.attempt(&pinged.request).await;
    assert_eq!(
        outcome,
        DeliveryOutcome::Delivered {
            response_status: None
        }
    );
    assert!(receiver.requests().is_empty());
}

/// The endpoint is the client's *current* registration, read at the attempt: a
/// client that has gone back to poll mode, lost its endpoint or been deleted is
/// not pinged.
#[tokio::test]
async fn the_clients_current_registration_decides() {
    let receiver = Receiver::start(204).await;
    let w = world_with(RecordingPublisher::default(), &receiver.url()).await;
    let pinged = w.ping_request(CibaDeliveryMode::Ping).await;
    w.approve(&pinged.request).await;
    let client = w
        .clients
        .get_by_client_id(w.tenant_id, &w.client_id)
        .await
        .unwrap();

    // Moved to another endpoint: the ping follows the registration.
    let other = Receiver::start(204).await;
    set_endpoint(&w, client.id, &other.url()).await;
    assert!(matches!(
        w.attempt(&pinged.request).await,
        DeliveryOutcome::Delivered { .. }
    ));
    assert_eq!(other.requests().len(), 1);
    assert!(receiver.requests().is_empty());

    // Endpoint removed.
    w.db.query(
        "UPDATE oauth2_client SET backchannel_client_notification_endpoint = NONE \
         WHERE meta::id(id) = $id",
    )
    .bind(("id", client.id.to_string()))
    .await
    .unwrap();
    assert!(matches!(
        w.attempt(&pinged.request).await,
        DeliveryOutcome::DeadLetter { .. }
    ));

    // Deleted.
    w.clients.delete(w.tenant_id, client.id).await.unwrap();
    assert!(matches!(
        w.attempt(&pinged.request).await,
        DeliveryOutcome::DeadLetter { .. }
    ));
}

#[tokio::test]
async fn the_deliverer_serves_only_its_own_kind() {
    let receiver = Receiver::start(204).await;
    let w = world_with(RecordingPublisher::default(), &receiver.url()).await;
    assert_eq!(w.deliverer().kind(), OutboundKind::CibaPing);
    let mut other = ping_message(w.tenant_id, Uuid::new_v4());
    other.kind = OutboundKind::Webhook;
    let outcome = w.deliverer().deliver_attempt(&other).await.unwrap();
    assert!(matches!(outcome, DeliveryOutcome::DeadLetter { .. }));
}
