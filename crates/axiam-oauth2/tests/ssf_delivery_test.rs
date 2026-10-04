//! **T23.5.3** — the SSF push deliverer and the outbox (G-5, D-36, D-48, D-49,
//! D-51), against the real stream and buffer repositories on an in-memory
//! database and a loopback receiver.
//!
//! The deliverer under test is the production one; the only difference is the
//! hidden `admitting_private_networks_for_tests` seam that lets its first hop
//! reach `127.0.0.1` over plain `http`. The tests that pin the address guard
//! build the deliverer **without** it.
//!
//! Keys, headers and tokens are generated at run time; no assertion or panic
//! message formats a header, a token or a SET.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use axiam_auth::config::AuthConfig;
use axiam_core::models::ssf::{
    NewSsfStream, SecretChange, SsfDeliveryMethod, SsfEventType, SsfOutbox, SsfOutboxError,
    SsfPendingEvent, SsfStream, SsfStreamStatus, SsfStreamUpdate, SsfSubjectFormat,
};
use axiam_core::outbound::{
    DeliveryOutcome, OutboundDeliverer, OutboundError, OutboundFuture, OutboundKind,
    OutboundMessage, OutboundPublisher,
};
use axiam_core::repository::{SsfEventBufferRepository, SsfStreamRepository};
use axiam_db::repository::{SurrealSsfEventBufferRepository, SurrealSsfStreamRepository};
use axiam_oauth2::ssf::{
    InitiatingEntity, SsfEvent, SsfSubject, delivery_id_of, prepare_event, prepare_stream_updated,
    prepare_verification,
};
use axiam_oauth2::ssf_delivery::{
    RFC_8935_ERROR_CODES, SET_CONTENT_TYPE, SsfOutboxService, SsfPushDeliverer,
};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;
use zeroize::Zeroizing;

type Streams = SurrealSsfStreamRepository<Db>;
type Buffer = SurrealSsfEventBufferRepository<Db>;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn pems() -> &'static (String, String) {
    static PEMS: OnceLock<(String, String)> = OnceLock::new();
    PEMS.get_or_init(|| {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519");
        (pair.serialize_pem(), pair.public_key_pem())
    })
}

fn config() -> AuthConfig {
    let (private, public) = pems();
    AuthConfig {
        jwt_private_key_pem: private.clone(),
        jwt_public_key_pem: public.clone(),
        oauth2_issuer_url: "https://iam.example.test".into(),
        ..AuthConfig::default()
    }
}

fn sealing() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    out
}

fn credential() -> String {
    format!("Bearer {}", Uuid::new_v4().simple())
}

struct World {
    streams: Streams,
    buffer: Buffer,
    auth: AuthConfig,
    tenant: Uuid,
}

async fn world() -> World {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    World {
        streams: SurrealSsfStreamRepository::new(db.clone(), Some(sealing())),
        buffer: SurrealSsfEventBufferRepository::new(db),
        auth: config(),
        tenant: Uuid::new_v4(),
    }
}

impl World {
    /// A stream registered directly in the datastore (the repository does not
    /// apply the write-time endpoint policy; delivery is what is under test).
    async fn stream(
        &self,
        method: SsfDeliveryMethod,
        status: SsfStreamStatus,
        endpoint: Option<String>,
        header: Option<String>,
    ) -> SsfStream {
        self.streams
            .create(NewSsfStream {
                tenant_id: self.tenant,
                receiver_client_id: "receiver".into(),
                audience: format!("https://rp.example.test/aud/{}", Uuid::new_v4().simple()),
                description: None,
                delivery_method: method,
                endpoint_url: endpoint,
                authorization_header: header.map(Zeroizing::new),
                events_allowed: vec![
                    SsfEventType::SessionRevoked,
                    SsfEventType::AccountDisabled,
                    SsfEventType::AccountEnabled,
                ],
                events_requested: vec![SsfEventType::SessionRevoked, SsfEventType::AccountEnabled],
                subject_format: SsfSubjectFormat::IssSub,
                status,
                status_reason: None,
            })
            .await
            .unwrap()
    }

    async fn push_stream(&self, receiver: &Receiver, header: Option<String>) -> SsfStream {
        self.stream(
            SsfDeliveryMethod::Push,
            SsfStreamStatus::Enabled,
            Some(receiver.url()),
            header,
        )
        .await
    }

    fn deliverer(&self) -> SsfPushDeliverer<Streams, Buffer> {
        SsfPushDeliverer::new(self.streams.clone(), self.buffer.clone(), self.auth.clone())
            .admitting_private_networks_for_tests()
    }

    fn production_deliverer(&self) -> SsfPushDeliverer<Streams, Buffer> {
        SsfPushDeliverer::new(self.streams.clone(), self.buffer.clone(), self.auth.clone())
    }

    fn pending(&self, stream: &SsfStream, event: &SsfEvent) -> SsfPendingEvent {
        prepare_event(
            &self.auth,
            stream,
            event,
            &subject(),
            Some("txn-1"),
            Utc::now(),
        )
        .unwrap()
    }

    fn message(&self, stream: &SsfStream, pending: &SsfPendingEvent) -> OutboundMessage {
        OutboundMessage {
            kind: OutboundKind::SsfPush,
            tenant_id: stream.tenant_id,
            target_id: stream.id,
            delivery_id: delivery_id_of(pending).unwrap(),
            event_type: pending.event_uri.clone(),
            payload: serde_json::to_value(pending).unwrap(),
            attempt: 0,
        }
    }

    async fn set_status(&self, stream: &SsfStream, status: SsfStreamStatus) -> SsfStream {
        let mut update = SsfStreamUpdate::from_stream(stream);
        update.status = status;
        self.streams
            .update(stream.tenant_id, stream.id, update)
            .await
            .unwrap()
    }
}

fn subject() -> SsfSubject {
    SsfSubject {
        user_id: Uuid::new_v4(),
        email: Some(format!("{}@example.test", Uuid::new_v4().simple())),
        email_vouched: true,
        session_id: Some(Uuid::new_v4()),
    }
}

fn revoked() -> SsfEvent {
    SsfEvent::SessionRevoked {
        initiating_entity: Some(InitiatingEntity::Admin),
        event_timestamp: Utc::now().timestamp(),
    }
}

// ---------------------------------------------------------------------------
// A loopback receiver
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Reply {
    status: u16,
    body: String,
    headers: Vec<(String, String)>,
}

impl Reply {
    fn status(status: u16) -> Self {
        Self {
            status,
            body: String::new(),
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
                        "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                        reply.status,
                        reply.body.len()
                    );
                    for (name, value) in &reply.headers {
                        out.push_str(&format!("{name}: {value}\r\n"));
                    }
                    out.push_str("\r\n");
                    out.push_str(&reply.body);
                    let _ = socket.write_all(out.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Self { port, reply, seen }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/ssf/events", self.port)
    }

    fn set_reply(&self, reply: Reply) {
        *self.reply.lock().unwrap() = reply;
    }

    fn requests(&self) -> Vec<Recorded> {
        self.seen.lock().unwrap().clone()
    }
}

/// Verify a SET against the deployment key, the way a receiver does.
fn verify(set: &str, auth: &AuthConfig, audience: &str) -> serde_json::Value {
    let key = DecodingKey::from_ed_pem(auth.jwt_public_key_pem.as_bytes()).unwrap();
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.set_audience(&[audience]);
    let header = jsonwebtoken::decode_header(set).unwrap();
    assert_eq!(header.typ.as_deref(), Some("secevent+jwt"));
    jsonwebtoken::decode::<serde_json::Value>(set, &key, &validation)
        .unwrap()
        .claims
}

fn is_delivered(outcome: &DeliveryOutcome, status: u16) -> bool {
    matches!(outcome, DeliveryOutcome::Delivered { response_status } if *response_status == Some(status))
}

fn reason_of(outcome: &DeliveryOutcome) -> &str {
    match outcome {
        DeliveryOutcome::Retry { reason } | DeliveryOutcome::DeadLetter { reason } => reason,
        DeliveryOutcome::Delivered { .. } => "",
    }
}

// ---------------------------------------------------------------------------
// The push
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_push_is_a_signed_set_with_the_stored_credential() {
    let w = world().await;
    let receiver = Receiver::start(202).await;
    let header = credential();
    let stream = w.push_stream(&receiver, Some(header.clone())).await;
    let pending = w.pending(&stream, &revoked());

    let outcome = w
        .deliverer()
        .deliver_attempt(&w.message(&stream, &pending))
        .await
        .unwrap();
    assert!(is_delivered(&outcome, 202));

    let seen = receiver.requests();
    assert_eq!(seen.len(), 1);
    let request = &seen[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.headers["content-type"], SET_CONTENT_TYPE);
    assert_eq!(request.headers["accept"], "application/json");
    assert!(
        request.headers.get("authorization") == Some(&header),
        "the stored Authorization header is sent verbatim"
    );
    let claims = verify(&request.body, &w.auth, &stream.audience);
    assert_eq!(claims["jti"], pending.jti);
    assert_eq!(claims["txn"], "txn-1");
    assert!(claims.get("exp").is_none() && claims.get("sub").is_none());
    assert!(
        claims["events"]
            .as_object()
            .unwrap()
            .contains_key(SsfEventType::SessionRevoked.uri())
    );
}

#[tokio::test]
async fn no_authorization_header_is_sent_when_none_is_stored() {
    let w = world().await;
    let receiver = Receiver::start(202).await;
    let stream = w.push_stream(&receiver, None).await;
    let pending = w.pending(&stream, &revoked());
    let outcome = w
        .deliverer()
        .deliver_attempt(&w.message(&stream, &pending))
        .await
        .unwrap();
    assert!(is_delivered(&outcome, 202));
    assert!(!receiver.requests()[0].headers.contains_key("authorization"));
}

/// Ed25519 is deterministic and the event is fixed at production: a retry
/// carries the byte-identical SET, one `jti` (D-48).
#[tokio::test]
async fn a_retried_push_carries_the_identical_set() {
    let w = world().await;
    let receiver = Receiver::start(503).await;
    let stream = w.push_stream(&receiver, None).await;
    let pending = w.pending(&stream, &revoked());
    let message = w.message(&stream, &pending);
    let deliverer = w.deliverer();

    assert!(matches!(
        deliverer.deliver_attempt(&message).await.unwrap(),
        DeliveryOutcome::Retry { .. }
    ));
    receiver.set_reply(Reply::status(202));
    let mut second = message.clone();
    second.attempt = 1;
    assert!(is_delivered(
        &deliverer.deliver_attempt(&second).await.unwrap(),
        202
    ));
    let seen = receiver.requests();
    assert_eq!(seen.len(), 2);
    assert!(seen[0].body == seen[1].body);
}

// ---------------------------------------------------------------------------
// D-49: the response mapping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_2xx_is_delivered() {
    let w = world().await;
    let receiver = Receiver::start(202).await;
    let stream = w.push_stream(&receiver, None).await;
    for status in [200u16, 201, 202, 204] {
        receiver.set_reply(Reply::status(status));
        let pending = w.pending(&stream, &revoked());
        let outcome = w
            .deliverer()
            .deliver_attempt(&w.message(&stream, &pending))
            .await
            .unwrap();
        assert!(is_delivered(&outcome, status));
    }
}

/// A `400` whose body carries an RFC 8935 `err` is dead-lettered with the code
/// in the reason (which becomes the audit row), and a free-text description the
/// receiver adds is not copied anywhere.
#[tokio::test]
async fn a_400_with_an_rfc_8935_error_is_dead_lettered_with_the_code() {
    let w = world().await;
    let receiver = Receiver::start(400).await;
    let stream = w.push_stream(&receiver, None).await;
    for code in RFC_8935_ERROR_CODES {
        receiver.set_reply(Reply {
            status: 400,
            body: serde_json::json!({ "err": code, "description": "call me on 555-0100" })
                .to_string(),
            headers: vec![("Content-Type".into(), "application/json".into())],
        });
        let pending = w.pending(&stream, &revoked());
        let outcome = w
            .deliverer()
            .deliver_attempt(&w.message(&stream, &pending))
            .await
            .unwrap();
        assert!(matches!(outcome, DeliveryOutcome::DeadLetter { .. }));
        assert!(reason_of(&outcome).contains(code));
        assert!(!reason_of(&outcome).contains("555"));
    }
}

/// D-53 (8): a `400` without a known RFC 8935 code will not change on retry:
/// dead-lettered, the reason the status and nothing the receiver said.
#[tokio::test]
async fn a_400_without_a_known_code_is_dead_lettered_with_its_status() {
    let w = world().await;
    let receiver = Receiver::start(400).await;
    let stream = w.push_stream(&receiver, None).await;
    for body in [
        "",
        "not json",
        r#"{"err":"invented"}"#,
        r#"{"error":"invalid_key"}"#,
    ] {
        receiver.set_reply(Reply {
            status: 400,
            body: body.into(),
            headers: Vec::new(),
        });
        let pending = w.pending(&stream, &revoked());
        let outcome = w
            .deliverer()
            .deliver_attempt(&w.message(&stream, &pending))
            .await
            .unwrap();
        assert!(matches!(outcome, DeliveryOutcome::DeadLetter { .. }));
        assert_eq!(reason_of(&outcome), "HTTP 400");
    }
}

/// D-53 (8): any other `4xx` — the ones D-49 does not name — dead-letters with
/// the reason `HTTP <status>`.
#[tokio::test]
async fn any_other_4xx_is_dead_lettered_with_its_status() {
    let w = world().await;
    let receiver = Receiver::start(410).await;
    let stream = w.push_stream(&receiver, None).await;
    for status in [402u16, 405, 409, 410, 413, 415, 422, 451] {
        receiver.set_reply(Reply::status(status));
        let pending = w.pending(&stream, &revoked());
        let outcome = w
            .deliverer()
            .deliver_attempt(&w.message(&stream, &pending))
            .await
            .unwrap();
        assert!(
            matches!(outcome, DeliveryOutcome::DeadLetter { .. }),
            "{status}"
        );
        assert_eq!(reason_of(&outcome), format!("HTTP {status}"));
    }
}

/// D-53 (8), (9): a `3xx` retries, and is never followed.
#[tokio::test]
async fn a_3xx_is_retried_and_never_followed() {
    let w = world().await;
    let target = Receiver::start(202).await;
    let receiver = Receiver::start(302).await;
    let stream = w.push_stream(&receiver, Some(credential())).await;
    for status in [300u16, 301, 302, 303, 307, 308] {
        receiver.set_reply(Reply {
            status,
            body: String::new(),
            headers: vec![("Location".into(), target.url())],
        });
        let pending = w.pending(&stream, &revoked());
        let outcome = w
            .deliverer()
            .deliver_attempt(&w.message(&stream, &pending))
            .await
            .unwrap();
        assert!(matches!(outcome, DeliveryOutcome::Retry { .. }), "{status}");
        assert!(reason_of(&outcome).contains("redirect"));
    }
    assert!(
        target.requests().is_empty(),
        "the redirect target saw nothing"
    );
}

/// The response body is read to at most 64 KiB: a `400` whose code sits beyond
/// that is not a coded rejection.
#[tokio::test]
async fn the_response_body_is_capped() {
    let w = world().await;
    let receiver = Receiver::start(400).await;
    let stream = w.push_stream(&receiver, None).await;
    let padding = " ".repeat(200 * 1024);
    receiver.set_reply(Reply {
        status: 400,
        body: format!(r#"{{"pad":"{padding}","err":"invalid_key"}}"#),
        headers: Vec::new(),
    });
    let pending = w.pending(&stream, &revoked());
    let outcome = w
        .deliverer()
        .deliver_attempt(&w.message(&stream, &pending))
        .await
        .unwrap();
    // The code sits beyond the cap, so it is not read: an uncoded 400.
    assert!(matches!(outcome, DeliveryOutcome::DeadLetter { .. }));
    assert_eq!(reason_of(&outcome), "HTTP 400");
}

#[tokio::test]
async fn a_refused_credential_is_dead_lettered() {
    let w = world().await;
    let receiver = Receiver::start(401).await;
    let stream = w.push_stream(&receiver, Some(credential())).await;
    for status in [401u16, 403] {
        receiver.set_reply(Reply::status(status));
        let pending = w.pending(&stream, &revoked());
        let outcome = w
            .deliverer()
            .deliver_attempt(&w.message(&stream, &pending))
            .await
            .unwrap();
        assert!(matches!(outcome, DeliveryOutcome::DeadLetter { .. }));
        assert!(reason_of(&outcome).contains(&status.to_string()));
    }
}

#[tokio::test]
async fn the_retryable_statuses_are_retried() {
    let w = world().await;
    let receiver = Receiver::start(500).await;
    let stream = w.push_stream(&receiver, None).await;
    // D-49's list; every other 4xx dead-letters (D-53 (8)).
    for status in [404u16, 408, 429, 500, 502, 503, 504] {
        receiver.set_reply(Reply::status(status));
        let pending = w.pending(&stream, &revoked());
        let outcome = w
            .deliverer()
            .deliver_attempt(&w.message(&stream, &pending))
            .await
            .unwrap();
        assert!(matches!(outcome, DeliveryOutcome::Retry { .. }), "{status}");
    }
}

#[tokio::test]
async fn no_connection_is_retried() {
    let w = world().await;
    // A port nothing listens on.
    let closed = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    let stream = w
        .stream(
            SsfDeliveryMethod::Push,
            SsfStreamStatus::Enabled,
            Some(format!("http://127.0.0.1:{closed}/ssf")),
            None,
        )
        .await;
    let pending = w.pending(&stream, &revoked());
    let outcome = w
        .deliverer()
        .deliver_attempt(&w.message(&stream, &pending))
        .await
        .unwrap();
    assert!(matches!(outcome, DeliveryOutcome::Retry { .. }));
}

/// D-49: no redirect is followed. The guard would follow one after re-running
/// itself on the `Location`; this deliverer refuses the second hop, so the SET
/// and the credential reach nobody the administrator did not name.
#[tokio::test]
async fn a_redirect_is_not_followed() {
    let w = world().await;
    // A public address literal: the guard admits it, so the only thing between
    // the SET and that host is the deliverer's own refusal. Nothing is sent.
    let receiver = Receiver::start(307).await;
    receiver.set_reply(Reply {
        status: 307,
        body: String::new(),
        headers: vec![("Location".into(), "https://93.184.216.34/ssf".into())],
    });
    let stream = w.push_stream(&receiver, Some(credential())).await;
    let pending = w.pending(&stream, &revoked());
    let outcome = w
        .deliverer()
        .deliver_attempt(&w.message(&stream, &pending))
        .await
        .unwrap();
    assert!(matches!(outcome, DeliveryOutcome::Retry { .. }));
    assert!(reason_of(&outcome).contains("redirect"));
    assert_eq!(receiver.requests().len(), 1);
}

#[tokio::test]
async fn a_redirect_to_a_private_address_is_refused_by_the_guard_too() {
    let w = world().await;
    let sink = Receiver::start(202).await;
    let receiver = Receiver::start(302).await;
    receiver.set_reply(Reply {
        status: 302,
        body: String::new(),
        headers: vec![("Location".into(), sink.url())],
    });
    let stream = w.push_stream(&receiver, Some(credential())).await;
    let pending = w.pending(&stream, &revoked());
    let outcome = w
        .deliverer()
        .deliver_attempt(&w.message(&stream, &pending))
        .await
        .unwrap();
    assert!(matches!(outcome, DeliveryOutcome::Retry { .. }));
    assert!(
        sink.requests().is_empty(),
        "the redirect target saw nothing"
    );
}

/// T-392: at delivery the production deliverer — `guarded_fetch` with
/// `allow_private = false` — refuses an endpoint that resolves to an internal
/// address, by literal and by name, and nothing reaches the listener.
#[tokio::test]
async fn the_address_guard_refuses_an_internal_endpoint_at_delivery() {
    let w = world().await;
    let receiver = Receiver::start(202).await;
    for endpoint in [
        format!("https://127.0.0.1:{}/ssf", receiver.port),
        format!("https://localhost:{}/ssf", receiver.port),
        format!("https://[::1]:{}/ssf", receiver.port),
        "https://169.254.169.254/latest/meta-data".to_owned(),
        "https://10.0.0.5/ssf".to_owned(),
    ] {
        let stream = w
            .stream(
                SsfDeliveryMethod::Push,
                SsfStreamStatus::Enabled,
                Some(endpoint),
                Some(credential()),
            )
            .await;
        let pending = w.pending(&stream, &revoked());
        let outcome = w
            .production_deliverer()
            .deliver_attempt(&w.message(&stream, &pending))
            .await
            .unwrap();
        assert!(matches!(outcome, DeliveryOutcome::Retry { .. }));
        // Refused by the guard before any connection: by address, or (for a
        // bracketed literal the resolver cannot read) as an unresolvable name.
        let reason = reason_of(&outcome);
        assert!(reason.contains("does not connect") || reason.contains("did not resolve"));
    }
    assert!(receiver.requests().is_empty());

    // A plaintext endpoint is refused before anything resolves.
    let plain = w
        .stream(
            SsfDeliveryMethod::Push,
            SsfStreamStatus::Enabled,
            Some(receiver.url()),
            None,
        )
        .await;
    let pending = w.pending(&plain, &revoked());
    let outcome = w
        .production_deliverer()
        .deliver_attempt(&w.message(&plain, &pending))
        .await
        .unwrap();
    assert!(matches!(outcome, DeliveryOutcome::DeadLetter { .. }));
    assert!(receiver.requests().is_empty());
}

// ---------------------------------------------------------------------------
// D-48, D-51: the stream as it is at the attempt
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_disabled_stream_delivers_nothing_and_a_queued_event_is_dead_lettered() {
    let w = world().await;
    let receiver = Receiver::start(202).await;
    let stream = w.push_stream(&receiver, None).await;
    let pending = w.pending(&stream, &revoked());
    let message = w.message(&stream, &pending);
    // Disabled after the event was queued.
    w.set_status(&stream, SsfStreamStatus::Disabled).await;

    let outcome = w.deliverer().deliver_attempt(&message).await.unwrap();
    assert!(matches!(outcome, DeliveryOutcome::DeadLetter { .. }));
    assert!(receiver.requests().is_empty());
    assert_eq!(w.buffer.count(w.tenant, stream.id).await.unwrap(), 0);
}

#[tokio::test]
async fn a_paused_stream_moves_the_event_to_the_buffer_and_acknowledges() {
    let w = world().await;
    let receiver = Receiver::start(202).await;
    let stream = w.push_stream(&receiver, None).await;
    let pending = w.pending(&stream, &revoked());
    let message = w.message(&stream, &pending);
    w.set_status(&stream, SsfStreamStatus::Paused).await;

    let outcome = w.deliverer().deliver_attempt(&message).await.unwrap();
    assert!(matches!(
        outcome,
        DeliveryOutcome::Delivered {
            response_status: None
        }
    ));
    assert!(receiver.requests().is_empty());
    let held = w
        .buffer
        .list_oldest(w.tenant, stream.id, 10, Utc::now())
        .await
        .unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].jti, pending.jti);
}

#[tokio::test]
async fn a_stream_that_became_a_poll_stream_buffers_the_event() {
    let w = world().await;
    let receiver = Receiver::start(202).await;
    let stream = w.push_stream(&receiver, None).await;
    let pending = w.pending(&stream, &revoked());
    let message = w.message(&stream, &pending);
    let mut update = SsfStreamUpdate::from_stream(&stream);
    update.delivery_method = SsfDeliveryMethod::Poll;
    update.endpoint_url = None;
    update.authorization_header = SecretChange::Clear;
    w.streams.update(w.tenant, stream.id, update).await.unwrap();

    let outcome = w.deliverer().deliver_attempt(&message).await.unwrap();
    assert!(matches!(outcome, DeliveryOutcome::Delivered { .. }));
    assert!(receiver.requests().is_empty());
    assert_eq!(w.buffer.count(w.tenant, stream.id).await.unwrap(), 1);
}

#[tokio::test]
async fn a_narrowed_stream_does_not_send_what_it_no_longer_wants() {
    let w = world().await;
    let receiver = Receiver::start(202).await;
    let stream = w.push_stream(&receiver, None).await;
    let pending = w.pending(&stream, &revoked());
    let message = w.message(&stream, &pending);
    let mut update = SsfStreamUpdate::from_stream(&stream);
    update.events_requested = vec![SsfEventType::AccountEnabled];
    w.streams.update(w.tenant, stream.id, update).await.unwrap();

    let outcome = w.deliverer().deliver_attempt(&message).await.unwrap();
    assert!(matches!(outcome, DeliveryOutcome::DeadLetter { .. }));
    assert!(receiver.requests().is_empty());
}

#[tokio::test]
async fn a_stream_that_is_gone_dead_letters_the_event() {
    let w = world().await;
    let receiver = Receiver::start(202).await;
    let stream = w.push_stream(&receiver, None).await;
    let pending = w.pending(&stream, &revoked());
    let message = w.message(&stream, &pending);
    w.streams.delete(w.tenant, stream.id).await.unwrap();

    let outcome = w.deliverer().deliver_attempt(&message).await.unwrap();
    assert!(matches!(outcome, DeliveryOutcome::DeadLetter { .. }));
    assert!(receiver.requests().is_empty());
}

/// The announcement of a disable follows the disable (SSF §8.1.5, D-51); it is
/// the one event a disabled stream still sends, and only while it is true.
#[tokio::test]
async fn the_announcement_of_a_status_goes_out_only_while_it_is_the_status() {
    let w = world().await;
    let receiver = Receiver::start(202).await;
    let stream = w.push_stream(&receiver, None).await;

    let disabled = w.set_status(&stream, SsfStreamStatus::Disabled).await;
    let announcement = prepare_stream_updated(&disabled, Utc::now());
    let outcome = w
        .deliverer()
        .deliver_attempt(&w.message(&disabled, &announcement))
        .await
        .unwrap();
    assert!(is_delivered(&outcome, 202));
    let claims = verify(&receiver.requests()[0].body, &w.auth, &stream.audience);
    let events = claims["events"].as_object().unwrap();
    let (_, event) = events.iter().next().unwrap();
    assert_eq!(event["status"], "disabled");

    // Once the stream is enabled again, the stale announcement is not sent.
    w.set_status(&disabled, SsfStreamStatus::Enabled).await;
    let outcome = w
        .deliverer()
        .deliver_attempt(&w.message(&disabled, &announcement))
        .await
        .unwrap();
    assert!(matches!(outcome, DeliveryOutcome::DeadLetter { .. }));
    assert_eq!(receiver.requests().len(), 1);
}

#[tokio::test]
async fn a_malformed_message_is_dead_lettered_without_a_request() {
    let w = world().await;
    let receiver = Receiver::start(202).await;
    let stream = w.push_stream(&receiver, None).await;
    let pending = w.pending(&stream, &revoked());

    let mut garbled = w.message(&stream, &pending);
    garbled.payload = serde_json::json!({ "not": "an event" });
    let mut mismatched = w.message(&stream, &pending);
    mismatched.delivery_id = Uuid::new_v4();
    let mut other_kind = w.message(&stream, &pending);
    other_kind.kind = OutboundKind::Webhook;

    for message in [garbled, mismatched, other_kind] {
        let outcome = w.deliverer().deliver_attempt(&message).await.unwrap();
        assert!(matches!(outcome, DeliveryOutcome::DeadLetter { .. }));
    }
    assert!(receiver.requests().is_empty());
}

// ---------------------------------------------------------------------------
// The outbox
// ---------------------------------------------------------------------------

#[derive(Default)]
struct RecordingPublisher {
    sent: Mutex<Vec<OutboundMessage>>,
    /// Fail every enqueue after this many succeeded.
    fail_after: Mutex<Option<usize>>,
}

impl OutboundPublisher for RecordingPublisher {
    fn enqueue<'a>(
        &'a self,
        msg: &'a OutboundMessage,
    ) -> OutboundFuture<'a, Result<(), OutboundError>> {
        Box::pin(async move {
            let mut sent = self.sent.lock().unwrap();
            if let Some(limit) = *self.fail_after.lock().unwrap()
                && sent.len() >= limit
            {
                return Err(OutboundError::Enqueue("the broker is down".into()));
            }
            sent.push(msg.clone());
            Ok(())
        })
    }
}

fn outbox(w: &World) -> (SsfOutboxService<Buffer>, Arc<RecordingPublisher>) {
    let publisher = Arc::new(RecordingPublisher::default());
    (
        SsfOutboxService::new(
            w.buffer.clone(),
            publisher.clone() as Arc<dyn OutboundPublisher>,
        ),
        publisher,
    )
}

#[tokio::test]
async fn an_enabled_push_stream_enqueues_one_message_with_the_unsigned_event() {
    let w = world().await;
    let (outbox, publisher) = outbox(&w);
    let stream = w
        .stream(
            SsfDeliveryMethod::Push,
            SsfStreamStatus::Enabled,
            Some("https://rp.example.test/ssf".into()),
            None,
        )
        .await;
    let pending = w.pending(&stream, &revoked());
    outbox.submit(&stream, &pending).await.unwrap();

    let sent = publisher.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].kind, OutboundKind::SsfPush);
    assert_eq!(sent[0].tenant_id, stream.tenant_id);
    assert_eq!(sent[0].target_id, stream.id);
    assert_eq!(Some(sent[0].delivery_id), delivery_id_of(&pending));
    assert_eq!(sent[0].event_type, pending.event_uri);
    assert_eq!(sent[0].attempt, 0);
    assert!(serde_json::from_value::<SsfPendingEvent>(sent[0].payload.clone()).unwrap() == pending);
    // Unsigned: the payload is the event, not a token.
    assert!(sent[0].payload.get("jti").is_some());
    assert!(!sent[0].payload.to_string().contains("eyJ"));
    assert_eq!(w.buffer.count(w.tenant, stream.id).await.unwrap(), 0);
}

#[tokio::test]
async fn poll_streams_and_paused_streams_buffer_and_enqueue_nothing() {
    let w = world().await;
    let (outbox, publisher) = outbox(&w);
    for (method, status) in [
        (SsfDeliveryMethod::Poll, SsfStreamStatus::Enabled),
        (SsfDeliveryMethod::Poll, SsfStreamStatus::Paused),
        (SsfDeliveryMethod::Push, SsfStreamStatus::Paused),
    ] {
        let endpoint =
            (method == SsfDeliveryMethod::Push).then(|| "https://rp.example.test/ssf".to_owned());
        let stream = w.stream(method, status, endpoint, None).await;
        // Prepared while the stream is not disabled; the event is the same.
        let pending = w.pending(&stream, &revoked());
        outbox.submit(&stream, &pending).await.unwrap();
        let held = w
            .buffer
            .list_oldest(w.tenant, stream.id, 10, Utc::now())
            .await
            .unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].jti, pending.jti);
    }
    assert!(publisher.sent.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_disabled_stream_refuses_and_keeps_nothing() {
    let w = world().await;
    let (outbox, publisher) = outbox(&w);
    for (method, endpoint) in [
        (
            SsfDeliveryMethod::Push,
            Some("https://rp.example.test/ssf".to_owned()),
        ),
        (SsfDeliveryMethod::Poll, None),
    ] {
        let enabled = w
            .stream(method, SsfStreamStatus::Enabled, endpoint, None)
            .await;
        let pending = w.pending(&enabled, &revoked());
        let disabled = w.set_status(&enabled, SsfStreamStatus::Disabled).await;
        assert_eq!(
            outbox.submit(&disabled, &pending).await,
            Err(SsfOutboxError::Disabled)
        );
        assert_eq!(w.buffer.count(w.tenant, disabled.id).await.unwrap(), 0);

        // A verification event is refused the same way.
        assert!(prepare_verification(&disabled, None, Utc::now()).is_err());
    }
    assert!(publisher.sent.lock().unwrap().is_empty());
}

#[tokio::test]
async fn the_announcement_of_a_status_is_enqueued_for_a_push_stream_whatever_the_status() {
    let w = world().await;
    let (outbox, publisher) = outbox(&w);
    let push = w
        .stream(
            SsfDeliveryMethod::Push,
            SsfStreamStatus::Enabled,
            Some("https://rp.example.test/ssf".into()),
            None,
        )
        .await;
    for status in [SsfStreamStatus::Disabled, SsfStreamStatus::Paused] {
        let now_in = w.set_status(&push, status).await;
        outbox
            .submit(&now_in, &prepare_stream_updated(&now_in, Utc::now()))
            .await
            .unwrap();
    }
    assert_eq!(publisher.sent.lock().unwrap().len(), 2);

    // A disabled poll stream holds nothing, not even the announcement.
    let poll = w
        .stream(
            SsfDeliveryMethod::Poll,
            SsfStreamStatus::Disabled,
            None,
            None,
        )
        .await;
    assert_eq!(
        outbox
            .submit(&poll, &prepare_stream_updated(&poll, Utc::now()))
            .await,
        Err(SsfOutboxError::Disabled)
    );
}

#[tokio::test]
async fn a_failing_broker_is_a_failure_that_carries_no_event() {
    let w = world().await;
    let (outbox, publisher) = outbox(&w);
    *publisher.fail_after.lock().unwrap() = Some(0);
    let stream = w
        .stream(
            SsfDeliveryMethod::Push,
            SsfStreamStatus::Enabled,
            Some("https://rp.example.test/ssf".into()),
            None,
        )
        .await;
    let pending = w.pending(&stream, &revoked());
    let error = outbox.submit(&stream, &pending).await.unwrap_err();
    let SsfOutboxError::Failed(text) = error else {
        panic!("a broker failure is a Failed")
    };
    assert!(!text.contains(&pending.jti));
}

/// D-48: resuming a paused push stream enqueues its held events oldest first.
#[tokio::test]
async fn resuming_a_paused_push_stream_enqueues_the_held_events_oldest_first() {
    let w = world().await;
    let (outbox, publisher) = outbox(&w);
    let paused = w
        .stream(
            SsfDeliveryMethod::Push,
            SsfStreamStatus::Paused,
            Some("https://rp.example.test/ssf".into()),
            None,
        )
        .await;
    let mut order = Vec::new();
    for _ in 0..3 {
        let enabled_view = SsfStream {
            status: SsfStreamStatus::Enabled,
            ..paused.clone()
        };
        let pending = w.pending(&enabled_view, &revoked());
        outbox.submit(&paused, &pending).await.unwrap();
        order.push(pending.jti);
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    assert_eq!(w.buffer.count(w.tenant, paused.id).await.unwrap(), 3);

    // Still paused: nothing is released.
    assert_eq!(outbox.resume(&paused).await.unwrap(), 0);
    assert!(publisher.sent.lock().unwrap().is_empty());

    let enabled = w.set_status(&paused, SsfStreamStatus::Enabled).await;
    assert_eq!(outbox.resume(&enabled).await.unwrap(), 3);
    let sent: Vec<String> = publisher
        .sent
        .lock()
        .unwrap()
        .iter()
        .map(|m| {
            serde_json::from_value::<SsfPendingEvent>(m.payload.clone())
                .unwrap()
                .jti
        })
        .collect();
    assert_eq!(sent, order);
    assert_eq!(w.buffer.count(w.tenant, paused.id).await.unwrap(), 0);
    // Nothing left to release.
    assert_eq!(outbox.resume(&enabled).await.unwrap(), 0);
}

#[tokio::test]
async fn a_failed_release_keeps_what_was_not_enqueued() {
    let w = world().await;
    let (outbox, publisher) = outbox(&w);
    let paused = w
        .stream(
            SsfDeliveryMethod::Push,
            SsfStreamStatus::Paused,
            Some("https://rp.example.test/ssf".into()),
            None,
        )
        .await;
    for _ in 0..3 {
        let view = SsfStream {
            status: SsfStreamStatus::Enabled,
            ..paused.clone()
        };
        outbox
            .submit(&paused, &w.pending(&view, &revoked()))
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    *publisher.fail_after.lock().unwrap() = Some(1);
    let enabled = w.set_status(&paused, SsfStreamStatus::Enabled).await;
    assert!(outbox.resume(&enabled).await.is_err());
    assert_eq!(publisher.sent.lock().unwrap().len(), 1);
    assert_eq!(w.buffer.count(w.tenant, paused.id).await.unwrap(), 2);

    // The broker is back: the rest follows.
    *publisher.fail_after.lock().unwrap() = None;
    assert_eq!(outbox.resume(&enabled).await.unwrap(), 2);
    assert_eq!(w.buffer.count(w.tenant, paused.id).await.unwrap(), 0);
}

#[tokio::test]
async fn a_poll_stream_releases_nothing_on_resume() {
    let w = world().await;
    let (outbox, publisher) = outbox(&w);
    let poll = w
        .stream(
            SsfDeliveryMethod::Poll,
            SsfStreamStatus::Enabled,
            None,
            None,
        )
        .await;
    outbox
        .submit(&poll, &w.pending(&poll, &revoked()))
        .await
        .unwrap();
    assert_eq!(outbox.resume(&poll).await.unwrap(), 0);
    assert_eq!(w.buffer.count(w.tenant, poll.id).await.unwrap(), 1);
    assert!(publisher.sent.lock().unwrap().is_empty());
}
