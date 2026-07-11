//! Closure-handler AMQP consumer (D-07): `consume(queue, handler)`.
//!
//! The SDK owns the full ack/nack loop. Every delivery is HMAC-verified
//! (CONTRACT.md §8) BEFORE the user-supplied handler closure is ever
//! invoked. On any verification failure (signature mismatch, missing
//! signature in the default strict mode, or a body that fails to parse as
//! JSON) the delivery is nacked WITHOUT requeue and a security event is
//! emitted — the event never contains the received or expected HMAC value.
//! Only a verified delivery reaches the handler, and only then is it acked.
//!
//! This design (D-07) is chosen over exposing a raw `Stream` that would push
//! ack/nack correctness onto the caller: the nack-without-requeue contract
//! on verification failure is security-sensitive, so the API makes it
//! impossible to misuse by never handing the caller an unverified message.
//!
//! ## NEW-4: v2 replay protection (CONTRACT.md §8 "v2 — Replay Protection")
//!
//! As of `key_version = 2` the signed body also carries `nonce` and
//! `issued_at`. Because verification re-serializes the parsed
//! `serde_json::Value` (minus `hmac_signature`) in the order the keys
//! arrived on the wire (SDK-Q01/`preserve_order`), these two fields are
//! automatically covered by the HMAC with no canonicalization change. Once a
//! signature verifies, [`verify_and_dispatch`] applies three additional
//! gates — the SAME nack-without-requeue path as an invalid signature —
//! before the handler is ever invoked:
//!   - `key_version` must be `>= 2` (the hard cutover; a v1 message is
//!     rejected outright, there is no grace path).
//!   - `issued_at` must lie within `±skew` of the consumer's clock (default
//!     5 minutes, see [`DEFAULT_FRESHNESS_SKEW_SECS`]).
//!   - `nonce` must not have already been seen within the freshness window
//!     (an in-memory, TTL-bounded dedup set — see [`ReplayGuard`]).

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};

use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, BasicNackOptions, QueueDeclareOptions};
use lapin::types::FieldTable;
use lapin::{Channel, Connection, ConnectionProperties};

use crate::amqp::hmac::verify_payload;
use crate::error::AxiamError;
use crate::sensitive::Sensitive;

/// Minimum accepted envelope `key_version` (NEW-4 hard cutover,
/// CONTRACT.md §8 "v2 — Replay Protection"). A message signed under an
/// older key version predates the mandatory `nonce`/`issued_at`
/// replay-protection fields and is rejected outright — there is no v1
/// grace path (mirrors the server's `MIN_ACCEPTED_KEY_VERSION`,
/// `crates/axiam-amqp/src/messages.rs:52`).
pub(crate) const MIN_ACCEPTED_KEY_VERSION: u8 = 2;

/// Default freshness skew for the `issued_at` acceptance window (NEW-4,
/// CONTRACT.md §8): a message is accepted only when its `issued_at` lies
/// within ±5 minutes of the consumer's current clock (mirrors the server's
/// `DEFAULT_FRESHNESS_SKEW_SECS`, `crates/axiam-amqp/src/messages.rs:58`).
/// [`consume`] lets a caller override this via its `freshness_skew`
/// parameter.
pub(crate) const DEFAULT_FRESHNESS_SKEW_SECS: i64 = 300;

/// The v2 replay-protection fields extracted from a body whose HMAC has
/// already verified. Extraction failing (missing/malformed field) is
/// itself a rejection cause under the NEW-4 hard cutover — there is no
/// fallback for a message that omits a mandatory v2 field.
struct ReplayFields {
    key_version: u8,
    nonce: String,
    issued_at: DateTime<Utc>,
}

/// Parse the mandatory NEW-4 fields out of a verified delivery body.
/// Returns `None` if any of `key_version`/`nonce`/`issued_at` is absent or
/// not the expected type/format.
fn extract_replay_fields(body: &serde_json::Value) -> Option<ReplayFields> {
    let key_version = u8::try_from(body.get("key_version")?.as_u64()?).ok()?;
    let nonce = body.get("nonce")?.as_str()?.to_owned();
    let issued_at = DateTime::parse_from_rfc3339(body.get("issued_at")?.as_str()?)
        .ok()?
        .with_timezone(&Utc);
    Some(ReplayFields {
        key_version,
        nonce,
        issued_at,
    })
}

/// In-memory nonce-replay guard + `issued_at` freshness gate (NEW-4).
///
/// One `ReplayGuard` is shared (via `Arc`) across every delivery processed
/// by [`consume`], so a nonce observed on one message is remembered for
/// every subsequent one on the same consumer. It never touches durable
/// storage — CONTRACT.md §8 permits "reject within the freshness window" as
/// the minimum bar for SDKs that do not persist nonces, which this
/// satisfies: a nonce is retained for `2 × skew` (the full width of the
/// freshness window on either side of `now`), which is always at least as
/// long as a replayed message could still pass the freshness gate on its
/// own — so a replay can never sneak through after its entry has been
/// pruned. Pruning is opportunistic (done inline on every check, see
/// [`check_and_record_nonce`](Self::check_and_record_nonce)) rather than via
/// a background sweep task, which is what keeps the map naturally bounded.
pub(crate) struct ReplayGuard {
    skew: chrono::Duration,
    seen: Mutex<HashMap<String, Instant>>,
}

impl ReplayGuard {
    /// Build a guard with an explicit freshness skew.
    pub(crate) fn new(skew: chrono::Duration) -> Self {
        Self {
            skew,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Build a guard using [`DEFAULT_FRESHNESS_SKEW_SECS`] (5 minutes) — what
    /// [`consume`] uses when no override is supplied.
    pub(crate) fn with_default_skew() -> Self {
        Self::new(chrono::Duration::seconds(DEFAULT_FRESHNESS_SKEW_SECS))
    }

    /// Nonce dedup TTL: `2 × skew`, i.e. the full width of the freshness
    /// acceptance window. Falls back to `2 × DEFAULT_FRESHNESS_SKEW_SECS` in
    /// the (practically unreachable, since skew is always a small duration)
    /// case where the doubled skew overflows `std::time::Duration`.
    fn ttl(&self) -> StdDuration {
        (self.skew * 2)
            .to_std()
            .unwrap_or_else(|_| StdDuration::from_secs(DEFAULT_FRESHNESS_SKEW_SECS as u64 * 2))
    }

    /// `true` when `issued_at` lies within ±skew of `now` — mirrors the
    /// server's `is_fresh` (`crates/axiam-amqp/src/messages.rs:86-88`).
    fn is_fresh(&self, issued_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        now.signed_duration_since(issued_at).abs() <= self.skew
    }

    /// Returns `true` the first time `nonce` is observed (accept); `false`
    /// if it was already recorded and hasn't expired yet (a replay).
    /// Expired entries are pruned on every call.
    fn check_and_record_nonce(&self, nonce: &str) -> bool {
        let ttl = self.ttl();
        let now = Instant::now();
        let mut seen = match self.seen.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        seen.retain(|_, expiry| *expiry > now);
        if seen.contains_key(nonce) {
            return false;
        }
        seen.insert(nonce.to_owned(), now + ttl);
        true
    }
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::with_default_skew()
    }
}

/// Check the NEW-4 replay-protection gates against an already-HMAC-verified
/// body. `Ok(())` means the message passes all three gates; `Err` carries a
/// short, HMAC-free reason string suitable for the security-event log.
fn validate_v2_replay_protection(
    body: &serde_json::Value,
    replay: &ReplayGuard,
) -> Result<(), &'static str> {
    let fields = extract_replay_fields(body).ok_or(
        "missing or malformed key_version/nonce/issued_at (NEW-4 v2 fields are mandatory)",
    )?;
    if fields.key_version < MIN_ACCEPTED_KEY_VERSION {
        return Err("key_version below the minimum accepted version (NEW-4 hard cutover)");
    }
    if !replay.is_fresh(fields.issued_at, Utc::now()) {
        return Err("issued_at outside the freshness skew window");
    }
    if !replay.check_and_record_nonce(&fields.nonce) {
        return Err("nonce already seen (replay)");
    }
    Ok(())
}

/// A minimal seam over the AMQP acknowledgement primitives this module
/// needs. `lapin::message::Delivery` implements this directly (via its
/// `Deref<Target = Acker>`); tests provide a recording fake that never
/// touches a live broker, so the security-sensitive nack-without-requeue
/// behavior of [`verify_and_dispatch`] can be asserted without a running
/// RabbitMQ instance.
pub(crate) trait AckableDelivery {
    /// The raw message payload bytes.
    fn data(&self) -> &[u8];
    /// Acknowledge the delivery (message processed successfully).
    fn ack(&self) -> impl Future<Output = ()> + Send;
    /// Negatively acknowledge the delivery. `requeue` MUST be `false` on
    /// every failure path in this module (verification failure, parse
    /// failure) so poison/unverifiable messages do not loop the queue.
    fn nack(&self, requeue: bool) -> impl Future<Output = ()> + Send;
}

impl AckableDelivery for lapin::message::Delivery {
    fn data(&self) -> &[u8] {
        &self.data
    }

    async fn ack(&self) {
        let _ = self.acker.ack(BasicAckOptions::default()).await;
    }

    async fn nack(&self, requeue: bool) {
        let _ = self
            .acker
            .nack(BasicNackOptions {
                requeue,
                ..Default::default()
            })
            .await;
    }
}

/// Verify a single delivery's HMAC signature (CONTRACT.md §8 steps a-g),
/// then apply the NEW-4 v2 replay-protection gates (`key_version`,
/// freshness, nonce dedup via `replay`) and, only if everything passes,
/// invoke `handler` with the parsed body before acking. On any failure the
/// delivery is nacked without requeue and a security event is emitted
/// (never containing the HMAC value).
///
/// This is the load-bearing, separately-testable unit backing
/// [`consume`]'s per-message loop — kept generic over [`AckableDelivery`]
/// so it can be exercised against a recording fake in unit tests without a
/// live broker.
pub(crate) async fn verify_and_dispatch<D, F, Fut>(
    delivery: &D,
    signing_key: &[u8],
    handler: &F,
    replay: &ReplayGuard,
) where
    D: AckableDelivery,
    F: Fn(serde_json::Value) -> Fut + Send + Sync,
    Fut: Future<Output = ()> + Send,
{
    // Step: parse the body as JSON. A body that fails to deserialize is
    // nacked without requeue and never reaches the handler.
    let mut body: serde_json::Value = match serde_json::from_slice(delivery.data()) {
        Ok(v) => v,
        Err(_) => {
            tracing::warn!(
                target: "axiam_sdk::security",
                "AMQP message body failed JSON parse; nacking without requeue"
            );
            delivery.nack(false).await;
            return;
        }
    };

    // Extract hmac_signature, then remove it from the body object before
    // re-serializing — matches the server's "field set to None before
    // signing" contract (CONTRACT.md §8.2b).
    //
    // Canonicalization contract (SDK-Q01): the server computes the HMAC over
    // `serde_json::to_vec` of the concrete message struct with
    // `hmac_signature` omitted, in FIELD-DECLARATION order (e.g. AuthzRequest:
    // correlation_id, tenant_id, subject_id, action, resource_id, scope,
    // key_version). To reproduce those exact bytes here we rely on two things:
    //   1. `serde_json`'s `preserve_order` feature (enabled in Cargo.toml), so
    //      this `Value`'s object map keeps the order the keys arrived in on the
    //      wire — which IS the server's declaration order, since the server
    //      serialized the struct in that order.
    //   2. `shift_remove` (not `remove`, which is `swap_remove` under
    //      `preserve_order` and would move the last field into the removed
    //      slot). `shift_remove` deletes `hmac_signature` while preserving the
    //      relative order of every remaining field, regardless of where
    //      `hmac_signature` sat — so the re-serialized bytes are byte-identical
    //      to what the server signed.
    // This is exact only when the incoming JSON is what the server emitted
    // (compact, declaration order); a re-encoded/pretty-printed body would not
    // match and would (correctly) be rejected as unverifiable.
    let sig = body
        .get("hmac_signature")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    if let Some(obj) = body.as_object_mut() {
        obj.shift_remove("hmac_signature");
    }
    let canonical = match serde_json::to_vec(&body) {
        Ok(bytes) => bytes,
        Err(_) => {
            tracing::warn!(
                target: "axiam_sdk::security",
                "AMQP message body failed to re-serialize for verification; nacking without requeue"
            );
            delivery.nack(false).await;
            return;
        }
    };

    // Strict mode (default, CONTRACT.md §8.3): a missing signature is
    // treated as a verification failure, not a pass-through.
    let verified = match sig {
        Some(ref s) => verify_payload(signing_key, &canonical, s),
        None => false,
    };

    if !verified {
        // Security event: timestamp (via tracing's own event timestamp),
        // exchange/routing-key/tenant context would be added by the
        // connection-level wrapper that has access to `Delivery::exchange`/
        // `routing_key`; this function logs the fact of the failure only.
        // The HMAC values (received or expected) are NEVER included.
        tracing::warn!(
            target: "axiam_sdk::security",
            "AMQP HMAC verification failed; nacking without requeue"
        );
        delivery.nack(false).await;
        return;
    }

    // NEW-4 (CONTRACT.md §8 "v2 — Replay Protection"): a verified signature
    // is necessary but not sufficient. `nonce`/`issued_at` are already
    // covered by the HMAC above (no canonicalization change needed — see
    // the module doc comment), so this is purely acceptance-policy: reject
    // key_version < 2, a stale/future issued_at, or an already-seen nonce
    // via the SAME nack-without-requeue path as an invalid signature.
    if let Err(reason) = validate_v2_replay_protection(&body, replay) {
        tracing::warn!(
            target: "axiam_sdk::security",
            reason,
            "AMQP v2 replay-protection check failed; nacking without requeue"
        );
        delivery.nack(false).await;
        return;
    }

    handler(body).await;
    delivery.ack().await;
}

/// Connect to the AMQP broker at `amqp_url`, declare `queue` as durable if
/// it does not already exist, and consume from it — verifying each
/// delivery's HMAC-SHA256 signature (CONTRACT.md §8) BEFORE invoking
/// `handler`. The handler never sees an unverified message; verification
/// failures are nacked without requeue and logged as a security event.
///
/// `signing_key` MUST be obtained from the AXIAM management API for the
/// tenant whose queue is being consumed (CONTRACT.md §8.1) — hardcoding a
/// signing key is prohibited. It is wrapped in [`Sensitive<Vec<u8>>`] so it
/// can never be logged accidentally.
///
/// `freshness_skew` overrides the NEW-4 `issued_at` acceptance window
/// (default `±5 minutes`, i.e. [`DEFAULT_FRESHNESS_SKEW_SECS`]) — pass
/// `None` to use the default. The same window (doubled) bounds how long a
/// `nonce` is remembered for replay detection; see [`ReplayGuard`].
///
/// This function owns the full ack/nack loop; the closure `handler` is
/// invoked only after successful verification (HMAC signature AND the
/// NEW-4 replay-protection gates) and MUST NOT itself call ack/nack (there
/// is no delivery handle exposed to it).
pub async fn consume<F, Fut>(
    amqp_url: &str,
    queue: &str,
    signing_key: Sensitive<Vec<u8>>,
    freshness_skew: Option<StdDuration>,
    handler: F,
) -> Result<(), AxiamError>
where
    F: Fn(serde_json::Value) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send,
{
    // X-2: refuse a plaintext `amqp://` broker URL (loopback excepted) — signed
    // message bodies and the per-tenant context would otherwise cross an
    // unencrypted link. Require `amqps://` for any routable host.
    if let Ok(parsed) = url::Url::parse(amqp_url) {
        crate::url_guard::ensure_secure_scheme(
            "AMQP url",
            parsed.scheme(),
            parsed.host_str(),
            "amqps",
        )
        .map_err(|message| AxiamError::Network {
            message,
            source: None,
        })?;
    }

    let connection = Connection::connect(amqp_url, ConnectionProperties::default())
        .await
        .map_err(|e| AxiamError::Network {
            message: format!("failed to connect to AMQP broker: {e}"),
            source: None,
        })?;

    let channel: Channel = connection
        .create_channel()
        .await
        .map_err(|e| AxiamError::Network {
            message: format!("failed to create AMQP channel: {e}"),
            source: None,
        })?;

    channel
        .queue_declare(
            queue.into(),
            QueueDeclareOptions {
                durable: true,
                ..Default::default()
            },
            FieldTable::default(),
        )
        .await
        .map_err(|e| AxiamError::Network {
            message: format!("failed to declare AMQP queue: {e}"),
            source: None,
        })?;

    let mut consumer = channel
        .basic_consume(
            queue.into(),
            "axiam-sdk-consumer".into(),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
        .map_err(|e| AxiamError::Network {
            message: format!("failed to start AMQP consumer: {e}"),
            source: None,
        })?;

    let key = Arc::new(signing_key);
    let handler = Arc::new(handler);
    // One ReplayGuard shared across every delivery on this consumer, so a
    // nonce observed on one message is remembered for the lifetime of the
    // loop (NEW-4).
    let replay = Arc::new(
        freshness_skew
            .and_then(|skew| chrono::Duration::from_std(skew).ok())
            .map(ReplayGuard::new)
            .unwrap_or_default(),
    );

    while let Some(delivery_result) = consumer.next().await {
        match delivery_result {
            Ok(delivery) => {
                let key = Arc::clone(&key);
                let handler = Arc::clone(&handler);
                let replay = Arc::clone(&replay);
                verify_and_dispatch(&delivery, key.expose(), handler.as_ref(), replay.as_ref())
                    .await;
            }
            Err(e) => {
                tracing::warn!(target: "axiam_sdk::security", error = %e, "AMQP consumer stream error");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use crate::amqp::hmac::sign_payload;

    /// A recording fake delivery: never touches a live broker. Records
    /// whether `ack` or `nack` (and with which `requeue` value) was called,
    /// so the security-sensitive nack-without-requeue contract can be
    /// asserted directly.
    #[derive(Clone)]
    struct RecordingDelivery {
        data: Vec<u8>,
        acked: Arc<AtomicUsize>,
        nacked_requeue_true: Arc<AtomicUsize>,
        nacked_requeue_false: Arc<AtomicUsize>,
    }

    impl RecordingDelivery {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                acked: Arc::new(AtomicUsize::new(0)),
                nacked_requeue_true: Arc::new(AtomicUsize::new(0)),
                nacked_requeue_false: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl AckableDelivery for RecordingDelivery {
        fn data(&self) -> &[u8] {
            &self.data
        }

        async fn ack(&self) {
            self.acked.fetch_add(1, Ordering::SeqCst);
        }

        async fn nack(&self, requeue: bool) {
            if requeue {
                self.nacked_requeue_true.fetch_add(1, Ordering::SeqCst);
            } else {
                self.nacked_requeue_false.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    // A minimal `tracing::Subscriber` that records the formatted message of
    // every event into a *thread-local* buffer, so the "security event
    // omits the HMAC value" assertion can inspect exactly what would have
    // been logged — without needing a `tracing-subscriber` dev-dependency,
    // and without racing other tests. `tracing`'s per-callsite interest
    // cache is process-global: installing a subscriber via the thread-local
    // `set_default` guard in each test, then calling
    // `rebuild_interest_cache()`, mutates that global cache and can race
    // with any other concurrently-running test thread that hits the same
    // `tracing::warn!` call sites in `verify_and_dispatch`/`consume`. To
    // avoid that race entirely, this subscriber is installed exactly once
    // (via `std::sync::Once`) as the *global* default for the whole test
    // binary, and routes every event into a `thread_local!` `Vec<String>` —
    // so each test thread only ever sees the events it caused itself,
    // regardless of how many other tests are running concurrently.
    thread_local! {
        static THREAD_EVENTS: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    struct ThreadLocalRecordingSubscriber;

    struct MessageVisitor(String);

    impl tracing::field::Visit for MessageVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!("{}={:?} ", field.name(), value));
        }
    }

    impl tracing::Subscriber for ThreadLocalRecordingSubscriber {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut visitor = MessageVisitor(String::new());
            event.record(&mut visitor);
            THREAD_EVENTS.with(|events| events.borrow_mut().push(visitor.0));
        }

        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    static INIT_GLOBAL_SUBSCRIBER: std::sync::Once = std::sync::Once::new();

    /// Install [`ThreadLocalRecordingSubscriber`] as the global default
    /// exactly once per test binary run, then clear this thread's event
    /// buffer so a prior test on the same worker thread cannot leak events
    /// into the next one.
    fn init_recording_subscriber() {
        INIT_GLOBAL_SUBSCRIBER.call_once(|| {
            tracing::subscriber::set_global_default(ThreadLocalRecordingSubscriber)
                .expect("no global subscriber set yet in this test binary");
        });
        THREAD_EVENTS.with(|events| events.borrow_mut().clear());
    }

    /// Build a v2 message body (NEW-4: always carries `key_version`,
    /// `nonce`, `issued_at`) with a fresh, unique `nonce` and `issued_at`
    /// set to `Utc::now()` unless overridden. Used by tests that only care
    /// about the HMAC verification step (not the replay-protection gates),
    /// so a sensible, always-fresh default keeps them independent of wall-
    /// clock timing.
    fn v2_body(key_version: u8, nonce: &str, issued_at: DateTime<Utc>) -> serde_json::Value {
        serde_json::json!({
            "correlation_id": "00000000-0000-0000-0000-000000000000",
            "action": "read",
            "key_version": key_version,
            "nonce": nonce,
            "issued_at": issued_at.to_rfc3339(),
        })
    }

    fn make_signed_body_with(
        key_version: u8,
        nonce: &str,
        issued_at: DateTime<Utc>,
    ) -> (serde_json::Value, Vec<u8>) {
        let key = b"consumer-test-signing-key";
        let mut body = v2_body(key_version, nonce, issued_at);
        let canonical = serde_json::to_vec(&body).unwrap();
        let sig = sign_payload(key, &canonical);
        body.as_object_mut()
            .unwrap()
            .insert("hmac_signature".into(), serde_json::Value::String(sig));
        let data = serde_json::to_vec(&body).unwrap();
        (body, data)
    }

    fn make_signed_body() -> (serde_json::Value, Vec<u8>) {
        make_signed_body_with(2, &uuid::Uuid::new_v4().to_string(), Utc::now())
    }

    #[tokio::test]
    async fn valid_signature_invokes_handler_once_then_acks() {
        let key = b"consumer-test-signing-key";
        let (_body, data) = make_signed_body();
        let delivery = RecordingDelivery::new(data);
        let replay = ReplayGuard::with_default_skew();
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &handler, &replay).await;

        assert_eq!(handler_calls.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 0);
        assert_eq!(delivery.nacked_requeue_true.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn mismatched_signature_never_invokes_handler_and_nacks_without_requeue() {
        let key = b"consumer-test-signing-key";
        let (mut body, _data) = make_signed_body();
        // Corrupt the signature so it no longer matches the canonical body.
        body.as_object_mut().unwrap().insert(
            "hmac_signature".into(),
            serde_json::Value::String(
                "0000000000000000000000000000000000000000000000000000000000000000".into(),
            ),
        );
        let data = serde_json::to_vec(&body).unwrap();
        let delivery = RecordingDelivery::new(data);
        let replay = ReplayGuard::with_default_skew();
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &handler, &replay).await;

        assert_eq!(
            handler_calls.load(Ordering::SeqCst),
            0,
            "handler must never be invoked on a tampered/mismatched signature"
        );
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.nacked_requeue_true.load(Ordering::SeqCst), 0);
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn missing_signature_strict_mode_default_never_invokes_handler_and_nacks_without_requeue()
    {
        let key = b"consumer-test-signing-key";
        let body = v2_body(2, &uuid::Uuid::new_v4().to_string(), Utc::now());
        let data = serde_json::to_vec(&body).unwrap();
        let delivery = RecordingDelivery::new(data);
        let replay = ReplayGuard::with_default_skew();
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &handler, &replay).await;

        assert_eq!(
            handler_calls.load(Ordering::SeqCst),
            0,
            "a delivery with no hmac_signature must be rejected in strict mode (the default)"
        );
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.nacked_requeue_true.load(Ordering::SeqCst), 0);
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn invalid_json_body_never_invokes_handler_and_nacks_without_requeue() {
        let key = b"consumer-test-signing-key";
        let delivery = RecordingDelivery::new(b"not valid json {{{".to_vec());
        let replay = ReplayGuard::with_default_skew();
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &handler, &replay).await;

        assert_eq!(handler_calls.load(Ordering::SeqCst), 0);
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.nacked_requeue_true.load(Ordering::SeqCst), 0);
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn security_event_log_omits_hmac_value() {
        init_recording_subscriber();

        let key = b"consumer-test-signing-key";
        let (mut body, _data) = make_signed_body();
        let leaked_signature_would_be = body
            .get("hmac_signature")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_owned();
        // Corrupt the signature so verification fails and the security
        // event path fires.
        let wrong_sig = "1".repeat(leaked_signature_would_be.len());
        body.as_object_mut().unwrap().insert(
            "hmac_signature".into(),
            serde_json::Value::String(wrong_sig.clone()),
        );
        let data = serde_json::to_vec(&body).unwrap();
        let delivery = RecordingDelivery::new(data);
        let replay = ReplayGuard::with_default_skew();
        let handler = |_value: serde_json::Value| async {};

        verify_and_dispatch(&delivery, key, &handler, &replay).await;

        let captured = THREAD_EVENTS.with(|events| events.borrow().clone());
        assert!(
            !captured.is_empty(),
            "a security event must be emitted on verification failure"
        );
        for event in captured.iter() {
            assert!(
                !event.contains(&wrong_sig) && !event.contains(&leaked_signature_would_be),
                "security event log line must never contain the received or expected HMAC \
                 value (CONTRACT.md §8.4): {event}"
            );
        }
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 1);
    }

    // SDK-Q01 regression: the server signs the HMAC over the concrete struct
    // serialized in FIELD-DECLARATION order (correlation_id, tenant_id,
    // subject_id, action, resource_id, scope, key_version, nonce, issued_at)
    // — which is NOT alphabetical. This fixture builds the canonical signed
    // bytes by HAND in that declaration order (never by round-tripping
    // through the verifier's own `Value` path), then feeds the SDK a
    // delivery whose body is exactly what the server put on the wire.
    // Before the fix (no `preserve_order`), the verifier re-serialized the
    // parsed `Value` alphabetically and HMACed over the wrong bytes,
    // rejecting this genuine message.
    //
    // NEW-4: bumped to `key_version = 2` with `nonce`/`issued_at` appended
    // in declaration order (immediately before `hmac_signature`).
    // `issued_at` is computed at call time (not baked into a `const`) so
    // these tests stay fresh regardless of when they actually run.
    fn authz_canonical(key_version: u8, nonce: &str, issued_at: DateTime<Utc>) -> String {
        format!(
            concat!(
                "{{",
                "\"correlation_id\":\"11111111-1111-1111-1111-111111111111\",",
                "\"tenant_id\":\"22222222-2222-2222-2222-222222222222\",",
                "\"subject_id\":\"33333333-3333-3333-3333-333333333333\",",
                "\"action\":\"read\",",
                "\"resource_id\":\"44444444-4444-4444-4444-444444444444\",",
                "\"scope\":\"sub\",",
                "\"key_version\":{},",
                "\"nonce\":\"{}\",",
                "\"issued_at\":\"{}\"",
                "}}"
            ),
            key_version,
            nonce,
            issued_at.to_rfc3339(),
        )
    }

    /// Build the on-the-wire delivery bytes: the canonical payload with
    /// `hmac_signature` appended as the final key (exactly how the server
    /// emits it after signing).
    fn wire_bytes_with_signature(canonical: &str, sig: &str) -> Vec<u8> {
        // Splice the signature in just before the closing brace, keeping the
        // canonical field order intact and adding `hmac_signature` last.
        let without_close = &canonical[..canonical.len() - 1];
        format!("{without_close},\"hmac_signature\":\"{sig}\"}}").into_bytes()
    }

    #[tokio::test]
    async fn server_declaration_order_message_is_accepted() {
        let key = b"declaration-order-signing-key";
        let canonical = authz_canonical(2, "77777777-7777-7777-7777-777777777777", Utc::now());
        // Sign the hand-built declaration-order canonical bytes — NOT bytes
        // produced by re-serializing a `Value` the same way the verifier does.
        let sig = sign_payload(key, canonical.as_bytes());
        let data = wire_bytes_with_signature(&canonical, &sig);
        let delivery = RecordingDelivery::new(data);
        let replay = ReplayGuard::with_default_skew();

        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &handler, &replay).await;

        assert_eq!(
            handler_calls.load(Ordering::SeqCst),
            1,
            "a genuine server message signed in declaration order must verify \
             and reach the handler (SDK-Q01)"
        );
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn server_declaration_order_message_tampered_is_rejected() {
        let key = b"declaration-order-signing-key";
        let canonical = authz_canonical(2, "88888888-8888-8888-8888-888888888888", Utc::now());
        // Signature is over the pristine canonical bytes...
        let sig = sign_payload(key, canonical.as_bytes());
        // ...but the delivered body flips `action` from read -> write, so the
        // recomputed HMAC must not match.
        let tampered_canonical = canonical.replace("\"read\"", "\"write\"");
        let data = wire_bytes_with_signature(&tampered_canonical, &sig);
        let delivery = RecordingDelivery::new(data);
        let replay = ReplayGuard::with_default_skew();

        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &handler, &replay).await;

        assert_eq!(
            handler_calls.load(Ordering::SeqCst),
            0,
            "a tampered body must never reach the handler"
        );
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn hmac_signature_not_last_field_still_verifies() {
        // Robustness of `shift_remove`: even if `hmac_signature` is not the
        // final key, removing it must preserve the order of the remaining
        // fields so the canonical bytes are reproduced. Here we place
        // `hmac_signature` FIRST in the delivered object.
        let key = b"declaration-order-signing-key";
        let canonical = authz_canonical(2, "99999999-9999-9999-9999-999999999999", Utc::now());
        let sig = sign_payload(key, canonical.as_bytes());
        let canonical_inner = &canonical[1..]; // drop leading '{'
        let data = format!("{{\"hmac_signature\":\"{sig}\",{canonical_inner}").into_bytes();
        let delivery = RecordingDelivery::new(data);
        let replay = ReplayGuard::with_default_skew();

        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &handler, &replay).await;

        assert_eq!(
            handler_calls.load(Ordering::SeqCst),
            1,
            "shift_remove must preserve field order regardless of where \
             hmac_signature sits, so the message still verifies"
        );
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 1);
    }

    // --- NEW-4: v2 replay-protection gate tests -----------------------------

    #[tokio::test]
    async fn key_version_below_minimum_is_rejected_even_with_valid_signature() {
        let key = b"declaration-order-signing-key";
        // key_version = 1 predates NEW-4; the HMAC over this body is
        // perfectly valid, but the hard-cutover gate must still reject it.
        let canonical = authz_canonical(1, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Utc::now());
        let sig = sign_payload(key, canonical.as_bytes());
        let data = wire_bytes_with_signature(&canonical, &sig);
        let delivery = RecordingDelivery::new(data);
        let replay = ReplayGuard::with_default_skew();

        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &handler, &replay).await;

        assert_eq!(
            handler_calls.load(Ordering::SeqCst),
            0,
            "key_version < 2 must be rejected even when the signature verifies (NEW-4 hard cutover)"
        );
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.nacked_requeue_true.load(Ordering::SeqCst), 0);
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn stale_issued_at_is_rejected_even_with_valid_signature() {
        let key = b"declaration-order-signing-key";
        // 10 minutes in the past — outside the default ±5 minute skew.
        let stale = Utc::now() - chrono::Duration::minutes(10);
        let canonical = authz_canonical(2, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", stale);
        let sig = sign_payload(key, canonical.as_bytes());
        let data = wire_bytes_with_signature(&canonical, &sig);
        let delivery = RecordingDelivery::new(data);
        let replay = ReplayGuard::with_default_skew();

        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &handler, &replay).await;

        assert_eq!(
            handler_calls.load(Ordering::SeqCst),
            0,
            "a stale issued_at (outside the freshness skew) must be rejected"
        );
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn replayed_nonce_is_rejected_on_second_delivery() {
        let key = b"declaration-order-signing-key";
        let nonce = "cccccccc-cccc-cccc-cccc-cccccccccccc";
        let canonical = authz_canonical(2, nonce, Utc::now());
        let sig = sign_payload(key, canonical.as_bytes());
        // Same ReplayGuard for both deliveries — the nonce dedup only works
        // if state is retained across messages on the same consumer.
        let replay = ReplayGuard::with_default_skew();

        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        let first_delivery = RecordingDelivery::new(wire_bytes_with_signature(&canonical, &sig));
        verify_and_dispatch(&first_delivery, key, &handler, &replay).await;
        assert_eq!(
            handler_calls.load(Ordering::SeqCst),
            1,
            "the first delivery of a fresh nonce must be accepted"
        );
        assert_eq!(first_delivery.acked.load(Ordering::SeqCst), 1);

        // Replay: identical body + signature, same nonce, delivered again.
        let second_delivery = RecordingDelivery::new(wire_bytes_with_signature(&canonical, &sig));
        verify_and_dispatch(&second_delivery, key, &handler, &replay).await;

        assert_eq!(
            handler_calls.load(Ordering::SeqCst),
            1,
            "a replayed nonce must not reach the handler a second time"
        );
        assert_eq!(
            second_delivery.nacked_requeue_false.load(Ordering::SeqCst),
            1
        );
        assert_eq!(second_delivery.acked.load(Ordering::SeqCst), 0);
    }

    // --- NEW-4: byte-for-byte parity against the server reference vectors --
    //
    // `crates/axiam-amqp/tests/fixtures/v2_reference_vectors.json` is
    // GENERATED by the AXIAM server sign path and is the ground truth every
    // SDK's HMAC implementation must reproduce exactly (CONTRACT.md §8
    // "Canonical reference vectors"). It carries, per message type, the
    // exact canonical signed JSON bytes, the resulting hex HMAC, and the
    // HKDF-derived per-tenant subkey used to compute it — this is a
    // read-only reference (this crate never depends on `axiam-amqp`).
    const REFERENCE_VECTORS_JSON: &str =
        include_str!("../../../../crates/axiam-amqp/tests/fixtures/v2_reference_vectors.json");

    fn hex_decode(s: &str) -> Vec<u8> {
        hex::decode(s).expect("fixture hex field must decode")
    }

    #[test]
    fn fixture_v2_reference_vectors_hmac_byte_parity() {
        let fixture: serde_json::Value =
            serde_json::from_str(REFERENCE_VECTORS_JSON).expect("fixture must parse as JSON");
        let subkey = hex_decode(
            fixture["hkdf"]["derived_subkey_hex"]
                .as_str()
                .expect("hkdf.derived_subkey_hex present"),
        );

        for message_type in ["authz_request", "audit_event"] {
            let vector = &fixture[message_type];
            let canonical = vector["canonical_signed_json"]
                .as_str()
                .unwrap_or_else(|| panic!("{message_type}.canonical_signed_json present"));
            let expected_hmac = vector["hmac_signature_hex"]
                .as_str()
                .unwrap_or_else(|| panic!("{message_type}.hmac_signature_hex present"));

            let sig = sign_payload(&subkey, canonical.as_bytes());
            assert_eq!(
                sig, expected_hmac,
                "{message_type}: SDK sign_payload output must be byte-for-byte identical to \
                 the server-generated reference vector"
            );
            assert!(
                verify_payload(&subkey, canonical.as_bytes(), expected_hmac),
                "{message_type}: the server-generated signature must verify against the same \
                 derived subkey + canonical bytes"
            );
        }
    }

    #[tokio::test]
    async fn fixture_v2_reference_vector_authz_request_accepted_by_consumer() {
        let fixture: serde_json::Value =
            serde_json::from_str(REFERENCE_VECTORS_JSON).expect("fixture must parse as JSON");
        let vector = &fixture["authz_request"];
        let canonical = vector["canonical_signed_json"]
            .as_str()
            .expect("authz_request.canonical_signed_json present");
        let expected_hmac = vector["hmac_signature_hex"]
            .as_str()
            .expect("authz_request.hmac_signature_hex present");
        let subkey = hex_decode(
            fixture["hkdf"]["derived_subkey_hex"]
                .as_str()
                .expect("hkdf.derived_subkey_hex present"),
        );

        let data = wire_bytes_with_signature(canonical, expected_hmac);
        let delivery = RecordingDelivery::new(data);
        // The fixture's `issued_at` (2026-07-10T12:00:00Z) is a fixed
        // historical timestamp baked into the reference vectors. This test
        // exercises HMAC/structure acceptance through the full dispatch
        // pipeline, NOT the freshness gate (covered independently by
        // `stale_issued_at_is_rejected_even_with_valid_signature`), so use a
        // generous skew that tolerates the gap between the fixture's
        // timestamp and whenever this test actually runs.
        let replay = ReplayGuard::new(chrono::Duration::days(3650));

        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, &subkey, &handler, &replay).await;

        assert_eq!(
            handler_calls.load(Ordering::SeqCst),
            1,
            "a genuine server-signed v2 reference vector must be accepted end-to-end"
        );
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 0);
    }
}
