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

use std::future::Future;
use std::sync::Arc;

use futures_util::StreamExt;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, BasicNackOptions, QueueDeclareOptions};
use lapin::types::FieldTable;
use lapin::{Channel, Connection, ConnectionProperties};

use crate::amqp::hmac::verify_payload;
use crate::error::AxiamError;
use crate::sensitive::Sensitive;

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

/// Verify a single delivery's HMAC signature (CONTRACT.md §8 steps a-g)
/// and, only on success, invoke `handler` with the parsed body before
/// acking. On any failure the delivery is nacked without requeue and a
/// security event is emitted (never containing the HMAC value).
///
/// This is the load-bearing, separately-testable unit backing
/// [`consume`]'s per-message loop — kept generic over [`AckableDelivery`]
/// so it can be exercised against a recording fake in unit tests without a
/// live broker.
pub(crate) async fn verify_and_dispatch<D, F, Fut>(delivery: &D, signing_key: &[u8], handler: &F)
where
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
/// This function owns the full ack/nack loop; the closure `handler` is
/// invoked only after successful verification and MUST NOT itself call
/// ack/nack (there is no delivery handle exposed to it).
pub async fn consume<F, Fut>(
    amqp_url: &str,
    queue: &str,
    signing_key: Sensitive<Vec<u8>>,
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

    while let Some(delivery_result) = consumer.next().await {
        match delivery_result {
            Ok(delivery) => {
                let key = Arc::clone(&key);
                let handler = Arc::clone(&handler);
                verify_and_dispatch(&delivery, key.expose(), handler.as_ref()).await;
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

    async fn make_signed_body() -> (serde_json::Value, Vec<u8>) {
        let key = b"consumer-test-signing-key";
        let mut body = serde_json::json!({
            "correlation_id": "00000000-0000-0000-0000-000000000000",
            "action": "read",
        });
        let canonical = serde_json::to_vec(&body).unwrap();
        let sig = sign_payload(key, &canonical);
        body.as_object_mut()
            .unwrap()
            .insert("hmac_signature".into(), serde_json::Value::String(sig));
        let data = serde_json::to_vec(&body).unwrap();
        (body, data)
    }

    #[tokio::test]
    async fn valid_signature_invokes_handler_once_then_acks() {
        let key = b"consumer-test-signing-key";
        let (_body, data) = make_signed_body().await;
        let delivery = RecordingDelivery::new(data);
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &handler).await;

        assert_eq!(handler_calls.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 0);
        assert_eq!(delivery.nacked_requeue_true.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn mismatched_signature_never_invokes_handler_and_nacks_without_requeue() {
        let key = b"consumer-test-signing-key";
        let (mut body, _data) = make_signed_body().await;
        // Corrupt the signature so it no longer matches the canonical body.
        body.as_object_mut().unwrap().insert(
            "hmac_signature".into(),
            serde_json::Value::String(
                "0000000000000000000000000000000000000000000000000000000000000000".into(),
            ),
        );
        let data = serde_json::to_vec(&body).unwrap();
        let delivery = RecordingDelivery::new(data);
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &handler).await;

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
        let body = serde_json::json!({
            "correlation_id": "00000000-0000-0000-0000-000000000000",
            "action": "read",
        });
        let data = serde_json::to_vec(&body).unwrap();
        let delivery = RecordingDelivery::new(data);
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &handler).await;

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
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &handler).await;

        assert_eq!(handler_calls.load(Ordering::SeqCst), 0);
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.nacked_requeue_true.load(Ordering::SeqCst), 0);
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn security_event_log_omits_hmac_value() {
        init_recording_subscriber();

        let key = b"consumer-test-signing-key";
        let (mut body, _data) = make_signed_body().await;
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
        let handler = |_value: serde_json::Value| async {};

        verify_and_dispatch(&delivery, key, &handler).await;

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
    // subject_id, action, resource_id, scope, key_version) — which is NOT
    // alphabetical. This fixture builds the canonical signed bytes by HAND in
    // that declaration order (never by round-tripping through the verifier's
    // own `Value` path), then feeds the SDK a delivery whose body is exactly
    // what the server put on the wire. Before the fix (no `preserve_order`),
    // the verifier re-serialized the parsed `Value` alphabetically and HMACed
    // over the wrong bytes, rejecting this genuine message.
    //
    // `AUTHZ_CANONICAL` is the payload the server signs: declaration order,
    // compact, `hmac_signature` omitted (set to None before signing).
    const AUTHZ_CANONICAL: &str = concat!(
        "{",
        "\"correlation_id\":\"11111111-1111-1111-1111-111111111111\",",
        "\"tenant_id\":\"22222222-2222-2222-2222-222222222222\",",
        "\"subject_id\":\"33333333-3333-3333-3333-333333333333\",",
        "\"action\":\"read\",",
        "\"resource_id\":\"44444444-4444-4444-4444-444444444444\",",
        "\"scope\":\"sub\",",
        "\"key_version\":1",
        "}"
    );

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
        // Sign the hand-built declaration-order canonical bytes — NOT bytes
        // produced by re-serializing a `Value` the same way the verifier does.
        let sig = sign_payload(key, AUTHZ_CANONICAL.as_bytes());
        let data = wire_bytes_with_signature(AUTHZ_CANONICAL, &sig);
        let delivery = RecordingDelivery::new(data);

        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &handler).await;

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
        // Signature is over the pristine canonical bytes...
        let sig = sign_payload(key, AUTHZ_CANONICAL.as_bytes());
        // ...but the delivered body flips `action` from read -> write, so the
        // recomputed HMAC must not match.
        let tampered_canonical = AUTHZ_CANONICAL.replace("\"read\"", "\"write\"");
        let data = wire_bytes_with_signature(&tampered_canonical, &sig);
        let delivery = RecordingDelivery::new(data);

        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &handler).await;

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
        let sig = sign_payload(key, AUTHZ_CANONICAL.as_bytes());
        let canonical_inner = &AUTHZ_CANONICAL[1..]; // drop leading '{'
        let data = format!("{{\"hmac_signature\":\"{sig}\",{canonical_inner}").into_bytes();
        let delivery = RecordingDelivery::new(data);

        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &handler).await;

        assert_eq!(
            handler_calls.load(Ordering::SeqCst),
            1,
            "shift_remove must preserve field order regardless of where \
             hmac_signature sits, so the message still verifies"
        );
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 1);
    }
}
