//! The generic consume loop, and the registry that tells it what one attempt
//! means for each kind.
//!
//! [`run_outbound_consumer`] consumes one kind's primary queue and, per
//! message: decodes it, asks that kind's
//! [`OutboundDeliverer`](axiam_core::outbound::OutboundDeliverer) for **one**
//! attempt, and settles the message from the outcome.
//!
//! | Outcome | Settlement | Audit record (`<slug>.` prefix) |
//! |---|---|---|
//! | `Delivered` | `ack` | `delivery_succeeded` (success) |
//! | `Retry`, or a deliverer `Err`, with attempts left | republish to the retry queue with TTL [`backoff_ttl_ms`]`(attempt + 1)`, then `ack` the original | `delivery_attempt` (failure) |
//! | `Retry` / `Err` with no attempts left | `nack(requeue = false)`, which dead-letters to the DLQ | `delivery_failed` (failure) |
//! | `DeadLetter` | as the line above, immediately | `delivery_failed` (failure) |
//! | undecodable bytes | `nack(requeue = false)`; the deliverer is not called | none |
//!
//! If the retry copy cannot be published the original is **not** acked: it is
//! requeued so the broker redelivers it (acking would drop the delivery with
//! no retry and no DLQ entry, while the audit trail claimed a retry was
//! scheduled; CQ-B49).
//!
//! What an attempt's outcome *means* (retry, dead-letter or delivered, and the
//! audit row) is decided by `outcome::decide`, which the in-process dispatcher
//! of the minimal profile ([`super::inprocess`]) shares; this module only
//! carries a verdict out against the broker.
//!
//! For the webhook kind the audit action names and metadata are exactly what
//! they were before the extraction (`webhook.delivery_succeeded`,
//! `webhook.delivery_attempt`, `webhook.delivery_failed`).

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use futures_lite::StreamExt;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, BasicNackOptions};
use lapin::types::FieldTable;
use lapin::{Acker, Channel};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use axiam_core::models::audit::CreateAuditLogEntry;
use axiam_core::outbound::{OutboundDeliverer, OutboundKind, OutboundMessage};
use axiam_core::repository::AuditLogRepository;

use super::outcome::{self, Verdict};
use super::publisher::AmqpOutboundPublisher;
use super::retry::OutboundRetryConfig;
use super::topology::OutboundTopology;
use super::wire;
use crate::connection::AmqpManager;

/// Why a consumer could not be set up (or a deliverer registered).
#[derive(Debug, thiserror::Error)]
pub enum OutboundConsumerError {
    /// No deliverer is registered for the kind. The consumer refuses to start
    /// rather than consume messages it can only retry into the DLQ.
    #[error("no deliverer registered for outbound kind `{0}`")]
    Unregistered(OutboundKind),
    /// A second deliverer was registered for a kind that already has one.
    #[error("a deliverer is already registered for outbound kind `{0}`")]
    Duplicate(OutboundKind),
    /// The broker refused `basic.consume` on the kind's primary queue.
    #[error("failed to start the `{kind}` outbound consumer: {source}")]
    Consume {
        /// The kind being consumed.
        kind: OutboundKind,
        /// The broker's error.
        source: lapin::Error,
    },
}

/// The deliverer for each kind. `axiam-server` fills it; the loop reads it.
///
/// Cheap to clone (the deliverers are `Arc`s), so a supervising reconnect loop
/// can hand a copy to each restart of the consumer.
#[derive(Clone, Default)]
pub struct OutboundDeliverers {
    by_kind: HashMap<OutboundKind, Arc<dyn OutboundDeliverer>>,
}

impl OutboundDeliverers {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `deliverer` under the kind it reports. One deliverer per kind.
    pub fn register(
        &mut self,
        deliverer: Arc<dyn OutboundDeliverer>,
    ) -> Result<(), OutboundConsumerError> {
        let kind = deliverer.kind();
        if self.by_kind.contains_key(&kind) {
            return Err(OutboundConsumerError::Duplicate(kind));
        }
        self.by_kind.insert(kind, deliverer);
        Ok(())
    }

    /// The deliverer for `kind`, if one is registered.
    pub fn get(&self, kind: OutboundKind) -> Option<&Arc<dyn OutboundDeliverer>> {
        self.by_kind.get(&kind)
    }

    /// The deliverer for `kind`, or [`OutboundConsumerError::Unregistered`].
    pub fn require(
        &self,
        kind: OutboundKind,
    ) -> Result<&Arc<dyn OutboundDeliverer>, OutboundConsumerError> {
        self.get(kind)
            .ok_or(OutboundConsumerError::Unregistered(kind))
    }
}

// ---------------------------------------------------------------------------
// Seams. The loop's decisions are exercised in tests against fakes of these;
// production uses the lapin and repository implementations below.
// ---------------------------------------------------------------------------

/// Settles one delivery with the broker.
pub(crate) trait Settlement: Send + Sync {
    fn ack(&self) -> impl Future<Output = Result<(), String>> + Send;
    fn nack(&self, requeue: bool) -> impl Future<Output = Result<(), String>> + Send;
}

/// Publishes the TTL-delayed retry copy.
pub(crate) trait RetryPublisher: Send + Sync {
    fn publish_retry(
        &self,
        msg: &OutboundMessage,
        ttl_ms: u64,
    ) -> impl Future<Output = Result<(), String>> + Send;
}

/// Appends a delivery audit record.
pub(crate) trait AuditSink: Send + Sync {
    fn record(&self, entry: CreateAuditLogEntry)
    -> impl Future<Output = Result<(), String>> + Send;
}

struct LapinSettlement<'a>(&'a Acker);

impl Settlement for LapinSettlement<'_> {
    async fn ack(&self) -> Result<(), String> {
        self.0
            .ack(BasicAckOptions::default())
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    async fn nack(&self, requeue: bool) -> Result<(), String> {
        self.0
            .nack(BasicNackOptions {
                requeue,
                ..BasicNackOptions::default()
            })
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

impl RetryPublisher for AmqpOutboundPublisher {
    async fn publish_retry(&self, msg: &OutboundMessage, ttl_ms: u64) -> Result<(), String> {
        AmqpOutboundPublisher::publish_retry(self, msg, ttl_ms)
            .await
            .map_err(|e| e.to_string())
    }
}

pub(crate) struct OwnedAuditSink<A>(pub(crate) A);

impl<A: AuditLogRepository> AuditSink for OwnedAuditSink<A> {
    async fn record(&self, entry: CreateAuditLogEntry) -> Result<(), String> {
        self.0
            .append(entry)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

struct RepoAuditSink<'a, A>(&'a A);

impl<A: AuditLogRepository> AuditSink for RepoAuditSink<'_, A> {
    async fn record(&self, entry: CreateAuditLogEntry) -> Result<(), String> {
        self.0
            .append(entry)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

// ---------------------------------------------------------------------------
// The loop
// ---------------------------------------------------------------------------

/// Consume `kind`'s primary queue until the stream ends.
///
/// Returns `Err(Unregistered)` *before* touching the broker when `deliverers`
/// has nothing for `kind`; `Ok(())` when the delivery stream ends (the caller
/// is expected to reconnect, as `axiam-server`'s supervisor does); and
/// `Err(Consume)` if the broker refuses the consume.
///
/// `channel` should come from `AmqpManager::create_channel` (QoS applied). The
/// queues must already exist: call `AmqpManager::declare_outbound_topology`.
pub async fn run_outbound_consumer<A>(
    channel: Channel,
    kind: OutboundKind,
    deliverers: &OutboundDeliverers,
    publisher: &AmqpOutboundPublisher,
    audit_repo: &A,
    cfg: OutboundRetryConfig,
) -> Result<(), OutboundConsumerError>
where
    A: AuditLogRepository,
{
    let deliverer = deliverers.require(kind)?;
    let queue = OutboundTopology::for_kind(kind).primary;
    info!(%kind, %queue, "Starting outbound AMQP consumer");

    let mut consumer = channel
        .basic_consume(
            queue.as_str().into(),
            format!("axiam-{kind}-consumer").into(),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
        .map_err(|source| {
            error!(%kind, error = %source, "Failed to start outbound consumer");
            OutboundConsumerError::Consume { kind, source }
        })?;

    let audit = RepoAuditSink(audit_repo);
    while let Some(delivery_result) = consumer.next().await {
        let delivery = match delivery_result {
            Ok(d) => d,
            Err(e) => {
                error!(%kind, error = %e, "Error receiving outbound delivery");
                continue;
            }
        };
        process_delivery(
            kind,
            &delivery.data,
            delivery.delivery_tag,
            deliverer.as_ref(),
            &LapinSettlement(&delivery.acker),
            publisher,
            &audit,
            &cfg,
        )
        .await;
    }

    warn!(%kind, "Outbound AMQP consumer stream ended");
    Ok(())
}

async fn record<A: AuditSink>(audit: &A, entry: CreateAuditLogEntry) {
    let action = entry.action.clone();
    if let Err(e) = audit.record(entry).await {
        error!(error = %e, %action, "Failed to write outbound delivery audit event");
    }
}

/// Handle one delivery end to end. The unit the tests drive.
///
/// What an attempt's outcome *means* is decided by [`outcome::decide`], shared
/// with the in-process dispatcher; this function only carries the verdict out
/// against the broker (ack, TTL-delayed republish, nack to the DLQ).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn process_delivery<S, R, A>(
    kind: OutboundKind,
    data: &[u8],
    delivery_tag: u64,
    deliverer: &dyn OutboundDeliverer,
    settle: &S,
    retry: &R,
    audit: &A,
    cfg: &OutboundRetryConfig,
) where
    S: Settlement,
    R: RetryPublisher,
    A: AuditSink,
{
    // Bad payload: nack requeue=false (not re-deliverable, not retried forever).
    let msg = match wire::decode(kind, data) {
        Ok(m) => m,
        Err(e) => {
            warn!(%kind, error = %e, delivery_tag, "Invalid outbound message payload, nacking");
            let _ = settle.nack(false).await;
            return;
        }
    };

    let result = deliverer.deliver_attempt(&msg).await;
    match outcome::decide(&msg, outcome::classify(result), cfg) {
        Verdict::Delivered { audit: entry } => {
            record(audit, entry).await;
            if let Err(e) = settle.ack().await {
                error!(%kind, error = %e, delivery_tag, "Failed to ack outbound delivery");
            }
        }
        Verdict::Retry {
            next,
            ttl_ms,
            audit: entry,
        } => {
            // CQ-B49: never ack the original if the retry copy was not enqueued.
            if let Err(e) = retry.publish_retry(&next, ttl_ms).await {
                error!(
                    %kind,
                    error = %e,
                    target_id = %msg.target_id,
                    delivery_id = %msg.delivery_id,
                    delivery_tag,
                    "Failed to publish outbound retry; requeuing original instead of acking"
                );
                if let Err(nack_err) = settle.nack(true).await {
                    error!(
                        %kind,
                        error = %nack_err,
                        delivery_tag,
                        "Failed to nack original outbound delivery after retry-publish failure"
                    );
                }
                return;
            }

            record(audit, entry).await;

            // Ack the ORIGINAL: the retry copy re-enters the primary queue via
            // TTL + DLX once the delay expires.
            if let Err(e) = settle.ack().await {
                error!(%kind, error = %e, delivery_tag, "Failed to ack original outbound delivery");
            }
        }
        Verdict::DeadLetter { audit: entry } => {
            record(audit, entry).await;

            // Terminal: nack requeue=false -> the primary queue's DLX -> the DLQ
            // (replayable).
            let _ = settle.nack(false).await;
        }
    }
}

// ---------------------------------------------------------------------------
// The supervisor
// ---------------------------------------------------------------------------

/// First delay of the supervisor's reconnect backoff.
const SUPERVISOR_BACKOFF_START: Duration = Duration::from_secs(1);
/// Ceiling of the supervisor's reconnect backoff.
const SUPERVISOR_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// The delay that follows `current` in the supervisor's reconnect schedule:
/// doubled, capped at 30 s (1, 2, 4, 8, 16, 30, 30, ...).
fn next_supervisor_backoff(current: Duration) -> Duration {
    (current * 2).min(SUPERVISOR_BACKOFF_MAX)
}

/// Spawn the supervised consumer for one outbound kind and return its handle.
///
/// The task never exits and never takes the process down (CQ-B53): a transient
/// broker disconnect (the consume stream ends, `basic.consume` is refused, or a
/// channel cannot be opened) recreates the consume channel on the shared
/// connection and restarts [`run_outbound_consumer`] after a bounded
/// exponential backoff (1 s doubling to 30 s; a successful channel open resets
/// it). Every log line carries the kind slug.
///
/// `publisher` is the kind's publisher, used for the TTL-delayed retry
/// republish; clone it from the one the producers hold.
pub fn spawn_outbound_consumer<A>(
    amqp: Arc<AmqpManager>,
    kind: OutboundKind,
    deliverers: OutboundDeliverers,
    publisher: AmqpOutboundPublisher,
    audit_repo: A,
    cfg: OutboundRetryConfig,
) -> JoinHandle<()>
where
    A: AuditLogRepository + 'static,
{
    tokio::spawn(async move {
        let mut backoff = SUPERVISOR_BACKOFF_START;
        loop {
            match amqp.create_channel().await {
                Ok(channel) => {
                    backoff = SUPERVISOR_BACKOFF_START;
                    if let Err(e) = run_outbound_consumer(
                        channel,
                        kind,
                        &deliverers,
                        &publisher,
                        &audit_repo,
                        cfg,
                    )
                    .await
                    {
                        error!(%kind, error = %e, "{kind} AMQP consumer failed");
                    }
                    warn!(%kind, "{kind} AMQP consumer exited - reconnecting");
                }
                Err(e) => {
                    error!(
                        %kind,
                        error = %e,
                        "Failed to (re)create {kind} consumer channel - retrying"
                    );
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = next_supervisor_backoff(backoff);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::super::outcome::table;
    use super::super::retry::backoff_ttl_ms;
    use super::*;
    use axiam_core::models::audit::AuditOutcome;
    use axiam_core::outbound::{DeliveryOutcome, OutboundError, OutboundFuture};
    use std::sync::Mutex;
    use uuid::Uuid;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn supervisor_backoff_doubles_from_one_second_and_caps_at_thirty() {
        let mut d = SUPERVISOR_BACKOFF_START;
        let mut seen = vec![d.as_secs()];
        for _ in 0..7 {
            d = next_supervisor_backoff(d);
            seen.push(d.as_secs());
        }
        assert_eq!(seen, vec![1, 2, 4, 8, 16, 30, 30, 30]);
    }

    // ---- fakes -----------------------------------------------------------

    #[derive(Default)]
    struct FakeSettle {
        calls: Mutex<Vec<String>>,
    }
    impl FakeSettle {
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }
    impl Settlement for FakeSettle {
        fn ack(&self) -> impl Future<Output = Result<(), String>> + Send {
            self.calls.lock().unwrap().push("ack".into());
            async { Ok(()) }
        }
        fn nack(&self, requeue: bool) -> impl Future<Output = Result<(), String>> + Send {
            self.calls
                .lock()
                .unwrap()
                .push(format!("nack(requeue={requeue})"));
            async { Ok(()) }
        }
    }

    #[derive(Default)]
    struct FakeRetry {
        published: Mutex<Vec<(u32, u64)>>,
        fail: bool,
    }
    impl RetryPublisher for FakeRetry {
        fn publish_retry(
            &self,
            msg: &OutboundMessage,
            ttl_ms: u64,
        ) -> impl Future<Output = Result<(), String>> + Send {
            let result = if self.fail {
                Err("broker down".to_string())
            } else {
                self.published.lock().unwrap().push((msg.attempt, ttl_ms));
                Ok(())
            };
            async move { result }
        }
    }

    #[derive(Default)]
    struct FakeAudit {
        entries: Mutex<Vec<CreateAuditLogEntry>>,
    }
    impl FakeAudit {
        fn entries(&self) -> Vec<CreateAuditLogEntry> {
            self.entries.lock().unwrap().clone()
        }
    }
    impl AuditSink for FakeAudit {
        fn record(
            &self,
            entry: CreateAuditLogEntry,
        ) -> impl Future<Output = Result<(), String>> + Send {
            self.entries.lock().unwrap().push(entry);
            async { Ok(()) }
        }
    }

    struct Scripted {
        result: Result<DeliveryOutcome, OutboundError>,
        calls: AtomicU32,
    }
    impl Scripted {
        fn new(result: Result<DeliveryOutcome, OutboundError>) -> Self {
            Self {
                result,
                calls: AtomicU32::new(0),
            }
        }
    }
    impl OutboundDeliverer for Scripted {
        fn kind(&self) -> OutboundKind {
            OutboundKind::Webhook
        }
        fn deliver_attempt<'a>(
            &'a self,
            _msg: &'a OutboundMessage,
        ) -> OutboundFuture<'a, Result<DeliveryOutcome, OutboundError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let result = self.result.clone();
            Box::pin(async move { result })
        }
    }

    // ---- fixtures --------------------------------------------------------

    const CFG: OutboundRetryConfig = table::CFG;

    fn message(attempt: u32) -> OutboundMessage {
        OutboundMessage {
            kind: OutboundKind::Webhook,
            tenant_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            delivery_id: Uuid::new_v4(),
            event_type: "user.created".into(),
            payload: serde_json::json!({"hello": "world"}),
            attempt,
        }
    }

    struct Rig {
        settle: FakeSettle,
        retry: FakeRetry,
        audit: FakeAudit,
    }
    impl Rig {
        fn new() -> Self {
            Self {
                settle: FakeSettle::default(),
                retry: FakeRetry::default(),
                audit: FakeAudit::default(),
            }
        }
        async fn run(&self, msg: &OutboundMessage, deliverer: &Scripted) {
            let bytes = wire::encode(msg).unwrap();
            self.run_bytes(&bytes, deliverer).await;
        }
        async fn run_bytes(&self, bytes: &[u8], deliverer: &Scripted) {
            process_delivery(
                OutboundKind::Webhook,
                bytes,
                7,
                deliverer,
                &self.settle,
                &self.retry,
                &self.audit,
                &CFG,
            )
            .await;
        }
    }

    // ---- the five behaviours D-36 requires --------------------------------

    #[tokio::test]
    async fn delivered_acks_and_audits_success() {
        let rig = Rig::new();
        let msg = message(0);
        let d = Scripted::new(Ok(DeliveryOutcome::Delivered {
            response_status: Some(204),
        }));
        rig.run(&msg, &d).await;

        assert_eq!(rig.settle.calls(), ["ack"]);
        assert!(rig.retry.published.lock().unwrap().is_empty());
        let entries = rig.audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "webhook.delivery_succeeded");
        assert!(matches!(entries[0].outcome, AuditOutcome::Success));
        assert_eq!(entries[0].resource_id, Some(msg.target_id));
        assert_eq!(entries[0].tenant_id, msg.tenant_id);
        assert_eq!(
            entries[0].metadata,
            Some(serde_json::json!({
                "delivery_id": msg.delivery_id, "attempt": 1, "status": 204
            }))
        );
    }

    #[tokio::test]
    async fn delivered_without_a_protocol_status_omits_it_from_the_audit_record() {
        let rig = Rig::new();
        let msg = message(0);
        let d = Scripted::new(Ok(DeliveryOutcome::Delivered {
            response_status: None,
        }));
        rig.run(&msg, &d).await;
        assert_eq!(
            rig.audit.entries()[0].metadata,
            Some(serde_json::json!({"delivery_id": msg.delivery_id, "attempt": 1}))
        );
    }

    #[tokio::test]
    async fn retry_republishes_with_backoff_ttl_and_acks_the_original() {
        for attempt in [0u32, 1] {
            let rig = Rig::new();
            let msg = message(attempt);
            let d = Scripted::new(Ok(DeliveryOutcome::Retry {
                reason: "non-2xx status: 503".into(),
            }));
            rig.run(&msg, &d).await;

            // Republished with the incremented attempt and TTL
            // backoff_ttl_ms(attempt + 1).
            assert_eq!(
                *rig.retry.published.lock().unwrap(),
                [(attempt + 1, backoff_ttl_ms(attempt + 1, &CFG))]
            );
            assert_eq!(rig.settle.calls(), ["ack"], "original acked, not nacked");

            let entries = rig.audit.entries();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].action, "webhook.delivery_attempt");
            assert!(matches!(entries[0].outcome, AuditOutcome::Failure));
            assert_eq!(
                entries[0].metadata,
                Some(serde_json::json!({
                    "delivery_id": msg.delivery_id,
                    "attempt": attempt + 1,
                    "error": "non-2xx status: 503",
                    "next_retry_in_ms": backoff_ttl_ms(attempt + 1, &CFG),
                }))
            );
        }
        assert_ne!(
            backoff_ttl_ms(1, &CFG),
            backoff_ttl_ms(2, &CFG),
            "the TTL grows with the attempt"
        );
    }

    #[tokio::test]
    async fn max_attempts_dead_letters() {
        let rig = Rig::new();
        // attempt 2 -> next_attempt 3 == max_attempts: exhausted.
        let msg = message(CFG.max_attempts - 1);
        let d = Scripted::new(Ok(DeliveryOutcome::Retry {
            reason: "still down".into(),
        }));
        rig.run(&msg, &d).await;

        assert!(
            rig.retry.published.lock().unwrap().is_empty(),
            "no retry copy"
        );
        assert_eq!(rig.settle.calls(), ["nack(requeue=false)"], "-> the DLQ");
        let entries = rig.audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "webhook.delivery_failed");
        assert_eq!(
            entries[0].metadata,
            Some(serde_json::json!({
                "delivery_id": msg.delivery_id,
                "attempt": CFG.max_attempts,
                "error": "still down",
                "next_retry_in_ms": null,
            }))
        );
    }

    #[tokio::test]
    async fn a_deliverer_error_is_mapped_to_retry() {
        let rig = Rig::new();
        let msg = message(0);
        let d = Scripted::new(Err(OutboundError::Delivery("lookup failed".into())));
        rig.run(&msg, &d).await;

        assert_eq!(d.calls.load(Ordering::SeqCst), 1, "exactly one attempt");
        assert_eq!(
            *rig.retry.published.lock().unwrap(),
            [(1, backoff_ttl_ms(1, &CFG))]
        );
        assert_eq!(rig.settle.calls(), ["ack"]);
        assert_eq!(rig.audit.entries()[0].action, "webhook.delivery_attempt");
    }

    #[tokio::test]
    async fn a_deliverer_error_on_the_last_attempt_dead_letters() {
        let rig = Rig::new();
        let d = Scripted::new(Err(OutboundError::Delivery("boom".into())));
        rig.run(&message(CFG.max_attempts - 1), &d).await;
        assert_eq!(rig.settle.calls(), ["nack(requeue=false)"]);
    }

    #[test]
    fn an_unregistered_kind_is_refused() {
        let deliverers = OutboundDeliverers::new();
        assert!(deliverers.get(OutboundKind::Webhook).is_none());
        match deliverers.require(OutboundKind::Webhook) {
            Err(OutboundConsumerError::Unregistered(OutboundKind::Webhook)) => {}
            other => panic!("expected Unregistered, got {:?}", other.map(|_| ())),
        }
    }

    // ---- the rest of the loop's contract -----------------------------------

    #[test]
    fn registry_holds_one_deliverer_per_kind() {
        let mut deliverers = OutboundDeliverers::new();
        let first: Arc<dyn OutboundDeliverer> =
            Arc::new(Scripted::new(Ok(DeliveryOutcome::Delivered {
                response_status: None,
            })));
        deliverers.register(first.clone()).unwrap();
        assert!(Arc::ptr_eq(
            deliverers.require(OutboundKind::Webhook).unwrap(),
            &first
        ));
        let second: Arc<dyn OutboundDeliverer> =
            Arc::new(Scripted::new(Ok(DeliveryOutcome::Delivered {
                response_status: None,
            })));
        assert!(matches!(
            deliverers.register(second),
            Err(OutboundConsumerError::Duplicate(OutboundKind::Webhook))
        ));
    }

    #[tokio::test]
    async fn dead_letter_outcome_skips_the_remaining_attempts() {
        let rig = Rig::new();
        let d = Scripted::new(Ok(DeliveryOutcome::DeadLetter {
            reason: "target gone".into(),
        }));
        rig.run(&message(0), &d).await;

        assert!(rig.retry.published.lock().unwrap().is_empty());
        assert_eq!(rig.settle.calls(), ["nack(requeue=false)"]);
        assert_eq!(rig.audit.entries()[0].action, "webhook.delivery_failed");
    }

    /// CQ-B49: a retry copy that cannot be enqueued must not cost the delivery.
    #[tokio::test]
    async fn retry_publish_failure_requeues_the_original_and_does_not_ack() {
        let mut rig = Rig::new();
        rig.retry.fail = true;
        let d = Scripted::new(Ok(DeliveryOutcome::Retry {
            reason: "down".into(),
        }));
        rig.run(&message(0), &d).await;

        assert_eq!(rig.settle.calls(), ["nack(requeue=true)"]);
        assert!(
            rig.audit.entries().is_empty(),
            "no false 'retry scheduled' record"
        );
    }

    #[tokio::test]
    async fn undecodable_bytes_are_nacked_without_calling_the_deliverer() {
        let rig = Rig::new();
        let d = Scripted::new(Ok(DeliveryOutcome::Delivered {
            response_status: None,
        }));
        rig.run_bytes(b"{not a webhook message", &d).await;

        assert_eq!(d.calls.load(Ordering::SeqCst), 0);
        assert_eq!(rig.settle.calls(), ["nack(requeue=false)"]);
        assert!(rig.audit.entries().is_empty());
    }

    /// G-8: this loop and the in-process dispatcher share `outcome::decide`.
    /// Every row of the shared table, driven through the AMQP loop, settles as
    /// its shape says and writes the audit row the table's action names.
    #[tokio::test]
    async fn every_row_of_the_shared_outcome_table_settles_and_audits_as_documented() {
        use table::Shape;
        for case in table::cases() {
            let rig = Rig::new();
            let msg = message(case.attempt);
            let d = Scripted::new(case.result.clone());
            rig.run(&msg, &d).await;

            let (settle, republished): (&[&str], usize) = match case.shape {
                Shape::Delivered => (&["ack"], 0),
                Shape::Retry => (&["ack"], 1),
                Shape::DeadLetter => (&["nack(requeue=false)"], 0),
            };
            assert_eq!(rig.settle.calls(), settle, "{}", case.name);
            assert_eq!(
                rig.retry.published.lock().unwrap().len(),
                republished,
                "{}",
                case.name
            );
            let entries = rig.audit.entries();
            assert_eq!(entries.len(), 1, "{}", case.name);
            assert_eq!(
                entries[0].action,
                format!("webhook.{}", case.action),
                "{}",
                case.name
            );
            assert_eq!(
                matches!(entries[0].outcome, AuditOutcome::Success),
                case.success,
                "{}",
                case.name
            );
        }
    }
}
