//! The in-process outbound dispatcher: the minimal profile's replacement for the
//! broker (`AXIAM__AMQP__ENABLED=false`, G-8, D-59).
//!
//! It implements the same two ports as the AMQP machinery. Producers keep their
//! `Arc<dyn OutboundPublisher>` and never learn which transport carries their
//! messages; the deliverers (`OutboundDeliverer`) are the very ones the AMQP
//! loop calls, once per attempt.
//!
//! | Piece | Role |
//! |---|---|
//! | [`InProcessOutboundPublisher`] | `OutboundPublisher` over one bounded `tokio::mpsc` channel per kind (capacity [`IN_PROCESS_CAPACITY`]); a full channel is an `OutboundError::Enqueue`, which every producer already treats as best-effort |
//! | [`spawn_in_process_consumer`] | one task per kind: takes a message, asks the kind's deliverer for **one** attempt, and applies `outcome::decide` — the same outcome table, the same retry policy (`AXIAM__<SLUG>__*`), the same audit vocabulary as the AMQP loop |
//!
//! # What differs from the broker, and why it is the profile's recorded trade
//!
//! * **Nothing survives a restart.** A queued message, and a retry that is
//!   sleeping, are lost with the process. There is no durable queue (a
//!   SurrealDB-backed one was rejected in D-59: a second dispatcher, for a
//!   profile whose point is being small).
//! * **A dead letter is the audit row only.** There is no dead-letter queue to
//!   replay from; `<slug>.delivery_failed` is the whole record.
//! * **A retry is a delayed re-dispatch**: a spawned task sleeps the policy's
//!   backoff and sends the message back into the kind's channel. The number of
//!   such sleeping retries is bounded ([`IN_PROCESS_MAX_PENDING_RETRIES`]); a
//!   retry that finds no free slot is dead-lettered with a stated reason rather
//!   than spawning without bound.
//! * **One attempt at a time per kind**, like one AMQP consumer with a
//!   prefetch of one delivery in flight.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use axiam_core::models::audit::CreateAuditLogEntry;
use axiam_core::outbound::{
    OutboundDeliverer, OutboundError, OutboundFuture, OutboundKind, OutboundMessage,
    OutboundPublisher,
};
use axiam_core::repository::AuditLogRepository;

use super::consumer::{AuditSink, OutboundConsumerError, OutboundDeliverers, OwnedAuditSink};
use super::outcome::{self, Verdict};
use super::retry::OutboundRetryConfig;

/// Messages one kind's channel holds before an enqueue is refused.
pub const IN_PROCESS_CAPACITY: usize = 1_024;

/// Retries one kind may have sleeping at once. A backlog of failing deliveries
/// cannot spawn an unbounded number of sleeping tasks.
pub const IN_PROCESS_MAX_PENDING_RETRIES: usize = 1_024;

/// The reason written to the audit row of a retry that could not be scheduled.
pub const RETRY_CAPACITY_REASON: &str = "in-process retry capacity exhausted";

/// `OutboundPublisher` over a bounded channel per kind.
#[derive(Clone)]
pub struct InProcessOutboundPublisher {
    senders: Arc<HashMap<OutboundKind, mpsc::Sender<OutboundMessage>>>,
}

impl OutboundPublisher for InProcessOutboundPublisher {
    fn enqueue<'a>(
        &'a self,
        msg: &'a OutboundMessage,
    ) -> OutboundFuture<'a, Result<(), OutboundError>> {
        Box::pin(async move {
            let sender = self.senders.get(&msg.kind).ok_or_else(|| {
                OutboundError::Enqueue(format!("no in-process queue for kind `{}`", msg.kind))
            })?;
            sender.try_send(msg.clone()).map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => OutboundError::Enqueue(format!(
                    "in-process `{}` queue is full ({} messages)",
                    msg.kind,
                    sender.max_capacity()
                )),
                mpsc::error::TrySendError::Closed(_) => OutboundError::Enqueue(format!(
                    "in-process `{}` dispatcher is not running",
                    msg.kind
                )),
            })
        })
    }
}

/// The consuming half of one kind's channel, plus the sender its delayed
/// retries re-enter through. Handed to [`spawn_in_process_consumer`].
pub struct InProcessConsumerEnd {
    kind: OutboundKind,
    receiver: mpsc::Receiver<OutboundMessage>,
    redispatch: mpsc::Sender<OutboundMessage>,
}

impl InProcessConsumerEnd {
    /// The kind this end serves.
    pub fn kind(&self) -> OutboundKind {
        self.kind
    }
}

/// The channels of every kind: the publisher producers hold, and the consuming
/// end of each kind, taken once by that kind's consumer.
pub struct InProcessOutbound {
    publisher: InProcessOutboundPublisher,
    ends: HashMap<OutboundKind, InProcessConsumerEnd>,
}

impl InProcessOutbound {
    /// One channel of [`IN_PROCESS_CAPACITY`] per [`OutboundKind`].
    pub fn new() -> Self {
        Self::with_capacity(IN_PROCESS_CAPACITY)
    }

    /// As [`Self::new`] with an explicit capacity (tests use a tiny one).
    pub fn with_capacity(capacity: usize) -> Self {
        let mut senders = HashMap::new();
        let mut ends = HashMap::new();
        for &kind in OutboundKind::ALL {
            let (tx, rx) = mpsc::channel(capacity.max(1));
            senders.insert(kind, tx.clone());
            ends.insert(
                kind,
                InProcessConsumerEnd {
                    kind,
                    receiver: rx,
                    redispatch: tx,
                },
            );
        }
        Self {
            publisher: InProcessOutboundPublisher {
                senders: Arc::new(senders),
            },
            ends,
        }
    }

    /// The publisher for every kind. Clone freely; producers hold it as an
    /// `Arc<dyn OutboundPublisher>`.
    pub fn publisher(&self) -> InProcessOutboundPublisher {
        self.publisher.clone()
    }

    /// Take `kind`'s consuming end. `None` if it was already taken.
    pub fn take_consumer_end(&mut self, kind: OutboundKind) -> Option<InProcessConsumerEnd> {
        self.ends.remove(&kind)
    }
}

impl Default for InProcessOutbound {
    fn default() -> Self {
        Self::new()
    }
}

/// Schedules the delayed re-dispatch of a retry, within a bound.
struct RetryScheduler {
    redispatch: mpsc::Sender<OutboundMessage>,
    slots: Arc<Semaphore>,
}

impl RetryScheduler {
    fn new(redispatch: mpsc::Sender<OutboundMessage>, max_pending: usize) -> Self {
        Self {
            redispatch,
            slots: Arc::new(Semaphore::new(max_pending.max(1))),
        }
    }

    /// Sleep `ttl_ms` in a spawned task, then send `next` back into the kind's
    /// channel. `Err(())` when [`IN_PROCESS_MAX_PENDING_RETRIES`] retries are
    /// already sleeping.
    fn schedule(&self, next: OutboundMessage, ttl_ms: u64) -> Result<(), ()> {
        let permit = Arc::clone(&self.slots).try_acquire_owned().map_err(|_| ())?;
        let tx = self.redispatch.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(ttl_ms)).await;
            // `send` (not `try_send`): a full channel makes the retry wait for
            // room rather than lose it. The permit is held meanwhile, so the
            // number of such waiters stays bounded.
            if tx.send(next).await.is_err() {
                warn!("in-process outbound dispatcher stopped; a pending retry was dropped");
            }
            drop(permit);
        });
        Ok(())
    }
}

async fn record<A: AuditSink>(audit: &A, entry: CreateAuditLogEntry) {
    let action = entry.action.clone();
    if let Err(e) = audit.record(entry).await {
        error!(error = %e, %action, "Failed to write outbound delivery audit event");
    }
}

/// Handle one message end to end: one attempt, then the verdict. The unit the
/// tests drive.
async fn process_message<A: AuditSink>(
    msg: OutboundMessage,
    deliverer: &dyn OutboundDeliverer,
    audit: &A,
    retries: &RetryScheduler,
    cfg: &OutboundRetryConfig,
) {
    let result = deliverer.deliver_attempt(&msg).await;
    match outcome::decide(&msg, outcome::classify(result), cfg) {
        Verdict::Delivered { audit: entry } => record(audit, entry).await,
        Verdict::Retry {
            next,
            ttl_ms,
            audit: entry,
        } => {
            if retries.schedule(next, ttl_ms).is_ok() {
                record(audit, entry).await;
            } else {
                // No slot for another sleeping retry: say so, and stop.
                warn!(
                    kind = %msg.kind,
                    delivery_id = %msg.delivery_id,
                    "in-process outbound retry capacity exhausted; dead-lettering"
                );
                record(audit, outcome::failed_entry(&msg, RETRY_CAPACITY_REASON)).await;
            }
        }
        // There is no dead-letter queue: the row is the whole record.
        Verdict::DeadLetter { audit: entry } => record(audit, entry).await,
    }
}

async fn run_in_process_consumer<A: AuditSink>(
    mut end: InProcessConsumerEnd,
    deliverer: Arc<dyn OutboundDeliverer>,
    audit: A,
    cfg: OutboundRetryConfig,
    max_pending_retries: usize,
) {
    let kind = end.kind;
    let retries = RetryScheduler::new(end.redispatch.clone(), max_pending_retries);
    info!(%kind, "Starting in-process outbound consumer");
    while let Some(msg) = end.receiver.recv().await {
        process_message(msg, deliverer.as_ref(), &audit, &retries, &cfg).await;
    }
    // Unreachable while `redispatch` is held, which it is for the loop's life;
    // kept so a future change to that ownership is loud rather than silent.
    warn!(%kind, "In-process outbound consumer stopped");
}

/// Spawn the in-process consumer for one outbound kind.
///
/// Returns `Err(Unregistered)` — before spawning anything — when `deliverers`
/// has nothing for the end's kind, exactly as the AMQP consumer refuses.
/// `audit_repo` receives the same `<slug>.delivery_*` rows the AMQP loop writes.
pub fn spawn_in_process_consumer<A>(
    end: InProcessConsumerEnd,
    deliverers: &OutboundDeliverers,
    audit_repo: A,
    cfg: OutboundRetryConfig,
) -> Result<JoinHandle<()>, OutboundConsumerError>
where
    A: AuditLogRepository + 'static,
{
    spawn_with_sink(
        end,
        deliverers,
        OwnedAuditSink(audit_repo),
        cfg,
        IN_PROCESS_MAX_PENDING_RETRIES,
    )
}

fn spawn_with_sink<A>(
    end: InProcessConsumerEnd,
    deliverers: &OutboundDeliverers,
    audit: A,
    cfg: OutboundRetryConfig,
    max_pending_retries: usize,
) -> Result<JoinHandle<()>, OutboundConsumerError>
where
    A: AuditSink + 'static,
{
    let deliverer = Arc::clone(deliverers.require(end.kind)?);
    Ok(tokio::spawn(run_in_process_consumer(
        end,
        deliverer,
        audit,
        cfg,
        max_pending_retries,
    )))
}

#[cfg(test)]
mod tests {
    use super::super::outcome::table::{self, Shape};
    use super::*;
    use axiam_core::models::audit::AuditOutcome;
    use axiam_core::outbound::DeliveryOutcome;
    use std::collections::VecDeque;
    use std::future::Future;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[derive(Clone, Default)]
    struct FakeAudit {
        entries: Arc<Mutex<Vec<CreateAuditLogEntry>>>,
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

    /// Answers from a script, one result per attempt; the last repeats.
    struct Scripted {
        kind: OutboundKind,
        script: Mutex<VecDeque<Result<DeliveryOutcome, OutboundError>>>,
        last: Mutex<Option<Result<DeliveryOutcome, OutboundError>>>,
        calls: AtomicU32,
        attempts_seen: Mutex<Vec<u32>>,
    }
    impl Scripted {
        fn new(kind: OutboundKind, script: Vec<Result<DeliveryOutcome, OutboundError>>) -> Self {
            Self {
                kind,
                script: Mutex::new(script.into()),
                last: Mutex::new(None),
                calls: AtomicU32::new(0),
                attempts_seen: Mutex::new(Vec::new()),
            }
        }
    }
    impl OutboundDeliverer for Scripted {
        fn kind(&self) -> OutboundKind {
            self.kind
        }
        fn deliver_attempt<'a>(
            &'a self,
            msg: &'a OutboundMessage,
        ) -> OutboundFuture<'a, Result<DeliveryOutcome, OutboundError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.attempts_seen.lock().unwrap().push(msg.attempt);
            let next = self.script.lock().unwrap().pop_front();
            let result = match next {
                Some(r) => {
                    *self.last.lock().unwrap() = Some(r.clone());
                    r
                }
                None => self.last.lock().unwrap().clone().expect("script is empty"),
            };
            Box::pin(async move { result })
        }
    }

    fn delivered() -> Result<DeliveryOutcome, OutboundError> {
        Ok(DeliveryOutcome::Delivered {
            response_status: Some(204),
        })
    }

    fn retry(reason: &str) -> Result<DeliveryOutcome, OutboundError> {
        Ok(DeliveryOutcome::Retry {
            reason: reason.into(),
        })
    }

    /// Millisecond backoff so retry tests run in real time.
    const FAST: OutboundRetryConfig = OutboundRetryConfig {
        max_attempts: 3,
        backoff_base_ms: 5,
        backoff_ceiling_ms: 20,
    };

    fn started(
        kind: OutboundKind,
        deliverer: Arc<Scripted>,
        cfg: OutboundRetryConfig,
        pending: usize,
    ) -> (InProcessOutboundPublisher, FakeAudit, JoinHandle<()>) {
        let mut hub = InProcessOutbound::with_capacity(8);
        let publisher = hub.publisher();
        let audit = FakeAudit::default();
        let mut deliverers = OutboundDeliverers::new();
        deliverers.register(deliverer).unwrap();
        let handle = spawn_with_sink(
            hub.take_consumer_end(kind).unwrap(),
            &deliverers,
            audit.clone(),
            cfg,
            pending,
        )
        .unwrap();
        (publisher, audit, handle)
    }

    async fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
        for _ in 0..400 {
            if done() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("timed out waiting for {what}");
    }

    #[tokio::test]
    async fn a_delivered_message_is_attempted_once_and_audited() {
        let deliverer = Arc::new(Scripted::new(OutboundKind::Webhook, vec![delivered()]));
        let (publisher, audit, _h) = started(OutboundKind::Webhook, deliverer.clone(), FAST, 8);

        let msg = table::message(OutboundKind::Webhook, 0);
        publisher.enqueue(&msg).await.unwrap();
        wait_for("the success row", || audit.entries().len() == 1).await;

        let entries = audit.entries();
        assert_eq!(entries[0].action, "webhook.delivery_succeeded");
        assert!(matches!(entries[0].outcome, AuditOutcome::Success));
        assert_eq!(entries[0].resource_id, Some(msg.target_id));
        assert_eq!(
            entries[0].metadata,
            Some(serde_json::json!({
                "delivery_id": msg.delivery_id, "attempt": 1, "status": 204
            }))
        );
        assert_eq!(deliverer.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_retry_backs_off_then_is_delivered_with_the_incremented_attempt() {
        let deliverer = Arc::new(Scripted::new(
            OutboundKind::SsfPush,
            vec![retry("non-2xx status: 503"), delivered()],
        ));
        let (publisher, audit, _h) = started(OutboundKind::SsfPush, deliverer.clone(), FAST, 8);

        let msg = table::message(OutboundKind::SsfPush, 0);
        publisher.enqueue(&msg).await.unwrap();
        wait_for("both rows", || audit.entries().len() == 2).await;

        let entries = audit.entries();
        assert_eq!(entries[0].action, "ssf_push.delivery_attempt");
        assert_eq!(
            entries[0].metadata,
            Some(serde_json::json!({
                "delivery_id": msg.delivery_id,
                "attempt": 1,
                "error": "non-2xx status: 503",
                "next_retry_in_ms": super::super::retry::backoff_ttl_ms(1, &FAST),
            }))
        );
        assert_eq!(entries[1].action, "ssf_push.delivery_succeeded");
        assert_eq!(
            *deliverer.attempts_seen.lock().unwrap(),
            [0, 1],
            "the re-dispatched copy carries attempt + 1"
        );
    }

    #[tokio::test]
    async fn max_attempts_ends_in_a_dead_letter_row_and_no_more_attempts() {
        let deliverer = Arc::new(Scripted::new(
            OutboundKind::ScimPush,
            vec![retry("still down")],
        ));
        let (publisher, audit, _h) = started(OutboundKind::ScimPush, deliverer.clone(), FAST, 8);

        let msg = table::message(OutboundKind::ScimPush, 0);
        publisher.enqueue(&msg).await.unwrap();
        wait_for("the dead-letter row", || {
            audit
                .entries()
                .iter()
                .any(|e| e.action == "scim_push.delivery_failed")
        })
        .await;

        let actions: Vec<_> = audit.entries().into_iter().map(|e| e.action).collect();
        assert_eq!(
            actions,
            [
                "scim_push.delivery_attempt",
                "scim_push.delivery_attempt",
                "scim_push.delivery_failed"
            ]
        );
        let last = audit.entries().pop().unwrap();
        assert_eq!(
            last.metadata,
            Some(serde_json::json!({
                "delivery_id": msg.delivery_id,
                "attempt": FAST.max_attempts,
                "error": "still down",
                "next_retry_in_ms": null,
            }))
        );
        // Nothing further is attempted after the dead letter.
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(deliverer.calls.load(Ordering::SeqCst), FAST.max_attempts);
    }

    #[tokio::test]
    async fn a_full_channel_refuses_the_enqueue() {
        let hub = InProcessOutbound::with_capacity(2);
        let publisher = hub.publisher();
        // No consumer is attached, so the channel only fills.
        for _ in 0..2 {
            publisher
                .enqueue(&table::message(OutboundKind::CibaPing, 0))
                .await
                .unwrap();
        }
        let err = publisher
            .enqueue(&table::message(OutboundKind::CibaPing, 0))
            .await
            .unwrap_err();
        assert!(matches!(err, OutboundError::Enqueue(_)), "{err:?}");
        // Another kind has its own channel and is unaffected.
        publisher
            .enqueue(&table::message(OutboundKind::Webhook, 0))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn the_production_capacity_is_1024_per_kind() {
        let hub = InProcessOutbound::new();
        let publisher = hub.publisher();
        for _ in 0..IN_PROCESS_CAPACITY {
            publisher
                .enqueue(&table::message(OutboundKind::Webhook, 0))
                .await
                .unwrap();
        }
        assert!(
            publisher
                .enqueue(&table::message(OutboundKind::Webhook, 0))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_kind_without_a_registered_deliverer_is_refused_before_spawning() {
        let mut hub = InProcessOutbound::new();
        let deliverers = OutboundDeliverers::new();
        let result = spawn_with_sink(
            hub.take_consumer_end(OutboundKind::Webhook).unwrap(),
            &deliverers,
            FakeAudit::default(),
            FAST,
            8,
        );
        assert!(matches!(
            result,
            Err(OutboundConsumerError::Unregistered(OutboundKind::Webhook))
        ));
    }

    #[tokio::test]
    async fn a_consumer_end_is_taken_once() {
        let mut hub = InProcessOutbound::new();
        assert!(hub.take_consumer_end(OutboundKind::Webhook).is_some());
        assert!(hub.take_consumer_end(OutboundKind::Webhook).is_none());
    }

    #[tokio::test]
    async fn a_retry_with_no_free_slot_is_dead_lettered_with_its_reason() {
        let deliverer = Arc::new(Scripted::new(
            OutboundKind::Webhook,
            vec![retry("down"), retry("down")],
        ));
        // A long backoff keeps the first retry asleep, holding the only slot.
        let slow = OutboundRetryConfig {
            max_attempts: 5,
            backoff_base_ms: 60_000,
            backoff_ceiling_ms: 60_000,
        };
        let (publisher, audit, _h) = started(OutboundKind::Webhook, deliverer, slow, 1);

        publisher
            .enqueue(&table::message(OutboundKind::Webhook, 0))
            .await
            .unwrap();
        let second = table::message(OutboundKind::Webhook, 0);
        publisher.enqueue(&second).await.unwrap();
        wait_for("both rows", || audit.entries().len() == 2).await;

        let entries = audit.entries();
        assert_eq!(entries[0].action, "webhook.delivery_attempt");
        assert_eq!(entries[1].action, "webhook.delivery_failed");
        assert_eq!(
            entries[1].metadata.as_ref().unwrap()["error"],
            RETRY_CAPACITY_REASON
        );
        assert_eq!(entries[1].resource_id, Some(second.target_id));
    }

    /// G-8: the same outcome table as the AMQP loop. Every row of the shared
    /// table, driven through this dispatcher, writes the audit row the table's
    /// action names, for every kind.
    #[tokio::test]
    async fn every_row_of_the_shared_outcome_table_audits_as_documented() {
        for case in table::cases() {
            for kind in OutboundKind::ALL {
                let audit = FakeAudit::default();
                let (tx, _rx) = mpsc::channel(8);
                let retries = RetryScheduler::new(tx, 8);
                let deliverer = Scripted::new(*kind, vec![case.result.clone()]);
                let msg = table::message(*kind, case.attempt);
                process_message(msg.clone(), &deliverer, &audit, &retries, &table::CFG).await;

                let entries = audit.entries();
                assert_eq!(entries.len(), 1, "{}", case.name);
                assert_eq!(
                    entries[0].action,
                    format!("{}.{}", kind.as_str(), case.action),
                    "{}",
                    case.name
                );
                assert_eq!(
                    matches!(entries[0].outcome, AuditOutcome::Success),
                    case.success,
                    "{}",
                    case.name
                );
                assert_eq!(
                    retries.slots.available_permits() < 8,
                    case.shape == Shape::Retry,
                    "{}: only a retry takes a slot",
                    case.name
                );
            }
        }
    }
}
