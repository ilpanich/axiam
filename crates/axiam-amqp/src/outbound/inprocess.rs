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
//! | [`InProcessOutboundPublisher`] | `OutboundPublisher` over one bounded `tokio::mpsc` channel per kind (capacity [`IN_PROCESS_CAPACITY`]); a full channel is an `OutboundError::Enqueue`, which every producer already treats as best-effort. The refusal's audit row is handed to the audit middleware's non-blocking queue, never awaited on the producer's path (#596), and a bulk producer's run adds at most one more for what it held back (R101W4-01). A bulk producer off every request path (SCIM reconciliation) offers through `enqueue_paced`, which waits for room — leaving [`PACED_RESERVE_DIVISOR`]'s share of the channel to producers that do not wait — until its deadline, a stop or a closed channel (R101-01) |
//! | [`spawn_in_process_consumer`] | one task per kind: takes a message, asks the kind's deliverer for **one** attempt, and applies `outcome::decide` — the same outcome table, the same retry policy (`AXIAM__<SLUG>__*`), the same audit vocabulary as the AMQP loop |
//!
//! # What differs from the broker, and why it is the profile's recorded trade
//!
//! * **Nothing survives a restart.** A queued message, and a retry that is
//!   sleeping, are lost with the process. There is no durable queue (a
//!   SurrealDB-backed one was rejected in D-59: a second dispatcher, for a
//!   profile whose point is being small). What the dispatcher can do is say so:
//!   at an orderly stop ([`InProcessShutdown`]) each kind's consumer writes one
//!   terminal `<slug>.delivery_abandoned` row per message still queued or
//!   waiting for a retry, and an enqueue the queue refuses writes one too
//!   (P23W5-A4). A kill, an OOM kill or a stop that overruns its deadline still
//!   loses them without a trace.
//! * **A dead letter is the audit row only.** There is no dead-letter queue to
//!   replay from; `<slug>.delivery_failed` is the whole record. A delivery
//!   abandoned at stop is a different row, `<slug>.delivery_abandoned`, so that
//!   a restart does not read as a downstream outage (SCIM's `scim_delivery_failed`
//!   notification matches `delivery_failed` only).
//! * **A retry is a delayed re-dispatch**: a spawned task sleeps the policy's
//!   backoff and sends the message back into the kind's channel. The number of
//!   such sleeping retries is bounded ([`IN_PROCESS_MAX_PENDING_RETRIES`]); a
//!   retry that finds no free slot is dead-lettered with a stated reason rather
//!   than spawning without bound.
//! * **One attempt at a time per kind**, like one AMQP consumer with a
//!   prefetch of one delivery in flight.

use std::collections::HashMap;
use std::future::pending;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use tokio::sync::{Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{error, info, warn};
use uuid::Uuid;

use axiam_audit::AuditMiddleware;
use axiam_core::models::audit::CreateAuditLogEntry;
use axiam_core::outbound::{
    DeliveryOutcome, OutboundDeliverer, OutboundError, OutboundFuture, OutboundKind,
    OutboundMessage, OutboundPublisher,
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

/// The reason of the `delivery_abandoned` row of a delivery that was queued, in
/// flight or waiting for a retry when the dispatcher stopped.
pub const STOPPED_REASON: &str = "in-process dispatcher stopped before the delivery completed";

/// The reason of the `delivery_abandoned` row of an enqueue refused because the
/// kind's channel was full.
pub const QUEUE_FULL_REASON: &str = "in-process queue full; the delivery was not accepted";

/// The reason of the `delivery_abandoned` row of an enqueue refused because the
/// kind's consumer is gone (stopped, or never started).
pub const NOT_RUNNING_REASON: &str =
    "in-process dispatcher not running; the delivery was not accepted";

/// A paced producer (`enqueue_paced`, R101-01) sends only while more than
/// `capacity / PACED_RESERVE_DIVISOR` slots of the channel are free: a quarter
/// is left to the producers that do not wait — a change reported on a request
/// path, a linked user's groups enqueued by the deliverer, a retry re-entering
/// the channel — so that a reconciliation that keeps the queue busy for minutes
/// does not get every live change of the tenant refused meanwhile.
pub const PACED_RESERVE_DIVISOR: usize = 4;

/// How often a paced producer looks for room, a stop and its deadline while it
/// waits. Small beside a delivery (an HTTP round trip) and beside the cleanup
/// task's stop bound (`ORDERLY_STOP.cleanup`, 5 s).
pub const PACE_POLL: Duration = Duration::from_millis(10);

/// How long an attempt already in flight is given to finish once a stop is
/// signalled. A healthy receiver answers well inside it and the delivery gets its
/// own verdict; a slow one is cancelled, so that it cannot hold back the account
/// of everything queued behind it (the receiver that is slow is the one whose
/// queue is fullest).
pub const IN_FLIGHT_STOP_GRACE: Duration = Duration::from_millis(500);

/// The least time between two `WARN` lines about refused enqueues of one kind
/// (#596). The first refusal logs at once; those inside the interval are
/// counted and the next line carries the count.
const REFUSAL_REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// Writes the `delivery_abandoned` row of a delivery the dispatcher lost. Object
/// safe, so the publisher (created before any audit repository is chosen) can
/// be given the consumer's sink once that consumer starts.
trait AbandonRecorder: Send + Sync {
    fn record<'a>(&'a self, entry: CreateAuditLogEntry) -> OutboundFuture<'a, ()>;
}

struct SinkRecorder<A>(Arc<A>);

impl<A: AuditSink + 'static> AbandonRecorder for SinkRecorder<A> {
    fn record<'a>(&'a self, entry: CreateAuditLogEntry) -> OutboundFuture<'a, ()> {
        Box::pin(record(self.0.as_ref(), entry))
    }
}

/// Where a kind's consumer registers its [`AbandonRecorder`] for the publisher.
type RecorderSlot = Arc<OnceLock<Arc<dyn AbandonRecorder>>>;

/// Write `msg`'s `delivery_abandoned` row, if a consumer has registered a sink.
///
/// For the consumer's own paths (a stop, a retry that finds the channel gone),
/// which run on the consumer's task and are bounded by what the queues hold; the
/// producer's refused enqueue goes through [`refuse`] instead.
async fn abandon(recorder: Option<&Arc<dyn AbandonRecorder>>, msg: &OutboundMessage, reason: &str) {
    warn!(
        kind = %msg.kind,
        delivery_id = %msg.delivery_id,
        reason,
        "in-process outbound delivery abandoned"
    );
    if let Some(recorder) = recorder {
        recorder.record(outcome::abandoned_entry(msg, reason)).await;
    }
}

/// Counts one kind's refused enqueues and decides which of them get a `WARN`
/// line, on the pattern of the audit worker's notification-drop report: the
/// first refusal is logged at once, then at most one line per
/// [`REFUSAL_REPORT_INTERVAL`], carrying how many were suppressed since.
#[derive(Default)]
struct RefusalLog {
    refused: AtomicU64,
    /// When the latest line was logged, and `refused` at that moment.
    last_report: Mutex<(Option<Instant>, u64)>,
}

/// What a `WARN` line about refusals says.
struct RefusalReport {
    /// Refusals of the kind since start, this one included.
    total: u64,
    /// Refusals since the previous line that were not logged.
    suppressed: u64,
}

impl RefusalLog {
    /// Count one refusal at `now`; `Some` when this one is to be logged.
    fn note(&self, now: Instant) -> Option<RefusalReport> {
        let total = self.refused.fetch_add(1, AtomicOrdering::Relaxed) + 1;
        let mut last = self
            .last_report
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (at, reported) = *last;
        if at.is_some_and(|t| now.saturating_duration_since(t) < REFUSAL_REPORT_INTERVAL) {
            return None;
        }
        *last = (Some(now), total);
        Some(RefusalReport {
            total,
            suppressed: total.saturating_sub(reported + 1),
        })
    }
}

/// The audit middleware's non-blocking queue, once the composition root has
/// bound it (the middleware is built after the producers' publishers are).
type AuditSlot = Arc<OnceLock<AuditMiddleware>>;

/// One kind's sending half and the slot its consumer's sink arrives in.
struct Queue {
    sender: mpsc::Sender<OutboundMessage>,
    recorder: RecorderSlot,
    refusals: RefusalLog,
}

/// What a refused enqueue leaves behind, on the producer's path (#596): at most
/// a rate-limited `WARN` and a hand-off to a queue that never waits.
///
/// The `delivery_abandoned` row goes to the audit middleware's bounded channel
/// with `try_record`. If that channel is down to the share it keeps for request
/// rows, the row is shed and counted (`outbound_abandoned_dropped`), never
/// dead-lettered and never counted as a lost request row (R101W4-01, R101W4-06);
/// nothing here touches the datastore. A bulk producer stops at its first
/// refusal and records the rest of its run as one row
/// ([`OutboundPublisher::record_not_offered`]). Only when no
/// middleware was bound (a publisher used before the composition root has built
/// it, or by an embedder with none) does the row fall back to the consumer's
/// sink, awaited as it always was.
async fn refuse(queue: &Queue, audit: &AuditSlot, msg: &OutboundMessage, reason: &str) {
    if let Some(report) = queue.refusals.note(Instant::now()) {
        warn!(
            kind = %msg.kind,
            delivery_id = %msg.delivery_id,
            reason,
            refused_total = report.total,
            suppressed_since_last_line = report.suppressed,
            "in-process outbound enqueue refused; the delivery was not accepted (logged at \
             most once a minute per kind; each refusal still hands its audit row to the \
             audit queue)"
        );
    }
    hand_off(queue, audit, outcome::abandoned_entry(msg, reason)).await;
}

/// Hand a refusal's row to the audit middleware's non-blocking queue, or, when
/// none was bound, to the consumer's sink. The middleware keeps a quarter of its
/// channel for request rows and sheds a refusal row rather than take it
/// (R101W4-01): such a row is counted in its own counter, never in the request
/// rows' `dropped` and never in the dead-letter file.
async fn hand_off(queue: &Queue, audit: &AuditSlot, entry: CreateAuditLogEntry) {
    match (audit.get(), queue.recorder.get()) {
        (Some(audit), _) => {
            audit.try_record(entry);
        }
        (None, Some(recorder)) => recorder.record(entry).await,
        (None, None) => {}
    }
}

/// `OutboundPublisher` over a bounded channel per kind.
#[derive(Clone)]
pub struct InProcessOutboundPublisher {
    queues: Arc<HashMap<OutboundKind, Queue>>,
    audit: AuditSlot,
}

impl InProcessOutboundPublisher {
    /// The refusal of `msg` by `queue` — full, or `closed` — and its trail.
    async fn refused(&self, queue: &Queue, msg: &OutboundMessage, closed: bool) -> OutboundError {
        let (reason, error) = if closed {
            (
                NOT_RUNNING_REASON,
                format!("in-process `{}` dispatcher is not running", msg.kind),
            )
        } else {
            (
                QUEUE_FULL_REASON,
                format!(
                    "in-process `{}` queue is full ({} messages)",
                    msg.kind,
                    queue.sender.max_capacity()
                ),
            )
        };
        // Every producer treats a refusal as best-effort and only logs it, so
        // the refusal is the delivery's whole trail: record it, without waiting
        // on the datastore (#596).
        refuse(queue, &self.audit, msg, reason).await;
        OutboundError::Enqueue(error)
    }
}

impl OutboundPublisher for InProcessOutboundPublisher {
    fn enqueue<'a>(
        &'a self,
        msg: &'a OutboundMessage,
    ) -> OutboundFuture<'a, Result<(), OutboundError>> {
        Box::pin(async move {
            let queue = self.queues.get(&msg.kind).ok_or_else(|| {
                OutboundError::Enqueue(format!("no in-process queue for kind `{}`", msg.kind))
            })?;
            let closed = match queue.sender.try_send(msg.clone()) {
                Ok(()) => return Ok(()),
                Err(mpsc::error::TrySendError::Full(_)) => false,
                Err(mpsc::error::TrySendError::Closed(_)) => true,
            };
            Err(self.refused(queue, msg, closed).await)
        })
    }

    /// R101-01: wait for room instead of refusing a channel that is only full
    /// for now. The message is sent once more than
    /// `capacity / PACED_RESERVE_DIVISOR` slots are free (the rest is left to
    /// producers that do not wait); the wait looks every [`PACE_POLL`] for room,
    /// for `should_stop` and for `deadline`, and ends at once on a closed
    /// channel. A wait that ends without room is refused exactly as `enqueue`
    /// refuses — one row, the reason the queue gives now — and the producer
    /// stops offering.
    fn enqueue_paced<'a>(
        &'a self,
        msg: &'a OutboundMessage,
        deadline: std::time::Instant,
        should_stop: &'a (dyn Fn() -> bool + Send + Sync),
    ) -> OutboundFuture<'a, Result<(), OutboundError>> {
        Box::pin(async move {
            let queue = self.queues.get(&msg.kind).ok_or_else(|| {
                OutboundError::Enqueue(format!("no in-process queue for kind `{}`", msg.kind))
            })?;
            let deadline = Instant::from_std(deadline);
            let reserve = queue.sender.max_capacity() / PACED_RESERVE_DIVISOR;
            let closed = loop {
                if queue.sender.is_closed() {
                    break true;
                }
                if queue.sender.capacity() > reserve {
                    match queue.sender.try_send(msg.clone()) {
                        Ok(()) => return Ok(()),
                        // Taken meanwhile by a producer that does not wait.
                        Err(mpsc::error::TrySendError::Full(_)) => {}
                        Err(mpsc::error::TrySendError::Closed(_)) => break true,
                    }
                }
                let now = Instant::now();
                if now >= deadline || should_stop() {
                    break false;
                }
                tokio::time::sleep_until((now + PACE_POLL).min(deadline)).await;
            };
            Err(self.refused(queue, msg, closed).await)
        })
    }

    /// One `<slug>.delivery_abandoned` row for the `not_offered` messages a bulk
    /// producer held back after this kind's queue refused one (R101W4-01), with
    /// `refused_count` and the reason the queue gives now (full, or not
    /// running). Handed off like a refusal's row: never awaited on the
    /// datastore once the middleware is bound.
    fn record_not_offered<'a>(
        &'a self,
        kind: OutboundKind,
        tenant_id: Uuid,
        target_id: Uuid,
        not_offered: u64,
    ) -> OutboundFuture<'a, ()> {
        Box::pin(async move {
            let Some(queue) = self.queues.get(&kind).filter(|_| not_offered > 0) else {
                return;
            };
            let reason = if queue.sender.is_closed() {
                NOT_RUNNING_REASON
            } else {
                QUEUE_FULL_REASON
            };
            warn!(
                %kind,
                %tenant_id,
                %target_id,
                reason,
                not_offered,
                "a bulk producer stopped offering at a refused enqueue; the rest of its run \
                 were not offered (one audit row records them)"
            );
            let entry = outcome::not_offered_entry(kind, tenant_id, target_id, reason, not_offered);
            hand_off(queue, &self.audit, entry).await;
        })
    }
}

/// The consuming half of one kind's channel, plus the sender its delayed
/// retries re-enter through. Handed to [`spawn_in_process_consumer`].
pub struct InProcessConsumerEnd {
    kind: OutboundKind,
    receiver: mpsc::Receiver<OutboundMessage>,
    redispatch: mpsc::Sender<OutboundMessage>,
    recorder: RecorderSlot,
    stop: watch::Receiver<bool>,
    done: oneshot::Sender<()>,
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
    stop: watch::Sender<bool>,
    done: HashMap<OutboundKind, oneshot::Receiver<()>>,
}

impl InProcessOutbound {
    /// One channel of [`IN_PROCESS_CAPACITY`] per [`OutboundKind`].
    pub fn new() -> Self {
        Self::with_capacity(IN_PROCESS_CAPACITY)
    }

    /// As [`Self::new`] with an explicit capacity (tests use a tiny one).
    pub fn with_capacity(capacity: usize) -> Self {
        let (stop, stop_rx) = watch::channel(false);
        let mut queues = HashMap::new();
        let mut ends = HashMap::new();
        let mut done = HashMap::new();
        for &kind in OutboundKind::ALL {
            let (tx, rx) = mpsc::channel(capacity.max(1));
            let recorder = RecorderSlot::default();
            let (done_tx, done_rx) = oneshot::channel();
            queues.insert(
                kind,
                Queue {
                    sender: tx.clone(),
                    recorder: Arc::clone(&recorder),
                    refusals: RefusalLog::default(),
                },
            );
            ends.insert(
                kind,
                InProcessConsumerEnd {
                    kind,
                    receiver: rx,
                    redispatch: tx,
                    recorder,
                    stop: stop_rx.clone(),
                    done: done_tx,
                },
            );
            done.insert(kind, done_rx);
        }
        Self {
            publisher: InProcessOutboundPublisher {
                queues: Arc::new(queues),
                audit: AuditSlot::default(),
            },
            ends,
            stop,
            done,
        }
    }

    /// The publisher for every kind. Clone freely; producers hold it as an
    /// `Arc<dyn OutboundPublisher>`.
    pub fn publisher(&self) -> InProcessOutboundPublisher {
        self.publisher.clone()
    }

    /// Give the publisher the audit middleware's non-blocking queue, for the
    /// `delivery_abandoned` rows of enqueues it refuses (#596). Call it once the
    /// middleware exists; publishers already handed out follow (they share the
    /// slot). `false` if one was bound already.
    pub fn bind_audit(&self, audit: AuditMiddleware) -> bool {
        self.publisher.audit.set(audit).is_ok()
    }

    /// Take `kind`'s consuming end. `None` if it was already taken.
    pub fn take_consumer_end(&mut self, kind: OutboundKind) -> Option<InProcessConsumerEnd> {
        self.ends.remove(&kind)
    }

    /// The handle that stops the consumers in order (P23W5-A4). Call it once
    /// every consumer has been spawned: an end nobody took by now never will be,
    /// so it is dropped here, and its channel then refuses enqueues.
    pub fn shutdown(&mut self) -> InProcessShutdown {
        self.ends.clear();
        InProcessShutdown {
            stop: self.stop.clone(),
            done: std::mem::take(&mut self.done).into_iter().collect(),
        }
    }
}

impl Default for InProcessOutbound {
    fn default() -> Self {
        Self::new()
    }
}

/// Stops the in-process consumers and waits until each has written the
/// `delivery_abandoned` rows of what it still held (P23W5-A4).
///
/// The composition root calls [`Self::stop`] in its teardown once nothing
/// produces any more (the REST listener and gRPC have stopped), before the audit
/// drain. A consumer gives the attempt it is in [`IN_FLIGHT_STOP_GRACE`] to
/// finish (past that the attempt is cancelled and abandoned like the rest), stops
/// taking messages, closes its channel and writes one row for each message still
/// queued and each retry still waiting. An enqueue after that is refused and
/// writes its own.
pub struct InProcessShutdown {
    stop: watch::Sender<bool>,
    done: Vec<(OutboundKind, oneshot::Receiver<()>)>,
}

impl InProcessShutdown {
    /// Signal every consumer and wait up to `deadline` for them to finish.
    /// Returns the kinds that had not finished when it ran out; their queued
    /// deliveries are lost without a row, like a kill's.
    pub async fn stop(self, deadline: Duration) -> Vec<OutboundKind> {
        let _ = self.stop.send(true);
        let until = Instant::now() + deadline;
        let mut unfinished = Vec::new();
        for (kind, done) in self.done {
            // `Err` is a consumer that ended without signalling (a panic, or an
            // end that was never taken): nothing more to wait for.
            if tokio::time::timeout_at(until, done).await.is_err() {
                unfinished.push(kind);
            }
        }
        unfinished.sort_by_key(|k| k.as_str());
        unfinished
    }
}

/// Resolves once a stop is signalled. If the signalling side is dropped without
/// one, the dispatcher keeps running, as it did before there was a stop.
async fn stopped(stop: &mut watch::Receiver<bool>) {
    if stop.wait_for(|stopping| *stopping).await.is_err() {
        pending::<()>().await;
    }
}

/// Why a retry could not be scheduled.
enum NotScheduled {
    /// [`IN_PROCESS_MAX_PENDING_RETRIES`] retries are already sleeping.
    Capacity,
    /// The dispatcher is stopping.
    Stopped,
}

/// Schedules the delayed re-dispatch of a retry, within a bound, and remembers
/// what is sleeping so a stop can account for it.
struct RetryScheduler {
    redispatch: mpsc::Sender<OutboundMessage>,
    slots: Arc<Semaphore>,
    /// The retries asleep, by delivery id; `None` once the dispatcher stopped.
    pending: Arc<Mutex<Option<HashMap<Uuid, OutboundMessage>>>>,
    recorder: Arc<dyn AbandonRecorder>,
}

impl RetryScheduler {
    fn new(
        redispatch: mpsc::Sender<OutboundMessage>,
        max_pending: usize,
        recorder: Arc<dyn AbandonRecorder>,
    ) -> Self {
        Self {
            redispatch,
            slots: Arc::new(Semaphore::new(max_pending.max(1))),
            pending: Arc::new(Mutex::new(Some(HashMap::new()))),
            recorder,
        }
    }

    /// Sleep `ttl_ms` in a spawned task, then send `next` back into the kind's
    /// channel.
    fn schedule(&self, next: OutboundMessage, ttl_ms: u64) -> Result<(), NotScheduled> {
        let permit = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| NotScheduled::Capacity)?;
        let id = next.delivery_id;
        match self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
        {
            Some(sleeping) => sleeping.insert(id, next),
            None => return Err(NotScheduled::Stopped),
        };
        let tx = self.redispatch.clone();
        let pending = Arc::clone(&self.pending);
        let recorder = Arc::clone(&self.recorder);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(ttl_ms)).await;
            // A stop that came meanwhile took the entry and wrote its row.
            let due = pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_mut()
                .and_then(|sleeping| sleeping.remove(&id));
            if let Some(msg) = due {
                // `send` (not `try_send`): a full channel makes the retry wait
                // for room rather than lose it. The permit is held meanwhile, so
                // the number of such waiters stays bounded.
                if let Err(mpsc::error::SendError(msg)) = tx.send(msg).await {
                    abandon(Some(&recorder), &msg, STOPPED_REASON).await;
                }
            }
            drop(permit);
        });
        Ok(())
    }

    /// Mark the dispatcher stopped and hand back every retry still asleep.
    fn stop(&self) -> Vec<OutboundMessage> {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .map(|sleeping| sleeping.into_values().collect())
            .unwrap_or_default()
    }
}

async fn record<A: AuditSink + ?Sized>(audit: &A, entry: CreateAuditLogEntry) {
    let action = entry.action.clone();
    if let Err(e) = audit.record(entry).await {
        error!(error = %e, %action, "Failed to write outbound delivery audit event");
    }
}

/// Carry out the verdict of one attempt's `result`: the audit row, and what
/// becomes of the message (nothing, a delayed re-dispatch, or an end).
async fn conclude<A: AuditSink>(
    msg: OutboundMessage,
    result: Result<DeliveryOutcome, OutboundError>,
    audit: &A,
    retries: &RetryScheduler,
    cfg: &OutboundRetryConfig,
) {
    match outcome::decide(&msg, outcome::classify(result), cfg) {
        Verdict::Delivered { audit: entry } => record(audit, entry).await,
        Verdict::Retry {
            next,
            ttl_ms,
            audit: entry,
        } => match retries.schedule(next.clone(), ttl_ms) {
            Ok(()) => record(audit, entry).await,
            Err(NotScheduled::Capacity) => {
                // No slot for another sleeping retry: say so, and stop.
                warn!(
                    kind = %msg.kind,
                    delivery_id = %msg.delivery_id,
                    "in-process outbound retry capacity exhausted; dead-lettering"
                );
                record(audit, outcome::failed_entry(&msg, RETRY_CAPACITY_REASON)).await;
            }
            Err(NotScheduled::Stopped) => {
                // The attempt ran and failed; the retry it earned never will.
                record(audit, entry).await;
                record(audit, outcome::abandoned_entry(&next, STOPPED_REASON)).await;
            }
        },
        // There is no dead-letter queue: the row is the whole record.
        Verdict::DeadLetter { audit: entry } => record(audit, entry).await,
    }
}

async fn run_in_process_consumer<A: AuditSink + 'static>(
    mut end: InProcessConsumerEnd,
    deliverer: Arc<dyn OutboundDeliverer>,
    audit: Arc<A>,
    cfg: OutboundRetryConfig,
    max_pending_retries: usize,
) {
    let kind = end.kind;
    let recorder: Arc<dyn AbandonRecorder> = Arc::new(SinkRecorder(Arc::clone(&audit)));
    // Until the audit middleware is bound, the publisher writes the row of a
    // refused enqueue through the same sink.
    let _ = end.recorder.set(Arc::clone(&recorder));
    let retries = RetryScheduler::new(
        end.redispatch.clone(),
        max_pending_retries,
        Arc::clone(&recorder),
    );
    info!(%kind, "Starting in-process outbound consumer");
    loop {
        let msg = tokio::select! {
            biased;
            () = stopped(&mut end.stop) => break,
            msg = end.receiver.recv() => match msg {
                Some(msg) => msg,
                None => break,
            },
        };
        // The attempt races the stop (after a short grace), so that a receiver
        // that never answers cannot hold back the account of what is queued.
        let result = tokio::select! {
            result = deliverer.deliver_attempt(&msg) => result,
            () = async {
                stopped(&mut end.stop).await;
                tokio::time::sleep(IN_FLIGHT_STOP_GRACE).await;
            } => {
                abandon(Some(&recorder), &msg, STOPPED_REASON).await;
                break;
            }
        };
        conclude(msg, result, audit.as_ref(), &retries, &cfg).await;
    }

    if !*end.stop.borrow() {
        // Unreachable while `redispatch` is held, which it is for the loop's
        // life; kept so a future change to that ownership is loud, not silent.
        warn!(%kind, "In-process outbound consumer stopped");
        return;
    }
    // An orderly stop: nothing more is attempted. Close the channel (a later
    // enqueue is refused and writes its own row), then account for everything
    // that was queued or asleep.
    end.receiver.close();
    let mut abandoned = 0usize;
    while let Ok(msg) = end.receiver.try_recv() {
        abandon(Some(&recorder), &msg, STOPPED_REASON).await;
        abandoned += 1;
    }
    for msg in retries.stop() {
        abandon(Some(&recorder), &msg, STOPPED_REASON).await;
        abandoned += 1;
    }
    info!(%kind, abandoned, "In-process outbound consumer stopped in order");
    let _ = end.done.send(());
}

/// Spawn the in-process consumer for one outbound kind.
///
/// Returns `Err(Unregistered)` — before spawning anything — when `deliverers`
/// has nothing for the end's kind, exactly as the AMQP consumer refuses.
/// `audit_repo` receives the same `<slug>.delivery_*` rows the AMQP loop writes,
/// and the `<slug>.delivery_abandoned` rows of a stop or a refused enqueue.
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
        Arc::new(audit),
        cfg,
        max_pending_retries,
    )))
}

#[cfg(test)]
mod tests {
    use super::super::outcome::table::{self, Shape};
    use super::*;

    /// Handle one message end to end: one attempt, then the verdict. The unit
    /// the table tests drive.
    async fn process_message<A: AuditSink>(
        msg: OutboundMessage,
        deliverer: &dyn OutboundDeliverer,
        audit: &A,
        retries: &RetryScheduler,
        cfg: &OutboundRetryConfig,
    ) {
        let result = deliverer.deliver_attempt(&msg).await;
        conclude(msg, result, audit, retries, cfg).await;
    }
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
        let (publisher, audit, handle, _hub) = started_in(8, kind, deliverer, cfg, pending);
        (publisher, audit, handle)
    }

    /// As [`started`], with the hub's channel `capacity`, and the hub kept so the
    /// test can stop it.
    fn started_in(
        capacity: usize,
        kind: OutboundKind,
        deliverer: Arc<dyn OutboundDeliverer>,
        cfg: OutboundRetryConfig,
        pending: usize,
    ) -> (
        InProcessOutboundPublisher,
        FakeAudit,
        JoinHandle<()>,
        InProcessOutbound,
    ) {
        let mut hub = InProcessOutbound::with_capacity(capacity);
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
        (publisher, audit, handle, hub)
    }

    /// Holds every attempt until the test releases it, so a message can be
    /// in flight while others queue behind it.
    struct Gated {
        kind: OutboundKind,
        started: AtomicU32,
        release: Semaphore,
    }
    impl Gated {
        fn new(kind: OutboundKind) -> Arc<Self> {
            Arc::new(Self {
                kind,
                started: AtomicU32::new(0),
                release: Semaphore::new(0),
            })
        }
    }
    impl OutboundDeliverer for Gated {
        fn kind(&self) -> OutboundKind {
            self.kind
        }
        fn deliver_attempt<'a>(
            &'a self,
            _msg: &'a OutboundMessage,
        ) -> OutboundFuture<'a, Result<DeliveryOutcome, OutboundError>> {
            self.started.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                self.release.acquire().await.unwrap().forget();
                delivered()
            })
        }
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

    /// The `delivery_abandoned` rows of `audit`, as (resource, metadata).
    fn abandoned_rows(audit: &FakeAudit, slug: &str) -> Vec<CreateAuditLogEntry> {
        audit
            .entries()
            .into_iter()
            .filter(|e| e.action == format!("{slug}.delivery_abandoned"))
            .collect()
    }

    /// P23W5-A4: a stop with deliveries queued behind the one in flight writes
    /// one terminal row per lost delivery, with the fixed reason, and the
    /// in-flight one still gets its own verdict.
    #[tokio::test]
    async fn stopping_with_queued_deliveries_writes_one_abandoned_row_per_lost_delivery() {
        let gate = Gated::new(OutboundKind::Webhook);
        let (publisher, audit, handle, mut hub) =
            started_in(8, OutboundKind::Webhook, gate.clone(), FAST, 8);
        let shutdown = hub.shutdown();

        let first = table::message(OutboundKind::Webhook, 0);
        publisher.enqueue(&first).await.unwrap();
        wait_for("the first attempt", || {
            gate.started.load(Ordering::SeqCst) == 1
        })
        .await;
        let queued: Vec<_> = (0..3)
            .map(|_| table::message(OutboundKind::Webhook, 0))
            .collect();
        for msg in &queued {
            publisher.enqueue(msg).await.unwrap();
        }

        let stopping = tokio::spawn(shutdown.stop(Duration::from_secs(5)));
        // The stop waits for the attempt in flight; let it finish.
        tokio::time::sleep(Duration::from_millis(20)).await;
        gate.release.add_permits(1);
        assert!(
            stopping.await.unwrap().is_empty(),
            "every consumer finished"
        );
        handle.await.unwrap();

        let rows = abandoned_rows(&audit, "webhook");
        assert_eq!(rows.len(), 3, "one per lost delivery: {rows:?}");
        let mut lost: Vec<_> = rows.iter().map(|r| r.resource_id.unwrap()).collect();
        let mut want: Vec<_> = queued.iter().map(|m| m.target_id).collect();
        lost.sort();
        want.sort();
        assert_eq!(lost, want);
        for row in &rows {
            assert!(matches!(row.outcome, AuditOutcome::Failure));
            assert_eq!(row.metadata.as_ref().unwrap()["reason"], STOPPED_REASON);
            assert_eq!(row.metadata.as_ref().unwrap()["attempts_made"], 0);
        }
        // The delivery in flight at the stop was not lost: it has its verdict,
        // and nothing else wrote a terminal row for it.
        let succeeded: Vec<_> = audit
            .entries()
            .into_iter()
            .filter(|e| e.action == "webhook.delivery_succeeded")
            .collect();
        assert_eq!(succeeded.len(), 1);
        assert_eq!(succeeded[0].resource_id, Some(first.target_id));
        assert_eq!(audit.entries().len(), 4);
    }

    /// A receiver that never answers cannot hold back the account of what is
    /// queued behind it: past the grace the attempt in flight is cancelled and
    /// abandoned like the rest, and the stop finishes inside its deadline.
    #[tokio::test]
    async fn an_attempt_that_outlives_the_grace_is_abandoned_with_the_queue() {
        let gate = Gated::new(OutboundKind::CibaPing);
        let (publisher, audit, handle, mut hub) =
            started_in(8, OutboundKind::CibaPing, gate.clone(), FAST, 8);
        let shutdown = hub.shutdown();

        let stuck = table::message(OutboundKind::CibaPing, 0);
        publisher.enqueue(&stuck).await.unwrap();
        wait_for("the attempt", || gate.started.load(Ordering::SeqCst) == 1).await;
        let queued = table::message(OutboundKind::CibaPing, 0);
        publisher.enqueue(&queued).await.unwrap();

        // Never released: only the grace ends the attempt.
        let unfinished = shutdown
            .stop(IN_FLIGHT_STOP_GRACE + Duration::from_secs(5))
            .await;
        assert!(unfinished.is_empty());
        handle.await.unwrap();

        let rows = abandoned_rows(&audit, "ciba_ping");
        let mut lost: Vec<_> = rows.iter().map(|r| r.resource_id.unwrap()).collect();
        let mut want = vec![stuck.target_id, queued.target_id];
        lost.sort();
        want.sort();
        assert_eq!(lost, want, "the stuck attempt and the one queued behind it");
        assert_eq!(audit.entries().len(), 2, "no verdict was invented");
    }

    /// A retry asleep at the stop is accounted for too, with the attempts it had
    /// already used, and never fires afterwards.
    #[tokio::test]
    async fn stopping_with_a_retry_waiting_writes_an_abandoned_row_and_never_retries() {
        let deliverer = Arc::new(Scripted::new(OutboundKind::SsfPush, vec![retry("down")]));
        let slow = OutboundRetryConfig {
            max_attempts: 5,
            backoff_base_ms: 60_000,
            backoff_ceiling_ms: 60_000,
        };
        let (publisher, audit, handle, mut hub) =
            started_in(8, OutboundKind::SsfPush, deliverer.clone(), slow, 8);
        let shutdown = hub.shutdown();

        let msg = table::message(OutboundKind::SsfPush, 0);
        publisher.enqueue(&msg).await.unwrap();
        wait_for("the attempt row", || audit.entries().len() == 1).await;

        assert!(shutdown.stop(Duration::from_secs(5)).await.is_empty());
        handle.await.unwrap();

        let rows = abandoned_rows(&audit, "ssf_push");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].resource_id, Some(msg.target_id));
        assert_eq!(
            rows[0].metadata,
            Some(serde_json::json!({
                "delivery_id": msg.delivery_id,
                "attempts_made": 1,
                "reason": STOPPED_REASON,
            }))
        );
        assert_eq!(deliverer.calls.load(Ordering::SeqCst), 1);
    }

    /// A retry earned by an attempt that finished once the scheduler had stopped
    /// is abandoned too: the attempt row, then the abandoned row, in that order.
    #[tokio::test]
    async fn a_retry_earned_by_the_attempt_in_flight_at_the_stop_is_abandoned() {
        let audit = FakeAudit::default();
        // The scheduler is stopped (as the consumer does at an orderly stop)
        // before the verdict of an attempt arrives.
        let (tx, _rx) = mpsc::channel(8);
        let retries = RetryScheduler::new(tx, 8, Arc::new(SinkRecorder(Arc::new(audit.clone()))));
        assert!(retries.stop().is_empty());
        let scripted = Scripted::new(OutboundKind::CibaPing, vec![retry("down")]);
        let msg = table::message(OutboundKind::CibaPing, 0);
        process_message(msg.clone(), &scripted, &audit, &retries, &FAST).await;

        let actions: Vec<_> = audit.entries().into_iter().map(|e| e.action).collect();
        assert_eq!(
            actions,
            ["ciba_ping.delivery_attempt", "ciba_ping.delivery_abandoned"]
        );
        assert_eq!(
            audit.entries()[1].metadata.as_ref().unwrap()["attempts_made"],
            1
        );
    }

    /// P23W5-A4: an enqueue the full channel refuses writes one row and still
    /// returns the error the producers log.
    #[tokio::test]
    async fn a_refused_enqueue_writes_one_abandoned_row() {
        let gate = Gated::new(OutboundKind::ScimPush);
        let (publisher, audit, _h, _hub) =
            started_in(1, OutboundKind::ScimPush, gate.clone(), FAST, 8);

        publisher
            .enqueue(&table::message(OutboundKind::ScimPush, 0))
            .await
            .unwrap();
        wait_for("the first attempt", || {
            gate.started.load(Ordering::SeqCst) == 1
        })
        .await;
        publisher
            .enqueue(&table::message(OutboundKind::ScimPush, 0))
            .await
            .unwrap();
        assert!(abandoned_rows(&audit, "scim_push").is_empty());

        let refused = table::message(OutboundKind::ScimPush, 0);
        let err = publisher.enqueue(&refused).await.unwrap_err();
        assert!(matches!(err, OutboundError::Enqueue(_)), "{err:?}");

        let rows = abandoned_rows(&audit, "scim_push");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].resource_id, Some(refused.target_id));
        assert_eq!(rows[0].tenant_id, refused.tenant_id);
        assert_eq!(
            rows[0].metadata.as_ref().unwrap()["reason"],
            QUEUE_FULL_REASON
        );
        assert_eq!(
            rows[0].metadata.as_ref().unwrap()["delivery_id"],
            serde_json::json!(refused.delivery_id)
        );
    }

    /// A datastore for the audit middleware: takes `delay` over each append and
    /// keeps what it took.
    #[derive(Clone)]
    struct Datastore {
        delay: Duration,
        rows: Arc<Mutex<Vec<CreateAuditLogEntry>>>,
    }
    impl Datastore {
        fn new(delay: Duration) -> Self {
            Self {
                delay,
                rows: Arc::default(),
            }
        }
        fn rows(&self) -> Vec<CreateAuditLogEntry> {
            self.rows.lock().unwrap().clone()
        }
    }
    impl AuditLogRepository for Datastore {
        async fn append(
            &self,
            input: CreateAuditLogEntry,
        ) -> axiam_core::error::AxiamResult<axiam_core::models::audit::AuditLogEntry> {
            tokio::time::sleep(self.delay).await;
            self.rows.lock().unwrap().push(input.clone());
            Ok(axiam_core::models::audit::AuditLogEntry {
                id: Uuid::new_v4(),
                tenant_id: input.tenant_id,
                actor_id: input.actor_id,
                actor_type: input.actor_type,
                action: input.action,
                resource_id: input.resource_id,
                outcome: input.outcome,
                ip_address: input.ip_address,
                metadata: input.metadata.unwrap_or(serde_json::Value::Null),
                timestamp: chrono::Utc::now(),
            })
        }
        async fn list(
            &self,
            _: Uuid,
            _: axiam_core::repository::AuditLogFilter,
            _: axiam_core::repository::Pagination,
        ) -> axiam_core::error::AxiamResult<
            axiam_core::repository::PaginatedResult<axiam_core::models::audit::AuditLogEntry>,
        > {
            unimplemented!()
        }
        async fn list_system(
            &self,
            _: axiam_core::repository::AuditLogFilter,
            _: axiam_core::repository::Pagination,
        ) -> axiam_core::error::AxiamResult<
            axiam_core::repository::PaginatedResult<axiam_core::models::audit::AuditLogEntry>,
        > {
            unimplemented!()
        }
        async fn get_by_ids(
            &self,
            _: Uuid,
            _: &[Uuid],
        ) -> axiam_core::error::AxiamResult<Vec<axiam_core::models::audit::AuditLogEntry>> {
            unimplemented!()
        }
        async fn pseudonymize_actor(
            &self,
            _: Uuid,
            _: Uuid,
            _: &str,
        ) -> axiam_core::error::AxiamResult<u64> {
            unimplemented!()
        }
        async fn prune_older_than(
            &self,
            _: chrono::DateTime<chrono::Utc>,
        ) -> axiam_core::error::AxiamResult<u64> {
            unimplemented!()
        }
    }

    /// #596: with the audit middleware bound, a refused enqueue hands its row to
    /// the middleware's queue; the consumer's own sink (the datastore the producer
    /// would have waited on) is not touched.
    #[tokio::test]
    async fn a_refused_enqueue_is_recorded_through_the_audit_middleware() {
        let gate = Gated::new(OutboundKind::ScimPush);
        let (publisher, sink, _h, hub) =
            started_in(1, OutboundKind::ScimPush, gate.clone(), FAST, 8);
        let store = Datastore::new(Duration::ZERO);
        let mw = AuditMiddleware::spawn(store.clone());
        assert!(hub.bind_audit(mw.clone()));
        assert!(!hub.bind_audit(mw.clone()), "bound once");

        publisher
            .enqueue(&table::message(OutboundKind::ScimPush, 0))
            .await
            .unwrap();
        wait_for("the first attempt", || {
            gate.started.load(Ordering::SeqCst) == 1
        })
        .await;
        publisher
            .enqueue(&table::message(OutboundKind::ScimPush, 0))
            .await
            .unwrap();
        let refused = table::message(OutboundKind::ScimPush, 0);
        assert!(publisher.enqueue(&refused).await.is_err());

        wait_for("the row through the middleware", || store.rows().len() == 1).await;
        let row = &store.rows()[0];
        assert_eq!(row.action, "scim_push.delivery_abandoned");
        assert_eq!(row.resource_id, Some(refused.target_id));
        assert_eq!(row.metadata.as_ref().unwrap()["reason"], QUEUE_FULL_REASON);
        assert!(
            abandoned_rows(&sink, "scim_push").is_empty(),
            "the consumer's sink was not written on the producer's path"
        );
        assert_eq!(mw.loss().snapshot().dropped, 0);
    }

    /// #596: with the audit channel full and the datastore stuck, `enqueue`
    /// still returns its refusal at once and no datastore write happens on the
    /// producer's path. R101W4-06: the shed row is counted in its own counter,
    /// not as a dropped request row (until R101W4-01 it moved `dropped`).
    #[tokio::test]
    async fn a_refusal_with_the_audit_channel_full_writes_nothing_and_counts_the_shed_row() {
        let gate = Gated::new(OutboundKind::Webhook);
        let (publisher, sink, _h, hub) =
            started_in(1, OutboundKind::Webhook, gate.clone(), FAST, 8);
        // A datastore that never answers, and an audit channel of one behind it.
        let store = Datastore::new(Duration::from_secs(3600));
        let mw = AuditMiddleware::spawn_configured(
            store.clone(),
            None,
            axiam_audit::DeadLetterWriter::disabled(),
            1,
        );
        hub.bind_audit(mw.clone());
        let filler = || axiam_core::models::audit::CreateAuditLogEntry {
            tenant_id: Uuid::nil(),
            actor_id: Uuid::nil(),
            actor_type: axiam_core::models::audit::ActorType::System,
            action: "filler".into(),
            resource_id: None,
            outcome: AuditOutcome::Success,
            ip_address: None,
            metadata: None,
        };
        // The worker takes the first and sticks in its append; the second fills
        // the channel.
        assert!(mw.try_record(filler()));
        wait_for("the worker to take the first row", || {
            mw.try_record(filler())
        })
        .await;
        assert!(!mw.try_record(filler()), "the audit channel is full");
        let before = mw.loss().snapshot().outbound_abandoned_dropped;

        publisher
            .enqueue(&table::message(OutboundKind::Webhook, 0))
            .await
            .unwrap();
        wait_for("the first attempt", || {
            gate.started.load(Ordering::SeqCst) == 1
        })
        .await;
        publisher
            .enqueue(&table::message(OutboundKind::Webhook, 0))
            .await
            .unwrap();

        let refused = table::message(OutboundKind::Webhook, 0);
        let err = tokio::time::timeout(Duration::from_secs(5), publisher.enqueue(&refused))
            .await
            .expect("a refusal does not wait on the audit path")
            .unwrap_err();
        assert!(matches!(err, OutboundError::Enqueue(_)), "{err:?}");

        let s = mw.loss().snapshot();
        assert_eq!(
            s.outbound_abandoned_dropped,
            before + 1,
            "the shed count moved"
        );
        assert_eq!(s.dropped, 0, "not counted as a lost request row");
        assert!(store.rows().is_empty(), "no datastore write completed");
        assert!(
            abandoned_rows(&sink, "webhook").is_empty(),
            "and none went through the consumer's sink"
        );
    }

    /// R101W4-01: what a bulk producer held back after a refusal is one
    /// `delivery_abandoned` row carrying the count and the queue-full reason;
    /// zero held back is no row.
    #[tokio::test]
    async fn the_messages_a_bulk_producer_held_back_are_one_row_with_the_count() {
        let gate = Gated::new(OutboundKind::ScimPush);
        let (publisher, audit, _h, _hub) =
            started_in(1, OutboundKind::ScimPush, gate.clone(), FAST, 8);
        let (tenant_id, target_id) = (Uuid::new_v4(), Uuid::new_v4());
        // The consumer has started (and registered its sink) once it attempts.
        publisher
            .enqueue(&table::message(OutboundKind::ScimPush, 0))
            .await
            .unwrap();
        wait_for("the first attempt", || {
            gate.started.load(Ordering::SeqCst) == 1
        })
        .await;

        publisher
            .record_not_offered(OutboundKind::ScimPush, tenant_id, target_id, 0)
            .await;
        assert!(abandoned_rows(&audit, "scim_push").is_empty());

        publisher
            .record_not_offered(OutboundKind::ScimPush, tenant_id, target_id, 8_976)
            .await;
        let rows = abandoned_rows(&audit, "scim_push");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tenant_id, tenant_id);
        assert_eq!(rows[0].resource_id, Some(target_id));
        assert!(matches!(rows[0].outcome, AuditOutcome::Failure));
        let metadata = rows[0].metadata.as_ref().unwrap();
        assert_eq!(metadata["reason"], QUEUE_FULL_REASON);
        assert_eq!(metadata["refused_count"], 8_976);
        assert_eq!(metadata["attempts_made"], 0);
        assert!(metadata.get("delivery_id").is_none(), "it stands for many");
    }

    /// R101W4-01, the review's probe kept as a regression test: a SCIM queue of
    /// one slot held by a gated deliverer (a consumer that never keeps up), the
    /// audit middleware at its production capacity over a datastore that takes
    /// 1 ms per append, then 10 000 enqueues in a loop that does **not** stop at
    /// the first refusal (the worst case; the SCIM producers now do stop), then
    /// 100 request rows through the real middleware. Every enqueue is refused
    /// and leaves its row to `try_record`, which stops at the request rows'
    /// reserve: all 100 request rows are queued and nothing is dead-lettered.
    /// Before the reserve: 4 096 refusal rows queued, 5 904 dropped and
    /// dead-lettered, then 100 of 100 request rows dropped.
    #[actix_web::test]
    async fn a_refusal_burst_leaves_the_audit_reserve_to_request_rows() {
        use actix_web::{App, HttpResponse, test, web};
        use axiam_audit::middleware::{CHANNEL_CAPACITY, REQUEST_RESERVE};
        const ENQUEUES: usize = 10_000;
        const REQUEST_ROWS: usize = 100;

        let gate = Gated::new(OutboundKind::ScimPush);
        let (publisher, sink, _h, hub) =
            started_in(1, OutboundKind::ScimPush, gate.clone(), FAST, 8);
        let store = Datastore::new(Duration::from_millis(1));
        let path = std::env::temp_dir().join(format!("axiam-r101w4-01-{}.jsonl", Uuid::new_v4()));
        let mw = AuditMiddleware::spawn_configured(
            store.clone(),
            None,
            axiam_audit::DeadLetterWriter::spawn(&path),
            CHANNEL_CAPACITY,
        );
        assert!(hub.bind_audit(mw.clone()));

        // The deliverer holds the first message; the second fills the slot.
        publisher
            .enqueue(&table::message(OutboundKind::ScimPush, 0))
            .await
            .unwrap();
        wait_for("the first attempt", || {
            gate.started.load(Ordering::SeqCst) == 1
        })
        .await;
        publisher
            .enqueue(&table::message(OutboundKind::ScimPush, 0))
            .await
            .unwrap();

        let mut refused = 0usize;
        for _ in 0..ENQUEUES {
            if publisher
                .enqueue(&table::message(OutboundKind::ScimPush, 0))
                .await
                .is_err()
            {
                refused += 1;
            }
        }
        assert_eq!(refused, ENQUEUES);
        let s = mw.loss().snapshot();
        assert_eq!(s.dropped, 0, "no refusal row counts as a request row");
        assert!(
            s.outbound_abandoned_dropped
                >= (ENQUEUES - (CHANNEL_CAPACITY - REQUEST_RESERVE)) as u64,
            "the refusal rows stopped at the reserve: {} shed",
            s.outbound_abandoned_dropped
        );

        let app = test::init_service(App::new().wrap(mw.clone()).route(
            "/api/thing",
            web::get().to(|| async { HttpResponse::Ok().finish() }),
        ))
        .await;
        for _ in 0..REQUEST_ROWS {
            let req = test::TestRequest::get().uri("/api/thing").to_request();
            assert!(test::call_service(&app, req).await.status().is_success());
        }
        let loss = mw.loss();
        assert!(loss.dead_letter().flush(Duration::from_secs(10)).await);
        let s = loss.snapshot();
        assert_eq!(s.dropped, 0, "all {REQUEST_ROWS} request rows were queued");
        let lines = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            lines.lines().count() <= 1,
            "at most one dead-letter line for the run"
        );
        assert!(
            abandoned_rows(&sink, "scim_push").is_empty(),
            "the consumer's sink was not written on the producer's path"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The first refusal is logged at once; the rest inside the interval are
    /// counted, and the next line carries how many were suppressed.
    #[test]
    fn the_refusal_warn_is_rate_limited_to_one_line_per_interval() {
        let log = RefusalLog::default();
        let t0 = Instant::now();
        let first = log.note(t0).expect("the first refusal logs at once");
        assert_eq!((first.total, first.suppressed), (1, 0));
        for i in 1..=5 {
            assert!(log.note(t0 + Duration::from_secs(i)).is_none());
        }
        assert!(
            log.note(t0 + REFUSAL_REPORT_INTERVAL - Duration::from_millis(1))
                .is_none()
        );
        let next = log
            .note(t0 + REFUSAL_REPORT_INTERVAL)
            .expect("a line after the interval");
        assert_eq!(
            (next.total, next.suppressed),
            (8, 6),
            "six refusals were suppressed since the first line, this one not among them"
        );
        assert!(log.note(t0 + REFUSAL_REPORT_INTERVAL).is_none());
    }

    /// An enqueue after the stop finds the channel closed, and writes its row.
    #[tokio::test]
    async fn an_enqueue_after_the_stop_is_refused_and_leaves_a_row() {
        let deliverer = Arc::new(Scripted::new(OutboundKind::Webhook, vec![delivered()]));
        let (publisher, audit, handle, mut hub) =
            started_in(8, OutboundKind::Webhook, deliverer, FAST, 8);
        assert!(hub.shutdown().stop(Duration::from_secs(5)).await.is_empty());
        handle.await.unwrap();

        let late = table::message(OutboundKind::Webhook, 0);
        assert!(publisher.enqueue(&late).await.is_err());
        let rows = abandoned_rows(&audit, "webhook");
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].metadata.as_ref().unwrap()["reason"],
            NOT_RUNNING_REASON
        );
    }

    /// A consumer that has not finished by the deadline is reported, not waited
    /// for: the stop is bounded.
    #[tokio::test]
    async fn the_stop_is_bounded_when_an_attempt_never_finishes() {
        let gate = Gated::new(OutboundKind::Webhook);
        let (publisher, _audit, _h, mut hub) =
            started_in(8, OutboundKind::Webhook, gate.clone(), FAST, 8);
        publisher
            .enqueue(&table::message(OutboundKind::Webhook, 0))
            .await
            .unwrap();
        wait_for("the attempt", || gate.started.load(Ordering::SeqCst) == 1).await;
        // A deadline inside the grace: the consumer is still waiting on the attempt.
        let unfinished = hub.shutdown().stop(Duration::from_millis(50)).await;
        assert_eq!(unfinished, [OutboundKind::Webhook]);
    }

    /// A refusal before any consumer registered a sink has nowhere to write; it
    /// is still an error, as before.
    #[tokio::test]
    async fn a_refusal_without_a_consumer_is_still_an_error() {
        let hub = InProcessOutbound::with_capacity(1);
        let publisher = hub.publisher();
        publisher
            .enqueue(&table::message(OutboundKind::Webhook, 0))
            .await
            .unwrap();
        assert!(
            publisher
                .enqueue(&table::message(OutboundKind::Webhook, 0))
                .await
                .is_err()
        );
    }

    // -------------------------------------------------------------------
    // R101-01: the paced enqueue of a bulk producer off the request path
    // -------------------------------------------------------------------

    fn never_stop() -> bool {
        false
    }

    /// A paced offer is taken while more than a quarter of the channel is free,
    /// then waits — leaving that quarter to producers that do not wait — and is
    /// taken as soon as the consumer makes room.
    #[tokio::test]
    async fn a_paced_enqueue_leaves_the_reserve_and_waits_for_room() {
        let mut hub = InProcessOutbound::with_capacity(4);
        let publisher = hub.publisher();
        let mut end = hub.take_consumer_end(OutboundKind::ScimPush).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        for _ in 0..3 {
            publisher
                .enqueue_paced(
                    &table::message(OutboundKind::ScimPush, 0),
                    deadline,
                    &never_stop,
                )
                .await
                .unwrap();
        }

        let waiting = {
            let publisher = publisher.clone();
            tokio::spawn(async move {
                publisher
                    .enqueue_paced(
                        &table::message(OutboundKind::ScimPush, 0),
                        deadline,
                        &never_stop,
                    )
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiting.is_finished(), "the fourth paced offer waits");
        // The reserve is a producer's that does not wait.
        publisher
            .enqueue(&table::message(OutboundKind::ScimPush, 0))
            .await
            .unwrap();

        // The consumer takes two: two slots free, more than the reserve.
        end.receiver.recv().await.unwrap();
        end.receiver.recv().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), waiting)
            .await
            .expect("taken once there is room")
            .unwrap()
            .unwrap();
    }

    /// #598: a stop request ends a paced wait within a poll, far inside the
    /// cleanup task's stop bound, and the offer is refused as a full queue's.
    #[tokio::test]
    async fn a_stop_request_ends_a_paced_wait_promptly() {
        let gate = Gated::new(OutboundKind::ScimPush);
        let (publisher, audit, _h, _hub) =
            started_in(1, OutboundKind::ScimPush, gate.clone(), FAST, 8);
        publisher
            .enqueue(&table::message(OutboundKind::ScimPush, 0))
            .await
            .unwrap();
        wait_for("the first attempt", || {
            gate.started.load(Ordering::SeqCst) == 1
        })
        .await;
        publisher
            .enqueue(&table::message(OutboundKind::ScimPush, 0))
            .await
            .unwrap();

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let stop = Arc::clone(&stop);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                stop.store(true, Ordering::SeqCst);
            });
        }
        let should_stop = {
            let stop = Arc::clone(&stop);
            move || stop.load(Ordering::SeqCst)
        };
        let refused = table::message(OutboundKind::ScimPush, 0);
        let began = Instant::now();
        let err = publisher
            .enqueue_paced(
                &refused,
                std::time::Instant::now() + Duration::from_secs(60),
                &should_stop,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, OutboundError::Enqueue(_)), "{err:?}");
        assert!(
            began.elapsed() < Duration::from_secs(1),
            "the wait ended at the stop, not at its deadline: {:?}",
            began.elapsed()
        );
        let rows = abandoned_rows(&audit, "scim_push");
        assert_eq!(rows.len(), 1, "one row, as a refused enqueue writes");
        assert_eq!(
            rows[0].metadata.as_ref().unwrap()["delivery_id"],
            serde_json::json!(refused.delivery_id)
        );
        assert_eq!(
            rows[0].metadata.as_ref().unwrap()["reason"],
            QUEUE_FULL_REASON
        );
        gate.release.add_permits(8);
    }

    /// A paced wait ends at its deadline; and the dispatcher's own stop, which
    /// closes the channel, ends one at once with the not-running reason.
    #[tokio::test]
    async fn a_paced_wait_ends_at_its_deadline_and_when_the_dispatcher_stops() {
        let gate = Gated::new(OutboundKind::ScimPush);
        let (publisher, audit, _h, mut hub) =
            started_in(1, OutboundKind::ScimPush, gate.clone(), FAST, 8);
        publisher
            .enqueue(&table::message(OutboundKind::ScimPush, 0))
            .await
            .unwrap();
        wait_for("the first attempt", || {
            gate.started.load(Ordering::SeqCst) == 1
        })
        .await;
        publisher
            .enqueue(&table::message(OutboundKind::ScimPush, 0))
            .await
            .unwrap();

        let began = Instant::now();
        assert!(
            publisher
                .enqueue_paced(
                    &table::message(OutboundKind::ScimPush, 0),
                    std::time::Instant::now() + Duration::from_millis(100),
                    &never_stop,
                )
                .await
                .is_err()
        );
        let waited = began.elapsed();
        assert!(
            waited >= Duration::from_millis(90) && waited < Duration::from_secs(2),
            "{waited:?}"
        );

        let waiting = {
            let publisher = publisher.clone();
            tokio::spawn(async move {
                publisher
                    .enqueue_paced(
                        &table::message(OutboundKind::ScimPush, 0),
                        std::time::Instant::now() + Duration::from_secs(60),
                        &never_stop,
                    )
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!waiting.is_finished());
        let began = Instant::now();
        // The attempt in flight is abandoned after the grace; the channel closes.
        assert!(hub.shutdown().stop(Duration::from_secs(5)).await.is_empty());
        assert!(
            tokio::time::timeout(Duration::from_secs(1), waiting)
                .await
                .expect("ended by the closed channel")
                .unwrap()
                .is_err()
        );
        assert!(began.elapsed() < IN_FLIGHT_STOP_GRACE + Duration::from_secs(1));
        let reasons: Vec<_> = abandoned_rows(&audit, "scim_push")
            .into_iter()
            .map(|row| row.metadata.unwrap()["reason"].clone())
            .collect();
        assert_eq!(reasons.first().unwrap(), QUEUE_FULL_REASON, "the deadline");
        assert_eq!(
            reasons.iter().filter(|r| *r == NOT_RUNNING_REASON).count(),
            1,
            "the wait the stop ended: {reasons:?}"
        );
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
                let retries =
                    RetryScheduler::new(tx, 8, Arc::new(SinkRecorder(Arc::new(audit.clone()))));
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
