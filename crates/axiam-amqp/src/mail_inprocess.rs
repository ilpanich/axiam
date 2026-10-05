//! In-process transactional mail for the minimal profile (`AXIAM__AMQP__ENABLED=false`,
//! G-8, D-59).
//!
//! The AMQP profile publishes an [`OutboundMailMessage`] to `axiam.mail.outbound`
//! and `start_mail_consumer` sends it. Without a broker the same two roles run in
//! one process on a bounded channel:
//!
//! * [`InProcessMailPublisher`] implements the core `MailPublisher` port over a
//!   `tokio::mpsc` channel of [`MAIL_CHANNEL_CAPACITY`] messages. A full channel
//!   is an error, which every caller already logs and swallows
//!   (`MailPublisher::publish` is fire-and-forget at the call site).
//! * [`spawn_in_process_mail_worker`] takes messages off it and runs the
//!   broker-free [`send_with_retry_and_audit`] — the very function the AMQP
//!   consumer calls — so recipient resolution (SEC-055), template resolution,
//!   rendering, the retry count ([`MAX_RETRIES`]) and the PII-minimal
//!   `email.delivery_failed` audit row (D-16) are identical by construction.
//!
//! Where the AMQP consumer sleeps and republishes, the worker schedules a
//! delayed re-dispatch (a spawned task that sleeps the same exponential
//! backoff, bounded by [`MAIL_MAX_PENDING_RETRIES`]).
//!
//! **Queued mail and sleeping retries are lost on restart** — the profile's
//! recorded trade; there is no dead-letter queue, so an exhausted message's
//! `email.delivery_failed` row is the whole record.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::mail::OutboundMailMessage;
use axiam_core::repository::{
    AuditLogRepository, EmailConfigRepository, EmailTemplateRepository, MailPublisher,
    OrganizationRepository, TenantRepository, UserRepository,
};

use crate::mail_consumer::{SendError, SendOutcome, default_retry_delay, send_with_retry_and_audit};

/// Messages the channel holds before a publish is refused.
pub const MAIL_CHANNEL_CAPACITY: usize = 1_024;

/// Retries that may be sleeping at once; a retry beyond it is given up on, with
/// the same audit row an exhausted message gets.
pub const MAIL_MAX_PENDING_RETRIES: usize = 1_024;

/// `error_class` of the audit row for a retry that found no free slot.
pub const MAIL_RETRY_CAPACITY_CLASS: &str = "retry_capacity_exhausted";

/// `MailPublisher` over a bounded channel.
#[derive(Clone)]
pub struct InProcessMailPublisher {
    /// `None` when no worker will ever run (no email encryption key): a publish
    /// then fails at once and says why, instead of filling a channel nobody
    /// reads.
    tx: Option<mpsc::Sender<OutboundMailMessage>>,
}

impl InProcessMailPublisher {
    /// A publisher with no worker behind it. Every publish is refused.
    pub fn disabled() -> Self {
        Self { tx: None }
    }
}

impl MailPublisher for InProcessMailPublisher {
    async fn publish(&self, msg: OutboundMailMessage) -> AxiamResult<()> {
        let Some(tx) = &self.tx else {
            return Err(AxiamError::Internal(
                "in-process mail is not running: AXIAM__AUTH__EMAIL_ENCRYPTION_KEY is not set"
                    .into(),
            ));
        };
        tx.try_send(msg).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => AxiamError::Internal(format!(
                "in-process mail queue is full ({} messages)",
                tx.max_capacity()
            )),
            mpsc::error::TrySendError::Closed(_) => {
                AxiamError::Internal("in-process mail worker is not running".into())
            }
        })
    }
}

/// The worker's end of the channel. Handed to [`spawn_in_process_mail_worker`].
pub struct InProcessMailQueue {
    rx: mpsc::Receiver<OutboundMailMessage>,
    redispatch: mpsc::Sender<OutboundMailMessage>,
}

/// A publisher and the queue its worker consumes.
pub fn in_process_mail_channel() -> (InProcessMailPublisher, InProcessMailQueue) {
    in_process_mail_channel_with_capacity(MAIL_CHANNEL_CAPACITY)
}

/// As [`in_process_mail_channel`] with an explicit capacity (tests).
pub fn in_process_mail_channel_with_capacity(
    capacity: usize,
) -> (InProcessMailPublisher, InProcessMailQueue) {
    let (tx, rx) = mpsc::channel(capacity.max(1));
    (
        InProcessMailPublisher {
            tx: Some(tx.clone()),
        },
        InProcessMailQueue {
            rx,
            redispatch: tx,
        },
    )
}

/// What the worker does with one message. A seam: production sends mail,
/// tests script the outcomes.
trait MailAttempt: Send + Sync + 'static {
    /// One attempt, the broker-free core shared with the AMQP consumer.
    fn attempt(
        &self,
        msg: &OutboundMailMessage,
    ) -> impl Future<Output = Result<SendOutcome, SendError>> + Send;

    /// Give up on a message for a reason of the worker's own (no retry slot):
    /// the same `email.delivery_failed` row an exhausted message gets.
    fn give_up(
        &self,
        msg: &OutboundMailMessage,
        error_class: &'static str,
    ) -> impl Future<Output = ()> + Send;
}

struct Repos<E, A, U, T, N, O> {
    email_config: E,
    audit: A,
    user: U,
    template: T,
    tenant: N,
    org: O,
}

impl<E, A, U, T, N, O> MailAttempt for Repos<E, A, U, T, N, O>
where
    E: EmailConfigRepository + 'static,
    A: AuditLogRepository + 'static,
    U: UserRepository + 'static,
    T: EmailTemplateRepository + 'static,
    N: TenantRepository + 'static,
    O: OrganizationRepository + 'static,
{
    async fn attempt(&self, msg: &OutboundMailMessage) -> Result<SendOutcome, SendError> {
        send_with_retry_and_audit(
            msg,
            &self.email_config,
            &self.audit,
            &self.user,
            &self.template,
            &self.tenant,
            &self.org,
        )
        .await
    }

    async fn give_up(&self, msg: &OutboundMailMessage, error_class: &'static str) {
        // D-16: no recipient address, no raw PII.
        let entry = CreateAuditLogEntry {
            tenant_id: msg.tenant_id,
            actor_id: msg.user_id,
            actor_type: ActorType::System,
            action: "email.delivery_failed".into(),
            resource_id: None,
            outcome: AuditOutcome::Failure,
            ip_address: None,
            metadata: Some(serde_json::json!({
                "provider": null,
                "error_class": error_class,
                "attempt_count": msg.attempt_count,
                "next_retry_at": null,
                "mail_type": format!("{:?}", msg.mail_type),
            })),
        };
        if let Err(e) = self.audit.append(entry).await {
            error!(error = %e, "failed to write email.delivery_failed audit event");
        }
    }
}

type RetryDelay = Arc<dyn Fn(u32) -> Duration + Send + Sync>;

async fn run_mail_worker<M: MailAttempt>(
    mut queue: InProcessMailQueue,
    attempts: Arc<M>,
    retry_delay: RetryDelay,
    max_pending_retries: usize,
) {
    let slots = Arc::new(Semaphore::new(max_pending_retries.max(1)));
    info!("Starting in-process mail worker");
    while let Some(msg) = queue.rx.recv().await {
        match attempts.attempt(&msg).await {
            // Delivered; or retries exhausted, with the audit row already
            // written inside `send_with_retry_and_audit`.
            Ok(SendOutcome::Delivered) | Ok(SendOutcome::Exhausted) => {}
            Ok(SendOutcome::RetryNeeded { .. }) => {
                let mut retry = msg.clone();
                retry.attempt_count += 1;
                let delay = retry_delay(retry.attempt_count);
                match Arc::clone(&slots).try_acquire_owned() {
                    Ok(permit) => {
                        info!(
                            attempt = retry.attempt_count,
                            delay_secs = delay.as_secs_f64(),
                            "Backing off before in-process mail retry"
                        );
                        let tx = queue.redispatch.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(delay).await;
                            if tx.send(retry).await.is_err() {
                                warn!("in-process mail worker stopped; a pending retry was dropped");
                            }
                            drop(permit);
                        });
                    }
                    Err(_) => {
                        error!("in-process mail retry capacity exhausted; giving up on a message");
                        attempts.give_up(&msg, MAIL_RETRY_CAPACITY_CLASS).await;
                    }
                }
            }
            // Config/infra error (no email config, disabled, ...): a retry
            // will not fix it. The AMQP consumer nacks without requeue.
            Err(e) => warn!(
                error = %e,
                mail_type = ?msg.mail_type,
                "Mail config/infra error - dropping without retry"
            ),
        }
    }
    warn!("In-process mail worker stopped");
}

/// Spawn the worker that delivers the queue's mail.
///
/// `retry_delay` maps the post-increment `attempt_count` of a retry to the wait
/// before it re-enters the queue; production passes
/// [`default_retry_delay`], the AMQP consumer's own schedule.
#[allow(clippy::too_many_arguments)]
pub fn spawn_in_process_mail_worker<E, A, U, T, N, O>(
    queue: InProcessMailQueue,
    email_config_repo: E,
    audit_repo: A,
    user_repo: U,
    template_repo: T,
    tenant_repo: N,
    org_repo: O,
    retry_delay: impl Fn(u32) -> Duration + Send + Sync + 'static,
) -> JoinHandle<()>
where
    E: EmailConfigRepository + 'static,
    A: AuditLogRepository + 'static,
    U: UserRepository + 'static,
    T: EmailTemplateRepository + 'static,
    N: TenantRepository + 'static,
    O: OrganizationRepository + 'static,
{
    tokio::spawn(run_mail_worker(
        queue,
        Arc::new(Repos {
            email_config: email_config_repo,
            audit: audit_repo,
            user: user_repo,
            template: template_repo,
            tenant: tenant_repo,
            org: org_repo,
        }),
        Arc::new(retry_delay),
        MAIL_MAX_PENDING_RETRIES,
    ))
}

/// [`spawn_in_process_mail_worker`] with the AMQP consumer's retry schedule.
#[allow(clippy::too_many_arguments)]
pub fn spawn_in_process_mail_worker_default<E, A, U, T, N, O>(
    queue: InProcessMailQueue,
    email_config_repo: E,
    audit_repo: A,
    user_repo: U,
    template_repo: T,
    tenant_repo: N,
    org_repo: O,
) -> JoinHandle<()>
where
    E: EmailConfigRepository + 'static,
    A: AuditLogRepository + 'static,
    U: UserRepository + 'static,
    T: EmailTemplateRepository + 'static,
    N: TenantRepository + 'static,
    O: OrganizationRepository + 'static,
{
    spawn_in_process_mail_worker(
        queue,
        email_config_repo,
        audit_repo,
        user_repo,
        template_repo,
        tenant_repo,
        org_repo,
        default_retry_delay,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::MailType;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    fn msg(attempt: u32) -> OutboundMailMessage {
        OutboundMailMessage {
            mail_type: MailType::PasswordReset,
            tenant_id: uuid::Uuid::new_v4(),
            org_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            to_address: "someone@example.com".into(),
            template_context: serde_json::json!({}),
            attempt_count: attempt,
            enqueued_at: chrono::Utc::now(),
        }
    }

    #[derive(Default)]
    struct Scripted {
        script: Mutex<VecDeque<Result<SendOutcome, SendError>>>,
        attempts: Mutex<Vec<u32>>,
        given_up: Mutex<Vec<&'static str>>,
    }
    impl Scripted {
        fn with(script: Vec<Result<SendOutcome, SendError>>) -> Arc<Self> {
            Arc::new(Self {
                script: Mutex::new(script.into()),
                ..Self::default()
            })
        }
    }
    impl MailAttempt for Scripted {
        fn attempt(
            &self,
            msg: &OutboundMailMessage,
        ) -> impl Future<Output = Result<SendOutcome, SendError>> + Send {
            self.attempts.lock().unwrap().push(msg.attempt_count);
            let next = self
                .script
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(SendOutcome::Delivered));
            async move { next }
        }
        fn give_up(
            &self,
            _msg: &OutboundMailMessage,
            error_class: &'static str,
        ) -> impl Future<Output = ()> + Send {
            self.given_up.lock().unwrap().push(error_class);
            async {}
        }
    }

    fn retry_needed() -> Result<SendOutcome, SendError> {
        Ok(SendOutcome::RetryNeeded {
            error_class: "provider_error".into(),
        })
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

    fn fast() -> RetryDelay {
        Arc::new(|_| Duration::from_millis(5))
    }

    #[tokio::test]
    async fn a_published_message_is_attempted_once() {
        let (publisher, queue) = in_process_mail_channel();
        let attempts = Scripted::with(vec![Ok(SendOutcome::Delivered)]);
        tokio::spawn(run_mail_worker(queue, attempts.clone(), fast(), 8));

        publisher.publish(msg(0)).await.unwrap();
        wait_for("the attempt", || attempts.attempts.lock().unwrap().len() == 1).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(*attempts.attempts.lock().unwrap(), [0]);
    }

    #[tokio::test]
    async fn a_retry_is_redispatched_with_an_incremented_attempt_count() {
        let (publisher, queue) = in_process_mail_channel();
        let attempts = Scripted::with(vec![
            retry_needed(),
            retry_needed(),
            Ok(SendOutcome::Delivered),
        ]);
        tokio::spawn(run_mail_worker(queue, attempts.clone(), fast(), 8));

        publisher.publish(msg(0)).await.unwrap();
        wait_for("three attempts", || {
            attempts.attempts.lock().unwrap().len() == 3
        })
        .await;
        assert_eq!(*attempts.attempts.lock().unwrap(), [0, 1, 2]);
    }

    #[tokio::test]
    async fn exhaustion_and_config_errors_end_the_message_without_a_retry() {
        let (publisher, queue) = in_process_mail_channel();
        let attempts = Scripted::with(vec![
            Ok(SendOutcome::Exhausted),
            Err(SendError("no email config for org/tenant".into())),
        ]);
        tokio::spawn(run_mail_worker(queue, attempts.clone(), fast(), 8));

        publisher.publish(msg(2)).await.unwrap();
        publisher.publish(msg(0)).await.unwrap();
        wait_for("both attempts", || {
            attempts.attempts.lock().unwrap().len() == 2
        })
        .await;
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(attempts.attempts.lock().unwrap().len(), 2, "no retry");
    }

    #[tokio::test]
    async fn a_retry_with_no_free_slot_is_given_up_on_with_a_stated_class() {
        let (publisher, queue) = in_process_mail_channel();
        let attempts = Scripted::with(vec![retry_needed(), retry_needed()]);
        // One slot, held by a long sleep.
        let slow: RetryDelay = Arc::new(|_| Duration::from_secs(60));
        tokio::spawn(run_mail_worker(queue, attempts.clone(), slow, 1));

        publisher.publish(msg(0)).await.unwrap();
        publisher.publish(msg(0)).await.unwrap();
        wait_for("the give-up", || {
            !attempts.given_up.lock().unwrap().is_empty()
        })
        .await;
        assert_eq!(
            *attempts.given_up.lock().unwrap(),
            [MAIL_RETRY_CAPACITY_CLASS]
        );
    }

    #[tokio::test]
    async fn a_full_channel_refuses_the_publish() {
        let (publisher, _queue) = in_process_mail_channel_with_capacity(2);
        publisher.publish(msg(0)).await.unwrap();
        publisher.publish(msg(0)).await.unwrap();
        assert!(publisher.publish(msg(0)).await.is_err());
    }

    #[tokio::test]
    async fn the_production_capacity_is_1024() {
        let (publisher, _queue) = in_process_mail_channel();
        for _ in 0..MAIL_CHANNEL_CAPACITY {
            publisher.publish(msg(0)).await.unwrap();
        }
        assert!(publisher.publish(msg(0)).await.is_err());
    }

    #[tokio::test]
    async fn a_disabled_publisher_refuses_and_names_the_missing_key() {
        let err = InProcessMailPublisher::disabled()
            .publish(msg(0))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("EMAIL_ENCRYPTION_KEY"), "{err}");
    }
}
