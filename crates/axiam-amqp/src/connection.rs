//! RabbitMQ connection management.

use lapin::options::{BasicQosOptions, ConfirmSelectOptions, QueueDeclareOptions};
use lapin::tcp::{OwnedIdentity, OwnedTLSConfig};
use lapin::types::FieldTable;
use lapin::{Channel, Connection, ConnectionProperties};
use tracing::{info, warn};

use crate::config::AmqpConfig;
use crate::error::AmqpError;

/// Read the configured TLS material off disk into lapin's owned TLS config
/// (A6).
///
/// Every read failure is reported with the path and the reason. A broker
/// connection that fails because a mount is missing looks identical to one
/// that fails because the broker is down, unless the error says which — and an
/// operator debugging a cert mount at 3am is exactly who this message is for.
///
/// # No protocol-version floor is set here, and none can be (SEC-106)
///
/// CLAUDE.md's standard is "TLS 1.3 minimum for all external communication",
/// and this connection crosses a service boundary by design. It is **not**
/// pinned to 1.3, and that is a limitation of the dependency rather than a
/// choice: lapin 4.10's only TLS-carrying entry point is
/// `Connection::connect_with_config(uri, props, OwnedTLSConfig, runtime)`, and
/// `OwnedTLSConfig` (`tcp-stream 0.34`) has exactly two fields — `identity`
/// and `cert_chain`. There is no seam for a rustls `ClientConfig`, so a client
/// -side floor would mean reimplementing `AMQPUriTcpExt::connect_with_config`
/// against `tcp_stream::TcpStream::into_rustls` and owning lapin's handshake
/// sequencing. rustls 0.23's default version set is TLS 1.2 + 1.3, so a broker
/// offering only 1.2 is currently accepted.
///
/// **Enforce the floor on the broker**, which is where it is enforceable for
/// this link and where it also covers every other AMQP client:
///
/// ```erlang
/// %% rabbitmq.conf / advanced.config
/// ssl_options.versions.1 = tlsv1.3
/// ```
///
/// `docs/deployment/README.md` states this as a MUST-level deployment
/// requirement. Revisit here if lapin gains a connector hook.
fn build_tls_config(config: &AmqpConfig) -> Result<OwnedTLSConfig, AmqpError> {
    let cert_chain = match &config.tls.ca_cert_path {
        Some(path) => Some(std::fs::read_to_string(path).map_err(|e| {
            AmqpError::Config(format!(
                "AMQP TLS: cannot read CA bundle at {path:?}: {e}. The broker certificate \
                 cannot be verified without it; connecting insecurely is not an option."
            ))
        })?),
        // System roots. Correct for a publicly-issued broker certificate, and
        // the reason a CA bundle is optional rather than required.
        None => None,
    };

    let identity = match (&config.tls.client_cert_path, &config.tls.client_key_path) {
        (Some(cert_path), Some(key_path)) => {
            let pem = std::fs::read(cert_path).map_err(|e| {
                AmqpError::Config(format!(
                    "AMQP TLS: cannot read client certificate at {cert_path:?}: {e}"
                ))
            })?;
            let key = std::fs::read(key_path).map_err(|e| {
                AmqpError::Config(format!(
                    "AMQP TLS: cannot read client key at {key_path:?}: {e}"
                ))
            })?;
            Some(OwnedIdentity::PKCS8 { pem, key })
        }
        // The mismatched cases are rejected by `AmqpTlsConfig::validate`,
        // which `validate_transport_security` runs before we get here.
        _ => None,
    };

    Ok(OwnedTLSConfig {
        identity,
        cert_chain,
    })
}

/// The `ConnectionProperties` every AXIAM AMQP connection is dialled with.
///
/// # Why `enable_auto_recover` rather than `default()`
///
/// Every long-lived consumer in `axiam-server` is supervised by the same shape
/// of loop: on failure, call [`AmqpManager::create_channel`] on the shared
/// manager and start again. The cache-invalidation consumer (§4.2), the
/// webhook consumer (CORR-03) and the X1 reactor transport's reply session all
/// do exactly this, and every one of them rebuilds a **channel** on an
/// existing **connection**.
///
/// That is the right recovery for the failure those loops were written for — a
/// channel-level exception closes one channel and leaves the connection up. It
/// does nothing at all for a broker restart. Under
/// `ConnectionProperties::default()` lapin does **not** reconnect (auto
/// recovery is off) and its TCP reconnect backoff is *zero retries*, so the
/// `Connection` stays dead, `create_channel` fails forever, and every
/// supervisor in the process spins until someone restarts it. Measured, not
/// argued: `tests/amqp_recovery_test.rs` polled a shared manager for 60 s
/// after a `docker restart` and it never became usable again.
///
/// The symptom that produces is the expensive kind, because the server keeps
/// serving. HTTP stays up, the decision cache goes permanently UNTRUSTED,
/// webhooks stop, and — since R2.4 — the reactor transport reports itself down
/// forever, which makes every `fail_closed` registration deny every login for
/// its tenant. Nothing in that picture points at the broker having bounced
/// hours earlier.
///
/// `enable_auto_recover` makes the IO loop reconnect transparently and replay
/// the exchange/queue/binding/consumer topology on the new connection, and
/// raises the TCP backoff to 16 attempts. The existing supervisors are
/// unaffected and still correct: they keep handling channel-level faults, and
/// they now do so on a connection that can actually come back.
///
/// Recovery applies to *recoverable* errors only — a deliberate
/// client-side `Connection::close` is still final, which is what
/// `reactor_containerized_test.rs`'s teardown test relies on.
fn connection_properties() -> ConnectionProperties {
    ConnectionProperties::default().enable_auto_recover()
}

/// Well-known queue names used by AXIAM.
pub mod queues {
    /// Inbound async authorization check requests.
    pub const AUTHZ_REQUEST: &str = "axiam.authz.request";
    /// Outbound authorization decision responses.
    pub const AUTHZ_RESPONSE: &str = "axiam.authz.response";
    /// Dead-letter queue for [`AUTHZ_REQUEST`] poison messages (CQ-B05).
    pub const AUTHZ_REQUEST_DLQ: &str = "axiam.authz.request.dlq";
    /// Inbound audit events from external services.
    pub const AUDIT_EVENTS: &str = "axiam.audit.events";
    /// Dead-letter queue for [`AUDIT_EVENTS`] poison messages (CQ-B05).
    pub const AUDIT_EVENTS_DLQ: &str = "axiam.audit.events.dlq";
    /// Outbound real-time event notifications.
    pub const NOTIFICATIONS: &str = "axiam.notifications";
    /// Outbound async mail delivery queue (D-14).
    ///
    /// Messages dead-letter to [`MAIL_OUTBOUND_DLQ`] when exhausted.
    pub const MAIL_OUTBOUND: &str = "axiam.mail.outbound";
    /// Dead-letter queue for [`MAIL_OUTBOUND`] exhausted-retry messages (D-14).
    pub const MAIL_OUTBOUND_DLQ: &str = "axiam.mail.outbound.dlq";
    /// Primary webhook delivery queue (CORR-03/D-07).
    ///
    /// A terminal nack (requeue=false, attempts exhausted) dead-letters to
    /// [`WEBHOOK_DLQ`]. Declared and consumed via [`AmqpManager::declare_webhook_topology`].
    pub const WEBHOOK: &str = "axiam.webhook";
    /// Webhook retry-delay queue (CORR-03/D-07). No consumer is ever
    /// attached to this queue — a message published here with a per-message
    /// TTL (`x-message-ttl`/`BasicProperties::with_expiration`) dead-letters
    /// back to [`WEBHOOK`] via the default exchange once the TTL expires,
    /// giving RabbitMQ-native delayed retry without an in-process sleep
    /// tying up a consumer slot (D-07/Pitfall 5).
    pub const WEBHOOK_RETRY: &str = "axiam.webhook.retry";
    /// Terminal dead-letter queue for exhausted webhook deliveries
    /// (CORR-03/D-07). Messages here are real and replayable — not silently
    /// dropped (see the DLX-wiring note on [`WEBHOOK`]/[`WEBHOOK_RETRY`]).
    pub const WEBHOOK_DLQ: &str = "axiam.webhook.dlq";
}

/// Well-known exchange names used by AXIAM.
pub mod exchanges {
    /// **Fanout** exchange carrying cross-replica authorization
    /// decision-cache invalidations (§4.2).
    ///
    /// Fanout, not a work queue: every replica binds its **own** exclusive
    /// auto-delete queue (`<this>.<replica_uuid>`) so every replica receives
    /// every invalidation. A shared queue would deliver each message to
    /// exactly one consumer and leave the rest serving stale allows. See
    /// [`crate::cache_invalidation`].
    pub const AUTHZ_CACHE_INVALIDATE: &str = "axiam.authz.cache.invalidate";
}

/// Queues declared via the plain durable loop (no special arguments).
///
/// These are declared first so that the DLQ targets already exist when the
/// primary queues with `x-dead-letter-exchange` are declared below.
const ALL_QUEUES: &[&str] = &[
    queues::AUTHZ_RESPONSE,
    queues::NOTIFICATIONS,
    // DLQs are plain-durable (no DLQ args of their own).
    queues::AUDIT_EVENTS_DLQ,
    queues::AUTHZ_REQUEST_DLQ,
    queues::MAIL_OUTBOUND_DLQ,
    // Primary queues with DLX are declared separately below.
];

/// Manages a RabbitMQ connection and channel.
pub struct AmqpManager {
    connection: Connection,
    channel: Channel,
    prefetch_count: u16,
}

impl AmqpManager {
    /// Establish a connection to RabbitMQ and create a channel.
    ///
    /// # Transport security (A6)
    ///
    /// The URL scheme selects the transport, and the posture is enforced
    /// **before** any socket is opened
    /// ([`AmqpConfig::validate_transport_security`]): an unrecognised scheme,
    /// half a client identity, or a plaintext URL in a release build without
    /// `AXIAM__AMQP__ALLOW_PLAINTEXT` all fail here rather than at connect
    /// time with a lapin error nobody can act on.
    ///
    /// There is **no silent plaintext fallback**. An `amqps://` URL whose CA
    /// bundle is missing, whose certificate is expired, or whose hostname does
    /// not match returns an error; it does not retry without TLS. That is the
    /// entire point — a fallback would make the failure invisible exactly when
    /// it matters.
    pub async fn connect(config: &AmqpConfig) -> Result<Self, AmqpError> {
        config
            .validate_transport_security()
            .map_err(|e| AmqpError::Config(e.to_string()))?;

        let tls = config.is_tls();
        info!(tls, "Connecting to RabbitMQ");

        let connection = if tls {
            let tls_config = build_tls_config(config)?;
            // `connect_with_config` is the only entry point that takes TLS
            // material, and it also requires an explicit runtime — so resolve
            // the same default runtime `Connection::connect` would have picked
            // rather than introducing a second runtime story for the TLS path.
            let runtime = lapin::runtime::default_runtime().map_err(AmqpError::Connection)?;
            Connection::connect_with_config(
                &config.url,
                connection_properties(),
                tls_config,
                runtime,
            )
            .await
            .map_err(AmqpError::Connection)?
        } else {
            Connection::connect(&config.url, connection_properties())
                .await
                .map_err(AmqpError::Connection)?
        };

        let channel = connection
            .create_channel()
            .await
            .map_err(AmqpError::Channel)?;

        channel
            .basic_qos(config.prefetch_count, BasicQosOptions::default())
            .await
            .map_err(AmqpError::Channel)?;

        info!("Successfully connected to RabbitMQ");

        Ok(Self {
            connection,
            channel,
            prefetch_count: config.prefetch_count,
        })
    }

    /// Connect with automatic retry on failure.
    ///
    /// Always attempts at least once. `max_retries` controls how many
    /// additional attempts are made after the first failure.
    pub async fn connect_with_retry(config: &AmqpConfig) -> Result<Self, AmqpError> {
        let total_attempts = config.max_retries.saturating_add(1);
        for attempt in 1..=total_attempts {
            match Self::connect(config).await {
                Ok(manager) => return Ok(manager),
                // A6: a configuration fault is not a transient one. Retrying a
                // missing CA mount or an unset AXIAM__AMQP__ALLOW_PLAINTEXT
                // `max_retries` times only delays the same error by
                // `max_retries × reconnect_delay_ms` and buries the actionable
                // message under identical warnings.
                Err(e @ AmqpError::Config(_)) => {
                    tracing::error!(error = %e, "RabbitMQ connection refused before dialling");
                    return Err(e);
                }
                Err(e) => {
                    if attempt == total_attempts {
                        let lapin_err = e.into_lapin_error();
                        tracing::error!(
                            error = %lapin_err,
                            attempts = total_attempts,
                            "Failed to connect to RabbitMQ after all retries"
                        );
                        return Err(AmqpError::MaxRetriesExhausted(lapin_err));
                    }
                    warn!(
                        error = %e,
                        attempt,
                        max_retries = config.max_retries,
                        delay_ms = config.reconnect_delay_ms,
                        "RabbitMQ connection failed, retrying"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(config.reconnect_delay_ms))
                        .await;
                }
            }
        }
        unreachable!("loop always returns")
    }

    /// Declare all AXIAM queues as durable.
    ///
    /// DLQ queues are declared first (plain durable, no DLQ args of their own),
    /// then the primary queues are declared with `x-dead-letter-exchange`
    /// pointing at their corresponding DLQs so that exhausted/rejected messages
    /// dead-letter rather than being silently dropped or hot-looping (CQ-B05).
    ///
    /// Queues with dead-letter routing:
    /// - `AUDIT_EVENTS`  → `AUDIT_EVENTS_DLQ`   (CQ-B05 / REQ-14 AC-5)
    /// - `AUTHZ_REQUEST` → `AUTHZ_REQUEST_DLQ`   (CQ-B05 / REQ-14 AC-5)
    /// - `MAIL_OUTBOUND` → `MAIL_OUTBOUND_DLQ`   (D-14)
    pub async fn declare_queues(&self) -> Result<(), AmqpError> {
        let options = QueueDeclareOptions {
            durable: true,
            ..QueueDeclareOptions::default()
        };

        // Declare plain-durable queues (DLQs and non-primary queues) first.
        for queue in ALL_QUEUES {
            self.channel
                .queue_declare((*queue).into(), options, FieldTable::default())
                .await
                .map_err(AmqpError::Declaration)?;
            info!(queue, "Declared queue");
        }

        // Declare AUDIT_EVENTS with dead-letter routing (CQ-B05).
        let mut audit_args = FieldTable::default();
        audit_args.insert(
            "x-dead-letter-exchange".into(),
            lapin::types::AMQPValue::LongString(queues::AUDIT_EVENTS_DLQ.into()),
        );
        self.channel
            .queue_declare(queues::AUDIT_EVENTS.into(), options, audit_args)
            .await
            .map_err(AmqpError::Declaration)?;
        info!(
            queue = queues::AUDIT_EVENTS,
            "Declared queue (with dead-letter routing)"
        );

        // Declare AUTHZ_REQUEST with dead-letter routing (CQ-B05).
        let mut authz_args = FieldTable::default();
        authz_args.insert(
            "x-dead-letter-exchange".into(),
            lapin::types::AMQPValue::LongString(queues::AUTHZ_REQUEST_DLQ.into()),
        );
        self.channel
            .queue_declare(queues::AUTHZ_REQUEST.into(), options, authz_args)
            .await
            .map_err(AmqpError::Declaration)?;
        info!(
            queue = queues::AUTHZ_REQUEST,
            "Declared queue (with dead-letter routing)"
        );

        // Declare MAIL_OUTBOUND with dead-letter routing (D-14).
        let mut mail_args = FieldTable::default();
        mail_args.insert(
            "x-dead-letter-exchange".into(),
            lapin::types::AMQPValue::LongString(queues::MAIL_OUTBOUND_DLQ.into()),
        );
        self.channel
            .queue_declare(queues::MAIL_OUTBOUND.into(), options, mail_args)
            .await
            .map_err(AmqpError::Declaration)?;
        info!(
            queue = queues::MAIL_OUTBOUND,
            "Declared queue (with dead-letter routing)"
        );

        Ok(())
    }

    /// Declare the durable webhook AMQP topology (primary + retry + DLQ,
    /// CORR-03/D-07).
    ///
    /// **Correct DLX form (Pitfall 4):** unlike [`Self::declare_queues`]'s
    /// existing `AUDIT_EVENTS`/`AUTHZ_REQUEST`/`MAIL_OUTBOUND` wiring above
    /// (which sets `x-dead-letter-exchange` to a queue NAME with no matching
    /// `exchange_declare` anywhere in this crate — RabbitMQ silently drops
    /// dead-lettered messages in that case), this topology uses the default
    /// (nameless, `""`) exchange plus an explicit `x-dead-letter-routing-key`
    /// for both dead-letter hops. The default exchange's implicit
    /// per-queue-name routing makes this the well-known-correct,
    /// minimal-surface form — never a bare undeclared exchange name.
    ///
    /// Declaration order (DLQ target first, same discipline as
    /// [`Self::declare_queues`]'s `ALL_QUEUES` convention):
    /// 1. [`queues::WEBHOOK_DLQ`] — terminal, plain durable, no DLX of its own.
    /// 2. [`queues::WEBHOOK`] — primary; a terminal nack (requeue=false,
    ///    attempts exhausted per `AXIAM__WEBHOOK__MAX_ATTEMPTS`) dead-letters
    ///    to [`queues::WEBHOOK_DLQ`].
    /// 3. [`queues::WEBHOOK_RETRY`] — no consumer ever attached; a message
    ///    published here with a per-message TTL dead-letters back to
    ///    [`queues::WEBHOOK`] once the TTL expires, so RabbitMQ (not an
    ///    in-process `tokio::time::sleep`) schedules the delay
    ///    (D-07/Pitfall 5).
    pub async fn declare_webhook_topology(&self) -> Result<(), AmqpError> {
        let options = QueueDeclareOptions {
            durable: true,
            ..QueueDeclareOptions::default()
        };

        // 1. Terminal DLQ — plain durable, no DLX args of its own.
        self.channel
            .queue_declare(queues::WEBHOOK_DLQ.into(), options, FieldTable::default())
            .await
            .map_err(AmqpError::Declaration)?;
        info!(queue = queues::WEBHOOK_DLQ, "Declared queue");

        // 2. Primary webhook queue: terminal-exhaustion nacks dead-letter to
        // WEBHOOK_DLQ via the default exchange + explicit routing key.
        let mut webhook_args = FieldTable::default();
        webhook_args.insert(
            "x-dead-letter-exchange".into(),
            lapin::types::AMQPValue::LongString("".into()),
        );
        webhook_args.insert(
            "x-dead-letter-routing-key".into(),
            lapin::types::AMQPValue::LongString(queues::WEBHOOK_DLQ.into()),
        );
        self.channel
            .queue_declare(queues::WEBHOOK.into(), options, webhook_args)
            .await
            .map_err(AmqpError::Declaration)?;
        info!(
            queue = queues::WEBHOOK,
            "Declared queue (with dead-letter routing to WEBHOOK_DLQ)"
        );

        // 3. Retry queue: per-message TTL (set at publish time) dead-letters
        // back to the primary WEBHOOK queue via the default exchange — no
        // consumer attached here, no in-process sleep holding a slot.
        let mut retry_args = FieldTable::default();
        retry_args.insert(
            "x-dead-letter-exchange".into(),
            lapin::types::AMQPValue::LongString("".into()),
        );
        retry_args.insert(
            "x-dead-letter-routing-key".into(),
            lapin::types::AMQPValue::LongString(queues::WEBHOOK.into()),
        );
        self.channel
            .queue_declare(queues::WEBHOOK_RETRY.into(), options, retry_args)
            .await
            .map_err(AmqpError::Declaration)?;
        info!(
            queue = queues::WEBHOOK_RETRY,
            "Declared queue (with dead-letter routing back to WEBHOOK)"
        );

        Ok(())
    }

    /// Returns a reference to the underlying AMQP channel.
    pub fn channel(&self) -> &Channel {
        &self.channel
    }

    /// Create a new channel on the existing connection with QoS applied.
    pub async fn create_channel(&self) -> Result<Channel, AmqpError> {
        let channel = self
            .connection
            .create_channel()
            .await
            .map_err(AmqpError::Channel)?;
        channel
            .basic_qos(self.prefetch_count, BasicQosOptions::default())
            .await
            .map_err(AmqpError::Channel)?;
        Ok(channel)
    }

    /// Create a new channel with QoS and publisher confirms enabled.
    ///
    /// Use this for channels that will publish messages and need broker
    /// acknowledgement (`Confirmation::Ack`/`Nack` instead of `NotRequested`).
    pub async fn create_publisher_channel(&self) -> Result<Channel, AmqpError> {
        let channel = self.create_channel().await?;
        channel
            .confirm_select(ConfirmSelectOptions::default())
            .await
            .map_err(AmqpError::Channel)?;
        Ok(channel)
    }

    /// Returns a reference to the underlying AMQP connection.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

/// Lets [`crate::cache_invalidation::CacheInvalidationPublisher`] reopen its
/// channel after a channel-level exception (§13.4 observation 2) instead of
/// holding one channel for the process lifetime.
impl crate::cache_invalidation::PublisherChannelFactory for AmqpManager {
    fn open<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Channel, AmqpError>> + Send + 'a>>
    {
        Box::pin(self.create_publisher_channel())
    }
}
