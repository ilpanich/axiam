//! RabbitMQ connection management.

use lapin::options::{BasicQosOptions, ConfirmSelectOptions, QueueDeclareOptions};
use lapin::types::FieldTable;
use lapin::{Channel, Connection, ConnectionProperties};
use tracing::{info, warn};

use crate::config::AmqpConfig;
use crate::error::AmqpError;

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
    pub async fn connect(config: &AmqpConfig) -> Result<Self, AmqpError> {
        info!("Connecting to RabbitMQ");

        let connection = Connection::connect(&config.url, ConnectionProperties::default())
            .await
            .map_err(AmqpError::Connection)?;

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
