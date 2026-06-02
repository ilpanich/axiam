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
    /// Inbound audit events from external services.
    pub const AUDIT_EVENTS: &str = "axiam.audit.events";
    /// Outbound real-time event notifications.
    pub const NOTIFICATIONS: &str = "axiam.notifications";
    /// Outbound async mail delivery queue (D-14).
    ///
    /// Messages dead-letter to [`MAIL_OUTBOUND_DLQ`] when exhausted.
    pub const MAIL_OUTBOUND: &str = "axiam.mail.outbound";
    /// Dead-letter queue for [`MAIL_OUTBOUND`] exhausted-retry messages (D-14).
    pub const MAIL_OUTBOUND_DLQ: &str = "axiam.mail.outbound.dlq";
}

/// Queues declared via the plain durable loop (no special arguments).
const ALL_QUEUES: &[&str] = &[
    queues::AUTHZ_REQUEST,
    queues::AUTHZ_RESPONSE,
    queues::AUDIT_EVENTS,
    queues::NOTIFICATIONS,
    // MAIL_OUTBOUND_DLQ is plain-durable (no DLQ args of its own).
    queues::MAIL_OUTBOUND_DLQ,
    // MAIL_OUTBOUND is declared separately below with x-dead-letter-exchange.
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
    /// `MAIL_OUTBOUND_DLQ` is declared first (plain durable, no DLQ args),
    /// then `MAIL_OUTBOUND` is declared explicitly with
    /// `x-dead-letter-exchange` pointing at the DLQ so that exhausted-retry
    /// messages dead-letter rather than being silently dropped (D-14).
    pub async fn declare_queues(&self) -> Result<(), AmqpError> {
        let options = QueueDeclareOptions {
            durable: true,
            ..QueueDeclareOptions::default()
        };

        for queue in ALL_QUEUES {
            self.channel
                .queue_declare((*queue).into(), options, FieldTable::default())
                .await
                .map_err(AmqpError::Declaration)?;
            info!(queue, "Declared queue");
        }

        // Declare MAIL_OUTBOUND with explicit dead-letter routing (D-14).
        // The DLQ must already exist at this point (declared in the loop above).
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
            "Declared queue (with DLQ routing)"
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
