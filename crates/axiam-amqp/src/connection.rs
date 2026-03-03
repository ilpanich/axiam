//! RabbitMQ connection management.

use lapin::options::{BasicQosOptions, QueueDeclareOptions};
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
}

const ALL_QUEUES: &[&str] = &[
    queues::AUTHZ_REQUEST,
    queues::AUTHZ_RESPONSE,
    queues::AUDIT_EVENTS,
    queues::NOTIFICATIONS,
];

/// Manages a RabbitMQ connection and channel.
pub struct AmqpManager {
    connection: Connection,
    channel: Channel,
}

impl AmqpManager {
    /// Establish a connection to RabbitMQ and create a channel.
    pub async fn connect(config: &AmqpConfig) -> Result<Self, AmqpError> {
        info!(url = %config.url, "Connecting to RabbitMQ");

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
        })
    }

    /// Connect with automatic retry on failure.
    pub async fn connect_with_retry(config: &AmqpConfig) -> Result<Self, AmqpError> {
        for attempt in 1..=config.max_retries {
            match Self::connect(config).await {
                Ok(manager) => return Ok(manager),
                Err(e) => {
                    if attempt == config.max_retries {
                        tracing::error!(
                            error = %e,
                            attempts = config.max_retries,
                            "Failed to connect to RabbitMQ after all retries"
                        );
                        return Err(AmqpError::MaxRetriesExhausted);
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
        Err(AmqpError::MaxRetriesExhausted)
    }

    /// Declare all AXIAM queues as durable.
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

        Ok(())
    }

    /// Returns a reference to the underlying AMQP channel.
    pub fn channel(&self) -> &Channel {
        &self.channel
    }

    /// Returns a reference to the underlying AMQP connection.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}
