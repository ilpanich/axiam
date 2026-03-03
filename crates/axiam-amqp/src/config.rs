//! AMQP configuration.

use serde::Deserialize;

/// Configuration for connecting to RabbitMQ.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AmqpConfig {
    /// AMQP connection URI (e.g., `amqp://localhost:5672`).
    pub url: String,
    /// Channel prefetch count for consumers.
    pub prefetch_count: u16,
    /// Delay between reconnection attempts in milliseconds.
    pub reconnect_delay_ms: u64,
    /// Maximum number of connection retries before giving up.
    pub max_retries: u32,
}

impl Default for AmqpConfig {
    fn default() -> Self {
        Self {
            url: "amqp://localhost:5672".into(),
            prefetch_count: 10,
            reconnect_delay_ms: 5000,
            max_retries: 5,
        }
    }
}
