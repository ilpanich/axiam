//! AMQP error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AmqpError {
    #[error("AMQP connection failed: {0}")]
    Connection(lapin::Error),

    #[error("AMQP channel creation failed: {0}")]
    Channel(lapin::Error),

    #[error("AMQP queue/exchange declaration failed: {0}")]
    Declaration(lapin::Error),

    #[error("AMQP publish failed: {0}")]
    Publish(String),

    #[error("AMQP connection failed after exhausting all retries: {0}")]
    MaxRetriesExhausted(#[source] lapin::Error),
}

impl AmqpError {
    /// Extract the underlying `lapin::Error` from connection-related variants.
    pub(crate) fn into_lapin_error(self) -> lapin::Error {
        match self {
            Self::Connection(e) | Self::Channel(e) | Self::Declaration(e) => e,
            _ => unreachable!("into_lapin_error called on non-lapin variant"),
        }
    }
}
