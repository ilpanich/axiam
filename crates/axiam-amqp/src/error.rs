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

    #[error("AMQP connection failed after exhausting all retries")]
    MaxRetriesExhausted,
}
