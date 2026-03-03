//! AXIAM AMQP — RabbitMQ integration for async authorization and event processing.

pub mod authz_consumer;
pub mod config;
pub mod connection;
pub mod error;
pub mod messages;

pub use config::AmqpConfig;
pub use connection::AmqpManager;
pub use error::AmqpError;
