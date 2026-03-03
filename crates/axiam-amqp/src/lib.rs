//! AXIAM AMQP — RabbitMQ integration for async authorization and event processing.

pub mod audit_consumer;
pub mod authz_consumer;
pub mod config;
pub mod connection;
pub mod error;
pub mod messages;
pub mod notification_publisher;

pub use config::AmqpConfig;
pub use connection::AmqpManager;
pub use error::AmqpError;
pub use notification_publisher::NotificationPublisher;
