//! AXIAM AMQP — RabbitMQ integration for async authorization and event processing.

pub mod audit_consumer;
pub mod authz_consumer;
pub mod config;
pub mod connection;
pub mod error;
pub mod mail_consumer;
pub mod mail_publisher;
pub mod messages;
pub mod notification_publisher;
pub mod webhook_publisher;

pub use config::AmqpConfig;
pub use connection::AmqpManager;
pub use connection::queues;
pub use error::AmqpError;
pub use mail_consumer::start_mail_consumer;
pub use mail_publisher::MailOutboundPublisher;
pub use messages::{MailType, OutboundMailMessage, WebhookMessage};
pub use notification_publisher::NotificationPublisher;
pub use webhook_publisher::WebhookPublisher;
