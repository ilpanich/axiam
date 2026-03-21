//! Email provider trait — the core abstraction for pluggable delivery.

use std::future::Future;
use std::pin::Pin;

use axiam_core::error::AxiamResult;

use crate::message::EmailMessage;

/// Result of a successful email send.
#[derive(Debug, Clone)]
pub struct SendResult {
    /// Provider-specific message ID (if available).
    pub message_id: Option<String>,
}

/// Pluggable email provider trait.
///
/// Implementations handle the actual delivery of email messages
/// via SMTP or REST API. Uses `Pin<Box<dyn Future>>` for object
/// safety — the concrete provider is selected at runtime from
/// configuration.
pub trait EmailProvider: Send + Sync {
    /// Send a single email message.
    fn send(
        &self,
        from_name: &str,
        from_email: &str,
        reply_to: Option<&str>,
        message: &EmailMessage,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<SendResult>> + Send + '_>>;

    /// Provider name for logging/diagnostics.
    fn provider_name(&self) -> &'static str;
}
