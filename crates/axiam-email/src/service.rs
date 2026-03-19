//! High-level email service that resolves the correct provider
//! from configuration and sends messages.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::email::EmailConfig;

use crate::message::EmailMessage;
use crate::provider::{EmailProvider, SendResult};
use crate::providers;

/// High-level email service — wraps a resolved provider and sender
/// identity.
///
/// Manual `Debug` impl because `Box<dyn EmailProvider>` is not `Debug`.
pub struct EmailService {
    provider: Box<dyn EmailProvider>,
    from_name: String,
    from_email: String,
    reply_to: Option<String>,
}

impl std::fmt::Debug for EmailService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailService")
            .field("provider", &self.provider.provider_name())
            .field("from_name", &self.from_name)
            .field("from_email", &self.from_email)
            .field("reply_to", &self.reply_to)
            .finish()
    }
}

impl EmailService {
    /// Build an `EmailService` from a resolved `EmailConfig`.
    ///
    /// Returns an error if the provider cannot be constructed (e.g.,
    /// invalid SMTP host) or if email is disabled.
    pub fn from_config(config: &EmailConfig) -> AxiamResult<Self> {
        if !config.enabled {
            return Err(AxiamError::EmailConfig(
                "email is disabled for this scope".into(),
            ));
        }

        let provider = providers::build_provider(&config.provider)?;

        Ok(Self {
            provider,
            from_name: config.from_name.clone(),
            from_email: config.from_email.clone(),
            reply_to: config.reply_to.clone(),
        })
    }

    /// Build from an explicit provider (useful for testing).
    pub fn with_provider(
        provider: Box<dyn EmailProvider>,
        from_name: String,
        from_email: String,
        reply_to: Option<String>,
    ) -> Self {
        Self {
            provider,
            from_name,
            from_email,
            reply_to,
        }
    }

    /// Send an email using the configured provider.
    pub async fn send(&self, message: &EmailMessage) -> AxiamResult<SendResult> {
        if !message.has_body() {
            return Err(AxiamError::EmailDelivery(
                "email has no body (html or text)".into(),
            ));
        }

        tracing::info!(
            provider = self.provider.provider_name(),
            to = %message.to,
            subject = %message.subject,
            "sending email"
        );

        self.provider
            .send(
                &self.from_name,
                &self.from_email,
                self.reply_to.as_deref(),
                message,
            )
            .await
    }

    /// Returns the name of the underlying provider.
    pub fn provider_name(&self) -> &'static str {
        self.provider.provider_name()
    }
}
