//! Email provider implementations.

pub mod brevo;
pub mod mock;
pub mod postmark;
pub mod resend;
pub mod sendgrid;
pub mod smtp;

use std::time::Duration;

use axiam_core::error::AxiamResult;
use axiam_core::models::email::ProviderConfig;
use reqwest::Client;
use reqwest::redirect::Policy;

use crate::provider::EmailProvider;

/// Default timeout for outbound email-provider HTTP requests.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Build a hardened HTTP client for email providers.
///
/// - 30-second timeout to prevent hanging tasks.
/// - Redirects disabled to prevent credential leakage / SSRF bypass.
pub(crate) fn build_http_client() -> Client {
    Client::builder()
        .timeout(HTTP_TIMEOUT)
        .redirect(Policy::none())
        .build()
        .expect("failed to build HTTP client")
}

/// Construct a boxed `EmailProvider` from a `ProviderConfig`.
pub fn build_provider(config: &ProviderConfig) -> AxiamResult<Box<dyn EmailProvider>> {
    match config {
        ProviderConfig::Smtp(c) => Ok(Box::new(smtp::SmtpProvider::new(c)?)),
        ProviderConfig::SendGrid(c) => Ok(Box::new(sendgrid::SendGridProvider::new(c))),
        ProviderConfig::Postmark(c) => Ok(Box::new(postmark::PostmarkProvider::new(c))),
        ProviderConfig::Resend(c) => Ok(Box::new(resend::ResendProvider::new(c))),
        ProviderConfig::Brevo(c) => Ok(Box::new(brevo::BrevoProvider::new(c))),
    }
}

/// Returns the provider name for a given config (without constructing
/// the provider).
pub fn provider_name(config: &ProviderConfig) -> &'static str {
    match config {
        ProviderConfig::Smtp(_) => "smtp",
        ProviderConfig::SendGrid(_) => "sendgrid",
        ProviderConfig::Postmark(_) => "postmark",
        ProviderConfig::Resend(_) => "resend",
        ProviderConfig::Brevo(_) => "brevo",
    }
}
