//! Email provider implementations.

pub mod brevo;
pub mod mock;
pub mod postmark;
pub mod resend;
pub mod sendgrid;
pub mod smtp;

use std::time::Duration;

use axiam_core::error::{AxiamError, AxiamResult};
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
pub(crate) fn build_http_client() -> AxiamResult<Client> {
    Client::builder()
        .timeout(HTTP_TIMEOUT)
        .redirect(Policy::none())
        .build()
        .map_err(|e| AxiamError::EmailDelivery(format!("failed to build HTTP client: {e}")))
}

/// Reject a provider config carrying no credential.
///
/// An empty secret reaches a provider as `Authorization: Bearer ` (or an empty
/// `api-key` header) and comes back as a 401 whose text names neither AXIAM nor
/// the configuration that produced it — twelve retries and a dead-letter later,
/// with nothing in the audit trail pointing at the missing key. Refusing here
/// names the problem at the moment the config is used.
///
/// This is also the net under the tenant-override write path, which stored the
/// ciphertext of an empty string whenever an operator saved a provider override
/// without re-typing the secret: a row written before that was fixed still
/// decrypts to `""`, and this turns it into a legible error rather than a
/// mysterious provider rejection.
fn reject_missing_credential(config: &ProviderConfig) -> AxiamResult<()> {
    let missing = match config {
        // SMTP genuinely allows an unauthenticated relay (a local MTA on
        // localhost:25 with no credentials is a normal deployment), so an
        // empty password is not by itself a misconfiguration. An empty host
        // is.
        ProviderConfig::Smtp(c) => c.host.trim().is_empty().then_some("SMTP host"),
        ProviderConfig::SendGrid(c) => c.api_key.is_empty().then_some("SendGrid API key"),
        ProviderConfig::Postmark(c) => c.api_key.is_empty().then_some("Postmark server token"),
        ProviderConfig::Resend(c) => c.api_key.is_empty().then_some("Resend API key"),
        ProviderConfig::Brevo(c) => c.api_key.is_empty().then_some("Brevo API key"),
    };
    match missing {
        None => Ok(()),
        Some(what) => Err(AxiamError::EmailConfig(format!(
            "email configuration is incomplete: the {what} is empty. Re-save the \
             organization or tenant email configuration with the credential filled in"
        ))),
    }
}

/// Construct a boxed `EmailProvider` from a `ProviderConfig`.
pub fn build_provider(config: &ProviderConfig) -> AxiamResult<Box<dyn EmailProvider>> {
    reject_missing_credential(config)?;
    match config {
        ProviderConfig::Smtp(c) => Ok(Box::new(smtp::SmtpProvider::new(c)?)),
        ProviderConfig::SendGrid(c) => Ok(Box::new(sendgrid::SendGridProvider::new(c)?)),
        ProviderConfig::Postmark(c) => Ok(Box::new(postmark::PostmarkProvider::new(c)?)),
        ProviderConfig::Resend(c) => Ok(Box::new(resend::ResendProvider::new(c)?)),
        ProviderConfig::Brevo(c) => Ok(Box::new(brevo::BrevoProvider::new(c)?)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::email::{ApiProviderConfig, SmtpConfig};

    fn api(key: &str) -> ApiProviderConfig {
        ApiProviderConfig {
            api_key: key.to_string(),
            api_url: None,
        }
    }

    fn smtp(host: &str) -> SmtpConfig {
        SmtpConfig {
            host: host.to_string(),
            port: 587,
            username: String::new(),
            password: String::new(),
            starttls: true,
        }
    }

    #[test]
    fn every_api_provider_refuses_an_empty_credential() {
        for config in [
            ProviderConfig::SendGrid(api("")),
            ProviderConfig::Postmark(api("")),
            ProviderConfig::Resend(api("")),
            ProviderConfig::Brevo(api("")),
        ] {
            let name = provider_name(&config);
            let err = build_provider(&config)
                .err()
                .unwrap_or_else(|| panic!("{name} must refuse an empty credential"));
            let msg = err.to_string();
            assert!(
                msg.contains("incomplete") && msg.contains("empty"),
                "{name}: unhelpful message: {msg}"
            );
        }
    }

    #[test]
    fn api_providers_build_once_a_credential_is_present() {
        for config in [
            ProviderConfig::SendGrid(api("k")),
            ProviderConfig::Postmark(api("k")),
            ProviderConfig::Resend(api("k")),
            ProviderConfig::Brevo(api("k")),
        ] {
            assert!(build_provider(&config).is_ok());
        }
    }

    #[test]
    fn smtp_refuses_an_empty_host_but_allows_an_empty_password() {
        // An unauthenticated local relay is a legitimate SMTP deployment, so
        // only the host is required.
        assert!(build_provider(&ProviderConfig::Smtp(smtp(""))).is_err());
        assert!(build_provider(&ProviderConfig::Smtp(smtp("   "))).is_err());
        assert!(build_provider(&ProviderConfig::Smtp(smtp("localhost"))).is_ok());
    }
}
