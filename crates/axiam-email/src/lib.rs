//! AXIAM Email — Pluggable email delivery service.
//!
//! Supports multiple providers: SMTP (via `lettre`), SendGrid,
//! Postmark, Resend, and Brevo (via `reqwest` REST calls).
//! Provider is configured at org level; tenants can override.

pub mod message;
pub mod provider;
pub mod providers;
pub mod service;
pub mod template;

// Re-exports for convenience.
pub use message::EmailMessage;
pub use provider::{EmailProvider, SendResult};
pub use service::EmailService;
pub use template::{TemplateContext, render_email, resolve_template};

#[cfg(test)]
mod tests {
    use axiam_core::models::email::{ApiProviderConfig, EmailConfig, ProviderConfig, SmtpConfig};
    use axiam_core::models::settings::SettingsScope;
    use chrono::Utc;
    use uuid::Uuid;

    use crate::message::EmailMessage;
    use crate::providers;
    use crate::providers::mock::MockProvider;
    use crate::service::EmailService;

    fn sample_message() -> EmailMessage {
        EmailMessage {
            to: "user@example.com".to_string(),
            subject: "Welcome".to_string(),
            html_body: Some("<h1>Hello</h1>".to_string()),
            text_body: Some("Hello".to_string()),
        }
    }

    fn sample_email_config(provider: ProviderConfig) -> EmailConfig {
        EmailConfig {
            id: Uuid::new_v4(),
            scope: SettingsScope::Org,
            scope_id: Uuid::new_v4(),
            enabled: true,
            from_name: "AXIAM".to_string(),
            from_email: "noreply@example.com".to_string(),
            reply_to: Some("support@example.com".to_string()),
            provider,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // --- MockProvider tests ---

    #[tokio::test]
    async fn mock_provider_records_sent_messages() {
        let mock = MockProvider::new();
        let result = mock
            .send("Test", "test@example.com", None, &sample_message())
            .await;
        assert!(result.is_ok());
        assert_eq!(mock.sent_count(), 1);

        let sent = mock.sent_messages();
        assert_eq!(sent[0].from_name, "Test");
        assert_eq!(sent[0].from_email, "test@example.com");
        assert_eq!(sent[0].message.to, "user@example.com");
    }

    use crate::provider::EmailProvider;

    #[tokio::test]
    async fn mock_provider_failing_returns_error() {
        let mock = MockProvider::failing();
        let result = mock
            .send("Test", "test@example.com", None, &sample_message())
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("mock provider configured to fail"));
        assert_eq!(mock.sent_count(), 0);
    }

    #[tokio::test]
    async fn mock_provider_passes_reply_to() {
        let mock = MockProvider::new();
        let _ = mock
            .send(
                "Test",
                "test@example.com",
                Some("reply@example.com"),
                &sample_message(),
            )
            .await;
        let sent = mock.sent_messages();
        assert_eq!(sent[0].reply_to.as_deref(), Some("reply@example.com"));
    }

    // --- EmailService tests ---

    #[tokio::test]
    async fn service_sends_through_mock() {
        let mock = MockProvider::new();
        let service = EmailService::with_provider(
            Box::new(MockProvider::new()),
            "AXIAM".to_string(),
            "noreply@example.com".to_string(),
            Some("support@example.com".to_string()),
        );

        let result = service.send(&sample_message()).await;
        assert!(result.is_ok());
        assert_eq!(service.provider_name(), "mock");

        // The mock inside the service is different from `mock` above,
        // so we test via the service wrapper instead.
        drop(mock);
    }

    #[tokio::test]
    async fn service_rejects_empty_body() {
        let service = EmailService::with_provider(
            Box::new(MockProvider::new()),
            "AXIAM".to_string(),
            "noreply@example.com".to_string(),
            None,
        );

        let msg = EmailMessage {
            to: "user@example.com".to_string(),
            subject: "Empty".to_string(),
            html_body: None,
            text_body: None,
        };
        let result = service.send(&msg).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no body"));
    }

    #[tokio::test]
    async fn service_from_disabled_config_errors() {
        let mut config = sample_email_config(ProviderConfig::SendGrid(ApiProviderConfig {
            api_key: "key".to_string(),
            api_url: None,
        }));
        config.enabled = false;
        let result = EmailService::from_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("disabled"));
    }

    // --- Provider factory tests ---

    #[test]
    fn build_provider_sendgrid() {
        let config = ProviderConfig::SendGrid(ApiProviderConfig {
            api_key: "sg_test".to_string(),
            api_url: None,
        });
        let provider = providers::build_provider(&config).unwrap();
        assert_eq!(provider.provider_name(), "sendgrid");
    }

    #[test]
    fn build_provider_postmark() {
        let config = ProviderConfig::Postmark(ApiProviderConfig {
            api_key: "pm_test".to_string(),
            api_url: None,
        });
        let provider = providers::build_provider(&config).unwrap();
        assert_eq!(provider.provider_name(), "postmark");
    }

    #[test]
    fn build_provider_resend() {
        let config = ProviderConfig::Resend(ApiProviderConfig {
            api_key: "re_test".to_string(),
            api_url: None,
        });
        let provider = providers::build_provider(&config).unwrap();
        assert_eq!(provider.provider_name(), "resend");
    }

    #[test]
    fn build_provider_brevo() {
        let config = ProviderConfig::Brevo(ApiProviderConfig {
            api_key: "xkeysib_test".to_string(),
            api_url: None,
        });
        let provider = providers::build_provider(&config).unwrap();
        assert_eq!(provider.provider_name(), "brevo");
    }

    #[test]
    fn provider_name_helper() {
        assert_eq!(
            providers::provider_name(&ProviderConfig::Smtp(SmtpConfig {
                host: "h".into(),
                port: 25,
                username: "u".into(),
                password: "p".into(),
                starttls: false,
            })),
            "smtp",
        );
        assert_eq!(
            providers::provider_name(&ProviderConfig::SendGrid(ApiProviderConfig {
                api_key: "k".into(),
                api_url: None,
            })),
            "sendgrid",
        );
    }

    // --- EmailMessage ---

    #[test]
    fn message_has_body_with_html() {
        let msg = EmailMessage {
            to: "x@y.com".into(),
            subject: "s".into(),
            html_body: Some("html".into()),
            text_body: None,
        };
        assert!(msg.has_body());
    }

    #[test]
    fn message_has_body_with_text() {
        let msg = EmailMessage {
            to: "x@y.com".into(),
            subject: "s".into(),
            html_body: None,
            text_body: Some("text".into()),
        };
        assert!(msg.has_body());
    }

    #[test]
    fn message_no_body() {
        let msg = EmailMessage {
            to: "x@y.com".into(),
            subject: "s".into(),
            html_body: None,
            text_body: None,
        };
        assert!(!msg.has_body());
    }
}
