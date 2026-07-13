//! Integration tests for `EmailService::from_config` and the `Debug` impl.

use axiam_core::models::email::{ApiProviderConfig, EmailConfig, ProviderConfig, SmtpConfig};
use axiam_core::models::settings::SettingsScope;
use axiam_email::EmailService;
use chrono::Utc;
use uuid::Uuid;

fn email_config(provider: ProviderConfig, enabled: bool) -> EmailConfig {
    EmailConfig {
        id: Uuid::new_v4(),
        scope: SettingsScope::Org,
        scope_id: Uuid::new_v4(),
        enabled,
        from_name: "AXIAM".to_string(),
        from_email: "noreply@example.com".to_string(),
        reply_to: Some("support@example.com".to_string()),
        provider,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn from_config_builds_sendgrid_service() {
    let cfg = email_config(
        ProviderConfig::SendGrid(ApiProviderConfig {
            api_key: "k".into(),
            api_url: None,
        }),
        true,
    );
    let service = EmailService::from_config(&cfg).unwrap();
    assert_eq!(service.provider_name(), "sendgrid");
}

#[test]
fn from_config_builds_smtp_service() {
    let cfg = email_config(
        ProviderConfig::Smtp(SmtpConfig {
            host: "smtp.example.com".into(),
            port: 587,
            username: "u".into(),
            password: "p".into(),
            starttls: true,
        }),
        true,
    );
    let service = EmailService::from_config(&cfg).unwrap();
    assert_eq!(service.provider_name(), "smtp");
}

#[test]
fn from_config_disabled_errors() {
    let cfg = email_config(
        ProviderConfig::Resend(ApiProviderConfig {
            api_key: "k".into(),
            api_url: None,
        }),
        false,
    );
    let err = EmailService::from_config(&cfg).unwrap_err().to_string();
    assert!(err.contains("disabled"), "got: {err}");
}

#[test]
fn service_debug_impl_shows_provider_and_identity() {
    let cfg = email_config(
        ProviderConfig::Brevo(ApiProviderConfig {
            api_key: "k".into(),
            api_url: None,
        }),
        true,
    );
    let service = EmailService::from_config(&cfg).unwrap();
    let dbg = format!("{service:?}");
    assert!(dbg.contains("EmailService"));
    assert!(dbg.contains("brevo"));
    assert!(dbg.contains("noreply@example.com"));
}
