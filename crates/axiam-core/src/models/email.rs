//! Email configuration model with org/tenant inheritance.
//!
//! Organizations configure an email provider baseline. Tenants may
//! override the provider or sender details. The effective email
//! config for a tenant = org baseline merged with tenant overrides.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AxiamError, AxiamResult};
use super::settings::SettingsScope;

// -----------------------------------------------------------------------
// Provider configuration
// -----------------------------------------------------------------------

/// Which email backend to use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EmailProviderKind {
    Smtp,
    SendGrid,
    Postmark,
    Resend,
    Brevo,
}

/// SMTP-specific configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    /// Stored encrypted at rest by the DB layer.
    pub password: String,
    /// Use STARTTLS (true) or implicit TLS (false).
    pub starttls: bool,
}

/// API-based provider configuration (SendGrid, Postmark, Resend, Brevo).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ApiProviderConfig {
    /// Stored encrypted at rest by the DB layer.
    pub api_key: String,
    /// Override base URL (useful for testing / self-hosted instances).
    pub api_url: Option<String>,
}

/// Provider-specific connection details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProviderConfig {
    Smtp(SmtpConfig),
    SendGrid(ApiProviderConfig),
    Postmark(ApiProviderConfig),
    Resend(ApiProviderConfig),
    Brevo(ApiProviderConfig),
}

impl ProviderConfig {
    pub fn kind(&self) -> EmailProviderKind {
        match self {
            Self::Smtp(_) => EmailProviderKind::Smtp,
            Self::SendGrid(_) => EmailProviderKind::SendGrid,
            Self::Postmark(_) => EmailProviderKind::Postmark,
            Self::Resend(_) => EmailProviderKind::Resend,
            Self::Brevo(_) => EmailProviderKind::Brevo,
        }
    }
}

// -----------------------------------------------------------------------
// Fully resolved email configuration
// -----------------------------------------------------------------------

/// Fully resolved email configuration (all fields present).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EmailConfig {
    pub id: Uuid,
    pub scope: SettingsScope,
    /// The org_id or tenant_id this config belongs to.
    pub scope_id: Uuid,
    pub enabled: bool,
    pub from_name: String,
    pub from_email: String,
    pub reply_to: Option<String>,
    pub provider: ProviderConfig,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// -----------------------------------------------------------------------
// Tenant override — all Option for partial inheritance
// -----------------------------------------------------------------------

/// Partial tenant overrides for email configuration.
/// `None` = inherit from org baseline.
#[derive(
    Debug, Clone, Default, PartialEq, Serialize, Deserialize, utoipa::ToSchema,
)]
pub struct EmailConfigOverride {
    pub enabled: Option<bool>,
    pub from_name: Option<String>,
    pub from_email: Option<String>,
    /// `Some(None)` explicitly clears reply-to; `None` inherits.
    pub reply_to: Option<Option<String>>,
    /// Full provider replacement (no partial merge within a provider).
    pub provider: Option<ProviderConfig>,
}

impl EmailConfigOverride {
    /// Returns `true` if every field is `None` (no overrides).
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

// -----------------------------------------------------------------------
// Input DTOs
// -----------------------------------------------------------------------

/// Input for setting organization-level email config.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SetOrgEmailConfig {
    pub enabled: bool,
    pub from_name: String,
    pub from_email: String,
    pub reply_to: Option<String>,
    pub provider: ProviderConfig,
}

/// Input for setting tenant-level email overrides.
pub type SetTenantEmailOverride = EmailConfigOverride;

// -----------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------

/// Validate an org-level email configuration.
pub fn validate_email_config(input: &SetOrgEmailConfig) -> AxiamResult<()> {
    let mut violations = Vec::new();

    if input.from_email.is_empty() || !input.from_email.contains('@') {
        violations.push(
            "from_email must be a valid email address".to_string(),
        );
    }

    if input.from_name.is_empty() {
        violations.push("from_name must not be empty".to_string());
    }

    if let Some(ref reply_to) = input.reply_to {
        if reply_to.is_empty() || !reply_to.contains('@') {
            violations.push(
                "reply_to must be a valid email address if provided"
                    .to_string(),
            );
        }
    }

    match &input.provider {
        ProviderConfig::Smtp(smtp) => {
            if smtp.host.is_empty() {
                violations.push("SMTP host must not be empty".to_string());
            }
            if smtp.port == 0 {
                violations.push("SMTP port must be > 0".to_string());
            }
        }
        ProviderConfig::SendGrid(api)
        | ProviderConfig::Postmark(api)
        | ProviderConfig::Resend(api)
        | ProviderConfig::Brevo(api) => {
            if api.api_key.is_empty() {
                violations.push("API key must not be empty".to_string());
            }
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(AxiamError::Validation {
            message: format!(
                "Invalid email config: {}",
                violations.join("; ")
            ),
        })
    }
}

// -----------------------------------------------------------------------
// Inheritance engine
// -----------------------------------------------------------------------

/// Merge org email config with tenant overrides to produce effective
/// config.
pub fn effective_email_config(
    org: &EmailConfig,
    tenant_override: &EmailConfigOverride,
    tenant_id: Uuid,
    result_id: Uuid,
) -> EmailConfig {
    EmailConfig {
        id: result_id,
        scope: SettingsScope::Tenant,
        scope_id: tenant_id,
        enabled: tenant_override.enabled.unwrap_or(org.enabled),
        from_name: tenant_override
            .from_name
            .clone()
            .unwrap_or_else(|| org.from_name.clone()),
        from_email: tenant_override
            .from_email
            .clone()
            .unwrap_or_else(|| org.from_email.clone()),
        reply_to: match &tenant_override.reply_to {
            Some(val) => val.clone(),
            None => org.reply_to.clone(),
        },
        provider: tenant_override
            .provider
            .clone()
            .unwrap_or_else(|| org.provider.clone()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Build an `EmailConfig` from a `SetOrgEmailConfig` input.
pub fn email_config_from_org_input(
    id: Uuid,
    org_id: Uuid,
    input: &SetOrgEmailConfig,
) -> EmailConfig {
    let now = Utc::now();
    EmailConfig {
        id,
        scope: SettingsScope::Org,
        scope_id: org_id,
        enabled: input.enabled,
        from_name: input.from_name.clone(),
        from_email: input.from_email.clone(),
        reply_to: input.reply_to.clone(),
        provider: input.provider.clone(),
        created_at: now,
        updated_at: now,
    }
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_smtp_provider() -> ProviderConfig {
        ProviderConfig::Smtp(SmtpConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            username: "user".to_string(),
            password: "pass".to_string(),
            starttls: true,
        })
    }

    fn sample_org_input() -> SetOrgEmailConfig {
        SetOrgEmailConfig {
            enabled: true,
            from_name: "AXIAM".to_string(),
            from_email: "noreply@example.com".to_string(),
            reply_to: Some("support@example.com".to_string()),
            provider: sample_smtp_provider(),
        }
    }

    fn sample_org_config() -> EmailConfig {
        email_config_from_org_input(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &sample_org_input(),
        )
    }

    // --- validation ---

    #[test]
    fn valid_org_config_passes() {
        assert!(validate_email_config(&sample_org_input()).is_ok());
    }

    #[test]
    fn empty_from_email_fails() {
        let mut input = sample_org_input();
        input.from_email = String::new();
        let err = validate_email_config(&input).unwrap_err();
        assert!(err.to_string().contains("from_email"));
    }

    #[test]
    fn from_email_without_at_fails() {
        let mut input = sample_org_input();
        input.from_email = "not-an-email".to_string();
        let err = validate_email_config(&input).unwrap_err();
        assert!(err.to_string().contains("from_email"));
    }

    #[test]
    fn empty_from_name_fails() {
        let mut input = sample_org_input();
        input.from_name = String::new();
        let err = validate_email_config(&input).unwrap_err();
        assert!(err.to_string().contains("from_name"));
    }

    #[test]
    fn invalid_reply_to_fails() {
        let mut input = sample_org_input();
        input.reply_to = Some("bad".to_string());
        let err = validate_email_config(&input).unwrap_err();
        assert!(err.to_string().contains("reply_to"));
    }

    #[test]
    fn empty_smtp_host_fails() {
        let mut input = sample_org_input();
        input.provider = ProviderConfig::Smtp(SmtpConfig {
            host: String::new(),
            port: 587,
            username: "u".to_string(),
            password: "p".to_string(),
            starttls: true,
        });
        let err = validate_email_config(&input).unwrap_err();
        assert!(err.to_string().contains("SMTP host"));
    }

    #[test]
    fn zero_smtp_port_fails() {
        let mut input = sample_org_input();
        input.provider = ProviderConfig::Smtp(SmtpConfig {
            host: "smtp.example.com".to_string(),
            port: 0,
            username: "u".to_string(),
            password: "p".to_string(),
            starttls: true,
        });
        let err = validate_email_config(&input).unwrap_err();
        assert!(err.to_string().contains("SMTP port"));
    }

    #[test]
    fn empty_api_key_fails() {
        let mut input = sample_org_input();
        input.provider = ProviderConfig::SendGrid(ApiProviderConfig {
            api_key: String::new(),
            api_url: None,
        });
        let err = validate_email_config(&input).unwrap_err();
        assert!(err.to_string().contains("API key"));
    }

    #[test]
    fn valid_api_provider_passes() {
        let mut input = sample_org_input();
        input.provider = ProviderConfig::Resend(ApiProviderConfig {
            api_key: "re_test_123".to_string(),
            api_url: None,
        });
        assert!(validate_email_config(&input).is_ok());
    }

    #[test]
    fn multiple_violations_reported() {
        let mut input = sample_org_input();
        input.from_name = String::new();
        input.from_email = String::new();
        let err = validate_email_config(&input).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("from_name"));
        assert!(msg.contains("from_email"));
    }

    // --- inheritance / merge ---

    #[test]
    fn empty_override_inherits_everything() {
        let org = sample_org_config();
        let overrides = EmailConfigOverride::default();
        let tenant_id = Uuid::new_v4();
        let result_id = Uuid::new_v4();
        let eff =
            effective_email_config(&org, &overrides, tenant_id, result_id);
        assert_eq!(eff.scope, SettingsScope::Tenant);
        assert_eq!(eff.scope_id, tenant_id);
        assert_eq!(eff.from_name, org.from_name);
        assert_eq!(eff.from_email, org.from_email);
        assert_eq!(eff.reply_to, org.reply_to);
        assert_eq!(eff.provider, org.provider);
        assert_eq!(eff.enabled, org.enabled);
    }

    #[test]
    fn override_from_name_applies() {
        let org = sample_org_config();
        let overrides = EmailConfigOverride {
            from_name: Some("Tenant Mail".to_string()),
            ..Default::default()
        };
        let eff = effective_email_config(
            &org,
            &overrides,
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        assert_eq!(eff.from_name, "Tenant Mail");
        assert_eq!(eff.from_email, org.from_email);
    }

    #[test]
    fn override_reply_to_with_none_clears_it() {
        let org = sample_org_config();
        assert!(org.reply_to.is_some());
        let overrides = EmailConfigOverride {
            reply_to: Some(None),
            ..Default::default()
        };
        let eff = effective_email_config(
            &org,
            &overrides,
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        assert_eq!(eff.reply_to, None);
    }

    #[test]
    fn override_provider_replaces_entirely() {
        let org = sample_org_config();
        let new_provider =
            ProviderConfig::SendGrid(ApiProviderConfig {
                api_key: "sg_key_123".to_string(),
                api_url: None,
            });
        let overrides = EmailConfigOverride {
            provider: Some(new_provider.clone()),
            ..Default::default()
        };
        let eff = effective_email_config(
            &org,
            &overrides,
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        assert_eq!(eff.provider, new_provider);
    }

    #[test]
    fn override_disabled_applies() {
        let org = sample_org_config();
        assert!(org.enabled);
        let overrides = EmailConfigOverride {
            enabled: Some(false),
            ..Default::default()
        };
        let eff = effective_email_config(
            &org,
            &overrides,
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        assert!(!eff.enabled);
    }

    // --- builder helpers ---

    #[test]
    fn email_config_from_org_input_sets_scope() {
        let id = Uuid::new_v4();
        let org_id = Uuid::new_v4();
        let config =
            email_config_from_org_input(id, org_id, &sample_org_input());
        assert_eq!(config.id, id);
        assert_eq!(config.scope, SettingsScope::Org);
        assert_eq!(config.scope_id, org_id);
    }

    // --- EmailConfigOverride::is_empty ---

    #[test]
    fn default_override_is_empty() {
        assert!(EmailConfigOverride::default().is_empty());
    }

    #[test]
    fn override_with_value_is_not_empty() {
        let o = EmailConfigOverride {
            enabled: Some(true),
            ..Default::default()
        };
        assert!(!o.is_empty());
    }

    // --- ProviderConfig::kind ---

    #[test]
    fn provider_config_kind_matches() {
        assert_eq!(
            sample_smtp_provider().kind(),
            EmailProviderKind::Smtp,
        );
        let sg = ProviderConfig::SendGrid(ApiProviderConfig {
            api_key: "k".into(),
            api_url: None,
        });
        assert_eq!(sg.kind(), EmailProviderKind::SendGrid);
    }
}
