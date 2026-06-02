//! Email template model with org/tenant customization.
//!
//! Built-in defaults exist for every template kind. Organizations
//! may customize templates. Tenants may further override. Resolution
//! order: tenant custom → org custom → built-in default.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::settings::SettingsScope;
use crate::error::{AxiamError, AxiamResult};

// -----------------------------------------------------------------------
// Template kind enum
// -----------------------------------------------------------------------

/// Which email template this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TemplateKind {
    Activation,
    PasswordReset,
    MfaSetupReminder,
    AdminNotification,
    /// Sent when an account deletion is scheduled (includes cancel link). D-09.
    DeletionScheduled,
    /// Sent when a data-export file is ready for download. D-12.
    ExportReady,
}

impl TemplateKind {
    /// All defined template kinds.
    pub const ALL: &[Self] = &[
        Self::Activation,
        Self::PasswordReset,
        Self::MfaSetupReminder,
        Self::AdminNotification,
        Self::DeletionScheduled,
        Self::ExportReady,
    ];

    /// Return a built-in default template for this kind.
    ///
    /// Placeholder tokens follow the `{{name}}` syntax understood by the
    /// template renderer.  Available tokens per kind:
    /// - `DeletionScheduled`: `username`, `tenant_name`, `action_url` (cancel link), `expiry_time`
    /// - `ExportReady`: `username`, `tenant_name`, `action_url` (download link), `expiry_time`
    pub fn builtin_template(&self) -> (&'static str, &'static str, &'static str) {
        // (subject, html_body, text_body)
        match self {
            Self::DeletionScheduled => (
                "Your account deletion has been scheduled",
                "<p>Hi {{username}},</p>\
                 <p>Your account on <strong>{{tenant_name}}</strong> is scheduled for \
                 deletion on <strong>{{expiry_time}}</strong>.</p>\
                 <p>If you did not request this, \
                 <a href=\"{{action_url}}\">click here to cancel</a> before that date.</p>",
                "Hi {{username}},\n\nYour account on {{tenant_name}} is scheduled for \
                 deletion on {{expiry_time}}.\n\nTo cancel, visit: {{action_url}}",
            ),
            Self::ExportReady => (
                "Your data export is ready",
                "<p>Hi {{username}},</p>\
                 <p>Your data export for <strong>{{tenant_name}}</strong> is ready. \
                 <a href=\"{{action_url}}\">Download it here</a> — the link expires at \
                 <strong>{{expiry_time}}</strong> and can only be used once.</p>",
                "Hi {{username}},\n\nYour data export for {{tenant_name}} is ready.\n\
                 Download: {{action_url}}\nExpires: {{expiry_time}}\nSingle-use link.",
            ),
            _ => ("", "", ""),
        }
    }
}

impl std::fmt::Display for TemplateKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Activation => write!(f, "activation"),
            Self::PasswordReset => write!(f, "password_reset"),
            Self::MfaSetupReminder => write!(f, "mfa_setup_reminder"),
            Self::AdminNotification => write!(f, "admin_notification"),
            Self::DeletionScheduled => write!(f, "deletion_scheduled"),
            Self::ExportReady => write!(f, "export_ready"),
        }
    }
}

impl std::str::FromStr for TemplateKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "activation" => Ok(Self::Activation),
            "password_reset" => Ok(Self::PasswordReset),
            "mfa_setup_reminder" => Ok(Self::MfaSetupReminder),
            "admin_notification" => Ok(Self::AdminNotification),
            "deletion_scheduled" => Ok(Self::DeletionScheduled),
            "export_ready" => Ok(Self::ExportReady),
            other => Err(format!("invalid template kind: {other}")),
        }
    }
}

// -----------------------------------------------------------------------
// Domain type
// -----------------------------------------------------------------------

/// A complete email template (resolved or stored).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EmailTemplate {
    pub id: Uuid,
    pub scope: SettingsScope,
    /// The org_id or tenant_id this template belongs to.
    pub scope_id: Uuid,
    pub kind: TemplateKind,
    /// Subject line (supports `{{placeholder}}` syntax).
    pub subject: String,
    /// HTML body (supports `{{placeholder}}` syntax).
    pub html_body: String,
    /// Plain-text body (supports `{{placeholder}}` syntax).
    pub text_body: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// -----------------------------------------------------------------------
// Input DTO
// -----------------------------------------------------------------------

/// Input for creating or updating a custom email template.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SetEmailTemplate {
    pub kind: TemplateKind,
    pub subject: String,
    pub html_body: String,
    pub text_body: String,
}

// -----------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------

/// Validate a template input.
pub fn validate_email_template(input: &SetEmailTemplate) -> AxiamResult<()> {
    let mut violations = Vec::new();

    if input.subject.trim().is_empty() {
        violations.push("subject must not be empty".to_string());
    }
    if input.html_body.trim().is_empty() {
        violations.push("html_body must not be empty".to_string());
    }
    if input.text_body.trim().is_empty() {
        violations.push("text_body must not be empty".to_string());
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(AxiamError::Validation {
            message: format!("Invalid email template: {}", violations.join("; ")),
        })
    }
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_input() -> SetEmailTemplate {
        SetEmailTemplate {
            kind: TemplateKind::Activation,
            subject: "Activate your account".to_string(),
            html_body: "<h1>Hello {{username}}</h1>".to_string(),
            text_body: "Hello {{username}}".to_string(),
        }
    }

    // --- Display / FromStr round-trip ---

    #[test]
    fn template_kind_round_trip() {
        for kind in TemplateKind::ALL {
            let s = kind.to_string();
            let parsed: TemplateKind = s.parse().unwrap();
            assert_eq!(*kind, parsed);
        }
    }

    #[test]
    fn template_kind_from_str_invalid() {
        let result = "bogus".parse::<TemplateKind>();
        assert!(result.is_err());
    }

    // --- Validation ---

    #[test]
    fn valid_template_passes() {
        assert!(validate_email_template(&valid_input()).is_ok());
    }

    #[test]
    fn empty_subject_fails() {
        let mut input = valid_input();
        input.subject = "  ".to_string();
        let err = validate_email_template(&input).unwrap_err();
        assert!(err.to_string().contains("subject"));
    }

    #[test]
    fn empty_html_body_fails() {
        let mut input = valid_input();
        input.html_body = String::new();
        let err = validate_email_template(&input).unwrap_err();
        assert!(err.to_string().contains("html_body"));
    }

    #[test]
    fn empty_text_body_fails() {
        let mut input = valid_input();
        input.text_body = "   ".to_string();
        let err = validate_email_template(&input).unwrap_err();
        assert!(err.to_string().contains("text_body"));
    }

    #[test]
    fn multiple_violations_reported() {
        let input = SetEmailTemplate {
            kind: TemplateKind::PasswordReset,
            subject: String::new(),
            html_body: String::new(),
            text_body: String::new(),
        };
        let err = validate_email_template(&input).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("subject"));
        assert!(msg.contains("html_body"));
        assert!(msg.contains("text_body"));
    }

    // --- TemplateKind::ALL ---

    #[test]
    fn all_contains_six_kinds() {
        assert_eq!(TemplateKind::ALL.len(), 6);
    }

    #[test]
    fn new_kinds_round_trip() {
        for kind in [TemplateKind::DeletionScheduled, TemplateKind::ExportReady] {
            let s = kind.to_string();
            let parsed: TemplateKind = s.parse().unwrap();
            assert_eq!(kind, parsed);
        }
    }

    #[test]
    fn new_kinds_have_builtin_templates() {
        for kind in [TemplateKind::DeletionScheduled, TemplateKind::ExportReady] {
            let (subj, html, text) = kind.builtin_template();
            assert!(!subj.is_empty());
            assert!(!html.is_empty());
            assert!(!text.is_empty());
        }
    }
}
