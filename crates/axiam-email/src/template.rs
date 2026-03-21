//! Email template engine — built-in defaults, rendering, resolution.
//!
//! Templates use `{{placeholder}}` syntax. Resolution order:
//! tenant custom → org custom → built-in default.

use std::collections::HashMap;

use axiam_core::models::email_template::{EmailTemplate, TemplateKind};
use axiam_core::models::settings::SettingsScope;
use chrono::Utc;
use uuid::Uuid;

use crate::message::EmailMessage;

// -----------------------------------------------------------------------
// Placeholder constants
// -----------------------------------------------------------------------

pub const PH_USERNAME: &str = "username";
pub const PH_EMAIL: &str = "email";
pub const PH_TENANT_NAME: &str = "tenant_name";
pub const PH_ORG_NAME: &str = "org_name";
pub const PH_ACTION_URL: &str = "action_url";
pub const PH_EXPIRY_TIME: &str = "expiry_time";

/// A map of placeholder names to values for template rendering.
pub type TemplateContext = HashMap<String, String>;

// -----------------------------------------------------------------------
// Rendering
// -----------------------------------------------------------------------

/// Replace all `{{key}}` placeholders with values from the context.
///
/// Uses single-pass rendering to prevent template injection: values
/// inserted from the context are never re-processed for further
/// placeholder expansion.  Unknown placeholders are left as-is.
pub fn render(template: &str, context: &TemplateContext) -> String {
    let mut output = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(start) = rest.find("{{") {
        output.push_str(&rest[..start]);
        let after_open = &rest[start + 2..];
        if let Some(end) = after_open.find("}}") {
            let key = &after_open[..end];
            if let Some(value) = context.get(key) {
                output.push_str(value);
            } else {
                // Unknown placeholder — preserve verbatim.
                output.push_str("{{");
                output.push_str(key);
                output.push_str("}}");
            }
            rest = &after_open[end + 2..];
        } else {
            // Unclosed `{{` — emit as literal text.
            output.push_str("{{");
            rest = after_open;
        }
    }
    output.push_str(rest);
    output
}

/// Render a resolved template into an `EmailMessage` ready for delivery.
pub fn render_email(template: &EmailTemplate, to: &str, context: &TemplateContext) -> EmailMessage {
    EmailMessage {
        to: to.to_string(),
        subject: render(&template.subject, context),
        html_body: Some(render(&template.html_body, context)),
        text_body: Some(render(&template.text_body, context)),
    }
}

// -----------------------------------------------------------------------
// Resolution
// -----------------------------------------------------------------------

/// Resolve the effective template: tenant → org → built-in default.
pub fn resolve_template(
    kind: TemplateKind,
    org_template: Option<&EmailTemplate>,
    tenant_template: Option<&EmailTemplate>,
) -> EmailTemplate {
    if let Some(t) = tenant_template {
        return t.clone();
    }
    if let Some(t) = org_template {
        return t.clone();
    }
    builtin_template(kind)
}

// -----------------------------------------------------------------------
// Built-in defaults
// -----------------------------------------------------------------------

/// Return the built-in default template for the given kind.
///
/// Built-in templates use `Uuid::nil()` as ID to signal they are
/// not stored in the database.
pub fn builtin_template(kind: TemplateKind) -> EmailTemplate {
    let now = Utc::now();
    let (subject, html, text) = match kind {
        TemplateKind::Activation => (
            "Activate your {{tenant_name}} account",
            r#"<!DOCTYPE html>
<html><body>
<h1>Welcome, {{username}}!</h1>
<p>Please activate your <strong>{{tenant_name}}</strong> account by clicking the link below:</p>
<p><a href="{{action_url}}">Activate Account</a></p>
<p>This link expires at {{expiry_time}}.</p>
<p>If you did not create this account, you can safely ignore this email.</p>
</body></html>"#,
            "Welcome, {{username}}!\n\n\
             Please activate your {{tenant_name}} account by visiting:\n\
             {{action_url}}\n\n\
             This link expires at {{expiry_time}}.\n\n\
             If you did not create this account, ignore this email.",
        ),
        TemplateKind::PasswordReset => (
            "Reset your password for {{tenant_name}}",
            r#"<!DOCTYPE html>
<html><body>
<h1>Password Reset</h1>
<p>Hi {{username}},</p>
<p>We received a request to reset your password for <strong>{{tenant_name}}</strong>.</p>
<p><a href="{{action_url}}">Reset Password</a></p>
<p>This link expires at {{expiry_time}}.</p>
<p>If you did not request this, you can safely ignore this email.</p>
</body></html>"#,
            "Hi {{username}},\n\n\
             We received a request to reset your password for {{tenant_name}}.\n\
             Visit: {{action_url}}\n\n\
             This link expires at {{expiry_time}}.\n\n\
             If you did not request this, ignore this email.",
        ),
        TemplateKind::MfaSetupReminder => (
            "Set up two-factor authentication for {{tenant_name}}",
            r#"<!DOCTYPE html>
<html><body>
<h1>Secure Your Account</h1>
<p>Hi {{username}},</p>
<p>Your organization requires two-factor authentication for <strong>{{tenant_name}}</strong>.</p>
<p><a href="{{action_url}}">Set Up MFA Now</a></p>
<p>If you have already set up MFA, you can ignore this reminder.</p>
</body></html>"#,
            "Hi {{username}},\n\n\
             Your organization requires two-factor authentication \
             for {{tenant_name}}.\n\
             Set it up here: {{action_url}}\n\n\
             If you have already set up MFA, ignore this reminder.",
        ),
        TemplateKind::AdminNotification => (
            "[{{org_name}}] Admin notification",
            r#"<!DOCTYPE html>
<html><body>
<h1>Admin Notification — {{org_name}}</h1>
<p>An event occurred in <strong>{{tenant_name}}</strong>:</p>
<p>User: {{username}} ({{email}})</p>
<p>Please review the audit log for details.</p>
</body></html>"#,
            "Admin Notification — {{org_name}}\n\n\
             An event occurred in {{tenant_name}}:\n\
             User: {{username}} ({{email}})\n\n\
             Please review the audit log for details.",
        ),
    };

    EmailTemplate {
        id: Uuid::nil(),
        scope: SettingsScope::Org,
        scope_id: Uuid::nil(),
        kind,
        subject: subject.to_string(),
        html_body: html.to_string(),
        text_body: text.to_string(),
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

    fn full_context() -> TemplateContext {
        HashMap::from([
            (PH_USERNAME.into(), "alice".into()),
            (PH_EMAIL.into(), "alice@example.com".into()),
            (PH_TENANT_NAME.into(), "Acme Corp".into()),
            (PH_ORG_NAME.into(), "Acme Org".into()),
            (PH_ACTION_URL.into(), "https://example.com/act".into()),
            (PH_EXPIRY_TIME.into(), "2026-03-20 12:00 UTC".into()),
        ])
    }

    // --- render ---

    #[test]
    fn render_replaces_all_placeholders() {
        let tpl = "Hello {{username}}, your email is {{email}}.";
        let ctx = full_context();
        let out = render(tpl, &ctx);
        assert_eq!(out, "Hello alice, your email is alice@example.com.");
    }

    #[test]
    fn render_leaves_unknown_placeholders() {
        let tpl = "Hello {{unknown_key}}!";
        let ctx = full_context();
        let out = render(tpl, &ctx);
        assert_eq!(out, "Hello {{unknown_key}}!");
    }

    #[test]
    fn render_empty_context_returns_template() {
        let tpl = "Hello {{username}}!";
        let ctx = TemplateContext::new();
        let out = render(tpl, &ctx);
        assert_eq!(out, "Hello {{username}}!");
    }

    #[test]
    fn render_no_placeholders_in_template() {
        let tpl = "No placeholders here.";
        let out = render(tpl, &full_context());
        assert_eq!(out, "No placeholders here.");
    }

    #[test]
    fn render_multiple_occurrences() {
        let tpl = "{{username}} and {{username}} again.";
        let out = render(tpl, &full_context());
        assert_eq!(out, "alice and alice again.");
    }

    #[test]
    fn render_resists_template_injection() {
        // A user-controlled value containing a placeholder must NOT be
        // expanded — single-pass rendering prevents this.
        let mut ctx = TemplateContext::new();
        ctx.insert("username".into(), "{{action_url}}".into());
        ctx.insert("action_url".into(), "https://evil.com".into());
        let tpl = "Hello {{username}}!";
        let out = render(tpl, &ctx);
        assert_eq!(
            out, "Hello {{action_url}}!",
            "injected placeholder must not expand"
        );
    }

    #[test]
    fn render_handles_unclosed_braces() {
        let tpl = "Hello {{ world";
        let out = render(tpl, &TemplateContext::new());
        assert_eq!(out, "Hello {{ world");
    }

    // --- resolve_template ---

    #[test]
    fn resolve_returns_tenant_when_present() {
        let org = builtin_template(TemplateKind::Activation);
        let mut tenant = org.clone();
        tenant.subject = "Tenant subject".into();
        let resolved = resolve_template(TemplateKind::Activation, Some(&org), Some(&tenant));
        assert_eq!(resolved.subject, "Tenant subject");
    }

    #[test]
    fn resolve_falls_back_to_org() {
        let mut org = builtin_template(TemplateKind::Activation);
        org.subject = "Org subject".into();
        let resolved = resolve_template(TemplateKind::Activation, Some(&org), None);
        assert_eq!(resolved.subject, "Org subject");
    }

    #[test]
    fn resolve_falls_back_to_builtin() {
        let resolved = resolve_template(TemplateKind::Activation, None, None);
        assert_eq!(resolved.id, Uuid::nil());
        assert!(resolved.subject.contains("{{tenant_name}}"));
    }

    // --- builtin_template ---

    #[test]
    fn all_builtins_have_non_empty_content() {
        for kind in TemplateKind::ALL {
            let t = builtin_template(*kind);
            assert!(!t.subject.is_empty(), "{kind} subject empty");
            assert!(!t.html_body.is_empty(), "{kind} html empty");
            assert!(!t.text_body.is_empty(), "{kind} text empty");
        }
    }

    #[test]
    fn builtin_activation_renders_with_context() {
        let t = builtin_template(TemplateKind::Activation);
        let ctx = full_context();
        let subject = render(&t.subject, &ctx);
        assert!(subject.contains("Acme Corp"));
        assert!(!subject.contains("{{"));
        let html = render(&t.html_body, &ctx);
        assert!(html.contains("alice"));
        assert!(html.contains("https://example.com/act"));
    }

    #[test]
    fn builtin_password_reset_renders_with_context() {
        let t = builtin_template(TemplateKind::PasswordReset);
        let ctx = full_context();
        let text = render(&t.text_body, &ctx);
        assert!(text.contains("alice"));
        assert!(text.contains("Acme Corp"));
        assert!(!text.contains("{{"));
    }

    #[test]
    fn builtin_mfa_renders_with_context() {
        let t = builtin_template(TemplateKind::MfaSetupReminder);
        let ctx = full_context();
        let html = render(&t.html_body, &ctx);
        assert!(html.contains("alice"));
        assert!(html.contains("Acme Corp"));
    }

    #[test]
    fn builtin_admin_renders_with_context() {
        let t = builtin_template(TemplateKind::AdminNotification);
        let ctx = full_context();
        let text = render(&t.text_body, &ctx);
        assert!(text.contains("Acme Org"));
        assert!(text.contains("alice@example.com"));
    }

    // --- render_email ---

    #[test]
    fn render_email_produces_correct_message() {
        let t = builtin_template(TemplateKind::Activation);
        let ctx = full_context();
        let msg = render_email(&t, "user@test.com", &ctx);
        assert_eq!(msg.to, "user@test.com");
        assert!(msg.subject.contains("Acme Corp"));
        assert!(msg.html_body.unwrap().contains("alice"));
        assert!(msg.text_body.unwrap().contains("alice"));
    }
}
