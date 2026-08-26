//! Notification rule model for admin email notifications on critical events.
//!
//! Notification rules allow tenant administrators to configure which
//! events trigger email alerts and who receives them.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// -----------------------------------------------------------------------
// Notification event type enum
// -----------------------------------------------------------------------

/// Events that can trigger an admin notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum NotificationEventType {
    // Security events
    LoginFailure,
    AccountLocked,
    MfaEnrollmentChanged,
    PasswordChanged,
    PasswordResetRequested,
    // Privilege events
    RoleAssigned,
    RoleUnassigned,
    PermissionGranted,
    PermissionRevoked,
    // Certificate events
    CertificateIssued,
    CertificateRevoked,
    CaCertificateRevoked,
    // User lifecycle events
    UserCreated,
    UserDeleted,
    UserUpdated,
    ServiceAccountCreated,
    ServiceAccountDeleted,
}

impl NotificationEventType {
    /// All defined notification event types.
    pub const ALL: &[Self] = &[
        Self::LoginFailure,
        Self::AccountLocked,
        Self::MfaEnrollmentChanged,
        Self::PasswordChanged,
        Self::PasswordResetRequested,
        Self::RoleAssigned,
        Self::RoleUnassigned,
        Self::PermissionGranted,
        Self::PermissionRevoked,
        Self::CertificateIssued,
        Self::CertificateRevoked,
        Self::CaCertificateRevoked,
        Self::UserCreated,
        Self::UserDeleted,
        Self::UserUpdated,
        Self::ServiceAccountCreated,
        Self::ServiceAccountDeleted,
    ];

    /// String representation suitable for SurrealDB storage.
    pub fn to_db_string(self) -> String {
        self.to_string()
    }

    /// Map an audit action + outcome pair to notification event types.
    ///
    /// A single audit action may map to zero or more event types. For
    /// example, a login failure maps to `LoginFailure`, while a
    /// successful user creation maps to `UserCreated`.
    ///
    /// Audit middleware records actions with actual request paths (e.g.
    /// `POST /api/v1/users/9d2f…`). This method normalises dynamic
    /// path segments (UUIDs, hex IDs) to `{id}` before matching, so
    /// both route templates and real paths are handled correctly.
    ///
    /// # The paths must be the ones actually served
    ///
    /// Five arms of this table used to read `/auth/…` while every auth route is
    /// mounted under `/api/v1/auth/…` (see `axiam-api-rest`'s `auth_scope`), so
    /// `login_failure`, `account_locked`, `password_changed`,
    /// `password_reset_requested` and `mfa_enrollment_changed` — the five
    /// security events an administrator is most likely to want an alert for —
    /// could never match anything. A prefix that is merely *plausible* is not
    /// checked by the compiler; `notification_event_paths_match_served_routes`
    /// in `axiam-api-rest`'s tests is what checks it now.
    pub fn from_audit_action(action: &str, outcome: &str) -> Vec<Self> {
        let normalised = normalise_audit_action(action);
        match (normalised.as_str(), outcome) {
            // Security events
            ("POST /api/v1/auth/login", "Failure") => {
                vec![Self::LoginFailure]
            }
            ("POST /api/v1/auth/login", "Denied") => {
                vec![Self::AccountLocked]
            }
            ("POST /api/v1/auth/mfa/enroll", "Success")
            | ("POST /api/v1/auth/mfa/confirm", "Success")
            | ("POST /api/v1/auth/mfa/setup/confirm", "Success") => {
                vec![Self::MfaEnrollmentChanged]
            }
            ("PUT /api/v1/users/{id}", "Success") => {
                // Password changes are tracked via a dedicated action
                vec![Self::UserUpdated]
            }
            ("POST /api/v1/auth/reset/confirm", "Success") => {
                vec![Self::PasswordChanged]
            }
            ("POST /api/v1/auth/reset", "Success") => {
                vec![Self::PasswordResetRequested]
            }
            // Privilege events
            ("POST /api/v1/roles/{id}/users", "Success") => {
                vec![Self::RoleAssigned]
            }
            ("DELETE /api/v1/roles/{id}/users/{id}", "Success") => vec![Self::RoleUnassigned],
            ("POST /api/v1/roles/{id}/permissions", "Success") => {
                vec![Self::PermissionGranted]
            }
            ("DELETE /api/v1/roles/{id}/permissions/{id}", "Success") => {
                vec![Self::PermissionRevoked]
            }
            // Certificate events
            ("POST /api/v1/certificates", "Success") => {
                vec![Self::CertificateIssued]
            }
            ("POST /api/v1/certificates/{id}/revoke", "Success") => vec![Self::CertificateRevoked],
            ("POST /api/v1/organizations/{id}/ca-certificates/{id}/revoke", "Success") => {
                vec![Self::CaCertificateRevoked]
            }
            // User lifecycle events
            ("POST /api/v1/users", "Success") => {
                vec![Self::UserCreated]
            }
            ("DELETE /api/v1/users/{id}", "Success") => {
                vec![Self::UserDeleted]
            }
            ("POST /api/v1/service-accounts", "Success") => {
                vec![Self::ServiceAccountCreated]
            }
            ("DELETE /api/v1/service-accounts/{id}", "Success") => {
                vec![Self::ServiceAccountDeleted]
            }
            _ => vec![],
        }
    }
}

/// Normalise an audit action string by replacing dynamic path segments
/// (UUIDs, hex strings of 8+ chars) with the placeholder `{id}`.
///
/// This lets the match table use a single canonical form regardless
/// of whether the action was recorded with the route template
/// (`/users/{user_id}`) or the real path (`/users/9d2f3a…`).
fn normalise_audit_action(action: &str) -> String {
    // Split on first space to separate method from path.
    let (method, path) = match action.split_once(' ') {
        Some(pair) => pair,
        None => return action.to_string(),
    };

    let normalised_segments: Vec<&str> = path
        .split('/')
        .map(|seg| if is_dynamic_segment(seg) { "{id}" } else { seg })
        .collect();

    format!("{method} {}", normalised_segments.join("/"))
}

/// Returns `true` if a path segment looks like a dynamic ID:
/// - a UUID (8-4-4-4-12 hex with dashes), or
/// - a hex string of 8+ characters, or
/// - any `{...}` route template placeholder.
fn is_dynamic_segment(seg: &str) -> bool {
    if seg.is_empty() {
        return false;
    }
    // Route-template placeholders like `{user_id}`
    if seg.starts_with('{') && seg.ends_with('}') {
        return true;
    }
    // UUID: 32 hex + 4 dashes = 36 chars
    if seg.len() == 36 && seg.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return true;
    }
    // Hex string of 8+ chars (covers short IDs, SurrealDB record IDs)
    seg.len() >= 8 && seg.chars().all(|c| c.is_ascii_hexdigit())
}

impl std::fmt::Display for NotificationEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LoginFailure => write!(f, "login_failure"),
            Self::AccountLocked => write!(f, "account_locked"),
            Self::MfaEnrollmentChanged => {
                write!(f, "mfa_enrollment_changed")
            }
            Self::PasswordChanged => write!(f, "password_changed"),
            Self::PasswordResetRequested => {
                write!(f, "password_reset_requested")
            }
            Self::RoleAssigned => write!(f, "role_assigned"),
            Self::RoleUnassigned => write!(f, "role_unassigned"),
            Self::PermissionGranted => {
                write!(f, "permission_granted")
            }
            Self::PermissionRevoked => {
                write!(f, "permission_revoked")
            }
            Self::CertificateIssued => {
                write!(f, "certificate_issued")
            }
            Self::CertificateRevoked => {
                write!(f, "certificate_revoked")
            }
            Self::CaCertificateRevoked => {
                write!(f, "ca_certificate_revoked")
            }
            Self::UserCreated => write!(f, "user_created"),
            Self::UserDeleted => write!(f, "user_deleted"),
            Self::UserUpdated => write!(f, "user_updated"),
            Self::ServiceAccountCreated => {
                write!(f, "service_account_created")
            }
            Self::ServiceAccountDeleted => {
                write!(f, "service_account_deleted")
            }
        }
    }
}

impl std::str::FromStr for NotificationEventType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "login_failure" => Ok(Self::LoginFailure),
            "account_locked" => Ok(Self::AccountLocked),
            "mfa_enrollment_changed" => Ok(Self::MfaEnrollmentChanged),
            "password_changed" => Ok(Self::PasswordChanged),
            "password_reset_requested" => Ok(Self::PasswordResetRequested),
            "role_assigned" => Ok(Self::RoleAssigned),
            "role_unassigned" => Ok(Self::RoleUnassigned),
            "permission_granted" => Ok(Self::PermissionGranted),
            "permission_revoked" => Ok(Self::PermissionRevoked),
            "certificate_issued" => Ok(Self::CertificateIssued),
            "certificate_revoked" => Ok(Self::CertificateRevoked),
            "ca_certificate_revoked" => Ok(Self::CaCertificateRevoked),
            "user_created" => Ok(Self::UserCreated),
            "user_deleted" => Ok(Self::UserDeleted),
            "user_updated" => Ok(Self::UserUpdated),
            "service_account_created" => Ok(Self::ServiceAccountCreated),
            "service_account_deleted" => Ok(Self::ServiceAccountDeleted),
            other => Err(format!("invalid notification event type: {other}")),
        }
    }
}

// -----------------------------------------------------------------------
// Domain types
// -----------------------------------------------------------------------

/// A notification rule that determines which events trigger admin emails.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NotificationRule {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: String,
    pub events: Vec<NotificationEventType>,
    pub recipient_emails: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Input for creating a notification rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNotificationRule {
    pub tenant_id: Uuid,
    pub name: String,
    pub description: String,
    pub events: Vec<NotificationEventType>,
    pub recipient_emails: Vec<String>,
}

/// Input for updating a notification rule. All fields are optional.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateNotificationRule {
    pub name: Option<String>,
    pub description: Option<String>,
    pub events: Option<Vec<NotificationEventType>>,
    pub recipient_emails: Option<Vec<String>>,
    pub enabled: Option<bool>,
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_type_display_from_str_roundtrip() {
        for kind in NotificationEventType::ALL {
            let s = kind.to_string();
            let parsed: NotificationEventType = s.parse().unwrap();
            assert_eq!(*kind, parsed);
        }
    }

    #[test]
    fn all_constant_complete() {
        // 17 variants total
        assert_eq!(NotificationEventType::ALL.len(), 17);
    }

    #[test]
    fn from_audit_action_login_failure() {
        // The path the audit middleware actually records — the auth routes are
        // mounted under `/api/v1/auth`, and this arm used to read `/auth/login`,
        // which nothing ever produced.
        let events = NotificationEventType::from_audit_action("POST /api/v1/auth/login", "Failure");
        assert_eq!(events, vec![NotificationEventType::LoginFailure]);
    }

    #[test]
    fn every_unauthenticated_security_event_matches_its_served_path() {
        // The five arms that were unreachable. Each is asserted against the
        // exact string `AuditMiddleware` builds — `"{method} {path}"` with the
        // path as served — because a plausible-looking prefix is exactly the
        // kind of mistake that compiles and then silently matches nothing.
        for (action, outcome, expected) in [
            (
                "POST /api/v1/auth/login",
                "Denied",
                NotificationEventType::AccountLocked,
            ),
            (
                "POST /api/v1/auth/reset",
                "Success",
                NotificationEventType::PasswordResetRequested,
            ),
            (
                "POST /api/v1/auth/reset/confirm",
                "Success",
                NotificationEventType::PasswordChanged,
            ),
            (
                "POST /api/v1/auth/mfa/enroll",
                "Success",
                NotificationEventType::MfaEnrollmentChanged,
            ),
            (
                "POST /api/v1/auth/mfa/confirm",
                "Success",
                NotificationEventType::MfaEnrollmentChanged,
            ),
        ] {
            assert_eq!(
                NotificationEventType::from_audit_action(action, outcome),
                vec![expected],
                "`{action}` ({outcome}) must map to {expected}"
            );
        }
    }

    #[test]
    fn the_old_unprefixed_auth_paths_match_nothing() {
        // Pins the direction of the fix: if someone "restores" the short form,
        // this fails rather than quietly reintroducing five dead rules.
        for action in [
            "POST /auth/login",
            "POST /auth/reset",
            "POST /auth/reset/confirm",
            "POST /auth/mfa/enroll",
        ] {
            assert!(
                NotificationEventType::from_audit_action(action, "Success").is_empty()
                    && NotificationEventType::from_audit_action(action, "Failure").is_empty(),
                "`{action}` is not a path this server serves"
            );
        }
    }

    #[test]
    fn from_audit_action_user_created() {
        let events = NotificationEventType::from_audit_action("POST /api/v1/users", "Success");
        assert_eq!(events, vec![NotificationEventType::UserCreated]);
    }

    #[test]
    fn from_audit_action_with_real_uuid_path() {
        // Audit middleware records actual UUIDs — must still match.
        let events = NotificationEventType::from_audit_action(
            "DELETE /api/v1/users/9d2f3a7b-1c4e-4f8a-b2d6-5e9f1a3c7b8d",
            "Success",
        );
        assert_eq!(events, vec![NotificationEventType::UserDeleted]);
    }

    #[test]
    fn from_audit_action_with_real_uuid_nested_path() {
        let events = NotificationEventType::from_audit_action(
            "DELETE /api/v1/roles/aabbccdd-1122-3344-5566-778899aabbcc/users/11223344-5566-7788-99aa-bbccddeeff00",
            "Success",
        );
        assert_eq!(events, vec![NotificationEventType::RoleUnassigned]);
    }

    #[test]
    fn from_audit_action_with_route_template() {
        // Route templates like `{user_id}` must also normalise.
        let events =
            NotificationEventType::from_audit_action("PUT /api/v1/users/{user_id}", "Success");
        assert_eq!(events, vec![NotificationEventType::UserUpdated]);
    }

    #[test]
    fn from_audit_action_unknown() {
        let events =
            NotificationEventType::from_audit_action("GET /api/v1/something-random", "Success");
        assert!(events.is_empty());
    }

    #[test]
    fn normalise_preserves_static_segments() {
        assert_eq!(
            normalise_audit_action("POST /api/v1/users"),
            "POST /api/v1/users"
        );
    }

    #[test]
    fn normalise_replaces_uuid_segments() {
        assert_eq!(
            normalise_audit_action("DELETE /api/v1/users/9d2f3a7b-1c4e-4f8a-b2d6-5e9f1a3c7b8d"),
            "DELETE /api/v1/users/{id}"
        );
    }

    #[test]
    fn normalise_replaces_template_placeholders() {
        assert_eq!(
            normalise_audit_action("PUT /api/v1/users/{user_id}"),
            "PUT /api/v1/users/{id}"
        );
    }

    #[test]
    fn to_db_string_matches_display() {
        for kind in NotificationEventType::ALL {
            assert_eq!(kind.to_db_string(), kind.to_string());
        }
    }

    #[test]
    fn from_str_invalid_returns_error() {
        let result = "bogus".parse::<NotificationEventType>();
        assert!(result.is_err());
    }
}
