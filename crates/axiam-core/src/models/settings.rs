//! Security settings model with org/tenant inheritance.
//!
//! Organizations set a security baseline. Tenants may override
//! settings, but only to be **more restrictive** (never weaker).
//! The effective settings for a tenant = org baseline merged with
//! tenant overrides.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AxiamError, AxiamResult};

// -----------------------------------------------------------------------
// Sub-policy structs
// -----------------------------------------------------------------------

/// Password complexity and history requirements.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PasswordPolicy {
    pub min_length: u32,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digits: bool,
    pub require_symbols: bool,
    pub password_history_count: u32,
    pub hibp_check_enabled: bool,
}

/// Multi-factor authentication policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MfaPolicy {
    pub mfa_enforced: bool,
    pub mfa_challenge_lifetime_secs: u64,
}

/// Account lockout rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LockoutPolicy {
    pub max_failed_login_attempts: u32,
    pub lockout_duration_secs: u64,
    pub lockout_backoff_multiplier: f64,
    pub max_lockout_duration_secs: u64,
}

/// Token lifetime configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TokenPolicy {
    pub access_token_lifetime_secs: u64,
    pub refresh_token_lifetime_secs: u64,
}

/// Email verification requirements.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EmailVerificationPolicy {
    pub email_verification_required: bool,
    pub email_verification_grace_period_hours: u32,
}

/// Certificate issuance constraints.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CertificatePolicy {
    pub default_cert_validity_days: u32,
    pub max_cert_validity_days: u32,
}

/// Admin notification preferences.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NotificationPolicy {
    pub admin_notifications_enabled: bool,
}

// -----------------------------------------------------------------------
// Scope enum
// -----------------------------------------------------------------------

/// Whether a settings row belongs to an organization or a tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum SettingsScope {
    Org,
    Tenant,
}

impl std::fmt::Display for SettingsScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Org => write!(f, "org"),
            Self::Tenant => write!(f, "tenant"),
        }
    }
}

impl std::str::FromStr for SettingsScope {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "org" => Ok(Self::Org),
            "tenant" => Ok(Self::Tenant),
            other => Err(format!("invalid settings scope: {other}")),
        }
    }
}

// -----------------------------------------------------------------------
// Main domain type — fully resolved
// -----------------------------------------------------------------------

/// Fully resolved security settings (all fields present).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SecuritySettings {
    pub id: Uuid,
    pub scope: SettingsScope,
    pub scope_id: Uuid,
    pub password: PasswordPolicy,
    pub mfa: MfaPolicy,
    pub lockout: LockoutPolicy,
    pub token: TokenPolicy,
    pub email: EmailVerificationPolicy,
    pub certificate: CertificatePolicy,
    pub notification: NotificationPolicy,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// -----------------------------------------------------------------------
// Tenant override — all Option<T> for partial overrides
// -----------------------------------------------------------------------

/// Partial tenant overrides. `None` = inherit from org baseline.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TenantSettingsOverride {
    // Password
    pub min_length: Option<u32>,
    pub require_uppercase: Option<bool>,
    pub require_lowercase: Option<bool>,
    pub require_digits: Option<bool>,
    pub require_symbols: Option<bool>,
    pub password_history_count: Option<u32>,
    pub hibp_check_enabled: Option<bool>,
    // MFA
    pub mfa_enforced: Option<bool>,
    pub mfa_challenge_lifetime_secs: Option<u64>,
    // Lockout
    pub max_failed_login_attempts: Option<u32>,
    pub lockout_duration_secs: Option<u64>,
    pub lockout_backoff_multiplier: Option<f64>,
    pub max_lockout_duration_secs: Option<u64>,
    // Token
    pub access_token_lifetime_secs: Option<u64>,
    pub refresh_token_lifetime_secs: Option<u64>,
    // Email
    pub email_verification_required: Option<bool>,
    pub email_verification_grace_period_hours: Option<u32>,
    // Certificate
    pub default_cert_validity_days: Option<u32>,
    pub max_cert_validity_days: Option<u32>,
    // Notification
    pub admin_notifications_enabled: Option<bool>,
}

impl TenantSettingsOverride {
    /// Returns `true` if every field is `None` (no overrides).
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

// -----------------------------------------------------------------------
// Input DTOs
// -----------------------------------------------------------------------

/// Input for setting organization-level security settings.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SetOrgSettings {
    // Password
    pub min_length: u32,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digits: bool,
    pub require_symbols: bool,
    pub password_history_count: u32,
    pub hibp_check_enabled: bool,
    // MFA
    pub mfa_enforced: bool,
    pub mfa_challenge_lifetime_secs: u64,
    // Lockout
    pub max_failed_login_attempts: u32,
    pub lockout_duration_secs: u64,
    pub lockout_backoff_multiplier: f64,
    pub max_lockout_duration_secs: u64,
    // Token
    pub access_token_lifetime_secs: u64,
    pub refresh_token_lifetime_secs: u64,
    // Email
    pub email_verification_required: bool,
    pub email_verification_grace_period_hours: u32,
    // Certificate
    pub default_cert_validity_days: u32,
    pub max_cert_validity_days: u32,
    // Notification
    pub admin_notifications_enabled: bool,
}

/// Input for setting tenant-level overrides (partial).
pub type SetTenantOverride = TenantSettingsOverride;

// -----------------------------------------------------------------------
// System defaults (OWASP-aligned, matching AuthConfig::default)
// -----------------------------------------------------------------------

/// OWASP-aligned system defaults matching the current `AuthConfig`.
pub fn system_defaults() -> SetOrgSettings {
    SetOrgSettings {
        // Password — OWASP ASVS v4.0 §2.1
        min_length: 12,
        require_uppercase: true,
        require_lowercase: true,
        require_digits: true,
        require_symbols: false,
        password_history_count: 5,
        hibp_check_enabled: true,
        // MFA
        mfa_enforced: false,
        mfa_challenge_lifetime_secs: 300,
        // Lockout — OWASP ASVS §2.2
        max_failed_login_attempts: 5,
        lockout_duration_secs: 300,
        lockout_backoff_multiplier: 2.0,
        max_lockout_duration_secs: 3600,
        // Token — short-lived access, 30-day refresh
        access_token_lifetime_secs: 900,
        refresh_token_lifetime_secs: 2_592_000,
        // Email
        email_verification_required: true,
        email_verification_grace_period_hours: 24,
        // Certificate
        default_cert_validity_days: 365,
        max_cert_validity_days: 730,
        // Notification
        admin_notifications_enabled: true,
    }
}

// -----------------------------------------------------------------------
// Org settings validation (internal invariants)
// -----------------------------------------------------------------------

/// Validate internal invariants of organization-level settings.
///
/// Checks relationships between fields (e.g., max >= min) and rejects
/// obviously invalid values (zero lifetimes where required).
pub fn validate_org_settings(input: &SetOrgSettings) -> AxiamResult<()> {
    let mut violations = Vec::new();

    if input.max_lockout_duration_secs < input.lockout_duration_secs {
        violations.push(format!(
            "max_lockout_duration_secs ({}) must be >= \
             lockout_duration_secs ({})",
            input.max_lockout_duration_secs, input.lockout_duration_secs,
        ));
    }

    if input.max_cert_validity_days < input.default_cert_validity_days {
        violations.push(format!(
            "max_cert_validity_days ({}) must be >= \
             default_cert_validity_days ({})",
            input.max_cert_validity_days, input.default_cert_validity_days,
        ));
    }

    if input.lockout_backoff_multiplier < 1.0 {
        violations.push(format!(
            "lockout_backoff_multiplier ({}) must be >= 1.0",
            input.lockout_backoff_multiplier,
        ));
    }

    if input.access_token_lifetime_secs == 0 {
        violations.push("access_token_lifetime_secs must be > 0".into());
    }

    if input.refresh_token_lifetime_secs == 0 {
        violations.push("refresh_token_lifetime_secs must be > 0".into());
    }

    if input.mfa_challenge_lifetime_secs == 0 {
        violations.push("mfa_challenge_lifetime_secs must be > 0".into());
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(AxiamError::Validation {
            message: format!("Invalid org settings: {}", violations.join("; "),),
        })
    }
}

// -----------------------------------------------------------------------
// Inheritance engine — pure functions
// -----------------------------------------------------------------------

/// Merge org baseline with tenant overrides to produce effective settings.
///
/// Any `Some` field in the override replaces the org baseline value.
/// `None` fields inherit from the org baseline unchanged.
pub fn effective_settings(
    org: &SecuritySettings,
    tenant_override: &TenantSettingsOverride,
    tenant_id: Uuid,
    result_id: Uuid,
) -> SecuritySettings {
    SecuritySettings {
        id: result_id,
        scope: SettingsScope::Tenant,
        scope_id: tenant_id,
        password: PasswordPolicy {
            min_length: tenant_override
                .min_length
                .unwrap_or(org.password.min_length),
            require_uppercase: tenant_override
                .require_uppercase
                .unwrap_or(org.password.require_uppercase),
            require_lowercase: tenant_override
                .require_lowercase
                .unwrap_or(org.password.require_lowercase),
            require_digits: tenant_override
                .require_digits
                .unwrap_or(org.password.require_digits),
            require_symbols: tenant_override
                .require_symbols
                .unwrap_or(org.password.require_symbols),
            password_history_count: tenant_override
                .password_history_count
                .unwrap_or(org.password.password_history_count),
            hibp_check_enabled: tenant_override
                .hibp_check_enabled
                .unwrap_or(org.password.hibp_check_enabled),
        },
        mfa: MfaPolicy {
            mfa_enforced: tenant_override.mfa_enforced.unwrap_or(org.mfa.mfa_enforced),
            mfa_challenge_lifetime_secs: tenant_override
                .mfa_challenge_lifetime_secs
                .unwrap_or(org.mfa.mfa_challenge_lifetime_secs),
        },
        lockout: LockoutPolicy {
            max_failed_login_attempts: tenant_override
                .max_failed_login_attempts
                .unwrap_or(org.lockout.max_failed_login_attempts),
            lockout_duration_secs: tenant_override
                .lockout_duration_secs
                .unwrap_or(org.lockout.lockout_duration_secs),
            lockout_backoff_multiplier: tenant_override
                .lockout_backoff_multiplier
                .unwrap_or(org.lockout.lockout_backoff_multiplier),
            max_lockout_duration_secs: tenant_override
                .max_lockout_duration_secs
                .unwrap_or(org.lockout.max_lockout_duration_secs),
        },
        token: TokenPolicy {
            access_token_lifetime_secs: tenant_override
                .access_token_lifetime_secs
                .unwrap_or(org.token.access_token_lifetime_secs),
            refresh_token_lifetime_secs: tenant_override
                .refresh_token_lifetime_secs
                .unwrap_or(org.token.refresh_token_lifetime_secs),
        },
        email: EmailVerificationPolicy {
            email_verification_required: tenant_override
                .email_verification_required
                .unwrap_or(org.email.email_verification_required),
            email_verification_grace_period_hours: tenant_override
                .email_verification_grace_period_hours
                .unwrap_or(org.email.email_verification_grace_period_hours),
        },
        certificate: CertificatePolicy {
            default_cert_validity_days: tenant_override
                .default_cert_validity_days
                .unwrap_or(org.certificate.default_cert_validity_days),
            max_cert_validity_days: tenant_override
                .max_cert_validity_days
                .unwrap_or(org.certificate.max_cert_validity_days),
        },
        notification: NotificationPolicy {
            admin_notifications_enabled: tenant_override
                .admin_notifications_enabled
                .unwrap_or(org.notification.admin_notifications_enabled),
        },
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Validate that a tenant override is only **more restrictive** than
/// the org baseline. Collects all violations into one error message.
///
/// Rules:
/// - `tenant >= org` for: min_length, password_history_count,
///   lockout_duration_secs, lockout_backoff_multiplier,
///   max_lockout_duration_secs
/// - `tenant <= org` for: max_failed_login_attempts,
///   access_token_lifetime_secs, refresh_token_lifetime_secs,
///   mfa_challenge_lifetime_secs, default_cert_validity_days,
///   max_cert_validity_days, email_verification_grace_period_hours
/// - enable-only (false->true OK, true->false NOT OK):
///   require_uppercase/lowercase/digits/symbols, mfa_enforced,
///   hibp_check_enabled, email_verification_required,
///   admin_notifications_enabled
pub fn validate_tenant_override(
    org: &SecuritySettings,
    overrides: &TenantSettingsOverride,
) -> AxiamResult<()> {
    let mut violations = Vec::new();

    // --- tenant >= org (higher minimum is more restrictive) ---
    macro_rules! check_min {
        ($field:ident, $org_path:expr, $label:expr) => {
            if let Some(val) = overrides.$field {
                if val < $org_path {
                    violations.push(format!(
                        "{}: tenant value {} is less restrictive \
                         than org baseline {}",
                        $label, val, $org_path,
                    ));
                }
            }
        };
    }

    check_min!(min_length, org.password.min_length, "min_length");
    check_min!(
        password_history_count,
        org.password.password_history_count,
        "password_history_count"
    );
    check_min!(
        lockout_duration_secs,
        org.lockout.lockout_duration_secs,
        "lockout_duration_secs"
    );
    check_min!(
        max_lockout_duration_secs,
        org.lockout.max_lockout_duration_secs,
        "max_lockout_duration_secs"
    );

    // lockout_backoff_multiplier (f64 — compare with partial_cmp)
    if let Some(val) = overrides.lockout_backoff_multiplier
        && val < org.lockout.lockout_backoff_multiplier
    {
        violations.push(format!(
            "lockout_backoff_multiplier: tenant value {} is \
             less restrictive than org baseline {}",
            val, org.lockout.lockout_backoff_multiplier,
        ));
    }

    // --- tenant <= org (lower max / shorter lifetime is more restrictive) ---
    macro_rules! check_max {
        ($field:ident, $org_path:expr, $label:expr) => {
            if let Some(val) = overrides.$field {
                if val > $org_path {
                    violations.push(format!(
                        "{}: tenant value {} is less restrictive \
                         than org baseline {}",
                        $label, val, $org_path,
                    ));
                }
            }
        };
    }

    check_max!(
        max_failed_login_attempts,
        org.lockout.max_failed_login_attempts,
        "max_failed_login_attempts"
    );
    check_max!(
        access_token_lifetime_secs,
        org.token.access_token_lifetime_secs,
        "access_token_lifetime_secs"
    );
    check_max!(
        refresh_token_lifetime_secs,
        org.token.refresh_token_lifetime_secs,
        "refresh_token_lifetime_secs"
    );
    check_max!(
        mfa_challenge_lifetime_secs,
        org.mfa.mfa_challenge_lifetime_secs,
        "mfa_challenge_lifetime_secs"
    );
    check_max!(
        default_cert_validity_days,
        org.certificate.default_cert_validity_days,
        "default_cert_validity_days"
    );
    check_max!(
        max_cert_validity_days,
        org.certificate.max_cert_validity_days,
        "max_cert_validity_days"
    );
    check_max!(
        email_verification_grace_period_hours,
        org.email.email_verification_grace_period_hours,
        "email_verification_grace_period_hours"
    );

    // --- enable-only (false->true OK, true->false NOT OK) ---
    macro_rules! check_enable_only {
        ($field:ident, $org_val:expr, $label:expr) => {
            if let Some(val) = overrides.$field {
                if $org_val && !val {
                    violations.push(format!(
                        "{}: cannot disable at tenant level when \
                         enabled at org level",
                        $label,
                    ));
                }
            }
        };
    }

    check_enable_only!(
        require_uppercase,
        org.password.require_uppercase,
        "require_uppercase"
    );
    check_enable_only!(
        require_lowercase,
        org.password.require_lowercase,
        "require_lowercase"
    );
    check_enable_only!(
        require_digits,
        org.password.require_digits,
        "require_digits"
    );
    check_enable_only!(
        require_symbols,
        org.password.require_symbols,
        "require_symbols"
    );
    check_enable_only!(mfa_enforced, org.mfa.mfa_enforced, "mfa_enforced");
    check_enable_only!(
        hibp_check_enabled,
        org.password.hibp_check_enabled,
        "hibp_check_enabled"
    );
    check_enable_only!(
        email_verification_required,
        org.email.email_verification_required,
        "email_verification_required"
    );
    check_enable_only!(
        admin_notifications_enabled,
        org.notification.admin_notifications_enabled,
        "admin_notifications_enabled"
    );

    if !violations.is_empty() {
        return Err(AxiamError::Validation {
            message: format!(
                "Tenant override violates org baseline: {}",
                violations.join("; "),
            ),
        });
    }

    // Cross-field invariant check: merge org + overrides and verify
    // the effective policy is internally consistent.
    let merged = effective_settings(org, overrides, Uuid::nil(), Uuid::nil());
    let mut cross = Vec::new();

    // Non-zero lifetime invariants (0 passes "more restrictive" checks
    // but produces an unusable policy).
    if merged.token.access_token_lifetime_secs == 0 {
        cross.push("effective access_token_lifetime_secs must be > 0".into());
    }
    if merged.token.refresh_token_lifetime_secs == 0 {
        cross.push("effective refresh_token_lifetime_secs must be > 0".into());
    }
    if merged.mfa.mfa_challenge_lifetime_secs == 0 {
        cross.push("effective mfa_challenge_lifetime_secs must be > 0".into());
    }

    if merged.lockout.max_lockout_duration_secs < merged.lockout.lockout_duration_secs {
        cross.push(format!(
            "effective max_lockout_duration_secs ({}) must be >= \
             lockout_duration_secs ({})",
            merged.lockout.max_lockout_duration_secs, merged.lockout.lockout_duration_secs,
        ));
    }
    if merged.certificate.max_cert_validity_days < merged.certificate.default_cert_validity_days {
        cross.push(format!(
            "effective max_cert_validity_days ({}) must be >= \
             default_cert_validity_days ({})",
            merged.certificate.max_cert_validity_days,
            merged.certificate.default_cert_validity_days,
        ));
    }

    if cross.is_empty() {
        Ok(())
    } else {
        Err(AxiamError::Validation {
            message: format!(
                "Tenant override produces inconsistent effective policy: {}",
                cross.join("; "),
            ),
        })
    }
}

/// Compute the diff between a complete tenant settings row and the
/// org baseline, producing a `TenantSettingsOverride` with only the
/// fields that differ set to `Some`.
pub fn diff_against_org(
    org: &SecuritySettings,
    tenant: &SecuritySettings,
) -> TenantSettingsOverride {
    macro_rules! diff {
        ($field:ident, $org_path:expr, $tenant_path:expr) => {
            if $tenant_path != $org_path {
                Some($tenant_path)
            } else {
                None
            }
        };
    }

    TenantSettingsOverride {
        min_length: diff!(
            min_length,
            org.password.min_length,
            tenant.password.min_length
        ),
        require_uppercase: diff!(
            require_uppercase,
            org.password.require_uppercase,
            tenant.password.require_uppercase
        ),
        require_lowercase: diff!(
            require_lowercase,
            org.password.require_lowercase,
            tenant.password.require_lowercase
        ),
        require_digits: diff!(
            require_digits,
            org.password.require_digits,
            tenant.password.require_digits
        ),
        require_symbols: diff!(
            require_symbols,
            org.password.require_symbols,
            tenant.password.require_symbols
        ),
        password_history_count: diff!(
            password_history_count,
            org.password.password_history_count,
            tenant.password.password_history_count
        ),
        hibp_check_enabled: diff!(
            hibp_check_enabled,
            org.password.hibp_check_enabled,
            tenant.password.hibp_check_enabled
        ),
        mfa_enforced: diff!(mfa_enforced, org.mfa.mfa_enforced, tenant.mfa.mfa_enforced),
        mfa_challenge_lifetime_secs: diff!(
            mfa_challenge_lifetime_secs,
            org.mfa.mfa_challenge_lifetime_secs,
            tenant.mfa.mfa_challenge_lifetime_secs
        ),
        max_failed_login_attempts: diff!(
            max_failed_login_attempts,
            org.lockout.max_failed_login_attempts,
            tenant.lockout.max_failed_login_attempts
        ),
        lockout_duration_secs: diff!(
            lockout_duration_secs,
            org.lockout.lockout_duration_secs,
            tenant.lockout.lockout_duration_secs
        ),
        lockout_backoff_multiplier: diff!(
            lockout_backoff_multiplier,
            org.lockout.lockout_backoff_multiplier,
            tenant.lockout.lockout_backoff_multiplier
        ),
        max_lockout_duration_secs: diff!(
            max_lockout_duration_secs,
            org.lockout.max_lockout_duration_secs,
            tenant.lockout.max_lockout_duration_secs
        ),
        access_token_lifetime_secs: diff!(
            access_token_lifetime_secs,
            org.token.access_token_lifetime_secs,
            tenant.token.access_token_lifetime_secs
        ),
        refresh_token_lifetime_secs: diff!(
            refresh_token_lifetime_secs,
            org.token.refresh_token_lifetime_secs,
            tenant.token.refresh_token_lifetime_secs
        ),
        email_verification_required: diff!(
            email_verification_required,
            org.email.email_verification_required,
            tenant.email.email_verification_required
        ),
        email_verification_grace_period_hours: diff!(
            email_verification_grace_period_hours,
            org.email.email_verification_grace_period_hours,
            tenant.email.email_verification_grace_period_hours
        ),
        default_cert_validity_days: diff!(
            default_cert_validity_days,
            org.certificate.default_cert_validity_days,
            tenant.certificate.default_cert_validity_days
        ),
        max_cert_validity_days: diff!(
            max_cert_validity_days,
            org.certificate.max_cert_validity_days,
            tenant.certificate.max_cert_validity_days
        ),
        admin_notifications_enabled: diff!(
            admin_notifications_enabled,
            org.notification.admin_notifications_enabled,
            tenant.notification.admin_notifications_enabled
        ),
    }
}

/// Build a `SecuritySettings` from a `SetOrgSettings` input.
pub fn settings_from_org_input(id: Uuid, org_id: Uuid, input: &SetOrgSettings) -> SecuritySettings {
    let now = Utc::now();
    SecuritySettings {
        id,
        scope: SettingsScope::Org,
        scope_id: org_id,
        password: PasswordPolicy {
            min_length: input.min_length,
            require_uppercase: input.require_uppercase,
            require_lowercase: input.require_lowercase,
            require_digits: input.require_digits,
            require_symbols: input.require_symbols,
            password_history_count: input.password_history_count,
            hibp_check_enabled: input.hibp_check_enabled,
        },
        mfa: MfaPolicy {
            mfa_enforced: input.mfa_enforced,
            mfa_challenge_lifetime_secs: input.mfa_challenge_lifetime_secs,
        },
        lockout: LockoutPolicy {
            max_failed_login_attempts: input.max_failed_login_attempts,
            lockout_duration_secs: input.lockout_duration_secs,
            lockout_backoff_multiplier: input.lockout_backoff_multiplier,
            max_lockout_duration_secs: input.max_lockout_duration_secs,
        },
        token: TokenPolicy {
            access_token_lifetime_secs: input.access_token_lifetime_secs,
            refresh_token_lifetime_secs: input.refresh_token_lifetime_secs,
        },
        email: EmailVerificationPolicy {
            email_verification_required: input.email_verification_required,
            email_verification_grace_period_hours: input.email_verification_grace_period_hours,
        },
        certificate: CertificatePolicy {
            default_cert_validity_days: input.default_cert_validity_days,
            max_cert_validity_days: input.max_cert_validity_days,
        },
        notification: NotificationPolicy {
            admin_notifications_enabled: input.admin_notifications_enabled,
        },
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

    /// Helper: build an org `SecuritySettings` from system defaults.
    fn org_settings() -> SecuritySettings {
        let defaults = system_defaults();
        settings_from_org_input(Uuid::new_v4(), Uuid::new_v4(), &defaults)
    }

    // --- system_defaults sanity ---

    #[test]
    fn system_defaults_has_sane_values() {
        let d = system_defaults();
        assert!(d.min_length >= 8);
        assert!(d.access_token_lifetime_secs <= 3600);
        assert!(d.refresh_token_lifetime_secs > 0);
        assert!(d.max_failed_login_attempts > 0);
        assert!(d.lockout_duration_secs > 0);
        assert!(d.lockout_backoff_multiplier >= 1.0);
        assert!(d.max_lockout_duration_secs >= d.lockout_duration_secs);
        assert!(d.mfa_challenge_lifetime_secs > 0);
        assert!(d.default_cert_validity_days > 0);
        assert!(d.max_cert_validity_days >= d.default_cert_validity_days);
    }

    // --- validate_tenant_override: valid cases ---

    #[test]
    fn all_none_override_is_valid() {
        let org = org_settings();
        let overrides = TenantSettingsOverride::default();
        assert!(validate_tenant_override(&org, &overrides).is_ok());
    }

    #[test]
    fn more_restrictive_values_are_valid() {
        let org = org_settings();
        let overrides = TenantSettingsOverride {
            min_length: Some(16),                            // higher min
            max_failed_login_attempts: Some(3),              // lower max
            access_token_lifetime_secs: Some(600),           // shorter
            refresh_token_lifetime_secs: Some(86_400),       // shorter
            lockout_duration_secs: Some(600),                // longer lockout
            max_lockout_duration_secs: Some(7200),           // longer
            mfa_challenge_lifetime_secs: Some(120),          // shorter
            default_cert_validity_days: Some(180),           // shorter
            max_cert_validity_days: Some(365),               // shorter
            email_verification_grace_period_hours: Some(12), // shorter
            password_history_count: Some(10),                // higher
            lockout_backoff_multiplier: Some(3.0),           // higher
            ..Default::default()
        };
        assert!(validate_tenant_override(&org, &overrides).is_ok());
    }

    #[test]
    fn enable_only_true_is_valid() {
        let org = org_settings();
        // org has require_symbols = false, so tenant can enable it
        let overrides = TenantSettingsOverride {
            require_symbols: Some(true),
            mfa_enforced: Some(true),
            ..Default::default()
        };
        assert!(validate_tenant_override(&org, &overrides).is_ok());
    }

    #[test]
    fn equal_values_are_valid_boundary() {
        let org = org_settings();
        let overrides = TenantSettingsOverride {
            min_length: Some(org.password.min_length),
            max_failed_login_attempts: Some(org.lockout.max_failed_login_attempts),
            access_token_lifetime_secs: Some(org.token.access_token_lifetime_secs),
            ..Default::default()
        };
        assert!(validate_tenant_override(&org, &overrides).is_ok());
    }

    // --- validate_tenant_override: invalid cases ---

    #[test]
    fn less_restrictive_min_length_is_invalid() {
        let org = org_settings();
        let overrides = TenantSettingsOverride {
            min_length: Some(6), // weaker
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &overrides).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("min_length"), "got: {msg}");
    }

    #[test]
    fn disable_mfa_enforced_is_invalid() {
        let mut org = org_settings();
        org.mfa.mfa_enforced = true; // org enforces MFA
        let overrides = TenantSettingsOverride {
            mfa_enforced: Some(false), // tenant tries to disable
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &overrides).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("mfa_enforced"), "got: {msg}");
    }

    #[test]
    fn longer_token_lifetime_is_invalid() {
        let org = org_settings();
        let overrides = TenantSettingsOverride {
            access_token_lifetime_secs: Some(7200), // longer than 900
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &overrides).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("access_token_lifetime_secs"), "got: {msg}");
    }

    #[test]
    fn higher_cert_validity_is_invalid() {
        let org = org_settings();
        let overrides = TenantSettingsOverride {
            max_cert_validity_days: Some(1000), // > 730
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &overrides).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("max_cert_validity_days"), "got: {msg}");
    }

    #[test]
    fn multiple_violations_reported_together() {
        let mut org = org_settings();
        org.mfa.mfa_enforced = true;
        let overrides = TenantSettingsOverride {
            min_length: Some(4),                    // weaker
            mfa_enforced: Some(false),              // disabling
            access_token_lifetime_secs: Some(9999), // longer
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &overrides).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("min_length"), "got: {msg}");
        assert!(msg.contains("mfa_enforced"), "got: {msg}");
        assert!(msg.contains("access_token_lifetime_secs"), "got: {msg}");
    }

    // --- cross-field invariant: zero lifetimes rejected ---

    #[test]
    fn zero_access_token_lifetime_is_rejected() {
        let org = org_settings();
        let overrides = TenantSettingsOverride {
            access_token_lifetime_secs: Some(0),
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &overrides).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("access_token_lifetime_secs must be > 0"),
            "got: {msg}",
        );
    }

    #[test]
    fn zero_mfa_challenge_lifetime_is_rejected() {
        let org = org_settings();
        let overrides = TenantSettingsOverride {
            mfa_challenge_lifetime_secs: Some(0),
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &overrides).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mfa_challenge_lifetime_secs must be > 0"),
            "got: {msg}",
        );
    }

    // --- effective_settings merging ---

    #[test]
    fn effective_settings_inherits_from_org() {
        let org = org_settings();
        let overrides = TenantSettingsOverride::default();
        let tenant_id = Uuid::new_v4();
        let result_id = Uuid::new_v4();
        let eff = effective_settings(&org, &overrides, tenant_id, result_id);
        assert_eq!(eff.password.min_length, org.password.min_length);
        assert_eq!(
            eff.token.access_token_lifetime_secs,
            org.token.access_token_lifetime_secs
        );
        assert_eq!(eff.scope, SettingsScope::Tenant);
        assert_eq!(eff.scope_id, tenant_id);
    }

    #[test]
    fn effective_settings_applies_overrides() {
        let org = org_settings();
        let overrides = TenantSettingsOverride {
            min_length: Some(20),
            access_token_lifetime_secs: Some(300),
            mfa_enforced: Some(true),
            ..Default::default()
        };
        let tenant_id = Uuid::new_v4();
        let result_id = Uuid::new_v4();
        let eff = effective_settings(&org, &overrides, tenant_id, result_id);
        assert_eq!(eff.password.min_length, 20);
        assert_eq!(eff.token.access_token_lifetime_secs, 300);
        assert!(eff.mfa.mfa_enforced);
        // Non-overridden fields inherit from org
        assert_eq!(
            eff.lockout.max_failed_login_attempts,
            org.lockout.max_failed_login_attempts,
        );
    }

    // --- diff_against_org ---

    #[test]
    fn diff_identical_settings_produces_empty_override() {
        let org = org_settings();
        let tenant = org.clone();
        let diff = diff_against_org(&org, &tenant);
        assert!(diff.is_empty());
    }

    #[test]
    fn diff_detects_changed_fields() {
        let org = org_settings();
        let mut tenant = org.clone();
        tenant.password.min_length = 20;
        tenant.token.access_token_lifetime_secs = 300;
        let diff = diff_against_org(&org, &tenant);
        assert_eq!(diff.min_length, Some(20));
        assert_eq!(diff.access_token_lifetime_secs, Some(300));
        // Unchanged fields are None
        assert_eq!(diff.mfa_enforced, None);
        assert_eq!(diff.max_failed_login_attempts, None);
    }
}
