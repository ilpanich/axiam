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
use crate::models::opaque::{
    OpaqueKsf, OpaqueMode, OpaqueSuite, opaque_ksf_is_at_least, opaque_suite_is_at_least,
};

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

/// Secure Remote Password policy.
///
/// `suite` and `ksf` are the parameters a *new* registration record is enrolled
/// with. They deliberately do not apply retroactively: an existing record is
/// only valid under the suite and KSF it was created with, so tightening these
/// takes effect as users next set a password rather than invalidating
/// everybody at once.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OpaquePolicy {
    /// Whether OPAQUE is offered, and whether password login is still accepted.
    #[schema(value_type = String, example = "disabled")]
    pub opaque_mode: OpaqueMode,
    /// RFC 9807 ciphersuite new records are enrolled under.
    #[schema(value_type = String, example = "ristretto255_sha512")]
    pub opaque_suite: OpaqueSuite,
    /// Key-stretching function new records are enrolled under. Both variants
    /// are memory-hard; see [`opaque_ksf_is_at_least`] for the tighten-only
    /// ordering.
    #[schema(value_type = String, example = "argon2id")]
    pub opaque_ksf: OpaqueKsf,
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
    pub opaque: OpaquePolicy,
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
    // OPAQUE
    #[schema(value_type = Option<String>)]
    pub opaque_mode: Option<OpaqueMode>,
    #[schema(value_type = Option<String>)]
    pub opaque_suite: Option<OpaqueSuite>,
    #[schema(value_type = Option<String>)]
    pub opaque_ksf: Option<OpaqueKsf>,
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
    // OPAQUE — defaulted so an existing API client that has never heard of
    // OPAQUE keeps working unchanged and lands on `disabled`.
    #[serde(default)]
    #[schema(value_type = String, example = "disabled")]
    pub opaque_mode: OpaqueMode,
    #[serde(default)]
    #[schema(value_type = String, example = "ristretto255_sha512")]
    pub opaque_suite: OpaqueSuite,
    #[serde(default)]
    #[schema(value_type = String, example = "argon2id")]
    pub opaque_ksf: OpaqueKsf,
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
        // OPAQUE — off by default. Turning it on is a deliberate operator
        // decision, and defaulting it on would change the login wire protocol
        // for every existing deployment on upgrade.
        opaque_mode: OpaqueMode::Disabled,
        opaque_suite: OpaqueSuite::Ristretto255Sha512,
        opaque_ksf: OpaqueKsf::Argon2id,
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
        opaque: OpaquePolicy {
            opaque_mode: tenant_override
                .opaque_mode
                .unwrap_or(org.opaque.opaque_mode),
            opaque_suite: tenant_override
                .opaque_suite
                .unwrap_or(org.opaque.opaque_suite),
            opaque_ksf: tenant_override.opaque_ksf.unwrap_or(org.opaque.opaque_ksf),
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

    // --- OPAQUE: tighten-only ---
    //
    // `OpaqueMode` derives `Ord` as Disabled < Optional < Required, which is
    // exactly the restrictiveness order, so this is a plain comparison. Suite
    // and KSF strength are ranked explicitly rather than by declaration order,
    // so that adding a variant forces a decision about where it sits.
    if let Some(mode) = overrides.opaque_mode
        && mode < org.opaque.opaque_mode
    {
        violations.push(format!(
            "opaque_mode: tenant value {} is less restrictive than org baseline {}",
            mode, org.opaque.opaque_mode,
        ));
    }
    if let Some(suite) = overrides.opaque_suite
        && !opaque_suite_is_at_least(suite, org.opaque.opaque_suite)
    {
        violations.push(format!(
            "opaque_suite: tenant value {} is weaker than org baseline {}",
            suite, org.opaque.opaque_suite,
        ));
    }
    if let Some(ksf) = overrides.opaque_ksf
        && !opaque_ksf_is_at_least(ksf, org.opaque.opaque_ksf)
    {
        violations.push(format!(
            "opaque_ksf: tenant value {} is weaker than org baseline {}",
            ksf, org.opaque.opaque_ksf,
        ));
    }

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
        opaque_mode: diff!(
            opaque_mode,
            org.opaque.opaque_mode,
            tenant.opaque.opaque_mode
        ),
        opaque_suite: diff!(
            opaque_suite,
            org.opaque.opaque_suite,
            tenant.opaque.opaque_suite
        ),
        opaque_ksf: diff!(opaque_ksf, org.opaque.opaque_ksf, tenant.opaque.opaque_ksf),
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
        opaque: OpaquePolicy {
            opaque_mode: input.opaque_mode,
            opaque_suite: input.opaque_suite,
            opaque_ksf: input.opaque_ksf,
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

    // --- OPAQUE policy ---

    #[test]
    fn opaque_defaults_to_disabled_so_an_upgrade_changes_no_wire_protocol() {
        let org = org_settings();
        assert_eq!(org.opaque.opaque_mode, OpaqueMode::Disabled);
        assert_eq!(org.opaque.opaque_suite, OpaqueSuite::Ristretto255Sha512);
        assert_eq!(org.opaque.opaque_ksf, OpaqueKsf::Argon2id);
    }

    #[test]
    fn a_tenant_may_tighten_opaque_mode_but_never_relax_it() {
        let mut org = org_settings();
        org.opaque.opaque_mode = OpaqueMode::Optional;

        let tighten = TenantSettingsOverride {
            opaque_mode: Some(OpaqueMode::Required),
            ..Default::default()
        };
        assert!(validate_tenant_override(&org, &tighten).is_ok());

        let relax = TenantSettingsOverride {
            opaque_mode: Some(OpaqueMode::Disabled),
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &relax).unwrap_err();
        assert!(err.to_string().contains("opaque_mode"), "{err}");
    }

    #[test]
    fn a_tenant_may_restate_the_org_suite_but_not_weaken_it() {
        // One suite ships today, so the reachable assertion is that an equal
        // value passes. The check itself is kept live (rather than deleted
        // until a second suite exists) so that adding `P256Sha256` is an
        // additive change to a lattice that already works.
        let org = org_settings();
        let same = TenantSettingsOverride {
            opaque_suite: Some(OpaqueSuite::Ristretto255Sha512),
            ..Default::default()
        };
        assert!(validate_tenant_override(&org, &same).is_ok());
    }

    #[test]
    fn a_tenant_may_not_downgrade_argon2id_to_scrypt() {
        // Doing so would weaken every record enrolled after the change, which
        // is exactly what the tighten-only rule exists to prevent.
        let org = org_settings(); // argon2id baseline
        let downgrade = TenantSettingsOverride {
            opaque_ksf: Some(OpaqueKsf::Scrypt),
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &downgrade).unwrap_err();
        assert!(err.to_string().contains("opaque_ksf"), "{err}");

        let mut weak_org = org_settings();
        weak_org.opaque.opaque_ksf = OpaqueKsf::Scrypt;
        let upgrade = TenantSettingsOverride {
            opaque_ksf: Some(OpaqueKsf::Argon2id),
            ..Default::default()
        };
        assert!(validate_tenant_override(&weak_org, &upgrade).is_ok());
    }

    #[test]
    fn opaque_overrides_flow_through_the_merge_and_back_out_of_the_diff() {
        let mut org = org_settings();
        org.opaque.opaque_mode = OpaqueMode::Optional;

        let overrides = TenantSettingsOverride {
            opaque_mode: Some(OpaqueMode::Required),
            ..Default::default()
        };
        let merged = effective_settings(&org, &overrides, Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(merged.opaque.opaque_mode, OpaqueMode::Required);
        // Unset fields still inherit.
        assert_eq!(merged.opaque.opaque_suite, org.opaque.opaque_suite);
        assert_eq!(merged.opaque.opaque_ksf, org.opaque.opaque_ksf);

        let round_tripped = diff_against_org(&org, &merged);
        assert_eq!(round_tripped.opaque_mode, Some(OpaqueMode::Required));
        assert_eq!(round_tripped.opaque_suite, None);
        assert_eq!(round_tripped.opaque_ksf, None);
    }

    // --- validate_org_settings ---

    #[test]
    fn validate_org_settings_accepts_system_defaults() {
        assert!(validate_org_settings(&system_defaults()).is_ok());
    }

    #[test]
    fn validate_org_settings_rejects_each_invariant_violation() {
        // max_lockout_duration_secs < lockout_duration_secs
        let mut s = system_defaults();
        s.max_lockout_duration_secs = 100;
        s.lockout_duration_secs = 200;
        assert!(validate_org_settings(&s).is_err());

        // max_cert_validity_days < default_cert_validity_days
        let mut s = system_defaults();
        s.max_cert_validity_days = 10;
        s.default_cert_validity_days = 100;
        assert!(validate_org_settings(&s).is_err());

        // lockout_backoff_multiplier < 1.0
        let mut s = system_defaults();
        s.lockout_backoff_multiplier = 0.5;
        assert!(validate_org_settings(&s).is_err());

        // zero token / challenge lifetimes
        for mutate in [
            (|s: &mut SetOrgSettings| s.access_token_lifetime_secs = 0) as fn(&mut SetOrgSettings),
            |s: &mut SetOrgSettings| s.refresh_token_lifetime_secs = 0,
            |s: &mut SetOrgSettings| s.mfa_challenge_lifetime_secs = 0,
        ] {
            let mut s = system_defaults();
            mutate(&mut s);
            assert!(validate_org_settings(&s).is_err());
        }
    }

    #[test]
    fn validate_org_settings_reports_all_violations_together() {
        let mut s = system_defaults();
        s.access_token_lifetime_secs = 0;
        s.refresh_token_lifetime_secs = 0;
        let err = validate_org_settings(&s).unwrap_err().to_string();
        assert!(err.contains("access_token_lifetime_secs"));
        assert!(err.contains("refresh_token_lifetime_secs"));
    }

    // --- diff_against_org ---

    #[test]
    fn diff_against_identical_settings_is_empty() {
        let s = org_settings();
        assert!(diff_against_org(&s, &s).is_empty());
    }

    #[test]
    fn diff_against_org_detects_changed_fields() {
        let org = org_settings();
        let mut modified = system_defaults();
        modified.min_length += 4;
        modified.mfa_enforced = !modified.mfa_enforced;
        modified.access_token_lifetime_secs += 100;
        modified.admin_notifications_enabled = !modified.admin_notifications_enabled;
        let tenant = settings_from_org_input(Uuid::new_v4(), Uuid::new_v4(), &modified);

        let diff = diff_against_org(&org, &tenant);
        assert!(!diff.is_empty());
        assert_eq!(diff.min_length, Some(modified.min_length));
        assert_eq!(
            diff.access_token_lifetime_secs,
            Some(modified.access_token_lifetime_secs)
        );
        assert_eq!(diff.mfa_enforced, Some(modified.mfa_enforced));
        // Unchanged fields stay None.
        assert_eq!(diff.require_uppercase, None);
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

    // --- SettingsScope Display / FromStr ---

    #[test]
    fn settings_scope_round_trips_through_its_string_form() {
        // These strings are persisted and appear in API payloads, so Display
        // and FromStr have to stay each other's inverse.
        for scope in [SettingsScope::Org, SettingsScope::Tenant] {
            let text = scope.to_string();
            let parsed: SettingsScope = text.parse().unwrap();
            assert_eq!(parsed, scope, "{text} must parse back to itself");
        }
        assert_eq!(SettingsScope::Org.to_string(), "org");
        assert_eq!(SettingsScope::Tenant.to_string(), "tenant");
    }

    #[test]
    fn an_unknown_settings_scope_is_an_error_naming_the_input() {
        let err = "organisation".parse::<SettingsScope>().unwrap_err();
        assert!(
            err.contains("organisation"),
            "the error must name what was rejected: {err}"
        );
        assert!(
            "Org".parse::<SettingsScope>().is_err(),
            "parsing is case-sensitive"
        );
        assert!("".parse::<SettingsScope>().is_err());
    }

    // --- diff_against_org completeness ---

    /// Every overridable field must appear in the diff when it differs.
    ///
    /// The existing `diff_against_org` tests change four fields, which leaves
    /// the other nineteen comparisons executed only down their "same" branch.
    /// That is precisely the shape of bug this guards: a field added to
    /// `SecuritySettings` and forgotten in `diff_against_org` produces a tenant
    /// override that silently drops it, so an administrator sets a value, the
    /// API accepts it, and the setting never takes effect. Nothing errors.
    #[test]
    fn diff_against_org_reports_every_field_that_differs() {
        let org = org_settings();

        let mut changed = system_defaults();
        changed.min_length += 4;
        changed.require_uppercase = !changed.require_uppercase;
        changed.require_lowercase = !changed.require_lowercase;
        changed.require_digits = !changed.require_digits;
        changed.require_symbols = !changed.require_symbols;
        changed.password_history_count += 3;
        changed.hibp_check_enabled = !changed.hibp_check_enabled;
        changed.mfa_enforced = !changed.mfa_enforced;
        changed.mfa_challenge_lifetime_secs += 60;
        changed.max_failed_login_attempts += 2;
        changed.lockout_duration_secs += 30;
        changed.lockout_backoff_multiplier += 0.5;
        // Kept >= lockout_duration_secs so the row stays internally consistent;
        // this test is about the diff, not about validation rejecting nonsense.
        changed.max_lockout_duration_secs += 3_600;
        changed.access_token_lifetime_secs += 100;
        changed.refresh_token_lifetime_secs += 1_000;
        changed.email_verification_required = !changed.email_verification_required;
        changed.email_verification_grace_period_hours += 12;
        changed.default_cert_validity_days += 5;
        changed.max_cert_validity_days += 50;
        changed.admin_notifications_enabled = !changed.admin_notifications_enabled;
        changed.opaque_mode = OpaqueMode::Optional;
        changed.opaque_ksf = OpaqueKsf::Scrypt;
        // `opaque_suite` is deliberately NOT changed: `OpaqueSuite` has exactly
        // one variant, so it cannot differ from the baseline and its branch is
        // unreachable until a second suite exists.

        let tenant = settings_from_org_input(Uuid::new_v4(), Uuid::new_v4(), &changed);
        let diff = diff_against_org(&org, &tenant);

        assert_eq!(diff.min_length, Some(changed.min_length));
        assert_eq!(diff.require_uppercase, Some(changed.require_uppercase));
        assert_eq!(diff.require_lowercase, Some(changed.require_lowercase));
        assert_eq!(diff.require_digits, Some(changed.require_digits));
        assert_eq!(diff.require_symbols, Some(changed.require_symbols));
        assert_eq!(
            diff.password_history_count,
            Some(changed.password_history_count)
        );
        assert_eq!(diff.hibp_check_enabled, Some(changed.hibp_check_enabled));
        assert_eq!(diff.mfa_enforced, Some(changed.mfa_enforced));
        assert_eq!(
            diff.mfa_challenge_lifetime_secs,
            Some(changed.mfa_challenge_lifetime_secs)
        );
        assert_eq!(
            diff.max_failed_login_attempts,
            Some(changed.max_failed_login_attempts)
        );
        assert_eq!(
            diff.lockout_duration_secs,
            Some(changed.lockout_duration_secs)
        );
        assert_eq!(
            diff.lockout_backoff_multiplier,
            Some(changed.lockout_backoff_multiplier)
        );
        assert_eq!(
            diff.max_lockout_duration_secs,
            Some(changed.max_lockout_duration_secs)
        );
        assert_eq!(
            diff.access_token_lifetime_secs,
            Some(changed.access_token_lifetime_secs)
        );
        assert_eq!(
            diff.refresh_token_lifetime_secs,
            Some(changed.refresh_token_lifetime_secs)
        );
        assert_eq!(
            diff.email_verification_required,
            Some(changed.email_verification_required)
        );
        assert_eq!(
            diff.email_verification_grace_period_hours,
            Some(changed.email_verification_grace_period_hours)
        );
        assert_eq!(
            diff.default_cert_validity_days,
            Some(changed.default_cert_validity_days)
        );
        assert_eq!(
            diff.max_cert_validity_days,
            Some(changed.max_cert_validity_days)
        );
        assert_eq!(
            diff.admin_notifications_enabled,
            Some(changed.admin_notifications_enabled)
        );
        assert_eq!(diff.opaque_mode, Some(changed.opaque_mode));
        assert_eq!(diff.opaque_ksf, Some(changed.opaque_ksf));
    }

    /// The mirror of the test above: an identical tenant produces an override
    /// with nothing set, so re-saving unchanged settings does not manufacture
    /// overrides that then pin the tenant against future org-baseline changes.
    #[test]
    fn diff_against_org_sets_nothing_when_the_tenant_matches_the_baseline() {
        let org = org_settings();
        let same = settings_from_org_input(Uuid::new_v4(), Uuid::new_v4(), &system_defaults());
        assert!(diff_against_org(&org, &same).is_empty());
    }
}
