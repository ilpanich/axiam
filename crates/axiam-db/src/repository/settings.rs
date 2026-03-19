//! SurrealDB implementation of [`SettingsRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::settings::{
    CertificatePolicy, EmailVerificationPolicy, LockoutPolicy, MfaPolicy, NotificationPolicy,
    PasswordPolicy, SecuritySettings, SetOrgSettings, SetTenantOverride, SettingsScope,
    TenantSettingsOverride, TokenPolicy, diff_against_org, effective_settings,
    settings_from_org_input, system_defaults,
};
use axiam_core::repository::SettingsRepository;
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

// -----------------------------------------------------------------------
// Row structs (flat, matching DB columns)
// -----------------------------------------------------------------------

/// Flat DB row without the record ID.
#[derive(Debug, SurrealValue)]
struct SettingsRow {
    scope: String,
    scope_id: String,
    // Password
    pw_min_length: u32,
    pw_require_uppercase: bool,
    pw_require_lowercase: bool,
    pw_require_digits: bool,
    pw_require_symbols: bool,
    pw_history_count: u32,
    pw_hibp_check: bool,
    // MFA
    mfa_enforced: bool,
    mfa_challenge_lifetime: u64,
    // Lockout
    lockout_max_attempts: u32,
    lockout_duration: u64,
    lockout_backoff: f64,
    lockout_max_duration: u64,
    // Token
    token_access_lifetime: u64,
    token_refresh_lifetime: u64,
    // Email
    email_verification_required: bool,
    email_grace_period_hours: u32,
    // Certificate
    cert_default_validity: u32,
    cert_max_validity: u32,
    // Notification
    notif_admin_enabled: bool,
    // Timestamps
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Flat DB row including the record ID via `meta::id(id)`.
#[derive(Debug, SurrealValue)]
struct SettingsRowWithId {
    record_id: String,
    scope: String,
    scope_id: String,
    // Password
    pw_min_length: u32,
    pw_require_uppercase: bool,
    pw_require_lowercase: bool,
    pw_require_digits: bool,
    pw_require_symbols: bool,
    pw_history_count: u32,
    pw_hibp_check: bool,
    // MFA
    mfa_enforced: bool,
    mfa_challenge_lifetime: u64,
    // Lockout
    lockout_max_attempts: u32,
    lockout_duration: u64,
    lockout_backoff: f64,
    lockout_max_duration: u64,
    // Token
    token_access_lifetime: u64,
    token_refresh_lifetime: u64,
    // Email
    email_verification_required: bool,
    email_grace_period_hours: u32,
    // Certificate
    cert_default_validity: u32,
    cert_max_validity: u32,
    // Notification
    notif_admin_enabled: bool,
    // Timestamps
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl SettingsRowWithId {
    fn try_into_security_settings(self) -> Result<SecuritySettings, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let scope_id = Uuid::parse_str(&self.scope_id)
            .map_err(|e| DbError::Migration(format!("invalid scope UUID: {e}")))?;
        let scope: SettingsScope = self
            .scope
            .parse()
            .map_err(|e: String| DbError::Migration(e))?;

        Ok(SecuritySettings {
            id,
            scope,
            scope_id,
            password: PasswordPolicy {
                min_length: self.pw_min_length,
                require_uppercase: self.pw_require_uppercase,
                require_lowercase: self.pw_require_lowercase,
                require_digits: self.pw_require_digits,
                require_symbols: self.pw_require_symbols,
                password_history_count: self.pw_history_count,
                hibp_check_enabled: self.pw_hibp_check,
            },
            mfa: MfaPolicy {
                mfa_enforced: self.mfa_enforced,
                mfa_challenge_lifetime_secs: self.mfa_challenge_lifetime,
            },
            lockout: LockoutPolicy {
                max_failed_login_attempts: self.lockout_max_attempts,
                lockout_duration_secs: self.lockout_duration,
                lockout_backoff_multiplier: self.lockout_backoff,
                max_lockout_duration_secs: self.lockout_max_duration,
            },
            token: TokenPolicy {
                access_token_lifetime_secs: self.token_access_lifetime,
                refresh_token_lifetime_secs: self.token_refresh_lifetime,
            },
            email: EmailVerificationPolicy {
                email_verification_required: self.email_verification_required,
                email_verification_grace_period_hours: self.email_grace_period_hours,
            },
            certificate: CertificatePolicy {
                default_cert_validity_days: self.cert_default_validity,
                max_cert_validity_days: self.cert_max_validity,
            },
            notification: NotificationPolicy {
                admin_notifications_enabled: self.notif_admin_enabled,
            },
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

// -----------------------------------------------------------------------
// SQL fragments
// -----------------------------------------------------------------------

const SETTINGS_FIELDS: &str = "\
scope = $scope, scope_id = $scope_id, \
pw_min_length = $pw_min_length, \
pw_require_uppercase = $pw_require_uppercase, \
pw_require_lowercase = $pw_require_lowercase, \
pw_require_digits = $pw_require_digits, \
pw_require_symbols = $pw_require_symbols, \
pw_history_count = $pw_history_count, \
pw_hibp_check = $pw_hibp_check, \
mfa_enforced = $mfa_enforced, \
mfa_challenge_lifetime = $mfa_challenge_lifetime, \
lockout_max_attempts = $lockout_max_attempts, \
lockout_duration = $lockout_duration, \
lockout_backoff = $lockout_backoff, \
lockout_max_duration = $lockout_max_duration, \
token_access_lifetime = $token_access_lifetime, \
token_refresh_lifetime = $token_refresh_lifetime, \
email_verification_required = $email_verification_required, \
email_grace_period_hours = $email_grace_period_hours, \
cert_default_validity = $cert_default_validity, \
cert_max_validity = $cert_max_validity, \
notif_admin_enabled = $notif_admin_enabled";

const SELECT_WITH_ID: &str = "\
SELECT meta::id(id) AS record_id, * \
FROM security_settings \
WHERE scope = $scope AND scope_id = $scope_id";

// -----------------------------------------------------------------------
// Repository
// -----------------------------------------------------------------------

/// SurrealDB implementation of the settings repository.
#[derive(Clone)]
pub struct SurrealSettingsRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealSettingsRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }

    /// Bind all settings fields from a SecuritySettings onto a query.
    fn bind_settings(&self, settings: &SecuritySettings) -> Vec<(&'static str, BindValue)> {
        vec![
            ("scope", BindValue::Str(settings.scope.to_string())),
            ("scope_id", BindValue::Str(settings.scope_id.to_string())),
            (
                "pw_min_length",
                BindValue::U32(settings.password.min_length),
            ),
            (
                "pw_require_uppercase",
                BindValue::Bool(settings.password.require_uppercase),
            ),
            (
                "pw_require_lowercase",
                BindValue::Bool(settings.password.require_lowercase),
            ),
            (
                "pw_require_digits",
                BindValue::Bool(settings.password.require_digits),
            ),
            (
                "pw_require_symbols",
                BindValue::Bool(settings.password.require_symbols),
            ),
            (
                "pw_history_count",
                BindValue::U32(settings.password.password_history_count),
            ),
            (
                "pw_hibp_check",
                BindValue::Bool(settings.password.hibp_check_enabled),
            ),
            ("mfa_enforced", BindValue::Bool(settings.mfa.mfa_enforced)),
            (
                "mfa_challenge_lifetime",
                BindValue::U64(settings.mfa.mfa_challenge_lifetime_secs),
            ),
            (
                "lockout_max_attempts",
                BindValue::U32(settings.lockout.max_failed_login_attempts),
            ),
            (
                "lockout_duration",
                BindValue::U64(settings.lockout.lockout_duration_secs),
            ),
            (
                "lockout_backoff",
                BindValue::F64(settings.lockout.lockout_backoff_multiplier),
            ),
            (
                "lockout_max_duration",
                BindValue::U64(settings.lockout.max_lockout_duration_secs),
            ),
            (
                "token_access_lifetime",
                BindValue::U64(settings.token.access_token_lifetime_secs),
            ),
            (
                "token_refresh_lifetime",
                BindValue::U64(settings.token.refresh_token_lifetime_secs),
            ),
            (
                "email_verification_required",
                BindValue::Bool(settings.email.email_verification_required),
            ),
            (
                "email_grace_period_hours",
                BindValue::U32(settings.email.email_verification_grace_period_hours),
            ),
            (
                "cert_default_validity",
                BindValue::U32(settings.certificate.default_cert_validity_days),
            ),
            (
                "cert_max_validity",
                BindValue::U32(settings.certificate.max_cert_validity_days),
            ),
            (
                "notif_admin_enabled",
                BindValue::Bool(settings.notification.admin_notifications_enabled),
            ),
        ]
    }

    /// Look up the organization_id for a tenant from the tenant table.
    async fn lookup_org_id(&self, tenant_id: Uuid) -> Result<Uuid, DbError> {
        let mut result = self
            .db
            .query(
                "SELECT organization_id FROM tenant \
                 WHERE meta::id(id) = $tenant_id",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<TenantOrgRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "tenant".into(),
            id: tenant_id.to_string(),
        })?;

        Uuid::parse_str(&row.organization_id)
            .map_err(|e| DbError::Migration(format!("invalid org UUID: {e}")))
    }

    /// Fetch a settings row by scope and scope_id.
    async fn fetch_row(
        &self,
        scope: &str,
        scope_id: &str,
    ) -> Result<Option<SecuritySettings>, DbError> {
        let mut result = self
            .db
            .query(SELECT_WITH_ID)
            .bind(("scope", scope.to_string()))
            .bind(("scope_id", scope_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<SettingsRowWithId> = result.take(0).map_err(DbError::from)?;
        match rows.into_iter().next() {
            Some(row) => Ok(Some(row.try_into_security_settings()?)),
            None => Ok(None),
        }
    }

    /// Upsert a complete settings row. Reuses the existing record ID
    /// and preserves `created_at` when a row already exists (UPDATE).
    /// Creates a new row otherwise (CREATE).
    async fn upsert(&self, settings: &SecuritySettings) -> Result<SecuritySettings, DbError> {
        // Use a deterministic record ID derived from (scope, scope_id) so
        // that concurrent requests for the same key converge on the same
        // row.  UPDATE on a deterministic ID is a single-statement upsert
        // that is safe under concurrency (no read-then-create race).
        let scope_str = settings.scope.to_string();
        let scope_id_str = settings.scope_id.to_string();
        let deterministic_id = Uuid::new_v5(
            &Uuid::NAMESPACE_OID,
            format!("{scope_str}:{scope_id_str}").as_bytes(),
        );
        let id_str = deterministic_id.to_string();

        // UPSERT: single statement — creates the row if it doesn't
        // exist, updates it otherwise. Timestamps are handled inline:
        // `created_at` is only set on initial creation via
        // `time::now()` default, and `updated_at` is always refreshed.
        let query = format!(
            "UPSERT type::record('security_settings', $id) SET \
             {SETTINGS_FIELDS}, \
             created_at = created_at OR time::now(), \
             updated_at = time::now()",
        );

        let bindings = self.bind_settings(settings);
        let mut builder = self.db.query(&query).bind(("id", id_str.clone()));
        for (name, value) in bindings {
            builder = match value {
                BindValue::Str(v) => builder.bind((name, v)),
                BindValue::Bool(v) => builder.bind((name, v)),
                BindValue::U32(v) => builder.bind((name, v)),
                BindValue::U64(v) => builder.bind((name, v)),
                BindValue::F64(v) => builder.bind((name, v)),
            };
        }

        let result = builder.await.map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<SettingsRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "security_settings".into(),
            id: id_str,
        })?;

        Ok(SecuritySettings {
            id: deterministic_id,
            scope: settings.scope,
            scope_id: settings.scope_id,
            password: PasswordPolicy {
                min_length: row.pw_min_length,
                require_uppercase: row.pw_require_uppercase,
                require_lowercase: row.pw_require_lowercase,
                require_digits: row.pw_require_digits,
                require_symbols: row.pw_require_symbols,
                password_history_count: row.pw_history_count,
                hibp_check_enabled: row.pw_hibp_check,
            },
            mfa: MfaPolicy {
                mfa_enforced: row.mfa_enforced,
                mfa_challenge_lifetime_secs: row.mfa_challenge_lifetime,
            },
            lockout: LockoutPolicy {
                max_failed_login_attempts: row.lockout_max_attempts,
                lockout_duration_secs: row.lockout_duration,
                lockout_backoff_multiplier: row.lockout_backoff,
                max_lockout_duration_secs: row.lockout_max_duration,
            },
            token: TokenPolicy {
                access_token_lifetime_secs: row.token_access_lifetime,
                refresh_token_lifetime_secs: row.token_refresh_lifetime,
            },
            email: EmailVerificationPolicy {
                email_verification_required: row.email_verification_required,
                email_verification_grace_period_hours: row.email_grace_period_hours,
            },
            certificate: CertificatePolicy {
                default_cert_validity_days: row.cert_default_validity,
                max_cert_validity_days: row.cert_max_validity,
            },
            notification: NotificationPolicy {
                admin_notifications_enabled: row.notif_admin_enabled,
            },
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

/// Helper enum to avoid Box<dyn> for query bindings.
enum BindValue {
    Str(String),
    Bool(bool),
    U32(u32),
    U64(u64),
    F64(f64),
}

/// Row for looking up a tenant's organization_id.
#[derive(Debug, SurrealValue)]
struct TenantOrgRow {
    organization_id: String,
}

impl<C: Connection> SettingsRepository for SurrealSettingsRepository<C> {
    async fn get_org_settings(&self, org_id: Uuid) -> AxiamResult<SecuritySettings> {
        match self.fetch_row("org", &org_id.to_string()).await? {
            Some(s) => Ok(s),
            None => {
                // Return system defaults as a synthetic settings
                let defaults = system_defaults();
                Ok(settings_from_org_input(Uuid::nil(), org_id, &defaults))
            }
        }
    }

    async fn set_org_settings(
        &self,
        org_id: Uuid,
        input: SetOrgSettings,
    ) -> AxiamResult<SecuritySettings> {
        // ID will be determined by upsert (reuses existing or generates new).
        let settings = settings_from_org_input(Uuid::nil(), org_id, &input);
        let result = self.upsert(&settings).await?;
        Ok(result)
    }

    async fn get_tenant_override(
        &self,
        tenant_id: Uuid,
    ) -> AxiamResult<Option<TenantSettingsOverride>> {
        let tenant_row = self.fetch_row("tenant", &tenant_id.to_string()).await?;
        match tenant_row {
            None => Ok(None),
            Some(tenant_settings) => {
                // Look up the tenant's org_id to compute a proper diff.
                let org_id = self.lookup_org_id(tenant_id).await?;
                let org = self.get_org_settings(org_id).await?;
                Ok(Some(diff_against_org(&org, &tenant_settings)))
            }
        }
    }

    async fn store_effective_tenant_settings(
        &self,
        tenant_id: Uuid,
        mut settings: SecuritySettings,
    ) -> AxiamResult<SecuritySettings> {
        settings.scope = SettingsScope::Tenant;
        settings.scope_id = tenant_id;
        let result = self.upsert(&settings).await?;
        Ok(result)
    }

    async fn set_tenant_override(
        &self,
        tenant_id: Uuid,
        input: SetTenantOverride,
    ) -> AxiamResult<TenantSettingsOverride> {
        // Look up the tenant's org_id to fetch the org baseline.
        let org_id = self.lookup_org_id(tenant_id).await?;
        let org = self.get_org_settings(org_id).await?;

        // Merge org baseline + overrides into a complete tenant row.
        let merged = effective_settings(&org, &input, tenant_id, Uuid::nil());

        let result = self.upsert(&merged).await?;
        // Diff the stored result against the org baseline (not the
        // previous tenant row) so the returned override reflects
        // actual deviations from org policy.
        Ok(diff_against_org(&org, &result))
    }

    async fn delete_tenant_override(&self, tenant_id: Uuid) -> AxiamResult<()> {
        self.db
            .query(
                "DELETE security_settings WHERE scope = 'tenant' \
                 AND scope_id = $scope_id",
            )
            .bind(("scope_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    async fn get_effective_settings(
        &self,
        org_id: Uuid,
        tenant_id: Uuid,
    ) -> AxiamResult<SecuritySettings> {
        let org = self.get_org_settings(org_id).await?;

        // If there is a stored tenant row, diff it against the current
        // org baseline and re-merge so that any org-level changes propagate
        // to fields the tenant has NOT explicitly overridden.
        if let Some(tenant_row) = self.fetch_row("tenant", &tenant_id.to_string()).await? {
            let overrides = diff_against_org(&org, &tenant_row);
            let merged = effective_settings(&org, &overrides, tenant_id, tenant_row.id);
            return Ok(merged);
        }

        // No tenant row — org settings (or system defaults) apply.
        Ok(org)
    }
}
