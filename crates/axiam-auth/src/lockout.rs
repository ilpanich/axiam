//! Shared failed-login / lockout accrual (D-06).
//!
//! Both the REST login path (`AuthService::record_failed_login`) and the
//! gRPC `UserService::validate_credentials` path call this single helper so
//! that there is no unmetered credential-check path anywhere in the system
//! (SEC-026b). This module is the single source of truth for the
//! failed-attempt/lockout increment — do NOT duplicate this logic anywhere
//! else.
//!
//! # Where the numbers come from
//!
//! The thresholds are a **per-organization, per-tenant policy**, not a
//! process-wide constant: an administrator sets `max_failed_login_attempts` and
//! the backoff on the organization, a tenant may narrow it, and
//! [`axiam_core::models::settings::effective_settings`] resolves the pair.
//!
//! Every caller here used to pass [`AuthConfig`] instead, so the organization's
//! setting was computed, displayed in the admin UI, stored — and never read by
//! the code that locks accounts. An administrator lowering the threshold to
//! three saw nothing change, because the login path was still counting to the
//! deployment default of five. Taking a [`LockoutPolicy`] rather than an
//! `AuthConfig` is what makes that impossible to get wrong again: there is no
//! longer a type that fits here and carries the wrong numbers.
//!
//! [`policy_from_config`] remains for the paths that genuinely have no tenant
//! in hand, and is the deployment-wide fallback rather than the norm.

use axiam_core::error::AxiamResult;
use axiam_core::models::settings::LockoutPolicy;
use axiam_core::models::user::User;
use axiam_core::repository::UserRepository;
use uuid::Uuid;

use crate::config::AuthConfig;

/// The deployment-wide lockout defaults, as a policy.
///
/// For the callers that cannot resolve a tenant's effective settings — a
/// credential check whose tenant is not yet established, or a settings lookup
/// that failed and must not be allowed to disable lockout entirely. Preferring
/// this over the tenant's own policy is a bug; falling back to it when there is
/// no tenant policy to be had is the safe direction, because it still meters.
///
/// # Examples
///
/// ```
/// use axiam_auth::config::AuthConfig;
/// use axiam_auth::lockout::policy_from_config;
///
/// let config = AuthConfig::default();
/// let policy = policy_from_config(&config);
/// assert_eq!(policy.max_failed_login_attempts, config.max_failed_login_attempts);
/// ```
pub fn policy_from_config(config: &AuthConfig) -> LockoutPolicy {
    LockoutPolicy {
        max_failed_login_attempts: config.max_failed_login_attempts,
        lockout_duration_secs: config.lockout_duration_secs,
        lockout_backoff_multiplier: config.lockout_backoff_multiplier,
        max_lockout_duration_secs: config.max_lockout_duration_secs,
    }
}

/// Resolves the lockout policy that applies to one tenant.
///
/// An object-safe seam, deliberately: the two credential-checking transports
/// reach settings by different routes. REST's login handler already holds the
/// tenant's resolved [`axiam_core::models::settings::SecuritySettings`] — it
/// fetched them to decide about OPAQUE and MFA — and simply passes
/// `settings.lockout` down. gRPC's `UserService` holds only a user repository
/// and would otherwise need two more repository type parameters threaded through
/// its generics for one field, so it holds one of these instead.
///
/// `Pin<Box<dyn Future>>` rather than `impl Future` because the repository
/// traits it wraps use RPITIT and are therefore not dyn-safe — the same seam
/// `axiam-api-rest`'s `DynMailPublisher` uses, for the same reason.
///
/// # Failure is not permission
///
/// An implementation that cannot reach the settings store MUST return the
/// deployment default (see [`policy_from_config`]) rather than an error or a
/// policy with no threshold. A settings outage that quietly disabled lockout
/// would turn a database hiccup into an open brute-force window.
pub trait LockoutPolicySource: Send + Sync {
    /// The effective policy for `tenant_id`, never failing.
    fn policy_for(
        &self,
        tenant_id: Uuid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = LockoutPolicy> + Send + '_>>;
}

/// A [`LockoutPolicySource`] that always answers with one fixed policy.
///
/// The deployment-wide default, for a composition root with no settings store
/// wired up and for tests. Named rather than anonymous so a `Debug` of the
/// service that holds it says which one it got.
#[derive(Debug, Clone)]
pub struct StaticLockoutPolicy(pub LockoutPolicy);

impl LockoutPolicySource for StaticLockoutPolicy {
    fn policy_for(
        &self,
        _tenant_id: Uuid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = LockoutPolicy> + Send + '_>> {
        let policy = self.0.clone();
        Box::pin(async move { policy })
    }
}

/// A [`LockoutPolicySource`] backed by the tenant's stored security settings.
///
/// Resolves the organization from the tenant record, then asks the settings
/// repository for the merged org→tenant policy — the same
/// `get_effective_settings` call the REST login handler makes, so both
/// transports lock accounts on identical numbers.
///
/// Both failures — an unknown tenant, an unreachable settings store — fall back
/// to `default_policy` with a warning rather than propagating. See
/// [`LockoutPolicySource`] on why failure must not mean "no lockout".
///
/// # Examples
///
/// ```ignore
/// let source = SettingsLockoutPolicy::new(
///     settings_repo.clone(),
///     tenant_repo.clone(),
///     policy_from_config(&auth_config),
/// );
/// let policy = source.policy_for(tenant_id).await;
/// ```
#[derive(Clone)]
pub struct SettingsLockoutPolicy<S, T> {
    settings_repo: S,
    tenant_repo: T,
    default_policy: LockoutPolicy,
}

impl<S, T> SettingsLockoutPolicy<S, T> {
    /// Build a source. `default_policy` is what a resolution failure answers
    /// with — pass [`policy_from_config`] of the deployment's `AuthConfig`.
    pub fn new(settings_repo: S, tenant_repo: T, default_policy: LockoutPolicy) -> Self {
        Self {
            settings_repo,
            tenant_repo,
            default_policy,
        }
    }
}

impl<S, T> LockoutPolicySource for SettingsLockoutPolicy<S, T>
where
    S: axiam_core::repository::SettingsRepository + Send + Sync,
    T: axiam_core::repository::TenantRepository + Send + Sync,
{
    fn policy_for(
        &self,
        tenant_id: Uuid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = LockoutPolicy> + Send + '_>> {
        Box::pin(async move {
            let tenant = match self.tenant_repo.get_by_id(tenant_id).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        %tenant_id,
                        "could not resolve the tenant for its lockout policy; \
                         metering against the deployment default"
                    );
                    return self.default_policy.clone();
                }
            };
            match self
                .settings_repo
                .get_effective_settings(tenant.organization_id, tenant_id)
                .await
            {
                Ok(settings) => settings.lockout,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        %tenant_id,
                        "could not resolve effective lockout settings; \
                         metering against the deployment default"
                    );
                    self.default_policy.clone()
                }
            }
        })
    }
}

/// Whether `user` is currently serving a lockout.
///
/// [`crate::AuthService::login`] checks this inline against the user it just
/// fetched. The OPAQUE login-finish path needs the same question answered from the
/// outside, and a free function is the way to ask it without naming
/// `AuthService`'s four repository type parameters at the call site.
pub fn is_locked_out(user: &axiam_core::models::user::User) -> bool {
    user.locked_until
        .is_some_and(|until| until > chrono::Utc::now())
}

/// Record a failed login attempt for `user`, applying the exponential
/// lockout backoff described by `policy`.
///
/// `policy` is the tenant-effective [`LockoutPolicy`] — see the module docs for
/// why this is not an [`AuthConfig`]. Use [`policy_from_config`] only where no
/// tenant policy can be resolved.
///
/// SEC-032: atomic increment — single SurrealQL UPDATE avoids TOCTOU race.
/// Lockout duration escalates exponentially per repeated lockout, capped
/// at `policy.max_lockout_duration_secs` (brute-force protection).
///
/// D-06: always-on accrual — callers must invoke this on every failed
/// credential check (wrong password against an existing, non-locked user),
/// never behind a config flag.
pub async fn record_failed_login<U: UserRepository>(
    user_repo: &U,
    policy: &LockoutPolicy,
    tenant_id: Uuid,
    user: &User,
) -> AxiamResult<()> {
    user_repo
        .increment_failed_logins(
            tenant_id,
            user.id,
            policy.max_failed_login_attempts,
            policy.lockout_duration_secs as i64,
            policy.lockout_backoff_multiplier,
            policy.max_lockout_duration_secs as i64,
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_from_config_carries_every_lockout_field() {
        let mut config = AuthConfig::default();
        config.max_failed_login_attempts = 3;
        config.lockout_duration_secs = 120;
        config.lockout_backoff_multiplier = 3.0;
        config.max_lockout_duration_secs = 900;

        let policy = policy_from_config(&config);

        // Each field asserted separately: a mapping that silently dropped one
        // would mean lockout ran on a default the operator never chose.
        assert_eq!(policy.max_failed_login_attempts, 3);
        assert_eq!(policy.lockout_duration_secs, 120);
        assert_eq!(policy.lockout_backoff_multiplier, 3.0);
        assert_eq!(policy.max_lockout_duration_secs, 900);
    }

    #[test]
    fn is_locked_out_reads_the_lockout_deadline() {
        use chrono::{Duration, Utc};

        let mut user = axiam_core::models::user::User {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            username: "u".into(),
            email: "u@example.com".into(),
            password_hash: String::new(),
            status: axiam_core::models::user::UserStatus::Active,
            mfa_enabled: false,
            mfa_secret: None,
            totp_last_used_step: None,
            failed_login_attempts: 0,
            last_failed_login_at: None,
            locked_until: None,
            email_verified_at: None,
            deletion_pending: false,
            scheduled_purge_at: None,
            metadata: serde_json::Value::Null,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(!is_locked_out(&user), "no deadline means not locked");

        user.locked_until = Some(Utc::now() - Duration::minutes(1));
        assert!(!is_locked_out(&user), "a past deadline has been served");

        user.locked_until = Some(Utc::now() + Duration::minutes(1));
        assert!(
            is_locked_out(&user),
            "a future deadline is an active lockout"
        );
    }
}
