//! Shared failed-login / lockout accrual (D-06).
//!
//! Both the REST login path (`AuthService::record_failed_login`) and the
//! gRPC `UserService::validate_credentials` path call this single helper so
//! that there is no unmetered credential-check path anywhere in the system
//! (SEC-026b). This module is the single source of truth for the
//! failed-attempt/lockout increment — do NOT duplicate this logic anywhere
//! else.

use axiam_core::error::AxiamResult;
use axiam_core::models::user::User;
use axiam_core::repository::UserRepository;
use uuid::Uuid;

use crate::config::AuthConfig;

/// Record a failed login attempt for `user`, applying the exponential
/// lockout backoff configured in `config`.
///
/// SEC-032: atomic increment — single SurrealQL UPDATE avoids TOCTOU race.
/// Lockout duration escalates exponentially per repeated lockout, capped
/// at `max_lockout_duration_secs` (brute-force protection).
///
/// D-06: always-on accrual — callers must invoke this on every failed
/// credential check (wrong password against an existing, non-locked user),
/// never behind a config flag.
/// Whether `user` is currently serving a lockout.
///
/// [`crate::AuthService::login`] checks this inline against the user it just
/// fetched. The SRP verify path needs the same question answered from the
/// outside, and a free function is the way to ask it without naming
/// `AuthService`'s four repository type parameters at the call site.
pub fn is_locked_out(user: &axiam_core::models::user::User) -> bool {
    user.locked_until
        .is_some_and(|until| until > chrono::Utc::now())
}

pub async fn record_failed_login<U: UserRepository>(
    user_repo: &U,
    config: &AuthConfig,
    tenant_id: Uuid,
    user: &User,
) -> AxiamResult<()> {
    user_repo
        .increment_failed_logins(
            tenant_id,
            user.id,
            config.max_failed_login_attempts,
            config.lockout_duration_secs as i64,
            config.lockout_backoff_multiplier,
            config.max_lockout_duration_secs as i64,
        )
        .await
}
