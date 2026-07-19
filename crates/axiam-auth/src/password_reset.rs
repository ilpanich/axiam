//! Password reset service — token generation, consumption, password
//! update with policy enforcement and fail2ban counter reset.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::password_history::CreatePasswordHistoryEntry;
use axiam_core::models::password_reset::CreatePasswordResetToken;
use axiam_core::models::settings::PasswordPolicy;
use axiam_core::models::user::UpdateUser;
use axiam_core::repository::{
    FederationLinkRepository, PasswordHistoryRepository, PasswordResetTokenRepository,
    RefreshTokenRepository, SessionRepository, UserRepository,
};
use chrono::{Duration, Utc};
use std::sync::Arc;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::crypto_gate::acquire_hash_permit;
use crate::error::AuthError;
use crate::password::{self, DUMMY_HASH, hash_password, verify_password};
use crate::policy::{PolicyCheckResult, evaluate_password};
use crate::token;

/// Maximum password reset requests per user per day.
const MAX_RESETS_PER_DAY: u64 = 3;

/// Password reset service.
///
/// Handles reset token generation with rate limiting and prior-token
/// invalidation, plus reset confirmation with password policy
/// enforcement, fail2ban counter reset, and password history storage.
///
/// `S` is the session repository — used by `confirm_reset` to invalidate ALL
/// active sessions after a successful password reset (D-16 — caller is
/// unauthenticated so there is no current session to preserve).
///
/// `T` is the OAuth2 refresh-token repository — used by `confirm_reset` to
/// also revoke OAuth2-flow refresh tokens (RESEARCH §4 "two chokepoints").
///
/// `Clone` (QUAL-07): this service is now a hoisted `AppState<C>` singleton
/// constructed once at startup and cloned per Actix worker, rather than
/// rebuilt per-request.
#[derive(Clone)]
pub struct PasswordResetService<U, R, F, H, S, T>
where
    U: UserRepository,
    R: PasswordResetTokenRepository,
    F: FederationLinkRepository,
    H: PasswordHistoryRepository,
    S: SessionRepository,
    T: RefreshTokenRepository,
{
    user_repo: U,
    token_repo: R,
    federation_repo: F,
    history_repo: H,
    session_repo: S,
    refresh_token_repo: T,
    /// Bounding semaphore (CQ-B02, mirrors `AuthService`): limits concurrent
    /// Argon2 operations (including the T-24-91 dummy-hash timing
    /// equalization below and the T-24-92 current-password check) to
    /// prevent CPU-bound crypto from starving the Tokio async runtime.
    crypto_semaphore: Arc<Semaphore>,
    /// B1: Seconds to wait for a `crypto_semaphore` permit before returning a
    /// 503 backpressure error. Threaded from `AuthConfig::hash_acquire_timeout_secs`.
    hash_acquire_timeout_secs: u64,
}

impl<U, R, F, H, S, T> PasswordResetService<U, R, F, H, S, T>
where
    U: UserRepository,
    R: PasswordResetTokenRepository,
    F: FederationLinkRepository,
    H: PasswordHistoryRepository,
    S: SessionRepository,
    T: RefreshTokenRepository,
{
    pub fn new(
        user_repo: U,
        token_repo: R,
        federation_repo: F,
        history_repo: H,
        session_repo: S,
        refresh_token_repo: T,
        crypto_semaphore: Arc<Semaphore>,
        hash_acquire_timeout_secs: u64,
    ) -> Self {
        Self {
            user_repo,
            token_repo,
            federation_repo,
            history_repo,
            session_repo,
            refresh_token_repo,
            crypto_semaphore,
            hash_acquire_timeout_secs,
        }
    }

    /// Constant-time dummy Argon2 verify (T-24-91).
    ///
    /// Mirrors the SEC-026 pattern already live in `AuthService::login`
    /// exactly: acquire the shared `crypto_semaphore`, run a dummy
    /// Argon2id verify against the relocated `DUMMY_HASH` constant inside
    /// `spawn_blocking`, and discard the result. Called from BOTH of
    /// `initiate_reset`'s `Ok(None)` branches (unknown email, federated
    /// user) so those responses are time-indistinguishable from the
    /// valid-account branch — no hand-tuned fixed-duration sleep.
    async fn dummy_hash_wait(&self, pepper: Option<&str>) {
        // B1: bound this enumeration-defence dummy hash by the crypto
        // semaphore (and its timeout) so it counts against the same
        // concurrency budget as real verifies and cannot itself become an
        // un-throttled arena allocator.
        //
        // Unlike the login not-found branch, we deliberately do NOT surface a
        // backpressure error here: `initiate_reset`'s *valid-account* branch
        // does no Argon2 work and never touches the semaphore, so if this path
        // returned 503 under saturation while the valid path returned
        // `Ok(None)`, that difference would itself be a user-enumeration oracle
        // (D-15). Instead we bound the wait by the same timeout and, if it
        // elapses, simply skip the dummy hash and return normally — the
        // observable result (`Ok(None)`) is identical to the valid branch
        // regardless of load. Memory stays bounded because the permit *count*
        // still caps concurrent arenas even when this path skips hashing.
        let acquired = tokio::time::timeout(
            std::time::Duration::from_secs(self.hash_acquire_timeout_secs),
            self.crypto_semaphore.acquire(),
        )
        .await;
        if let Ok(Ok(_permit)) = acquired {
            let pepper_owned = pepper.map(str::to_string);
            let _ = tokio::task::spawn_blocking(move || {
                password::verify_password("dummy", DUMMY_HASH, pepper_owned.as_deref())
            })
            .await;
        }
    }

    /// Initiate a password reset for the given email.
    ///
    /// Returns `Ok(Some((raw_token, user_id, expires_at)))` on success,
    /// `Ok(None)` if the email doesn't exist or user is federated
    /// (to prevent user enumeration).
    ///
    /// Returns `Err(RateLimited)` if the daily limit is exceeded.
    ///
    /// `pepper` is threaded through so the unknown-email and federated-user
    /// branches can run the T-24-91 constant-time dummy Argon2 verify with
    /// the same pepper the real hashing/verification call sites use.
    pub async fn initiate_reset(
        &self,
        tenant_id: Uuid,
        email: &str,
        expiry_hours: u32,
        pepper: Option<&str>,
    ) -> AxiamResult<Option<(String, Uuid, chrono::DateTime<chrono::Utc>)>> {
        // Look up user — silently return None if not found.
        let user = match self.user_repo.get_by_email(tenant_id, email).await {
            Ok(u) => u,
            Err(AxiamError::NotFound { .. }) => {
                // T-24-91: constant-time dummy Argon2 verify so an unknown
                // email is time-indistinguishable from a valid one.
                self.dummy_hash_wait(pepper).await;
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        // Federated users cannot reset passwords — return None to
        // prevent enumeration.
        let links = self
            .federation_repo
            .get_by_user_id(tenant_id, user.id)
            .await?;
        if !links.is_empty() {
            // T-24-91: same constant-time treatment as the unknown-email
            // branch above — a federated account must not resolve faster.
            self.dummy_hash_wait(pepper).await;
            return Ok(None);
        }

        // Rate limit: max resets per day.
        let count = self.token_repo.count_today(tenant_id, user.id).await?;
        if count >= MAX_RESETS_PER_DAY {
            return Err(AxiamError::RateLimited);
        }

        // Invalidate any prior unconsumed tokens for this user so
        // intercepted older emails cannot be used after a newer
        // reset request.
        self.token_repo
            .delete_unconsumed_for_user(tenant_id, user.id)
            .await?;

        let raw_token = token::generate_refresh_token();
        let token_hash = token::hash_refresh_token(&raw_token);
        let expires_at = Utc::now() + Duration::hours(expiry_hours as i64);

        self.token_repo
            .create(CreatePasswordResetToken {
                tenant_id,
                user_id: user.id,
                token_hash,
                expires_at,
            })
            .await?;

        Ok(Some((raw_token, user.id, expires_at)))
    }

    /// Confirm a password reset using the raw token and a new password.
    ///
    /// Validates the token, enforces password policy, hashes the new
    /// password, updates the user (including resetting fail2ban
    /// counters), and stores the old password in history.
    pub async fn confirm_reset(
        &self,
        tenant_id: Uuid,
        raw_token: &str,
        new_password: &str,
        policy: &PasswordPolicy,
        pepper: Option<&str>,
        http_client: Option<&reqwest::Client>,
    ) -> AxiamResult<()> {
        let token_hash = token::hash_refresh_token(raw_token);

        // Atomically consume the token.
        let consumed = self
            .token_repo
            .consume(tenant_id, &token_hash)
            .await
            .map_err(|e| match e {
                AxiamError::NotFound { .. } => AxiamError::from(AuthError::ResetTokenInvalid),
                other => other,
            })?;

        // Look up the user.
        let user = self
            .user_repo
            .get_by_id(tenant_id, consumed.user_id)
            .await?;

        // Federated users cannot reset passwords.
        let links = self
            .federation_repo
            .get_by_user_id(tenant_id, user.id)
            .await?;
        if !links.is_empty() {
            return Err(AuthError::FederatedUserPasswordReset.into());
        }

        // T-24-92 / RESEARCH Pitfall 4: explicit current-password-reuse
        // rejection, independent of and in addition to the
        // password_history_count-based check below. The history check
        // alone is insufficient because the pre-reset hash is not yet in
        // `password_history` at check time (it's written further down),
        // so a user with zero prior history rows could otherwise reset
        // straight back to their own current password. CPU-bound Argon2,
        // run under the crypto_semaphore-gated spawn_blocking path (A3)
        // consistent with every other Argon2 call site in this codebase.
        {
            // B1: bounded acquire — 503 backpressure on timeout. Enumeration is
            // not a concern here (the caller already holds a valid reset token),
            // so surfacing the error is safe and correct.
            let _permit = acquire_hash_permit(
                &self.crypto_semaphore,
                std::time::Duration::from_secs(self.hash_acquire_timeout_secs),
            )
            .await?;
            let new_pw_owned = new_password.to_string();
            let current_hash_owned = user.password_hash.clone();
            let pepper_owned = pepper.map(str::to_string);
            let is_current_password = tokio::task::spawn_blocking(move || {
                verify_password(&new_pw_owned, &current_hash_owned, pepper_owned.as_deref())
            })
            .await
            .map_err(|e| AxiamError::Internal(format!("spawn_blocking join error: {e}")))?
            .map_err(|e| AxiamError::Crypto(e.to_string()))?;
            if is_current_password {
                return Err(AuthError::PasswordReusedCurrent.into());
            }
        }

        // Evaluate password policy, including the password_history_count
        // check (which performs its own CPU-bound Argon2 verifies against
        // recent history entries) and the HIBP breach check when the
        // policy has it enabled and a client is provided. Held under the
        // crypto_semaphore for the duration of the call so the history
        // check's Argon2 work is CPU-isolated like every other crypto
        // call site (A3) — `confirm_reset` previously performed this work
        // fully ungated.
        let check: PolicyCheckResult = {
            // B1: bounded acquire — held for the duration of the policy
            // evaluation so the history check's Argon2 verifies run under one
            // permit; 503 backpressure on timeout.
            let _permit = acquire_hash_permit(
                &self.crypto_semaphore,
                std::time::Duration::from_secs(self.hash_acquire_timeout_secs),
            )
            .await?;
            evaluate_password(
                new_password,
                pepper,
                policy,
                tenant_id,
                user.id,
                &self.history_repo,
                http_client,
            )
            .await?
        };

        if !check.is_ok() {
            return Err(AxiamError::Validation {
                message: check.error_message(),
            });
        }

        // Hash the new password.
        let new_hash = hash_password(new_password, pepper)?;

        // Store the old password in history.
        self.history_repo
            .create(CreatePasswordHistoryEntry {
                tenant_id,
                user_id: user.id,
                password_hash: user.password_hash.clone(),
            })
            .await?;

        // Invalidate all active sessions for the user (D-16: password reset
        // caller is unauthenticated, so there is no current session to preserve —
        // ALL sessions die).  Both the session-flow tokens AND the OAuth2-flow
        // refresh tokens must be revoked (RESEARCH §4 — D-18 "two chokepoints").
        self.session_repo
            .invalidate_user_sessions(tenant_id, user.id)
            .await?;
        self.refresh_token_repo
            .revoke_all_for_user(tenant_id, user.id)
            .await?;

        // Update user: new password hash + reset fail2ban counters.
        self.user_repo
            .update(
                tenant_id,
                user.id,
                UpdateUser {
                    password_hash: Some(new_hash),
                    failed_login_attempts: Some(0),
                    locked_until: Some(None),
                    last_failed_login_at: Some(None),
                    ..Default::default()
                },
            )
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::federation::{
        CreateFederationConfig, CreateFederationLink, FederationProtocol,
    };
    use axiam_core::models::password_history::CreatePasswordHistoryEntry;
    use axiam_core::models::settings::PasswordPolicy;
    use axiam_core::models::user::CreateUser;
    use axiam_core::repository::{
        FederationConfigRepository, FederationLinkRepository, PasswordHistoryRepository,
        PasswordResetTokenRepository, UserRepository,
    };
    use axiam_db::{
        SurrealFederationConfigRepository, SurrealFederationLinkRepository,
        SurrealPasswordHistoryRepository, SurrealPasswordResetTokenRepository,
        SurrealRefreshTokenRepository, SurrealSessionRepository, SurrealUserRepository,
        run_migrations,
    };
    use surrealdb::engine::local::Db;

    fn relaxed_policy() -> PasswordPolicy {
        PasswordPolicy {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_digits: true,
            require_symbols: false,
            password_history_count: 5,
            hibp_check_enabled: false,
        }
    }

    async fn create_test_user(
        user_repo: &SurrealUserRepository<Db>,
        tenant_id: Uuid,
    ) -> axiam_core::models::user::User {
        user_repo
            .create(CreateUser {
                tenant_id,
                username: "testuser".into(),
                email: "test@example.com".into(),
                password: "OldPassw0rd!Strong".into(),
                metadata: None,
            })
            .await
            .unwrap()
    }

    /// Helper: create an org + tenant and return their IDs.
    async fn create_org_tenant(db: &surrealdb::Surreal<Db>) -> (Uuid, Uuid) {
        use axiam_core::models::organization::CreateOrganization;
        use axiam_core::models::tenant::CreateTenant;
        use axiam_core::repository::{OrganizationRepository, TenantRepository};
        use axiam_db::{SurrealOrganizationRepository, SurrealTenantRepository};

        let org_repo = SurrealOrganizationRepository::new(db.clone());
        let org = org_repo
            .create(CreateOrganization {
                name: "Test Org".into(),
                slug: "test-org".into(),
                metadata: None,
            })
            .await
            .unwrap();

        let tenant_repo = SurrealTenantRepository::new(db.clone());
        let tenant = tenant_repo
            .create(CreateTenant {
                organization_id: org.id,
                name: "Test Tenant".into(),
                slug: "test-tenant".into(),
                metadata: None,
            })
            .await
            .unwrap();

        (org.id, tenant.id)
    }

    /// Full setup: DB + org + tenant + user.
    async fn full_setup() -> (
        SurrealUserRepository<Db>,
        SurrealPasswordResetTokenRepository<Db>,
        SurrealFederationLinkRepository<Db>,
        SurrealPasswordHistoryRepository<Db>,
        SurrealSessionRepository<Db>,
        SurrealRefreshTokenRepository<Db>,
        Uuid, // tenant_id
        axiam_core::models::user::User,
    ) {
        let db = surrealdb::Surreal::new::<surrealdb::engine::local::Mem>(())
            .await
            .unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        run_migrations(&db).await.unwrap();

        let (_org_id, tenant_id) = create_org_tenant(&db).await;

        let user_repo = SurrealUserRepository::new(db.clone());
        let token_repo = SurrealPasswordResetTokenRepository::new(db.clone());
        let fed_repo = SurrealFederationLinkRepository::new(db.clone());
        let hist_repo = SurrealPasswordHistoryRepository::new(db.clone());
        let session_repo = SurrealSessionRepository::new(db.clone());
        let refresh_token_repo = SurrealRefreshTokenRepository::new(db.clone());

        let user = create_test_user(&user_repo, tenant_id).await;

        (
            user_repo,
            token_repo,
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            tenant_id,
            user,
        )
    }

    #[tokio::test]
    async fn initiate_reset_generates_token() {
        let (
            user_repo,
            token_repo,
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            tid,
            user,
        ) = full_setup().await;
        let svc = PasswordResetService::new(
            user_repo,
            token_repo,
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            Arc::new(Semaphore::new(4)),
            5,
        );

        let result = svc.initiate_reset(tid, &user.email, 1, None).await.unwrap();

        assert!(result.is_some());
        let (raw_token, user_id, expires_at) = result.unwrap();
        assert_eq!(user_id, user.id);
        assert!(!raw_token.is_empty());
        assert!(expires_at > Utc::now());
    }

    #[tokio::test]
    async fn initiate_reset_returns_none_for_unknown_email() {
        let (
            user_repo,
            token_repo,
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            tid,
            _user,
        ) = full_setup().await;
        let svc = PasswordResetService::new(
            user_repo,
            token_repo,
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            Arc::new(Semaphore::new(4)),
            5,
        );

        let result = svc
            .initiate_reset(tid, "nonexistent@example.com", 1, None)
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn initiate_reset_returns_none_for_federated_user() {
        let db = surrealdb::Surreal::new::<surrealdb::engine::local::Mem>(())
            .await
            .unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        run_migrations(&db).await.unwrap();

        let (_org_id, tid) = create_org_tenant(&db).await;

        let user_repo = SurrealUserRepository::new(db.clone());
        let token_repo = SurrealPasswordResetTokenRepository::new(db.clone());
        let fed_repo = SurrealFederationLinkRepository::new(db.clone());
        let hist_repo = SurrealPasswordHistoryRepository::new(db.clone());
        let session_repo = SurrealSessionRepository::new(db.clone());
        let refresh_token_repo = SurrealRefreshTokenRepository::new(db.clone());

        let user = create_test_user(&user_repo, tid).await;

        // Create a federation config, then link the user.
        let fed_config_repo = SurrealFederationConfigRepository::new(db.clone());
        let fed_config = fed_config_repo
            .create(CreateFederationConfig {
                tenant_id: tid,
                provider: "google".into(),
                protocol: FederationProtocol::OidcConnect,
                metadata_url: None,
                client_id: "google-client-id".into(),
                client_secret: "google-secret".into(),
                attribute_map: None,
                idp_signing_cert_pem: None,
                allowed_algorithms: None,
            })
            .await
            .unwrap();

        fed_repo
            .create(CreateFederationLink {
                tenant_id: tid,
                user_id: user.id,
                federation_config_id: fed_config.id,
                external_subject: "ext-123".into(),
                external_email: Some("test@example.com".into()),
            })
            .await
            .unwrap();

        let svc = PasswordResetService::new(
            user_repo,
            token_repo,
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            Arc::new(Semaphore::new(4)),
            5,
        );

        let result = svc.initiate_reset(tid, &user.email, 1, None).await.unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn initiate_reset_rate_limited() {
        let (
            user_repo,
            token_repo,
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            tid,
            user,
        ) = full_setup().await;
        let svc = PasswordResetService::new(
            user_repo,
            token_repo,
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            Arc::new(Semaphore::new(4)),
            5,
        );

        // First 3 requests should succeed.
        for _ in 0..3 {
            let result = svc.initiate_reset(tid, &user.email, 1, None).await.unwrap();
            assert!(result.is_some());
        }

        // 4th request should be rate limited.
        let result = svc.initiate_reset(tid, &user.email, 1, None).await;
        assert!(
            matches!(result, Err(AxiamError::RateLimited)),
            "expected RateLimited, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn initiate_reset_invalidates_prior_tokens() {
        let (
            user_repo,
            token_repo,
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            tid,
            user,
        ) = full_setup().await;
        let svc = PasswordResetService::new(
            user_repo,
            token_repo.clone(),
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            Arc::new(Semaphore::new(4)),
            5,
        );

        // Generate first token.
        let first = svc
            .initiate_reset(tid, &user.email, 1, None)
            .await
            .unwrap()
            .unwrap();

        // Generate second token — should invalidate the first.
        let second = svc
            .initiate_reset(tid, &user.email, 1, None)
            .await
            .unwrap()
            .unwrap();

        assert_ne!(first.0, second.0);

        // First token should now be invalidated (deleted).
        let first_hash = token::hash_refresh_token(&first.0);
        let consume_result = token_repo.consume(tid, &first_hash).await;
        assert!(
            consume_result.is_err(),
            "first token should be invalidated after new request"
        );

        // Second token should still be consumable.
        let second_hash = token::hash_refresh_token(&second.0);
        let consume_result = token_repo.consume(tid, &second_hash).await;
        assert!(consume_result.is_ok(), "latest token should be consumable");
    }

    #[tokio::test]
    async fn confirm_reset_succeeds_and_clears_lockout() {
        let (
            user_repo,
            token_repo,
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            tid,
            user,
        ) = full_setup().await;

        // Lock the user out first.
        user_repo
            .update(
                tid,
                user.id,
                UpdateUser {
                    failed_login_attempts: Some(5),
                    locked_until: Some(Some(Utc::now() + Duration::hours(1))),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let svc = PasswordResetService::new(
            user_repo.clone(),
            token_repo,
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            Arc::new(Semaphore::new(4)),
            5,
        );

        let (raw_token, _uid, _exp) = svc
            .initiate_reset(tid, &user.email, 1, None)
            .await
            .unwrap()
            .unwrap();

        let policy = relaxed_policy();
        svc.confirm_reset(tid, &raw_token, "NewStr0ngPassword", &policy, None, None)
            .await
            .unwrap();

        // Verify lockout was fully cleared.
        let updated = user_repo.get_by_id(tid, user.id).await.unwrap();
        assert_eq!(updated.failed_login_attempts, 0);
        assert!(updated.locked_until.is_none());
        assert!(updated.last_failed_login_at.is_none());
    }

    #[tokio::test]
    async fn confirm_reset_invalid_token() {
        let (
            user_repo,
            token_repo,
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            tid,
            _user,
        ) = full_setup().await;
        let svc = PasswordResetService::new(
            user_repo,
            token_repo,
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            Arc::new(Semaphore::new(4)),
            5,
        );
        let policy = relaxed_policy();

        let result = svc
            .confirm_reset(tid, "bogus-token", "NewStr0ngPassword", &policy, None, None)
            .await;

        assert!(result.is_err());
        assert!(
            matches!(result, Err(AxiamError::Validation { .. })),
            "expected Validation error, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn confirm_reset_expired_token() {
        let (
            user_repo,
            token_repo,
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            tid,
            user,
        ) = full_setup().await;

        // Create a token that is already expired.
        let raw_token = token::generate_refresh_token();
        let token_hash = token::hash_refresh_token(&raw_token);
        token_repo
            .create(CreatePasswordResetToken {
                tenant_id: tid,
                user_id: user.id,
                token_hash,
                expires_at: Utc::now() - Duration::hours(1),
            })
            .await
            .unwrap();

        let svc = PasswordResetService::new(
            user_repo,
            token_repo,
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            Arc::new(Semaphore::new(4)),
            5,
        );
        let policy = relaxed_policy();

        let result = svc
            .confirm_reset(tid, &raw_token, "NewStr0ngPassword", &policy, None, None)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn confirm_reset_rejects_weak_password() {
        let (
            user_repo,
            token_repo,
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            tid,
            user,
        ) = full_setup().await;
        let svc = PasswordResetService::new(
            user_repo,
            token_repo,
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            Arc::new(Semaphore::new(4)),
            5,
        );

        let (raw_token, _uid, _exp) = svc
            .initiate_reset(tid, &user.email, 1, None)
            .await
            .unwrap()
            .unwrap();

        let policy = relaxed_policy();
        let result = svc
            .confirm_reset(tid, &raw_token, "weak", &policy, None, None)
            .await;

        assert!(
            matches!(result, Err(AxiamError::Validation { .. })),
            "expected Validation error, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn confirm_reset_rejects_reused_password() {
        let (
            user_repo,
            token_repo,
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            tid,
            user,
        ) = full_setup().await;

        // Store the old password in history.
        let old_hash = crate::password::hash_password("ReusedPassw0rd", None).unwrap();
        hist_repo
            .create(CreatePasswordHistoryEntry {
                tenant_id: tid,
                user_id: user.id,
                password_hash: old_hash,
            })
            .await
            .unwrap();

        let svc = PasswordResetService::new(
            user_repo,
            token_repo,
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            Arc::new(Semaphore::new(4)),
            5,
        );

        let (raw_token, _uid, _exp) = svc
            .initiate_reset(tid, &user.email, 1, None)
            .await
            .unwrap()
            .unwrap();

        let policy = relaxed_policy();
        let result = svc
            .confirm_reset(tid, &raw_token, "ReusedPassw0rd", &policy, None, None)
            .await;

        assert!(
            matches!(result, Err(AxiamError::Validation { .. })),
            "expected Validation error, got: {result:?}"
        );
    }

    /// T-24-92 / RESEARCH Pitfall 4: a user who has NEVER reset before
    /// (zero `password_history` rows — the fresh-signup password from
    /// `create_test_user`) must be rejected when resetting to that SAME
    /// current password. The history-count check alone cannot catch this
    /// (the pre-reset hash isn't in history yet), so this proves the
    /// explicit `verify_password(new, current_hash)` comparison added to
    /// `confirm_reset` is truly independent of history depth.
    #[tokio::test]
    async fn confirm_reset_rejects_current_password() {
        let (
            user_repo,
            token_repo,
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            tid,
            user,
        ) = full_setup().await;

        // Sanity: zero history rows for this freshly-created user.
        let history = hist_repo.get_recent(tid, user.id, 5).await.unwrap();
        assert!(
            history.is_empty(),
            "expected zero prior password_history rows for a fresh signup"
        );

        let svc = PasswordResetService::new(
            user_repo,
            token_repo,
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            Arc::new(Semaphore::new(4)),
            5,
        );

        let (raw_token, _uid, _exp) = svc
            .initiate_reset(tid, &user.email, 1, None)
            .await
            .unwrap()
            .unwrap();

        let policy = relaxed_policy();
        // `create_test_user` sets the current password to "OldPassw0rd!Strong".
        let result = svc
            .confirm_reset(tid, &raw_token, "OldPassw0rd!Strong", &policy, None, None)
            .await;

        assert!(
            matches!(result, Err(AxiamError::Validation { .. })),
            "expected current-password reuse to be rejected as Validation, got: {result:?}"
        );

        // A genuinely NEW password must still succeed with the same
        // (still-unconsumed... no — the token above was already atomically
        // consumed on the failed attempt) — issue a fresh token to prove
        // the rejection above wasn't a false-positive that also blocks
        // legitimate resets.
        let (raw_token2, _uid, _exp) = svc
            .initiate_reset(tid, &user.email, 1, None)
            .await
            .unwrap()
            .unwrap();
        let ok_result = svc
            .confirm_reset(
                tid,
                &raw_token2,
                "BrandNewStr0ngPassword",
                &policy,
                None,
                None,
            )
            .await;
        assert!(
            ok_result.is_ok(),
            "resetting to a genuinely new password must still succeed: {ok_result:?}"
        );
    }

    /// T-24-91 statistical timing test: sample the ineligible/unknown and
    /// federated `Ok(None)` branches (both now run the constant-time
    /// `dummy_hash_wait`) alongside the valid-account branch, and assert
    /// the ineligible branches are never anomalously fast relative to the
    /// valid branch — the exact enumeration side-channel this task closes
    /// (an attacker timing responses to distinguish "unknown email" from
    /// "valid email" by an near-instant vs. slower response).
    ///
    /// `#[ignore]`d because timing tests are inherently sensitive to host
    /// scheduling noise; run explicitly with `-- --ignored` (24-RESEARCH
    /// "Sampling Rate" / Wave 0 Gaps).
    #[tokio::test]
    #[ignore = "statistical timing test — run explicitly with `cargo test -- --ignored`"]
    async fn reset_timing_indistinguishable() {
        use std::time::{Duration as StdDuration, Instant};

        const N: usize = 15;

        let db = surrealdb::Surreal::new::<surrealdb::engine::local::Mem>(())
            .await
            .unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        run_migrations(&db).await.unwrap();
        let (_org_id, tid) = create_org_tenant(&db).await;

        let user_repo = SurrealUserRepository::new(db.clone());
        let token_repo = SurrealPasswordResetTokenRepository::new(db.clone());
        let fed_repo = SurrealFederationLinkRepository::new(db.clone());
        let hist_repo = SurrealPasswordHistoryRepository::new(db.clone());
        let session_repo = SurrealSessionRepository::new(db.clone());
        let refresh_token_repo = SurrealRefreshTokenRepository::new(db.clone());

        let svc = PasswordResetService::new(
            user_repo.clone(),
            token_repo,
            fed_repo,
            hist_repo,
            session_repo,
            refresh_token_repo,
            Arc::new(Semaphore::new(4)),
            5,
        );

        fn mean(samples: &[StdDuration]) -> StdDuration {
            let total: StdDuration = samples.iter().sum();
            total / (samples.len() as u32)
        }

        // Sample 1: unknown-email branch (Ok(None), dummy_hash_wait).
        let mut unknown_samples = Vec::with_capacity(N);
        for i in 0..N {
            let email = format!("nonexistent-{i}@example.com");
            let start = Instant::now();
            let result = svc.initiate_reset(tid, &email, 1, None).await.unwrap();
            unknown_samples.push(start.elapsed());
            assert!(result.is_none());
        }

        // Sample 2: valid-account branch — a fresh user per iteration so
        // the per-user MAX_RESETS_PER_DAY limit never trips.
        let mut valid_samples = Vec::with_capacity(N);
        for i in 0..N {
            let user = user_repo
                .create(CreateUser {
                    tenant_id: tid,
                    username: format!("timing-user-{i}"),
                    email: format!("timing-user-{i}@example.com"),
                    password: "OldPassw0rd!Strong".into(),
                    metadata: None,
                })
                .await
                .unwrap();
            let start = Instant::now();
            let result = svc.initiate_reset(tid, &user.email, 1, None).await.unwrap();
            valid_samples.push(start.elapsed());
            assert!(result.is_some());
        }

        let mean_unknown = mean(&unknown_samples);
        let mean_valid = mean(&valid_samples);

        tracing::info!(
            ?mean_unknown,
            ?mean_valid,
            "reset_timing_indistinguishable: sampled means"
        );

        // T-24-91's regression target: BEFORE this fix, the unknown-email
        // branch returned `Ok(None)` almost immediately (no Argon2 work at
        // all) while the valid branch did real DB work — an attacker could
        // trivially distinguish "unknown" from "valid" by response time
        // alone. Now BOTH branches perform comparable dominant-cost work
        // (the valid branch's DB round-trips vs. the unknown branch's
        // dummy Argon2 verify), so the unknown branch must never resolve
        // in a small fraction of the valid branch's time. A generous
        // bound (rather than a tight one) is used deliberately — per
        // 24-RESEARCH Anti-Patterns, this must never regress into a
        // hand-tuned fixed-duration assertion; it only guards against the
        // original "near-instant" enumeration signal.
        let floor = mean_valid / 4;
        assert!(
            mean_unknown >= floor,
            "unknown-email branch resolved suspiciously fast \
             (mean_unknown={mean_unknown:?} vs mean_valid={mean_valid:?}, \
             expected mean_unknown >= {floor:?}) — dummy_hash_wait may not \
             be running"
        );

        // The two Ok(None) branches (unknown + federated) execute the
        // identical dummy_hash_wait code path, so they should be tightly
        // overlapping with each other. Sample the federated branch too.
        let fed_user = user_repo
            .create(CreateUser {
                tenant_id: tid,
                username: "fed-timing-user".into(),
                email: "fed-timing-user@example.com".into(),
                password: "OldPassw0rd!Strong".into(),
                metadata: None,
            })
            .await
            .unwrap();
        let fed_config_repo = SurrealFederationConfigRepository::new(db.clone());
        let fed_config = fed_config_repo
            .create(CreateFederationConfig {
                tenant_id: tid,
                provider: "google".into(),
                protocol: FederationProtocol::OidcConnect,
                metadata_url: None,
                client_id: "google-client-id".into(),
                client_secret: "google-secret".into(),
                attribute_map: None,
                idp_signing_cert_pem: None,
                allowed_algorithms: None,
            })
            .await
            .unwrap();
        let fed_link_repo = SurrealFederationLinkRepository::new(db.clone());
        fed_link_repo
            .create(CreateFederationLink {
                tenant_id: tid,
                user_id: fed_user.id,
                federation_config_id: fed_config.id,
                external_subject: "ext-timing".into(),
                external_email: Some(fed_user.email.clone()),
            })
            .await
            .unwrap();

        let mut fed_samples = Vec::with_capacity(N);
        for _ in 0..N {
            let start = Instant::now();
            let result = svc
                .initiate_reset(tid, &fed_user.email, 1, None)
                .await
                .unwrap();
            fed_samples.push(start.elapsed());
            assert!(result.is_none());
        }
        let mean_fed = mean(&fed_samples);

        tracing::info!(?mean_fed, "reset_timing_indistinguishable: federated mean");

        // Overlap check between the two structurally-identical dummy-hash
        // branches: neither should be more than 5x the other. This is a
        // loose bound tolerant of scheduler jitter while still catching a
        // gross asymmetry (e.g. dummy_hash_wait accidentally skipped on
        // one of the two Ok(None) branches).
        let (lo, hi) = if mean_unknown <= mean_fed {
            (mean_unknown, mean_fed)
        } else {
            (mean_fed, mean_unknown)
        };
        assert!(
            hi <= lo * 5,
            "unknown-email and federated-user branches diverged too far: \
             mean_unknown={mean_unknown:?}, mean_fed={mean_fed:?}"
        );
    }
}
