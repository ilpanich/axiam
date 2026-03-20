//! Password reset service — token generation, consumption, password
//! update with policy enforcement and fail2ban counter reset.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::password_history::CreatePasswordHistoryEntry;
use axiam_core::models::password_reset::CreatePasswordResetToken;
use axiam_core::models::settings::PasswordPolicy;
use axiam_core::models::user::UpdateUser;
use axiam_core::repository::{
    FederationLinkRepository, PasswordHistoryRepository, PasswordResetTokenRepository,
    UserRepository,
};
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::error::AuthError;
use crate::password::hash_password;
use crate::policy::{PolicyCheckResult, evaluate_password};
use crate::token;

/// Maximum password reset requests per user per day.
const MAX_RESETS_PER_DAY: u64 = 3;

/// Password reset service.
///
/// Handles reset token generation with rate limiting and prior-token
/// invalidation, plus reset confirmation with password policy
/// enforcement, fail2ban counter reset, and password history storage.
pub struct PasswordResetService<U, R, F, H>
where
    U: UserRepository,
    R: PasswordResetTokenRepository,
    F: FederationLinkRepository,
    H: PasswordHistoryRepository,
{
    user_repo: U,
    token_repo: R,
    federation_repo: F,
    history_repo: H,
}

impl<U, R, F, H> PasswordResetService<U, R, F, H>
where
    U: UserRepository,
    R: PasswordResetTokenRepository,
    F: FederationLinkRepository,
    H: PasswordHistoryRepository,
{
    pub fn new(user_repo: U, token_repo: R, federation_repo: F, history_repo: H) -> Self {
        Self {
            user_repo,
            token_repo,
            federation_repo,
            history_repo,
        }
    }

    /// Initiate a password reset for the given email.
    ///
    /// Returns `Ok(Some((raw_token, user_id, expires_at)))` on success,
    /// `Ok(None)` if the email doesn't exist or user is federated
    /// (to prevent user enumeration).
    ///
    /// Returns `Err(RateLimited)` if the daily limit is exceeded.
    pub async fn initiate_reset(
        &self,
        tenant_id: Uuid,
        email: &str,
        expiry_hours: u32,
    ) -> AxiamResult<Option<(String, Uuid, chrono::DateTime<chrono::Utc>)>> {
        // Look up user — silently return None if not found.
        let user = match self.user_repo.get_by_email(tenant_id, email).await {
            Ok(u) => u,
            Err(AxiamError::NotFound { .. }) => return Ok(None),
            Err(e) => return Err(e),
        };

        // Federated users cannot reset passwords — return None to
        // prevent enumeration.
        let links = self
            .federation_repo
            .get_by_user_id(tenant_id, user.id)
            .await?;
        if !links.is_empty() {
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

        // Evaluate password policy.
        let check: PolicyCheckResult = evaluate_password(
            new_password,
            pepper,
            policy,
            tenant_id,
            user.id,
            &self.history_repo,
            None, // Skip HIBP in reset flow (can be enabled later)
        )
        .await?;

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

        // Update user: new password hash + reset fail2ban counters.
        // TODO(T19): invalidate all active sessions for the user.
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
        SurrealUserRepository, run_migrations,
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

        let user = create_test_user(&user_repo, tenant_id).await;

        (user_repo, token_repo, fed_repo, hist_repo, tenant_id, user)
    }

    #[tokio::test]
    async fn initiate_reset_generates_token() {
        let (user_repo, token_repo, fed_repo, hist_repo, tid, user) = full_setup().await;
        let svc = PasswordResetService::new(user_repo, token_repo, fed_repo, hist_repo);

        let result = svc.initiate_reset(tid, &user.email, 1).await.unwrap();

        assert!(result.is_some());
        let (raw_token, user_id, expires_at) = result.unwrap();
        assert_eq!(user_id, user.id);
        assert!(!raw_token.is_empty());
        assert!(expires_at > Utc::now());
    }

    #[tokio::test]
    async fn initiate_reset_returns_none_for_unknown_email() {
        let (user_repo, token_repo, fed_repo, hist_repo, tid, _user) = full_setup().await;
        let svc = PasswordResetService::new(user_repo, token_repo, fed_repo, hist_repo);

        let result = svc
            .initiate_reset(tid, "nonexistent@example.com", 1)
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

        let svc = PasswordResetService::new(user_repo, token_repo, fed_repo, hist_repo);

        let result = svc.initiate_reset(tid, &user.email, 1).await.unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn initiate_reset_rate_limited() {
        let (user_repo, token_repo, fed_repo, hist_repo, tid, user) = full_setup().await;
        let svc = PasswordResetService::new(user_repo, token_repo, fed_repo, hist_repo);

        // First 3 requests should succeed.
        for _ in 0..3 {
            let result = svc.initiate_reset(tid, &user.email, 1).await.unwrap();
            assert!(result.is_some());
        }

        // 4th request should be rate limited.
        let result = svc.initiate_reset(tid, &user.email, 1).await;
        assert!(
            matches!(result, Err(AxiamError::RateLimited)),
            "expected RateLimited, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn initiate_reset_invalidates_prior_tokens() {
        let (user_repo, token_repo, fed_repo, hist_repo, tid, user) = full_setup().await;
        let svc = PasswordResetService::new(user_repo, token_repo.clone(), fed_repo, hist_repo);

        // Generate first token.
        let first = svc
            .initiate_reset(tid, &user.email, 1)
            .await
            .unwrap()
            .unwrap();

        // Generate second token — should invalidate the first.
        let second = svc
            .initiate_reset(tid, &user.email, 1)
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
        let (user_repo, token_repo, fed_repo, hist_repo, tid, user) = full_setup().await;

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

        let svc = PasswordResetService::new(user_repo.clone(), token_repo, fed_repo, hist_repo);

        let (raw_token, _uid, _exp) = svc
            .initiate_reset(tid, &user.email, 1)
            .await
            .unwrap()
            .unwrap();

        let policy = relaxed_policy();
        svc.confirm_reset(tid, &raw_token, "NewStr0ngPassword", &policy, None)
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
        let (user_repo, token_repo, fed_repo, hist_repo, tid, _user) = full_setup().await;
        let svc = PasswordResetService::new(user_repo, token_repo, fed_repo, hist_repo);
        let policy = relaxed_policy();

        let result = svc
            .confirm_reset(tid, "bogus-token", "NewStr0ngPassword", &policy, None)
            .await;

        assert!(result.is_err());
        assert!(
            matches!(result, Err(AxiamError::Validation { .. })),
            "expected Validation error, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn confirm_reset_expired_token() {
        let (user_repo, token_repo, fed_repo, hist_repo, tid, user) = full_setup().await;

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

        let svc = PasswordResetService::new(user_repo, token_repo, fed_repo, hist_repo);
        let policy = relaxed_policy();

        let result = svc
            .confirm_reset(tid, &raw_token, "NewStr0ngPassword", &policy, None)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn confirm_reset_rejects_weak_password() {
        let (user_repo, token_repo, fed_repo, hist_repo, tid, user) = full_setup().await;
        let svc = PasswordResetService::new(user_repo, token_repo, fed_repo, hist_repo);

        let (raw_token, _uid, _exp) = svc
            .initiate_reset(tid, &user.email, 1)
            .await
            .unwrap()
            .unwrap();

        let policy = relaxed_policy();
        let result = svc
            .confirm_reset(tid, &raw_token, "weak", &policy, None)
            .await;

        assert!(
            matches!(result, Err(AxiamError::Validation { .. })),
            "expected Validation error, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn confirm_reset_rejects_reused_password() {
        let (user_repo, token_repo, fed_repo, hist_repo, tid, user) = full_setup().await;

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

        let svc = PasswordResetService::new(user_repo, token_repo, fed_repo, hist_repo);

        let (raw_token, _uid, _exp) = svc
            .initiate_reset(tid, &user.email, 1)
            .await
            .unwrap()
            .unwrap();

        let policy = relaxed_policy();
        let result = svc
            .confirm_reset(tid, &raw_token, "ReusedPassw0rd", &policy, None)
            .await;

        assert!(
            matches!(result, Err(AxiamError::Validation { .. })),
            "expected Validation error, got: {result:?}"
        );
    }
}
