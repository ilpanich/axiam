//! Email verification service -- token generation, verification,
//! and resend with rate limiting.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::email_verification::CreateEmailVerificationToken;
use axiam_core::models::user::{UpdateUser, UserStatus};
use axiam_core::repository::{
    EmailVerificationTokenRepository, FederationLinkRepository, UserRepository,
};
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::error::AuthError;
use crate::token;

/// Maximum number of verification emails per user per day.
const MAX_RESENDS_PER_DAY: u64 = 2;

/// Default token expiry in hours.
const TOKEN_EXPIRY_HOURS: i64 = 24;

/// Email verification service.
///
/// Handles token generation, consumption, and resend with
/// rate limiting. Federated-user detection is also exposed
/// here so the API layer can skip verification for social
/// login users.
pub struct EmailVerificationService<U, V, F>
where
    U: UserRepository,
    V: EmailVerificationTokenRepository,
    F: FederationLinkRepository,
{
    user_repo: U,
    token_repo: V,
    federation_repo: F,
}

impl<U, V, F> EmailVerificationService<U, V, F>
where
    U: UserRepository,
    V: EmailVerificationTokenRepository,
    F: FederationLinkRepository,
{
    /// Create a new verification service.
    pub fn new(user_repo: U, token_repo: V, federation_repo: F) -> Self {
        Self {
            user_repo,
            token_repo,
            federation_repo,
        }
    }

    /// Generate a verification token for a user.
    ///
    /// Returns `(raw_token, expires_at)`. The raw token is used to
    /// build the action URL; only the SHA-256 hash is stored.
    pub async fn initiate_verification(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AxiamResult<(String, chrono::DateTime<chrono::Utc>)> {
        let raw_token = token::generate_refresh_token();
        let token_hash = token::hash_refresh_token(&raw_token);
        let expires_at = Utc::now() + Duration::hours(TOKEN_EXPIRY_HOURS);

        self.token_repo
            .create(CreateEmailVerificationToken {
                tenant_id,
                user_id,
                token_hash,
                expires_at,
            })
            .await?;

        Ok((raw_token, expires_at))
    }

    /// Verify an email using the raw token.
    ///
    /// Atomically consumes the token and activates the user.
    pub async fn verify_email(&self, tenant_id: Uuid, raw_token: &str) -> AxiamResult<()> {
        let token_hash = token::hash_refresh_token(raw_token);

        // Atomically consume -- fails if expired or already used.
        let consumed = self
            .token_repo
            .consume(tenant_id, &token_hash)
            .await
            .map_err(|e| match e {
                AxiamError::NotFound { .. } => {
                    AxiamError::from(AuthError::VerificationTokenInvalid)
                }
                other => other,
            })?;

        // Check the user exists and hasn't already verified.
        let user = self
            .user_repo
            .get_by_id(tenant_id, consumed.user_id)
            .await?;

        if user.email_verified_at.is_some() {
            return Err(AuthError::EmailAlreadyVerified.into());
        }

        // Update email_verified_at and, if appropriate, activate the
        // user. Only transition to Active from PendingVerification to
        // avoid reactivating admin-disabled or locked accounts.
        let mut update = UpdateUser {
            email_verified_at: Some(Some(Utc::now())),
            ..Default::default()
        };
        if user.status == UserStatus::PendingVerification {
            update.status = Some(UserStatus::Active);
        }

        self.user_repo
            .update(tenant_id, consumed.user_id, update)
            .await?;

        Ok(())
    }

    /// Resend verification email for a user identified by email.
    ///
    /// Returns `Ok(Some((raw_token, user_id, expires_at)))` on
    /// success, `Ok(None)` if the email doesn't exist or user is
    /// already verified (to prevent user enumeration).
    pub async fn resend_verification(
        &self,
        tenant_id: Uuid,
        email: &str,
    ) -> AxiamResult<Option<(String, Uuid, chrono::DateTime<chrono::Utc>)>> {
        // Look up user -- silently return None if not found.
        let user = match self.user_repo.get_by_email(tenant_id, email).await {
            Ok(u) => u,
            Err(AxiamError::NotFound { .. }) => return Ok(None),
            Err(e) => return Err(e),
        };

        // Only resend for PendingVerification users.
        if user.status != UserStatus::PendingVerification {
            return Ok(None);
        }

        // Rate limit: max resends per day.
        let count = self.token_repo.count_today(tenant_id, user.id).await?;
        if count >= MAX_RESENDS_PER_DAY {
            return Err(AxiamError::RateLimited);
        }

        let (raw_token, expires_at) = self.initiate_verification(tenant_id, user.id).await?;

        Ok(Some((raw_token, user.id, expires_at)))
    }

    /// Check if a user has any federation links (social/external
    /// IdP). Federated users typically skip email verification.
    pub async fn is_federated_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<bool> {
        let links = self
            .federation_repo
            .get_by_user_id(tenant_id, user_id)
            .await?;
        Ok(!links.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::user::{CreateUser, UserStatus};
    use axiam_core::repository::UserRepository;
    use axiam_db::{
        SurrealEmailVerificationTokenRepository, SurrealFederationLinkRepository,
        SurrealUserRepository, run_migrations,
    };
    use surrealdb::engine::local::Db;

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

    /// Full setup: DB + org + tenant + user + repos.
    async fn full_setup() -> (
        SurrealUserRepository<Db>,
        SurrealEmailVerificationTokenRepository<Db>,
        SurrealFederationLinkRepository<Db>,
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
        let token_repo = SurrealEmailVerificationTokenRepository::new(db.clone());
        let fed_repo = SurrealFederationLinkRepository::new(db.clone());

        let user = create_test_user(&user_repo, tenant_id).await;

        (user_repo, token_repo, fed_repo, tenant_id, user)
    }

    #[tokio::test]
    async fn verify_email_activates_pending_user() {
        let (user_repo, token_repo, fed_repo, tid, user) = full_setup().await;

        // User starts as PendingVerification.
        assert_eq!(user.status, UserStatus::PendingVerification);

        let svc = EmailVerificationService::new(user_repo.clone(), token_repo, fed_repo);

        let (raw_token, _expires) = svc.initiate_verification(tid, user.id).await.unwrap();

        svc.verify_email(tid, &raw_token).await.unwrap();

        let updated = user_repo.get_by_id(tid, user.id).await.unwrap();
        assert_eq!(updated.status, UserStatus::Active);
        assert!(updated.email_verified_at.is_some());
    }

    #[tokio::test]
    async fn replay_consumed_token_fails() {
        let (user_repo, token_repo, fed_repo, tid, user) = full_setup().await;
        let svc = EmailVerificationService::new(user_repo, token_repo, fed_repo);

        let (raw_token, _expires) = svc.initiate_verification(tid, user.id).await.unwrap();

        // First use succeeds.
        svc.verify_email(tid, &raw_token).await.unwrap();

        // Second use must fail.
        let result = svc.verify_email(tid, &raw_token).await;
        assert!(result.is_err(), "replayed token should be rejected");
    }

    #[tokio::test]
    async fn resend_respects_rate_limit() {
        let (user_repo, token_repo, fed_repo, tid, user) = full_setup().await;
        let svc = EmailVerificationService::new(user_repo, token_repo, fed_repo);

        // First MAX_RESENDS_PER_DAY resends should succeed.
        for _ in 0..MAX_RESENDS_PER_DAY {
            let result = svc.resend_verification(tid, &user.email).await.unwrap();
            assert!(result.is_some());
        }

        // Next resend should be rate-limited.
        let result = svc.resend_verification(tid, &user.email).await;
        assert!(
            matches!(result, Err(AxiamError::RateLimited)),
            "expected RateLimited, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn resend_returns_none_for_nonexistent_email() {
        let (user_repo, token_repo, fed_repo, tid, _user) = full_setup().await;
        let svc = EmailVerificationService::new(user_repo, token_repo, fed_repo);

        let result = svc
            .resend_verification(tid, "nobody@example.com")
            .await
            .unwrap();

        assert!(
            result.is_none(),
            "unknown email should silently return None"
        );
    }

    #[tokio::test]
    async fn resend_returns_none_for_non_pending_user() {
        let (user_repo, token_repo, fed_repo, tid, user) = full_setup().await;

        // Activate the user so they are no longer
        // PendingVerification.
        user_repo
            .update(
                tid,
                user.id,
                UpdateUser {
                    status: Some(UserStatus::Active),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let svc = EmailVerificationService::new(user_repo, token_repo, fed_repo);

        let result = svc.resend_verification(tid, &user.email).await.unwrap();

        assert!(
            result.is_none(),
            "non-PendingVerification user should get None"
        );
    }

    #[tokio::test]
    async fn verify_inactive_user_sets_verified_but_stays_inactive() {
        let (user_repo, token_repo, fed_repo, tid, user) = full_setup().await;

        // Admin-disable the user.
        user_repo
            .update(
                tid,
                user.id,
                UpdateUser {
                    status: Some(UserStatus::Inactive),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let svc = EmailVerificationService::new(user_repo.clone(), token_repo, fed_repo);

        let (raw_token, _expires) = svc.initiate_verification(tid, user.id).await.unwrap();

        svc.verify_email(tid, &raw_token).await.unwrap();

        let updated = user_repo.get_by_id(tid, user.id).await.unwrap();
        assert_eq!(
            updated.status,
            UserStatus::Inactive,
            "admin-disabled user must stay Inactive after verification"
        );
        assert!(
            updated.email_verified_at.is_some(),
            "email_verified_at should still be set"
        );
    }
}
