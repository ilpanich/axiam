//! Email verification service -- token generation, verification,
//! and resend with rate limiting.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::email_verification::CreateEmailVerificationToken;
use axiam_core::models::user::{UpdateUser, UserStatus};
use axiam_core::repository::{
    EmailVerificationTokenRepository, FederationLinkRepository,
    UserRepository,
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
    pub fn new(
        user_repo: U,
        token_repo: V,
        federation_repo: F,
    ) -> Self {
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
        let expires_at =
            Utc::now() + Duration::hours(TOKEN_EXPIRY_HOURS);

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
    pub async fn verify_email(
        &self,
        tenant_id: Uuid,
        raw_token: &str,
    ) -> AxiamResult<()> {
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

        // Activate the user and set email_verified_at.
        self.user_repo
            .update(
                tenant_id,
                consumed.user_id,
                UpdateUser {
                    status: Some(UserStatus::Active),
                    email_verified_at: Some(Some(Utc::now())),
                    ..Default::default()
                },
            )
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
    ) -> AxiamResult<
        Option<(String, Uuid, chrono::DateTime<chrono::Utc>)>,
    > {
        // Look up user -- silently return None if not found.
        let user = match self
            .user_repo
            .get_by_email(tenant_id, email)
            .await
        {
            Ok(u) => u,
            Err(AxiamError::NotFound { .. }) => return Ok(None),
            Err(e) => return Err(e),
        };

        // Only resend for PendingVerification users.
        if user.status != UserStatus::PendingVerification {
            return Ok(None);
        }

        // Rate limit: max resends per day.
        let count =
            self.token_repo.count_today(tenant_id, user.id).await?;
        if count >= MAX_RESENDS_PER_DAY {
            return Err(AxiamError::RateLimited);
        }

        let (raw_token, expires_at) =
            self.initiate_verification(tenant_id, user.id).await?;

        Ok(Some((raw_token, user.id, expires_at)))
    }

    /// Check if a user has any federation links (social/external
    /// IdP). Federated users typically skip email verification.
    pub async fn is_federated_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AxiamResult<bool> {
        let links = self
            .federation_repo
            .get_by_user_id(tenant_id, user_id)
            .await?;
        Ok(!links.is_empty())
    }
}
