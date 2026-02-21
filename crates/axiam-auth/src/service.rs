//! Authentication service — login and logout orchestration.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::session::CreateSession;
use axiam_core::models::user::UserStatus;
use axiam_core::repository::{SessionRepository, UserRepository};
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::config::AuthConfig;
use crate::error::AuthError;
use crate::password;
use crate::token;

/// Input for the login flow.
#[derive(Debug)]
pub struct LoginInput {
    pub tenant_id: Uuid,
    pub org_id: Uuid,
    pub username_or_email: String,
    pub password: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Successful login result.
#[derive(Debug)]
pub struct LoginOutput {
    /// Signed JWT access token.
    pub access_token: String,
    /// Raw opaque refresh token (return to client, not stored).
    pub refresh_token: String,
    /// Session ID (can be used for logout).
    pub session_id: Uuid,
    /// Access token lifetime in seconds.
    pub expires_in: u64,
}

/// Input for the refresh token rotation flow.
#[derive(Debug)]
pub struct RefreshInput {
    pub tenant_id: Uuid,
    pub org_id: Uuid,
    pub raw_refresh_token: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Successful refresh result (new token pair).
#[derive(Debug)]
pub struct RefreshOutput {
    /// New signed JWT access token.
    pub access_token: String,
    /// New opaque refresh token (replaces the consumed one).
    pub refresh_token: String,
    /// New session ID.
    pub session_id: Uuid,
    /// Access token lifetime in seconds.
    pub expires_in: u64,
}

/// Authentication service.
///
/// Generic over repository implementations so that the auth layer
/// has no dependency on the database crate.
pub struct AuthService<U: UserRepository, S: SessionRepository> {
    user_repo: U,
    session_repo: S,
    config: AuthConfig,
}

impl<U: UserRepository, S: SessionRepository> AuthService<U, S> {
    pub fn new(user_repo: U, session_repo: S, config: AuthConfig) -> Self {
        Self {
            user_repo,
            session_repo,
            config,
        }
    }

    /// Authenticate a user with username/email + password and issue
    /// tokens.
    pub async fn login(&self, input: LoginInput) -> AxiamResult<LoginOutput> {
        // 1. Look up user — try username first, then email.
        let user = match self
            .user_repo
            .get_by_username(input.tenant_id, &input.username_or_email)
            .await
        {
            Ok(u) => u,
            Err(AxiamError::NotFound { .. }) => self
                .user_repo
                .get_by_email(input.tenant_id, &input.username_or_email)
                .await
                .map_err(|_| AuthError::InvalidCredentials)?,
            Err(e) => return Err(e),
        };

        // 2. Verify password.
        let valid = password::verify_password(
            &input.password,
            &user.password_hash,
            self.config.pepper.as_deref(),
        )
        .map_err(|e| AxiamError::Crypto(e.to_string()))?;

        if !valid {
            return Err(AuthError::InvalidCredentials.into());
        }

        // 3. Check account status.
        match user.status {
            UserStatus::Active => {}
            UserStatus::Locked => {
                return Err(AuthError::AccountLocked.into());
            }
            UserStatus::Inactive => {
                return Err(AuthError::AccountInactive.into());
            }
            UserStatus::PendingVerification => {
                return Err(AuthError::AccountPendingVerification.into());
            }
        }

        // 4. Check MFA — if enabled, reject at this stage
        //    (full MFA challenge flow is T2.3).
        if user.mfa_enabled {
            return Err(AuthError::MfaRequired.into());
        }

        // 5. Generate refresh token and create session.
        let raw_refresh = token::generate_refresh_token();
        let token_hash = token::hash_refresh_token(&raw_refresh);
        let expires_at =
            Utc::now() + Duration::seconds(self.config.refresh_token_lifetime_secs as i64);

        let session = self
            .session_repo
            .create(CreateSession {
                tenant_id: input.tenant_id,
                user_id: user.id,
                token_hash,
                ip_address: input.ip_address,
                user_agent: input.user_agent,
                expires_at,
            })
            .await?;

        // 6. Issue JWT access token.
        let access_token =
            token::issue_access_token(user.id, input.tenant_id, input.org_id, &self.config)?;

        Ok(LoginOutput {
            access_token,
            refresh_token: raw_refresh,
            session_id: session.id,
            expires_in: self.config.access_token_lifetime_secs,
        })
    }

    /// Rotate a refresh token: consume the old one, verify the user
    /// is still active, and issue a new token pair.
    ///
    /// Each refresh token is single-use — the old session is
    /// invalidated before the new one is created.
    pub async fn refresh(&self, input: RefreshInput) -> AxiamResult<RefreshOutput> {
        // 1. Look up session by token hash.
        let token_hash = token::hash_refresh_token(&input.raw_refresh_token);
        let session = self
            .session_repo
            .get_by_token_hash(input.tenant_id, &token_hash)
            .await
            .map_err(|e| match e {
                AxiamError::NotFound { .. } => {
                    AuthError::TokenInvalid("refresh token not found or already used".into()).into()
                }
                other => other,
            })?;

        // 2. Check session expiry.
        if session.expires_at <= Utc::now() {
            // Invalidate the expired session and reject.
            let _ = self
                .session_repo
                .invalidate(input.tenant_id, session.id)
                .await;
            return Err(AuthError::TokenExpired.into());
        }

        // 3. Invalidate old session (single-use guarantee).
        self.session_repo
            .invalidate(input.tenant_id, session.id)
            .await?;

        // 4. Verify user is still active.
        let user = self
            .user_repo
            .get_by_id(input.tenant_id, session.user_id)
            .await?;

        match user.status {
            UserStatus::Active => {}
            UserStatus::Locked => return Err(AuthError::AccountLocked.into()),
            UserStatus::Inactive => return Err(AuthError::AccountInactive.into()),
            UserStatus::PendingVerification => {
                return Err(AuthError::AccountPendingVerification.into());
            }
        }

        // 5. Create new session with rotated refresh token.
        let raw_refresh = token::generate_refresh_token();
        let new_hash = token::hash_refresh_token(&raw_refresh);
        let expires_at =
            Utc::now() + Duration::seconds(self.config.refresh_token_lifetime_secs as i64);

        let new_session = self
            .session_repo
            .create(CreateSession {
                tenant_id: input.tenant_id,
                user_id: user.id,
                token_hash: new_hash,
                ip_address: input.ip_address,
                user_agent: input.user_agent,
                expires_at,
            })
            .await?;

        // 6. Issue new access token.
        let access_token =
            token::issue_access_token(user.id, input.tenant_id, input.org_id, &self.config)?;

        Ok(RefreshOutput {
            access_token,
            refresh_token: raw_refresh,
            session_id: new_session.id,
            expires_in: self.config.access_token_lifetime_secs,
        })
    }

    /// Invalidate a single session (logout).
    pub async fn logout(&self, tenant_id: Uuid, session_id: Uuid) -> AxiamResult<()> {
        self.session_repo.invalidate(tenant_id, session_id).await
    }

    /// Revoke all sessions for a user (e.g. on password change).
    pub async fn revoke_all_sessions(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<()> {
        self.session_repo
            .invalidate_user_sessions(tenant_id, user_id)
            .await
    }
}
