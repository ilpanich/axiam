//! Authentication service — login, logout, token refresh, and MFA.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::session::CreateSession;
use axiam_core::models::user::{UpdateUser, UserStatus};
use axiam_core::repository::{SessionRepository, UserRepository};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::AuthConfig;
use crate::error::AuthError;
use crate::{password, token, totp};

// -----------------------------------------------------------------------
// Input / output types
// -----------------------------------------------------------------------

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

/// Successful login result (no MFA required).
#[derive(Debug)]
pub struct LoginOutput {
    pub access_token: String,
    pub refresh_token: String,
    pub session_id: Uuid,
    pub expires_in: u64,
}

/// Login result — either full success or MFA challenge.
#[derive(Debug)]
pub enum LoginResult {
    /// Credentials valid, no MFA — tokens issued.
    Success(LoginOutput),
    /// Credentials valid, MFA required — client must call `verify_mfa`.
    MfaRequired(MfaChallengeOutput),
}

/// MFA challenge token returned when login detects MFA is enabled.
#[derive(Debug)]
pub struct MfaChallengeOutput {
    /// Short-lived JWT encoding user_id + tenant_id + org_id.
    pub challenge_token: String,
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
    pub access_token: String,
    pub refresh_token: String,
    pub session_id: Uuid,
    pub expires_in: u64,
}

/// Result of MFA enrollment (step 1).
#[derive(Debug)]
pub struct EnrollMfaOutput {
    /// Base32-encoded TOTP secret (for manual entry).
    pub secret_base32: String,
    /// `otpauth://` URI for QR code generation.
    pub totp_uri: String,
}

/// Input for MFA verification after login challenge.
#[derive(Debug)]
pub struct VerifyMfaInput {
    pub challenge_token: String,
    pub totp_code: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

// -----------------------------------------------------------------------
// MFA challenge token claims (internal JWT)
// -----------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct MfaChallengeClaims {
    sub: String,
    tenant_id: String,
    org_id: String,
    purpose: String,
    iss: String,
    iat: i64,
    exp: i64,
}

// -----------------------------------------------------------------------
// AuthService
// -----------------------------------------------------------------------

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

    /// Authenticate a user with username/email + password.
    ///
    /// Returns `LoginResult::Success` if no MFA, or
    /// `LoginResult::MfaRequired` with a challenge token if MFA is
    /// enabled.
    pub async fn login(&self, input: LoginInput) -> AxiamResult<LoginResult> {
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

        // 2. Check temporary lockout (brute force protection).
        if let Some(locked_until) = user.locked_until
            && locked_until > Utc::now()
        {
            return Err(AuthError::InvalidCredentials.into());
        }

        // 3. Verify password.
        let valid = password::verify_password(
            &input.password,
            &user.password_hash,
            self.config.pepper.as_deref(),
        )
        .map_err(|e| AxiamError::Crypto(e.to_string()))?;

        if !valid {
            self.record_failed_login(input.tenant_id, &user).await?;
            return Err(AuthError::InvalidCredentials.into());
        }

        // 4. Reset failed login counter on success.
        if user.failed_login_attempts > 0 {
            self.reset_failed_logins(input.tenant_id, user.id).await?;
        }

        // 5. Check account status.
        Self::check_user_status(&user.status)?;

        // 6. Check MFA.
        if user.mfa_enabled && user.mfa_secret.is_some() {
            let challenge_token =
                self.issue_mfa_challenge(user.id, input.tenant_id, input.org_id)?;
            return Ok(LoginResult::MfaRequired(MfaChallengeOutput {
                challenge_token,
            }));
        }

        // 7. No MFA — issue tokens directly.
        let output = self
            .create_session_and_tokens(
                user.id,
                input.tenant_id,
                input.org_id,
                input.ip_address,
                input.user_agent,
            )
            .await?;

        Ok(LoginResult::Success(output))
    }

    /// Complete MFA verification after a login challenge.
    pub async fn verify_mfa(&self, input: VerifyMfaInput) -> AxiamResult<LoginOutput> {
        // 1. Decode the challenge token.
        let claims = self.decode_mfa_challenge(&input.challenge_token)?;
        let user_id: Uuid = claims
            .sub
            .parse()
            .map_err(|_| AuthError::TokenInvalid("bad sub".into()))?;
        let tenant_id: Uuid = claims
            .tenant_id
            .parse()
            .map_err(|_| AuthError::TokenInvalid("bad tenant_id".into()))?;
        let org_id: Uuid = claims
            .org_id
            .parse()
            .map_err(|_| AuthError::TokenInvalid("bad org_id".into()))?;

        // 2. Fetch user and verify TOTP.
        let user = self.user_repo.get_by_id(tenant_id, user_id).await?;
        Self::check_user_status(&user.status)?;

        let encrypted_secret = user
            .mfa_secret
            .as_deref()
            .ok_or(AuthError::MfaNotEnrolled)?;
        let encryption_key = self
            .config
            .mfa_encryption_key
            .as_ref()
            .ok_or_else(|| AuthError::Crypto("MFA encryption key not configured".into()))?;

        let secret_bytes = totp::decrypt_secret(encryption_key, encrypted_secret)?;
        let valid = totp::verify_code(
            &secret_bytes,
            &input.totp_code,
            &self.config.totp_issuer,
            &user.email,
        )?;

        if !valid {
            return Err(AuthError::MfaInvalidCode.into());
        }

        // 3. Create session and issue tokens.
        self.create_session_and_tokens(
            user_id,
            tenant_id,
            org_id,
            input.ip_address,
            input.user_agent,
        )
        .await
    }

    /// Start MFA enrollment for a user (step 1 of 2).
    ///
    /// Generates a TOTP secret, encrypts it, stores it on the user,
    /// but does NOT enable MFA yet — call `confirm_mfa` with a valid
    /// code to activate.
    pub async fn enroll_mfa(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<EnrollMfaOutput> {
        let encryption_key = self
            .config
            .mfa_encryption_key
            .as_ref()
            .ok_or_else(|| AuthError::Crypto("MFA encryption key not configured".into()))?;

        let user = self.user_repo.get_by_id(tenant_id, user_id).await?;

        let (base32_secret, totp_uri) =
            totp::generate_enrollment(&self.config.totp_issuer, &user.email)?;

        // Parse the base32 secret to raw bytes for encryption.
        let secret = totp_rs::Secret::Encoded(base32_secret.clone());
        let secret_bytes = secret
            .to_bytes()
            .map_err(|e| AuthError::Crypto(format!("secret decode: {e}")))?;
        let encrypted = totp::encrypt_secret(encryption_key, &secret_bytes)?;

        // Store encrypted secret but leave mfa_enabled = false.
        self.user_repo
            .update(
                tenant_id,
                user_id,
                UpdateUser {
                    mfa_secret: Some(Some(encrypted)),
                    ..Default::default()
                },
            )
            .await?;

        Ok(EnrollMfaOutput {
            secret_base32: base32_secret,
            totp_uri,
        })
    }

    /// Confirm MFA enrollment (step 2 of 2).
    ///
    /// The user provides a TOTP code to prove they saved the secret.
    /// On success, `mfa_enabled` is set to `true`.
    pub async fn confirm_mfa(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        totp_code: &str,
    ) -> AxiamResult<()> {
        let encryption_key = self
            .config
            .mfa_encryption_key
            .as_ref()
            .ok_or_else(|| AuthError::Crypto("MFA encryption key not configured".into()))?;

        let user = self.user_repo.get_by_id(tenant_id, user_id).await?;
        let encrypted_secret = user
            .mfa_secret
            .as_deref()
            .ok_or(AuthError::MfaNotEnrolled)?;

        let secret_bytes = totp::decrypt_secret(encryption_key, encrypted_secret)?;
        let valid = totp::verify_code(
            &secret_bytes,
            totp_code,
            &self.config.totp_issuer,
            &user.email,
        )?;

        if !valid {
            return Err(AuthError::MfaInvalidCode.into());
        }

        // Activate MFA.
        self.user_repo
            .update(
                tenant_id,
                user_id,
                UpdateUser {
                    mfa_enabled: Some(true),
                    ..Default::default()
                },
            )
            .await?;

        Ok(())
    }

    /// Rotate a refresh token: consume the old one, verify the user
    /// is still active, and issue a new token pair.
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
        Self::check_user_status(&user.status)?;

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

    // -------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------

    fn check_user_status(status: &UserStatus) -> Result<(), AuthError> {
        match status {
            UserStatus::Active => Ok(()),
            UserStatus::Locked => Err(AuthError::AccountLocked),
            UserStatus::Inactive => Err(AuthError::AccountInactive),
            UserStatus::PendingVerification => Err(AuthError::AccountPendingVerification),
        }
    }

    async fn create_session_and_tokens(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        org_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AxiamResult<LoginOutput> {
        let raw_refresh = token::generate_refresh_token();
        let token_hash = token::hash_refresh_token(&raw_refresh);
        let expires_at =
            Utc::now() + Duration::seconds(self.config.refresh_token_lifetime_secs as i64);

        let session = self
            .session_repo
            .create(CreateSession {
                tenant_id,
                user_id,
                token_hash,
                ip_address,
                user_agent,
                expires_at,
            })
            .await?;

        let access_token = token::issue_access_token(user_id, tenant_id, org_id, &self.config)?;

        Ok(LoginOutput {
            access_token,
            refresh_token: raw_refresh,
            session_id: session.id,
            expires_in: self.config.access_token_lifetime_secs,
        })
    }

    fn issue_mfa_challenge(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        org_id: Uuid,
    ) -> Result<String, AuthError> {
        use jsonwebtoken::{Algorithm, EncodingKey, Header};

        let now = Utc::now().timestamp();
        let claims = MfaChallengeClaims {
            sub: user_id.to_string(),
            tenant_id: tenant_id.to_string(),
            org_id: org_id.to_string(),
            purpose: "mfa_challenge".into(),
            iss: self.config.jwt_issuer.clone(),
            iat: now,
            exp: now + self.config.mfa_challenge_lifetime_secs as i64,
        };

        let key = EncodingKey::from_ed_pem(self.config.jwt_private_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad private key: {e}")))?;
        let header = Header::new(Algorithm::EdDSA);
        jsonwebtoken::encode(&header, &claims, &key)
            .map_err(|e| AuthError::Crypto(format!("JWT encode: {e}")))
    }

    fn decode_mfa_challenge(&self, token: &str) -> Result<MfaChallengeClaims, AuthError> {
        use jsonwebtoken::{Algorithm, DecodingKey, Validation};

        let key = DecodingKey::from_ed_pem(self.config.jwt_public_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad public key: {e}")))?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&self.config.jwt_issuer]);
        validation.set_required_spec_claims(&["sub", "exp", "iat", "iss"]);

        let data =
            jsonwebtoken::decode::<MfaChallengeClaims>(token, &key, &validation).map_err(|e| {
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                    _ => AuthError::TokenInvalid(e.to_string()),
                }
            })?;

        if data.claims.purpose != "mfa_challenge" {
            return Err(AuthError::TokenInvalid("not an MFA challenge token".into()));
        }

        Ok(data.claims)
    }

    async fn record_failed_login(
        &self,
        tenant_id: Uuid,
        user: &axiam_core::models::user::User,
    ) -> AxiamResult<()> {
        let new_count = user.failed_login_attempts + 1;
        let now = Utc::now();

        let locked_until = if new_count >= self.config.max_failed_login_attempts {
            let exponent = (new_count - self.config.max_failed_login_attempts) as f64;
            let duration_secs = (self.config.lockout_duration_secs as f64
                * self.config.lockout_backoff_multiplier.powf(exponent))
            .min(self.config.max_lockout_duration_secs as f64)
                as i64;
            Some(Some(now + Duration::seconds(duration_secs)))
        } else {
            None
        };

        let mut update = UpdateUser {
            failed_login_attempts: Some(new_count),
            last_failed_login_at: Some(Some(now)),
            ..Default::default()
        };
        if let Some(lu) = locked_until {
            update.locked_until = Some(lu);
        }

        self.user_repo.update(tenant_id, user.id, update).await?;
        Ok(())
    }

    async fn reset_failed_logins(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<()> {
        self.user_repo
            .update(
                tenant_id,
                user_id,
                UpdateUser {
                    failed_login_attempts: Some(0),
                    last_failed_login_at: Some(None),
                    locked_until: Some(None),
                    ..Default::default()
                },
            )
            .await?;
        Ok(())
    }
}
