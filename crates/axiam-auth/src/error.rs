//! Authentication error types.

use axiam_core::error::AxiamError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("account is locked")]
    AccountLocked,

    #[error("account is inactive")]
    AccountInactive,

    #[error("account is pending verification")]
    AccountPendingVerification,

    #[error("MFA is required")]
    MfaRequired,

    #[error("invalid MFA code")]
    MfaInvalidCode,

    #[error("MFA is not enrolled for this user")]
    MfaNotEnrolled,

    #[error("token has expired")]
    TokenExpired,

    #[error("invalid token: {0}")]
    TokenInvalid(String),

    #[error("email verification token expired or invalid")]
    VerificationTokenInvalid,

    #[error("email already verified")]
    EmailAlreadyVerified,

    #[error("password reset token expired or invalid")]
    ResetTokenInvalid,

    #[error("federated users cannot reset passwords")]
    FederatedUserPasswordReset,

    #[error("MFA setup token expired or invalid")]
    MfaSetupTokenInvalid,

    #[error("MFA is already configured for this user")]
    MfaAlreadyConfigured,

    #[error("WebAuthn registration failed: {0}")]
    WebauthnRegistration(String),

    #[error("WebAuthn authentication failed: {0}")]
    WebauthnAuthentication(String),

    #[error("WebAuthn state token invalid or expired")]
    WebauthnStateInvalid,

    #[error("no WebAuthn credentials registered for this user")]
    WebauthnNoCredentials,

    #[error("cannot remove the last MFA method while MFA is enabled")]
    MfaCannotRemoveLastMethod,

    #[error("cryptography error: {0}")]
    Crypto(String),
}

impl From<AuthError> for AxiamError {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::InvalidCredentials
            | AuthError::AccountLocked
            | AuthError::AccountInactive
            | AuthError::AccountPendingVerification
            | AuthError::MfaRequired
            | AuthError::MfaInvalidCode
            | AuthError::MfaNotEnrolled
            | AuthError::WebauthnRegistration(_)
            | AuthError::WebauthnAuthentication(_)
            | AuthError::WebauthnStateInvalid
            | AuthError::WebauthnNoCredentials => {
                AxiamError::AuthenticationFailed {
                    reason: err.to_string(),
                }
            }
            AuthError::TokenExpired | AuthError::TokenInvalid(_) => {
                AxiamError::AuthenticationFailed {
                    reason: err.to_string(),
                }
            }
            AuthError::VerificationTokenInvalid
            | AuthError::EmailAlreadyVerified
            | AuthError::ResetTokenInvalid
            | AuthError::FederatedUserPasswordReset
            | AuthError::MfaAlreadyConfigured
            | AuthError::MfaCannotRemoveLastMethod => AxiamError::Validation {
                message: err.to_string(),
            },
            AuthError::MfaSetupTokenInvalid => AxiamError::AuthenticationFailed {
                reason: err.to_string(),
            },
            AuthError::Crypto(msg) => AxiamError::Crypto(msg),
        }
    }
}
