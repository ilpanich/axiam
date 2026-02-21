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
            | AuthError::MfaNotEnrolled => AxiamError::AuthenticationFailed {
                reason: err.to_string(),
            },
            AuthError::TokenExpired | AuthError::TokenInvalid(_) => {
                AxiamError::AuthenticationFailed {
                    reason: err.to_string(),
                }
            }
            AuthError::Crypto(msg) => AxiamError::Crypto(msg),
        }
    }
}
