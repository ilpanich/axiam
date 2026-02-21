//! AXIAM Auth — Password authentication, JWT issuance/validation,
//! and MFA (TOTP).

pub mod config;
pub mod error;
pub mod password;
pub mod service;
pub mod token;
pub mod totp;

pub use config::AuthConfig;
pub use error::AuthError;
pub use service::{
    AuthService, EnrollMfaOutput, LoginInput, LoginOutput, LoginResult, MfaChallengeOutput,
    RefreshInput, RefreshOutput, VerifyMfaInput,
};
pub use token::{AccessTokenClaims, ValidatedClaims};
