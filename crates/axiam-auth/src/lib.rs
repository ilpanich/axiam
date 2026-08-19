//! AXIAM Auth — Password authentication, JWT issuance/validation,
//! and MFA (TOTP).

pub mod attestation;
pub mod client_secret;
pub mod config;
pub mod crypto;
pub mod crypto_gate;
pub mod error;
pub mod hibp_breaker;
pub mod lockout;
pub mod mfa_methods;
pub mod password;
pub mod password_reset;
pub mod policy;
pub mod service;
pub mod srp;
pub mod token;
pub mod totp;
pub mod verification;
pub mod webauthn;

pub use attestation::{AttestationCaCache, ComplianceStatus, evaluate_credential_compliance};
pub use client_secret::{ClientSecretHasher, ClientSecretVerdict};
pub use config::AuthConfig;
pub use error::AuthError;
pub use hibp_breaker::HibpBreaker;
pub use mfa_methods::MfaMethodService;
pub use password_reset::PasswordResetService;
pub use service::{
    AuthService, EnrollMfaOutput, LoginInput, LoginOutput, LoginResult, MfaChallengeOutput,
    MfaSetupOutput, RefreshInput, RefreshOutput, VerifyMfaInput,
};
pub use srp::{SrpServer, SrpVerified};
pub use token::{AccessTokenClaims, ValidatedClaims};
pub use verification::EmailVerificationService;
pub use webauthn::WebauthnService;
