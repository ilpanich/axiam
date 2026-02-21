//! AXIAM Auth — Password authentication, JWT issuance/validation,
//! and MFA (TOTP).

pub mod config;
pub mod error;
pub mod password;
pub mod service;
pub mod token;

pub use config::AuthConfig;
pub use error::AuthError;
pub use service::{AuthService, LoginInput, LoginOutput};
pub use token::AccessTokenClaims;
