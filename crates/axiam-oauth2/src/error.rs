//! OAuth2 error types per RFC 6749.

use thiserror::Error;

/// OAuth2-specific errors following RFC 6749 error codes.
#[derive(Debug, Error)]
pub enum OAuth2Error {
    #[error("invalid_request: {0}")]
    InvalidRequest(String),
    #[error("unauthorized_client: {0}")]
    UnauthorizedClient(String),
    #[error("access_denied: {0}")]
    AccessDenied(String),
    #[error("unsupported_response_type")]
    UnsupportedResponseType,
    #[error("invalid_scope: {0}")]
    InvalidScope(String),
    #[error("invalid_grant: {0}")]
    InvalidGrant(String),
    #[error("invalid_client: {0}")]
    InvalidClient(String),
    #[error("unsupported_grant_type")]
    UnsupportedGrantType,
    #[error("server_error: {0}")]
    ServerError(String),
}

impl OAuth2Error {
    /// RFC 6749 error code string.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request",
            Self::UnauthorizedClient(_) => "unauthorized_client",
            Self::AccessDenied(_) => "access_denied",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope(_) => "invalid_scope",
            Self::InvalidGrant(_) => "invalid_grant",
            Self::InvalidClient(_) => "invalid_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::ServerError(_) => "server_error",
        }
    }

    /// Human-readable error description for the `error_description` field.
    pub fn error_description(&self) -> String {
        self.to_string()
    }
}
