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
    #[error("invalid_request: {0}")]
    InvalidRedirectUri(String),
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
            Self::InvalidRedirectUri(_) => "invalid_request",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::ServerError(_) => "server_error",
        }
    }

    /// Human-readable error description for the `error_description` field.
    ///
    /// Strips the RFC error-code prefix from the Display output so that
    /// `error_description` contains only the message (the code goes in
    /// the separate `error` field per RFC 6749 §5.2).
    pub fn error_description(&self) -> String {
        let full = self.to_string();
        // Display format is "error_code: message"; extract the message part.
        match full.split_once(": ") {
            Some((_, msg)) => msg.to_string(),
            None => full,
        }
    }
}
