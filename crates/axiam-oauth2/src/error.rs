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
    #[error("unsupported_response_type: only 'code' response type is supported")]
    UnsupportedResponseType,
    #[error("invalid_scope: {0}")]
    InvalidScope(String),
    #[error("invalid_grant: {0}")]
    InvalidGrant(String),
    #[error("invalid_client: {0}")]
    InvalidClient(String),
    #[error("invalid_request: {0}")]
    InvalidRedirectUri(String),
    #[error("unsupported_grant_type: grant type is not supported")]
    UnsupportedGrantType,
    #[error("server_error: {0}")]
    ServerError(String),

    // --- RFC 8628 device-flow polling errors (B2) --------------------------
    //
    // These are NOT failures in the usual sense: `authorization_pending` is
    // the *expected* answer to almost every poll, and `slow_down` is
    // corrective rather than terminal. They are modelled as errors because
    // that is what RFC 8628 §3.5 puts on the wire — a 400 with an `error`
    // field — and because keeping them in one type is what stops the token
    // endpoint growing a second, parallel response path.
    /// The user has not yet approved or denied. The device keeps polling.
    #[error("authorization_pending: the user has not yet completed authorization")]
    AuthorizationPending,
    /// The device is polling faster than the interval it was given. The
    /// interval has been raised; the device must honour the new one.
    #[error("slow_down: polling faster than the permitted interval")]
    SlowDown,
    /// The device code expired before the user acted.
    #[error("expired_token: the device code has expired; restart the flow")]
    ExpiredToken,

    // --- RFC 8693 token exchange (B3) --------------------------------------
    /// RFC 8693 §2.2.2 — the requested `audience`/`resource` is not one the
    /// exchanging client may address. Its own error code rather than
    /// `invalid_request` because a caller can act on it: the target is
    /// well-formed, it is simply not theirs to address.
    #[error("invalid_target: {0}")]
    InvalidTarget(String),
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
            Self::AuthorizationPending => "authorization_pending",
            Self::SlowDown => "slow_down",
            Self::ExpiredToken => "expired_token",
            Self::InvalidTarget(_) => "invalid_target",
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
