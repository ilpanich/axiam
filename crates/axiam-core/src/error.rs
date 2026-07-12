//! Error types for the AXIAM system.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AxiamError {
    #[error("Entity not found: {entity} with id {id}")]
    NotFound { entity: String, id: String },

    #[error("Entity already exists: {entity}")]
    AlreadyExists { entity: String },

    #[error("Authentication failed: {reason}")]
    AuthenticationFailed { reason: String },

    #[error("Authorization denied: {reason}")]
    AuthorizationDenied {
        reason: String,
        /// The action being checked (e.g. `"users:create"`), when known at
        /// the denial site. Surfaced to clients so SDKs can parse it from
        /// the 403 response body (SDK-Q02).
        action: Option<String>,
        /// The resource id being checked, when known and not the
        /// "global" nil-UUID sentinel. Surfaced to clients alongside
        /// `action` (SDK-Q02).
        resource_id: Option<String>,
    },

    #[error("Validation error: {message}")]
    Validation { message: String },

    #[error("Password policy violation: {message}")]
    PasswordPolicy { message: String },

    #[error("Database error: {0}")]
    Database(String),

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error("Email delivery failed: {0}")]
    EmailDelivery(String),

    #[error("Email configuration error: {0}")]
    EmailConfig(String),

    #[error("Webhook delivery failed: {0}")]
    WebhookDelivery(String),

    #[error("Tenant context missing or invalid")]
    TenantContext,

    #[error("Rate limit exceeded")]
    RateLimited,

    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("SAML assertion replay detected")]
    ReplayDetected,

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type AxiamResult<T> = Result<T, AxiamError>;
