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
    AuthorizationDenied { reason: String },

    #[error("Validation error: {message}")]
    Validation { message: String },

    #[error("Database error: {0}")]
    Database(String),

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error("Webhook delivery failed: {0}")]
    WebhookDelivery(String),

    #[error("Tenant context missing or invalid")]
    TenantContext,

    #[error("Rate limit exceeded")]
    RateLimited,

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type AxiamResult<T> = Result<T, AxiamError>;
