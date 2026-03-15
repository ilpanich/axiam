//! Error types for OIDC federation operations.

/// Errors that can occur during federation operations.
#[derive(Debug, thiserror::Error)]
pub enum FederationError {
    #[error("Federation config not found")]
    ConfigNotFound,

    #[error("Federation config is disabled")]
    ConfigDisabled,

    #[error("OIDC discovery failed: {0}")]
    DiscoveryFailed(String),

    #[error("Token exchange failed: {0}")]
    TokenExchangeFailed(String),

    #[error("ID token validation failed: {0}")]
    IdTokenValidationFailed(String),

    #[error("User provisioning failed: {0}")]
    ProvisioningFailed(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<FederationError> for axiam_core::error::AxiamError {
    fn from(err: FederationError) -> Self {
        match err {
            FederationError::ConfigNotFound => axiam_core::error::AxiamError::NotFound {
                entity: "federation_config".into(),
                id: String::new(),
            },
            FederationError::ConfigDisabled => axiam_core::error::AxiamError::Validation {
                message: "Federation config is disabled".into(),
            },
            FederationError::IdTokenValidationFailed(reason) => {
                axiam_core::error::AxiamError::AuthenticationFailed { reason }
            }
            other => axiam_core::error::AxiamError::Internal(other.to_string()),
        }
    }
}
