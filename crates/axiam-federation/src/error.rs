//! Error types for federation operations (OIDC and SAML).

/// Errors that can occur during federation operations.
#[derive(Debug, thiserror::Error)]
pub enum FederationError {
    #[error("Federation config not found: {0}")]
    ConfigNotFound(String),

    #[error("Federation config is disabled")]
    ConfigDisabled,

    #[error("Protocol mismatch: {0}")]
    ProtocolMismatch(String),

    #[error("Invalid metadata URL: {0}")]
    InvalidMetadataUrl(String),

    #[error("OIDC discovery failed: {0}")]
    DiscoveryFailed(String),

    #[error("Token exchange failed: {0}")]
    TokenExchangeFailed(String),

    #[error("ID token validation failed: {0}")]
    IdTokenValidationFailed(String),

    #[error("SAML metadata fetch/parse failed: {0}")]
    SamlMetadataFailed(String),

    #[error("SAML response validation failed: {0}")]
    SamlResponseFailed(String),

    #[error("User provisioning failed: {0}")]
    ProvisioningFailed(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<FederationError> for axiam_core::error::AxiamError {
    fn from(err: FederationError) -> Self {
        match err {
            FederationError::ConfigNotFound(id) => axiam_core::error::AxiamError::NotFound {
                entity: "federation_config".into(),
                id,
            },
            FederationError::ConfigDisabled
            | FederationError::ProtocolMismatch(_)
            | FederationError::InvalidMetadataUrl(_) => axiam_core::error::AxiamError::Validation {
                message: err.to_string(),
            },
            FederationError::IdTokenValidationFailed(reason)
            | FederationError::SamlResponseFailed(reason) => {
                axiam_core::error::AxiamError::AuthenticationFailed { reason }
            }
            other => axiam_core::error::AxiamError::Internal(other.to_string()),
        }
    }
}
