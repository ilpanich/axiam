//! Error types for federation operations (OIDC and SAML).

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
            FederationError::ConfigNotFound => axiam_core::error::AxiamError::NotFound {
                entity: "federation_config".into(),
                id: String::new(),
            },
            FederationError::ConfigDisabled => axiam_core::error::AxiamError::Validation {
                message: "Federation config is disabled".into(),
            },
            FederationError::IdTokenValidationFailed(reason)
            | FederationError::SamlResponseFailed(reason) => {
                axiam_core::error::AxiamError::AuthenticationFailed { reason }
            }
            other => axiam_core::error::AxiamError::Internal(other.to_string()),
        }
    }
}
