//! Error types for federation operations (OIDC and SAML).

/// Errors that can occur during federation operations.
#[derive(Debug, thiserror::Error)]
pub enum FederationError {
    #[error("Federation config not found: {0}")]
    ConfigNotFound(String),

    #[error("Federation config is disabled")]
    ConfigDisabled,

    #[error("Federation config is incomplete (missing required credentials)")]
    ConfigIncomplete,

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

    // ------------------------------------------------------------------
    // JWKS / signature verification errors (plan 04-02)
    // ------------------------------------------------------------------
    /// JWKS endpoint returned an error or was unreachable (and no valid
    /// stale-while-revalidate cache entry exists).
    #[error("JWKS fetch failed: {0}")]
    JwksFetchFailed(String),

    /// The JWT header contained a `kid` not found in the JWKS (after
    /// rate-limited forced refetch).
    #[error("Unknown key id (kid) in ID token — key not in JWKS")]
    JwksKidUnknown,

    /// JWT signature verification failed.
    #[error("JWT signature invalid")]
    JwtSignatureInvalid,

    /// A required JWT claim was missing or did not match the expected value
    /// (iss, aud, exp, nonce, etc.).
    #[error("JWT claim rejected: {0}")]
    JwtClaimRejected(String),

    /// The JWT algorithm is not in the per-config allow-list, or is "none"
    /// (always rejected at code level regardless of configuration).
    #[error("Algorithm not allowed: {0}")]
    AlgorithmNotAllowed(String),

    // ------------------------------------------------------------------
    // Crypto error (plan 04-02 secrets module)
    // ------------------------------------------------------------------
    #[error("Cryptography error: {0}")]
    CryptoError(String),

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
            // OIDC signature / claim errors → 401
            FederationError::JwtSignatureInvalid
            | FederationError::JwtClaimRejected(_)
            | FederationError::AlgorithmNotAllowed(_)
            | FederationError::JwksKidUnknown => {
                axiam_core::error::AxiamError::AuthenticationFailed {
                    reason: err.to_string(),
                }
            }
            other => axiam_core::error::AxiamError::Internal(other.to_string()),
        }
    }
}
