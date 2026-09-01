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

    // ------------------------------------------------------------------
    // SAML XML signature / replay errors (plan 04-03)
    // ------------------------------------------------------------------
    /// The IdP signing certificate PEM is invalid (rejected at upload or at
    /// verify time if a stored cert becomes corrupt).
    #[error("Invalid IdP certificate: {0}")]
    InvalidIdpCert(String),

    /// The SAML XML signature is missing, structurally invalid, or does not
    /// verify against the configured IdP certificate.
    #[error("SAML signature invalid: {0}")]
    SamlSignatureInvalid(String),

    /// A SAML assertion with this ID has already been consumed by this tenant
    /// (replay attack detected).
    #[error("Assertion replay detected")]
    AssertionReplay,

    // ------------------------------------------------------------------
    // Login-provider errors
    // ------------------------------------------------------------------
    /// The stored configuration cannot be used as written — a missing OAuth2
    /// endpoint, a malformed Apple identifier, an unusable signing key, or a
    /// templated issuer with no accepted tenants.
    ///
    /// Distinct from [`FederationError::ConfigIncomplete`], which says only
    /// that credentials are absent: this one carries *which* part is wrong, so
    /// the operator is not left comparing their form against an IdP error page.
    #[error("Federation config is invalid: {0}")]
    ConfigInvalid(String),

    /// The provider returned no email address it affirmatively marks verified.
    ///
    /// Refused rather than provisioned. AXIAM keys account recovery,
    /// verification and administrative notification on the address; adopting an
    /// unverified one is account takeover by whoever typed it into the provider
    /// first, and provisioning without one produces an account that cannot
    /// recover itself and an operator a user row that looks real. See
    /// `claude_dev/federation-sso-login-design.md` §5.3.
    #[error(
        "the identity provider returned no verified email address; \
         AXIAM will not adopt an unverified address as an identity"
    )]
    UnverifiedExternalEmail,

    /// The userinfo endpoint answered, but not with something that identifies
    /// anyone — no subject could be mapped out of it.
    #[error("userinfo response did not identify a subject: {0}")]
    UserinfoUnusable(String),

    /// The ID token's `tid` names an external IdP tenant this config does not
    /// accept (templated-issuer path).
    #[error(
        "the identity provider tenant that issued this token is not accepted by this configuration"
    )]
    IssuerTenantNotAllowed,
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
            // SAML signature / replay errors → 401
            FederationError::SamlSignatureInvalid(reason) => {
                axiam_core::error::AxiamError::AuthenticationFailed { reason }
            }
            FederationError::AssertionReplay => {
                axiam_core::error::AxiamError::AuthenticationFailed {
                    reason: "assertion replay".into(),
                }
            }
            // IdP cert validation error → admin-facing 400 (Validation)
            FederationError::InvalidIdpCert(msg) => {
                axiam_core::error::AxiamError::Validation { message: msg }
            }
            // A config the operator has to fix → 400, with the reason. These
            // are not authentication failures: nothing about the end user is
            // wrong, and telling them "invalid credentials" would send the
            // wrong person looking.
            FederationError::ConfigInvalid(msg) => {
                axiam_core::error::AxiamError::Validation { message: msg }
            }
            // Refusals that ARE about this sign-in attempt → 401. The
            // unverified-email message is deliberately specific: a user who
            // cannot sign in with GitHub needs to be told to verify their
            // GitHub email, not to try a different password.
            FederationError::UnverifiedExternalEmail
            | FederationError::IssuerTenantNotAllowed
            | FederationError::UserinfoUnusable(_) => {
                axiam_core::error::AxiamError::AuthenticationFailed {
                    reason: err.to_string(),
                }
            }
            // CQ-B23: upstream-IdP failures (discovery fetch/parse, token
            // exchange, JWKS fetch) are NOT our bug — the local server did
            // nothing wrong, but the external IdP is unreachable, timed out,
            // misconfigured, or returned a malformed/erroring response.
            // Mapping these to the generic `Internal` (500) catch-all
            // mislabels an upstream dependency failure as a server bug.
            // `AxiamError` has no dedicated 502 Bad Gateway variant; the
            // closest existing variant is `ServiceUnavailable` (503), which
            // — like a 502 — signals "an upstream dependency failed" rather
            // than "the server itself is broken", so it is used here instead
            // of inventing a new status/variant.
            FederationError::DiscoveryFailed(msg)
            | FederationError::TokenExchangeFailed(msg)
            | FederationError::JwksFetchFailed(msg) => {
                axiam_core::error::AxiamError::ServiceUnavailable(msg)
            }
            other => axiam_core::error::AxiamError::Internal(other.to_string()),
        }
    }
}
