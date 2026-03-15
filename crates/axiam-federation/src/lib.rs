//! AXIAM Federation — SAML Service Provider and OIDC external IdP integration.
//!
//! This crate provides OIDC and SAML federation support for authenticating
//! users through external identity providers (Google, Okta, Azure AD,
//! Shibboleth, ADFS, etc.).

pub mod error;
pub mod oidc;
pub mod saml;

use error::FederationError;

/// Validate that a metadata URL uses the HTTPS scheme to mitigate
/// SSRF attacks via admin-configured URLs pointing at internal hosts.
pub(crate) fn validate_metadata_url(url: &str) -> Result<(), FederationError> {
    let parsed = url::Url::parse(url)
        .map_err(|e| FederationError::DiscoveryFailed(format!("Invalid metadata URL: {e}")))?;
    if parsed.scheme() != "https" {
        return Err(FederationError::DiscoveryFailed(
            "metadata_url must use HTTPS".into(),
        ));
    }
    Ok(())
}
