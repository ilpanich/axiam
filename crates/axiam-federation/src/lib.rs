//! AXIAM Federation — SAML Service Provider and OIDC external IdP integration.
//!
//! This crate provides OIDC and SAML federation support for authenticating
//! users through external identity providers (Google, Okta, Azure AD,
//! Shibboleth, ADFS, etc.).

pub mod error;
pub mod oidc;
pub mod saml;

use error::FederationError;

/// Validate that a metadata URL uses the HTTPS scheme.
///
/// This is a scheme-only check. Additional SSRF mitigations (private IP
/// blocking, DNS rebinding) are handled at the HTTP client level via
/// `redirect(Policy::none())` and network-layer controls.
pub(crate) fn validate_metadata_url(url: &str) -> Result<(), FederationError> {
    let parsed =
        url::Url::parse(url).map_err(|e| FederationError::InvalidMetadataUrl(format!("{e}")))?;
    if parsed.scheme() != "https" {
        return Err(FederationError::InvalidMetadataUrl(
            "metadata_url must use HTTPS".into(),
        ));
    }
    Ok(())
}
