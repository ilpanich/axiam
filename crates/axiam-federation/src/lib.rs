//! AXIAM Federation — SAML Service Provider and OIDC external IdP integration.
//!
//! This crate provides OIDC and SAML federation support for authenticating
//! users through external identity providers (Google, Okta, Azure AD,
//! Shibboleth, ADFS, etc.).

/// Sign in with Apple's ES256 client secret, minted rather than stored.
pub mod apple;
pub mod cert;
pub mod discovery_cache;
pub mod error;
/// Templated OIDC issuers (Entra ID's `{tenantid}`) and the allow-list that
/// keeps "any tenant" from being an accident.
pub mod issuer;
pub mod jwks_cache;
/// The plain-OAuth2 login variant: authentication by userinfo call, for
/// providers that issue no ID token.
pub mod oauth2;
pub mod oidc;
/// PKCE (RFC 7636) for the outbound federation flows.
pub mod pkce;
#[cfg(feature = "saml")]
pub mod saml;
/// SAML 2.0 identity provider: assertion issuance — `NameID` policy, attribute
/// mapping, enveloped XML-DSig, the response envelope (G-2, T23.2.2). A library;
/// the SSO, SLO and metadata endpoints are `axiam-api-rest`'s.
#[cfg(feature = "saml")]
pub mod saml_idp;
/// The SAML identity provider's entity id and endpoint URLs. Not behind the
/// `saml` feature: contract §29's `get_idp` answers them in every build (T23.2.5).
pub mod saml_idp_urls;
/// The SAML SP's view of an external IdP's metadata document: its signature,
/// when the configuration names a certificate, and a per-process cache
/// (#530).
#[cfg(feature = "saml")]
pub mod saml_metadata;
/// Write-time rules for the SAML service-provider registry (G-2, T23.2.1):
/// the ACS allow-list, SP certificates and attribute mappings. Plain data and
/// URL/X.509 parsing, so it is not behind the `saml` feature.
pub mod saml_sp;
pub mod secrets;
/// X4 — verifying an external IdP's token as an RFC 8693 subject token.
pub mod token_exchange;

/// Shared SSRF guard (D2, X3): lifted verbatim to `axiam-pki` because it now
/// backs the MDS BLOB fetch path too, and PKI is where trust-anchor/outbound
/// fetch concerns belong. Re-exported here so every pre-existing
/// `crate::ssrf::…` call site and test in this crate keeps compiling
/// unchanged — `axiam-pki` depends only on `axiam-core`, so this direction
/// (`federation -> pki`) introduces no dependency cycle.
pub use axiam_pki::ssrf;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_metadata_url_accepts_https() {
        assert!(validate_metadata_url("https://idp.example.com/metadata").is_ok());
    }

    #[test]
    fn validate_metadata_url_rejects_http() {
        let err = validate_metadata_url("http://idp.example.com/metadata").unwrap_err();
        assert!(matches!(err, FederationError::InvalidMetadataUrl(_)));
    }

    #[test]
    fn validate_metadata_url_rejects_non_url() {
        let err = validate_metadata_url("not a url").unwrap_err();
        assert!(matches!(err, FederationError::InvalidMetadataUrl(_)));
    }
}
