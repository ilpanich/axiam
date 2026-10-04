//! The SAML identity provider's identifiers: its entity id and endpoint URLs
//! (G-2, T23.2.2 / T23.2.5).
//!
//! **Not behind the `saml` feature.** They are string functions of the
//! deployment's public base URL and a tenant id, and contract §29's `get_idp`
//! answers them in every build — including one that serves no SAML — so the
//! administrator sees the metadata URL and entity id an SP will be given before
//! the IdP is switched on. They were in `saml_idp`, which is gated; they moved
//! here so the two can never disagree (D-40).
//!
//! The base is the deployment's public root, `AuthConfig::root_issuer()` — the
//! value the OIDC issuer and the T21.6 per-tenant issuers are built on — with or
//! without a trailing slash. The tenant is the tenant **of the request path**,
//! never one read from a stored row.

use uuid::Uuid;

/// The tenant's IdP entity id: `{public_base_url}/saml/v2/{tenant_id}/metadata`.
///
/// **The one definition.** The `Issuer` of every response and assertion, the
/// metadata document's `entityID` (T23.2.5) and anything else that names the
/// IdP must come from here, so they cannot disagree.
///
/// The entity id is the metadata URL itself, the common convention that lets an
/// SP administrator paste one URL and fetch the metadata from it.
#[must_use]
pub fn idp_entity_id(public_base_url: &str, tenant_id: Uuid) -> String {
    idp_endpoint(public_base_url, tenant_id, "metadata")
}

/// The tenant's SSO endpoint, `{public_base_url}/saml/v2/{tenant_id}/sso`, for
/// the metadata `SingleSignOnService` locations (T23.2.5).
#[must_use]
pub fn idp_sso_url(public_base_url: &str, tenant_id: Uuid) -> String {
    idp_endpoint(public_base_url, tenant_id, "sso")
}

/// The tenant's SLO endpoint, `{public_base_url}/saml/v2/{tenant_id}/slo`, for
/// the metadata `SingleLogoutService` locations (T23.2.4) and the `Destination`
/// every logout message sent to it must carry.
#[must_use]
pub fn idp_slo_url(public_base_url: &str, tenant_id: Uuid) -> String {
    idp_endpoint(public_base_url, tenant_id, "slo")
}

fn idp_endpoint(public_base_url: &str, tenant_id: Uuid, leaf: &str) -> String {
    format!(
        "{}/saml/v2/{tenant_id}/{leaf}",
        public_base_url.trim_end_matches('/')
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_urls_are_one_function_of_the_base_and_the_tenant() {
        let tenant = Uuid::nil();
        for base in ["https://iam.example.com", "https://iam.example.com/"] {
            assert_eq!(
                idp_entity_id(base, tenant),
                format!("https://iam.example.com/saml/v2/{tenant}/metadata")
            );
            assert_eq!(
                idp_sso_url(base, tenant),
                format!("https://iam.example.com/saml/v2/{tenant}/sso")
            );
            assert_eq!(
                idp_slo_url(base, tenant),
                format!("https://iam.example.com/saml/v2/{tenant}/slo")
            );
        }
    }
}
