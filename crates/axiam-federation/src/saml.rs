//! SAML Service Provider federation service.
//!
//! Handles SAML 2.0 SP-initiated SSO: building AuthnRequests, parsing
//! SAML Responses, extracting assertions, and provisioning or linking
//! local users to external IdP identities via SAML NameIDs.

use std::collections::HashMap;
use std::io::Write;

use axiam_core::error::AxiamError;
use axiam_core::models::federation::{CreateFederationLink, FederationProtocol};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    FederationConfigRepository, FederationLinkRepository, UserRepository,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::Utc;
use flate2::Compression;
use flate2::write::DeflateEncoder;
use samael::metadata::{EntityDescriptorType, HTTP_POST_BINDING, HTTP_REDIRECT_BINDING};
use samael::schema::{AuthnRequest, Issuer, NameIdPolicy};
use samael::traits::ToXml;
use serde::Serialize;
use tracing::{info, warn};
use uuid::Uuid;

use crate::error::FederationError;
use crate::oidc::FederationCallbackResult;
use crate::validate_metadata_url;

/// SAML success status URI.
const SAML_STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";

/// Persistent NameID format URI.
const NAMEID_FORMAT_PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Parsed IdP metadata extracted from SAML metadata XML.
#[derive(Debug, Clone)]
pub struct IdpMetadata {
    /// The IdP's entity ID from the metadata document.
    pub entity_id: String,
    /// The SSO endpoint URL.
    pub sso_url: String,
    /// The binding type for the SSO endpoint.
    pub sso_binding: String,
}

/// Result of building a SAML AuthnRequest.
#[derive(Debug, Clone, Serialize)]
pub struct SamlAuthnRequestResult {
    /// Full redirect URL (HTTP-Redirect) or IdP SSO URL (HTTP-POST).
    pub url: String,
    /// Base64-encoded AuthnRequest XML.
    pub saml_request: String,
    /// Binding type used for this request.
    pub binding: String,
    /// Relay state passed through the SSO flow.
    pub relay_state: Option<String>,
}

/// Claims extracted from a SAML assertion.
#[derive(Debug, Clone)]
pub struct SamlAssertionClaims {
    /// The NameID value from the assertion subject.
    pub name_id: String,
    /// Session index from the AuthnStatement, if present.
    pub session_index: Option<String>,
    /// All attributes keyed by attribute name, with multiple values.
    pub attributes: HashMap<String, Vec<String>>,
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// SAML Federation Service that handles external SAML IdP integration.
///
/// Generic over repository implementations for testability.
pub struct SamlFederationService<FC, FL, UR> {
    federation_config_repo: FC,
    federation_link_repo: FL,
    user_repo: UR,
    http_client: reqwest::Client,
}

impl<FC, FL, UR> SamlFederationService<FC, FL, UR>
where
    FC: FederationConfigRepository,
    FL: FederationLinkRepository,
    UR: UserRepository,
{
    /// Create a new SAML federation service.
    pub fn new(
        federation_config_repo: FC,
        federation_link_repo: FL,
        user_repo: UR,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            federation_config_repo,
            federation_link_repo,
            user_repo,
            http_client,
        }
    }

    /// Fetch and parse the IdP SAML metadata from the given URL.
    ///
    /// Only HTTPS URLs are accepted to mitigate SSRF risks.
    pub async fn fetch_idp_metadata(
        &self,
        metadata_url: &str,
    ) -> Result<IdpMetadata, FederationError> {
        validate_metadata_url(metadata_url)?;

        let response = self
            .http_client
            .get(metadata_url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| {
                FederationError::SamlMetadataFailed(format!("HTTP request failed: {e}"))
            })?;

        if !response.status().is_success() {
            return Err(FederationError::SamlMetadataFailed(format!(
                "HTTP {} from metadata endpoint",
                response.status()
            )));
        }

        let text = response.text().await.map_err(|e| {
            FederationError::SamlMetadataFailed(format!("Failed to read metadata body: {e}"))
        })?;

        let descriptor_type: EntityDescriptorType = text.parse().map_err(|e| {
            FederationError::SamlMetadataFailed(format!("Failed to parse metadata XML: {e}"))
        })?;

        // Extract the first EntityDescriptor from the parsed metadata.
        let ed = descriptor_type.iter().next().ok_or_else(|| {
            FederationError::SamlMetadataFailed("No EntityDescriptor found in metadata".into())
        })?;

        let entity_id = ed.entity_id.clone().ok_or_else(|| {
            FederationError::SamlMetadataFailed("EntityDescriptor missing entityID".into())
        })?;

        let idp_descriptors = ed.idp_sso_descriptors.as_ref().ok_or_else(|| {
            FederationError::SamlMetadataFailed("No IDPSSODescriptor in metadata".into())
        })?;

        let idp = idp_descriptors.first().ok_or_else(|| {
            FederationError::SamlMetadataFailed("Empty IDPSSODescriptor list in metadata".into())
        })?;

        // Prefer HTTP-POST binding, fall back to HTTP-Redirect.
        let sso_endpoint = idp
            .single_sign_on_services
            .iter()
            .find(|ep| ep.binding == HTTP_POST_BINDING)
            .or_else(|| {
                idp.single_sign_on_services
                    .iter()
                    .find(|ep| ep.binding == HTTP_REDIRECT_BINDING)
            })
            .ok_or_else(|| {
                FederationError::SamlMetadataFailed(
                    "No HTTP-POST or HTTP-Redirect SSO endpoint".into(),
                )
            })?;

        Ok(IdpMetadata {
            entity_id,
            sso_url: sso_endpoint.location.clone(),
            sso_binding: sso_endpoint.binding.clone(),
        })
    }

    /// Build a SAML AuthnRequest for the specified federation config.
    ///
    /// Returns the SSO URL, base64-encoded request, binding type, and
    /// optional relay state for the caller to use in the redirect or
    /// POST form.
    pub async fn build_authn_request(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
        acs_url: &str,
        relay_state: Option<String>,
    ) -> Result<SamlAuthnRequestResult, FederationError> {
        let config = self
            .federation_config_repo
            .get_by_id(tenant_id, config_id)
            .await
            .map_err(|e| match e {
                AxiamError::NotFound { id, .. } => FederationError::ConfigNotFound(id),
                other => FederationError::Internal(other.to_string()),
            })?;

        if !config.enabled {
            return Err(FederationError::ConfigDisabled);
        }

        if config.protocol != FederationProtocol::Saml {
            return Err(FederationError::ProtocolMismatch(
                "expected Saml protocol".into(),
            ));
        }

        let metadata_url = config.metadata_url.as_deref().ok_or_else(|| {
            FederationError::SamlMetadataFailed("No metadata URL configured".into())
        })?;

        let idp = self.fetch_idp_metadata(metadata_url).await?;

        let authn_request = AuthnRequest {
            id: format!("_{}", Uuid::new_v4()),
            version: "2.0".into(),
            issue_instant: Utc::now(),
            destination: Some(idp.sso_url.clone()),
            issuer: Some(Issuer {
                value: Some(config.client_id.clone()),
                ..Default::default()
            }),
            assertion_consumer_service_url: Some(acs_url.to_string()),
            protocol_binding: Some(HTTP_POST_BINDING.to_string()),
            name_id_policy: Some(NameIdPolicy {
                allow_create: Some(true),
                format: Some(NAMEID_FORMAT_PERSISTENT.into()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let xml = authn_request.to_string().map_err(|e| {
            FederationError::Internal(format!("Failed to serialize AuthnRequest to XML: {e:?}"))
        })?;

        let (saml_request, url) = if idp.sso_binding == HTTP_REDIRECT_BINDING {
            // HTTP-Redirect: DEFLATE compress then base64 encode.
            let deflated = deflate_encode(xml.as_bytes())?;
            let encoded = STANDARD.encode(&deflated);

            let mut redirect_url = url::Url::parse(&idp.sso_url).map_err(|e| {
                FederationError::SamlMetadataFailed(format!("Invalid SSO URL: {e}"))
            })?;

            redirect_url
                .query_pairs_mut()
                .append_pair("SAMLRequest", &encoded);

            if let Some(ref rs) = relay_state {
                redirect_url.query_pairs_mut().append_pair("RelayState", rs);
            }

            (encoded, redirect_url.to_string())
        } else {
            // HTTP-POST: base64 encode the raw XML (no deflate).
            let encoded = STANDARD.encode(xml.as_bytes());
            (encoded, idp.sso_url.clone())
        };

        info!(
            tenant_id = %tenant_id,
            config_id = %config_id,
            binding = %idp.sso_binding,
            "Built SAML AuthnRequest"
        );

        Ok(SamlAuthnRequestResult {
            url,
            saml_request,
            binding: idp.sso_binding,
            relay_state,
        })
    }

    /// Handle a SAML Response received at the Assertion Consumer Service.
    ///
    /// Decodes, parses, validates the response, extracts the assertion
    /// claims, and provisions or links the local user.
    pub async fn handle_saml_response(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
        saml_response_b64: &str,
        _relay_state: Option<&str>,
    ) -> Result<FederationCallbackResult, FederationError> {
        let config = self
            .federation_config_repo
            .get_by_id(tenant_id, config_id)
            .await
            .map_err(|e| match e {
                AxiamError::NotFound { id, .. } => FederationError::ConfigNotFound(id),
                other => FederationError::Internal(other.to_string()),
            })?;

        if !config.enabled {
            return Err(FederationError::ConfigDisabled);
        }

        if config.protocol != FederationProtocol::Saml {
            return Err(FederationError::ProtocolMismatch(
                "expected Saml protocol".into(),
            ));
        }

        // Decode base64 SAML response.
        let decoded = STANDARD.decode(saml_response_b64).map_err(|e| {
            FederationError::SamlResponseFailed(format!("Base64 decode failed: {e}"))
        })?;

        let xml = String::from_utf8(decoded).map_err(|e| {
            FederationError::SamlResponseFailed(format!("Invalid UTF-8 in SAML response: {e}"))
        })?;

        let response: samael::schema::Response = xml.parse().map_err(|e| {
            FederationError::SamlResponseFailed(format!("Failed to parse SAML Response XML: {e}"))
        })?;

        // NOTE: XML signature verification is not yet implemented.
        // This mirrors the OIDC module's deferred JWT signature
        // verification. Full signature validation using the IdP's
        // X.509 certificate from metadata should be added before
        // production use.
        warn!(
            tenant_id = %tenant_id,
            config_id = %config_id,
            "SAML response signature verification is not yet implemented"
        );

        // Validate status.
        let status = response.status.as_ref().ok_or_else(|| {
            FederationError::SamlResponseFailed("SAML Response missing Status element".into())
        })?;

        let status_value = status.status_code.value.as_deref().unwrap_or("");
        if status_value != SAML_STATUS_SUCCESS {
            return Err(FederationError::SamlResponseFailed(format!(
                "SAML Response status is not Success: {status_value}"
            )));
        }

        // Extract assertion.
        let assertion = response.assertion.as_ref().ok_or_else(|| {
            FederationError::SamlResponseFailed("SAML Response missing Assertion".into())
        })?;

        // Validate conditions if present.
        if let Some(conditions) = &assertion.conditions {
            let now = Utc::now();
            if let Some(not_before) = conditions.not_before
                && now < not_before
            {
                return Err(FederationError::SamlResponseFailed(format!(
                    "Assertion not yet valid (NotBefore: {not_before})"
                )));
            }
            if let Some(not_on_or_after) = conditions.not_on_or_after
                && now >= not_on_or_after
            {
                return Err(FederationError::SamlResponseFailed(format!(
                    "Assertion expired (NotOnOrAfter: {not_on_or_after})"
                )));
            }

            // Validate audience restriction matches our SP entity ID.
            if let Some(audience_restrictions) = &conditions.audience_restrictions {
                let sp_entity_id = &config.client_id;
                let audience_matches = audience_restrictions
                    .iter()
                    .any(|ar| ar.audience.iter().any(|aud| aud == sp_entity_id));
                if !audience_matches {
                    return Err(FederationError::SamlResponseFailed(format!(
                        "Audience restriction does not match \
                             SP entity ID: {sp_entity_id}"
                    )));
                }
            }
        }

        // Extract claims from assertion.
        let claims = extract_assertion_claims(assertion)?;

        info!(
            tenant_id = %tenant_id,
            config_id = %config_id,
            name_id = %claims.name_id,
            "SAML ACS: assertion validated successfully"
        );

        // Apply attribute_map to resolve email and display name.
        let (email, display_name) = apply_attribute_map(&claims, &config.attribute_map);

        self.provision_or_link_user(
            tenant_id,
            config_id,
            &claims.name_id,
            email.as_deref(),
            display_name.as_deref(),
        )
        .await
    }

    /// Generate SP metadata XML for the given federation config.
    pub async fn generate_sp_metadata(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
        acs_url: &str,
    ) -> Result<String, FederationError> {
        let config = self
            .federation_config_repo
            .get_by_id(tenant_id, config_id)
            .await
            .map_err(|e| match e {
                AxiamError::NotFound { id, .. } => FederationError::ConfigNotFound(id),
                other => FederationError::Internal(other.to_string()),
            })?;

        if config.protocol != FederationProtocol::Saml {
            return Err(FederationError::ProtocolMismatch(
                "expected Saml protocol".into(),
            ));
        }

        let sp_entity_id = xml_escape(&config.client_id);
        let acs_escaped = xml_escape(acs_url);

        Ok(format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="{sp_entity_id}">
  <md:SPSSODescriptor
      AuthnRequestsSigned="false"
      WantAssertionsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>{NAMEID_FORMAT_PERSISTENT}</md:NameIDFormat>
    <md:AssertionConsumerService
        Binding="{HTTP_POST_BINDING}"
        Location="{acs_escaped}"
        index="0"
        isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"#
        ))
    }

    /// Provision a new user or link an existing one to the external
    /// SAML IdP identity.
    async fn provision_or_link_user(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
        name_id: &str,
        email: Option<&str>,
        display_name: Option<&str>,
    ) -> Result<FederationCallbackResult, FederationError> {
        // Check if a link already exists for this NameID.
        let existing_link = self
            .federation_link_repo
            .get_by_external_subject(tenant_id, config_id, name_id)
            .await;

        match existing_link {
            Ok(link) => {
                let user = self
                    .user_repo
                    .get_by_id(tenant_id, link.user_id)
                    .await
                    .map_err(|e| {
                        FederationError::ProvisioningFailed(format!(
                            "Failed to fetch linked user: {e}"
                        ))
                    })?;

                info!(
                    tenant_id = %tenant_id,
                    user_id = %user.id,
                    name_id = %name_id,
                    "Returning existing SAML-federated user"
                );

                Ok(FederationCallbackResult {
                    user,
                    federation_link: link,
                    newly_provisioned: false,
                })
            }
            Err(AxiamError::NotFound { .. }) => {
                self.provision_new_user(tenant_id, config_id, name_id, email, display_name)
                    .await
            }
            Err(e) => Err(FederationError::ProvisioningFailed(format!(
                "Failed to check existing federation link: {e}"
            ))),
        }
    }

    /// Create a new local user and federation link for a SAML identity.
    async fn provision_new_user(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
        name_id: &str,
        email: Option<&str>,
        display_name: Option<&str>,
    ) -> Result<FederationCallbackResult, FederationError> {
        let username = display_name.or(email).unwrap_or(name_id).to_string();

        let user_email = email
            .map(String::from)
            .unwrap_or_else(|| format!("{name_id}@federated.local"));

        // Federated users get a random non-usable password since they
        // authenticate through the external IdP.
        let random_password = Uuid::new_v4().to_string();

        let create_user = CreateUser {
            tenant_id,
            username,
            email: user_email.clone(),
            password: random_password,
            metadata: Some(serde_json::json!({
                "federation_config_id": config_id.to_string(),
                "external_subject": name_id,
                "provisioned_by": "saml_federation",
            })),
        };

        let user = self.user_repo.create(create_user).await.map_err(|e| {
            FederationError::ProvisioningFailed(format!("Failed to create user: {e}"))
        })?;

        let create_link = CreateFederationLink {
            tenant_id,
            user_id: user.id,
            federation_config_id: config_id,
            external_subject: name_id.to_string(),
            external_email: Some(user_email),
        };

        let link = self
            .federation_link_repo
            .create(create_link)
            .await
            .map_err(|e| {
                FederationError::ProvisioningFailed(format!(
                    "Failed to create federation link: {e}"
                ))
            })?;

        info!(
            tenant_id = %tenant_id,
            user_id = %user.id,
            name_id = %name_id,
            "Provisioned new SAML-federated user"
        );

        Ok(FederationCallbackResult {
            user,
            federation_link: link,
            newly_provisioned: true,
        })
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Extract NameID, session index, and attributes from a SAML assertion.
fn extract_assertion_claims(
    assertion: &samael::schema::Assertion,
) -> Result<SamlAssertionClaims, FederationError> {
    let name_id = assertion
        .subject
        .as_ref()
        .and_then(|s| s.name_id.as_ref())
        .map(|n| n.value.clone())
        .ok_or_else(|| {
            FederationError::SamlResponseFailed("Assertion missing Subject/NameID".into())
        })?;

    let session_index = assertion
        .authn_statements
        .as_ref()
        .and_then(|stmts| stmts.first())
        .and_then(|stmt| stmt.session_index.clone());

    let mut attributes: HashMap<String, Vec<String>> = HashMap::new();
    if let Some(attr_statements) = &assertion.attribute_statements {
        for statement in attr_statements {
            for attr in &statement.attributes {
                let attr_name = attr
                    .name
                    .as_deref()
                    .or(attr.friendly_name.as_deref())
                    .unwrap_or("unknown");

                let values: Vec<String> =
                    attr.values.iter().filter_map(|v| v.value.clone()).collect();

                attributes
                    .entry(attr_name.to_string())
                    .or_default()
                    .extend(values);
            }
        }
    }

    Ok(SamlAssertionClaims {
        name_id,
        session_index,
        attributes,
    })
}

/// Apply the federation config's attribute_map to resolve email and
/// display name from SAML assertion attributes.
///
/// The attribute_map is a JSON object mapping AXIAM field names to SAML
/// attribute names, e.g.: `{"email": "mail", "name": "displayName"}`.
fn apply_attribute_map(
    claims: &SamlAssertionClaims,
    attribute_map: &serde_json::Value,
) -> (Option<String>, Option<String>) {
    let get_mapped = |field: &str| -> Option<String> {
        let saml_attr_name = attribute_map.get(field)?.as_str()?;
        claims
            .attributes
            .get(saml_attr_name)
            .and_then(|vals| vals.first())
            .cloned()
    };

    let email = get_mapped("email");
    let display_name = get_mapped("name").or_else(|| get_mapped("displayName"));

    (email, display_name)
}

/// Escape XML special characters in attribute values and text content.
fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// DEFLATE-compress the input bytes (raw deflate, no zlib/gzip headers).
fn deflate_encode(input: &[u8]) -> Result<Vec<u8>, FederationError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(input)
        .map_err(|e| FederationError::Internal(format!("DEFLATE compression failed: {e}")))?;
    encoder
        .finish()
        .map_err(|e| FederationError::Internal(format!("DEFLATE finish failed: {e}")))
}
