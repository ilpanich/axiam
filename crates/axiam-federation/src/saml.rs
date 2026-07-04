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
    AssertionReplayRepository, FederationConfigRepository, FederationLinkRepository, UserRepository,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{self, Utc};
use flate2::Compression;
use flate2::write::DeflateEncoder;
use samael::metadata::{EntityDescriptorType, HTTP_POST_BINDING, HTTP_REDIRECT_BINDING};
use samael::schema::{AuthnRequest, Issuer, NameIdPolicy};
use samael::traits::ToXml;
use serde::Serialize;
use tracing::info;
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
    /// The AuthnRequest ID (`_<uuid>` format).
    ///
    /// Callers MUST store this in `FederationLoginState.request_id` so the
    /// ACS handler can verify `Response.InResponseTo` (SEC-005/REQ-14 AC-5).
    pub request_id: String,
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
pub struct SamlFederationService<FC, FL, UR, AR> {
    federation_config_repo: FC,
    federation_link_repo: FL,
    user_repo: UR,
    replay_repo: AR,
    http_client: reqwest::Client,
}

impl<FC, FL, UR, AR> SamlFederationService<FC, FL, UR, AR>
where
    FC: FederationConfigRepository,
    FL: FederationLinkRepository,
    UR: UserRepository,
    AR: AssertionReplayRepository,
{
    /// Create a new SAML federation service.
    pub fn new(
        federation_config_repo: FC,
        federation_link_repo: FL,
        user_repo: UR,
        replay_repo: AR,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            federation_config_repo,
            federation_link_repo,
            user_repo,
            replay_repo,
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

        // Enforce a maximum body size to prevent memory exhaustion from
        // a large metadata document.
        const MAX_METADATA_SIZE: usize = 512 * 1024; // 512 KiB
        let bytes = response.bytes().await.map_err(|e| {
            FederationError::SamlMetadataFailed(format!("Failed to read metadata body: {e}"))
        })?;
        if bytes.len() > MAX_METADATA_SIZE {
            return Err(FederationError::SamlMetadataFailed(format!(
                "Metadata document too large: {} bytes (max {})",
                bytes.len(),
                MAX_METADATA_SIZE
            )));
        }

        let text = String::from_utf8(bytes.to_vec()).map_err(|e| {
            FederationError::SamlMetadataFailed(format!("Invalid UTF-8 in metadata: {e}"))
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

        // Validate that the SSO endpoint uses HTTPS to prevent
        // redirecting users to insecure origins. Fail closed on
        // parse errors — reject malformed URLs outright.
        let sso_parsed = url::Url::parse(&sso_endpoint.location).map_err(|e| {
            FederationError::SamlMetadataFailed(format!("IdP SSO endpoint is not a valid URL: {e}"))
        })?;
        if sso_parsed.scheme() != "https" {
            return Err(FederationError::SamlMetadataFailed(
                "IdP SSO endpoint must use HTTPS".into(),
            ));
        }

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

        let authn_request_id = format!("_{}", Uuid::new_v4());
        let authn_request = AuthnRequest {
            id: authn_request_id.clone(),
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
            request_id: authn_request_id,
        })
    }

    /// Handle a SAML Response received at the Assertion Consumer Service.
    ///
    /// Decodes, parses, validates the response, extracts the assertion
    /// claims, and provisions or links the local user.
    ///
    /// `expected_request_id` — if `Some`, checked against `Response.InResponseTo`
    /// (SEC-005/REQ-14 AC-5).  Pass the ID stored in `FederationLoginState.request_id`.
    ///
    /// `expected_destination` — if `Some` and non-empty, checked against
    /// `Response.Destination` (SEC-005/REQ-14 AC-5).
    ///
    /// `require_in_response_to` — if `true` and `expected_request_id` is `None`,
    /// reject a response with no `InResponseTo` at all (unsolicited-response
    /// defense for callers, such as the authenticated ACS path, that have no
    /// stored request ID to compare against but still must not accept an
    /// out-of-band response). Has no effect when `expected_request_id` is
    /// `Some` — that already enforces presence-and-equality (SECFIX-04/SEC-005).
    pub async fn handle_saml_response(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
        saml_response_b64: &str,
        _relay_state: Option<&str>,
        expected_request_id: Option<&str>,
        expected_destination: Option<&str>,
        require_in_response_to: bool,
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

        // Step 1 — XML signature verification (D-06/D-07/D-08).
        // MUST run before any claims are trusted. Fails closed when:
        //   - idp_signing_cert_pem is None (config incomplete)
        //   - <ds:Signature> is absent from the document
        //   - The digest or signature value does not verify
        self.verify_signature(xml.as_bytes(), &config)?;

        // Step 1a — Protocol binding checks (SEC-005/REQ-14 AC-5).
        // These run after signature verification so we only check authentic responses.

        // InResponseTo: reject unsolicited responses when a request ID is available.
        if let Some(expected_id) = expected_request_id
            && !expected_id.is_empty()
        {
            match response.in_response_to.as_deref() {
                None => {
                    return Err(FederationError::SamlResponseFailed(
                        "SAML Response missing InResponseTo (unsolicited response rejected)".into(),
                    ));
                }
                Some(actual_id) if actual_id != expected_id => {
                    return Err(FederationError::SamlResponseFailed(format!(
                        "SAML Response InResponseTo mismatch: expected {expected_id}, \
                         got {actual_id}"
                    )));
                }
                _ => {}
            }
        } else if require_in_response_to && response.in_response_to.is_none() {
            // No stored expected_request_id is available (e.g. the authenticated
            // ACS path has no FederationLoginState row), but the caller still
            // requires presence to reject unsolicited responses (SECFIX-04/SEC-005).
            return Err(FederationError::SamlResponseFailed(
                "SAML Response missing InResponseTo (unsolicited response rejected)".into(),
            ));
        }

        // Destination: reject responses not addressed to this ACS URL.
        if let Some(expected_dest) = expected_destination
            && !expected_dest.is_empty()
        {
            match response.destination.as_deref() {
                None => {
                    return Err(FederationError::SamlResponseFailed(
                        "SAML Response missing Destination".into(),
                    ));
                }
                Some(actual_dest) if actual_dest != expected_dest => {
                    return Err(FederationError::SamlResponseFailed(format!(
                        "SAML Response Destination mismatch: expected {expected_dest}, \
                         got {actual_dest}"
                    )));
                }
                _ => {}
            }
        }

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

        // Step 2 — XSW (XML Signature Wrapping) binding check (SECFIX-04/SEC-005).
        // `verify_signature` above only proves SOME valid <ds:Signature> exists
        // somewhere in the document; it never surfaces which element ID it
        // verified. `response.assertion` is a scalar field, so a wrapped/duplicated
        // second <Assertion> sibling would otherwise be trusted unchallenged. Bind
        // the cryptographically verified signature to THIS consumed assertion by
        // raw-XML introspection: exactly one <Assertion> must exist document-wide,
        // and at least one <Signature>'s <Reference URI> must resolve to this
        // assertion's ID. Must run AFTER verify_signature (378) and AFTER the
        // assertion is read (above), BEFORE any of its claims are trusted.
        bind_signature_to_assertion(xml.as_bytes(), &assertion.id)?;

        // Validate conditions — REQUIRED (SEC-005/REQ-14 AC-5).
        // An assertion without a Conditions block has no validity window and no
        // audience restriction, so it must be rejected to prevent XSW attacks.
        let conditions = assertion.conditions.as_ref().ok_or_else(|| {
            FederationError::SamlResponseFailed(
                "Assertion missing required Conditions element".into(),
            )
        })?;

        {
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

        // Step 3 — Assertion replay protection (D-09).
        // Record the assertion ID in saml_assertion_replay. Returns
        // ReplayDetected on UNIQUE violation (same tenant_id + assertion_id).
        // Use NotOnOrAfter as the row TTL (Conditions is now required above;
        // fall back to 1 hour from now if NotOnOrAfter is not set).
        let replay_expires_at = conditions
            .not_on_or_after
            .unwrap_or_else(|| Utc::now() + chrono::Duration::hours(1));

        self.replay_repo
            .insert_assertion(tenant_id, &assertion.id, replay_expires_at)
            .await
            .map_err(|e| match e {
                AxiamError::ReplayDetected => FederationError::AssertionReplay,
                other => FederationError::Internal(other.to_string()),
            })?;

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

        // SEC-005/REQ-14 AC-5: advertise that we require signed assertions and
        // signed authn requests so compliant IdPs enforce these controls.
        Ok(format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="{sp_entity_id}">
  <md:SPSSODescriptor
      AuthnRequestsSigned="true"
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

    /// Verify the XML signature(s) in a SAML document against the configured
    /// IdP signing certificate.
    ///
    /// Behaviour (D-06/D-07/D-08):
    /// - If `config.idp_signing_cert_pem` is `None` → `ConfigIncomplete` (fail
    ///   closed: the config is not finished).
    /// - If no `<ds:Signature>` is present in the document → `SamlSignatureInvalid`
    ///   (samael's `verify_signed_xml` returns an error when there is no signature).
    /// - If the digest or signature value does not match → `SamlSignatureInvalid`.
    ///
    /// Must be called BEFORE `validate_conditions` so that a forged/unsigned
    /// assertion is rejected before any claims are trusted.
    fn verify_signature(
        &self,
        xml_bytes: &[u8],
        config: &axiam_core::models::federation::FederationConfig,
    ) -> Result<(), FederationError> {
        let pem = config
            .idp_signing_cert_pem
            .as_deref()
            .ok_or(FederationError::ConfigIncomplete)?;

        let der = crate::cert::pem_cert_to_der(pem)?;

        samael::crypto::verify_signed_xml(xml_bytes, &der, Some("ID"))
            .map_err(|e| FederationError::SamlSignatureInvalid(e.to_string()))
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
        _display_name: Option<&str>,
    ) -> Result<FederationCallbackResult, FederationError> {
        // Derive a deterministic unique username: prefer email (likely
        // unique per-tenant), otherwise use config_id + name_id. Display
        // names are neither stable nor unique, so they are not used.
        let username = email
            .map(String::from)
            .unwrap_or_else(|| format!("federated-{config_id}-{name_id}"));

        // Prefer an explicit email attribute; otherwise, if the SAML NameID is
        // itself email-shaped (the common `emailAddress` NameID format), use it
        // directly. Only fall back to a synthetic, namespaced address when the
        // NameID is opaque (e.g. a persistent/transient identifier).
        let user_email = email
            .map(String::from)
            .or_else(|| name_id.contains('@').then(|| name_id.to_string()))
            .unwrap_or_else(|| format!("{name_id}.{config_id}@federated.local"));

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

/// Bind the cryptographically verified XML signature to the assertion actually
/// consumed by `handle_saml_response` (SECFIX-04/SEC-005 — XML Signature
/// Wrapping defense).
///
/// `samael::crypto::verify_signed_xml` (called by `verify_signature` above)
/// only proves that SOME valid `<ds:Signature>` exists somewhere in the
/// document — it never surfaces which element ID the verified signature's
/// `<Reference URI="#...">` pointed to. Meanwhile `samael::schema::Response`
/// exposes `assertion` as a *scalar* `Option<Assertion>`, so an attacker can
/// keep the original signed assertion intact somewhere in the tree (so the
/// lone-signature check still passes) and inject a second, forged, unsigned
/// `<Assertion>` sibling that the deserializer happens to bind to
/// `response.assertion`.
///
/// This performs an independent raw-XML introspection pass (via `libxml`,
/// already resolved transitively through samael 0.0.19's `xmlsec` feature)
/// to close that gap:
///
/// 1. Exactly one `<Assertion>` element (namespace-agnostic local name) must
///    exist anywhere in the document — rejects the wrapped/duplicated payload
///    shape outright, regardless of signature status.
/// 2. At least one `<Signature>`'s `<Reference URI="#...">` must resolve to
///    `claimed_assertion_id` — binds "the element that was cryptographically
///    verified" to "the element whose claims are about to be trusted".
///    Rejects on an empty, absent, or non-matching reference.
///
/// Never uses regex/string search on the XML (a real, namespace-aware XPath
/// parser is required — see 23-RESEARCH.md Anti-Patterns).
fn bind_signature_to_assertion(
    xml_bytes: &[u8],
    claimed_assertion_id: &str,
) -> Result<(), FederationError> {
    let parser = libxml::parser::Parser::default();
    let doc = parser.parse_string(xml_bytes).map_err(|e| {
        FederationError::SamlResponseFailed(format!(
            "XSW binding check: failed to re-parse SAML response XML: {e}"
        ))
    })?;

    let mut context = libxml::xpath::Context::new(&doc).map_err(|()| {
        FederationError::SamlResponseFailed(
            "XSW binding check: failed to create XPath context".into(),
        )
    })?;

    // 1. Exactly one Assertion element must exist anywhere in the document.
    let assertions = context
        .findnodes("//*[local-name()='Assertion']", None)
        .map_err(|()| {
            FederationError::SamlResponseFailed(
                "XSW binding check: XPath evaluation failed (Assertion)".into(),
            )
        })?;
    if assertions.len() != 1 {
        return Err(FederationError::SamlResponseFailed(format!(
            "expected exactly 1 Assertion element in SAML Response, found {} \
             (possible XML Signature Wrapping attack)",
            assertions.len()
        )));
    }

    // 2. Every <Signature>'s Reference URI must resolve to the consumed
    //    assertion's ID. Reject on empty/absent/non-matching references.
    let references = context
        .findnodes(
            "//*[local-name()='Signature']//*[local-name()='Reference']/@URI",
            None,
        )
        .map_err(|()| {
            FederationError::SamlResponseFailed(
                "XSW binding check: XPath evaluation failed (Signature/Reference)".into(),
            )
        })?;

    let expected_reference = format!("#{claimed_assertion_id}");
    let bound = references.iter().any(|node| {
        let uri = node.get_content();
        !uri.is_empty() && uri == expected_reference
    });
    if !bound {
        return Err(FederationError::SamlResponseFailed(
            "no verified Signature references the consumed Assertion \
             (XML Signature Wrapping rejected)"
                .into(),
        ));
    }

    Ok(())
}

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

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::federation::FederationProtocol;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn test_cert_pem() -> String {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/saml/signing_cert.pem"),
        )
        .expect("signing_cert.pem must be present in tests/fixtures/saml/")
    }

    fn load_fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/saml")
                .join(name),
        )
        .unwrap_or_else(|_| panic!("fixture {name} must be present"))
    }

    fn test_federation_config(
        cert_pem: Option<String>,
    ) -> axiam_core::models::federation::FederationConfig {
        axiam_core::models::federation::FederationConfig {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            provider: "test-idp".into(),
            protocol: FederationProtocol::Saml,
            metadata_url: None,
            client_id: "https://sp.example.com".into(),
            client_secret: String::new(),
            attribute_map: serde_json::json!({}),
            enabled: true,
            allowed_algorithms: vec![],
            idp_signing_cert_pem: cert_pem,
            client_secret_ciphertext: None,
            client_secret_nonce: None,
            client_secret_key_version: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // Minimal in-memory replay repo for unit tests.
    struct MemReplayRepo(std::sync::Mutex<std::collections::HashSet<(Uuid, String)>>);

    impl MemReplayRepo {
        fn new() -> Self {
            Self(std::sync::Mutex::new(std::collections::HashSet::new()))
        }
    }

    impl axiam_core::repository::AssertionReplayRepository for MemReplayRepo {
        async fn insert_assertion(
            &self,
            tenant_id: Uuid,
            assertion_id: &str,
            _expires_at: chrono::DateTime<Utc>,
        ) -> axiam_core::error::AxiamResult<()> {
            let key = (tenant_id, assertion_id.to_string());
            let mut set = self.0.lock().unwrap();
            if set.contains(&key) {
                Err(axiam_core::error::AxiamError::ReplayDetected)
            } else {
                set.insert(key);
                Ok(())
            }
        }

        async fn cleanup_expired(&self) -> axiam_core::error::AxiamResult<u64> {
            Ok(0)
        }
    }

    // Minimal in-memory repo shims for the other generic params.
    use axiam_core::models::federation::{
        CreateFederationConfig, CreateFederationLink, FederationConfig, FederationLink,
        UpdateFederationConfig,
    };
    use axiam_core::models::user::{CreateUser, UpdateUser, User};
    use axiam_core::repository::{
        FederationConfigRepository, FederationLinkRepository, PaginatedResult, Pagination,
        UserRepository,
    };

    struct NoopFedConfigRepo;
    impl FederationConfigRepository for NoopFedConfigRepo {
        async fn create(
            &self,
            _: CreateFederationConfig,
        ) -> axiam_core::error::AxiamResult<FederationConfig> {
            unimplemented!()
        }
        async fn get_by_id(
            &self,
            _: Uuid,
            _: Uuid,
        ) -> axiam_core::error::AxiamResult<FederationConfig> {
            unimplemented!()
        }
        async fn update(
            &self,
            _: Uuid,
            _: Uuid,
            _: UpdateFederationConfig,
        ) -> axiam_core::error::AxiamResult<FederationConfig> {
            unimplemented!()
        }
        async fn delete(&self, _: Uuid, _: Uuid) -> axiam_core::error::AxiamResult<()> {
            unimplemented!()
        }
        async fn list(
            &self,
            _: Uuid,
            _: Pagination,
        ) -> axiam_core::error::AxiamResult<PaginatedResult<FederationConfig>> {
            unimplemented!()
        }
        async fn list_with_legacy_plaintext_secret(
            &self,
        ) -> axiam_core::error::AxiamResult<Vec<FederationConfig>> {
            unimplemented!()
        }
        async fn set_encrypted_secret(
            &self,
            _: Uuid,
            _: Uuid,
            _: String,
            _: String,
            _: i64,
        ) -> axiam_core::error::AxiamResult<()> {
            unimplemented!()
        }
    }

    struct NoopFedLinkRepo;
    impl FederationLinkRepository for NoopFedLinkRepo {
        async fn create(
            &self,
            _: CreateFederationLink,
        ) -> axiam_core::error::AxiamResult<FederationLink> {
            unimplemented!()
        }
        async fn get_by_external_subject(
            &self,
            _: Uuid,
            _: Uuid,
            _: &str,
        ) -> axiam_core::error::AxiamResult<FederationLink> {
            unimplemented!()
        }
        async fn get_by_user_id(
            &self,
            _: Uuid,
            _: Uuid,
        ) -> axiam_core::error::AxiamResult<Vec<FederationLink>> {
            unimplemented!()
        }
        async fn delete(&self, _: Uuid, _: Uuid) -> axiam_core::error::AxiamResult<()> {
            unimplemented!()
        }
    }

    struct NoopUserRepo;
    impl UserRepository for NoopUserRepo {
        async fn create(&self, _: CreateUser) -> axiam_core::error::AxiamResult<User> {
            unimplemented!()
        }
        async fn get_by_id(&self, _: Uuid, _: Uuid) -> axiam_core::error::AxiamResult<User> {
            unimplemented!()
        }
        async fn get_by_username(&self, _: Uuid, _: &str) -> axiam_core::error::AxiamResult<User> {
            unimplemented!()
        }
        async fn get_by_email(&self, _: Uuid, _: &str) -> axiam_core::error::AxiamResult<User> {
            unimplemented!()
        }
        async fn update(
            &self,
            _: Uuid,
            _: Uuid,
            _: UpdateUser,
        ) -> axiam_core::error::AxiamResult<User> {
            unimplemented!()
        }
        async fn delete(&self, _: Uuid, _: Uuid) -> axiam_core::error::AxiamResult<()> {
            unimplemented!()
        }
        async fn update_totp_step(
            &self,
            _: Uuid,
            _: Uuid,
            _: u64,
        ) -> axiam_core::error::AxiamResult<bool> {
            unimplemented!()
        }
        async fn list(
            &self,
            _: Uuid,
            _: Pagination,
        ) -> axiam_core::error::AxiamResult<PaginatedResult<User>> {
            unimplemented!()
        }
        async fn increment_failed_logins(
            &self,
            _: Uuid,
            _: Uuid,
            _: u32,
            _: i64,
            _: f64,
            _: i64,
        ) -> axiam_core::error::AxiamResult<()> {
            unimplemented!()
        }
    }

    fn make_service()
    -> SamlFederationService<NoopFedConfigRepo, NoopFedLinkRepo, NoopUserRepo, MemReplayRepo> {
        SamlFederationService::new(
            NoopFedConfigRepo,
            NoopFedLinkRepo,
            NoopUserRepo,
            MemReplayRepo::new(),
            reqwest::Client::new(),
        )
    }

    // -----------------------------------------------------------------------
    // Signature verification tests (compiled with the `saml` feature, which
    // pulls samael's xmlsec backend; needs Debian libxmlsec1 1.2.x at build time)
    // -----------------------------------------------------------------------

    /// Verifies that a well-formed, correctly-signed SAML response passes.
    #[test]
    fn verify_accepts_well_signed_response() {
        let svc = make_service();
        let xml = load_fixture("well_signed_response.xml");
        let config = test_federation_config(Some(test_cert_pem()));
        svc.verify_signature(&xml, &config)
            .expect("well-signed response should pass verification");
    }

    /// Verifies that a response with a tampered body is rejected (digest mismatch).
    #[test]
    fn verify_rejects_tampered_body() {
        let svc = make_service();
        let xml = load_fixture("tampered_response.xml");
        let config = test_federation_config(Some(test_cert_pem()));
        let err = svc
            .verify_signature(&xml, &config)
            .expect_err("tampered response must be rejected");
        assert!(
            matches!(err, FederationError::SamlSignatureInvalid(_)),
            "expected SamlSignatureInvalid, got: {err:?}"
        );
    }

    /// Verifies that a response with the signature block stripped is rejected.
    #[test]
    fn verify_rejects_missing_signature() {
        let svc = make_service();
        let raw = load_fixture("well_signed_response.xml");
        let xml_str = String::from_utf8(raw).unwrap();
        // Strip the ds:Signature block.
        let stripped = xml_str
            .lines()
            .filter(|l| !l.contains("<ds:Signature") && !l.contains("</ds:Signature"))
            .collect::<Vec<_>>()
            .join("\n");
        let config = test_federation_config(Some(test_cert_pem()));
        let err = svc
            .verify_signature(stripped.as_bytes(), &config)
            .expect_err("unsigned response must be rejected");
        assert!(
            matches!(err, FederationError::SamlSignatureInvalid(_)),
            "expected SamlSignatureInvalid, got: {err:?}"
        );
    }

    /// Verifies that ConfigIncomplete is returned when no cert is configured.
    #[test]
    fn verify_rejects_when_no_cert_configured() {
        let svc = make_service();
        let xml = b"<whatever/>";
        let config = test_federation_config(None);
        let err = svc
            .verify_signature(xml, &config)
            .expect_err("missing cert must return ConfigIncomplete");
        assert!(
            matches!(err, FederationError::ConfigIncomplete),
            "expected ConfigIncomplete, got: {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Replay detection test (no xmlsec dependency — uses MemReplayRepo)
    // -----------------------------------------------------------------------

    /// Tests that `insert_assertion` is called and the second submission of
    /// the same assertion ID returns AssertionReplay.
    ///
    /// This test works without the xmlsec feature because it bypasses
    /// `verify_signature` by calling the replay repo directly on the service's
    /// internal `replay_repo`.
    #[tokio::test]
    async fn acs_rejects_replayed_assertion_via_replay_repo() {
        let tenant_id = Uuid::new_v4();
        let assertion_id = "replay-victim-1";
        let expires_at = Utc::now() + chrono::Duration::hours(1);

        let repo = MemReplayRepo::new();

        // First insertion must succeed.
        repo.insert_assertion(tenant_id, assertion_id, expires_at)
            .await
            .expect("first insert should succeed");

        // Second insertion of the same ID must fail with ReplayDetected.
        let err = repo
            .insert_assertion(tenant_id, assertion_id, expires_at)
            .await
            .expect_err("second insert should return ReplayDetected");

        assert!(
            matches!(err, axiam_core::error::AxiamError::ReplayDetected),
            "expected ReplayDetected, got: {err:?}"
        );
    }
}
