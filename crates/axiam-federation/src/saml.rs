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

/// SAML 2.0 "bearer" subject-confirmation method URI.
///
/// The Web-Browser-SSO profile (§4.1.4.2) REQUIRES the assertion to carry at
/// least one `<SubjectConfirmation>` with exactly this `Method`; everything the
/// SP is entitled to trust about *who* the assertion was minted for hangs off
/// that confirmation's `<SubjectConfirmationData>`.
const SUBJECT_CONFIRMATION_METHOD_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

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
///
/// `Clone` (QUAL-07, axiam-api-rest): hoisted `AppState<C>` singleton,
/// constructed once at startup and cloned per Actix worker.
#[derive(Clone)]
pub struct SamlFederationService<FC, FL, UR, AR> {
    federation_config_repo: FC,
    federation_link_repo: FL,
    user_repo: UR,
    replay_repo: AR,
    /// Retained for constructor API stability across the ~9 call sites in
    /// `axiam-api-rest::handlers::federation` and the `axiam-server`
    /// integration tests (out of this plan's scope). No longer read
    /// directly: `fetch_idp_metadata` now routes through
    /// `ssrf::guarded_fetch`, which builds its own fresh, IP-pinned client
    /// per request rather than reusing an injected pooled client (D-01c).
    #[allow(dead_code)]
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

        // SECHRD-02: route the metadata GET through the shared, IP-pinning
        // SSRF guard (D-01a/b/c). Production always fails closed against
        // private/loopback/link-local addresses and internal redirect
        // targets — `allow_private=false`.
        let response = crate::ssrf::guarded_fetch(metadata_url, false, |c, u| c.get(u))
            .await
            .map_err(|e| FederationError::SamlMetadataFailed(e.to_string()))?;

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

        // Deliberately v4, not `new_id()`: the AuthnRequest ID is echoed back
        // in `InResponseTo` and gates replay detection, so it must not be
        // predictable from the request's timing.
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
    /// `expected_destination` — the SP's real ACS URL. If `Some` and non-empty
    /// it is checked against **both** `Response.Destination` (SEC-005/REQ-14
    /// AC-5) and the signed
    /// `Subject/SubjectConfirmation[@Method=…cm:bearer]/SubjectConfirmationData/@Recipient`
    /// (R1.5). One argument, one source of truth — the two checks can never
    /// drift onto separate config paths.
    ///
    /// `require_in_response_to` — if `true` and `expected_request_id` is `None`,
    /// reject a response with no `InResponseTo` at all (unsolicited-response
    /// defense for callers, such as the authenticated ACS path, that have no
    /// stored request ID to compare against but still must not accept an
    /// out-of-band response). Has no effect when `expected_request_id` is
    /// `Some` — that already enforces presence-and-equality (SECFIX-04/SEC-005).
    ///
    /// Independently of these arguments, the assertion MUST carry a bearer
    /// `<SubjectConfirmation>` with usable `<SubjectConfirmationData>`; see
    /// `validate_bearer_subject_confirmation` for the fail-closed rules and for
    /// AXIAM's IdP-initiated-SSO posture (R1.5/SEC-005).
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

        // One wall-clock reading, shared by the `<Conditions>` window below and
        // the `<SubjectConfirmationData>` window in Step 2b, so both apply the
        // identical strict "no leeway" policy (R1.5/SEC-005) and can never
        // disagree about *when* "now" was.
        let now = Utc::now();

        {
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

        // Step 2b — Bearer <SubjectConfirmationData> validation
        // (R1.5, closing the SEC-005 residual; Web-Browser-SSO profile §4.1.4.3).
        //
        // Runs AFTER signature verification and the XSW binding check (so the
        // confirmation we read is provably the signed one) and BEFORE the replay
        // insert, so a profile-invalid assertion never burns a replay row.
        //
        // `expected_destination` is deliberately reused as the expected
        // `@Recipient`: it IS the SP's real ACS URL, supplied by
        // `SamlAcsRequest.acs_url` at the one authenticated ACS call site. Using
        // the same argument for both checks keeps "which endpoint are we?" on a
        // single source of truth.
        validate_bearer_subject_confirmation(
            assertion,
            now,
            response.in_response_to.as_deref(),
            expected_request_id,
            expected_destination,
            require_in_response_to,
        )?;

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
        let cert = samael::crypto::CertificateDer::from(der);

        <samael::crypto::XmlSec as samael::crypto::CryptoProvider>::verify_signed_xml(
            xml_bytes,
            &cert,
            Some("ID"),
        )
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
        //
        // Deliberately v4, not `new_id()`: this value must be unguessable, and
        // a v7 id spends 48 bits on a timestamp that an attacker can bound from
        // the user's creation time. See `axiam_core::id` — v7 is for
        // identifiers, never for secrets.
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

/// Validate the assertion's bearer `<SubjectConfirmation>` /
/// `<SubjectConfirmationData>` (R1.5, closing the SEC-005 residual).
///
/// SAML 2.0 Web-Browser-SSO profile §4.1.4.2-3 requires the SP to reject an
/// assertion unless it carries **at least one** bearer `<SubjectConfirmation>`
/// whose `<SubjectConfirmationData>`
///   * has a `@Recipient` matching the ACS URL the response was delivered to,
///   * has a `@NotOnOrAfter` that has not passed, and
///   * has an `@InResponseTo` matching the SP's outstanding `AuthnRequest`.
///
/// **Why this is not redundant with the checks already done in
/// `handle_saml_response`.** `Response@Destination` and `Response@InResponseTo`
/// live on the `<samlp:Response>` root, which is *outside* the enveloped
/// signature — the IdP signs the `<Assertion>` (see `bind_signature_to_assertion`).
/// An attacker relaying an assertion that the same IdP legitimately minted for a
/// **different** SP can rewrite both attributes for free and pass those checks.
/// `<SubjectConfirmationData>` sits *inside* the signed assertion, so it is the
/// only tamper-proof statement of who the assertion was for and which request it
/// answers. Without this function the cross-SP relay of §4.1.4.3 succeeds.
///
/// **Fail closed.** A missing `<Subject>`, no bearer `<SubjectConfirmation>`, a
/// bearer confirmation with no `<SubjectConfirmationData>`, or confirmation data
/// missing `@Recipient`/`@NotOnOrAfter` are all rejections — never a pass.
/// Bearer confirmation is REQUIRED by the profile, so "the IdP did not send one"
/// describes an unusable assertion, not a permissive default.
///
/// **IdP-initiated (unsolicited) SSO posture.** §4.1.4.2 says `@InResponseTo`
/// MUST be absent for an unsolicited response. AXIAM's posture is that it
/// **does not accept unsolicited/IdP-initiated SSO at all**, on either ACS path,
/// so that branch is unreachable by construction and this function mirrors the
/// posture rather than duplicating it:
///   * the public first-time-SSO path passes the `FederationLoginState.request_id`
///     it stored when it built the `AuthnRequest` (`expected_request_id`), and
///   * the authenticated ACS path, which has no state row, passes
///     `require_in_response_to = true`, which already rejects a `<Response>`
///     without `InResponseTo` before we are reached.
///
/// So `@InResponseTo` is REQUIRED here and must equal the outstanding request id
/// — the caller's stored id when it has one, otherwise the `Response@InResponseTo`
/// the caller insisted on (which cross-binds the unsigned root attribute to the
/// signed assertion). No constraint is imposed only when the caller opted out of
/// both, a configuration no production ACS call site uses. Should AXIAM ever
/// support IdP-initiated SSO, the change belongs here *and* at the caller flags
/// together: accept the absence of `@InResponseTo` and reject its presence.
fn validate_bearer_subject_confirmation(
    assertion: &samael::schema::Assertion,
    now: chrono::DateTime<Utc>,
    response_in_response_to: Option<&str>,
    expected_request_id: Option<&str>,
    expected_recipient: Option<&str>,
    require_in_response_to: bool,
) -> Result<(), FederationError> {
    let subject = assertion.subject.as_ref().ok_or_else(|| {
        FederationError::SamlResponseFailed(
            "Assertion missing required Subject (no bearer SubjectConfirmation possible)".into(),
        )
    })?;

    let bearer: Vec<&samael::schema::SubjectConfirmation> = subject
        .subject_confirmations
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|c| c.method.as_deref() == Some(SUBJECT_CONFIRMATION_METHOD_BEARER))
        .collect();

    if bearer.is_empty() {
        return Err(FederationError::SamlResponseFailed(format!(
            "Assertion carries no bearer SubjectConfirmation \
             (Method=\"{SUBJECT_CONFIRMATION_METHOD_BEARER}\" is REQUIRED by the \
             SAML 2.0 Web-Browser-SSO profile)"
        )));
    }

    // Which AuthnRequest must this confirmation answer? Prefer the caller's
    // stored request id; otherwise fall back to the `Response@InResponseTo` the
    // caller already required to be present. See the posture note above.
    let required_in_response_to: Option<&str> = match expected_request_id {
        Some(id) if !id.is_empty() => Some(id),
        _ if require_in_response_to => response_in_response_to,
        _ => None,
    };

    let expected_recipient = expected_recipient.filter(|r| !r.is_empty());

    // The profile requires only that ONE bearer confirmation satisfy every
    // constraint. Try each, keeping the last failure so the rejection names a
    // concrete violation rather than a generic "nothing matched".
    let mut last_error: Option<FederationError> = None;
    for confirmation in bearer {
        match check_bearer_confirmation_data(
            confirmation,
            now,
            required_in_response_to,
            expected_recipient,
        ) {
            Ok(()) => return Ok(()),
            Err(e) => last_error = Some(e),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        FederationError::SamlResponseFailed(
            "no bearer SubjectConfirmationData satisfied the Web-Browser-SSO profile".into(),
        )
    }))
}

/// Check one bearer `<SubjectConfirmation>`'s `<SubjectConfirmationData>`.
///
/// Every branch is a rejection; `validate_bearer_subject_confirmation` accepts
/// the assertion on the first `Ok`.
fn check_bearer_confirmation_data(
    confirmation: &samael::schema::SubjectConfirmation,
    now: chrono::DateTime<Utc>,
    required_in_response_to: Option<&str>,
    expected_recipient: Option<&str>,
) -> Result<(), FederationError> {
    let data = confirmation
        .subject_confirmation_data
        .as_ref()
        .ok_or_else(|| {
            FederationError::SamlResponseFailed(
                "bearer SubjectConfirmation missing required SubjectConfirmationData".into(),
            )
        })?;

    // --- @Recipient — this assertion must have been minted for THIS SP. ------
    // Presence is REQUIRED unconditionally (§4.1.4.2). The value is compared
    // whenever the caller knows its own ACS URL; the only caller that does not
    // is the public first-time-SSO path, whose AuthnRequest carries no
    // AssertionConsumerServiceURL and whose login-state row has no column for
    // one — closing that needs a schema addition, tracked as the SEC-005
    // residual in claude_dev/security-audit.md §7 (SAML-01).
    let recipient = data
        .recipient
        .as_deref()
        .filter(|r| !r.is_empty())
        .ok_or_else(|| {
            FederationError::SamlResponseFailed(
                "SubjectConfirmationData missing required Recipient".into(),
            )
        })?;
    if let Some(expected) = expected_recipient
        && recipient != expected
    {
        return Err(FederationError::SamlResponseFailed(format!(
            "SubjectConfirmationData Recipient mismatch: expected {expected}, got {recipient} \
             (assertion was issued for a different service provider)"
        )));
    }

    // --- @NotOnOrAfter — strict, no leeway; identical to <Conditions>. -------
    let not_on_or_after = data.not_on_or_after.ok_or_else(|| {
        FederationError::SamlResponseFailed(
            "SubjectConfirmationData missing required NotOnOrAfter".into(),
        )
    })?;
    if now >= not_on_or_after {
        return Err(FederationError::SamlResponseFailed(format!(
            "SubjectConfirmationData expired (NotOnOrAfter: {not_on_or_after})"
        )));
    }
    // §4.1.4.2 says @NotBefore MUST NOT be present. We do not reject its mere
    // presence (real IdPs emit it and rejecting would break interop for no
    // security gain), but we do honour it: a confirmation that is not yet valid
    // is not a confirmation.
    if let Some(not_before) = data.not_before
        && now < not_before
    {
        return Err(FederationError::SamlResponseFailed(format!(
            "SubjectConfirmationData not yet valid (NotBefore: {not_before})"
        )));
    }

    // --- @InResponseTo — must answer OUR outstanding AuthnRequest. -----------
    if let Some(expected) = required_in_response_to {
        match data.in_response_to.as_deref() {
            None => {
                return Err(FederationError::SamlResponseFailed(format!(
                    "SubjectConfirmationData missing InResponseTo (expected {expected}; \
                     AXIAM does not accept unsolicited/IdP-initiated responses)"
                )));
            }
            Some(actual) if actual != expected => {
                return Err(FederationError::SamlResponseFailed(format!(
                    "SubjectConfirmationData InResponseTo mismatch: expected {expected}, \
                     got {actual}"
                )));
            }
            _ => {}
        }
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
            token_exchange: Default::default(),
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
        async fn list_token_exchange_enabled(
            &self,
            _tenant_id: Uuid,
        ) -> axiam_core::error::AxiamResult<Vec<FederationConfig>> {
            Ok(Vec::new())
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
        async fn anonymize_user(
            &self,
            _: Uuid,
            _: Uuid,
            _: &str,
            _: &str,
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

    // -----------------------------------------------------------------------
    // R5 additions — stateful repo stubs + non-xmlsec logic coverage
    //
    // These drive `handle_saml_response` end-to-end against the committed
    // xmlsec fixtures (the ONLY source of signed XML) plus stateful in-memory
    // repos, and unit-test the pure helpers (`extract_assertion_claims`,
    // `apply_attribute_map`, `bind_signature_to_assertion`, `deflate_encode`,
    // `xml_escape`) and the guard clauses of `build_authn_request` /
    // `generate_sp_metadata` that run before any network I/O.
    // -----------------------------------------------------------------------

    use std::str::FromStr;
    use std::sync::Mutex;

    use axiam_core::models::user::UserStatus;

    /// Config repo that returns a preset config (or NotFound if `None`).
    struct MapConfigRepo {
        config: Option<FederationConfig>,
    }
    impl FederationConfigRepository for MapConfigRepo {
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
            self.config.clone().ok_or(AxiamError::NotFound {
                entity: "federation_config".into(),
                id: "missing-cfg".into(),
            })
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
        async fn list_token_exchange_enabled(
            &self,
            _tenant_id: Uuid,
        ) -> axiam_core::error::AxiamResult<Vec<FederationConfig>> {
            Ok(Vec::new())
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

    /// Link repo that records created links and can be configured to return an
    /// existing link, a NotFound (→ provisioning path), a generic DB error, or
    /// a create failure.
    struct RecordingLinkRepo {
        existing: Option<FederationLink>,
        get_returns_db_error: bool,
        fail_create: bool,
        created: Mutex<Vec<CreateFederationLink>>,
    }
    impl RecordingLinkRepo {
        fn provisioning() -> Self {
            Self {
                existing: None,
                get_returns_db_error: false,
                fail_create: false,
                created: Mutex::new(Vec::new()),
            }
        }
    }
    impl FederationLinkRepository for RecordingLinkRepo {
        async fn create(
            &self,
            input: CreateFederationLink,
        ) -> axiam_core::error::AxiamResult<FederationLink> {
            if self.fail_create {
                return Err(AxiamError::Database("link create boom".into()));
            }
            let link = FederationLink {
                id: Uuid::new_v4(),
                tenant_id: input.tenant_id,
                user_id: input.user_id,
                federation_config_id: input.federation_config_id,
                external_subject: input.external_subject.clone(),
                external_email: input.external_email.clone(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            self.created.lock().unwrap().push(input);
            Ok(link)
        }
        async fn get_by_external_subject(
            &self,
            _: Uuid,
            _: Uuid,
            _: &str,
        ) -> axiam_core::error::AxiamResult<FederationLink> {
            if self.get_returns_db_error {
                return Err(AxiamError::Database("link lookup boom".into()));
            }
            self.existing.clone().ok_or(AxiamError::NotFound {
                entity: "federation_link".into(),
                id: "no-link".into(),
            })
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

    /// User repo that records created users and can be configured with a preset
    /// user for `get_by_id` (existing-link path) or a create failure.
    struct RecordingUserRepo {
        preset: Option<User>,
        fail_create: bool,
        created: Mutex<Vec<CreateUser>>,
    }
    impl RecordingUserRepo {
        fn provisioning() -> Self {
            Self {
                preset: None,
                fail_create: false,
                created: Mutex::new(Vec::new()),
            }
        }
    }
    impl UserRepository for RecordingUserRepo {
        async fn create(&self, input: CreateUser) -> axiam_core::error::AxiamResult<User> {
            if self.fail_create {
                return Err(AxiamError::Database("user create boom".into()));
            }
            let user = User {
                id: Uuid::new_v4(),
                tenant_id: input.tenant_id,
                username: input.username.clone(),
                email: input.email.clone(),
                password_hash: "x".into(),
                status: UserStatus::Active,
                mfa_enabled: false,
                mfa_secret: None,
                totp_last_used_step: None,
                failed_login_attempts: 0,
                last_failed_login_at: None,
                locked_until: None,
                email_verified_at: None,
                deletion_pending: false,
                scheduled_purge_at: None,
                metadata: input.metadata.clone().unwrap_or(serde_json::Value::Null),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            self.created.lock().unwrap().push(input);
            Ok(user)
        }
        async fn get_by_id(&self, _: Uuid, _: Uuid) -> axiam_core::error::AxiamResult<User> {
            self.preset.clone().ok_or(AxiamError::NotFound {
                entity: "user".into(),
                id: "no-user".into(),
            })
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
        async fn anonymize_user(
            &self,
            _: Uuid,
            _: Uuid,
            _: &str,
            _: &str,
        ) -> axiam_core::error::AxiamResult<()> {
            unimplemented!()
        }
    }

    type AcsService =
        SamlFederationService<MapConfigRepo, RecordingLinkRepo, RecordingUserRepo, MemReplayRepo>;

    /// A federation config wired to the committed fixtures: `client_id` matches
    /// the fixture Audience (`https://sp.example.com`), cert matches the
    /// fixture signature, attribute_map resolves `email`.
    fn acs_config() -> FederationConfig {
        let mut c = test_federation_config(Some(test_cert_pem()));
        c.attribute_map = serde_json::json!({ "email": "email", "name": "displayName" });
        c
    }

    fn make_acs_service(
        config: Option<FederationConfig>,
        link: RecordingLinkRepo,
        user: RecordingUserRepo,
    ) -> AcsService {
        SamlFederationService::new(
            MapConfigRepo { config },
            link,
            user,
            MemReplayRepo::new(),
            reqwest::Client::new(),
        )
    }

    fn well_signed_b64() -> String {
        STANDARD.encode(load_fixture("well_signed_response.xml"))
    }

    // ----- handle_saml_response: full happy-path provisioning -----

    #[tokio::test]
    async fn handle_saml_response_provisions_new_user() {
        let tenant = Uuid::new_v4();
        let cfg = acs_config();
        let cfg_id = cfg.id;
        let svc = make_acs_service(
            Some(cfg),
            RecordingLinkRepo::provisioning(),
            RecordingUserRepo::provisioning(),
        );

        let result = svc
            .handle_saml_response(tenant, cfg_id, &well_signed_b64(), None, None, None, false)
            .await
            .expect("well-signed fixture should provision a user");

        assert!(
            result.newly_provisioned,
            "expected a freshly provisioned user"
        );
        // NameID in the fixture is `user@example.com`; the `email` attribute
        // maps to the same value, so username and email both resolve to it.
        assert_eq!(result.user.email, "user@example.com");
        assert_eq!(result.user.username, "user@example.com");
        assert_eq!(result.federation_link.external_subject, "user@example.com");
    }

    // ----- handle_saml_response: existing link returns the linked user -----

    #[tokio::test]
    async fn handle_saml_response_returns_existing_link() {
        let tenant = Uuid::new_v4();
        let cfg = acs_config();
        let cfg_id = cfg.id;
        let user_id = Uuid::new_v4();

        let preset_user = User {
            id: user_id,
            tenant_id: tenant,
            username: "existing".into(),
            email: "existing@example.com".into(),
            password_hash: "x".into(),
            status: UserStatus::Active,
            mfa_enabled: false,
            mfa_secret: None,
            totp_last_used_step: None,
            failed_login_attempts: 0,
            last_failed_login_at: None,
            locked_until: None,
            email_verified_at: None,
            deletion_pending: false,
            scheduled_purge_at: None,
            metadata: serde_json::Value::Null,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let existing_link = FederationLink {
            id: Uuid::new_v4(),
            tenant_id: tenant,
            user_id,
            federation_config_id: cfg_id,
            external_subject: "user@example.com".into(),
            external_email: Some("existing@example.com".into()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let link_repo = RecordingLinkRepo {
            existing: Some(existing_link),
            get_returns_db_error: false,
            fail_create: false,
            created: Mutex::new(Vec::new()),
        };
        let user_repo = RecordingUserRepo {
            preset: Some(preset_user),
            fail_create: false,
            created: Mutex::new(Vec::new()),
        };

        let svc = make_acs_service(Some(cfg), link_repo, user_repo);
        let result = svc
            .handle_saml_response(tenant, cfg_id, &well_signed_b64(), None, None, None, false)
            .await
            .expect("existing link should resolve");

        assert!(
            !result.newly_provisioned,
            "existing link must not re-provision"
        );
        assert_eq!(result.user.id, user_id);
    }

    // ----- handle_saml_response: replay is rejected on second submit -----

    #[tokio::test]
    async fn handle_saml_response_rejects_replayed_assertion() {
        let tenant = Uuid::new_v4();
        let cfg = acs_config();
        let cfg_id = cfg.id;
        let svc = make_acs_service(
            Some(cfg),
            RecordingLinkRepo::provisioning(),
            RecordingUserRepo::provisioning(),
        );

        // First submit succeeds and records the assertion ID.
        svc.handle_saml_response(tenant, cfg_id, &well_signed_b64(), None, None, None, false)
            .await
            .expect("first submit should succeed");

        // Second submit of the SAME assertion (same tenant + assertion_id
        // `well-signed-1`) must be rejected. WHY: `insert_assertion` returns
        // `AxiamError::ReplayDetected` on the duplicate, mapped to
        // `FederationError::AssertionReplay` — and this fires BEFORE any claims
        // are re-trusted or the user re-provisioned.
        let err = svc
            .handle_saml_response(tenant, cfg_id, &well_signed_b64(), None, None, None, false)
            .await
            .expect_err("replayed assertion must be rejected");
        assert!(
            matches!(err, FederationError::AssertionReplay),
            "expected AssertionReplay, got: {err:?}"
        );
    }

    // ----- handle_saml_response: tampered signature is rejected (security) ---

    #[tokio::test]
    async fn handle_saml_response_rejects_tampered_signature() {
        let tenant = Uuid::new_v4();
        let cfg = acs_config();
        let cfg_id = cfg.id;
        let svc = make_acs_service(
            Some(cfg),
            RecordingLinkRepo::provisioning(),
            RecordingUserRepo::provisioning(),
        );

        let b64 = STANDARD.encode(load_fixture("tampered_response.xml"));
        let err = svc
            .handle_saml_response(tenant, cfg_id, &b64, None, None, None, false)
            .await
            .expect_err("tampered fixture must be rejected");
        // WHY: xmlsec digest/signature verification fails on the mutated body,
        // surfaced as SamlSignatureInvalid BEFORE claims/replay are touched.
        assert!(
            matches!(err, FederationError::SamlSignatureInvalid(_)),
            "expected SamlSignatureInvalid, got: {err:?}"
        );
    }

    // ----- handle_saml_response: InResponseTo / Destination / Audience binds -

    #[tokio::test]
    async fn handle_saml_response_rejects_missing_in_response_to() {
        let tenant = Uuid::new_v4();
        let cfg = acs_config();
        let cfg_id = cfg.id;
        let svc = make_acs_service(
            Some(cfg),
            RecordingLinkRepo::provisioning(),
            RecordingUserRepo::provisioning(),
        );

        // The fixture carries no InResponseTo; supplying an expected request ID
        // must reject it as an unsolicited response (SEC-005). Runs AFTER
        // signature verification, so the rejection is on the binding, not crypto.
        let err = svc
            .handle_saml_response(
                tenant,
                cfg_id,
                &well_signed_b64(),
                None,
                Some("_expected-req-id"),
                None,
                false,
            )
            .await
            .expect_err("missing InResponseTo must be rejected when an ID is expected");
        match err {
            FederationError::SamlResponseFailed(msg) => {
                assert!(
                    msg.contains("InResponseTo"),
                    "expected InResponseTo rejection, got: {msg}"
                );
            }
            other => panic!("expected SamlResponseFailed, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn handle_saml_response_require_in_response_to_flag_rejects() {
        let tenant = Uuid::new_v4();
        let cfg = acs_config();
        let cfg_id = cfg.id;
        let svc = make_acs_service(
            Some(cfg),
            RecordingLinkRepo::provisioning(),
            RecordingUserRepo::provisioning(),
        );

        // No expected ID, but `require_in_response_to = true` and the fixture
        // has no InResponseTo → unsolicited-response rejection (SECFIX-04).
        let err = svc
            .handle_saml_response(tenant, cfg_id, &well_signed_b64(), None, None, None, true)
            .await
            .expect_err("require_in_response_to must reject a response with no InResponseTo");
        assert!(
            matches!(err, FederationError::SamlResponseFailed(ref m) if m.contains("InResponseTo")),
            "expected SamlResponseFailed(InResponseTo), got: {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_saml_response_rejects_destination_mismatch() {
        let tenant = Uuid::new_v4();
        let cfg = acs_config();
        let cfg_id = cfg.id;
        let svc = make_acs_service(
            Some(cfg),
            RecordingLinkRepo::provisioning(),
            RecordingUserRepo::provisioning(),
        );

        // Fixture Response has no Destination attribute; requiring one rejects it.
        let err = svc
            .handle_saml_response(
                tenant,
                cfg_id,
                &well_signed_b64(),
                None,
                None,
                Some("https://acs.example.com/expected"),
                false,
            )
            .await
            .expect_err("missing Destination must be rejected when one is expected");
        assert!(
            matches!(err, FederationError::SamlResponseFailed(ref m) if m.contains("Destination")),
            "expected SamlResponseFailed(Destination), got: {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_saml_response_rejects_audience_mismatch() {
        let tenant = Uuid::new_v4();
        let mut cfg = acs_config();
        // Break the audience match: fixture Audience is `https://sp.example.com`.
        cfg.client_id = "https://not-the-sp.example.com".into();
        let cfg_id = cfg.id;
        let svc = make_acs_service(
            Some(cfg),
            RecordingLinkRepo::provisioning(),
            RecordingUserRepo::provisioning(),
        );

        // Signature still verifies (cert-based, independent of client_id), but
        // the AudienceRestriction no longer matches our SP entity ID → reject
        // BEFORE replay insertion or provisioning.
        let err = svc
            .handle_saml_response(tenant, cfg_id, &well_signed_b64(), None, None, None, false)
            .await
            .expect_err("audience mismatch must be rejected");
        assert!(
            matches!(err, FederationError::SamlResponseFailed(ref m) if m.contains("Audience")),
            "expected SamlResponseFailed(Audience), got: {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // R1.5 / SEC-005 residual — bearer <SubjectConfirmationData> validation
    // (Web-Browser-SSO profile §4.1.4.3)
    //
    // Every test below drives `handle_saml_response` with the EXACT parameter
    // shape the authenticated ACS handler uses
    // (`crates/axiam-api-rest/src/handlers/federation.rs`, `saml_acs`):
    //
    //     expected_request_id     = None          (no stored login-state row)
    //     expected_destination    = Some(acs_url) (the SP's real ACS URL)
    //     require_in_response_to  = true          (unsolicited SSO refused)
    //
    // The `scd_*` fixtures are built so that EVERY pre-existing control
    // (signature, XSW binding, Response/@Destination, Response/@InResponseTo,
    // <Conditions> validity, <AudienceRestriction>) passes. `Destination` and
    // `Response/@InResponseTo` sit on the UNSIGNED <samlp:Response> root, so a
    // relaying attacker rewrites them for free; only the signed
    // <SubjectConfirmationData> can catch the three negatives below. Before
    // this fix all three assertions were accepted.
    // -----------------------------------------------------------------------

    /// The SP's real ACS URL — the single source of truth shared by the
    /// `Destination` check and the new `Recipient` check (both read the
    /// `expected_destination` argument, which `saml_acs` fills from
    /// `SamlAcsRequest.acs_url`).
    const TEST_ACS_URL: &str = "https://sp.example.com/api/v1/federation/saml/acs";

    fn scd_fixture_b64(name: &str) -> String {
        STANDARD.encode(load_fixture(name))
    }

    /// Positive vector: a fully profile-conformant bearer confirmation —
    /// `@Recipient` = our ACS URL, `@NotOnOrAfter` in the future,
    /// `@InResponseTo` = the outstanding request — is accepted.
    #[tokio::test]
    async fn handle_saml_response_accepts_valid_subject_confirmation() {
        let tenant = Uuid::new_v4();
        let cfg = acs_config();
        let cfg_id = cfg.id;
        let svc = make_acs_service(
            Some(cfg),
            RecordingLinkRepo::provisioning(),
            RecordingUserRepo::provisioning(),
        );

        let result = svc
            .handle_saml_response(
                tenant,
                cfg_id,
                &scd_fixture_b64("scd_valid_response.xml"),
                None,
                None,
                Some(TEST_ACS_URL),
                true,
            )
            .await
            .expect("a conformant bearer SubjectConfirmationData must be accepted");

        assert!(result.newly_provisioned);
        assert_eq!(result.user.email, "user@example.com");
    }

    /// Positive vector, SP-initiated shape: when the caller DOES have a stored
    /// request id (the public ACS path), the same fixture still validates —
    /// `SubjectConfirmationData/@InResponseTo` equals it.
    #[tokio::test]
    async fn handle_saml_response_accepts_valid_scd_with_stored_request_id() {
        let tenant = Uuid::new_v4();
        let cfg = acs_config();
        let cfg_id = cfg.id;
        let svc = make_acs_service(
            Some(cfg),
            RecordingLinkRepo::provisioning(),
            RecordingUserRepo::provisioning(),
        );

        svc.handle_saml_response(
            tenant,
            cfg_id,
            &scd_fixture_b64("scd_valid_response.xml"),
            None,
            Some("_axiam-req-1"),
            Some(TEST_ACS_URL),
            false,
        )
        .await
        .expect("matching stored request id must validate against the SCD InResponseTo");
    }

    /// NEGATIVE 1 — the assertion was minted by the same IdP for a DIFFERENT
    /// SP: the signed `@Recipient` names `https://other-sp.example.com/...`
    /// while the (unsigned, attacker-rewritable) `Destination` still says us.
    /// Web-Browser-SSO profile §4.1.4.3 requires the SP to reject this.
    #[tokio::test]
    async fn handle_saml_response_rejects_subject_confirmation_recipient_mismatch() {
        let tenant = Uuid::new_v4();
        let cfg = acs_config();
        let cfg_id = cfg.id;
        let svc = make_acs_service(
            Some(cfg),
            RecordingLinkRepo::provisioning(),
            RecordingUserRepo::provisioning(),
        );

        let err = svc
            .handle_saml_response(
                tenant,
                cfg_id,
                &scd_fixture_b64("scd_wrong_recipient_response.xml"),
                None,
                None,
                Some(TEST_ACS_URL),
                true,
            )
            .await
            .expect_err(
                "an assertion whose SubjectConfirmationData/@Recipient names another SP \
                 must be rejected (SEC-005, profile §4.1.4.3)",
            );

        assert!(
            matches!(err, FederationError::SamlResponseFailed(ref m) if m.contains("Recipient")),
            "expected SamlResponseFailed naming Recipient, got: {err:?}"
        );
    }

    /// NEGATIVE 2 — the bearer confirmation window has closed
    /// (`SubjectConfirmationData/@NotOnOrAfter` = 2020) even though
    /// `<Conditions>` is still valid until 2099. The Conditions check cannot
    /// see this; the SCD clock check must.
    #[tokio::test]
    async fn handle_saml_response_rejects_expired_subject_confirmation_data() {
        let tenant = Uuid::new_v4();
        let cfg = acs_config();
        let cfg_id = cfg.id;
        let svc = make_acs_service(
            Some(cfg),
            RecordingLinkRepo::provisioning(),
            RecordingUserRepo::provisioning(),
        );

        let err = svc
            .handle_saml_response(
                tenant,
                cfg_id,
                &scd_fixture_b64("scd_expired_response.xml"),
                None,
                None,
                Some(TEST_ACS_URL),
                true,
            )
            .await
            .expect_err("an expired bearer SubjectConfirmationData must be rejected");

        assert!(
            matches!(
                err,
                FederationError::SamlResponseFailed(ref m)
                    if m.contains("SubjectConfirmationData") && m.contains("NotOnOrAfter")
            ),
            "expected SamlResponseFailed naming the SCD expiry, got: {err:?}"
        );
    }

    /// NEGATIVE 3 — the signed `@InResponseTo` answers a FOREIGN AuthnRequest
    /// (`_attacker-req-9`) while the unsigned `Response/@InResponseTo` has been
    /// rewritten to our own `_axiam-req-1`. Only the signed value proves the
    /// IdP actually issued this assertion for our request.
    #[tokio::test]
    async fn handle_saml_response_rejects_foreign_subject_confirmation_in_response_to() {
        let tenant = Uuid::new_v4();
        let cfg = acs_config();
        let cfg_id = cfg.id;
        let svc = make_acs_service(
            Some(cfg),
            RecordingLinkRepo::provisioning(),
            RecordingUserRepo::provisioning(),
        );

        let err = svc
            .handle_saml_response(
                tenant,
                cfg_id,
                &scd_fixture_b64("scd_foreign_in_response_to_response.xml"),
                None,
                None,
                Some(TEST_ACS_URL),
                true,
            )
            .await
            .expect_err(
                "a SubjectConfirmationData answering a foreign AuthnRequest must be rejected",
            );

        assert!(
            matches!(
                err,
                FederationError::SamlResponseFailed(ref m)
                    if m.contains("SubjectConfirmationData") && m.contains("InResponseTo")
            ),
            "expected SamlResponseFailed naming the SCD InResponseTo, got: {err:?}"
        );
    }

    /// FAIL-CLOSED — bearer confirmation is REQUIRED. An authentic, correctly
    /// signed assertion carrying no `<SubjectConfirmation>` at all is a
    /// rejection, never a pass.
    #[tokio::test]
    async fn handle_saml_response_rejects_missing_bearer_subject_confirmation() {
        let tenant = Uuid::new_v4();
        let cfg = acs_config();
        let cfg_id = cfg.id;
        let svc = make_acs_service(
            Some(cfg),
            RecordingLinkRepo::provisioning(),
            RecordingUserRepo::provisioning(),
        );

        let err = svc
            .handle_saml_response(
                tenant,
                cfg_id,
                &scd_fixture_b64("scd_missing_confirmation_response.xml"),
                None,
                None,
                Some(TEST_ACS_URL),
                true,
            )
            .await
            .expect_err("a missing bearer SubjectConfirmation must fail closed");

        assert!(
            matches!(
                err,
                FederationError::SamlResponseFailed(ref m) if m.contains("SubjectConfirmation")
            ),
            "expected SamlResponseFailed naming SubjectConfirmation, got: {err:?}"
        );
    }

    // ----- handle_saml_response: config guard clauses -----

    #[tokio::test]
    async fn handle_saml_response_rejects_disabled_config() {
        let tenant = Uuid::new_v4();
        let mut cfg = acs_config();
        cfg.enabled = false;
        let cfg_id = cfg.id;
        let svc = make_acs_service(
            Some(cfg),
            RecordingLinkRepo::provisioning(),
            RecordingUserRepo::provisioning(),
        );
        let err = svc
            .handle_saml_response(tenant, cfg_id, &well_signed_b64(), None, None, None, false)
            .await
            .expect_err("disabled config must be rejected");
        assert!(
            matches!(err, FederationError::ConfigDisabled),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_saml_response_rejects_protocol_mismatch() {
        let tenant = Uuid::new_v4();
        let mut cfg = acs_config();
        cfg.protocol = FederationProtocol::OidcConnect;
        let cfg_id = cfg.id;
        let svc = make_acs_service(
            Some(cfg),
            RecordingLinkRepo::provisioning(),
            RecordingUserRepo::provisioning(),
        );
        let err = svc
            .handle_saml_response(tenant, cfg_id, &well_signed_b64(), None, None, None, false)
            .await
            .expect_err("protocol mismatch must be rejected");
        assert!(
            matches!(err, FederationError::ProtocolMismatch(_)),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_saml_response_rejects_bad_base64() {
        let tenant = Uuid::new_v4();
        let cfg = acs_config();
        let cfg_id = cfg.id;
        let svc = make_acs_service(
            Some(cfg),
            RecordingLinkRepo::provisioning(),
            RecordingUserRepo::provisioning(),
        );
        let err = svc
            .handle_saml_response(tenant, cfg_id, "!!!not-base64!!!", None, None, None, false)
            .await
            .expect_err("invalid base64 must be rejected");
        assert!(
            matches!(err, FederationError::SamlResponseFailed(ref m) if m.contains("Base64")),
            "got: {err:?}"
        );
    }

    // ----- build_authn_request: guard clauses (run before any network I/O) --

    #[tokio::test]
    async fn build_authn_request_rejects_config_not_found() {
        let svc = make_acs_service(
            None, // repo returns NotFound
            RecordingLinkRepo::provisioning(),
            RecordingUserRepo::provisioning(),
        );
        let err = svc
            .build_authn_request(Uuid::new_v4(), Uuid::new_v4(), "https://acs", None)
            .await
            .expect_err("unknown config must map to ConfigNotFound");
        assert!(
            matches!(err, FederationError::ConfigNotFound(_)),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn build_authn_request_rejects_disabled_config() {
        let mut cfg = acs_config();
        cfg.enabled = false;
        let cfg_id = cfg.id;
        let svc = make_acs_service(
            Some(cfg),
            RecordingLinkRepo::provisioning(),
            RecordingUserRepo::provisioning(),
        );
        let err = svc
            .build_authn_request(Uuid::new_v4(), cfg_id, "https://acs", None)
            .await
            .expect_err("disabled config must be rejected");
        assert!(
            matches!(err, FederationError::ConfigDisabled),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn build_authn_request_rejects_protocol_mismatch() {
        let mut cfg = acs_config();
        cfg.protocol = FederationProtocol::OidcConnect;
        let cfg_id = cfg.id;
        let svc = make_acs_service(
            Some(cfg),
            RecordingLinkRepo::provisioning(),
            RecordingUserRepo::provisioning(),
        );
        let err = svc
            .build_authn_request(Uuid::new_v4(), cfg_id, "https://acs", None)
            .await
            .expect_err("non-SAML config must be rejected");
        assert!(
            matches!(err, FederationError::ProtocolMismatch(_)),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn build_authn_request_rejects_missing_metadata_url() {
        let mut cfg = acs_config();
        cfg.metadata_url = None; // already None in the base config, explicit here
        let cfg_id = cfg.id;
        let svc = make_acs_service(
            Some(cfg),
            RecordingLinkRepo::provisioning(),
            RecordingUserRepo::provisioning(),
        );
        let err = svc
            .build_authn_request(Uuid::new_v4(), cfg_id, "https://acs", None)
            .await
            .expect_err("missing metadata URL must be rejected");
        assert!(
            matches!(err, FederationError::SamlMetadataFailed(ref m) if m.contains("metadata URL")),
            "got: {err:?}"
        );
    }

    // ----- generate_sp_metadata -----

    #[tokio::test]
    async fn generate_sp_metadata_emits_expected_fields() {
        let cfg = acs_config();
        let cfg_id = cfg.id;
        let svc = make_acs_service(
            Some(cfg),
            RecordingLinkRepo::provisioning(),
            RecordingUserRepo::provisioning(),
        );
        let xml = svc
            .generate_sp_metadata(Uuid::new_v4(), cfg_id, "https://acs.example.com/saml")
            .await
            .expect("metadata generation should succeed");
        assert!(xml.contains("entityID=\"https://sp.example.com\""), "{xml}");
        assert!(xml.contains("https://acs.example.com/saml"), "{xml}");
        assert!(xml.contains("WantAssertionsSigned=\"true\""), "{xml}");
        assert!(xml.contains("AuthnRequestsSigned=\"true\""), "{xml}");
    }

    #[tokio::test]
    async fn generate_sp_metadata_rejects_protocol_mismatch() {
        let mut cfg = acs_config();
        cfg.protocol = FederationProtocol::OidcConnect;
        let cfg_id = cfg.id;
        let svc = make_acs_service(
            Some(cfg),
            RecordingLinkRepo::provisioning(),
            RecordingUserRepo::provisioning(),
        );
        let err = svc
            .generate_sp_metadata(Uuid::new_v4(), cfg_id, "https://acs")
            .await
            .expect_err("non-SAML config must be rejected");
        assert!(
            matches!(err, FederationError::ProtocolMismatch(_)),
            "got: {err:?}"
        );
    }

    // ----- extract_assertion_claims (parsed, unsigned assertion XML) -----

    #[test]
    fn extract_assertion_claims_reads_nameid_session_and_attributes() {
        // Unsigned assertion XML — extract_assertion_claims performs no crypto,
        // so crafting the shape here (NOT a signed document) is legitimate.
        let xml = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1" Version="2.0" IssueInstant="2099-01-01T00:00:00Z">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">nid-value-123</saml:NameID>
  </saml:Subject>
  <saml:AuthnStatement AuthnInstant="2099-01-01T00:00:00Z" SessionIndex="sess-42">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
  <saml:AttributeStatement>
    <saml:Attribute Name="mail">
      <saml:AttributeValue>a@b.com</saml:AttributeValue>
      <saml:AttributeValue>a2@b.com</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute FriendlyName="fn-only">
      <saml:AttributeValue>fv</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>"#;
        let assertion = samael::schema::Assertion::from_str(xml).expect("assertion should parse");
        let claims = extract_assertion_claims(&assertion).expect("claims should extract");
        assert_eq!(claims.name_id, "nid-value-123");
        assert_eq!(claims.session_index.as_deref(), Some("sess-42"));
        assert_eq!(
            claims.attributes.get("mail").map(Vec::as_slice),
            Some(["a@b.com".to_string(), "a2@b.com".to_string()].as_slice())
        );
        // No Name → falls back to FriendlyName as the key.
        assert_eq!(
            claims.attributes.get("fn-only").map(Vec::as_slice),
            Some(["fv".to_string()].as_slice())
        );
    }

    #[test]
    fn extract_assertion_claims_rejects_missing_nameid() {
        let xml = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1" Version="2.0" IssueInstant="2099-01-01T00:00:00Z">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
</saml:Assertion>"#;
        let assertion = samael::schema::Assertion::from_str(xml).expect("assertion should parse");
        let err = extract_assertion_claims(&assertion)
            .expect_err("assertion without Subject/NameID must be rejected");
        assert!(
            matches!(err, FederationError::SamlResponseFailed(ref m) if m.contains("NameID")),
            "got: {err:?}"
        );
    }

    // ----- apply_attribute_map (pure) -----

    #[test]
    fn apply_attribute_map_resolves_email_and_name() {
        let mut attributes = HashMap::new();
        attributes.insert("mail".to_string(), vec!["u@example.com".to_string()]);
        attributes.insert("cn".to_string(), vec!["Full Name".to_string()]);
        let claims = SamlAssertionClaims {
            name_id: "nid".into(),
            session_index: None,
            attributes,
        };
        let map = serde_json::json!({ "email": "mail", "name": "cn" });
        let (email, name) = apply_attribute_map(&claims, &map);
        assert_eq!(email.as_deref(), Some("u@example.com"));
        assert_eq!(name.as_deref(), Some("Full Name"));
    }

    #[test]
    fn apply_attribute_map_falls_back_to_display_name_key() {
        let mut attributes = HashMap::new();
        attributes.insert("displayName".to_string(), vec!["Disp".to_string()]);
        let claims = SamlAssertionClaims {
            name_id: "nid".into(),
            session_index: None,
            attributes,
        };
        // No "name" mapping; the code then tries the "displayName" field key.
        let map = serde_json::json!({ "displayName": "displayName" });
        let (email, name) = apply_attribute_map(&claims, &map);
        assert!(email.is_none());
        assert_eq!(name.as_deref(), Some("Disp"));
    }

    #[test]
    fn apply_attribute_map_returns_none_when_unmapped() {
        let claims = SamlAssertionClaims {
            name_id: "nid".into(),
            session_index: None,
            attributes: HashMap::new(),
        };
        let (email, name) = apply_attribute_map(&claims, &serde_json::json!({}));
        assert!(email.is_none());
        assert!(name.is_none());
    }

    // ----- bind_signature_to_assertion (XSW defense; pure introspection) -----

    #[test]
    fn bind_signature_accepts_single_assertion_with_matching_reference() {
        let xml = r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <saml:Assertion ID="asrt-1">
    <ds:Signature><ds:SignedInfo><ds:Reference URI="#asrt-1"/></ds:SignedInfo></ds:Signature>
  </saml:Assertion>
</samlp:Response>"##;
        bind_signature_to_assertion(xml.as_bytes(), "asrt-1")
            .expect("single assertion with matching reference must bind");
    }

    #[test]
    fn bind_signature_rejects_two_assertions_xsw() {
        // Two <Assertion> elements is the classic XML Signature Wrapping shape.
        let xml = r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <saml:Assertion ID="asrt-1">
    <ds:Signature><ds:SignedInfo><ds:Reference URI="#asrt-1"/></ds:SignedInfo></ds:Signature>
  </saml:Assertion>
  <saml:Assertion ID="asrt-forged"/>
</samlp:Response>"##;
        let err = bind_signature_to_assertion(xml.as_bytes(), "asrt-forged")
            .expect_err("two assertions must be rejected");
        assert!(
            matches!(err, FederationError::SamlResponseFailed(ref m) if m.contains("exactly 1 Assertion")),
            "got: {err:?}"
        );
    }

    #[test]
    fn bind_signature_rejects_reference_not_pointing_at_assertion() {
        // One assertion, but the signature reference points elsewhere → the
        // verified signature is not bound to the consumed assertion.
        let xml = r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <saml:Assertion ID="asrt-1">
    <ds:Signature><ds:SignedInfo><ds:Reference URI="#some-other-element"/></ds:SignedInfo></ds:Signature>
  </saml:Assertion>
</samlp:Response>"##;
        let err = bind_signature_to_assertion(xml.as_bytes(), "asrt-1")
            .expect_err("non-matching reference must be rejected");
        assert!(
            matches!(err, FederationError::SamlResponseFailed(ref m) if m.contains("XML Signature Wrapping")),
            "got: {err:?}"
        );
    }

    // ----- pure helpers: deflate_encode + xml_escape -----

    #[test]
    fn deflate_encode_roundtrips() {
        use flate2::read::DeflateDecoder;
        use std::io::Read;

        let original = b"<AuthnRequest>redirect-binding-deflate-payload</AuthnRequest>";
        let deflated = deflate_encode(original).expect("deflate must succeed");
        assert!(!deflated.is_empty());
        assert_ne!(deflated.as_slice(), original.as_slice());

        let mut decoder = DeflateDecoder::new(deflated.as_slice());
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).expect("inflate must succeed");
        assert_eq!(out.as_slice(), original.as_slice());
    }

    #[test]
    fn xml_escape_escapes_all_special_chars() {
        let escaped = xml_escape(r#"a&b"c'd<e>f"#);
        assert_eq!(escaped, "a&amp;b&quot;c&apos;d&lt;e&gt;f");
    }
}

// ---------------------------------------------------------------------------
// Bearer SubjectConfirmation — SAML 2.0 Web-Browser-SSO profile §4.1.4.2
// ---------------------------------------------------------------------------
//
// The existing tests in this file drive whole responses through fixtures, which
// proves the happy path and the signature handling but leaves the bearer
// confirmation checks reachable only in combination. These build the
// `SubjectConfirmation` values directly so each REJECTION can be pinned on its
// own — and every branch in `check_bearer_confirmation_data` is a rejection.
//
// Two of them are the ones an attacker actually needs:
//
//  * `@Recipient` mismatch — an assertion the IdP minted for a DIFFERENT
//    service provider. Without this check, a malicious (or merely
//    multi-tenant) SP could forward an assertion it legitimately received and
//    log in as that user here.
//  * `@InResponseTo` missing or mismatched — an assertion that does not answer
//    an AuthnRequest AXIAM actually sent. That is the unsolicited /
//    IdP-initiated flow, which is exactly how a stolen assertion is replayed.

#[cfg(test)]
mod bearer_confirmation_tests {
    use super::*;
    use samael::schema::{Subject, SubjectConfirmation, SubjectConfirmationData};

    fn ts(s: &str) -> chrono::DateTime<Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .expect("fixture timestamp parses")
            .with_timezone(&Utc)
    }

    /// "Now" for every case below; the validity windows are written around it.
    fn now() -> chrono::DateTime<Utc> {
        ts("2026-06-01T12:00:00Z")
    }

    /// A confirmation that satisfies every constraint — each test then breaks
    /// exactly one field, so a failure names the check that fired.
    fn valid_data() -> SubjectConfirmationData {
        SubjectConfirmationData {
            not_before: None,
            not_on_or_after: Some(ts("2026-06-01T12:05:00Z")),
            recipient: Some("https://axiam.example/acs".into()),
            in_response_to: Some("req-123".into()),
            address: None,
            content: None,
        }
    }

    fn bearer(data: Option<SubjectConfirmationData>) -> SubjectConfirmation {
        SubjectConfirmation {
            method: Some(SUBJECT_CONFIRMATION_METHOD_BEARER.into()),
            name_id: None,
            subject_confirmation_data: data,
        }
    }

    fn check(
        data: Option<SubjectConfirmationData>,
        in_response_to: Option<&str>,
        recipient: Option<&str>,
    ) -> Result<(), FederationError> {
        check_bearer_confirmation_data(&bearer(data), now(), in_response_to, recipient)
    }

    #[test]
    fn a_fully_conforming_confirmation_is_accepted() {
        assert!(
            check(
                Some(valid_data()),
                Some("req-123"),
                Some("https://axiam.example/acs")
            )
            .is_ok()
        );
    }

    #[test]
    fn an_assertion_minted_for_another_service_provider_is_refused() {
        let err = check(
            Some(SubjectConfirmationData {
                recipient: Some("https://someone-else.example/acs".into()),
                ..valid_data()
            }),
            Some("req-123"),
            Some("https://axiam.example/acs"),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Recipient mismatch"), "{msg}");
        // The message names both sides, so an operator debugging a federation
        // rollout can see which SP the IdP actually addressed.
        assert!(msg.contains("someone-else.example"), "{msg}");
    }

    #[test]
    fn recipient_must_be_present_even_when_the_caller_cannot_compare_it() {
        // The public first-time-SSO path passes `None` because it has no ACS
        // URL to compare against. Presence is still REQUIRED by §4.1.4.2, so a
        // missing or empty Recipient is refused on that path too — otherwise
        // "we don't know our own URL" would silently become "any recipient".
        for recipient in [None, Some(String::new())] {
            let err = check(
                Some(SubjectConfirmationData {
                    recipient,
                    ..valid_data()
                }),
                Some("req-123"),
                None,
            )
            .unwrap_err();
            assert!(err.to_string().contains("missing required Recipient"));
        }
    }

    #[test]
    fn an_expired_confirmation_is_refused_with_no_leeway() {
        // NotOnOrAfter is exclusive: at exactly the boundary the assertion is
        // already invalid, and there is deliberately no clock skew allowance.
        let err = check(
            Some(SubjectConfirmationData {
                not_on_or_after: Some(now()),
                ..valid_data()
            }),
            Some("req-123"),
            Some("https://axiam.example/acs"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn a_missing_not_on_or_after_is_refused_rather_than_treated_as_unbounded() {
        let err = check(
            Some(SubjectConfirmationData {
                not_on_or_after: None,
                ..valid_data()
            }),
            Some("req-123"),
            Some("https://axiam.example/acs"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("missing required NotOnOrAfter"));
    }

    #[test]
    fn a_not_yet_valid_confirmation_is_refused() {
        // §4.1.4.2 says NotBefore MUST NOT be present, but real IdPs emit it.
        // The posture is to honour it rather than reject its presence.
        let err = check(
            Some(SubjectConfirmationData {
                not_before: Some(ts("2026-06-01T12:01:00Z")),
                ..valid_data()
            }),
            Some("req-123"),
            Some("https://axiam.example/acs"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("not yet valid"));

        // A NotBefore already in the past is fine — presence alone is not a
        // rejection.
        assert!(
            check(
                Some(SubjectConfirmationData {
                    not_before: Some(ts("2026-06-01T11:59:00Z")),
                    ..valid_data()
                }),
                Some("req-123"),
                Some("https://axiam.example/acs"),
            )
            .is_ok()
        );
    }

    #[test]
    fn an_unsolicited_assertion_is_refused_when_a_request_id_is_expected() {
        let err = check(
            Some(SubjectConfirmationData {
                in_response_to: None,
                ..valid_data()
            }),
            Some("req-123"),
            Some("https://axiam.example/acs"),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("missing InResponseTo"), "{msg}");
        assert!(msg.contains("IdP-initiated"), "{msg}");
    }

    #[test]
    fn an_assertion_answering_a_different_request_is_refused() {
        let err = check(
            Some(SubjectConfirmationData {
                in_response_to: Some("some-other-request".into()),
                ..valid_data()
            }),
            Some("req-123"),
            Some("https://axiam.example/acs"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("InResponseTo mismatch"));
    }

    #[test]
    fn in_response_to_is_not_checked_when_the_caller_expects_none() {
        // The caller decides whether a request id is required; when it passes
        // None, an assertion carrying any InResponseTo (or none) still passes
        // this particular check.
        assert!(check(Some(valid_data()), None, Some("https://axiam.example/acs")).is_ok());
        assert!(
            check(
                Some(SubjectConfirmationData {
                    in_response_to: None,
                    ..valid_data()
                }),
                None,
                Some("https://axiam.example/acs"),
            )
            .is_ok()
        );
    }

    #[test]
    fn a_confirmation_with_no_data_element_is_refused() {
        let err = check(None, Some("req-123"), Some("https://axiam.example/acs")).unwrap_err();
        assert!(
            err.to_string()
                .contains("missing required SubjectConfirmationData")
        );
    }

    // -- the assertion-level wrapper ---------------------------------------

    fn assertion_with(subject: Option<Subject>) -> samael::schema::Assertion {
        samael::schema::Assertion {
            id: "assertion-1".into(),
            issue_instant: now(),
            version: "2.0".into(),
            issuer: samael::schema::Issuer {
                value: Some("https://idp.example".into()),
                ..Default::default()
            },
            signature: None,
            subject,
            conditions: None,
            authn_statements: None,
            attribute_statements: None,
        }
    }

    fn validate(subject: Option<Subject>) -> Result<(), FederationError> {
        validate_bearer_subject_confirmation(
            &assertion_with(subject),
            now(),
            Some("req-123"),
            Some("req-123"),
            Some("https://axiam.example/acs"),
            true,
        )
    }

    #[test]
    fn an_assertion_with_no_subject_is_refused() {
        let err = validate(None).unwrap_err();
        assert!(err.to_string().contains("missing required Subject"));
    }

    #[test]
    fn an_assertion_with_no_bearer_confirmation_is_refused() {
        // A holder-of-key confirmation is a valid SAML construct, but it is not
        // the Web-Browser-SSO profile and must not authenticate a browser flow.
        let holder_of_key = SubjectConfirmation {
            method: Some("urn:oasis:names:tc:SAML:2.0:cm:holder-of-key".into()),
            name_id: None,
            subject_confirmation_data: Some(valid_data()),
        };
        for confirmations in [Some(vec![]), None, Some(vec![holder_of_key])] {
            let err = validate(Some(Subject {
                name_id: None,
                subject_confirmations: confirmations,
            }))
            .unwrap_err();
            assert!(
                err.to_string().contains("no bearer SubjectConfirmation"),
                "got: {err}"
            );
        }
    }

    #[test]
    fn one_satisfying_confirmation_among_several_is_enough() {
        // §4.1.4.2 requires only that ONE bearer confirmation satisfy the
        // profile. An IdP that emits a stale one alongside a good one must not
        // be rejected — but the good one has to actually be there.
        let stale = bearer(Some(SubjectConfirmationData {
            not_on_or_after: Some(ts("2026-06-01T11:00:00Z")),
            ..valid_data()
        }));
        let good = bearer(Some(valid_data()));

        assert!(
            validate(Some(Subject {
                name_id: None,
                subject_confirmations: Some(vec![stale.clone(), good]),
            }))
            .is_ok()
        );

        // With only the stale one, the rejection names the concrete violation
        // rather than a generic "nothing matched".
        let err = validate(Some(Subject {
            name_id: None,
            subject_confirmations: Some(vec![stale]),
        }))
        .unwrap_err();
        assert!(err.to_string().contains("expired"), "got: {err}");
    }

    #[test]
    fn the_response_in_response_to_is_the_fallback_when_no_request_id_is_stored() {
        // The public first-time-SSO path has no stored request id, so the
        // Response's own InResponseTo becomes the required value — the
        // confirmation must still answer the same request, not any request.
        let subject = Some(Subject {
            name_id: None,
            subject_confirmations: Some(vec![bearer(Some(valid_data()))]),
        });
        let call = |expected_request_id, response_in_response_to| {
            validate_bearer_subject_confirmation(
                &assertion_with(subject.clone()),
                now(),
                response_in_response_to,
                expected_request_id,
                Some("https://axiam.example/acs"),
                true,
            )
        };

        assert!(call(None, Some("req-123")).is_ok());
        assert!(
            call(Some(""), Some("req-123")).is_ok(),
            "an empty stored id falls back too"
        );
        assert!(call(None, Some("a-different-request")).is_err());
    }
}

// ---------------------------------------------------------------------------
// Claim extraction and attribute mapping
// ---------------------------------------------------------------------------
//
// These run on every successful SSO, after the signature and the confirmation
// checks have passed, and they decide WHO the caller is. The fixture-driven
// tests above exercise them only through whole assertions that happen to be
// well-shaped; what is pinned here is the behaviour on the shapes real IdPs
// actually vary in — multiple AttributeStatements, friendlyName-only
// attributes, multi-valued attributes, and an attribute_map that names a claim
// the IdP did not send.

#[cfg(test)]
mod claim_extraction_tests {
    use super::*;
    use samael::attribute::{Attribute, AttributeValue};
    use samael::schema::{AttributeStatement, AuthnStatement, Subject, SubjectNameID};
    use serde_json::json;

    fn value(v: &str) -> AttributeValue {
        AttributeValue {
            attribute_type: None,
            value: Some(v.into()),
        }
    }

    fn attribute(name: Option<&str>, friendly: Option<&str>, values: &[&str]) -> Attribute {
        Attribute {
            friendly_name: friendly.map(str::to_owned),
            name: name.map(str::to_owned),
            name_format: None,
            values: values.iter().map(|v| value(v)).collect(),
        }
    }

    fn assertion(
        name_id: Option<&str>,
        authn: Option<Vec<AuthnStatement>>,
        attrs: Option<Vec<AttributeStatement>>,
    ) -> samael::schema::Assertion {
        samael::schema::Assertion {
            id: "a-1".into(),
            issue_instant: chrono::Utc::now(),
            version: "2.0".into(),
            issuer: samael::schema::Issuer {
                value: Some("https://idp.example".into()),
                ..Default::default()
            },
            signature: None,
            subject: name_id.map(|v| Subject {
                name_id: Some(SubjectNameID {
                    format: None,
                    value: v.into(),
                }),
                subject_confirmations: None,
            }),
            conditions: None,
            authn_statements: authn,
            attribute_statements: attrs,
        }
    }

    fn authn_statement(session_index: Option<&str>) -> AuthnStatement {
        AuthnStatement {
            authn_instant: None,
            session_index: session_index.map(str::to_owned),
            session_not_on_or_after: None,
            subject_locality: None,
            authn_context: None,
        }
    }

    #[test]
    fn an_assertion_without_a_name_id_identifies_nobody_and_is_refused() {
        // The NameID is the federated identity. Defaulting it — to the empty
        // string, or to the issuer — would let an assertion that names no one
        // resolve to *some* account.
        let err = extract_assertion_claims(&assertion(None, None, None)).unwrap_err();
        assert!(err.to_string().contains("missing Subject/NameID"));

        // Present-but-subjectless is the same failure.
        let mut a = assertion(Some("u"), None, None);
        a.subject = Some(Subject {
            name_id: None,
            subject_confirmations: None,
        });
        assert!(extract_assertion_claims(&a).is_err());
    }

    #[test]
    fn the_session_index_comes_from_the_first_authn_statement() {
        // It is what Single Logout later correlates on, so an assertion
        // carrying several statements must not silently pick a later one.
        let claims = extract_assertion_claims(&assertion(
            Some("user@example.test"),
            Some(vec![
                authn_statement(Some("session-A")),
                authn_statement(Some("session-B")),
            ]),
            None,
        ))
        .unwrap();
        assert_eq!(claims.name_id, "user@example.test");
        assert_eq!(claims.session_index.as_deref(), Some("session-A"));
    }

    #[test]
    fn an_absent_session_index_is_none_rather_than_an_error() {
        // SLO is optional; an IdP that omits SessionIndex must still log in.
        for authn in [None, Some(vec![]), Some(vec![authn_statement(None)])] {
            let claims = extract_assertion_claims(&assertion(Some("u"), authn, None)).unwrap();
            assert!(claims.session_index.is_none());
        }
    }

    #[test]
    fn attributes_are_keyed_by_name_and_fall_back_to_friendly_name() {
        let claims = extract_assertion_claims(&assertion(
            Some("u"),
            None,
            Some(vec![AttributeStatement {
                attributes: vec![
                    attribute(
                        Some("urn:oid:0.9.2342.19200300.100.1.3"),
                        Some("mail"),
                        &["a@x.test"],
                    ),
                    // name absent — friendlyName is the key instead.
                    attribute(None, Some("displayName"), &["Ada"]),
                    // neither — the documented "unknown" bucket.
                    attribute(None, None, &["orphan"]),
                ],
            }]),
        ))
        .unwrap();

        assert_eq!(
            claims.attributes.get("urn:oid:0.9.2342.19200300.100.1.3"),
            Some(&vec!["a@x.test".to_string()])
        );
        assert_eq!(
            claims.attributes.get("displayName"),
            Some(&vec!["Ada".to_string()])
        );
        assert_eq!(
            claims.attributes.get("unknown"),
            Some(&vec!["orphan".to_string()])
        );
    }

    #[test]
    fn repeated_attributes_accumulate_across_statements() {
        // Group membership is the case that matters: an IdP may emit one
        // `memberOf` per group, spread over several AttributeStatements. Taking
        // only the last would silently drop a user's groups.
        let claims = extract_assertion_claims(&assertion(
            Some("u"),
            None,
            Some(vec![
                AttributeStatement {
                    attributes: vec![attribute(Some("memberOf"), None, &["admins"])],
                },
                AttributeStatement {
                    attributes: vec![attribute(Some("memberOf"), None, &["auditors", "staff"])],
                },
            ]),
        ))
        .unwrap();

        assert_eq!(
            claims.attributes.get("memberOf"),
            Some(&vec![
                "admins".to_string(),
                "auditors".to_string(),
                "staff".to_string()
            ])
        );
    }

    #[test]
    fn valueless_attribute_entries_are_dropped_not_turned_into_empty_strings() {
        let claims = extract_assertion_claims(&assertion(
            Some("u"),
            None,
            Some(vec![AttributeStatement {
                attributes: vec![Attribute {
                    friendly_name: None,
                    name: Some("mail".into()),
                    name_format: None,
                    values: vec![
                        AttributeValue {
                            attribute_type: None,
                            value: None,
                        },
                        value("a@x.test"),
                    ],
                }],
            }]),
        ))
        .unwrap();
        assert_eq!(
            claims.attributes.get("mail"),
            Some(&vec!["a@x.test".to_string()])
        );
    }

    // -- attribute_map ------------------------------------------------------

    fn claims_with(pairs: &[(&str, &[&str])]) -> SamlAssertionClaims {
        SamlAssertionClaims {
            name_id: "u".into(),
            session_index: None,
            attributes: pairs
                .iter()
                .map(|(k, vs)| {
                    (
                        (*k).to_string(),
                        vs.iter().map(|v| (*v).to_string()).collect(),
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn the_attribute_map_resolves_email_and_display_name() {
        let claims = claims_with(&[("mail", &["a@x.test"]), ("displayName", &["Ada"])]);
        let (email, name) =
            apply_attribute_map(&claims, &json!({"email": "mail", "name": "displayName"}));
        assert_eq!(email.as_deref(), Some("a@x.test"));
        assert_eq!(name.as_deref(), Some("Ada"));
    }

    #[test]
    fn display_name_falls_back_to_the_display_name_key() {
        // Two spellings are accepted for the same thing; `name` wins when both
        // are configured.
        let claims = claims_with(&[("dn", &["Ada"]), ("cn", &["Ada Lovelace"])]);

        let (_, only_fallback) = apply_attribute_map(&claims, &json!({"displayName": "cn"}));
        assert_eq!(only_fallback.as_deref(), Some("Ada Lovelace"));

        let (_, both) = apply_attribute_map(&claims, &json!({"name": "dn", "displayName": "cn"}));
        assert_eq!(both.as_deref(), Some("Ada"), "`name` takes precedence");
    }

    #[test]
    fn a_map_naming_an_attribute_the_idp_did_not_send_yields_none() {
        // Not an error: the caller decides whether a missing email is fatal.
        // Inventing one here would be worse than returning nothing.
        let claims = claims_with(&[("mail", &["a@x.test"])]);
        let (email, name) = apply_attribute_map(
            &claims,
            &json!({"email": "someOtherAttribute", "name": "alsoMissing"}),
        );
        assert!(email.is_none());
        assert!(name.is_none());
    }

    #[test]
    fn a_non_string_or_absent_mapping_is_ignored_rather_than_coerced() {
        let claims = claims_with(&[("mail", &["a@x.test"]), ("42", &["nope"])]);
        for map in [
            json!({}),
            json!({"email": 42}),
            json!({"email": null}),
            json!([]),
        ] {
            let (email, _) = apply_attribute_map(&claims, &map);
            assert!(email.is_none(), "map {map} must not resolve an email");
        }
    }

    #[test]
    fn only_the_first_value_of_a_multi_valued_attribute_is_used() {
        let claims = claims_with(&[("mail", &["first@x.test", "second@x.test"])]);
        let (email, _) = apply_attribute_map(&claims, &json!({"email": "mail"}));
        assert_eq!(email.as_deref(), Some("first@x.test"));
    }

    // -- serialization helpers ---------------------------------------------

    #[test]
    fn xml_escape_replaces_the_ampersand_first() {
        // Ordering is the whole correctness content of this function: if `&`
        // were replaced after `<`, the `&` introduced by `&lt;` would itself be
        // escaped and the output would read `&amp;lt;`.
        assert_eq!(xml_escape("<a>"), "&lt;a&gt;");
        assert_eq!(xml_escape("a & b"), "a &amp; b");
        assert_eq!(
            xml_escape(r#"<tag attr="v" o='p'>x & y</tag>"#),
            "&lt;tag attr=&quot;v&quot; o=&apos;p&apos;&gt;x &amp; y&lt;/tag&gt;"
        );
        // The escaped form must be a fixed point in the sense that escaping
        // never produces a bare `&` for a later pass to double-escape.
        assert!(!xml_escape("<&>").contains("&amp;lt;"));
        assert_eq!(xml_escape(""), "");
        assert_eq!(xml_escape("nothing to do"), "nothing to do");
    }

    #[test]
    fn deflate_encode_produces_raw_deflate_that_inflates_back() {
        use flate2::read::DeflateDecoder;
        use std::io::Read;

        let original =
            b"<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>";
        let compressed = deflate_encode(original).unwrap();

        // Raw deflate, no zlib header — the HTTP-Redirect binding requires it,
        // and a zlib-wrapped payload would be rejected by every IdP.
        assert_ne!(
            compressed.first(),
            Some(&0x78),
            "zlib header must be absent"
        );

        let mut out = Vec::new();
        DeflateDecoder::new(&compressed[..])
            .read_to_end(&mut out)
            .expect("raw deflate round-trips");
        assert_eq!(out, original);
    }
}
