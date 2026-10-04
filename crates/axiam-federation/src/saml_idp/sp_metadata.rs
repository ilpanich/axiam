//! Importing a service provider's metadata — a **parse to a draft, never a
//! write** (G-2, T23.2.5, D-41).
//!
//! An SP's metadata document is attacker-influenced XML (an upload, or whatever
//! a URL serves) and it is usually unsigned. So this module only *suggests*: it
//! turns a document into a [`SpMetadataDraft`] — a
//! [`SamlServiceProviderInput`] the administrator reads and then submits through
//! the ordinary create or update, where the validator and the write-time
//! refusals apply as to a manual entry. Nothing here touches the registry.
//!
//! # How the XML is refused
//!
//! As the receiver refuses an `AuthnRequest` (`request.rs`), in the same order:
//!
//! 1. the size ([`MAX_SP_METADATA_BYTES`], 512 KiB) and UTF-8;
//! 2. [`refuse_markup_declarations`] — any `<!` other than a comment or CDATA
//!    section — and [`refuse_other_encodings`] on the bytes, before any parser
//!    sees them: with no DTD there is no entity, external or internal, to read
//!    or to expand;
//! 3. libxml, without recovery, network or DTD defaults, which bounds the nesting
//!    depth and decides that the root really is `md:EntityDescriptor` (an
//!    `EntitiesDescriptor` aggregate is refused here, before `samael`'s
//!    recursive deserializer can be fed a deeply nested one);
//! 4. `samael`'s metadata types, which open no network, and exactly one
//!    `SPSSODescriptor` supporting SAML 2.0.
//!
//! Every refusal is one of three generic [`MetadataError`] categories. The
//! message never carries the document, a parser's text, a status line or an
//! address (T-356's lesson), so the route cannot be used to read an internal
//! response back.
//!
//! # What is taken, and what is trusted
//!
//! Taken, as a draft: `entityID`; the HTTP-POST `AssertionConsumerService`
//! endpoints with their `index` and `isDefault`; one `SingleLogoutService`
//! (HTTP-Redirect preferred over HTTP-POST — no signature to harvest, D-38);
//! the first signing `KeyDescriptor` as the request-signing certificate and an
//! `use="encryption"` one as the encryption certificate (**`encrypt_assertions`
//! is never set**, D-2); `AuthnRequestsSigned`; the first of persistent and
//! `emailAddress` among the `NameIDFormat`s; a display name.
//!
//! **Trusted from an unsigned document: nothing.** A `ds:Signature` in it is not
//! evaluated — there is no anchor, and evaluating it against a certificate the
//! same document carries would be circular — and its presence is reported as a
//! warning. `validUntil` and `cacheDuration` are ignored. The SHA-256
//! fingerprints of the certificates are returned for the administrator to compare
//! out of band. AXIAM never re-reads an SP's metadata on its own.

use axiam_core::models::saml_sp::{
    AcsEndpoint, MAX_ACS_ENDPOINTS, MAX_DISPLAY_NAME_BYTES, NameIdFormat, SamlBinding,
    SamlServiceProviderInput,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use samael::metadata::{
    EntityDescriptor, EntityDescriptorType, HTTP_POST_BINDING, HTTP_REDIRECT_BINDING, KeyDescriptor,
};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

use super::request::{refuse_markup_declarations, refuse_other_encodings};

/// The largest metadata document accepted, in bytes — the cap the SP side's
/// `fetch_idp_metadata` already uses.
pub const MAX_SP_METADATA_BYTES: usize = 512 * 1024;

/// The metadata namespace.
const NS_METADATA: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
/// XML-DSig namespace, for noticing a document signature.
const NS_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
/// The SAML 2.0 protocol URN an `SPSSODescriptor` must support.
const PROTOCOL_SAML2: &str = "urn:oasis:names:tc:SAML:2.0:protocol";

/// Why metadata could not be imported: one of three generic categories, each
/// with a fixed message. Nothing about the document, the response or the
/// resolved address is in any of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataError {
    /// The URL was refused before or while fetching: not `https`, carries
    /// credentials, does not resolve, resolves to an address the SSRF guard
    /// refuses, or redirects somewhere it refuses.
    UrlRefused,
    /// The fetch itself failed: a transport error, or a response that was not a
    /// success.
    FetchFailed,
    /// The document is not usable SP metadata: too large, not UTF-8, containing
    /// a DTD or entity declaration, not well-formed, not exactly one
    /// `EntityDescriptor` with one SAML 2.0 `SPSSODescriptor`.
    NotSpMetadata,
}

impl MetadataError {
    /// The message every caller gives — and the audit row records the category
    /// by [`Self::category`].
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::UrlRefused => "metadata_url refused",
            Self::FetchFailed => "metadata fetch failed",
            Self::NotSpMetadata => "not SAML service-provider metadata",
        }
    }

    /// The category as a stable machine-readable word, for the audit row.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::UrlRefused => "url_refused",
            Self::FetchFailed => "fetch_failed",
            Self::NotSpMetadata => "not_sp_metadata",
        }
    }
}

impl std::fmt::Display for MetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for MetadataError {}

/// What importing produced: a suggestion and what the administrator needs to
/// judge it. Not a registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpMetadataDraft {
    /// The registration the document suggests, as a create or update body.
    /// `encrypt_assertions` is `false`.
    pub service_provider: SamlServiceProviderInput,
    /// Lower-case hex SHA-256 of the signing certificate's DER the draft
    /// carries, or `None`.
    pub signing_certificate_fingerprint: Option<String>,
    /// Lower-case hex SHA-256 of the encryption certificate's DER the draft
    /// carries, or `None`.
    pub encryption_certificate_fingerprint: Option<String>,
    /// What the administrator should know before submitting it. Human text; a
    /// caller must not parse it.
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------

/// Fetch the metadata at `url`: **one** request through
/// [`axiam_pki::ssrf::guarded_fetch`] — the name resolved once and the
/// connection pinned to the vetted address, private, loopback, link-local and
/// cloud-metadata addresses refused, every redirect hop re-validated, a
/// transport timeout and cap — then held to [`MAX_SP_METADATA_BYTES`].
///
/// `allow_private` is the guard's test seam and the production caller passes
/// **`false`**: it relaxes the address rule and the scheme rule for the first
/// hop only (never for a redirect), so a test can reach a loopback mock.
/// With it `false`, only `https` is accepted, and a URL with a user name or
/// password is refused (no credentials are ever sent).
///
/// No refresh, no retry, no cookies: a changed SP is re-imported by a person.
///
/// # Errors
///
/// [`MetadataError::UrlRefused`] for everything decided by the URL or the
/// address it resolves to — **one** category, so the answer cannot be used to map
/// internal DNS; [`MetadataError::FetchFailed`] for a transport failure or a
/// non-success status; [`MetadataError::NotSpMetadata`] for a response over the
/// cap.
pub async fn fetch_sp_metadata(url: &str, allow_private: bool) -> Result<Vec<u8>, MetadataError> {
    use axiam_pki::ssrf::{SsrfError, guarded_fetch, read_capped_body};

    let parsed = url::Url::parse(url).map_err(|_| MetadataError::UrlRefused)?;
    if parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || (!allow_private && parsed.scheme() != "https")
    {
        return Err(MetadataError::UrlRefused);
    }

    let response = guarded_fetch(url, allow_private, |client, target| client.get(target))
        .await
        .map_err(|error| match error {
            SsrfError::InvalidUrl
            | SsrfError::ResolveFailed
            | SsrfError::Blocked
            | SsrfError::InsecureScheme
            | SsrfError::TooManyRedirects => MetadataError::UrlRefused,
            SsrfError::ResponseTooLarge(_) => MetadataError::NotSpMetadata,
            SsrfError::ClientBuildFailed | SsrfError::RequestFailed(_) => {
                MetadataError::FetchFailed
            }
        })?;
    if !response.status().is_success() {
        return Err(MetadataError::FetchFailed);
    }
    read_capped_body(response, MAX_SP_METADATA_BYTES)
        .await
        .map_err(|error| match error {
            SsrfError::ResponseTooLarge(_) => MetadataError::NotSpMetadata,
            _ => MetadataError::FetchFailed,
        })
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse `document` into a draft.
///
/// # Errors
///
/// [`MetadataError::NotSpMetadata`] for every way the document is refused. Never
/// anything else, and never any text of the document.
pub fn parse_sp_metadata(document: &[u8]) -> Result<SpMetadataDraft, MetadataError> {
    let refused = MetadataError::NotSpMetadata;
    if document.len() > MAX_SP_METADATA_BYTES {
        return Err(refused);
    }
    let text = std::str::from_utf8(document).map_err(|_| refused)?;
    refuse_markup_declarations(text).map_err(|_| refused)?;
    refuse_other_encodings(text).map_err(|_| refused)?;

    // libxml first: well-formedness, a bounded depth, and the root's identity.
    let options = libxml::parser::ParserOptions {
        recover: false,
        no_net: true,
        no_def_dtd: true,
        ignore_enc: true,
        encoding: Some("UTF-8"),
        ..Default::default()
    };
    let doc = libxml::parser::Parser::default()
        .parse_string_with_options(document, options)
        .map_err(|_| refused)?;
    let root = doc.get_root_element().ok_or(refused)?;
    if root.get_name() != "EntityDescriptor"
        || !root
            .get_namespace()
            .is_some_and(|ns| ns.get_href() == NS_METADATA)
    {
        // Includes an `EntitiesDescriptor` aggregate.
        return Err(refused);
    }

    let descriptor: EntityDescriptorType = text.parse().map_err(|_| refused)?;
    let EntityDescriptorType::EntityDescriptor(entity) = descriptor else {
        return Err(refused);
    };
    draft_from(&entity, text)
}

/// Map one `EntityDescriptor` to a draft.
fn draft_from(entity: &EntityDescriptor, text: &str) -> Result<SpMetadataDraft, MetadataError> {
    let refused = MetadataError::NotSpMetadata;
    let entity_id = entity
        .entity_id
        .clone()
        .filter(|id| !id.is_empty())
        .ok_or(refused)?;
    let sp = match entity.sp_sso_descriptors.as_deref() {
        Some([only]) => only,
        _ => return Err(refused),
    };
    if !sp
        .protocol_support_enumeration
        .as_deref()
        .is_some_and(|list| list.split_whitespace().any(|p| p == PROTOCOL_SAML2))
    {
        return Err(refused);
    }

    let mut warnings = Vec::new();

    // --- the signature of the document itself: noticed, never evaluated ---
    if entity.signature.is_some() || text.contains(NS_DSIG) && text.contains("SignatureValue") {
        warnings.push(
            "metadata signature not verified: the document's own signature is not evaluated, \
             so nothing in this draft is trusted because the document carried it"
                .to_string(),
        );
    }

    // --- AssertionConsumerService: HTTP-POST only ---
    let mut dropped_bindings = 0usize;
    let mut acs_urls: Vec<AcsEndpoint> = Vec::new();
    let mut dropped_indexes = 0usize;
    for endpoint in &sp.assertion_consumer_services {
        if endpoint.binding != HTTP_POST_BINDING {
            dropped_bindings += 1;
            continue;
        }
        let Ok(index) = u16::try_from(endpoint.index) else {
            dropped_indexes += 1;
            continue;
        };
        if acs_urls.iter().any(|e| e.index == index) {
            dropped_indexes += 1;
            continue;
        }
        if acs_urls.len() == MAX_ACS_ENDPOINTS {
            dropped_indexes += 1;
            continue;
        }
        acs_urls.push(AcsEndpoint {
            url: endpoint.location.clone(),
            binding: SamlBinding::HttpPost,
            index,
            is_default: endpoint.is_default == Some(true),
        });
    }
    if dropped_bindings > 0 {
        warnings.push(format!(
            "{dropped_bindings} AssertionConsumerService endpoint(s) with a binding other than \
             HTTP-POST were not imported: AXIAM answers by HTTP-POST only"
        ));
    }
    if dropped_indexes > 0 {
        warnings.push(format!(
            "{dropped_indexes} AssertionConsumerService endpoint(s) were not imported: an \
             index that is out of range or repeated, or more than {MAX_ACS_ENDPOINTS} endpoints"
        ));
    }
    if acs_urls.is_empty() {
        warnings.push(
            "the metadata names no HTTP-POST AssertionConsumerService: add one before \
             registering"
                .to_string(),
        );
    }
    if let Some(first_default) = acs_urls.iter().position(|e| e.is_default) {
        let mut extra = 0usize;
        for (at, endpoint) in acs_urls.iter_mut().enumerate() {
            if endpoint.is_default && at != first_default {
                endpoint.is_default = false;
                extra += 1;
            }
        }
        if extra > 0 {
            warnings.push(
                "more than one AssertionConsumerService is marked default: only the first \
                 stays the default"
                    .to_string(),
            );
        }
    }

    // --- SingleLogoutService: one, HTTP-Redirect preferred ---
    let slo_services = sp.single_logout_services.as_deref().unwrap_or_default();
    let slo = slo_services
        .iter()
        .find(|e| e.binding == HTTP_REDIRECT_BINDING)
        .or_else(|| slo_services.iter().find(|e| e.binding == HTTP_POST_BINDING));
    let (slo_url, slo_binding) = match slo {
        Some(endpoint) => (
            Some(endpoint.location.clone()),
            Some(if endpoint.binding == HTTP_REDIRECT_BINDING {
                SamlBinding::HttpRedirect
            } else {
                SamlBinding::HttpPost
            }),
        ),
        None => (None, None),
    };
    if !slo_services.is_empty() && slo_url.is_none() {
        warnings.push(
            "the metadata's SingleLogoutService uses a binding AXIAM does not support (only \
             HTTP-Redirect and HTTP-POST): no logout endpoint was imported"
                .to_string(),
        );
    } else if slo_services.len() > 1 {
        warnings.push(
            "more than one SingleLogoutService: one was imported, HTTP-Redirect before HTTP-POST"
                .to_string(),
        );
    }

    // --- keys ---
    let keys = sp.key_descriptors.as_deref().unwrap_or_default();
    let signing_keys: Vec<&KeyDescriptor> = keys
        .iter()
        .filter(|k| k.key_use.as_deref().is_none_or(|u| u == "signing"))
        .collect();
    let encryption_keys: Vec<&KeyDescriptor> = keys
        .iter()
        .filter(|k| k.key_use.as_deref() == Some("encryption"))
        .collect();
    if signing_keys.len() > 1 {
        warnings.push("more than one signing certificate: only the first was imported".to_string());
    }
    let signing = signing_keys
        .first()
        .and_then(|k| certificate_of(k, "signing", &mut warnings));
    let encryption = encryption_keys
        .first()
        .and_then(|k| certificate_of(k, "encryption", &mut warnings));
    if encryption.is_some() {
        warnings.push(
            "an encryption certificate was imported, but assertion encryption is not supported \
             yet: encrypt_assertions stays false"
                .to_string(),
        );
    }

    // --- NameID format and display name ---
    let name_id_format = sp
        .name_id_formats
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find_map(|f| {
            [NameIdFormat::Persistent, NameIdFormat::EmailAddress]
                .into_iter()
                .find(|known| known.urn() == f)
        });
    if name_id_format.is_none() && !sp.name_id_formats.as_deref().unwrap_or_default().is_empty() {
        warnings.push(
            "the metadata lists no NameIDFormat AXIAM issues (persistent, emailAddress): \
             persistent was chosen"
                .to_string(),
        );
    }
    let display_name = display_name_of(sp.organization.as_ref(), &entity_id);

    let service_provider = SamlServiceProviderInput {
        enabled: true,
        display_name,
        entity_id,
        acs_urls,
        slo_url,
        slo_binding,
        name_id_format: name_id_format.unwrap_or_default(),
        sign_responses: true,
        // D-2: never set from a document.
        encrypt_assertions: false,
        sp_signing_cert_pem: signing.as_ref().map(|c| c.pem.clone()),
        sp_encryption_cert_pem: encryption.as_ref().map(|c| c.pem.clone()),
        want_authn_requests_signed: sp.authn_requests_signed == Some(true),
        allow_idp_initiated: false,
        attribute_mappings: Vec::new(),
        allowed_groups: Vec::new(),
    };

    // What a write of this draft would be refused for, said now: the same rules,
    // run on the draft, so the administrator is not told one thing here and
    // another on submit. (The rules that need the datastore are the write's.)
    for violation in crate::saml_sp::saml_sp_violations(&service_provider) {
        warnings.push(format!(
            "a write of this draft would be refused: {violation}"
        ));
    }
    for refusal in crate::saml_sp::saml_sp_write_refusals(&service_provider) {
        warnings.push(format!("a write of this draft would be refused: {refusal}"));
    }

    Ok(SpMetadataDraft {
        signing_certificate_fingerprint: signing.map(|c| c.fingerprint),
        encryption_certificate_fingerprint: encryption.map(|c| c.fingerprint),
        service_provider,
        warnings,
    })
}

/// A certificate lifted out of a `KeyDescriptor`.
struct ImportedCertificate {
    pem: String,
    fingerprint: String,
}

/// The first X.509 certificate of a `KeyDescriptor`, as PEM and fingerprint, or
/// `None` with a warning when it carries none that parses. An expired
/// certificate is imported and warned about: SAML trusts a registered key as a
/// key, not by its dates.
fn certificate_of(
    key: &KeyDescriptor,
    kind: &str,
    warnings: &mut Vec<String>,
) -> Option<ImportedCertificate> {
    let encoded = key
        .key_info
        .x509_data
        .as_ref()
        .and_then(|data| data.certificates.first());
    let Some(encoded) = encoded else {
        warnings.push(format!(
            "the {kind} KeyDescriptor carries no X509Certificate: it was not imported"
        ));
        return None;
    };
    let compact: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
    let der = STANDARD.decode(compact.as_bytes()).ok()?;
    let Ok((_, parsed)) = X509Certificate::from_der(&der) else {
        warnings.push(format!(
            "the {kind} certificate is not a parseable X.509 certificate: it was not imported"
        ));
        return None;
    };
    if parsed.validity().not_after.timestamp() < chrono::Utc::now().timestamp() {
        warnings.push(format!(
            "the {kind} certificate has expired; it is imported because SAML trusts a \
             registered key as a key, but the SP will need to rotate it"
        ));
    }
    // LF line endings, as every other certificate PEM in the registry.
    let pem = ::pem::encode_config(
        &::pem::Pem::new("CERTIFICATE", der.clone()),
        ::pem::EncodeConfig::new().set_line_ending(::pem::LineEnding::LF),
    );
    Some(ImportedCertificate {
        pem,
        fingerprint: hex::encode(Sha256::digest(&der)),
    })
}

/// A display name that satisfies the registry's own rule: the first
/// `OrganizationDisplayName`, else the entity id's host, else the entity id —
/// trimmed, free of control characters, at most
/// [`MAX_DISPLAY_NAME_BYTES`] bytes.
fn display_name_of(
    organization: Option<&samael::metadata::Organization>,
    entity_id: &str,
) -> String {
    let from_document = organization
        .and_then(|o| o.organization_display_names.as_ref())
        .and_then(|names| names.first())
        .map(|n| n.value.as_str());
    let host = url::Url::parse(entity_id)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned));
    let candidate = from_document
        .map(str::to_owned)
        .or(host)
        .unwrap_or_else(|| entity_id.to_owned());
    let mut cleaned: String = candidate.chars().filter(|c| !c.is_control()).collect();
    cleaned = cleaned.trim().to_owned();
    while cleaned.len() > MAX_DISPLAY_NAME_BYTES {
        cleaned.pop();
    }
    let cleaned = cleaned.trim().to_owned();
    if cleaned.is_empty() {
        "service provider".to_owned()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A certificate generated now (no PEM literal in the source), as the body
    /// of a `X509Certificate` element.
    fn cert_b64() -> (String, String) {
        let key = rcgen::KeyPair::generate().expect("key pair");
        let pem = rcgen::CertificateParams::new(vec!["sp.example.test".to_string()])
            .expect("params")
            .self_signed(&key)
            .expect("self-signed")
            .pem();
        let der = crate::cert::pem_cert_to_der(&pem).expect("der");
        (STANDARD.encode(&der), hex::encode(Sha256::digest(&der)))
    }

    fn key_descriptor(usage: Option<&str>, b64: &str) -> String {
        let use_attr = usage.map(|u| format!(" use=\"{u}\"")).unwrap_or_default();
        format!(
            "<md:KeyDescriptor{use_attr}><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{b64}\
             </ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
        )
    }

    fn metadata(entity_attrs: &str, sp_attrs: &str, body: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" \
             xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" \
             entityID=\"https://sp.example.test/metadata\"{entity_attrs}>\
             <md:SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"\
             {sp_attrs}>{body}</md:SPSSODescriptor></md:EntityDescriptor>"
        )
    }

    const ACS_POST: &str = "<md:AssertionConsumerService \
        Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" \
        Location=\"https://sp.example.test/acs\" index=\"0\" isDefault=\"true\"/>";

    fn parse(xml: &str) -> Result<SpMetadataDraft, MetadataError> {
        parse_sp_metadata(xml.as_bytes())
    }

    #[test]
    fn a_good_document_becomes_the_draft_it_describes() {
        let (signing, signing_fp) = cert_b64();
        let (encryption, encryption_fp) = cert_b64();
        let xml = metadata(
            "",
            " AuthnRequestsSigned=\"true\"",
            &format!(
                "{}{}\
                 <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" \
                   Location=\"https://sp.example.test/slo-post\"/>\
                 <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" \
                   Location=\"https://sp.example.test/slo-redirect\"/>\
                 <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>\
                 {ACS_POST}\
                 <md:AssertionConsumerService \
                   Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" \
                   Location=\"https://sp.example.test/acs-2\" index=\"1\"/>\
                 <md:AssertionConsumerService \
                   Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" \
                   Location=\"https://sp.example.test/artifact\" index=\"2\"/>",
                key_descriptor(Some("signing"), &signing),
                key_descriptor(Some("encryption"), &encryption),
            ),
        );
        let draft = parse(&xml).expect("a good document");
        let sp = &draft.service_provider;
        assert_eq!(sp.entity_id, "https://sp.example.test/metadata");
        assert_eq!(sp.display_name, "sp.example.test", "the entity id's host");
        assert_eq!(sp.acs_urls.len(), 2, "the artifact endpoint is dropped");
        assert_eq!(sp.acs_urls[0].url, "https://sp.example.test/acs");
        assert_eq!(sp.acs_urls[0].index, 0);
        assert!(sp.acs_urls[0].is_default);
        assert_eq!(sp.acs_urls[1].index, 1);
        assert!(!sp.acs_urls[1].is_default);
        assert_eq!(
            sp.slo_url.as_deref(),
            Some("https://sp.example.test/slo-redirect")
        );
        assert_eq!(
            sp.slo_binding,
            Some(SamlBinding::HttpRedirect),
            "Redirect preferred"
        );
        assert_eq!(sp.name_id_format, NameIdFormat::EmailAddress);
        assert!(sp.want_authn_requests_signed);
        assert!(sp.sp_signing_cert_pem.is_some());
        assert!(sp.sp_encryption_cert_pem.is_some());
        assert!(!sp.encrypt_assertions, "D-2: never set from a document");
        assert!(!sp.allow_idp_initiated);
        assert!(sp.enabled && sp.sign_responses);
        assert_eq!(
            draft.signing_certificate_fingerprint.as_deref(),
            Some(signing_fp.as_str())
        );
        assert_eq!(
            draft.encryption_certificate_fingerprint.as_deref(),
            Some(encryption_fp.as_str())
        );
        assert!(
            draft.warnings.iter().any(|w| w.contains("HTTP-POST")),
            "the dropped binding is reported: {:?}",
            draft.warnings
        );
        assert!(
            draft
                .warnings
                .iter()
                .any(|w| w.contains("encrypt_assertions stays false"))
        );
        // The draft is what a write would accept, bar the rules of the datastore.
        assert!(
            crate::saml_sp::validate_saml_service_provider_write(sp).is_ok(),
            "{:?}",
            draft.warnings
        );
    }

    #[test]
    fn the_imported_certificate_round_trips_through_the_sso_endpoint_decoder() {
        let (signing, fingerprint) = cert_b64();
        let draft = parse(&metadata(
            "",
            "",
            &format!("{ACS_POST}{}", key_descriptor(None, &signing)),
        ))
        .unwrap();
        let pem = draft.service_provider.sp_signing_cert_pem.expect("pem");
        let der = crate::cert::pem_cert_to_der(&pem).expect("the SSO endpoint's own decoder");
        assert_eq!(hex::encode(Sha256::digest(&der)), fingerprint);
        assert!(draft.service_provider.sp_encryption_cert_pem.is_none());
    }

    #[test]
    fn a_dtd_an_entity_and_a_declared_foreign_encoding_are_refused_on_the_bytes() {
        let base = metadata("", "", ACS_POST);
        let with_doctype = base.replacen(
            "<md:EntityDescriptor",
            "<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><md:EntityDescriptor",
            1,
        );
        assert_eq!(parse(&with_doctype), Err(MetadataError::NotSpMetadata));
        let billion = base.replacen(
            "<md:EntityDescriptor",
            "<!DOCTYPE l [<!ENTITY a \"aaaa\"><!ENTITY b \"&a;&a;&a;&a;\">]><md:EntityDescriptor",
            1,
        );
        assert_eq!(parse(&billion), Err(MetadataError::NotSpMetadata));
        let bare_entity = base.replacen(
            "<md:EntityDescriptor",
            "<!ENTITY e \"x\"><md:EntityDescriptor",
            1,
        );
        assert_eq!(parse(&bare_entity), Err(MetadataError::NotSpMetadata));
        let utf16_declaration = base.replace("encoding=\"UTF-8\"", "encoding=\"UTF-16\"");
        assert_eq!(parse(&utf16_declaration), Err(MetadataError::NotSpMetadata));
        // UTF-16 on the wire: a NUL after every ASCII byte, not UTF-8 at all.
        let utf16: Vec<u8> = base.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(parse_sp_metadata(&utf16), Err(MetadataError::NotSpMetadata));
        // A comment and a CDATA section are not declarations.
        let harmless = base.replacen(
            "<md:SPSSODescriptor",
            "<!-- a note --><md:SPSSODescriptor",
            1,
        );
        assert!(parse(&harmless).is_ok());
    }

    #[test]
    fn an_aggregate_a_wrong_root_two_sp_descriptors_and_a_non_saml2_one_are_refused() {
        let inner = metadata("", "", ACS_POST);
        let body = inner.split_once("?>").unwrap().1;
        let aggregate = format!(
            "<md:EntitiesDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\">{body}\
             </md:EntitiesDescriptor>"
        );
        assert_eq!(parse(&aggregate), Err(MetadataError::NotSpMetadata));

        assert_eq!(parse("<root/>"), Err(MetadataError::NotSpMetadata));
        assert_eq!(parse("not xml at all"), Err(MetadataError::NotSpMetadata));
        assert_eq!(parse(""), Err(MetadataError::NotSpMetadata));
        // The right local name in the wrong namespace.
        let wrong_ns = inner.replace(NS_METADATA, "urn:example:not-metadata");
        assert_eq!(parse(&wrong_ns), Err(MetadataError::NotSpMetadata));

        let sp = "<md:SPSSODescriptor protocolSupportEnumeration=\
                  \"urn:oasis:names:tc:SAML:2.0:protocol\"></md:SPSSODescriptor>";
        let two = inner.replacen(
            "</md:EntityDescriptor>",
            &format!("{sp}</md:EntityDescriptor>"),
            1,
        );
        assert_eq!(parse(&two), Err(MetadataError::NotSpMetadata));

        let saml1 = inner.replace(
            "urn:oasis:names:tc:SAML:2.0:protocol",
            "urn:oasis:names:tc:SAML:1.1:protocol",
        );
        assert_eq!(parse(&saml1), Err(MetadataError::NotSpMetadata));

        let idp_only = "<?xml version=\"1.0\"?><md:EntityDescriptor \
            xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"https://idp.example.test\">\
            <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\
            </md:IDPSSODescriptor></md:EntityDescriptor>";
        assert_eq!(parse(idp_only), Err(MetadataError::NotSpMetadata));

        let no_entity_id = inner.replace(" entityID=\"https://sp.example.test/metadata\"", "");
        assert_eq!(parse(&no_entity_id), Err(MetadataError::NotSpMetadata));
    }

    #[test]
    fn an_oversize_document_and_a_deeply_nested_one_are_refused() {
        let mut huge = metadata("", "", ACS_POST);
        huge.push_str(&" ".repeat(MAX_SP_METADATA_BYTES));
        assert_eq!(parse(&huge), Err(MetadataError::NotSpMetadata));

        let depth = 30_000;
        let nested = format!(
            "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" \
             entityID=\"https://x.test\">{}{}</md:EntityDescriptor>",
            "<a>".repeat(depth),
            "</a>".repeat(depth)
        );
        assert!(nested.len() < MAX_SP_METADATA_BYTES);
        assert_eq!(parse(&nested), Err(MetadataError::NotSpMetadata));
    }

    #[test]
    fn a_document_signature_is_reported_and_never_evaluated() {
        let signed = metadata("", "", ACS_POST).replacen(
            "<md:SPSSODescriptor",
            "<ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod \
             Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod \
             Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><ds:Reference \
             URI=\"\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\
             <ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo>\
             <ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature><md:SPSSODescriptor",
            1,
        );
        let draft = parse(&signed).expect("parsed, though the signature cannot verify");
        assert!(
            draft
                .warnings
                .iter()
                .any(|w| w.starts_with("metadata signature not verified")),
            "{:?}",
            draft.warnings
        );
        assert!(
            parse(&metadata("", "", ACS_POST))
                .unwrap()
                .warnings
                .iter()
                .all(|w| !w.contains("signature"))
        );
    }

    #[test]
    fn an_expired_certificate_a_second_key_and_a_default_clash_are_warned() {
        let expired_pem = {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params =
                rcgen::CertificateParams::new(vec!["old.example.test".to_string()]).unwrap();
            params.not_before = rcgen::date_time_ymd(2001, 1, 1);
            params.not_after = rcgen::date_time_ymd(2002, 1, 1);
            params.self_signed(&key).unwrap().pem()
        };
        let expired = STANDARD.encode(crate::cert::pem_cert_to_der(&expired_pem).unwrap());
        let (other, _) = cert_b64();
        let xml = metadata(
            "",
            "",
            &format!(
                "{}{}{ACS_POST}\
                 <md:AssertionConsumerService \
                   Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" \
                   Location=\"https://sp.example.test/acs-2\" index=\"1\" isDefault=\"true\"/>",
                key_descriptor(Some("signing"), &expired),
                key_descriptor(None, &other),
            ),
        );
        let draft = parse(&xml).unwrap();
        let all = draft.warnings.join(" | ");
        assert!(all.contains("has expired"), "{all}");
        assert!(all.contains("more than one signing certificate"), "{all}");
        assert!(
            all.contains("more than one AssertionConsumerService is marked default"),
            "{all}"
        );
        assert!(
            draft.service_provider.sp_signing_cert_pem.is_some(),
            "expired is imported"
        );
        let defaults = draft
            .service_provider
            .acs_urls
            .iter()
            .filter(|e| e.is_default)
            .count();
        assert_eq!(defaults, 1);
    }

    #[test]
    fn a_draft_that_a_write_would_refuse_says_so_and_is_still_returned() {
        // An http ACS, no HTTP-POST at all in another document.
        let xml = metadata(
            "",
            "",
            "<md:AssertionConsumerService \
             Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" \
             Location=\"http://sp.example.test/acs\" index=\"0\"/>",
        );
        let draft = parse(&xml).unwrap();
        assert!(
            draft
                .warnings
                .iter()
                .any(|w| w.starts_with("a write of this draft would be refused"))
        );
        // No ACS at all is not SP metadata (the schema requires one); one with
        // only an unsupported binding is, and the draft says what is missing.
        assert_eq!(
            parse(&metadata("", "", "")),
            Err(MetadataError::NotSpMetadata)
        );
        let none = parse(&metadata(
            "",
            "",
            "<md:AssertionConsumerService \
             Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" \
             Location=\"https://sp.example.test/artifact\" index=\"0\"/>",
        ))
        .unwrap();
        assert!(none.service_provider.acs_urls.is_empty());
        assert!(
            none.warnings
                .iter()
                .any(|w| w.contains("no HTTP-POST AssertionConsumerService"))
        );
    }

    #[test]
    fn the_display_name_is_the_organization_then_the_host_and_always_acceptable() {
        let xml = metadata(
            "",
            "",
            &format!(
                "{ACS_POST}<md:Organization><md:OrganizationName xml:lang=\"en\">Acme</md:OrganizationName>\
                 <md:OrganizationDisplayName xml:lang=\"en\">  Acme Payroll  </md:OrganizationDisplayName>\
                 <md:OrganizationURL xml:lang=\"en\">https://acme.example.test</md:OrganizationURL>\
                 </md:Organization>"
            ),
        );
        let draft = parse(&xml).expect("an Organization block parses");
        assert_eq!(draft.service_provider.display_name, "Acme Payroll");
        assert_eq!(
            display_name_of(None, "https://sp.example.test/m"),
            "sp.example.test"
        );
        assert_eq!(display_name_of(None, "urn:sp:example"), "urn:sp:example");
        let long = format!("https://{}.test", "a".repeat(400));
        assert!(display_name_of(None, &long).len() <= MAX_DISPLAY_NAME_BYTES);
        assert_eq!(display_name_of(None, "\u{7}\u{8}"), "service provider");
    }

    #[test]
    fn the_messages_are_the_three_generic_ones() {
        assert_eq!(MetadataError::UrlRefused.message(), "metadata_url refused");
        assert_eq!(
            MetadataError::FetchFailed.message(),
            "metadata fetch failed"
        );
        assert_eq!(
            MetadataError::NotSpMetadata.message(),
            "not SAML service-provider metadata"
        );
        assert_eq!(
            MetadataError::UrlRefused.to_string(),
            "metadata_url refused"
        );
    }
}

/// The fetch path against a loopback server, through the guard's test seam.
/// Production passes `allow_private = false`; the route's HTTP tests prove that
/// refusal, and these prove what the fetch does once the guard has said yes —
/// including that an error never carries what the server said.
#[cfg(test)]
mod fetch_tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn marker() -> String {
        format!("internal-{}", uuid::Uuid::new_v4().simple())
    }

    #[tokio::test]
    async fn without_the_seam_every_loopback_private_and_plain_http_url_is_refused() {
        for url in [
            "https://127.0.0.1/metadata",
            "https://localhost/metadata",
            "https://10.0.0.5/metadata",
            "https://192.168.1.10/metadata",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/metadata",
            "http://sp.example.test/metadata",
            "ftp://sp.example.test/metadata",
            "https://user:pw@sp.example.test/metadata",
            "not a url",
            "https:///no-host",
        ] {
            assert_eq!(
                fetch_sp_metadata(url, false).await,
                Err(MetadataError::UrlRefused),
                "{url}"
            );
        }
    }

    #[tokio::test]
    async fn a_success_is_the_body_and_a_failure_is_a_category_never_the_body() {
        let server = MockServer::start().await;
        let secret = marker();
        Mock::given(method("GET"))
            .and(path("/ok"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<doc/>"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/boom"))
            .respond_with(ResponseTemplate::new(500).set_body_string(secret.clone()))
            .mount(&server)
            .await;
        let base = server.uri();
        assert_eq!(
            fetch_sp_metadata(&format!("{base}/ok"), true)
                .await
                .unwrap(),
            b"<doc/>"
        );
        let refused = fetch_sp_metadata(&format!("{base}/boom"), true)
            .await
            .unwrap_err();
        assert_eq!(refused, MetadataError::FetchFailed);
        assert!(!format!("{refused:?} {refused}").contains(&secret));
        let missing = fetch_sp_metadata(&format!("{base}/absent"), true)
            .await
            .unwrap_err();
        assert_eq!(
            missing,
            MetadataError::FetchFailed,
            "a 404 is a failed fetch"
        );
    }

    #[tokio::test]
    async fn the_response_is_capped_and_a_redirect_is_re_validated_strictly() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/big"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("x".repeat(MAX_SP_METADATA_BYTES + 1)),
            )
            .mount(&server)
            .await;
        // The first hop is admitted by the seam; the redirect target never is.
        Mock::given(method("GET"))
            .and(path("/bounce"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/ok", server.uri()).as_str()),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/ok"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<doc/>"))
            .mount(&server)
            .await;
        let base = server.uri();
        assert_eq!(
            fetch_sp_metadata(&format!("{base}/big"), true).await,
            Err(MetadataError::NotSpMetadata),
            "over the cap is not metadata"
        );
        assert_eq!(
            fetch_sp_metadata(&format!("{base}/bounce"), true).await,
            Err(MetadataError::UrlRefused),
            "a redirect hop is held to the production rule, which refuses loopback and http"
        );
    }
}
