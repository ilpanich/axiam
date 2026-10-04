//! The tenant's IdP metadata document (G-2, T23.2.5, D-40).
//!
//! What a service provider's administrator pastes into their SP: one
//! `EntityDescriptor` for the tenant's IdP, with the certificates it will sign
//! assertions with and the SSO locations. Built from a **fixed template**, with
//! every value escaped through [`xml::escape`](super::xml::escape) — nothing is
//! serialized from a data structure, so nothing that is not named here can reach
//! the document.
//!
//! # What it carries
//!
//! * `entityID`, the two `SingleSignOnService` locations (HTTP-Redirect and
//!   HTTP-POST, both at the SSO endpoint) and the two `SingleLogoutService`
//!   locations (both at the SLO endpoint, T23.2.4) — passed in by the caller from
//!   [`idp_entity_id`](super::idp_entity_id),
//!   [`idp_sso_url`](super::idp_sso_url) and
//!   [`idp_slo_url`](super::idp_slo_url) of the **path** tenant, never from a
//!   stored row (T-307, T-367);
//! * one `KeyDescriptor use="signing"` per publishable credential, **`active`
//!   first and then `next`**, each an `X509Certificate` and nothing else, so an
//!   SP has the successor before it ever sees an assertion signed with it
//!   (T-309). A retired credential's key is destroyed and its certificate must
//!   stop being trusted, so it is never published;
//! * both `NameIDFormat`s the IdP can issue (persistent and `emailAddress`).
//!
//! # What it does not carry
//!
//! No encryption key (AXIAM decrypts nothing), no `validUntil`,
//! `cacheDuration`, `Organization` or `ContactPerson`. The `SingleLogoutService`
//! elements arrived in the commit that added the `/slo` route (T23.2.4): the
//! document never advertises a route that is not there.
//!
//! # Unsigned, on purpose
//!
//! Signing the metadata with the key it publishes anchors nothing — whoever
//! could swap the document could swap the key — and a signed `EntityDescriptor`
//! is one more document under the tenant key (T-316). Trust comes from TLS to the
//! deployment's origin and, for a careful SP administrator, from comparing the
//! SHA-256 fingerprint contract §29 shows.

use axiam_core::models::saml_idp_credential::{SamlIdpCredential, SamlIdpCredentialStatus};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

use super::xml::escape;

/// The metadata media type (SAML Metadata §4.1.1).
pub const IDP_METADATA_MEDIA_TYPE: &str = "application/samlmetadata+xml";

/// `Cache-Control` of the document: an hour (D-40). The rotation guidance is to
/// issue `next`, wait at least this long and the SPs' own refresh interval, and
/// only then promote.
pub const IDP_METADATA_CACHE_CONTROL: &str = "public, max-age=3600";

/// The SAML 2.0 protocol URN `protocolSupportEnumeration` names.
const PROTOCOL_SAML2: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
/// HTTP-Redirect binding.
const BINDING_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
/// HTTP-POST binding.
const BINDING_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
/// Persistent `NameIDFormat`.
const NAME_ID_PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
/// `emailAddress` `NameIDFormat`.
const NAME_ID_EMAIL: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

/// A rendered metadata document and its validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdpMetadataDocument {
    /// The document, UTF-8 XML.
    pub xml: String,
    /// A strong `ETag` — the SHA-256 of [`Self::xml`], hex, in double quotes.
    pub etag: String,
}

/// The credentials a metadata document publishes, in the order it publishes
/// them: `active`, then `next`; nothing else. A credential whose certificate
/// does not decode is not publishable (and is skipped, never half-written).
///
/// Returns each with its certificate's DER.
fn publishable(credentials: &[SamlIdpCredential]) -> Vec<(&SamlIdpCredential, Vec<u8>)> {
    [
        SamlIdpCredentialStatus::Active,
        SamlIdpCredentialStatus::Next,
    ]
    .into_iter()
    .filter_map(|wanted| {
        credentials
            .iter()
            .find(|c| c.status == wanted)
            .and_then(|c| {
                crate::cert::pem_cert_to_der(&c.certificate_pem)
                    .ok()
                    .map(|d| (c, d))
            })
    })
    .collect()
}

/// The tenant's metadata, or `None` when there is nothing to publish — no
/// `active` or `next` credential with a decodable certificate. The caller
/// answers that with the D-20 `404`, the same as a tenant that serves no SAML
/// (a `503` would tell anyone the tenant exists, T-368).
///
/// `slo_url` is the tenant's SLO endpoint when this deployment serves one —
/// always, since T23.2.4 — and `None` for a document that must not advertise a
/// logout route.
///
/// `credentials` is the tenant's keyless list ([`SamlIdpCredentialRepository::list`],
/// never `get_active_sealed`): at most one credential per status is published.
///
/// [`SamlIdpCredentialRepository::list`]: axiam_core::repository::SamlIdpCredentialRepository::list
#[must_use]
pub fn build_idp_metadata(
    entity_id: &str,
    sso_url: &str,
    slo_url: Option<&str>,
    credentials: &[SamlIdpCredential],
) -> Option<IdpMetadataDocument> {
    let keys = publishable(credentials);
    if keys.is_empty() {
        return None;
    }

    let mut xml = String::with_capacity(2048 + keys.len() * 2048);
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(
        "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" \
         xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"",
    );
    xml.push_str(&escape(entity_id));
    xml.push_str("\">\n  <md:IDPSSODescriptor protocolSupportEnumeration=\"");
    xml.push_str(PROTOCOL_SAML2);
    xml.push_str("\">\n");
    for (_, der) in &keys {
        // One line of standard base64: what every SP's parser reads, and what
        // the credential's own certificate decodes back from.
        xml.push_str(
            "    <md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data>\
             <ds:X509Certificate>",
        );
        xml.push_str(&STANDARD.encode(der));
        xml.push_str("</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>\n");
    }
    // Schema order (SAML Metadata §2.4.3): the key descriptors, then the logout
    // services, then the `NameIDFormat`s, then the sign-on services.
    if let Some(slo_url) = slo_url {
        for binding in [BINDING_REDIRECT, BINDING_POST] {
            xml.push_str("    <md:SingleLogoutService Binding=\"");
            xml.push_str(binding);
            xml.push_str("\" Location=\"");
            xml.push_str(&escape(slo_url));
            xml.push_str("\"/>\n");
        }
    }
    for format in [NAME_ID_PERSISTENT, NAME_ID_EMAIL] {
        xml.push_str("    <md:NameIDFormat>");
        xml.push_str(format);
        xml.push_str("</md:NameIDFormat>\n");
    }
    for binding in [BINDING_REDIRECT, BINDING_POST] {
        xml.push_str("    <md:SingleSignOnService Binding=\"");
        xml.push_str(binding);
        xml.push_str("\" Location=\"");
        xml.push_str(&escape(sso_url));
        xml.push_str("\"/>\n");
    }
    xml.push_str("  </md:IDPSSODescriptor>\n</md:EntityDescriptor>\n");

    let etag = format!("\"{}\"", hex::encode(Sha256::digest(xml.as_bytes())));
    Some(IdpMetadataDocument { xml, etag })
}

/// Whether an `If-None-Match` header value matches `etag` (RFC 9110 §13.1.2,
/// weak comparison): `*`, or any listed entity tag equal to `etag` once a `W/`
/// prefix is ignored. The caller answers `304` on `true`.
#[must_use]
pub fn if_none_match_matches(header: &str, etag: &str) -> bool {
    let wanted = etag.trim_start_matches("W/");
    header
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == "*" || candidate.trim_start_matches("W/") == wanted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::ca_keys::CaKeyCustody;
    use chrono::{Duration, Utc};
    use uuid::Uuid;

    /// A self-signed certificate generated now; no PEM literal in the source.
    fn cert_pem() -> String {
        let key = rcgen::KeyPair::generate().expect("key pair");
        rcgen::CertificateParams::new(vec!["idp.example.test".to_string()])
            .expect("params")
            .self_signed(&key)
            .expect("self-signed")
            .pem()
    }

    fn credential(status: SamlIdpCredentialStatus, pem: String) -> SamlIdpCredential {
        SamlIdpCredential {
            id: Uuid::new_v4(),
            tenant_id: Uuid::nil(),
            issuer_ca_id: Uuid::nil(),
            certificate_pem: pem,
            serial: "01".into(),
            fingerprint: "00".into(),
            not_before: Utc::now() - Duration::hours(1),
            not_after: Utc::now() + Duration::days(30),
            status,
            key_custody: CaKeyCustody::Database,
            created_at: Utc::now(),
            retired_at: None,
        }
    }

    fn body(credentials: &[SamlIdpCredential]) -> Option<IdpMetadataDocument> {
        build_idp_metadata(
            "https://iam.example.test/saml/v2/t/metadata",
            "https://iam.example.test/saml/v2/t/sso",
            Some("https://iam.example.test/saml/v2/t/slo"),
            credentials,
        )
    }

    fn der_b64(pem: &str) -> String {
        STANDARD.encode(crate::cert::pem_cert_to_der(pem).expect("der"))
    }

    #[test]
    fn active_is_published_before_next_whatever_the_list_order() {
        let (active, next) = (cert_pem(), cert_pem());
        let doc = body(&[
            credential(SamlIdpCredentialStatus::Next, next.clone()),
            credential(SamlIdpCredentialStatus::Active, active.clone()),
        ])
        .expect("publishable");
        let first = doc.xml.find(&der_b64(&active)).expect("active published");
        let second = doc.xml.find(&der_b64(&next)).expect("next published");
        assert!(first < second, "active comes first");
        assert_eq!(doc.xml.matches("<md:KeyDescriptor").count(), 2);
    }

    #[test]
    fn a_retired_credential_is_never_published_and_nothing_means_no_document() {
        let retired = cert_pem();
        assert!(
            body(&[credential(
                SamlIdpCredentialStatus::Retired,
                retired.clone()
            )])
            .is_none(),
            "only a retired credential: nothing to publish"
        );
        assert!(body(&[]).is_none());
        let active = cert_pem();
        let doc = body(&[
            credential(SamlIdpCredentialStatus::Retired, retired.clone()),
            credential(SamlIdpCredentialStatus::Active, active),
        ])
        .expect("active");
        assert!(!doc.xml.contains(&der_b64(&retired)));
        assert_eq!(doc.xml.matches("<md:KeyDescriptor").count(), 1);
    }

    #[test]
    fn a_certificate_that_does_not_decode_is_skipped_not_half_written() {
        let good = cert_pem();
        let doc = body(&[
            credential(SamlIdpCredentialStatus::Active, "not a certificate".into()),
            credential(SamlIdpCredentialStatus::Next, good.clone()),
        ])
        .expect("next is publishable");
        assert_eq!(doc.xml.matches("<md:KeyDescriptor").count(), 1);
        assert!(doc.xml.contains(&der_b64(&good)));
        assert!(
            body(&[credential(
                SamlIdpCredentialStatus::Active,
                "not a certificate".into()
            )])
            .is_none()
        );
    }

    #[test]
    fn the_template_carries_what_d40_names_and_nothing_else() {
        let doc = body(&[credential(SamlIdpCredentialStatus::Active, cert_pem())]).unwrap();
        let xml = &doc.xml;
        for needed in [
            "entityID=\"https://iam.example.test/saml/v2/t/metadata\"",
            "protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"",
            "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>",
            "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>",
            "Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" \
             Location=\"https://iam.example.test/saml/v2/t/sso\"",
            "Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" \
             Location=\"https://iam.example.test/saml/v2/t/sso\"",
            "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" \
             Location=\"https://iam.example.test/saml/v2/t/slo\"",
            "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" \
             Location=\"https://iam.example.test/saml/v2/t/slo\"",
        ] {
            assert!(xml.contains(needed), "missing {needed}");
        }
        for absent in [
            "use=\"encryption\"",
            "validUntil",
            "cacheDuration",
            "Organization",
            "ContactPerson",
            "WantAuthnRequestsSigned",
            "ds:Signature",
            "Extensions",
        ] {
            assert!(!xml.contains(absent), "must not carry {absent}");
        }
    }

    #[test]
    fn every_value_is_escaped_into_the_template() {
        let doc = build_idp_metadata(
            "https://x.test/a\"><evil/>&",
            "https://x.test/s?a=1&b=\"2\"<",
            Some("https://x.test/l?c=3&d=\"4\"<"),
            &[credential(SamlIdpCredentialStatus::Active, cert_pem())],
        )
        .unwrap();
        assert!(!doc.xml.contains("<evil/>"));
        assert!(doc.xml.contains("&quot;&gt;&lt;evil/&gt;&amp;"));
        assert!(doc.xml.contains("a=1&amp;b=&quot;2&quot;&lt;"));
        assert!(doc.xml.contains("c=3&amp;d=&quot;4&quot;&lt;"));
    }

    #[test]
    fn a_document_built_without_a_logout_url_advertises_no_logout_service() {
        let doc = build_idp_metadata(
            "https://iam.example.test/saml/v2/t/metadata",
            "https://iam.example.test/saml/v2/t/sso",
            None,
            &[credential(SamlIdpCredentialStatus::Active, cert_pem())],
        )
        .unwrap();
        assert!(!doc.xml.contains("SingleLogoutService"));
    }

    #[test]
    fn the_logout_services_sit_where_the_metadata_schema_puts_them() {
        let doc = body(&[credential(SamlIdpCredentialStatus::Active, cert_pem())]).unwrap();
        let key = doc.xml.find("<md:KeyDescriptor").unwrap();
        let slo = doc.xml.find("<md:SingleLogoutService").unwrap();
        let name_id = doc.xml.find("<md:NameIDFormat").unwrap();
        let sso = doc.xml.find("<md:SingleSignOnService").unwrap();
        assert!(key < slo && slo < name_id && name_id < sso);
        assert_eq!(doc.xml.matches("<md:SingleLogoutService").count(), 2);
    }

    #[test]
    fn the_etag_is_a_strong_digest_of_the_body_and_changes_with_it() {
        let one = body(&[credential(SamlIdpCredentialStatus::Active, cert_pem())]).unwrap();
        let again = build_idp_metadata(
            "https://iam.example.test/saml/v2/t/metadata",
            "https://iam.example.test/saml/v2/t/sso",
            Some("https://iam.example.test/saml/v2/t/slo"),
            &[credential(SamlIdpCredentialStatus::Active, cert_pem())],
        )
        .unwrap();
        assert!(one.etag.starts_with('"') && one.etag.ends_with('"'));
        assert!(!one.etag.starts_with("W/"));
        assert_eq!(one.etag.len(), 64 + 2);
        assert_ne!(
            one.etag, again.etag,
            "a different certificate, a different tag"
        );
        assert_eq!(
            one.etag,
            format!("\"{}\"", hex::encode(Sha256::digest(one.xml.as_bytes())))
        );
    }

    #[test]
    fn if_none_match_uses_weak_comparison_over_a_list_and_star() {
        let tag = "\"abc\"";
        assert!(if_none_match_matches("\"abc\"", tag));
        assert!(if_none_match_matches("W/\"abc\"", tag));
        assert!(if_none_match_matches("\"x\", \"abc\"", tag));
        assert!(if_none_match_matches("*", tag));
        assert!(!if_none_match_matches("\"abd\"", tag));
        assert!(!if_none_match_matches("", tag));
    }
}
