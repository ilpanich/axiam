//! Write-time rules for the SAML service-provider registry (G-2, T23.2.1).
//!
//! One pure function, [`validate_saml_service_provider`], decides whether a
//! [`SamlServiceProviderInput`] may be stored. It lives here and not in
//! `axiam-core` because it needs URL and X.509 parsing, which layer 0 does not
//! carry; and it is **not** behind the `saml` feature, because it parses no
//! XML and the registry is plain data (the SAML protocol code that uses it is
//! what the feature gates).
//!
//! # The ACS allow-list is a redirect-URI registration
//!
//! An `AssertionConsumerServiceURL` is where AXIAM sends a signed assertion, so
//! it is a redirect target in the OAuth2 sense: the same attacks (an assertion
//! delivered to an attacker's endpoint) and therefore the same registration
//! rules. [`check_redirect_uri_registration`] is that rule, and it is **the one
//! copy**: the admin API's `validate_redirect_uris`
//! (`axiam-api-rest`, layer 6) calls it rather than carrying its own, so the two
//! can never disagree about what a registrable redirect is. On top of it the ACS
//! list refuses any `*`, because the allow-list is exact strings and a wildcard
//! would be a glob by another name (the URL parser admits `*` in a host).
//!
//! The same URL rule is applied to `slo_url`.

use std::collections::HashSet;

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::saml_sp::{
    ATTRIBUTE_NAME_FORMATS, MAX_ACS_ENDPOINTS, MAX_ALLOWED_GROUPS, MAX_ATTRIBUTE_MAPPINGS,
    MAX_ATTRIBUTE_NAME_BYTES, MAX_DISPLAY_NAME_BYTES, MAX_ENTITY_ID_BYTES, MAX_SP_CERT_PEM_BYTES,
    SamlServiceProviderInput,
};
use x509_parser::prelude::{FromDer, X509Certificate};

/// Structural rules for a redirect URI, shared by the admin OAuth2 client
/// registration API, `POST /oauth2/register` and the SAML ACS allow-list.
///
/// Returns the refusal text on failure. The strings are the ones the admin API
/// has always answered with; callers wrap them in their own error type.
///
/// * absolute, with a host;
/// * `https`, except `http` for the loopback hosts `localhost`, `127.0.0.1` and
///   `[::1]` (`Url::host_str` spells an IPv6 literal with its brackets);
/// * no fragment (RFC 6749 §3.1.2).
///
/// # Errors
///
/// A human-readable message naming the offending URI.
pub fn check_redirect_uri_registration(uri: &str) -> Result<(), String> {
    let parsed: url::Url = uri
        .parse()
        .map_err(|_| format!("invalid redirect_uri: {uri}"))?;
    // Redirect URIs must be absolute with an authority (host)
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("redirect_uri must be an absolute URL with a host: {uri}"))?;
    // Allow http for localhost/loopback only, require HTTPS otherwise.
    //
    // `[::1]`, with the brackets, is what `Url::host_str` returns for an IPv6
    // literal. The rest of the stack always spelled it with brackets: the
    // redirect matcher's loopback arm (`axiam_oauth2::redirect_uri`), the DCR
    // host allow-list and the CIMD document validator all do. RFC 8252 §7.3
    // lists the IPv6 loopback beside `127.0.0.1`.
    let is_localhost = host == "localhost" || host == "127.0.0.1" || host == "[::1]";
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && is_localhost) {
        return Err(format!(
            "redirect_uri must use https (http is only allowed for localhost/127.0.0.1/[::1]): {uri}"
        ));
    }
    // RFC 6749 §3.1.2: redirect URIs must not include a fragment
    if parsed.fragment().is_some() {
        return Err(format!("redirect_uri must not contain a fragment: {uri}"));
    }
    Ok(())
}

/// Why a certificate PEM was refused. Never carries the PEM itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertDefect {
    TooLarge,
    NotPem,
    NotCertificateBlock,
    MoreThanOneBlock,
    Unparseable,
}

impl CertDefect {
    fn describe(self) -> &'static str {
        match self {
            Self::TooLarge => "is larger than the permitted size",
            Self::NotPem => "is not PEM",
            Self::NotCertificateBlock => {
                "is not a CERTIFICATE block (a private key must never be stored here)"
            }
            Self::MoreThanOneBlock => "holds more than one PEM block; exactly one is required",
            Self::Unparseable => "is not a parseable X.509 certificate",
        }
    }
}

/// Exactly one `CERTIFICATE` PEM block that parses as X.509.
///
/// A private key, a bundle, trailing blocks and DER-as-text are all refused:
/// the registry holds public material only.
fn check_certificate_pem(pem: &str) -> Result<(), CertDefect> {
    if pem.len() > MAX_SP_CERT_PEM_BYTES {
        return Err(CertDefect::TooLarge);
    }
    let (rest, block) =
        x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|_| CertDefect::NotPem)?;
    if block.label != "CERTIFICATE" {
        return Err(CertDefect::NotCertificateBlock);
    }
    if !rest.iter().all(u8::is_ascii_whitespace) {
        return Err(CertDefect::MoreThanOneBlock);
    }
    X509Certificate::from_der(&block.contents).map_err(|_| CertDefect::Unparseable)?;
    Ok(())
}

/// A name that is non-empty, within bounds, free of control characters and not
/// padded with whitespace.
fn check_plain_text(label: &str, value: &str, max_bytes: usize, out: &mut Vec<String>) {
    if value.trim().is_empty() {
        out.push(format!("{label} must not be empty"));
    } else if value.len() > max_bytes {
        out.push(format!("{label} must be at most {max_bytes} bytes"));
    } else if value != value.trim() {
        out.push(format!("{label} must not start or end with whitespace"));
    } else if value.chars().any(char::is_control) {
        out.push(format!("{label} must not contain control characters"));
    }
}

/// Every reason `input` may not be stored, in a stable order. Empty means it
/// may.
#[must_use]
pub fn saml_sp_violations(input: &SamlServiceProviderInput) -> Vec<String> {
    let mut v = Vec::new();

    check_plain_text(
        "display_name",
        &input.display_name,
        MAX_DISPLAY_NAME_BYTES,
        &mut v,
    );
    check_plain_text("entity_id", &input.entity_id, MAX_ENTITY_ID_BYTES, &mut v);

    // --- ACS allow-list ---
    if input.acs_urls.is_empty() {
        v.push("acs_urls must contain at least one endpoint".into());
    }
    if input.acs_urls.len() > MAX_ACS_ENDPOINTS {
        v.push(format!(
            "acs_urls may hold at most {MAX_ACS_ENDPOINTS} endpoints"
        ));
    }
    let mut seen_urls = HashSet::new();
    let mut seen_indexes = HashSet::new();
    for (position, endpoint) in input.acs_urls.iter().enumerate() {
        if let Err(msg) = check_redirect_uri_registration(&endpoint.url) {
            v.push(format!("acs_urls[{position}]: {msg}"));
        } else if endpoint.url.contains('*') {
            v.push(format!(
                "acs_urls[{position}]: wildcards are not allowed; an ACS URL is matched exactly"
            ));
        }
        if !seen_urls.insert(endpoint.url.as_str()) {
            v.push(format!(
                "acs_urls[{position}]: duplicate ACS URL (already registered above)"
            ));
        }
        if !seen_indexes.insert(endpoint.index) {
            v.push(format!(
                "acs_urls[{position}]: duplicate index {} (an AssertionConsumerServiceIndex must \
                 name one endpoint)",
                endpoint.index
            ));
        }
    }
    if input.acs_urls.iter().filter(|e| e.is_default).count() > 1 {
        v.push("acs_urls may mark at most one endpoint as the default".into());
    }

    // --- single logout ---
    match (&input.slo_url, &input.slo_binding) {
        (Some(url), Some(_)) => {
            if let Err(msg) = check_redirect_uri_registration(url) {
                v.push(format!("slo_url: {msg}"));
            } else if url.contains('*') {
                v.push("slo_url: wildcards are not allowed".into());
            }
        }
        (None, None) => {}
        (Some(_), None) => v.push("slo_binding is required when slo_url is set".into()),
        (None, Some(_)) => v.push("slo_binding must not be set without slo_url".into()),
    }

    // --- certificates ---
    for (label, cert) in [
        ("sp_signing_cert_pem", &input.sp_signing_cert_pem),
        ("sp_encryption_cert_pem", &input.sp_encryption_cert_pem),
    ] {
        if let Some(pem) = cert
            && let Err(defect) = check_certificate_pem(pem)
        {
            v.push(format!("{label} {}", defect.describe()));
        }
    }
    if input.encrypt_assertions && input.sp_encryption_cert_pem.is_none() {
        v.push("encrypt_assertions requires sp_encryption_cert_pem".into());
    }
    if input.want_authn_requests_signed && input.sp_signing_cert_pem.is_none() {
        v.push("want_authn_requests_signed requires sp_signing_cert_pem".into());
    }

    // --- attribute mappings ---
    if input.attribute_mappings.len() > MAX_ATTRIBUTE_MAPPINGS {
        v.push(format!(
            "attribute_mappings may hold at most {MAX_ATTRIBUTE_MAPPINGS} entries"
        ));
    }
    let mut seen_names = HashSet::new();
    for (position, mapping) in input.attribute_mappings.iter().enumerate() {
        let label = format!("attribute_mappings[{position}].saml_name");
        check_plain_text(&label, &mapping.saml_name, MAX_ATTRIBUTE_NAME_BYTES, &mut v);
        if !seen_names.insert(mapping.saml_name.as_str()) {
            v.push(format!(
                "attribute_mappings[{position}]: duplicate attribute name (names are \
                 case-sensitive and must be unique)"
            ));
        }
        if let Some(format) = &mapping.name_format
            && !ATTRIBUTE_NAME_FORMATS.contains(&format.as_str())
        {
            v.push(format!(
                "attribute_mappings[{position}].name_format is not a SAML attribute name format"
            ));
        }
    }

    // --- group restriction ---
    if input.allowed_groups.len() > MAX_ALLOWED_GROUPS {
        v.push(format!(
            "allowed_groups may name at most {MAX_ALLOWED_GROUPS} groups"
        ));
    }

    v
}

/// Whether `input` may be stored.
///
/// # Errors
///
/// [`AxiamError::Validation`] carrying every violation, joined by `; `.
pub fn validate_saml_service_provider(input: &SamlServiceProviderInput) -> AxiamResult<()> {
    let violations = saml_sp_violations(input);
    if violations.is_empty() {
        Ok(())
    } else {
        Err(AxiamError::Validation {
            message: violations.join("; "),
        })
    }
}

// ---------------------------------------------------------------------------
// D-42 — what a write must satisfy beyond the validator
// ---------------------------------------------------------------------------

/// The smallest RSA modulus an SP's request-signing certificate may carry, in
/// bits.
pub const MIN_SP_RSA_BITS: usize = 2048;

/// NIST curves an SP's ECDSA request-signing certificate may use, by OID: P-256,
/// P-384, P-521 (the three xmlsec verifies with `ecdsa-sha256/384/512`).
const SP_EC_CURVE_OIDS: [&str; 3] = ["1.2.840.10045.3.1.7", "1.3.132.0.34", "1.3.132.0.35"];

/// Why the SSO endpoint could not use `pem` as an SP's request-signing
/// certificate, or `None` when it can. The text names the rule and never the
/// certificate.
///
/// *Could not use* means one of: its decoder, [`crate::cert::pem_cert_to_der`] —
/// the very function the SSO endpoint calls, so the two cannot disagree — refuses
/// it; it is not X.509; or its public key is one no verifier AXIAM runs can use:
/// RSA under [`MIN_SP_RSA_BITS`] bits, or anything but RSA or ECDSA on P-256,
/// P-384 or P-521. (An ECDSA certificate verifies HTTP-POST requests only; the
/// HTTP-Redirect binding is RSA-only, which contract §29 says.) A certificate's
/// validity dates are **not** judged: SAML trusts a registered key as a key.
#[must_use]
pub fn sp_signing_certificate_refusal(pem: &str) -> Option<String> {
    const FIELD: &str = "sp_signing_cert_pem";
    let Ok(der) = crate::cert::pem_cert_to_der(pem) else {
        return Some(format!(
            "{FIELD} is not a certificate the SSO endpoint can decode"
        ));
    };
    let Ok((_, cert)) = X509Certificate::from_der(&der) else {
        return Some(format!("{FIELD} is not a parseable X.509 certificate"));
    };
    let spki = cert.public_key();
    match spki.parsed() {
        Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => {
            // Bits of the modulus, without the DER sign byte or leading zeros.
            let significant: &[u8] = rsa
                .modulus
                .iter()
                .position(|b| *b != 0)
                .map_or(&[][..], |at| &rsa.modulus[at..]);
            let bits = significant.first().map_or(0, |top| {
                significant.len() * 8 - top.leading_zeros() as usize
            });
            (bits < MIN_SP_RSA_BITS)
                .then(|| format!("{FIELD}: an RSA key must be at least {MIN_SP_RSA_BITS} bits"))
        }
        Ok(x509_parser::public_key::PublicKey::EC(_)) => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|oid| oid.to_id_string());
            curve
                .is_none_or(|oid| !SP_EC_CURVE_OIDS.contains(&oid.as_str()))
                .then(|| format!("{FIELD}: an ECDSA key must be on P-256, P-384 or P-521"))
        }
        _ => Some(format!(
            "{FIELD}: the key must be RSA (at least {MIN_SP_RSA_BITS} bits) or ECDSA on \
             P-256, P-384 or P-521"
        )),
    }
}

/// The write-time refusals of D-42 that need no database, each naming its rule
/// — beyond [`saml_sp_violations`], which the caller runs first:
///
/// * `encrypt_assertions: true` — assertion encryption is not implemented (D-2);
///   an SP asking for it would be refused at every sign-on, so it is refused
///   here, where the administrator can read why;
/// * an `sp_signing_cert_pem` the SSO endpoint cannot use
///   ([`sp_signing_certificate_refusal`]).
///
/// The other two — an `allowed_groups` entry outside the tenant and a changed
/// `entity_id` — need the datastore and the stored row, and are the route's.
#[must_use]
pub fn saml_sp_write_refusals(input: &SamlServiceProviderInput) -> Vec<String> {
    let mut refusals = Vec::new();
    if input.encrypt_assertions {
        refusals.push(
            "encrypt_assertions: assertion encryption is not supported yet; leave it false"
                .to_string(),
        );
    }
    if let Some(pem) = input.sp_signing_cert_pem.as_deref() {
        refusals.extend(sp_signing_certificate_refusal(pem));
    }
    refusals
}

/// [`validate_saml_service_provider`], then [`saml_sp_write_refusals`]: every
/// rule a registry write must satisfy that needs neither the datastore nor the
/// stored row.
///
/// # Errors
///
/// [`AxiamError::Validation`] carrying the violations of the first of the two
/// that has any, joined by `; `. The message never echoes a certificate.
pub fn validate_saml_service_provider_write(input: &SamlServiceProviderInput) -> AxiamResult<()> {
    validate_saml_service_provider(input)?;
    let refusals = saml_sp_write_refusals(input);
    if refusals.is_empty() {
        Ok(())
    } else {
        Err(AxiamError::Validation {
            message: refusals.join("; "),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::saml_sp::{
        AcsEndpoint, AttributeMapping, AttributeSource, NameIdFormat, SamlBinding,
    };
    use rcgen::{CertificateParams, KeyPair};
    use uuid::Uuid;

    /// A certificate generated at runtime; no PEM literal lives in the source.
    fn cert_pem() -> String {
        let key = KeyPair::generate().expect("generate a key pair");
        CertificateParams::new(vec!["sp.example.com".to_string()])
            .expect("params")
            .self_signed(&key)
            .expect("self-sign")
            .pem()
    }

    fn acs(url: &str, index: u16, is_default: bool) -> AcsEndpoint {
        AcsEndpoint {
            url: url.into(),
            binding: SamlBinding::HttpPost,
            index,
            is_default,
        }
    }

    /// An input that validates; each test breaks exactly one thing.
    fn valid() -> SamlServiceProviderInput {
        SamlServiceProviderInput {
            enabled: true,
            display_name: "Payroll".into(),
            entity_id: "https://payroll.example.com/saml/metadata".into(),
            acs_urls: vec![acs("https://payroll.example.com/saml/acs", 0, true)],
            slo_url: None,
            slo_binding: None,
            name_id_format: NameIdFormat::Persistent,
            sign_responses: true,
            encrypt_assertions: false,
            sp_signing_cert_pem: None,
            sp_encryption_cert_pem: None,
            want_authn_requests_signed: false,
            allow_idp_initiated: false,
            attribute_mappings: Vec::new(),
            allowed_groups: Vec::new(),
        }
    }

    fn refusal(input: &SamlServiceProviderInput) -> String {
        saml_sp_violations(input).join("; ")
    }

    #[test]
    fn the_minimal_input_is_accepted() {
        validate_saml_service_provider(&valid()).expect("a minimal SP is valid");
    }

    #[test]
    fn a_fully_populated_input_is_accepted() {
        let mut input = valid();
        input.acs_urls = vec![
            acs("https://payroll.example.com/saml/acs", 0, true),
            acs("https://payroll.example.com/saml/acs2", 1, false),
            acs("http://localhost:8080/acs", 2, false),
            acs("http://127.0.0.1/acs", 3, false),
            acs("http://[::1]/acs", 4, false),
        ];
        input.slo_url = Some("https://payroll.example.com/saml/slo".into());
        input.slo_binding = Some(SamlBinding::HttpRedirect);
        input.sp_signing_cert_pem = Some(cert_pem());
        input.sp_encryption_cert_pem = Some(cert_pem());
        input.want_authn_requests_signed = true;
        input.encrypt_assertions = true;
        input.attribute_mappings = vec![
            AttributeMapping {
                saml_name: "mail".into(),
                name_format: Some(ATTRIBUTE_NAME_FORMATS[1].into()),
                source: AttributeSource::Email,
            },
            AttributeMapping {
                saml_name: "groups".into(),
                name_format: None,
                source: AttributeSource::Groups,
            },
        ];
        input.allowed_groups = vec![Uuid::new_v4()];
        validate_saml_service_provider(&input).expect("a complete SP is valid");
    }

    #[test]
    fn zero_acs_urls_are_refused() {
        let mut input = valid();
        input.acs_urls.clear();
        assert!(refusal(&input).contains("at least one endpoint"));
    }

    #[test]
    fn a_duplicate_acs_url_is_refused() {
        let mut input = valid();
        input.acs_urls = vec![
            acs("https://payroll.example.com/saml/acs", 0, false),
            acs("https://payroll.example.com/saml/acs", 1, false),
        ];
        assert!(refusal(&input).contains("duplicate ACS URL"));
    }

    #[test]
    fn a_duplicate_acs_index_is_refused() {
        let mut input = valid();
        input.acs_urls = vec![
            acs("https://payroll.example.com/saml/acs", 7, false),
            acs("https://payroll.example.com/saml/acs2", 7, false),
        ];
        assert!(refusal(&input).contains("duplicate index 7"));
    }

    #[test]
    fn two_default_acs_endpoints_are_refused() {
        let mut input = valid();
        input.acs_urls = vec![
            acs("https://payroll.example.com/saml/acs", 0, true),
            acs("https://payroll.example.com/saml/acs2", 1, true),
        ];
        assert!(refusal(&input).contains("at most one endpoint as the default"));
    }

    #[test]
    fn more_than_the_permitted_number_of_acs_endpoints_is_refused() {
        let mut input = valid();
        input.acs_urls = (0..=MAX_ACS_ENDPOINTS)
            .map(|n| {
                acs(
                    &format!("https://payroll.example.com/acs/{n}"),
                    n as u16,
                    false,
                )
            })
            .collect();
        assert!(refusal(&input).contains("at most 32 endpoints"));
    }

    /// The accept/refuse list the OAuth2 redirect-URI registration applies,
    /// pinned here. `axiam-api-rest` pins the same list against its own entry
    /// point, and both call [`check_redirect_uri_registration`].
    const REDIRECT_ACCEPTED: &[&str] = &[
        "https://app.example.com/cb",
        "https://app.example.com:8443/cb?x=1",
        "http://localhost/cb",
        "http://localhost:3000/cb",
        "http://127.0.0.1/cb",
        "http://127.0.0.1:8080/cb",
        "http://[::1]/cb",
        "http://[::1]:9000/cb",
    ];
    const REDIRECT_REFUSED: &[&str] = &[
        "",
        "not a url",
        "/relative/path",
        "https://app.example.com/cb#frag",
        "http://app.example.com/cb",
        "http://localhost.example.com/cb",
        "ftp://app.example.com/cb",
        "javascript:alert(1)",
        "myapp://callback",
        "mailto:a@example.com",
    ];

    #[test]
    fn the_redirect_registration_rule_accepts_and_refuses_the_pinned_list() {
        for uri in REDIRECT_ACCEPTED {
            check_redirect_uri_registration(uri)
                .unwrap_or_else(|e| panic!("{uri} must be registrable: {e}"));
        }
        for uri in REDIRECT_REFUSED {
            assert!(
                check_redirect_uri_registration(uri).is_err(),
                "{uri} must not be registrable"
            );
        }
    }

    #[test]
    fn an_acs_url_is_refused_exactly_when_a_redirect_uri_would_be() {
        for uri in REDIRECT_ACCEPTED {
            let mut input = valid();
            input.acs_urls = vec![acs(uri, 0, false)];
            assert!(
                saml_sp_violations(&input).is_empty(),
                "{uri} must be accepted as an ACS URL"
            );
        }
        for uri in REDIRECT_REFUSED {
            let mut input = valid();
            input.acs_urls = vec![acs(uri, 0, false)];
            assert!(
                !saml_sp_violations(&input).is_empty(),
                "{uri} must be refused as an ACS URL"
            );
        }
    }

    #[test]
    fn a_wildcard_acs_url_is_refused() {
        for uri in [
            "https://*.example.com/acs",
            "https://payroll.example.com/*",
            "https://payroll.example.com/acs?next=*",
        ] {
            let mut input = valid();
            input.acs_urls = vec![acs(uri, 0, false)];
            assert!(
                refusal(&input).contains("wildcards are not allowed"),
                "{uri} must be refused as a glob"
            );
        }
    }

    #[test]
    fn an_acs_url_with_a_fragment_is_refused() {
        let mut input = valid();
        input.acs_urls = vec![acs("https://payroll.example.com/acs#x", 0, false)];
        assert!(refusal(&input).contains("fragment"));
    }

    #[test]
    fn a_plain_http_acs_url_is_refused_unless_it_is_loopback() {
        let mut input = valid();
        input.acs_urls = vec![acs("http://payroll.example.com/acs", 0, false)];
        assert!(refusal(&input).contains("https"));
    }

    #[test]
    fn an_empty_or_oversized_entity_id_is_refused() {
        let mut input = valid();
        input.entity_id = String::new();
        assert!(refusal(&input).contains("entity_id must not be empty"));
        input.entity_id = "   ".into();
        assert!(refusal(&input).contains("entity_id must not be empty"));
        input.entity_id = "x".repeat(MAX_ENTITY_ID_BYTES + 1);
        assert!(refusal(&input).contains("entity_id must be at most 1024 bytes"));
        input.entity_id = "x".repeat(MAX_ENTITY_ID_BYTES);
        assert!(
            saml_sp_violations(&input).is_empty(),
            "1024 bytes is allowed"
        );
    }

    #[test]
    fn a_padded_or_control_character_entity_id_is_refused() {
        let mut input = valid();
        input.entity_id = " https://payroll.example.com/m".into();
        assert!(refusal(&input).contains("whitespace"));
        input.entity_id = "https://payroll.example.com/\u{0}m".into();
        assert!(refusal(&input).contains("control characters"));
    }

    #[test]
    fn an_empty_display_name_is_refused() {
        let mut input = valid();
        input.display_name = String::new();
        assert!(refusal(&input).contains("display_name must not be empty"));
    }

    #[test]
    fn encryption_without_an_encryption_certificate_is_refused() {
        let mut input = valid();
        input.encrypt_assertions = true;
        assert!(refusal(&input).contains("encrypt_assertions requires sp_encryption_cert_pem"));
        input.sp_encryption_cert_pem = Some(cert_pem());
        assert!(saml_sp_violations(&input).is_empty());
    }

    #[test]
    fn signed_requests_without_a_signing_certificate_are_refused() {
        let mut input = valid();
        input.want_authn_requests_signed = true;
        assert!(
            refusal(&input).contains("want_authn_requests_signed requires sp_signing_cert_pem")
        );
        input.sp_signing_cert_pem = Some(cert_pem());
        assert!(saml_sp_violations(&input).is_empty());
    }

    #[test]
    fn an_unparseable_certificate_is_refused() {
        let mut input = valid();
        input.sp_signing_cert_pem = Some("not a certificate".into());
        assert!(refusal(&input).contains("sp_signing_cert_pem is not PEM"));

        // Well-formed PEM armour around bytes that are not X.509.
        input.sp_signing_cert_pem =
            Some("-----BEGIN CERTIFICATE-----\nAAAAAAAA\n-----END CERTIFICATE-----\n".into());
        assert!(refusal(&input).contains("not a parseable X.509 certificate"));

        input.sp_signing_cert_pem = None;
        input.sp_encryption_cert_pem = Some(String::new());
        assert!(refusal(&input).contains("sp_encryption_cert_pem"));
    }

    #[test]
    fn a_private_key_is_never_accepted_as_a_certificate() {
        let key = KeyPair::generate()
            .expect("generate a key pair")
            .serialize_pem();
        let mut input = valid();
        input.sp_signing_cert_pem = Some(key.clone());
        assert!(refusal(&input).contains("private key must never be stored"));
        input.sp_signing_cert_pem = None;
        input.sp_encryption_cert_pem = Some(key);
        assert!(refusal(&input).contains("private key must never be stored"));

        // A certificate followed by a key in the same field is a bundle: refused.
        let mut input = valid();
        let bundle = format!(
            "{}{}",
            cert_pem(),
            KeyPair::generate()
                .expect("generate a key pair")
                .serialize_pem()
        );
        input.sp_signing_cert_pem = Some(bundle);
        assert!(refusal(&input).contains("more than one PEM block"));
    }

    #[test]
    fn two_certificates_in_one_field_are_refused() {
        let mut input = valid();
        input.sp_signing_cert_pem = Some(format!("{}{}", cert_pem(), cert_pem()));
        assert!(refusal(&input).contains("more than one PEM block"));
    }

    #[test]
    fn an_oversized_certificate_is_refused() {
        let mut input = valid();
        input.sp_signing_cert_pem = Some(" ".repeat(MAX_SP_CERT_PEM_BYTES + 1));
        assert!(refusal(&input).contains("larger than the permitted size"));
    }

    fn mapping(name: &str) -> AttributeMapping {
        AttributeMapping {
            saml_name: name.into(),
            name_format: None,
            source: AttributeSource::Email,
        }
    }

    #[test]
    fn a_duplicate_attribute_name_is_refused_and_names_are_case_sensitive() {
        let mut input = valid();
        input.attribute_mappings = vec![mapping("mail"), mapping("mail")];
        assert!(refusal(&input).contains("duplicate attribute name"));
        input.attribute_mappings = vec![mapping("mail"), mapping("Mail")];
        assert!(saml_sp_violations(&input).is_empty());
    }

    #[test]
    fn an_empty_oversized_or_padded_attribute_name_is_refused() {
        let mut input = valid();
        input.attribute_mappings = vec![mapping("")];
        assert!(refusal(&input).contains("saml_name must not be empty"));
        input.attribute_mappings = vec![mapping(&"a".repeat(MAX_ATTRIBUTE_NAME_BYTES + 1))];
        assert!(refusal(&input).contains("saml_name must be at most 256 bytes"));
        input.attribute_mappings = vec![mapping(" mail")];
        assert!(refusal(&input).contains("whitespace"));
        input.attribute_mappings = vec![mapping("ma\nil")];
        assert!(refusal(&input).contains("control characters"));
    }

    #[test]
    fn an_unknown_attribute_name_format_is_refused() {
        let mut input = valid();
        input.attribute_mappings = vec![AttributeMapping {
            saml_name: "mail".into(),
            name_format: Some("urn:example:made-up".into()),
            source: AttributeSource::Email,
        }];
        assert!(refusal(&input).contains("not a SAML attribute name format"));
    }

    #[test]
    fn the_attribute_mapping_list_is_bounded() {
        let mut input = valid();
        input.attribute_mappings = (0..=MAX_ATTRIBUTE_MAPPINGS)
            .map(|n| mapping(&format!("attr{n}")))
            .collect();
        assert!(refusal(&input).contains("at most 64 entries"));
        input.attribute_mappings.pop();
        assert!(saml_sp_violations(&input).is_empty());
    }

    #[test]
    fn slo_url_and_slo_binding_travel_together_and_obey_the_url_rule() {
        let mut input = valid();
        input.slo_url = Some("https://payroll.example.com/slo".into());
        assert!(refusal(&input).contains("slo_binding is required"));
        input.slo_url = None;
        input.slo_binding = Some(SamlBinding::HttpPost);
        assert!(refusal(&input).contains("slo_binding must not be set without slo_url"));
        input.slo_url = Some("http://payroll.example.com/slo".into());
        assert!(refusal(&input).contains("slo_url:"));
        input.slo_url = Some("https://*.example.com/slo".into());
        assert!(refusal(&input).contains("slo_url: wildcards"));
    }

    #[test]
    fn the_allowed_group_list_is_bounded() {
        let mut input = valid();
        input.allowed_groups = (0..=MAX_ALLOWED_GROUPS).map(|_| Uuid::new_v4()).collect();
        assert!(refusal(&input).contains("at most 256 groups"));
    }

    #[test]
    fn every_violation_is_reported_together() {
        let mut input = valid();
        input.entity_id = String::new();
        input.acs_urls.clear();
        input.encrypt_assertions = true;
        let all = refusal(&input);
        assert!(all.contains("entity_id"));
        assert!(all.contains("acs_urls"));
        assert!(all.contains("encrypt_assertions"));
        let err = validate_saml_service_provider(&input).expect_err("refused");
        assert!(matches!(err, AxiamError::Validation { .. }));
    }
}

/// The D-42 certificate rule, on real keys of every kind it names. Needs
/// OpenSSL's RSA generation (`test_support`), which is behind `saml`.
#[cfg(all(test, feature = "saml"))]
mod write_refusal_tests {
    use super::*;
    use crate::saml_idp::test_support::rsa_material;
    use axiam_core::models::saml_sp::{AcsEndpoint, SamlBinding};

    fn ec_pem(algorithm: &'static rcgen::SignatureAlgorithm) -> String {
        let key = rcgen::KeyPair::generate_for(algorithm).expect("key pair");
        rcgen::CertificateParams::new(vec!["sp.example.test".to_string()])
            .expect("params")
            .self_signed(&key)
            .expect("self-signed")
            .pem()
    }

    /// A self-signed certificate over an EC key on `curve`, by OpenSSL (rcgen
    /// here has no P-521).
    fn openssl_ec_pem(curve: openssl::nid::Nid) -> String {
        use openssl::{asn1, ec, hash, nid, pkey, x509};
        let group = ec::EcGroup::from_curve_name(curve).expect("curve");
        let pair =
            pkey::PKey::from_ec_key(ec::EcKey::generate(&group).expect("ec key")).expect("pkey");
        let mut name = x509::X509NameBuilder::new().expect("name");
        name.append_entry_by_nid(nid::Nid::COMMONNAME, "sp")
            .expect("cn");
        let name = name.build();
        let mut builder = x509::X509Builder::new().expect("builder");
        builder.set_version(2).expect("version");
        builder.set_subject_name(&name).expect("subject");
        builder.set_issuer_name(&name).expect("issuer");
        builder.set_pubkey(&pair).expect("pubkey");
        builder
            .set_not_before(&asn1::Asn1Time::days_from_now(0).expect("nb"))
            .expect("nb");
        builder
            .set_not_after(&asn1::Asn1Time::days_from_now(30).expect("na"))
            .expect("na");
        builder
            .sign(&pair, hash::MessageDigest::sha256())
            .expect("sign");
        String::from_utf8(builder.build().to_pem().expect("pem")).expect("utf8")
    }

    fn input() -> SamlServiceProviderInput {
        SamlServiceProviderInput {
            enabled: true,
            display_name: "Payroll".into(),
            entity_id: "https://payroll.example.com/saml/metadata".into(),
            acs_urls: vec![AcsEndpoint {
                url: "https://payroll.example.com/acs".into(),
                binding: SamlBinding::HttpPost,
                index: 0,
                is_default: true,
            }],
            slo_url: None,
            slo_binding: None,
            name_id_format: Default::default(),
            sign_responses: true,
            encrypt_assertions: false,
            sp_signing_cert_pem: None,
            sp_encryption_cert_pem: None,
            want_authn_requests_signed: false,
            allow_idp_initiated: false,
            attribute_mappings: Vec::new(),
            allowed_groups: Vec::new(),
        }
    }

    #[test]
    fn rsa_from_2048_bits_and_ecdsa_on_the_three_nist_curves_are_usable() {
        for (label, pem) in [
            ("rsa-2048", rsa_material(2048, "sp", 30).cert_pem),
            ("p-256", ec_pem(&rcgen::PKCS_ECDSA_P256_SHA256)),
            ("p-384", ec_pem(&rcgen::PKCS_ECDSA_P384_SHA384)),
            ("p-521", openssl_ec_pem(openssl::nid::Nid::SECP521R1)),
        ] {
            assert_eq!(sp_signing_certificate_refusal(&pem), None, "{label}");
        }
    }

    #[test]
    fn a_short_rsa_key_a_non_rsa_non_ecdsa_key_and_garbage_are_refused_by_rule() {
        let short = rsa_material(1024, "sp", 30).cert_pem;
        let refusal = sp_signing_certificate_refusal(&short).expect("1024-bit RSA");
        assert!(refusal.starts_with("sp_signing_cert_pem") && refusal.contains("2048"));

        // An EC curve outside the three is refused too.
        let koblitz = openssl_ec_pem(openssl::nid::Nid::SECP256K1);
        let refusal = sp_signing_certificate_refusal(&koblitz).expect("secp256k1");
        assert!(
            refusal.contains("P-256") && refusal.contains("P-521"),
            "{refusal}"
        );

        let ed25519 = ec_pem(&rcgen::PKCS_ED25519);
        let refusal = sp_signing_certificate_refusal(&ed25519).expect("Ed25519");
        assert!(refusal.contains("RSA") && refusal.contains("P-256"));

        for garbage in [
            "",
            "not a pem",
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
        ] {
            let refusal = sp_signing_certificate_refusal(garbage).expect("garbage");
            assert!(refusal.starts_with("sp_signing_cert_pem"), "{refusal}");
        }
        // Dates are not judged: an expired certificate is usable as a key.
        let mut params =
            rcgen::CertificateParams::new(vec!["old.example.test".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2001, 1, 1);
        params.not_after = rcgen::date_time_ymd(2002, 1, 1);
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        assert_eq!(
            sp_signing_certificate_refusal(&params.self_signed(&key).unwrap().pem()),
            None
        );
    }

    #[test]
    fn the_write_rules_run_after_the_validator_and_name_each_refusal() {
        assert!(validate_saml_service_provider_write(&input()).is_ok());

        let mut encrypting = input();
        encrypting.encrypt_assertions = true;
        encrypting.sp_encryption_cert_pem = Some(ec_pem(&rcgen::PKCS_ECDSA_P256_SHA256));
        let error = validate_saml_service_provider_write(&encrypting).expect_err("encryption");
        assert!(error.to_string().contains("encrypt_assertions"), "{error}");

        let mut weak = input();
        weak.sp_signing_cert_pem = Some(rsa_material(1024, "sp", 30).cert_pem);
        let error = validate_saml_service_provider_write(&weak).expect_err("weak key");
        let text = error.to_string();
        assert!(
            text.contains("sp_signing_cert_pem") && !text.contains("BEGIN"),
            "{text}"
        );

        // The validator's own refusals come first and stand alone.
        let mut invalid = input();
        invalid.display_name = String::new();
        invalid.encrypt_assertions = true;
        let text = validate_saml_service_provider_write(&invalid)
            .unwrap_err()
            .to_string();
        assert!(
            text.contains("display_name") && !text.contains("not supported yet"),
            "{text}"
        );
    }
}
