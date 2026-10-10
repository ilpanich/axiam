//! Tests for receiving an `AuthnRequest` (T23.2.3).
//!
//! The SP's key and certificate are generated at runtime, once per test binary
//! (RSA-2048: an SP's key, not the IdP's). Assertion messages name the case,
//! never a key, a signature or a document.

use std::io::Write;
use std::sync::OnceLock;

use axiam_core::models::saml_sp::NameIdFormat;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{Duration, SecondsFormat, Utc};
use samael::crypto::{CryptoProvider, XmlSec};

use super::*;

const SP_ENTITY: &str = "https://sp.example.test/metadata";
const DESTINATION: &str = "https://axiam.example.test/saml/v2/t/sso";
const SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

struct SpKey {
    key_der: Vec<u8>,
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
    cert_der: Vec<u8>,
}

fn generate_sp_key() -> SpKey {
    let rsa = openssl::rsa::Rsa::generate(2048).expect("RSA generation");
    let pkey = openssl::pkey::PKey::from_rsa(rsa).expect("pkey");
    let pkcs8 = String::from_utf8(pkey.private_key_to_pem_pkcs8().expect("pkcs8")).expect("utf8");
    let key_pair = rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(&pkcs8, &rcgen::PKCS_RSA_SHA256)
        .expect("rcgen key");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "SP request-signing test");
    let cert = params.self_signed(&key_pair).expect("self-signed");
    SpKey {
        key_der: pkey.private_key_to_der().expect("der"),
        pkey,
        cert_der: cert.der().to_vec(),
    }
}

fn sp_key() -> &'static SpKey {
    static K: OnceLock<SpKey> = OnceLock::new();
    K.get_or_init(generate_sp_key)
}

fn other_key() -> &'static SpKey {
    static K: OnceLock<SpKey> = OnceLock::new();
    K.get_or_init(generate_sp_key)
}

fn instant(offset_secs: i64) -> String {
    (Utc::now() + Duration::seconds(offset_secs)).to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// An `AuthnRequest` with `extra` attributes on the root and `children` after
/// the `Issuer`.
fn request_with(id: &str, at: &str, extra: &str, children: &str) -> String {
    format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{at}" Destination="{DESTINATION}"{extra}><saml:Issuer>{SP_ENTITY}</saml:Issuer>{children}</samlp:AuthnRequest>"#
    )
}

fn request(id: &str) -> String {
    request_with(id, &instant(0), "", "")
}

/// The request, signed enveloped with `key`, the template after `Issuer`.
fn signed_with(id: &str, key: &SpKey) -> String {
    let template = super::super::sign::signature_template(id, &key.cert_der);
    let document = request_with(id, &instant(0), "", &template);
    let signed =
        <XmlSec as CryptoProvider>::sign_xml(document.as_bytes(), &key.key_der).expect("signing");
    super::super::xml::strip_declaration(&signed).to_owned()
}

fn deflate(document: &str) -> Vec<u8> {
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(document.as_bytes()).expect("deflate");
    encoder.finish().expect("deflate")
}

fn form_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// A signed Redirect-binding query string, signed over exactly what is sent.
fn redirect_query(document: &str, relay_state: Option<&str>, key: &SpKey) -> String {
    let mut query = format!(
        "SAMLRequest={}",
        form_encode(&STANDARD.encode(deflate(document)))
    );
    if let Some(relay) = relay_state {
        query.push_str(&format!("&RelayState={}", form_encode(relay)));
    }
    query.push_str(&format!("&SigAlg={}", form_encode(SHA256)));
    let signature = sign_octets(&query, key, openssl::hash::MessageDigest::sha256());
    query.push_str(&format!("&Signature={}", form_encode(&signature)));
    query
}

fn sign_octets(octets: &str, key: &SpKey, digest: openssl::hash::MessageDigest) -> String {
    let mut signer = openssl::sign::Signer::new(digest, &key.pkey).expect("signer");
    signer.update(octets.as_bytes()).expect("update");
    STANDARD.encode(signer.sign_to_vec().expect("sign"))
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

#[test]
fn a_redirect_request_round_trips() {
    let document = request("_r1");
    let encoded = STANDARD.encode(deflate(&document));
    assert_eq!(decode_redirect(&encoded).expect("decodes"), document);
    let parsed = parse_authn_request(&document, Utc::now()).expect("parses");
    assert_eq!(parsed.id, "_r1");
    assert_eq!(parsed.issuer, SP_ENTITY);
    assert_eq!(parsed.destination.as_deref(), Some(DESTINATION));
    assert!(!parsed.force_authn && !parsed.is_passive && !parsed.enveloped_signature);
}

/// **A decompression bomb is refused at the bound**: 16 MiB of zeros deflates
/// to a few kilobytes, well inside the encoded cap, and inflating stops one byte
/// past [`MAX_REQUEST_XML_BYTES`].
#[test]
fn a_decompression_bomb_is_refused_at_the_inflated_bound() {
    let bomb = deflate(&"\0".repeat(16 * 1024 * 1024));
    let encoded = STANDARD.encode(&bomb);
    assert!(
        encoded.len() < MAX_ENCODED_REQUEST_BYTES,
        "the bomb must pass the encoded cap to test the inflate cap"
    );
    assert_eq!(decode_redirect(&encoded), Err(RequestError::TooLarge));
    // One byte over the bound, of an otherwise plausible document.
    let over = deflate(&"a".repeat(MAX_REQUEST_XML_BYTES + 1));
    assert_eq!(
        decode_redirect(&STANDARD.encode(over)),
        Err(RequestError::TooLarge)
    );
}

#[test]
fn malformed_encodings_are_refused() {
    assert_eq!(decode_redirect(""), Err(RequestError::Encoding));
    assert_eq!(
        decode_redirect("!!!not-base64"),
        Err(RequestError::Encoding)
    );
    assert_eq!(
        decode_redirect(&STANDARD.encode(b"not deflate at all")),
        Err(RequestError::Inflate)
    );
    assert_eq!(
        decode_redirect(&"A".repeat(MAX_ENCODED_REQUEST_BYTES + 4)),
        Err(RequestError::TooLarge)
    );
    assert_eq!(decode_post("@@@@"), Err(RequestError::Encoding));
    assert_eq!(
        decode_post(&STANDARD.encode(vec![b'a'; MAX_REQUEST_XML_BYTES + 1])),
        Err(RequestError::TooLarge)
    );
    // Line breaks are tolerated on the POST binding.
    let document = request("_r2");
    let wrapped: String = STANDARD
        .encode(&document)
        .as_bytes()
        .chunks(76)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("\r\n");
    assert_eq!(decode_post(&wrapped).expect("decodes"), document);
}

// ---------------------------------------------------------------------------
// XML: declarations, entities, encodings
// ---------------------------------------------------------------------------

/// **XXE.** An external entity in the internal subset is refused on the bytes,
/// before libxml sees the document — and so before any SP lookup.
#[test]
fn an_external_entity_request_is_refused_before_parsing() {
    let xxe = format!(
        r#"<?xml version="1.0"?><!DOCTYPE samlp:AuthnRequest [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>{}"#,
        request_with("_x", &instant(0), "", "").replace(SP_ENTITY, "&xxe;")
    );
    assert_eq!(refuse_markup_declarations(&xxe), Err(RequestError::Dtd));
    assert_eq!(
        parse_authn_request(&xxe, Utc::now()).map(|_| ()),
        Err(RequestError::Dtd)
    );
    let parameter_entity =
        r#"<!DOCTYPE r [<!ENTITY % p SYSTEM "http://evil.example/x.dtd"> %p;]><r/>"#;
    assert_eq!(
        parse_authn_request(parameter_entity, Utc::now()).map(|_| ()),
        Err(RequestError::Dtd)
    );
}

/// **Billion laughs.** Refused on its bytes; nothing is expanded.
#[test]
fn a_billion_laughs_request_is_refused_before_parsing() {
    let mut dtd = String::from(r#"<!DOCTYPE lolz [<!ENTITY lol "lol">"#);
    for level in 1..=9 {
        let prev = if level == 1 {
            "lol".to_owned()
        } else {
            format!("lol{}", level - 1)
        };
        dtd.push_str(&format!(
            r#"<!ENTITY lol{level} "{}">"#,
            format!("&{prev};").repeat(10)
        ));
    }
    dtd.push_str("]>");
    let bomb = format!(
        "{dtd}{}",
        request_with("_b", &instant(0), "", "").replace(SP_ENTITY, "&lol9;")
    );
    assert_eq!(
        parse_authn_request(&bomb, Utc::now()).map(|_| ()),
        Err(RequestError::Dtd)
    );
    // Every declaration keyword, in any case, is refused; a comment and a
    // CDATA section are not declarations.
    for declaration in [
        "<!DOCTYPE x>",
        "<!doctype x>",
        "<!ENTITY x 'y'>",
        "<!ELEMENT x ANY>",
        "<!ATTLIST x y CDATA #IMPLIED>",
        "<!NOTATION x SYSTEM 'y'>",
    ] {
        assert_eq!(
            refuse_markup_declarations(&format!("{declaration}<x/>")),
            Err(RequestError::Dtd),
            "{declaration}"
        );
    }
    assert_eq!(
        refuse_markup_declarations("<!-- note --><x><![CDATA[text]]></x>"),
        Ok(())
    );
}

/// A document whose bytes are not plainly UTF-8 is refused: UTF-16 spells
/// `<!DOCTYPE` with NULs between the letters, which the byte scan would miss.
#[test]
fn a_document_in_another_encoding_is_refused() {
    let utf16: String = "<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><x>&e;</x>"
        .chars()
        .flat_map(|c| [c, '\0'])
        .collect();
    assert!(parse_authn_request(&utf16, Utc::now()).is_err());
    for declared in [
        r#"<?xml version="1.0" encoding="UTF-16"?>"#,
        r#"<?xml version="1.0" encoding='ISO-8859-1'?>"#,
    ] {
        let document = format!("{declared}{}", request("_e"));
        assert_eq!(
            parse_authn_request(&document, Utc::now()).map(|_| ()),
            Err(RequestError::Malformed),
            "{declared}"
        );
    }
    let utf8 = format!(r#"<?xml version="1.0" encoding="utf-8"?>{}"#, request("_e"));
    assert!(parse_authn_request(&utf8, Utc::now()).is_ok());
}

#[test]
fn malformed_xml_is_refused_not_repaired() {
    for broken in [
        "<samlp:AuthnRequest",
        "not xml",
        "<a><b></a>",
        "",
        &request("_m").replace("</samlp:AuthnRequest>", ""),
    ] {
        assert_eq!(
            parse_authn_request(broken, Utc::now()).map(|_| ()),
            Err(RequestError::Malformed)
        );
    }
}

// ---------------------------------------------------------------------------
// Shape
// ---------------------------------------------------------------------------

#[test]
fn only_a_saml_2_authn_request_is_accepted() {
    let logout = request("_l").replace("AuthnRequest", "LogoutRequest");
    let wrong_ns = request("_w").replace(
        "urn:oasis:names:tc:SAML:2.0:protocol",
        "urn:example:not-saml",
    );
    let version = request("_v").replace(r#"Version="2.0""#, r#"Version="1.1""#);
    for (label, document) in [
        ("logout", logout),
        ("namespace", wrong_ns),
        ("version", version),
    ] {
        assert_eq!(
            parse_authn_request(&document, Utc::now()).map(|_| ()),
            Err(RequestError::NotAnAuthnRequest),
            "{label}"
        );
    }
}

#[test]
fn the_id_issue_instant_and_issuer_are_checked() {
    let now = Utc::now();
    for (label, document, expected) in [
        (
            "an ID starting with a digit",
            request("1abc"),
            RequestError::InvalidId,
        ),
        (
            "an ID with markup",
            request_with("_a&quot;b", &instant(0), "", ""),
            RequestError::InvalidId,
        ),
        (
            "a request six and a half minutes old",
            request_with("_old", &instant(-390), "", ""),
            RequestError::Stale,
        ),
        (
            "a request from two minutes in the future",
            request_with("_future", &instant(120), "", ""),
            RequestError::Stale,
        ),
        (
            "an IssueInstant that is not a date",
            request_with("_d", "yesterday", "", ""),
            RequestError::InvalidField,
        ),
        (
            "no Issuer",
            request("_n").replace(&format!("<saml:Issuer>{SP_ENTITY}</saml:Issuer>"), ""),
            RequestError::InvalidField,
        ),
        (
            "two Issuers",
            request_with(
                "_two",
                &instant(0),
                "",
                &format!("<saml:Issuer>{SP_ENTITY}</saml:Issuer>"),
            ),
            RequestError::InvalidField,
        ),
        (
            "an Issuer that is not an entity",
            request("_f").replace(
                "<saml:Issuer>",
                r#"<saml:Issuer Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">"#,
            ),
            RequestError::InvalidField,
        ),
        (
            "a Subject",
            request_with(
                "_s",
                &instant(0),
                "",
                "<saml:Subject><saml:NameID>someone</saml:NameID></saml:Subject>",
            ),
            RequestError::SubjectUnsupported,
        ),
        (
            "ForceAuthn that is not a boolean",
            request_with("_fa", &instant(0), r#" ForceAuthn="yes""#, ""),
            RequestError::InvalidField,
        ),
        (
            "an ACS index that is not a number",
            request_with(
                "_i",
                &instant(0),
                r#" AssertionConsumerServiceIndex="x""#,
                "",
            ),
            RequestError::InvalidField,
        ),
    ] {
        assert_eq!(
            parse_authn_request(&document, now).map(|_| ()),
            Err(expected),
            "{label}"
        );
    }
    // The edges of the window are inside it.
    assert!(parse_authn_request(&request_with("_e1", &instant(-355), "", ""), now).is_ok());
    assert!(parse_authn_request(&request_with("_e2", &instant(55), "", ""), now).is_ok());
}

#[test]
fn the_fields_the_endpoint_acts_on_are_read() {
    let document = request_with(
        "_full",
        &instant(0),
        r#" ForceAuthn="true" IsPassive="1" AssertionConsumerServiceURL="https://sp.example.test/acs" AssertionConsumerServiceIndex="3" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST""#,
        r#"<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" AllowCreate="true"/>"#,
    );
    let parsed = parse_authn_request(&document, Utc::now()).expect("parses");
    assert!(parsed.force_authn && parsed.is_passive);
    assert_eq!(
        parsed.acs_url.as_deref(),
        Some("https://sp.example.test/acs")
    );
    assert_eq!(parsed.acs_index, Some(3));
    assert_eq!(parsed.protocol_binding.as_deref(), Some(BINDING_HTTP_POST));
    assert_eq!(
        parsed.name_id_format.as_deref(),
        Some(NameIdFormat::Persistent.urn())
    );
}

#[test]
fn name_id_policy_compatibility() {
    for configured in [NameIdFormat::Persistent, NameIdFormat::EmailAddress] {
        assert!(name_id_format_compatible(None, configured));
        assert!(name_id_format_compatible(
            Some(NAME_ID_FORMAT_UNSPECIFIED),
            configured
        ));
        assert!(name_id_format_compatible(
            Some(configured.urn()),
            configured
        ));
    }
    assert!(!name_id_format_compatible(
        Some(NameIdFormat::EmailAddress.urn()),
        NameIdFormat::Persistent
    ));
    assert!(!name_id_format_compatible(
        Some("urn:oasis:names:tc:SAML:2.0:nameid-format:transient"),
        NameIdFormat::Persistent
    ));
}

// ---------------------------------------------------------------------------
// HTTP-POST: the enveloped signature
// ---------------------------------------------------------------------------

#[test]
fn a_signed_post_request_verifies_against_the_sp_certificate_only() {
    let document = signed_with("_p1", sp_key());
    let parsed = parse_authn_request(&document, Utc::now()).expect("parses");
    assert!(parsed.enveloped_signature);
    assert_eq!(verify_post_signature(&document, &sp_key().cert_der), Ok(()));
    assert_eq!(
        verify_post_signature(&document, &other_key().cert_der),
        Err(RequestError::SignatureInvalid),
        "the wrong key"
    );
    let tampered = document.replace(DESTINATION, "https://axiam.example.test/saml/v2/u/sso");
    assert_eq!(
        verify_post_signature(&tampered, &sp_key().cert_der),
        Err(RequestError::SignatureInvalid),
        "a changed attribute"
    );
}

/// D-23's placement rule on the receiving side: one signature, the root's
/// enveloped child, referencing the root.
#[test]
fn a_signature_anywhere_else_refuses_the_request() {
    let signed = signed_with("_p2", sp_key());
    let signature_start = signed.find("<ds:Signature").expect("signature");
    let signature_end = signed.find("</ds:Signature>").expect("signature end") + 15;
    let signature = &signed[signature_start..signature_end];
    let unsigned = format!("{}{}", &signed[..signature_start], &signed[signature_end..]);

    // Inside Extensions rather than at the root.
    let nested = unsigned.replace(
        "</samlp:AuthnRequest>",
        &format!("<samlp:Extensions>{signature}</samlp:Extensions></samlp:AuthnRequest>"),
    );
    // Two signatures.
    let twice = signed.replace(
        "</samlp:AuthnRequest>",
        &format!("{signature}</samlp:AuthnRequest>"),
    );
    // A reference to some other element.
    let elsewhere = signed.replace(r##"URI="#_p2""##, r##"URI="#_other""##);
    for (label, document) in [
        ("nested", nested),
        ("twice", twice),
        ("elsewhere", elsewhere),
    ] {
        assert_eq!(
            parse_authn_request(&document, Utc::now()).map(|_| ()),
            Err(RequestError::SignaturePlacement),
            "{label}"
        );
    }
}

// ---------------------------------------------------------------------------
// HTTP-Redirect: the query signature over the exact octets
// ---------------------------------------------------------------------------

#[test]
fn a_signed_redirect_query_verifies_over_the_octets_received() {
    // Built once: `request` stamps IssueInstant from the clock, so two calls
    // straddling a second boundary would differ.
    let original = request("_q1");
    let query = redirect_query(&original, Some("relay/1+2"), sp_key());
    let parsed = RedirectQuery::parse(&query).expect("splits");
    assert!(parsed.is_signed());
    assert_eq!(parsed.verify_signature(&sp_key().cert_der), Ok(()));
    assert_eq!(parsed.relay_state().as_deref(), Some("relay/1+2"));
    assert_eq!(
        decode_redirect(&parsed.message()).expect("decodes"),
        original
    );
    assert_eq!(
        parsed.verify_signature(&other_key().cert_der),
        Err(RequestError::SignatureInvalid),
        "the wrong key"
    );
}

/// The octets as the SP encoded them, not a re-encoding: an SP that writes
/// lower-case percent escapes signs those, and AXIAM verifies those.
#[test]
fn an_sp_s_own_percent_encoding_is_what_is_verified() {
    let saml_request = STANDARD.encode(deflate(&request("_q2")));
    let lower = |s: &str| -> String {
        form_encode(s)
            .split('%')
            .enumerate()
            .map(|(i, part)| {
                if i == 0 {
                    part.to_owned()
                } else {
                    let (hex, rest) = part.split_at(2.min(part.len()));
                    format!("%{}{rest}", hex.to_ascii_lowercase())
                }
            })
            .collect()
    };
    let mut query = format!(
        "SAMLRequest={}&RelayState={}&SigAlg={}",
        lower(&saml_request),
        lower("a/b"),
        lower(SHA256)
    );
    let signature = sign_octets(&query, sp_key(), openssl::hash::MessageDigest::sha256());
    query.push_str(&format!("&Signature={}", form_encode(&signature)));
    let parsed = RedirectQuery::parse(&query).expect("splits");
    assert_eq!(parsed.verify_signature(&sp_key().cert_der), Ok(()));
}

#[test]
fn a_tampered_missing_or_weak_redirect_signature_is_refused() {
    let query = redirect_query(&request("_q3"), Some("relay"), sp_key());

    let tampered = query.replace("RelayState=relay", "RelayState=other");
    assert_eq!(
        RedirectQuery::parse(&tampered)
            .unwrap()
            .verify_signature(&sp_key().cert_der),
        Err(RequestError::SignatureInvalid),
        "a changed RelayState"
    );

    let dropped_relay = query.replace("&RelayState=relay", "");
    assert_eq!(
        RedirectQuery::parse(&dropped_relay)
            .unwrap()
            .verify_signature(&sp_key().cert_der),
        Err(RequestError::SignatureInvalid),
        "a removed RelayState"
    );

    let no_signature = query.split("&Signature=").next().unwrap().to_owned();
    assert_eq!(
        RedirectQuery::parse(&no_signature)
            .unwrap()
            .verify_signature(&sp_key().cert_der),
        Err(RequestError::SignatureMissing)
    );
    let unsigned = format!(
        "SAMLRequest={}",
        form_encode(&STANDARD.encode(deflate(&request("_q4"))))
    );
    let unsigned = RedirectQuery::parse(&unsigned).unwrap();
    assert!(!unsigned.is_signed());
    assert_eq!(
        unsigned.verify_signature(&sp_key().cert_der),
        Err(RequestError::SignatureMissing)
    );

    // SHA-1, signed correctly: refused for the algorithm.
    let mut sha1 = format!(
        "SAMLRequest={}&SigAlg={}",
        form_encode(&STANDARD.encode(deflate(&request("_q5")))),
        form_encode("http://www.w3.org/2000/09/xmldsig#rsa-sha1")
    );
    let signature = sign_octets(&sha1, sp_key(), openssl::hash::MessageDigest::sha1());
    sha1.push_str(&format!("&Signature={}", form_encode(&signature)));
    assert_eq!(
        RedirectQuery::parse(&sha1)
            .unwrap()
            .verify_signature(&sp_key().cert_der),
        Err(RequestError::SignatureAlgorithm)
    );
}

#[test]
fn a_repeated_redirect_parameter_is_refused() {
    let query = redirect_query(&request("_q6"), Some("relay"), sp_key());
    for repeated in [
        format!("{query}&RelayState=other"),
        format!("{query}&SAMLRequest=AAAA"),
        format!("{query}&SigAlg=x"),
        format!("{query}&Signature=x"),
    ] {
        assert_eq!(
            RedirectQuery::parse(&repeated).map(|_| ()),
            Err(RequestError::DuplicateParameter)
        );
    }
    assert_eq!(
        RedirectQuery::parse("RelayState=x").map(|_| ()),
        Err(RequestError::Encoding),
        "no SAMLRequest"
    );
    // Unrelated parameters are ignored.
    assert!(RedirectQuery::parse(&format!("{query}&utm_source=x")).is_ok());
}
