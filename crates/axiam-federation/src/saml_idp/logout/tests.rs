//! Tests for single logout's receiving and sending (T23.2.4).
//!
//! The IdP's credential (RSA-4096) and the SP's key (RSA-2048) are generated at
//! runtime, once per test binary. Assertion messages name the case, never a key,
//! a signature, a `NameID` or a document.

use std::sync::OnceLock;

use axiam_core::ca_keys::CaKeyCustody;
use axiam_core::models::saml_idp_credential::{SamlIdpCredential, SamlIdpCredentialStatus};
use axiam_core::models::saml_sp::{NameIdFormat, SamlBinding, SamlServiceProvider};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::SecondsFormat;
use samael::crypto::{CryptoProvider, XmlSec};
use zeroize::Zeroizing;

use super::super::request::verify_post_signature;
use super::*;

const SP_ENTITY: &str = "https://sp.example.test/metadata";
const SLO_URL: &str = "https://sp.example.test/saml/slo";
const BASE_URL: &str = "https://axiam.example.test";
const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

struct Material {
    key_pkcs8_pem: String,
    key_der: Vec<u8>,
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
    cert_pem: String,
    cert_der: Vec<u8>,
}

fn generate(bits: u32, name: &str) -> Material {
    let rsa = openssl::rsa::Rsa::generate(bits).expect("RSA generation");
    let pkey = openssl::pkey::PKey::from_rsa(rsa).expect("pkey");
    let key_pkcs8_pem =
        String::from_utf8(pkey.private_key_to_pem_pkcs8().expect("pkcs8")).expect("utf8");
    let key_pair =
        rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(&key_pkcs8_pem, &rcgen::PKCS_RSA_SHA256)
            .expect("rcgen key");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    let cert = params.self_signed(&key_pair).expect("self-signed");
    Material {
        key_pkcs8_pem,
        key_der: pkey.private_key_to_der().expect("der"),
        pkey,
        cert_pem: cert.pem(),
        cert_der: cert.der().to_vec(),
    }
}

fn idp() -> &'static Material {
    static M: OnceLock<Material> = OnceLock::new();
    M.get_or_init(|| generate(4096, "AXIAM SAML IdP logout test"))
}

fn sp_key() -> &'static Material {
    static M: OnceLock<Material> = OnceLock::new();
    M.get_or_init(|| generate(2048, "SP logout test"))
}

fn other_key() -> &'static Material {
    static M: OnceLock<Material> = OnceLock::new();
    M.get_or_init(|| generate(2048, "Not the SP"))
}

fn tenant() -> Uuid {
    static T: OnceLock<Uuid> = OnceLock::new();
    *T.get_or_init(Uuid::new_v4)
}

fn issuer() -> SamlIdpIssuer {
    SamlIdpIssuer::new(BASE_URL, None)
}

fn slo_destination() -> String {
    crate::saml_idp_urls::idp_slo_url(BASE_URL, tenant())
}

fn credential(status: SamlIdpCredentialStatus, valid_from_days: i64) -> SamlIdpCredential {
    SamlIdpCredential {
        id: Uuid::new_v4(),
        tenant_id: tenant(),
        issuer_ca_id: Uuid::new_v4(),
        certificate_pem: idp().cert_pem.clone(),
        serial: "01".into(),
        fingerprint: "00".into(),
        not_before: Utc::now() + Duration::days(valid_from_days),
        not_after: Utc::now() + Duration::days(valid_from_days + 30),
        status,
        key_custody: CaKeyCustody::Database,
        created_at: Utc::now(),
        retired_at: None,
    }
}

fn signing_key() -> SamlIdpSigningKey {
    SamlIdpSigningKey {
        credential: credential(SamlIdpCredentialStatus::Active, -1),
        private_key_pem: Zeroizing::new(idp().key_pkcs8_pem.clone()),
    }
}

fn sp(binding: Option<SamlBinding>) -> SamlServiceProvider {
    SamlServiceProvider {
        id: Uuid::new_v4(),
        tenant_id: tenant(),
        enabled: true,
        display_name: "SP".into(),
        entity_id: SP_ENTITY.into(),
        acs_urls: Vec::new(),
        slo_url: binding.map(|_| SLO_URL.into()),
        slo_binding: binding,
        name_id_format: NameIdFormat::Persistent,
        sign_responses: false,
        encrypt_assertions: false,
        sp_signing_cert_pem: None,
        sp_encryption_cert_pem: None,
        want_authn_requests_signed: false,
        allow_idp_initiated: false,
        attribute_mappings: Vec::new(),
        allowed_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn session_index() -> String {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    URL_SAFE_NO_PAD.encode(bytes)
}

fn at(offset_secs: i64) -> String {
    (Utc::now() + Duration::seconds(offset_secs)).to_rfc3339_opts(SecondsFormat::Secs, true)
}

// ---------------------------------------------------------------------------
// Documents an SP sends
// ---------------------------------------------------------------------------

/// A `LogoutRequest` with `extra` attributes on the root and `body` after the
/// `Issuer`.
fn request_with(id: &str, issued: &str, extra: &str, body: &str) -> String {
    format!(
        r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{issued}" Destination="{}"{extra}><saml:Issuer>{SP_ENTITY}</saml:Issuer>{body}</samlp:LogoutRequest>"#,
        slo_destination()
    )
}

fn name_id(value: &str) -> String {
    format!(r#"<saml:NameID Format="{PERSISTENT}">{value}</saml:NameID>"#)
}

fn request(id: &str, indexes: &[&str]) -> String {
    let indexes: String = indexes
        .iter()
        .map(|i| format!("<samlp:SessionIndex>{i}</samlp:SessionIndex>"))
        .collect();
    request_with(
        id,
        &at(0),
        "",
        &format!("{}{indexes}", name_id("subject-1")),
    )
}

fn response_with(id: &str, in_response_to: &str, status: &str) -> String {
    format!(
        r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{}" Destination="{}" InResponseTo="{in_response_to}"><saml:Issuer>{SP_ENTITY}</saml:Issuer><samlp:Status>{status}</samlp:Status></samlp:LogoutResponse>"#,
        at(0),
        slo_destination()
    )
}

const SUCCESS: &str = r#"<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>"#;

fn parse(document: &str) -> Result<ParsedLogoutMessage, RequestError> {
    parse_logout_message(document, Utc::now())
}

fn parse_request(document: &str) -> ParsedLogoutRequest {
    match parse(document).expect("parses") {
        ParsedLogoutMessage::Request(r) => r,
        ParsedLogoutMessage::Response(_) => panic!("a request"),
    }
}

fn refusal(document: &str) -> RequestError {
    parse(document).expect_err("must be refused")
}

fn signed_with(document_template: impl Fn(&str) -> String, id: &str, key: &Material) -> String {
    let template = sign::signature_template(id, &key.cert_der);
    let document = document_template(&template);
    let signed =
        <XmlSec as CryptoProvider>::sign_xml(document.as_bytes(), &key.key_der).expect("signing");
    xml::strip_declaration(&signed).to_owned()
}

fn signed_request(id: &str, key: &Material) -> String {
    signed_with(
        |template| {
            request_with(
                id,
                &at(0),
                "",
                &format!("{template}{}", name_id("subject-1")),
            )
        },
        id,
        key,
    )
}

// ---------------------------------------------------------------------------
// Parsing a request
// ---------------------------------------------------------------------------

#[test]
fn a_logout_request_parses_into_its_principal_and_indexes() {
    let parsed = parse_request(&request("_r1", &["idx-a", "idx-b", "idx-a"]));
    assert_eq!(parsed.id, "_r1");
    assert_eq!(parsed.issuer, SP_ENTITY);
    assert_eq!(
        parsed.destination.as_deref(),
        Some(slo_destination().as_str())
    );
    assert_eq!(parsed.name_id, "subject-1");
    assert_eq!(parsed.name_id_format.as_deref(), Some(PERSISTENT));
    assert_eq!(
        parsed.session_indexes,
        vec!["idx-a", "idx-b"],
        "in order, without repeats"
    );
    assert!(!parsed.enveloped_signature && parsed.not_on_or_after.is_none());

    let none = parse_request(&request("_r2", &[]));
    assert!(
        none.session_indexes.is_empty(),
        "no index: every session the SP holds for the NameID"
    );

    let printed = format!("{parsed:?}");
    assert!(
        !printed.contains("subject-1"),
        "Debug never prints a NameID"
    );
}

#[test]
fn the_principal_is_one_name_id_and_nothing_else() {
    let issued = at(0);
    let two = request_with(
        "_a",
        &issued,
        "",
        &format!("{}{}", name_id("a"), name_id("b")),
    );
    assert_eq!(refusal(&two), RequestError::NameIdMissing);
    let none = request_with(
        "_b",
        &issued,
        "",
        "<samlp:SessionIndex>x</samlp:SessionIndex>",
    );
    assert_eq!(refusal(&none), RequestError::NameIdMissing);
    let empty = request_with("_c", &issued, "", &name_id("   "));
    assert_eq!(refusal(&empty), RequestError::NameIdMissing);
    let base = request_with("_d", &issued, "", r#"<saml:BaseID>opaque</saml:BaseID>"#);
    assert_eq!(refusal(&base), RequestError::NameIdUnsupported);
    let encrypted = request_with(
        "_e",
        &issued,
        "",
        r#"<saml:EncryptedID><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/></saml:EncryptedID>"#,
    );
    assert_eq!(refusal(&encrypted), RequestError::NameIdUnsupported);
    // An EncryptedID beside a plain NameID is still refused: never "use the one
    // that is readable".
    let both = request_with(
        "_f",
        &issued,
        "",
        &format!("{}<saml:EncryptedID/>", name_id("a")),
    );
    assert_eq!(refusal(&both), RequestError::NameIdUnsupported);
}

#[test]
fn at_most_32_session_indexes_are_read() {
    let ok: Vec<String> = (0..MAX_SESSION_INDEXES).map(|i| format!("i{i}")).collect();
    let refs: Vec<&str> = ok.iter().map(String::as_str).collect();
    assert_eq!(
        parse_request(&request("_ok", &refs)).session_indexes.len(),
        MAX_SESSION_INDEXES
    );
    let over: Vec<String> = (0..=MAX_SESSION_INDEXES).map(|i| format!("i{i}")).collect();
    let refs: Vec<&str> = over.iter().map(String::as_str).collect();
    assert_eq!(
        refusal(&request("_over", &refs)),
        RequestError::TooManySessionIndexes
    );
    // Repeats count: the bound is on what is sent, not on what survives.
    let repeats: Vec<&str> = vec!["same"; MAX_SESSION_INDEXES + 1];
    assert_eq!(
        refusal(&request("_rep", &repeats)),
        RequestError::TooManySessionIndexes
    );
    assert_eq!(
        refusal(&request_with(
            "_empty",
            &at(0),
            "",
            &format!("{}<samlp:SessionIndex> </samlp:SessionIndex>", name_id("a"))
        )),
        RequestError::InvalidField
    );
    let long = "x".repeat(super::super::MAX_SESSION_INDEX_BYTES + 1);
    assert_eq!(
        refusal(&request("_long", &[long.as_str()])),
        RequestError::InvalidField
    );
}

#[test]
fn freshness_version_and_shape_are_checked() {
    let body = name_id("a");
    assert_eq!(
        refusal(&request_with("_old", &at(-600), "", &body)),
        RequestError::Stale
    );
    assert_eq!(
        refusal(&request_with("_future", &at(300), "", &body)),
        RequestError::Stale
    );
    let _ = parse(&request_with("_edge", &at(-250), "", &body)).expect("inside the window");
    assert_eq!(
        refusal(&request_with(
            "_x",
            &at(0),
            r#" NotOnOrAfter="2001-01-01T00:00:00Z""#,
            &body
        )),
        RequestError::Expired
    );
    let future = Utc::now() + Duration::minutes(5);
    let ok = request_with(
        "_nooa",
        &at(0),
        &format!(
            r#" NotOnOrAfter="{}""#,
            future.to_rfc3339_opts(SecondsFormat::Secs, true)
        ),
        &body,
    );
    assert!(parse_request(&ok).not_on_or_after.is_some());
    assert_eq!(
        refusal(
            &request_with("_v", &at(0), "", &body).replace(r#"Version="2.0""#, r#"Version="1.1""#)
        ),
        RequestError::NotALogoutMessage
    );
    assert_eq!(
        refusal(&request_with("1bad", &at(0), "", &body)),
        RequestError::InvalidId
    );
    assert_eq!(
        refusal(
            &request_with("_i", &at(0), "", &body)
                .replace(&format!("<saml:Issuer>{SP_ENTITY}</saml:Issuer>"), "")
        ),
        RequestError::InvalidField
    );
    assert_eq!(
        refusal(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_a" Version="2.0"/>"#
        ),
        RequestError::NotALogoutMessage
    );
    assert_eq!(refusal("not xml"), RequestError::Malformed);
    // The destination is reported as sent, for the endpoint to compare.
    let none = request_with("_d", &at(0), "", &body)
        .replace(&format!(r#" Destination="{}""#, slo_destination()), "");
    assert_eq!(parse(&none).expect("parses").destination(), None);
}

/// XXE and entity expansion are refused on the bytes, before libxml.
#[test]
fn a_dtd_or_entity_is_refused_before_parsing() {
    let xxe = format!(
        r#"<?xml version="1.0"?><!DOCTYPE samlp:LogoutRequest [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>{}"#,
        request("_x", &[]).replace("subject-1", "&xxe;")
    );
    assert_eq!(refusal(&xxe), RequestError::Dtd);
    let utf16_declared = r#"<?xml version="1.0" encoding="UTF-16"?><r/>"#;
    assert_eq!(refusal(utf16_declared), RequestError::Malformed);
}

// ---------------------------------------------------------------------------
// Parsing a response
// ---------------------------------------------------------------------------

#[test]
fn a_response_reports_what_the_sp_said() {
    let id = "_resp";
    let outcome = |status: &str| match parse(&response_with(id, "_req", status)).expect("parses") {
        ParsedLogoutMessage::Response(r) => r,
        ParsedLogoutMessage::Request(_) => panic!("a response"),
    };
    let ok = outcome(SUCCESS);
    assert_eq!(ok.status, LogoutStatus::Success);
    assert_eq!(ok.in_response_to, "_req");
    assert_eq!(ok.issuer, SP_ENTITY);
    assert_eq!(
        outcome(
            r#"<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:PartialLogout"/></samlp:StatusCode>"#
        )
        .status,
        LogoutStatus::PartialLogout
    );
    for failing in [
        r#"<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/>"#,
        r#"<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"/></samlp:StatusCode>"#,
        // Success with a nested code that is not PartialLogout is not Success.
        r#"<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"/></samlp:StatusCode>"#,
    ] {
        assert_eq!(outcome(failing).status, LogoutStatus::Failed);
    }
    // No Status, two Status codes, no InResponseTo.
    assert_eq!(
        refusal(&response_with(id, "_req", "")),
        RequestError::InvalidField
    );
    assert_eq!(
        refusal(&response_with(id, "_req", &format!("{SUCCESS}{SUCCESS}"))),
        RequestError::InvalidField
    );
    assert_eq!(
        refusal(&response_with(id, "_req", SUCCESS).replace(r#" InResponseTo="_req""#, "")),
        RequestError::InvalidField
    );
}

// ---------------------------------------------------------------------------
// Where a signature may sit
// ---------------------------------------------------------------------------

#[test]
fn one_enveloped_signature_on_the_root_is_reported_and_verifies() {
    let signed = signed_request("_s1", sp_key());
    let parsed = parse_request(&signed);
    assert!(parsed.enveloped_signature);
    verify_post_signature(&signed, &sp_key().cert_der).expect("verifies");
    assert_eq!(
        verify_post_signature(&signed, &other_key().cert_der),
        Err(RequestError::SignatureInvalid),
        "a wrong key"
    );
    let tampered = signed.replace("subject-1", "subject-2");
    assert_eq!(
        verify_post_signature(&tampered, &sp_key().cert_der),
        Err(RequestError::SignatureInvalid),
        "a changed byte"
    );
}

/// The D-23 rule for this root: a signature anywhere but the root's own child —
/// inside the `NameID`, a wrapper, a second one — refuses the document.
#[test]
fn a_signature_anywhere_but_the_roots_own_child_is_refused() {
    let template = sign::signature_template("_m1", &sp_key().cert_der);
    let placements = [
        // Inside an element the verifier would read.
        request_with(
            "_m1",
            &at(0),
            "",
            &format!(r#"<saml:NameID Format="{PERSISTENT}">a{template}</saml:NameID>"#),
        ),
        // After the SessionIndex, in an Extensions wrapper.
        request_with(
            "_m1",
            &at(0),
            "",
            &format!(
                "{}<samlp:Extensions>{template}</samlp:Extensions>",
                name_id("a")
            ),
        ),
        // Two signatures.
        request_with(
            "_m1",
            &at(0),
            "",
            &format!("{template}{template}{}", name_id("a")),
        ),
    ];
    for (n, document) in placements.iter().enumerate() {
        assert_eq!(
            refusal(document),
            RequestError::SignaturePlacement,
            "placement {n}"
        );
    }
    // A reference that names something else than the root.
    let mismatched = request_with(
        "_m2",
        &at(0),
        "",
        &format!(
            "{}{}",
            sign::signature_template("_somebody-else", &sp_key().cert_der),
            name_id("a")
        ),
    );
    assert_eq!(refusal(&mismatched), RequestError::SignaturePlacement);
}

// ---------------------------------------------------------------------------
// The Redirect binding, for either parameter
// ---------------------------------------------------------------------------

fn enc(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn redirect(param: &str, document: &str, relay: Option<&str>, key: &Material) -> String {
    let mut query = format!(
        "{param}={}",
        enc(&deflate_base64(document.as_bytes()).unwrap())
    );
    if let Some(relay) = relay {
        query.push_str(&format!("&RelayState={}", enc(relay)));
    }
    query.push_str(&format!("&SigAlg={}", enc(SHA256)));
    let mut signer =
        openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &key.pkey).unwrap();
    signer.update(query.as_bytes()).unwrap();
    let signature = STANDARD.encode(signer.sign_to_vec().unwrap());
    query.push_str(&format!("&Signature={}", enc(&signature)));
    query
}

#[test]
fn a_redirect_query_carries_one_message_and_is_signed_over_that_parameter() {
    for (param, expected) in [
        ("SAMLRequest", MessageParam::Request),
        ("SAMLResponse", MessageParam::Response),
    ] {
        let query = redirect(param, &request("_q", &[]), Some("rs"), sp_key());
        let parsed = RedirectQuery::parse_logout(&query).expect("splits");
        assert_eq!(parsed.param, expected);
        assert!(parsed.is_signed());
        assert_eq!(parsed.relay_state().as_deref(), Some("rs"));
        parsed
            .verify_signature(&sp_key().cert_der)
            .expect("verifies");
        assert_eq!(
            parsed.verify_signature(&other_key().cert_der),
            Err(RequestError::SignatureInvalid)
        );
        // The same octets under the other parameter's name were not signed.
        let renamed = query.replacen(
            param,
            if param == "SAMLRequest" {
                "SAMLResponse"
            } else {
                "SAMLRequest"
            },
            1,
        );
        let renamed = RedirectQuery::parse_logout(&renamed).expect("splits");
        assert_eq!(
            renamed.verify_signature(&sp_key().cert_der),
            Err(RequestError::SignatureInvalid),
            "the parameter's name is part of what is signed"
        );
    }
}

#[test]
fn a_query_naming_both_messages_or_repeating_one_is_refused() {
    let doc = enc(&deflate_base64(request("_q", &[]).as_bytes()).unwrap());
    assert_eq!(
        RedirectQuery::parse_logout(&format!("SAMLRequest={doc}&SAMLResponse={doc}")).map(|_| ()),
        Err(RequestError::DuplicateParameter)
    );
    assert_eq!(
        RedirectQuery::parse_logout(&format!("SAMLRequest={doc}&SAMLRequest={doc}")).map(|_| ()),
        Err(RequestError::DuplicateParameter)
    );
    assert_eq!(
        RedirectQuery::parse_logout("RelayState=x").map(|_| ()),
        Err(RequestError::Encoding)
    );
    // The SSO endpoint's parser still takes a SAMLRequest only.
    assert_eq!(
        RedirectQuery::parse(&format!("SAMLResponse={doc}")).map(|_| ()),
        Err(RequestError::Encoding)
    );
    let both = format!("SAMLRequest={doc}&SAMLResponse={doc}");
    let both_for_sso = RedirectQuery::parse(&both).expect("SSO ignores a SAMLResponse");
    assert_eq!(both_for_sso.param, MessageParam::Request);
}

// ---------------------------------------------------------------------------
// Sending: LogoutRequest
// ---------------------------------------------------------------------------

fn subject(index: &str) -> LogoutSubject<'_> {
    LogoutSubject {
        name_id: "subject-1",
        name_id_format: PERSISTENT,
        session_index: index,
    }
}

fn redirect_location(out: &OutboundLogout) -> &str {
    match &out.delivery {
        LogoutDelivery::Redirect { location } => location,
        LogoutDelivery::Post { .. } => panic!("a redirect"),
    }
}

fn posted(out: &OutboundLogout) -> (String, &'static str, String, Option<String>) {
    match &out.delivery {
        LogoutDelivery::Post {
            destination,
            field,
            value,
            relay_state,
        } => (
            destination.clone(),
            field,
            String::from_utf8(STANDARD.decode(value).unwrap()).unwrap(),
            relay_state.clone(),
        ),
        LogoutDelivery::Redirect { .. } => panic!("a post"),
    }
}

/// The document a Redirect-bound query carries, inflated.
fn inflated(query: &str) -> String {
    let parsed = RedirectQuery::parse_logout(query).expect("splits");
    super::super::request::decode_redirect(&parsed.message()).expect("inflates")
}

#[test]
fn a_redirect_logout_request_has_a_detached_signature_and_no_xml_signature() {
    let index = session_index();
    let out = issuer()
        .logout_request(
            tenant(),
            &sp(Some(SamlBinding::HttpRedirect)),
            &subject(&index),
            &signing_key(),
            Utc::now(),
        )
        .expect("issued");
    assert!(
        out.id.starts_with('_') && out.id.len() == 65,
        "256 random bits"
    );
    let location = redirect_location(&out);
    let (base, query) = location.split_once('?').expect("a query");
    assert_eq!(
        base, SLO_URL,
        "the registered endpoint, nothing from a message"
    );
    let parsed = RedirectQuery::parse_logout(query).expect("splits");
    assert_eq!(parsed.param, MessageParam::Request);
    parsed
        .verify_signature(&idp().cert_der)
        .expect("the detached signature verifies against the tenant credential");
    assert_eq!(
        parsed.verify_signature(&sp_key().cert_der),
        Err(RequestError::SignatureInvalid)
    );

    let document = inflated(query);
    assert!(
        !document.contains("Signature"),
        "no ds:Signature exists to harvest (T-373)"
    );
    // AXIAM's own receiver reads it back.
    let ParsedLogoutMessage::Request(read) = parse_logout_message(&document, Utc::now()).unwrap()
    else {
        panic!("a request")
    };
    assert_eq!(read.id, out.id);
    assert_eq!(read.issuer, issuer().entity_id(tenant()));
    assert_eq!(read.destination.as_deref(), Some(SLO_URL));
    assert_eq!(read.name_id, "subject-1");
    assert_eq!(read.name_id_format.as_deref(), Some(PERSISTENT));
    assert_eq!(read.session_indexes, vec![index.clone()]);
    assert!(read.not_on_or_after.is_some());
    assert!(!read.enveloped_signature);
    assert!(
        document.contains(r#"SPNameQualifier="https://sp.example.test/metadata""#),
        "a persistent NameID is qualified"
    );

    // A query on the registered URL keeps its own parameters.
    let mut with_query = sp(Some(SamlBinding::HttpRedirect));
    with_query.slo_url = Some(format!("{SLO_URL}?tenant=1"));
    let out = issuer()
        .logout_request(
            tenant(),
            &with_query,
            &subject(&index),
            &signing_key(),
            Utc::now(),
        )
        .unwrap();
    assert!(redirect_location(&out).starts_with(&format!("{SLO_URL}?tenant=1&SAMLRequest=")));
}

#[test]
fn a_post_logout_request_is_enveloped_and_verifies_under_the_roots_own_signature() {
    let index = session_index();
    let out = issuer()
        .logout_request(
            tenant(),
            &sp(Some(SamlBinding::HttpPost)),
            &subject(&index),
            &signing_key(),
            Utc::now(),
        )
        .expect("issued");
    let (destination, field, document, relay) = posted(&out);
    assert_eq!((destination.as_str(), field), (SLO_URL, "SAMLRequest"));
    assert!(relay.is_none());
    verify_post_signature(&document, &idp().cert_der).expect("verifies");
    assert_eq!(
        verify_post_signature(&document, &sp_key().cert_der),
        Err(RequestError::SignatureInvalid)
    );
    let ParsedLogoutMessage::Request(read) = parse_logout_message(&document, Utc::now()).unwrap()
    else {
        panic!("a request")
    };
    assert!(read.enveloped_signature, "one signature, the root's own");
    assert_eq!(read.id, out.id);
    assert_eq!(read.session_indexes, vec![index.clone()]);
    for needle in [
        "subject-1",
        index.as_str(),
        out.id.as_str(),
        "NotOnOrAfter=\"",
    ] {
        let tampered = document.replacen(
            needle,
            &needle.replace(|c: char| c.is_ascii_alphanumeric(), "z"),
            1,
        );
        assert_ne!(tampered, document);
        assert!(
            verify_post_signature(&tampered, &idp().cert_der).is_err(),
            "a change in {needle:?} breaks the signature"
        );
    }
}

#[test]
fn values_are_escaped_into_the_message() {
    let mut hostile = sp(Some(SamlBinding::HttpPost));
    hostile.entity_id = r#"https://sp.example.test/m"><injected/>"#.into();
    let index = session_index();
    let out = issuer()
        .logout_request(
            tenant(),
            &hostile,
            &LogoutSubject {
                name_id: r#"a"<b>&'c"#,
                name_id_format: PERSISTENT,
                session_index: &index,
            },
            &signing_key(),
            Utc::now(),
        )
        .expect("issued");
    let (_, _, document, _) = posted(&out);
    assert!(!document.contains("<injected/>"));
    let ParsedLogoutMessage::Request(read) = parse_logout_message(&document, Utc::now()).unwrap()
    else {
        panic!("a request")
    };
    assert_eq!(read.name_id, r#"a"<b>&'c"#, "round-trips through escaping");
}

// ---------------------------------------------------------------------------
// Sending: LogoutResponse
// ---------------------------------------------------------------------------

#[test]
fn a_logout_response_is_signed_on_both_bindings_and_reports_success_or_partial() {
    for binding in [SamlBinding::HttpRedirect, SamlBinding::HttpPost] {
        for partial in [false, true] {
            let out = issuer()
                .logout_response(
                    tenant(),
                    &sp(Some(binding)),
                    "_their-request",
                    Some("their relay"),
                    partial,
                    &signing_key(),
                    Utc::now(),
                )
                .expect("issued");
            let document = match binding {
                SamlBinding::HttpRedirect => {
                    let location = redirect_location(&out);
                    let query = location.split_once('?').unwrap().1;
                    let parsed = RedirectQuery::parse_logout(query).unwrap();
                    assert_eq!(parsed.param, MessageParam::Response);
                    assert_eq!(parsed.relay_state().as_deref(), Some("their relay"));
                    parsed.verify_signature(&idp().cert_der).expect("verifies");
                    let document = inflated(query);
                    assert!(!document.contains("Signature"), "detached only");
                    document
                }
                SamlBinding::HttpPost => {
                    let (_, field, document, relay) = posted(&out);
                    assert_eq!(field, "SAMLResponse");
                    assert_eq!(relay.as_deref(), Some("their relay"));
                    verify_post_signature(&document, &idp().cert_der).expect("verifies");
                    document
                }
            };
            let ParsedLogoutMessage::Response(read) =
                parse_logout_message(&document, Utc::now()).unwrap()
            else {
                panic!("a response")
            };
            assert_eq!(read.in_response_to, "_their-request");
            assert_eq!(read.destination.as_deref(), Some(SLO_URL));
            assert_eq!(
                read.status,
                if partial {
                    LogoutStatus::PartialLogout
                } else {
                    LogoutStatus::Success
                }
            );
        }
    }
}

#[test]
fn nothing_is_signed_for_an_input_that_is_not_in_order() {
    let index = session_index();
    let key = signing_key();
    let post = sp(Some(SamlBinding::HttpPost));
    let no_endpoint = sp(None);
    assert_eq!(
        issuer()
            .logout_request(tenant(), &no_endpoint, &subject(&index), &key, Utc::now())
            .map(|_| ()),
        Err(SamlIdpError::SloNotRegistered)
    );
    assert_eq!(
        issuer()
            .logout_response(tenant(), &no_endpoint, "_r", None, false, &key, Utc::now())
            .map(|_| ()),
        Err(SamlIdpError::SloNotRegistered)
    );
    assert_eq!(
        issuer()
            .logout_request(Uuid::new_v4(), &post, &subject(&index), &key, Utc::now())
            .map(|_| ()),
        Err(SamlIdpError::TenantMismatch),
        "another tenant's SP is never signed for"
    );
    for bad in ["", "has space", "a<b", &"x".repeat(300)] {
        assert_eq!(
            issuer()
                .logout_request(tenant(), &post, &subject(bad), &key, Utc::now())
                .map(|_| ()),
            Err(SamlIdpError::SessionIndexInvalid),
            "{bad:.10}"
        );
    }
    for bad in ["", "1starts-with-digit", "has space"] {
        assert_eq!(
            issuer()
                .logout_response(tenant(), &post, bad, None, false, &key, Utc::now())
                .map(|_| ()),
            Err(SamlIdpError::InvalidRequestId)
        );
    }
    assert_eq!(
        issuer()
            .logout_response(
                tenant(),
                &post,
                "_r",
                Some(&"r".repeat(81)),
                false,
                &key,
                Utc::now()
            )
            .map(|_| ()),
        Err(SamlIdpError::RelayStateTooLong)
    );
    // The credential: not active, or outside its validity window.
    let retired = SamlIdpSigningKey {
        credential: credential(SamlIdpCredentialStatus::Retired, -1),
        private_key_pem: Zeroizing::new(idp().key_pkcs8_pem.clone()),
    };
    let future = SamlIdpSigningKey {
        credential: credential(SamlIdpCredentialStatus::Active, 5),
        private_key_pem: Zeroizing::new(idp().key_pkcs8_pem.clone()),
    };
    for (label, bad) in [("retired", &retired), ("not yet valid", &future)] {
        assert!(
            issuer()
                .logout_request(tenant(), &post, &subject(&index), bad, Utc::now())
                .is_err(),
            "{label}"
        );
    }
}

#[test]
fn every_outbound_request_gets_its_own_256_bit_id() {
    let index = session_index();
    let post = sp(Some(SamlBinding::HttpPost));
    let ids: std::collections::BTreeSet<String> = (0..5)
        .map(|_| {
            issuer()
                .logout_request(
                    tenant(),
                    &post,
                    &subject(&index),
                    &signing_key(),
                    Utc::now(),
                )
                .unwrap()
                .id
        })
        .collect();
    assert_eq!(ids.len(), 5);
    assert!(
        ids.iter()
            .all(|id| id.len() == 65 && id[1..].bytes().all(|b| b.is_ascii_hexdigit()))
    );
}
