//! Tests for the SAML IdP issuer (T23.2.2).
//!
//! The oracles, strongest first: AXIAM's own SP verifier
//! (`SamlFederationService::handle_saml_response_for`, which runs signature
//! verification, the XSW binding check, `Conditions`, the bearer confirmation
//! and replay); xmlsec directly against the credential's certificate; and the
//! parsed document. Keys and certificates are generated at runtime, once per
//! test binary.

use std::str::FromStr;
use std::sync::OnceLock;

use axiam_core::ca_keys::CaKeyCustody;
use axiam_core::models::group::Group;
use axiam_core::models::role::Role;
use axiam_core::models::saml_idp_credential::{SamlIdpCredential, SamlIdpCredentialStatus};
use axiam_core::models::saml_sp::{
    AcsEndpoint, AttributeMapping, AttributeSource, NameIdFormat, SamlBinding, SamlServiceProvider,
};
use axiam_core::models::session::{Amr, Session};
use axiam_core::models::user::{OIDC_METADATA_KEY, User, UserStatus};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Duration, SubsecRound, Utc};
use samael::crypto::{
    AllowedSignatureAlgorithm, CertificateDer, CryptoProvider, ReduceMode, XmlSec,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::*;
use crate::saml::tests::{
    RecordingLinkRepo, RecordingUserRepo, make_acs_service, test_federation_config,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SP_ENTITY: &str = "https://sp.example.test/metadata";
const ACS: &str = "https://sp.example.test/acs";
const ACS_2: &str = "https://sp.example.test/acs/second";
const ACS_REDIRECT: &str = "https://sp.example.test/acs/redirect";
const BASE_URL: &str = "https://axiam.example.test/";
const REQUEST_ID: &str = "_request-7f3a.1";

/// An RSA-4096 key and a self-signed certificate carrying the `SamlSigning`
/// profile (keyUsage digitalSignature, EKU id-kp-documentSigning, no SAN).
struct Material {
    key_pkcs8_pem: String,
    key_pkcs1_pem: String,
    cert_pem: String,
}

fn generate_material() -> Material {
    let rsa = openssl::rsa::Rsa::generate(4096).expect("RSA-4096 generation");
    let pkey = openssl::pkey::PKey::from_rsa(rsa).expect("pkey");
    let key_pkcs8_pem =
        String::from_utf8(pkey.private_key_to_pem_pkcs8().expect("pkcs8")).expect("utf8");
    let key_pkcs1_pem = String::from_utf8(
        pkey.rsa()
            .expect("rsa")
            .private_key_to_pem()
            .expect("pkcs1"),
    )
    .expect("utf8");
    let key_pair =
        rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(&key_pkcs8_pem, &rcgen::PKCS_RSA_SHA256)
            .expect("rcgen key");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "AXIAM SAML IdP test");
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::Other(vec![
        1, 3, 6, 1, 5, 5, 7, 3, 36,
    ])];
    let cert = params.self_signed(&key_pair).expect("self-signed");
    Material {
        key_pkcs8_pem,
        key_pkcs1_pem,
        cert_pem: cert.pem(),
    }
}

/// The tenant's current credential.
fn material() -> &'static Material {
    static M: OnceLock<Material> = OnceLock::new();
    M.get_or_init(generate_material)
}

/// A second credential, as after a rotation.
fn rotated_material() -> &'static Material {
    static M: OnceLock<Material> = OnceLock::new();
    M.get_or_init(generate_material)
}

fn tenant() -> Uuid {
    static T: OnceLock<Uuid> = OnceLock::new();
    *T.get_or_init(Uuid::new_v4)
}

fn now() -> DateTime<Utc> {
    Utc::now().trunc_subsecs(0)
}

fn pairwise_key() -> PairwiseKey {
    static BYTES: OnceLock<[u8; 32]> = OnceLock::new();
    let bytes = BYTES.get_or_init(|| {
        let mut b = [0u8; 32];
        b[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        b[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        b
    });
    PairwiseKey::new(*bytes)
}

/// A second pairwise key, distinct from [`pairwise_key`], minted at run time
/// (never a literal: CodeQL `rust/hard-coded-cryptographic-value`).
fn other_pairwise_key() -> PairwiseKey {
    let mut b = [0u8; 32];
    b[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    b[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    PairwiseKey::new(b)
}

fn issuer() -> SamlIdpIssuer {
    SamlIdpIssuer::new(BASE_URL, Some(pairwise_key()))
}

fn credential_for(m: &Material, tenant_id: Uuid) -> SamlIdpCredential {
    SamlIdpCredential {
        id: Uuid::new_v4(),
        tenant_id,
        issuer_ca_id: Uuid::new_v4(),
        certificate_pem: m.cert_pem.clone(),
        serial: "01".into(),
        fingerprint: "00".into(),
        not_before: now() - Duration::days(1),
        not_after: now() + Duration::days(30),
        status: SamlIdpCredentialStatus::Active,
        key_custody: CaKeyCustody::Database,
        created_at: now(),
        retired_at: None,
    }
}

fn signing_key_from(m: &Material, credential: SamlIdpCredential) -> SamlIdpSigningKey {
    SamlIdpSigningKey {
        credential,
        private_key_pem: Zeroizing::new(m.key_pkcs8_pem.clone()),
    }
}

fn signing_key() -> SamlIdpSigningKey {
    signing_key_from(material(), credential_for(material(), tenant()))
}

fn endpoint(url: &str, binding: SamlBinding, index: u16) -> AcsEndpoint {
    AcsEndpoint {
        url: url.into(),
        binding,
        index,
        is_default: index == 0,
    }
}

fn sp() -> SamlServiceProvider {
    SamlServiceProvider {
        id: Uuid::new_v4(),
        tenant_id: tenant(),
        enabled: true,
        display_name: "Test SP".into(),
        entity_id: SP_ENTITY.into(),
        acs_urls: vec![
            endpoint(ACS, SamlBinding::HttpPost, 0),
            endpoint(ACS_2, SamlBinding::HttpPost, 1),
            endpoint(ACS_REDIRECT, SamlBinding::HttpRedirect, 2),
        ],
        slo_url: None,
        slo_binding: None,
        name_id_format: NameIdFormat::Persistent,
        sign_responses: false,
        encrypt_assertions: false,
        sp_signing_cert_pem: None,
        sp_encryption_cert_pem: None,
        want_authn_requests_signed: false,
        allow_idp_initiated: false,
        attribute_mappings: Vec::new(),
        allowed_groups: Vec::new(),
        created_at: now(),
        updated_at: now(),
    }
}

fn user_in(tenant_id: Uuid) -> User {
    User {
        id: Uuid::new_v4(),
        tenant_id,
        username: "ada".into(),
        email: "ada@example.test".into(),
        password_hash: String::new(),
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
        phone_number: None,
        phone_number_verified_at: None,
        address: None,
        directory_external_id: None,
        metadata: serde_json::json!({
            OIDC_METADATA_KEY: {
                "name": "Ada Lovelace",
                "given_name": "Ada",
                "family_name": "Lovelace",
            }
        }),
        created_at: now(),
        updated_at: now(),
    }
}

fn user() -> User {
    user_in(tenant())
}

fn session_for(user: &User) -> Session {
    Session {
        id: Uuid::new_v4(),
        tenant_id: user.tenant_id,
        user_id: user.id,
        token_hash: String::new(),
        ip_address: None,
        user_agent: None,
        expires_at: now() + Duration::hours(1),
        created_at: now(),
        authenticated_at: now() - Duration::minutes(7),
        amr: vec![Amr::Pwd],
        browser_token_hash: None,
        refresh_replay_at: None,
        refresh_replay_grace_accepted: 0,
        refresh_replay_refused: 0,
    }
}

fn group(name: &str) -> Group {
    Group {
        id: Uuid::new_v4(),
        tenant_id: tenant(),
        name: name.into(),
        description: String::new(),
        metadata: serde_json::Value::Null,
        created_at: now(),
        updated_at: now(),
    }
}

fn role(name: &str) -> Role {
    Role {
        id: Uuid::new_v4(),
        tenant_id: tenant(),
        name: name.into(),
        description: String::new(),
        is_global: true,
        created_at: now(),
        updated_at: now(),
    }
}

/// What the participant record mints: 32 CSPRNG bytes, base64url, no padding.
fn mint_session_index() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    URL_SAFE_NO_PAD.encode(bytes)
}

/// One change to a [`Case`].
type Edit = Box<dyn Fn(&mut Case)>;

/// Everything one issuance needs, owned, so a test can bend one input.
struct Case {
    sp: SamlServiceProvider,
    user: User,
    session: Session,
    groups: Vec<Group>,
    roles: Vec<Role>,
    acs: String,
    request_id: Option<String>,
    relay_state: Option<String>,
    /// The per-SP index the endpoint recorded (D-37): random, and never the
    /// session id.
    session_index: String,
}

impl Case {
    fn new() -> Self {
        let user = user();
        let session = session_for(&user);
        Self {
            sp: sp(),
            user,
            session,
            groups: Vec::new(),
            roles: Vec::new(),
            acs: ACS.into(),
            request_id: Some(REQUEST_ID.into()),
            relay_state: Some("relay-1".into()),
            session_index: mint_session_index(),
        }
    }

    fn req(&self) -> SsoIssuance<'_> {
        SsoIssuance {
            tenant_id: tenant(),
            sp: &self.sp,
            acs_url: &self.acs,
            in_response_to: self.request_id.as_deref(),
            relay_state: self.relay_state.as_deref(),
            session: &self.session,
            session_index: &self.session_index,
            user: &self.user,
            groups: &self.groups,
            roles: &self.roles,
        }
    }

    fn issue(&self) -> Result<IssuedResponse, SamlIdpError> {
        issuer().issue(&self.req(), &signing_key(), Utc::now())
    }

    fn issue_ok(&self) -> IssuedResponse {
        self.issue().expect("issuance must succeed")
    }
}

fn decode(issued: &IssuedResponse) -> String {
    String::from_utf8(
        STANDARD
            .decode(&issued.binding.saml_response)
            .expect("base64"),
    )
    .expect("utf8")
}

fn decode_binding(binding: &PostBinding) -> String {
    String::from_utf8(STANDARD.decode(&binding.saml_response).expect("base64")).expect("utf8")
}

fn cert_der(m: &Material) -> CertificateDer {
    CertificateDer::from(crate::cert::pem_cert_to_der(&m.cert_pem).expect("cert der"))
}

fn xpath(xml: &str, path: &str) -> Vec<String> {
    let doc = libxml::parser::Parser::default()
        .parse_string(xml.as_bytes())
        .expect("parse");
    let mut ctx = libxml::xpath::Context::new(&doc).expect("ctx");
    ctx.findnodes(path, None)
        .expect("xpath")
        .iter()
        .map(libxml::tree::Node::get_content)
        .collect()
}

fn one(xml: &str, path: &str) -> String {
    let values = xpath(xml, path);
    assert_eq!(values.len(), 1, "{path}: {values:?}");
    values.into_iter().next().expect("one value")
}

fn parse(xml: &str) -> samael::schema::Response {
    samael::schema::Response::from_str(xml).expect("samael parses the response")
}

fn verify_first_signature(xml: &str, m: &Material) -> bool {
    <XmlSec as CryptoProvider>::verify_signed_xml(xml.as_bytes(), &cert_der(m), Some("ID")).is_ok()
}

fn verify_every_signature(xml: &str, m: &Material) -> Result<String, samael::crypto::CryptoError> {
    <XmlSec as CryptoProvider>::reduce_xml_to_signed_with_allowed_algorithms(
        xml,
        &[cert_der(m)],
        ReduceMode::ValidateAndMarkNoAncestors,
        Some(&[AllowedSignatureAlgorithm::RsaSha256]),
    )
}

/// The SP-side config that trusts this credential for this SP.
fn sp_config() -> axiam_core::models::federation::FederationConfig {
    let mut config = test_federation_config(Some(material().cert_pem.clone()));
    config.client_id = SP_ENTITY.into();
    config.provider_kind = axiam_core::models::federation::ProviderKind::GenericSaml;
    config.attribute_map = serde_json::json!({ "email": "mail" });
    config
}

/// Drive a response through AXIAM's own SP: signature, XSW binding,
/// `Conditions`, bearer confirmation, replay, claims.
async fn sp_accepts(
    xml: &str,
    expected_request_id: Option<&str>,
    expected_destination: Option<&str>,
    require_in_response_to: bool,
) -> Result<crate::oidc::FederationCallbackResult, crate::error::FederationError> {
    let config = sp_config();
    let service = make_acs_service(
        Some(config.clone()),
        RecordingLinkRepo::provisioning(),
        RecordingUserRepo::provisioning(),
    );
    service
        .handle_saml_response_for(
            &config,
            config.tenant_id,
            &STANDARD.encode(xml.as_bytes()),
            None,
            expected_request_id,
            expected_destination,
            require_in_response_to,
        )
        .await
}

/// Change one byte of `xml`: the last character of the first occurrence of
/// `needle`, to a different character of the same class.
fn flip_last_char_of(xml: &str, needle: &str) -> String {
    flip_after(xml, 0, needle)
}

/// [`flip_last_char_of`], searching only inside the assertion.
fn flip_in_assertion(xml: &str, needle: &str) -> String {
    let from = xml.find("<saml:Assertion").expect("an assertion");
    flip_after(xml, from, needle)
}

fn flip_after(xml: &str, from: usize, needle: &str) -> String {
    let start = from
        + xml[from..]
            .find(needle)
            .unwrap_or_else(|| panic!("{needle} not in the document"));
    let at = start + needle.len() - 1;
    let old = xml.as_bytes()[at];
    let new = match old {
        b'0'..=b'8' => old + 1,
        b'9' => b'0',
        b'a'..=b'y' | b'A'..=b'Y' => old + 1,
        b'z' => b'a',
        b'Z' => b'A',
        _ => b'x',
    };
    let mut bytes = xml.as_bytes().to_vec();
    bytes[at] = new;
    String::from_utf8(bytes).expect("ascii flip keeps utf8")
}

// ---------------------------------------------------------------------------
// Round trip and signature verification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_signed_assertion_is_accepted_by_axiam_own_sp_verifier() {
    for sign_responses in [false, true] {
        let mut case = Case::new();
        case.sp.sign_responses = sign_responses;
        let issued = case.issue_ok();
        let xml = decode(&issued);

        let result = sp_accepts(&xml, Some(REQUEST_ID), Some(ACS), true)
            .await
            .unwrap_or_else(|e| {
                panic!("sign_responses={sign_responses}: AXIAM's SP refused it: {e:?}")
            });
        assert_eq!(result.federation_link.external_subject, issued.name_id);
        assert!(result.newly_provisioned);
        assert_eq!(
            result.upstream_auth_time,
            Some(case.session.authenticated_at.trunc_subsecs(0)),
            "AuthnInstant reaches the SP as the session's authenticated_at"
        );
    }
}

#[tokio::test]
async fn an_idp_initiated_response_is_accepted_without_in_response_to() {
    let mut case = Case::new();
    case.sp.allow_idp_initiated = true;
    case.request_id = None;
    let xml = decode(&case.issue_ok());

    assert!(xpath(&xml, "/*/@InResponseTo").is_empty());
    assert!(
        xpath(
            &xml,
            "//*[local-name()='SubjectConfirmationData']/@InResponseTo"
        )
        .is_empty()
    );
    sp_accepts(&xml, None, Some(ACS), false)
        .await
        .expect("an unsolicited response verifies when the SP expects none");
    // AXIAM's own SP refuses unsolicited responses by policy, which is the
    // right answer for a response that has no InResponseTo.
    assert!(sp_accepts(&xml, None, Some(ACS), true).await.is_err());
}

#[test]
fn xmlsec_verifies_every_signature_against_the_credential_certificate_only() {
    for sign_responses in [false, true] {
        let mut case = Case::new();
        case.sp.sign_responses = sign_responses;
        let xml = decode(&case.issue_ok());
        verify_every_signature(&xml, material())
            .unwrap_or_else(|e| panic!("sign_responses={sign_responses}: {e}"));
        assert!(verify_first_signature(&xml, material()));
        // Another certificate verifies nothing.
        assert!(verify_every_signature(&xml, rotated_material()).is_err());
        assert!(!verify_first_signature(&xml, rotated_material()));
    }
}

#[test]
fn the_signing_certificate_is_in_key_info() {
    let xml = decode(&Case::new().issue_ok());
    let der = crate::cert::pem_cert_to_der(&material().cert_pem).expect("der");
    assert_eq!(
        one(&xml, "//*[local-name()='X509Certificate']"),
        STANDARD.encode(der)
    );
}

#[test]
fn the_algorithms_are_rsa_sha256_sha256_and_exclusive_c14n() {
    let mut case = Case::new();
    case.sp.sign_responses = true;
    let xml = decode(&case.issue_ok());
    for path in [
        "//*[local-name()='SignatureMethod']/@Algorithm",
        "//*[local-name()='DigestMethod']/@Algorithm",
        "//*[local-name()='CanonicalizationMethod']/@Algorithm",
    ] {
        let values = xpath(&xml, path);
        assert_eq!(values.len(), 2, "{path}");
        assert!(values.iter().all(|v| v == &values[0]));
    }
    assert_eq!(
        xpath(&xml, "//*[local-name()='SignatureMethod']/@Algorithm")[0],
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    );
    assert_eq!(
        xpath(&xml, "//*[local-name()='DigestMethod']/@Algorithm")[0],
        "http://www.w3.org/2001/04/xmlenc#sha256"
    );
    assert_eq!(
        xpath(
            &xml,
            "//*[local-name()='CanonicalizationMethod']/@Algorithm"
        )[0],
        "http://www.w3.org/2001/10/xml-exc-c14n#"
    );
}

#[test]
fn a_single_changed_byte_in_any_signed_element_fails_verification() {
    let mut case = Case::new();
    case.groups = vec![group("engineering")];
    case.sp.attribute_mappings = vec![AttributeMapping {
        saml_name: "groups".into(),
        name_format: None,
        source: AttributeSource::Groups,
    }];
    let issued = case.issue_ok();
    let xml = decode(&issued);
    assert!(verify_first_signature(&xml, material()));

    // The assertion is the signed element: every part of it is covered.
    let session_index = case.session_index.clone();
    let issuer_text = format!(">{}", idp_entity_id(BASE_URL, tenant()));
    let not_on_or_after = format!("NotOnOrAfter=\"{}", xml::instant(issued.not_on_or_after));
    for needle in [
        issued.name_id.as_str(),
        issuer_text.as_str(),
        ">https://sp.example.test/metadata",
        "Recipient=\"https://sp.example.test/acs",
        not_on_or_after.as_str(),
        session_index.as_str(),
        "PasswordProtectedTransport",
        ">engineering",
        issued.assertion_id.as_str(),
    ] {
        let tampered = flip_in_assertion(&xml, needle);
        assert_ne!(tampered, xml);
        assert!(
            !verify_first_signature(&tampered, material()),
            "a change in {needle:?} must break the assertion signature"
        );
    }
    // A change outside the signed assertion (the unsigned envelope) leaves the
    // assertion's signature intact, which is why the SP never trusts the
    // envelope's Destination or InResponseTo alone.
    let envelope_change = flip_last_char_of(&xml, "Destination=\"https://sp.example.test/acs");
    assert!(verify_first_signature(&envelope_change, material()));
}

#[test]
fn with_response_signing_on_both_signatures_verify_and_the_response_signature_covers_the_signed_assertion()
 {
    let mut case = Case::new();
    case.sp.sign_responses = true;
    let issued = case.issue_ok();
    let xml = decode(&issued);

    // Two signatures: the response's, a child of the root, first in document
    // order; then the assertion's, inside it.
    let references = xpath(&xml, "//*[local-name()='Reference']/@URI");
    assert_eq!(
        references,
        vec![
            format!("#{}", issued.response_id),
            format!("#{}", issued.assertion_id)
        ]
    );
    assert_eq!(
        one(
            &xml,
            "/*/*[local-name()='Signature']//*[local-name()='Reference']/@URI"
        ),
        format!("#{}", issued.response_id)
    );
    assert_eq!(
        one(
            &xml,
            "/*/*[local-name()='Assertion']/*[local-name()='Signature']//*[local-name()='Reference']/@URI"
        ),
        format!("#{}", issued.assertion_id)
    );
    verify_every_signature(&xml, material()).expect("both signatures verify");

    // The response signature's verified content holds the assertion *with its
    // signature value*: it covers the signed assertion.
    let assertion_signature_value = one(
        &xml,
        "/*/*[local-name()='Assertion']/*[local-name()='Signature']/*[local-name()='SignatureValue']",
    );
    let predigest = <XmlSec as CryptoProvider>::reduce_xml_to_signed(
        &xml,
        &[cert_der(material())],
        ReduceMode::PreDigest,
    )
    .expect("pre-digest of the response reference");
    let compact = |s: &str| s.split_whitespace().collect::<String>();
    assert!(predigest.contains(&issued.assertion_id));
    assert!(compact(&predigest).contains(&compact(&assertion_signature_value)));

    // And so a change to the assertion's signature value alone breaks the
    // response signature (the first one a verifier reaches).
    let tampered = flip_last_char_of(&xml, &assertion_signature_value[..40]);
    assert!(!verify_first_signature(&tampered, material()));
    // A change to the response's own attributes breaks it too.
    let tampered = flip_last_char_of(&xml, "Destination=\"https://sp.example.test/acs");
    assert!(!verify_first_signature(&tampered, material()));
    let tampered = flip_last_char_of(&xml, &format!("InResponseTo=\"{REQUEST_ID}"));
    assert!(!verify_first_signature(&tampered, material()));
}

#[test]
fn with_response_signing_off_only_the_assertion_is_signed() {
    let issued = Case::new().issue_ok();
    let xml = decode(&issued);
    assert!(xpath(&xml, "/*/*[local-name()='Signature']").is_empty());
    assert_eq!(
        xpath(&xml, "//*[local-name()='Signature']").len(),
        1,
        "exactly one signature"
    );
    assert_eq!(
        one(
            &xml,
            "/*/*[local-name()='Assertion']/*[local-name()='Signature']//*[local-name()='Reference']/@URI"
        ),
        format!("#{}", issued.assertion_id)
    );
}

#[test]
fn a_pkcs1_key_signs_too_and_a_key_that_does_not_match_the_certificate_is_refused() {
    let case = Case::new();
    let mut signer = signing_key();
    signer.private_key_pem = Zeroizing::new(material().key_pkcs1_pem.clone());
    let issued = issuer()
        .issue(&case.req(), &signer, Utc::now())
        .expect("PKCS#1 PEM");
    assert!(verify_first_signature(&decode(&issued), material()));

    // The current certificate with the rotated key: xmlsec signs happily, the
    // issuer's own check of its output refuses to let it out.
    let mismatched = signing_key_from(rotated_material(), credential_for(material(), tenant()));
    assert_eq!(
        issuer().issue(&case.req(), &mismatched, Utc::now()),
        Err(SamlIdpError::SigningFailed)
    );

    for garbage in [
        "",
        "not a key",
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
    ] {
        let mut signer = signing_key();
        signer.private_key_pem = Zeroizing::new(garbage.to_owned());
        assert_eq!(
            issuer().issue(&case.req(), &signer, Utc::now()),
            Err(SamlIdpError::SigningFailed)
        );
    }
}

// ---------------------------------------------------------------------------
// Signature wrapping
// ---------------------------------------------------------------------------

#[test]
fn the_output_has_one_assertion_unique_ids_and_matching_references() {
    for sign_responses in [false, true] {
        let mut case = Case::new();
        case.sp.sign_responses = sign_responses;
        let issued = case.issue_ok();
        let xml = decode(&issued);
        assert_eq!(xpath(&xml, "//*[local-name()='Assertion']").len(), 1);
        let ids = xpath(&xml, "//@ID");
        assert_eq!(
            ids,
            vec![issued.response_id.clone(), issued.assertion_id.clone()]
        );
        assert_ne!(ids[0], ids[1]);
        for id in &ids {
            assert_eq!(id.len(), 41, "{id}");
            assert!(id.starts_with('_'));
            assert!(id[1..].bytes().all(|b| b.is_ascii_hexdigit()));
        }
        // Every reference names an element of the document.
        for uri in xpath(&xml, "//*[local-name()='Reference']/@URI") {
            assert!(
                ids.contains(&uri.trim_start_matches('#').to_owned()),
                "{uri}"
            );
        }
    }
    // And no two issuances share an id.
    let a = Case::new().issue_ok();
    let b = Case::new().issue_ok();
    assert_ne!(a.assertion_id, b.assertion_id);
    assert_ne!(a.response_id, b.response_id);
}

/// A forged assertion for a victim, unsigned, with everything else plausible.
fn evil_assertion(id: &str) -> String {
    let in_5 = xml::instant(Utc::now() + Duration::minutes(5));
    let before = xml::instant(Utc::now() - Duration::minutes(1));
    format!(
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{before}"><saml:Issuer>{issuer}</saml:Issuer><saml:Subject><saml:NameID>victim</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="{ACS}" NotOnOrAfter="{in_5}" InResponseTo="{REQUEST_ID}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{before}" NotOnOrAfter="{in_5}"><saml:AudienceRestriction><saml:Audience>{SP_ENTITY}</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion>"#,
        issuer = idp_entity_id(BASE_URL, tenant()),
    )
}

fn without_declaration(s: &str) -> &str {
    xml::strip_declaration(s)
}

#[tokio::test]
async fn xsw1_and_xsw2_wrapped_copies_of_a_signed_response_are_refused_by_the_sp() {
    let mut case = Case::new();
    case.sp.sign_responses = true;
    let issued = case.issue_ok();
    let original = decode(&issued);
    sp_accepts(&original, Some(REQUEST_ID), Some(ACS), true)
        .await
        .expect("the original is accepted");

    let response_signature = {
        let start = original.find("<ds:Signature").expect("response signature");
        let end = original.find("</ds:Signature>").expect("end") + "</ds:Signature>".len();
        original[start..end].to_owned()
    };
    let open = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_evil-response" Version="2.0" IssueInstant="{}" Destination="{ACS}" InResponseTo="{REQUEST_ID}"><saml:Issuer>{}</saml:Issuer>"#,
        xml::instant(Utc::now()),
        idp_entity_id(BASE_URL, tenant())
    );
    let status = r#"<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>"#;

    // XSW1: the original response moved into the copied signature's Object.
    let with_object = response_signature.replace(
        "</ds:Signature>",
        &format!(
            "<ds:Object>{}</ds:Object></ds:Signature>",
            without_declaration(&original)
        ),
    );
    let xsw1 = format!(
        "{open}{with_object}{status}{}</samlp:Response>",
        evil_assertion("_evil-assertion")
    );
    // XSW2: the original response as a detached sibling before the signature.
    let xsw2 = format!(
        "{open}{}{response_signature}{status}{}</samlp:Response>",
        without_declaration(&original),
        evil_assertion("_evil-assertion")
    );

    for (shape, forged) in [("XSW1", xsw1), ("XSW2", xsw2)] {
        let err = sp_accepts(&forged, Some(REQUEST_ID), Some(ACS), true)
            .await
            .expect_err(shape);
        assert!(
            format!("{err:?}").contains("exactly 1 Assertion")
                || format!("{err:?}").contains("(XSW)")
                || matches!(err, crate::error::FederationError::SamlSignatureInvalid(_)),
            "{shape}: refused for the wrong reason: {err:?}"
        );
    }
}

#[tokio::test]
async fn assertion_level_wrapping_of_the_builder_output_is_refused_by_the_sp() {
    let issued = Case::new().issue_ok();
    let original = decode(&issued);
    let signed_assertion = {
        let start = original.find("<saml:Assertion").expect("assertion");
        let end = original.rfind("</saml:Assertion>").expect("end") + "</saml:Assertion>".len();
        original[start..end].to_owned()
    };
    let evil = evil_assertion("_evil-assertion");

    // XSW3: a forged assertion before the signed one.
    let xsw3 = original.replace(&signed_assertion, &format!("{evil}{signed_assertion}"));
    // XSW4: the signed assertion nested inside the forged one.
    let xsw4 = original.replace(
        &signed_assertion,
        &evil.replace(
            "</saml:Assertion>",
            &format!("{signed_assertion}</saml:Assertion>"),
        ),
    );
    for (shape, forged) in [("XSW3", xsw3), ("XSW4", xsw4)] {
        let err = sp_accepts(&forged, Some(REQUEST_ID), Some(ACS), true)
            .await
            .expect_err(shape);
        // Two sibling assertions never reach the XSW check: samael's
        // deserializer refuses the duplicate first. A nested one parses and is
        // refused by the signature placement rule (D-23): its signature is no
        // longer the enveloped child of an Assertion that is the root's child.
        let text = format!("{err:?}");
        assert!(
            text.contains("exactly 1 Assertion")
                || text.contains("duplicate field `Assertion`")
                || text.contains("(XSW)"),
            "{shape}: {err:?}"
        );
    }
}

/// **Signature confusion (D-23).** Found by T23.2.2 in AXIAM's own SP verifier
/// and fixed in the same task: `verify_signature` used to verify only the
/// *first* `ds:Signature` in document order, and `bind_signature_to_assertion`
/// accepted *any* `Reference` naming the assertion, verified or not. A document
/// the IdP's key signed that carries no assertion, placed ahead of a forged
/// assertion with a dummy signature naming it, passed both.
#[tokio::test]
async fn a_signed_assertion_free_document_cannot_vouch_for_a_forged_assertion() {
    let forged = signature_confusion_document();
    assert!(
        sp_accepts(&forged, Some(REQUEST_ID), Some(ACS), true)
            .await
            .is_err(),
        "a forged assertion was accepted on the strength of another document's signature"
    );
}

/// A logout request signed with the tenant's key (what T23.2.4's SLO, or any
/// external IdP, signs), embedded ahead of a forged assertion whose own
/// signature element is a copy that verifies nothing.
fn signature_confusion_document() -> String {
    let evil = evil_assertion_with(Dummy::Enveloped, None);
    forged_response(
        &format!(
            "<samlp:Extensions>{}</samlp:Extensions>",
            gadget(Gadget::LogoutRequest)
        ),
        "",
        &evil,
    )
}

/// Documents the tenant's key signs that carry no assertion.
#[derive(Debug, Clone, Copy)]
enum Gadget {
    LogoutRequest,
    LogoutResponse,
    ErrorResponse,
}

/// Where the forged assertion's dummy (unverifiable) signature sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dummy {
    /// As the assertion's enveloped child, referencing it.
    Enveloped,
    /// As a child of the response root, still referencing the assertion.
    AtTheRoot,
    /// Inside `Extensions`, referencing the assertion.
    InExtensions,
}

/// Where the gadget sits.
#[derive(Debug, Clone, Copy)]
enum Placement {
    Extensions,
    SiblingOfTheAssertion,
    AdviceOfTheAssertion,
}

const EVIL_ID: &str = "_evil-assertion";

fn signed(document: &str) -> String {
    let signer = signing_key();
    let key_der = sign::private_key_der(&signer).expect("der");
    sign::sign(document, &key_der).expect("signed gadget")
}

fn cert_bytes() -> Vec<u8> {
    crate::cert::pem_cert_to_der(&material().cert_pem).expect("der")
}

/// A document of `kind`, validly signed with the tenant's credential.
fn gadget(kind: Gadget) -> String {
    let id = xml::new_id();
    let at = xml::instant(Utc::now());
    let issuer = idp_entity_id(BASE_URL, tenant());
    let template = sign::signature_template(&id, &cert_bytes());
    let ns = r#"xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion""#;
    let document = match kind {
        Gadget::LogoutRequest => format!(
            r#"<samlp:LogoutRequest {ns} ID="{id}" Version="2.0" IssueInstant="{at}"><saml:Issuer>{issuer}</saml:Issuer>{template}<saml:NameID>someone</saml:NameID></samlp:LogoutRequest>"#
        ),
        Gadget::LogoutResponse => format!(
            r#"<samlp:LogoutResponse {ns} ID="{id}" Version="2.0" IssueInstant="{at}" InResponseTo="{REQUEST_ID}"><saml:Issuer>{issuer}</saml:Issuer>{template}<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>"#
        ),
        Gadget::ErrorResponse => format!(
            r#"<samlp:Response {ns} ID="{id}" Version="2.0" IssueInstant="{at}" Destination="{ACS}" InResponseTo="{REQUEST_ID}"><saml:Issuer>{issuer}</saml:Issuer>{template}<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/></samlp:Status></samlp:Response>"#
        ),
    };
    signed(&document)
}

/// The forged assertion, optionally with its dummy signature enveloped and
/// optionally carrying `advice` (in `saml:Advice`, after `Conditions`).
fn evil_assertion_with(dummy: Dummy, advice: Option<&str>) -> String {
    let mut evil = evil_assertion(EVIL_ID);
    if dummy == Dummy::Enveloped {
        evil = evil.replacen(
            "<saml:Subject>",
            &format!(
                "{}<saml:Subject>",
                sign::signature_template(EVIL_ID, &cert_bytes())
            ),
            1,
        );
    }
    if let Some(advice) = advice {
        evil = evil.replacen(
            "</saml:Assertion>",
            &format!("<saml:Advice>{advice}</saml:Advice></saml:Assertion>"),
            1,
        );
    }
    evil
}

/// A response: `after_issuer` (signatures, `Extensions`), `Status` Success,
/// then `body` (the assertion and anything beside it).
fn forged_response(after_issuer: &str, before_assertion: &str, body: &str) -> String {
    format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_evil-response" Version="2.0" IssueInstant="{}" Destination="{ACS}" InResponseTo="{REQUEST_ID}"><saml:Issuer>{}</saml:Issuer>{after_issuer}<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>{before_assertion}{body}</samlp:Response>"#,
        xml::instant(Utc::now()),
        idp_entity_id(BASE_URL, tenant()),
    )
}

/// Every gadget, in every placement, with the dummy signature enveloped or
/// elsewhere: none may vouch for the forged assertion (D-23).
#[tokio::test]
async fn no_signed_gadget_vouches_for_a_forged_assertion_wherever_it_is_placed() {
    let mut cases = 0;
    for kind in [
        Gadget::LogoutRequest,
        Gadget::LogoutResponse,
        Gadget::ErrorResponse,
    ] {
        for placement in [
            Placement::Extensions,
            Placement::SiblingOfTheAssertion,
            Placement::AdviceOfTheAssertion,
        ] {
            for dummy in [Dummy::Enveloped, Dummy::AtTheRoot, Dummy::InExtensions] {
                let g = gadget(kind);
                let dummy_sig = sign::signature_template(EVIL_ID, &cert_bytes());
                let mut extensions = String::new();
                if matches!(placement, Placement::Extensions) {
                    extensions.push_str(&g);
                }
                if dummy == Dummy::InExtensions {
                    extensions.push_str(&dummy_sig);
                }
                let mut after_issuer = String::new();
                if dummy == Dummy::AtTheRoot {
                    after_issuer.push_str(&dummy_sig);
                }
                if !extensions.is_empty() {
                    after_issuer.push_str(&format!(
                        "<samlp:Extensions>{extensions}</samlp:Extensions>"
                    ));
                }
                let advice =
                    matches!(placement, Placement::AdviceOfTheAssertion).then_some(g.as_str());
                let before = if matches!(placement, Placement::SiblingOfTheAssertion) {
                    g.as_str()
                } else {
                    ""
                };
                let forged =
                    forged_response(&after_issuer, before, &evil_assertion_with(dummy, advice));
                let result = sp_accepts(&forged, Some(REQUEST_ID), Some(ACS), true).await;
                assert!(
                    result.is_err(),
                    "{kind:?} gadget, {placement:?}, dummy {dummy:?}: the forged assertion was accepted"
                );
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 27);

    // The signed error response as the document itself, with the forged
    // assertion added to it: its own signature no longer verifies.
    let error = gadget(Gadget::ErrorResponse);
    let forged = error.replacen(
        "</samlp:Response>",
        &format!(
            "{}</samlp:Response>",
            evil_assertion_with(Dummy::Enveloped, None)
        ),
        1,
    );
    assert!(
        sp_accepts(&forged, Some(REQUEST_ID), Some(ACS), true)
            .await
            .is_err()
    );
}

/// A legitimately signed response carrying one extra, unsigned `Signature`
/// element is refused wherever the extra one sits: at the root, in
/// `Extensions`, or as a second signature in the assertion.
#[tokio::test]
async fn a_valid_response_with_an_extra_unsigned_signature_is_refused() {
    for sign_responses in [false, true] {
        let mut case = Case::new();
        case.sp.sign_responses = sign_responses;
        let issued = case.issue_ok();
        let xml = decode(&issued);
        sp_accepts(&xml, Some(REQUEST_ID), Some(ACS), true)
            .await
            .expect("the untouched response is accepted");

        let issuer_close = "</saml:Issuer>";
        let at_root = sign::signature_template(&issued.response_id, &cert_bytes());
        let in_assertion = sign::signature_template(&issued.assertion_id, &cert_bytes());
        let assertion_issuer_end = {
            let from = xml.find("<saml:Assertion").expect("assertion");
            from + xml[from..].find(issuer_close).expect("assertion issuer") + issuer_close.len()
        };
        let mut variants = vec![
            (
                "in Extensions",
                xml.replacen(
                    "<samlp:Status>",
                    &format!("<samlp:Extensions>{at_root}</samlp:Extensions><samlp:Status>"),
                    1,
                ),
            ),
            ("a second one in the assertion", {
                let mut v = xml.clone();
                v.insert_str(assertion_issuer_end, &in_assertion);
                v
            }),
            (
                "after the assertion",
                xml.replacen(
                    "</samlp:Response>",
                    &format!("{at_root}</samlp:Response>"),
                    1,
                ),
            ),
        ];
        if !sign_responses {
            // Unsigned response: an unsigned root signature in the allowed
            // place still has to verify.
            variants.push((
                "at the root",
                xml.replacen("<samlp:Status>", &format!("{at_root}<samlp:Status>"), 1),
            ));
        }
        for (where_, forged) in variants {
            assert_ne!(forged, xml);
            assert!(
                sp_accepts(&forged, Some(REQUEST_ID), Some(ACS), true)
                    .await
                    .is_err(),
                "sign_responses={sign_responses}: an extra signature {where_} was accepted"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Timing, audience, recipient, destination, InResponseTo
// ---------------------------------------------------------------------------

#[test]
fn conditions_and_confirmation_are_five_minutes_for_this_sp_at_this_acs() {
    let mut case = Case::new();
    case.acs = ACS_2.into();
    let at = now();
    let issued = issuer()
        .issue(&case.req(), &signing_key(), at)
        .expect("issued");
    let xml = decode(&issued);
    let response = parse(&xml);
    let assertion = response.assertion.as_ref().expect("assertion");

    let five = at + Duration::seconds(300);
    assert_eq!(issued.not_on_or_after, five);
    assert_eq!(response.issue_instant, at);
    assert_eq!(assertion.issue_instant, at);
    let conditions = assertion.conditions.as_ref().expect("conditions");
    assert_eq!(conditions.not_on_or_after, Some(five));
    assert_eq!(
        conditions.not_before,
        Some(at - Duration::seconds(crate::oidc::CLOCK_SKEW_LEEWAY_SECS as i64)),
        "backdated by the skew allowance and no more"
    );
    let audiences: Vec<_> = conditions
        .audience_restrictions
        .iter()
        .flatten()
        .flat_map(|r| r.audience.iter())
        .collect();
    assert_eq!(audiences, vec![SP_ENTITY]);

    let confirmation = &assertion
        .subject
        .as_ref()
        .and_then(|s| s.subject_confirmations.as_ref())
        .expect("confirmations")[0];
    assert_eq!(
        confirmation.method.as_deref(),
        Some("urn:oasis:names:tc:SAML:2.0:cm:bearer")
    );
    let data = confirmation
        .subject_confirmation_data
        .as_ref()
        .expect("data");
    assert_eq!(data.recipient.as_deref(), Some(ACS_2));
    assert_eq!(data.not_on_or_after, Some(five));
    assert_eq!(data.not_before, None, "Profiles §4.1.4.2: no NotBefore");
    assert_eq!(data.in_response_to.as_deref(), Some(REQUEST_ID));

    assert_eq!(response.destination.as_deref(), Some(ACS_2));
    assert_eq!(issued.binding.acs_url, ACS_2);
    assert_eq!(response.in_response_to.as_deref(), Some(REQUEST_ID));
    let entity = idp_entity_id(BASE_URL, tenant());
    assert_eq!(
        response.issuer.as_ref().and_then(|i| i.value.as_deref()),
        Some(entity.as_str())
    );
    assert_eq!(assertion.issuer.value.as_deref(), Some(entity.as_str()));
    assert_eq!(
        one(
            &xml,
            "/*/*[local-name()='Status']/*[local-name()='StatusCode']/@Value"
        ),
        "urn:oasis:names:tc:SAML:2.0:status:Success"
    );
}

#[tokio::test]
async fn the_sp_refuses_the_assertion_at_another_acs_or_for_another_request() {
    let xml = decode(&Case::new().issue_ok());
    assert!(
        sp_accepts(&xml, Some(REQUEST_ID), Some(ACS_2), true)
            .await
            .is_err()
    );
    assert!(
        sp_accepts(&xml, Some("_another"), Some(ACS), true)
            .await
            .is_err()
    );
}

#[test]
fn the_idp_entity_id_is_one_function_of_the_base_url_and_the_path_tenant() {
    let t = Uuid::new_v4();
    let expected = format!("https://axiam.example.test/saml/v2/{t}/metadata");
    assert_eq!(idp_entity_id("https://axiam.example.test", t), expected);
    assert_eq!(idp_entity_id("https://axiam.example.test/", t), expected);
    assert_eq!(SamlIdpIssuer::new(BASE_URL, None).entity_id(t), expected);
    assert_eq!(
        idp_sso_url(BASE_URL, t),
        format!("https://axiam.example.test/saml/v2/{t}/sso")
    );
    assert_eq!(
        idp_slo_url(BASE_URL, t),
        format!("https://axiam.example.test/saml/v2/{t}/slo")
    );
}

// ---------------------------------------------------------------------------
// NameID
// ---------------------------------------------------------------------------

#[test]
fn the_pairwise_name_id_is_stable_across_calls_and_across_a_credential_rotation() {
    let case = Case::new();
    let first = case.issue_ok();
    let second = case.issue_ok();
    assert_eq!(first.name_id, second.name_id);

    let rotated = signing_key_from(
        rotated_material(),
        credential_for(rotated_material(), tenant()),
    );
    let after_rotation = issuer()
        .issue(&case.req(), &rotated, Utc::now())
        .expect("issued with the rotated credential");
    assert!(verify_first_signature(
        &decode(&after_rotation),
        rotated_material()
    ));
    assert_eq!(first.name_id, after_rotation.name_id);

    // And the value is the one the pure function gives.
    assert_eq!(
        first.name_id,
        pairwise_name_id(&pairwise_key(), tenant(), SP_ENTITY, case.user.id)
    );
}

#[test]
fn the_pairwise_name_id_differs_across_sps_tenants_users_and_keys() {
    let derivation = pairwise_key();
    let user_id = Uuid::new_v4();
    let t = tenant();
    let base = pairwise_name_id(&derivation, t, SP_ENTITY, user_id);
    assert_eq!(base.len(), 64);
    assert!(base.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    for other in [
        pairwise_name_id(
            &derivation,
            t,
            "https://other-sp.example.test/metadata",
            user_id,
        ),
        pairwise_name_id(&derivation, Uuid::new_v4(), SP_ENTITY, user_id),
        pairwise_name_id(&derivation, t, SP_ENTITY, Uuid::new_v4()),
        pairwise_name_id(&other_pairwise_key(), t, SP_ENTITY, user_id),
    ] {
        assert_ne!(base, other);
    }

    // Through the issuer: a second SP sees another value for the same user.
    let mut case = Case::new();
    let at_first = case.issue_ok().name_id;
    case.sp.entity_id = "https://other-sp.example.test/metadata".into();
    assert_ne!(at_first, case.issue_ok().name_id);
}

#[test]
fn the_pairwise_name_id_contains_neither_the_user_id_nor_the_tenant_id() {
    let mut case = Case::new();
    // The NameID is 64 hex digits, so a username made only of hex letters
    // (the fixture's "ada") appears in it by chance about once in seventy
    // runs. A name with non-hex letters can only appear if it leaked.
    case.user.username = "grace.hopper".into();
    let issued = case.issue_ok();
    let xml = decode(&issued);
    let name_id = one(&xml, "//*[local-name()='NameID']");
    assert_eq!(name_id, issued.name_id);
    for id in [case.user.id, tenant()] {
        for form in [
            id.to_string(),
            id.simple().to_string(),
            hex::encode(&id.as_bytes()[..8]),
        ] {
            assert!(!name_id.contains(&form), "{form}");
        }
    }
    assert!(!name_id.contains(&case.user.username));
    assert_eq!(
        one(&xml, "//*[local-name()='NameID']/@Format"),
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    );
    assert_eq!(
        one(&xml, "//*[local-name()='NameID']/@NameQualifier"),
        idp_entity_id(BASE_URL, tenant())
    );
    assert_eq!(
        one(&xml, "//*[local-name()='NameID']/@SPNameQualifier"),
        SP_ENTITY
    );
}

#[test]
fn an_email_name_id_is_the_address_and_a_missing_address_is_a_refusal() {
    let mut case = Case::new();
    case.sp.name_id_format = NameIdFormat::EmailAddress;
    let xml = decode(&case.issue_ok());
    assert_eq!(one(&xml, "//*[local-name()='NameID']"), "ada@example.test");
    assert_eq!(
        one(&xml, "//*[local-name()='NameID']/@Format"),
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    );

    for missing in ["", "   "] {
        case.user.email = missing.into();
        let err = case.issue().expect_err("no address, no email NameID");
        assert_eq!(err, SamlIdpError::NameIdUnavailable);
        assert_eq!(err.status(), SamlStatus::InvalidNameIdPolicy);
    }
}

/// **T-313, D-25.** An email `NameID` is issued only for an address something
/// vouches for: verified, or an `Active` account. A `PendingVerification`
/// account with an unverified address — a self-registration in its grace
/// period — is refused at an email-keyed SP, the `email` attribute is omitted
/// for it, and it still signs on where the `NameID` is pairwise.
#[test]
fn t_313_an_unverified_pending_address_is_never_asserted() {
    let mut case = Case::new();
    case.sp.name_id_format = NameIdFormat::EmailAddress;
    case.user.status = UserStatus::PendingVerification;
    case.user.email_verified_at = None;
    let err = case
        .issue()
        .expect_err("an unvouched address is not asserted");
    assert_eq!(err, SamlIdpError::NameIdUnverified);
    assert_eq!(err.status(), SamlStatus::InvalidNameIdPolicy);

    // Verified: asserted, whatever the status.
    case.user.email_verified_at = Some(now());
    let xml = decode(&case.issue_ok());
    assert_eq!(one(&xml, "//*[local-name()='NameID']"), "ada@example.test");

    // Pairwise: the pending account signs on, and the email attribute is not
    // released for its unverified address.
    case.user.email_verified_at = None;
    case.sp.name_id_format = NameIdFormat::Persistent;
    case.sp.attribute_mappings = vec![AttributeMapping {
        saml_name: "mail".into(),
        name_format: None,
        source: AttributeSource::Email,
    }];
    let xml = decode(&case.issue_ok());
    assert!(
        xpath(&xml, "//*[local-name()='Attribute'][@Name='mail']").is_empty(),
        "an unvouched address is not released as an attribute either"
    );
    case.user.status = UserStatus::Active;
    let xml = decode(&case.issue_ok());
    assert_eq!(
        xpath(
            &xml,
            "//*[local-name()='Attribute'][@Name='mail']/*[local-name()='AttributeValue']"
        ),
        vec!["ada@example.test".to_owned()]
    );
}

#[test]
fn a_persistent_name_id_without_the_pairwise_key_is_a_refusal() {
    let case = Case::new();
    let err = SamlIdpIssuer::new(BASE_URL, None)
        .issue(&case.req(), &signing_key(), Utc::now())
        .expect_err("no key, no persistent NameID");
    assert_eq!(err, SamlIdpError::PairwiseKeyMissing);
    assert_eq!(err.status(), SamlStatus::Responder);
}

// ---------------------------------------------------------------------------
// AuthnStatement
// ---------------------------------------------------------------------------

#[test]
fn the_authn_context_mapping_table_is_pinned() {
    use Amr::*;
    let table: &[(&[Amr], &str)] = &[
        (&[Pwd], AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT),
        (&[Pwd, Otp, Mfa], AUTHN_CONTEXT_MFA),
        (&[Mfa], AUTHN_CONTEXT_MFA),
        (&[Hwk, User], AUTHN_CONTEXT_MFA),
        (&[Swk, User], AUTHN_CONTEXT_MFA),
        (&[Pwd, Hwk, User], AUTHN_CONTEXT_MFA),
        (&[X509], AUTHN_CONTEXT_X509),
        (&[X509, Mfa], AUTHN_CONTEXT_MFA),
        (&[Pwd, Otp], AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT),
        (&[Hwk], AUTHN_CONTEXT_UNSPECIFIED),
        (&[Swk], AUTHN_CONTEXT_UNSPECIFIED),
        (&[User], AUTHN_CONTEXT_UNSPECIFIED),
        (&[Fed], AUTHN_CONTEXT_UNSPECIFIED),
        (&[], AUTHN_CONTEXT_UNSPECIFIED),
    ];
    for (amr, expected) in table {
        assert_eq!(authn_context_class_ref(amr), *expected, "{amr:?}");
    }
    assert_eq!(AUTHN_CONTEXT_MFA, "https://refeds.org/profile/mfa");
    assert_eq!(
        AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT,
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    );
    assert_eq!(
        AUTHN_CONTEXT_X509,
        "urn:oasis:names:tc:SAML:2.0:ac:classes:X509"
    );
    assert_eq!(
        AUTHN_CONTEXT_UNSPECIFIED,
        "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
    );
}

#[test]
fn the_authn_statement_carries_the_per_sp_index_instant_and_class() {
    let mut case = Case::new();
    case.session.amr = vec![Amr::Pwd, Amr::Otp, Amr::Mfa];
    let issued = case.issue_ok();
    assert_eq!(issued.session_index, case.session_index);
    assert_ne!(
        issued.session_index,
        case.session.id.to_string(),
        "D-37: the index is not the session id"
    );
    let xml_text = decode(&issued);
    assert!(
        !xml_text.contains(&case.session.id.to_string()),
        "the session id does not reach the XML at all"
    );
    let response = parse(&xml_text);
    let statement = &response
        .assertion
        .as_ref()
        .and_then(|a| a.authn_statements.as_ref())
        .expect("statements")[0];
    assert_eq!(
        statement.session_index.as_deref(),
        Some(case.session_index.as_str())
    );
    assert_eq!(
        statement.authn_instant,
        Some(case.session.authenticated_at.trunc_subsecs(0))
    );
    assert_eq!(
        statement
            .authn_context
            .as_ref()
            .and_then(|c| c.value.as_ref())
            .and_then(|r| r.value.as_deref()),
        Some(AUTHN_CONTEXT_MFA)
    );
}

// ---------------------------------------------------------------------------
// Attributes
// ---------------------------------------------------------------------------

fn mapping(name: &str, source: AttributeSource, name_format: Option<&str>) -> AttributeMapping {
    AttributeMapping {
        saml_name: name.into(),
        name_format: name_format.map(str::to_owned),
        source,
    }
}

fn attributes(xml: &str) -> Vec<(String, Option<String>, Vec<String>)> {
    parse(xml)
        .assertion
        .and_then(|a| a.attribute_statements)
        .into_iter()
        .flatten()
        .flat_map(|s| s.attributes)
        .map(|a| {
            (
                a.name.unwrap_or_default(),
                a.name_format,
                a.values.into_iter().filter_map(|v| v.value).collect(),
            )
        })
        .collect()
}

#[test]
fn every_attribute_source_is_mapped() {
    const URI: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
    let mut case = Case::new();
    case.groups = vec![group("staff"), group("engineering"), group("staff")];
    case.roles = vec![role("viewer"), role("admin")];
    case.sp.attribute_mappings = vec![
        mapping(
            "urn:oid:0.9.2342.19200300.100.1.1",
            AttributeSource::Username,
            Some(URI),
        ),
        mapping("mail", AttributeSource::Email, None),
        mapping("displayName", AttributeSource::DisplayName, None),
        mapping("givenName", AttributeSource::GivenName, None),
        mapping("sn", AttributeSource::FamilyName, None),
        mapping("groups", AttributeSource::Groups, None),
        mapping("roles", AttributeSource::Roles, None),
    ];
    let xml = decode(&case.issue_ok());
    let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
    assert_eq!(
        attributes(&xml),
        vec![
            (
                "urn:oid:0.9.2342.19200300.100.1.1".into(),
                Some(URI.to_owned()),
                s(&["ada"])
            ),
            ("mail".into(), None, s(&["ada@example.test"])),
            ("displayName".into(), None, s(&["Ada Lovelace"])),
            ("givenName".into(), None, s(&["Ada"])),
            ("sn".into(), None, s(&["Lovelace"])),
            ("groups".into(), None, s(&["engineering", "staff"])),
            ("roles".into(), None, s(&["admin", "viewer"])),
        ]
    );
}

#[test]
fn an_attribute_with_no_value_is_omitted_and_no_mapping_means_no_statement() {
    let mut case = Case::new();
    let xml = decode(&case.issue_ok());
    assert!(xpath(&xml, "//*[local-name()='AttributeStatement']").is_empty());

    case.user.metadata = serde_json::Value::Null;
    case.sp.attribute_mappings = vec![
        mapping("displayName", AttributeSource::DisplayName, None),
        mapping("groups", AttributeSource::Groups, None),
        mapping("uid", AttributeSource::Username, None),
    ];
    let xml = decode(&case.issue_ok());
    assert_eq!(
        attributes(&xml),
        vec![("uid".to_owned(), None, vec!["ada".to_owned()])]
    );
}

#[test]
fn values_are_escaped_and_round_trip_as_text_not_markup() {
    let hostile_name = r#"<b>Ada</b> & "Bob" 'C' ]]> <!-- x --> &amp;"#;
    let hostile_group = "</saml:AttributeValue><saml:AttributeValue>admin";
    let mut case = Case::new();
    case.user.metadata = serde_json::json!({ OIDC_METADATA_KEY: { "name": hostile_name } });
    case.groups = vec![group(hostile_group)];
    case.sp.attribute_mappings = vec![
        mapping("displayName", AttributeSource::DisplayName, None),
        mapping("groups", AttributeSource::Groups, None),
        mapping(r#"x" injected="1"#, AttributeSource::Username, None),
    ];
    let xml = decode(&case.issue_ok());
    assert!(verify_first_signature(&xml, material()));
    assert_eq!(
        attributes(&xml),
        vec![
            ("displayName".into(), None, vec![hostile_name.to_owned()]),
            ("groups".into(), None, vec![hostile_group.to_owned()]),
            (r#"x" injected="1"#.into(), None, vec!["ada".to_owned()]),
        ]
    );
    assert!(xpath(&xml, "//@injected").is_empty());
    assert!(xpath(&xml, "//comment()").is_empty());
}

#[test]
fn characters_xml_cannot_carry_are_replaced_and_whitespace_survives() {
    let mut case = Case::new();
    case.user.metadata = serde_json::json!({ OIDC_METADATA_KEY: { "name": "a\u{1}b\tc\nd\re" } });
    case.sp.attribute_mappings = vec![mapping("displayName", AttributeSource::DisplayName, None)];
    let xml = decode(&case.issue_ok());
    assert_eq!(
        attributes(&xml)[0].2,
        vec!["a\u{FFFD}b\tc\nd\re".to_owned()]
    );
}

#[test]
fn allowed_groups_is_a_refusal_input() {
    let member = group("pilots");
    let mut sp = sp();
    assert_eq!(check_allowed_groups(&sp, &[]), Ok(()), "empty: everyone");

    sp.allowed_groups = vec![member.id];
    assert_eq!(
        check_allowed_groups(&sp, std::slice::from_ref(&member)),
        Ok(())
    );
    assert_eq!(
        check_allowed_groups(&sp, &[group("pilots")]),
        Err(SamlIdpError::GroupNotAllowed),
        "a group of the same name is not the group"
    );
    assert_eq!(
        check_allowed_groups(&sp, &[]),
        Err(SamlIdpError::GroupNotAllowed)
    );
    let mut foreign = member.clone();
    foreign.tenant_id = Uuid::new_v4();
    assert_eq!(
        check_allowed_groups(&sp, &[foreign]),
        Err(SamlIdpError::GroupNotAllowed)
    );

    // The issuer applies it too.
    let mut case = Case::new();
    case.sp.allowed_groups = vec![member.id];
    let err = case.issue().expect_err("not a member");
    assert_eq!(err, SamlIdpError::GroupNotAllowed);
    assert_eq!(err.status(), SamlStatus::RequestDenied);
    case.groups = vec![member];
    case.issue_ok();
}

// ---------------------------------------------------------------------------
// The credential
// ---------------------------------------------------------------------------

#[test]
fn a_credential_outside_its_validity_window_or_not_active_refuses_to_sign() {
    let case = Case::new();
    let at = now();
    let with = |edit: &dyn Fn(&mut SamlIdpCredential)| {
        let mut credential = credential_for(material(), tenant());
        edit(&mut credential);
        issuer().issue(&case.req(), &signing_key_from(material(), credential), at)
    };

    let expired = with(&|c| c.not_after = at - Duration::seconds(1));
    assert_eq!(expired, Err(SamlIdpError::CredentialNotValid));
    let at_the_end = with(&|c| c.not_after = at);
    assert_eq!(at_the_end, Err(SamlIdpError::CredentialNotValid));
    let not_yet = with(&|c| c.not_before = at + Duration::seconds(1));
    assert_eq!(not_yet, Err(SamlIdpError::CredentialNotValid));
    assert!(
        with(&|c| c.not_before = at).is_ok(),
        "valid from its first second"
    );
    for status in [
        SamlIdpCredentialStatus::Next,
        SamlIdpCredentialStatus::Retired,
    ] {
        assert_eq!(
            with(&|c| c.status = status),
            Err(SamlIdpError::CredentialNotActive)
        );
    }
    assert_eq!(
        with(&|c| c.tenant_id = Uuid::new_v4()),
        Err(SamlIdpError::TenantMismatch),
        "another tenant's credential never signs for this one"
    );
    for err in [
        SamlIdpError::CredentialNotValid,
        SamlIdpError::CredentialNotActive,
        SamlIdpError::NoActiveCredential,
    ] {
        assert_eq!(err.status(), SamlStatus::Responder);
    }
}

#[test]
fn no_debug_output_carries_key_material() {
    let signer = signing_key();
    let body = signer
        .private_key_pem
        .lines()
        .nth(1)
        .expect("a base64 line")
        .to_owned();
    let issuer = issuer();
    let shown = format!("{signer:?} {issuer:?} {:?}", pairwise_key());
    assert!(!shown.contains(&body));
    assert!(shown.contains("[REDACTED]"));
    // An error never carries a value either: its text is fixed.
    let mut bad = signing_key();
    bad.private_key_pem = Zeroizing::new(format!(
        "-----BEGIN PRIVATE KEY-----\n{body}!\n-----END PRIVATE KEY-----"
    ));
    let err = issuer
        .issue(&Case::new().req(), &bad, Utc::now())
        .expect_err("garbage key");
    assert!(!format!("{err} {err:?}").contains(&body[..16]));
}

// ---------------------------------------------------------------------------
// Refusals before signing
// ---------------------------------------------------------------------------

#[test]
fn every_input_from_another_tenant_is_refused() {
    let foreign = Uuid::new_v4();
    let edits: Vec<Edit> = vec![
        Box::new(move |c| c.sp.tenant_id = foreign),
        Box::new(move |c| c.user.tenant_id = foreign),
        Box::new(move |c| c.session.tenant_id = foreign),
        Box::new(move |c| {
            let mut g = group("g");
            g.tenant_id = foreign;
            c.groups = vec![g];
        }),
        Box::new(move |c| {
            let mut r = role("r");
            r.tenant_id = foreign;
            c.roles = vec![r];
        }),
    ];
    for edit in edits {
        let mut case = Case::new();
        edit(&mut case);
        let err = case.issue().expect_err("tenant mismatch");
        assert_eq!(err, SamlIdpError::TenantMismatch);
        assert_eq!(err.status(), SamlStatus::Responder);
    }
}

#[test]
fn the_session_must_be_the_users_and_live_and_the_account_may_act() {
    let mut case = Case::new();
    case.session.user_id = Uuid::new_v4();
    assert_eq!(case.issue(), Err(SamlIdpError::SessionMismatch));

    let mut case = Case::new();
    case.session.expires_at = Utc::now() - Duration::seconds(1);
    assert_eq!(case.issue(), Err(SamlIdpError::SessionMismatch));

    for status in [
        UserStatus::Locked,
        UserStatus::Inactive,
        UserStatus::Anonymized,
    ] {
        let mut case = Case::new();
        case.user.status = status;
        let err = case.issue().expect_err("may not act");
        assert_eq!(err, SamlIdpError::AccountMayNotAct);
        assert_eq!(err.status(), SamlStatus::AuthnFailed);
    }
    // T-160: pending verification is never a refusal.
    let mut case = Case::new();
    case.user.status = UserStatus::PendingVerification;
    case.issue_ok();
}

#[test]
fn request_shaped_refusals() {
    let cases: Vec<(Edit, SamlIdpError, SamlStatus)> = vec![
        (
            Box::new(|c| c.sp.enabled = false),
            SamlIdpError::SpDisabled,
            SamlStatus::RequestDenied,
        ),
        (
            Box::new(|c| c.acs = "https://attacker.example.test/acs".into()),
            SamlIdpError::AcsNotRegistered,
            SamlStatus::Requester,
        ),
        (
            Box::new(|c| c.acs = format!("{ACS}/")),
            SamlIdpError::AcsNotRegistered,
            SamlStatus::Requester,
        ),
        (
            Box::new(|c| c.acs = ACS_REDIRECT.into()),
            SamlIdpError::AcsBindingUnsupported,
            SamlStatus::Requester,
        ),
        (
            Box::new(|c| c.request_id = None),
            SamlIdpError::IdpInitiatedNotAllowed,
            SamlStatus::RequestDenied,
        ),
        (
            Box::new(|c| c.request_id = Some("1starts-with-a-digit".into())),
            SamlIdpError::InvalidRequestId,
            SamlStatus::Requester,
        ),
        (
            Box::new(|c| c.request_id = Some(r#"_a"b"#.into())),
            SamlIdpError::InvalidRequestId,
            SamlStatus::Requester,
        ),
        (
            Box::new(|c| c.request_id = Some(format!("_{}", "a".repeat(MAX_REQUEST_ID_BYTES)))),
            SamlIdpError::InvalidRequestId,
            SamlStatus::Requester,
        ),
        (
            Box::new(|c| c.relay_state = Some("r".repeat(MAX_RELAY_STATE_BYTES + 1))),
            SamlIdpError::RelayStateTooLong,
            SamlStatus::Requester,
        ),
        (
            Box::new(|c| c.sp.encrypt_assertions = true),
            SamlIdpError::EncryptionUnsupported,
            SamlStatus::Responder,
        ),
    ];
    for (edit, expected, status) in cases {
        let mut case = Case::new();
        edit(&mut case);
        let err = case.issue().expect_err("refused");
        assert_eq!(err, expected);
        assert_eq!(err.status(), status, "{expected:?}");
    }

    // The boundaries are inclusive.
    let mut case = Case::new();
    case.relay_state = Some("r".repeat(MAX_RELAY_STATE_BYTES));
    case.request_id = Some(format!("_{}", "a".repeat(MAX_REQUEST_ID_BYTES - 1)));
    case.issue_ok();
}

#[test]
fn the_pre_hop_checks_are_exposed_on_their_own() {
    let sp = sp();
    assert_eq!(check_acs_url(&sp, ACS), Ok(()));
    assert_eq!(check_acs_url(&sp, ACS_2), Ok(()));
    assert_eq!(
        check_acs_url(&sp, "https://SP.example.test/acs"),
        Err(SamlIdpError::AcsNotRegistered)
    );
    assert_eq!(
        check_acs_url(&sp, ACS_REDIRECT),
        Err(SamlIdpError::AcsBindingUnsupported)
    );
    for good in ["_abc", "a", "id-1.2_3", "ONELOGIN_4fee3b04"] {
        assert_eq!(check_request_id(good), Ok(()), "{good}");
    }
    for bad in ["", "1abc", "-abc", "a b", "a\u{e9}", "a<b", "a:b"] {
        assert_eq!(
            check_request_id(bad),
            Err(SamlIdpError::InvalidRequestId),
            "{bad}"
        );
    }
    assert_eq!(check_relay_state(None), Ok(()));
    assert_eq!(check_relay_state(Some("")), Ok(()));
    assert_eq!(
        check_relay_state(Some(&"x".repeat(81))),
        Err(SamlIdpError::RelayStateTooLong)
    );
}

#[test]
fn the_status_mapping_is_pinned_and_errors_carry_no_values() {
    use SamlIdpError::*;
    let table = [
        (TenantMismatch, SamlStatus::Responder),
        (SessionMismatch, SamlStatus::AuthnFailed),
        (AccountMayNotAct, SamlStatus::AuthnFailed),
        (SpDisabled, SamlStatus::RequestDenied),
        (AcsNotRegistered, SamlStatus::Requester),
        (AcsBindingUnsupported, SamlStatus::Requester),
        (InvalidRequestId, SamlStatus::Requester),
        (RelayStateTooLong, SamlStatus::Requester),
        (IdpInitiatedNotAllowed, SamlStatus::RequestDenied),
        (GroupNotAllowed, SamlStatus::RequestDenied),
        (NameIdUnavailable, SamlStatus::InvalidNameIdPolicy),
        (PairwiseKeyMissing, SamlStatus::Responder),
        (EncryptionUnsupported, SamlStatus::Responder),
        (NoActiveCredential, SamlStatus::Responder),
        (CredentialNotActive, SamlStatus::Responder),
        (CredentialNotValid, SamlStatus::Responder),
        (SigningFailed, SamlStatus::Responder),
    ];
    for (err, status) in table {
        assert_eq!(err.status(), status, "{err:?}");
        let text = err.to_string();
        assert!(!text.contains("http") && !text.contains('@'), "{text}");
    }
    let codes = [
        (SamlStatus::Requester, "Requester", None),
        (SamlStatus::Responder, "Responder", None),
        (SamlStatus::NoPassive, "Responder", Some("NoPassive")),
        (SamlStatus::AuthnFailed, "Responder", Some("AuthnFailed")),
        (
            SamlStatus::RequestDenied,
            "Responder",
            Some("RequestDenied"),
        ),
        (
            SamlStatus::InvalidNameIdPolicy,
            "Responder",
            Some("InvalidNameIDPolicy"),
        ),
    ];
    for (status, top, second) in codes {
        assert_eq!(
            status.top_level(),
            format!("urn:oasis:names:tc:SAML:2.0:status:{top}")
        );
        assert_eq!(
            status.second_level().map(str::to_owned),
            second.map(|s| format!("urn:oasis:names:tc:SAML:2.0:status:{s}"))
        );
    }
}

// ---------------------------------------------------------------------------
// The envelopes
// ---------------------------------------------------------------------------

#[test]
fn failure_responses_are_status_only_unsigned_and_echo_what_can_be_echoed() {
    let sp = sp();
    for status in [
        SamlStatus::Requester,
        SamlStatus::Responder,
        SamlStatus::NoPassive,
        SamlStatus::AuthnFailed,
        SamlStatus::RequestDenied,
        SamlStatus::InvalidNameIdPolicy,
    ] {
        let binding = issuer()
            .failure(
                tenant(),
                &sp,
                ACS,
                Some(REQUEST_ID),
                Some("rs"),
                status,
                Utc::now(),
            )
            .expect("failure envelope");
        let xml = decode_binding(&binding);
        assert!(xpath(&xml, "//*[local-name()='Assertion']").is_empty());
        assert!(xpath(&xml, "//*[local-name()='Signature']").is_empty());
        assert!(xpath(&xml, "//*[local-name()='StatusMessage']").is_empty());
        assert!(xpath(&xml, "//*[local-name()='StatusDetail']").is_empty());
        let codes = xpath(&xml, "//*[local-name()='StatusCode']/@Value");
        let mut expected = vec![status.top_level().to_owned()];
        expected.extend(status.second_level().map(str::to_owned));
        assert_eq!(codes, expected);
        assert_eq!(one(&xml, "/*/@Destination"), ACS);
        assert_eq!(one(&xml, "/*/@InResponseTo"), REQUEST_ID);
        assert_eq!(
            one(&xml, "/*/*[local-name()='Issuer']"),
            idp_entity_id(BASE_URL, tenant())
        );
        let parsed = parse(&xml);
        assert!(parsed.assertion.is_none());
        assert_eq!(binding.acs_url, ACS);
        assert_eq!(binding.relay_state.as_deref(), Some("rs"));
    }

    // What cannot be echoed is left out, not refused.
    let binding = issuer()
        .failure(
            tenant(),
            &sp,
            ACS,
            Some("1-not-an-ncname"),
            Some(&"r".repeat(81)),
            SamlStatus::Requester,
            Utc::now(),
        )
        .expect("still answered");
    assert!(xpath(&decode_binding(&binding), "/*/@InResponseTo").is_empty());
    assert_eq!(binding.relay_state, None);

    // Never to an unregistered URL, and never for another tenant's SP.
    assert_eq!(
        issuer().failure(
            tenant(),
            &sp,
            "https://attacker.example.test/acs",
            None,
            None,
            SamlStatus::Requester,
            Utc::now()
        ),
        Err(SamlIdpError::AcsNotRegistered)
    );
    assert_eq!(
        issuer().failure(
            Uuid::new_v4(),
            &sp,
            ACS,
            None,
            None,
            SamlStatus::Requester,
            Utc::now()
        ),
        Err(SamlIdpError::TenantMismatch)
    );
}

#[tokio::test]
async fn axiam_own_sp_refuses_a_failure_response() {
    let binding = issuer()
        .failure(
            tenant(),
            &sp(),
            ACS,
            Some(REQUEST_ID),
            None,
            SamlStatus::AuthnFailed,
            Utc::now(),
        )
        .expect("failure envelope");
    assert!(
        sp_accepts(&decode_binding(&binding), Some(REQUEST_ID), Some(ACS), true)
            .await
            .is_err()
    );
}

#[test]
fn the_post_binding_echoes_relay_state_verbatim_and_carries_one_line_of_base64() {
    let mut case = Case::new();
    let relay = r#"<a href="x">&'</a>"#;
    case.relay_state = Some(relay.into());
    let issued = case.issue_ok();
    assert_eq!(issued.binding.relay_state.as_deref(), Some(relay));
    assert!(!issued.binding.saml_response.contains(['\n', '\r', ' ']));
    assert!(!decode(&issued).starts_with("<?xml"));

    case.relay_state = None;
    assert_eq!(case.issue_ok().binding.relay_state, None);
}
