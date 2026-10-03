//! Enveloped XML-DSig with the tenant's credential, and the check of what was
//! signed.
//!
//! Signing goes through `samael`'s `xmlsec` provider, the library the SP side
//! verifies with: it signs the **first** `ds:Signature` template in document
//! order (a pre-order walk from the root), registering every `ID` attribute so
//! the template's `#id` reference resolves. The issuer relies on that order and
//! nothing else: an assertion is signed on its own, as the document root, so its
//! template is the only one; a response's template sits after its `Issuer`,
//! before the embedded (already signed) assertion, so it is reached first.

use axiam_core::models::saml_idp_credential::{SamlIdpCredential, SamlIdpCredentialStatus};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use samael::crypto::{CertificateDer, CryptoProvider, XmlSec};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{SamlIdpError, SamlIdpSigningKey, xml};

/// XML-DSig namespace.
const NS_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
/// Exclusive XML canonicalization 1.0, without comments.
const C14N_EXCLUSIVE: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
/// The enveloped-signature transform.
const TRANSFORM_ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
/// RSA PKCS#1 v1.5 over SHA-256 (D-21).
const SIG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
/// SHA-256 digest.
const DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

/// Refuse a credential that is not the tenant's, not `active`, or not valid at
/// `now`.
///
/// `SamlIdpCredentialService::get_active_signing_key` returns the active row
/// whatever its dates (T23.2.1); this is where an expired or not-yet-valid one
/// stops. The interval is the certificate's, `not_before ≤ now < not_after`.
pub(super) fn check_credential(
    credential: &SamlIdpCredential,
    tenant_id: Uuid,
    now: DateTime<Utc>,
) -> Result<(), SamlIdpError> {
    if credential.tenant_id != tenant_id {
        return Err(SamlIdpError::TenantMismatch);
    }
    if credential.status != SamlIdpCredentialStatus::Active {
        return Err(SamlIdpError::CredentialNotActive);
    }
    if now < credential.not_before || now >= credential.not_after {
        return Err(SamlIdpError::CredentialNotValid);
    }
    Ok(())
}

/// The credential's certificate as DER, for `KeyInfo` and for checking the
/// output.
pub(super) fn certificate_der(credential: &SamlIdpCredential) -> Result<Vec<u8>, SamlIdpError> {
    crate::cert::pem_cert_to_der(&credential.certificate_pem)
        .map_err(|_| SamlIdpError::SigningFailed)
}

/// The private key as DER, decoded straight into a zeroizing buffer.
///
/// Decoded here rather than by the `pem` crate, whose parser keeps
/// intermediate copies of the base64 text it does not wipe. Accepts exactly one
/// `PRIVATE KEY` (PKCS#8, what T23.2.1 stores) or `RSA PRIVATE KEY` (PKCS#1)
/// block. A failure says nothing about the input.
pub(super) fn private_key_der(
    signing_key: &SamlIdpSigningKey,
) -> Result<Zeroizing<Vec<u8>>, SamlIdpError> {
    let pem: &str = signing_key.private_key_pem.as_str();
    let (begin, end) = [
        ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"),
        (
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
        ),
    ]
    .into_iter()
    .find(|(begin, _)| pem.trim_start().starts_with(begin))
    .ok_or(SamlIdpError::SigningFailed)?;
    let body_start = pem.find(begin).ok_or(SamlIdpError::SigningFailed)? + begin.len();
    let body_len = pem[body_start..]
        .find(end)
        .ok_or(SamlIdpError::SigningFailed)?;
    if !pem[body_start + body_len + end.len()..].trim().is_empty() {
        return Err(SamlIdpError::SigningFailed);
    }

    let mut base64_body = Zeroizing::new(String::with_capacity(body_len));
    base64_body.extend(
        pem[body_start..body_start + body_len]
            .chars()
            .filter(|c| !c.is_ascii_whitespace()),
    );
    let mut der = Zeroizing::new(vec![0u8; base64_body.len().div_ceil(4) * 3]);
    let written = STANDARD
        .decode_slice(base64_body.as_bytes(), der.as_mut_slice())
        .map_err(|_| SamlIdpError::SigningFailed)?;
    der.truncate(written);
    if der.is_empty() {
        return Err(SamlIdpError::SigningFailed);
    }
    Ok(der)
}

/// The `ds:Signature` template for the element whose `ID` is `id`, with the
/// signing certificate in `KeyInfo/X509Data`.
///
/// No whitespace between elements: canonicalization keeps text nodes, and a
/// template with none has nothing for a re-indenting proxy to change.
pub(super) fn signature_template(id: &str, cert_der: &[u8]) -> String {
    format!(
        concat!(
            r#"<ds:Signature xmlns:ds="{ns}">"#,
            r#"<ds:SignedInfo>"#,
            r#"<ds:CanonicalizationMethod Algorithm="{c14n}"/>"#,
            r#"<ds:SignatureMethod Algorithm="{sig}"/>"#,
            r##"<ds:Reference URI="#{id}">"##,
            r#"<ds:Transforms>"#,
            r#"<ds:Transform Algorithm="{enveloped}"/>"#,
            r#"<ds:Transform Algorithm="{c14n}"/>"#,
            r#"</ds:Transforms>"#,
            r#"<ds:DigestMethod Algorithm="{digest}"/>"#,
            r#"<ds:DigestValue></ds:DigestValue>"#,
            r#"</ds:Reference>"#,
            r#"</ds:SignedInfo>"#,
            r#"<ds:SignatureValue></ds:SignatureValue>"#,
            r#"<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"#,
            r#"</ds:Signature>"#
        ),
        ns = NS_DSIG,
        c14n = C14N_EXCLUSIVE,
        sig = SIG_RSA_SHA256,
        id = xml::escape(id),
        enveloped = TRANSFORM_ENVELOPED,
        digest = DIGEST_SHA256,
        cert = STANDARD.encode(cert_der),
    )
}

/// Sign the first signature template in `document`.
pub(super) fn sign(document: &str, key_der: &[u8]) -> Result<String, SamlIdpError> {
    match <XmlSec as CryptoProvider>::sign_xml(document.as_bytes(), key_der) {
        Ok(signed) => Ok(xml::strip_declaration(&signed).to_owned()),
        Err(error) => {
            // The error is xmlsec's or libxml's fixed text; it never carries
            // the key or the document.
            tracing::error!(%error, "SAML IdP: signing failed");
            Err(SamlIdpError::SigningFailed)
        }
    }
}

/// Check the finished response before it leaves: every signature verifies
/// against the credential's certificate, and the document has exactly the
/// shape the issuer meant to sign.
///
/// * exactly one `saml:Assertion`, the root's child, with `ID = assertion_id`;
/// * one `ds:Signature` in the assertion, referencing `#assertion_id`;
/// * when `response_signed`, one more, a child of the root, referencing
///   `#response_id`; otherwise none there;
/// * no other `ds:Signature` anywhere, and no duplicate `ID`.
///
/// Signatures are checked with the same xmlsec verifier the SP side uses, one
/// document per signature: the response as delivered (whose first signature is
/// the response's when it is signed, the assertion's otherwise), and the
/// assertion lifted out on its own when the response is signed too.
pub(super) fn verify_output(
    response: &str,
    cert_der: &[u8],
    response_id: &str,
    assertion_id: &str,
    response_signed: bool,
) -> Result<(), SamlIdpError> {
    let fail = |reason: &'static str| {
        tracing::error!(reason, "SAML IdP: the signed response failed its own check");
        SamlIdpError::SigningFailed
    };

    let parser = libxml::parser::Parser::default();
    let doc = parser
        .parse_string(response.as_bytes())
        .map_err(|_| fail("unparseable output"))?;
    let root = doc.get_root_element().ok_or_else(|| fail("no root"))?;
    if !is_element(&root, super::NS_PROTOCOL, "Response")
        || root.get_attribute("ID").as_deref() != Some(response_id)
    {
        return Err(fail("root is not the response"));
    }

    let mut context = libxml::xpath::Context::new(&doc).map_err(|()| fail("no XPath context"))?;
    let count = |context: &mut libxml::xpath::Context, path: &str| {
        context
            .findnodes(path, None)
            .map(|nodes| nodes.len())
            .map_err(|()| fail("XPath failed"))
    };
    if count(&mut context, "//*[local-name()='Assertion']")? != 1 {
        return Err(fail("not exactly one Assertion"));
    }
    let signatures = count(
        &mut context,
        &format!("//*[local-name()='Signature' and namespace-uri()='{NS_DSIG}']"),
    )?;
    if signatures != if response_signed { 2 } else { 1 } {
        return Err(fail("unexpected number of signatures"));
    }
    let ids = context
        .findnodes("//@ID", None)
        .map_err(|()| fail("XPath failed"))?
        .iter()
        .map(libxml::tree::Node::get_content)
        .collect::<Vec<_>>();
    if ids.len() != 2 || ids[0] == ids[1] {
        return Err(fail("unexpected IDs"));
    }

    let children = root.get_child_elements();
    let assertions: Vec<_> = children
        .iter()
        .filter(|c| is_element(c, super::NS_ASSERTION, "Assertion"))
        .collect();
    let [assertion] = assertions.as_slice() else {
        return Err(fail("the Assertion is not the root's child"));
    };
    if assertion.get_attribute("ID").as_deref() != Some(assertion_id)
        || !signature_child_references(assertion, assertion_id)
    {
        return Err(fail("the assertion's signature does not reference it"));
    }
    if signature_child_references(&root, response_id) != response_signed {
        return Err(fail("the response signature is not as intended"));
    }

    let cert = CertificateDer::from(cert_der.to_vec());
    let verify = |document: &str| {
        <XmlSec as CryptoProvider>::verify_signed_xml(document.as_bytes(), &cert, Some("ID"))
            .map_err(|_| fail("a signature does not verify"))
    };
    verify(response)?;
    if response_signed {
        verify(&doc.node_to_string(assertion))?;
    }
    Ok(())
}

fn is_element(node: &libxml::tree::Node, namespace: &str, name: &str) -> bool {
    node.get_name() == name
        && node
            .get_namespace()
            .is_some_and(|ns| ns.get_href() == namespace)
}

/// Whether `parent` has exactly one `ds:Signature` child, whose one reference
/// is `#id`.
fn signature_child_references(parent: &libxml::tree::Node, id: &str) -> bool {
    let signatures: Vec<_> = parent
        .get_child_elements()
        .into_iter()
        .filter(|c| is_element(c, NS_DSIG, "Signature"))
        .collect();
    let [signature] = signatures.as_slice() else {
        return false;
    };
    let references: Vec<_> = signature
        .get_child_elements()
        .into_iter()
        .filter(|c| is_element(c, NS_DSIG, "SignedInfo"))
        .flat_map(|info| info.get_child_elements())
        .filter(|c| is_element(c, NS_DSIG, "Reference"))
        .collect();
    let expected = format!("#{id}");
    matches!(references.as_slice(), [reference] if reference.get_attribute("URI").as_deref() == Some(expected.as_str()))
}
