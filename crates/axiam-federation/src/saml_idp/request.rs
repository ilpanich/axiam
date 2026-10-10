//! Receiving an `AuthnRequest` (T23.2.3): decoding, parsing and signature
//! verification for the SSO endpoint, on both bindings.
//!
//! Pure and synchronous, like the rest of this module: no I/O, no lookups. The
//! SSO endpoint calls these in order — decode, parse, find the SP by the parsed
//! `Issuer`, verify — and every refusal here happens **before** any service
//! provider is looked up, any row is written or any person is sent to a
//! sign-in page.
//!
//! # What is refused before XML parsing
//!
//! * **Size.** The encoded value is bounded ([`MAX_ENCODED_REQUEST_BYTES`]),
//!   and so is the document it decodes to ([`MAX_REQUEST_XML_BYTES`]). On the
//!   HTTP-Redirect binding the document is raw DEFLATE, and inflating stops one
//!   byte past the bound: a decompression bomb costs at most that much memory,
//!   however small its compressed form.
//! * **Any markup declaration.** An `AuthnRequest` has no use for a DTD, so a
//!   document containing `<!` other than a comment or a CDATA section —
//!   `<!DOCTYPE`, `<!ENTITY`, `<!ELEMENT`, `<!ATTLIST` — is refused on its
//!   bytes, before libxml sees it. That is the whole defence against external
//!   entities and entity expansion ("billion laughs"): there is no entity to
//!   expand. libxml is then run without recovery and without network access, so
//!   a malformed document is refused rather than repaired into something the
//!   signature check and the field reader might read differently.
//!
//! # Signatures
//!
//! * **HTTP-POST** — an enveloped `ds:Signature`, and only one place may hold it:
//!   the child of the `AuthnRequest` root, with exactly one reference, naming the
//!   root's `ID`. Any other `ds:Signature` anywhere refuses the document (the
//!   placement rule D-23 gave the SP side). The one admitted signature is
//!   verified by xmlsec against the SP's registered certificate, on its own
//!   node, with SHA-1 algorithms refused.
//! * **HTTP-Redirect** — the `Signature` query parameter over the octets SAML
//!   Bindings §3.4.4.1 names, **exactly as received**:
//!   `SAMLRequest=…[&RelayState=…]&SigAlg=…`, each value still percent-encoded
//!   the way the SP encoded it. Re-encoding the decoded values (what
//!   `samael`'s `UrlVerifier` does) would verify a string the SP never signed.
//!   Each of the four parameters may appear once; a repeated one is refused,
//!   since two readers could pick different copies. RSA with SHA-256, -384 or
//!   -512 only.
//!
//! An enveloped signature inside a Redirect-binding document is not a signature
//! of that binding (§3.4.4.1 says it must be removed); it is refused rather than
//! ignored, so no document carries a signature nobody checked.
//!
//! # Reused by single logout (T23.2.4)
//!
//! [`super::logout`] receives `LogoutRequest`s and `LogoutResponse`s with the same
//! decoding, the same refusals before libxml, the same placement rule —
//! [`signature_placement`] is a function over **any root element** — and the same
//! two signature verifiers. [`RedirectQuery`] carries either `SAMLRequest` or
//! `SAMLResponse` ([`MessageParam`]) and signs over whichever it was, exactly as
//! received. `verify_signed_xml`, which checks only the first signature, is never
//! called (D-23, D-38).

use std::io::Read;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Duration, Utc};
use samael::crypto::{
    AllowedSignatureAlgorithm, CertificateDer, CryptoProvider, ReduceMode, XmlSec,
};

use super::{NS_ASSERTION, NS_PROTOCOL};

/// XML-DSig namespace.
const NS_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";

/// The largest `AuthnRequest` document accepted, in bytes. A real one is a
/// kilobyte or two; a signed one with a certificate in `KeyInfo` a few more.
pub const MAX_REQUEST_XML_BYTES: usize = 64 * 1024;

/// The largest encoded `SAMLRequest` value accepted, in bytes (base64 of
/// [`MAX_REQUEST_XML_BYTES`], with room for line breaks on the POST binding).
pub const MAX_ENCODED_REQUEST_BYTES: usize = 96 * 1024;

/// How old an `IssueInstant` may be: five minutes, the assertion lifetime. With
/// the clock-skew allowance on either side, this is the window the pending
/// row's replay guard must outlive (it does: ten minutes).
pub const REQUEST_MAX_AGE_SECS: i64 = 300;

/// The HTTP-POST binding URN, the only `ProtocolBinding` a response is sent by.
pub const BINDING_HTTP_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

/// `NameIDPolicy@Format` meaning "whatever the IdP chooses".
pub const NAME_ID_FORMAT_UNSPECIFIED: &str =
    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

/// The `Issuer@Format` of an entity, the only one an `AuthnRequest`'s issuer
/// may carry (SAML Core §3.2.1, when present).
const NAME_ID_FORMAT_ENTITY: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";

/// The signature algorithms an enveloped request signature may use: no SHA-1.
/// The SAML SP verifier takes the same list (#531).
pub(crate) const ALLOWED_XML_SIGNATURE_ALGORITHMS: [AllowedSignatureAlgorithm; 6] = [
    AllowedSignatureAlgorithm::RsaSha256,
    AllowedSignatureAlgorithm::RsaSha384,
    AllowedSignatureAlgorithm::RsaSha512,
    AllowedSignatureAlgorithm::EcdsaSha256,
    AllowedSignatureAlgorithm::EcdsaSha384,
    AllowedSignatureAlgorithm::EcdsaSha512,
];

/// Why an `AuthnRequest` was refused before any lookup.
///
/// Fixed strings with no value in them, so a refusal can be logged as is. None
/// of these is delivered to an SP: the request is not yet known to come from
/// one, so the endpoint answers with an error page that posts nowhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    /// The message is larger than this endpoint reads.
    #[error("the SAML request is too large")]
    TooLarge,
    /// No `SAMLRequest`, or it is not base64.
    #[error("the SAML request is missing or not base64")]
    Encoding,
    /// The Redirect binding's DEFLATE stream is not valid.
    #[error("the SAML request does not inflate")]
    Inflate,
    /// The document contains a markup declaration (a DTD, an entity).
    #[error("the SAML request declares a DTD or an entity")]
    Dtd,
    /// The document is not well-formed UTF-8 XML.
    #[error("the SAML request is not well-formed XML")]
    Malformed,
    /// The root is not a SAML 2.0 `samlp:AuthnRequest`.
    #[error("the message is not a SAML 2.0 AuthnRequest")]
    NotAnAuthnRequest,
    /// `ID` is missing or not a request id this IdP will echo.
    #[error("the AuthnRequest ID is missing or invalid")]
    InvalidId,
    /// An attribute or child element is missing, repeated or malformed.
    #[error("the AuthnRequest is malformed")]
    InvalidField,
    /// `IssueInstant` is outside the accepted window.
    #[error("the AuthnRequest IssueInstant is outside the accepted window")]
    Stale,
    /// The request names a `Subject`, which this IdP does not honour.
    #[error("an AuthnRequest naming a Subject is not supported")]
    SubjectUnsupported,
    /// A query parameter of the Redirect binding appears more than once.
    #[error("a SAML query parameter is repeated")]
    DuplicateParameter,
    /// A signature sits somewhere a signature may not.
    #[error("a signature is placed where none may be")]
    SignaturePlacement,
    /// The SP requires signed requests and this one is not signed.
    #[error("the AuthnRequest is not signed")]
    SignatureMissing,
    /// The signature algorithm is not one this IdP accepts.
    #[error("the signature algorithm is not accepted")]
    SignatureAlgorithm,
    /// The root is not a SAML 2.0 `samlp:LogoutRequest` or `samlp:LogoutResponse`.
    #[error("the message is not a SAML 2.0 LogoutRequest or LogoutResponse")]
    NotALogoutMessage,
    /// A `LogoutRequest` that names no `NameID`, or more than one.
    #[error("the LogoutRequest does not name exactly one NameID")]
    NameIdMissing,
    /// A `LogoutRequest` naming its principal by `BaseID` or `EncryptedID`,
    /// neither of which this IdP issues.
    #[error("a BaseID or EncryptedID is not supported")]
    NameIdUnsupported,
    /// More `SessionIndex` elements than one request may carry.
    #[error("the LogoutRequest carries too many SessionIndex elements")]
    TooManySessionIndexes,
    /// The request's `NotOnOrAfter` has passed.
    #[error("the LogoutRequest has expired")]
    Expired,
    /// The message carries no `Destination`.
    #[error("the message has no Destination")]
    DestinationMissing,
    /// The signature does not verify against the SP's certificate.
    #[error("the AuthnRequest signature does not verify")]
    SignatureInvalid,
}

/// The fields of an `AuthnRequest` the SSO endpoint acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAuthnRequest {
    /// `ID`, already checked by [`super::check_request_id`].
    pub id: String,
    /// `IssueInstant`.
    pub issue_instant: DateTime<Utc>,
    /// `Destination`, when present.
    pub destination: Option<String>,
    /// The `Issuer` element's text: the SP's entity id.
    pub issuer: String,
    /// `ForceAuthn`.
    pub force_authn: bool,
    /// `IsPassive`.
    pub is_passive: bool,
    /// `AssertionConsumerServiceURL`.
    pub acs_url: Option<String>,
    /// `AssertionConsumerServiceIndex`.
    pub acs_index: Option<u16>,
    /// `ProtocolBinding`.
    pub protocol_binding: Option<String>,
    /// `NameIDPolicy@Format`.
    pub name_id_format: Option<String>,
    /// Whether the document carries the (one admissible) enveloped signature.
    pub enveloped_signature: bool,
}

/// Decode an HTTP-Redirect `SAMLRequest` value (already URL-decoded): base64,
/// then raw DEFLATE inflated to at most [`MAX_REQUEST_XML_BYTES`].
///
/// # Errors
///
/// [`RequestError::TooLarge`], [`RequestError::Encoding`],
/// [`RequestError::Inflate`], [`RequestError::Malformed`] (not UTF-8).
pub fn decode_redirect(value: &str) -> Result<String, RequestError> {
    let compressed = decode_base64(value, false)?;
    let mut inflated = Vec::with_capacity(4096);
    flate2::read::DeflateDecoder::new(compressed.as_slice())
        .take(MAX_REQUEST_XML_BYTES as u64 + 1)
        .read_to_end(&mut inflated)
        .map_err(|_| RequestError::Inflate)?;
    if inflated.len() > MAX_REQUEST_XML_BYTES {
        return Err(RequestError::TooLarge);
    }
    String::from_utf8(inflated).map_err(|_| RequestError::Malformed)
}

/// Decode an HTTP-POST `SAMLRequest` value: base64 of the document, line breaks
/// tolerated (some SPs wrap at 76 columns).
///
/// # Errors
///
/// [`RequestError::TooLarge`], [`RequestError::Encoding`],
/// [`RequestError::Malformed`] (not UTF-8).
pub fn decode_post(value: &str) -> Result<String, RequestError> {
    let bytes = decode_base64(value, true)?;
    if bytes.len() > MAX_REQUEST_XML_BYTES {
        return Err(RequestError::TooLarge);
    }
    String::from_utf8(bytes).map_err(|_| RequestError::Malformed)
}

fn decode_base64(value: &str, allow_line_breaks: bool) -> Result<Vec<u8>, RequestError> {
    if value.len() > MAX_ENCODED_REQUEST_BYTES {
        return Err(RequestError::TooLarge);
    }
    let compact: String = if allow_line_breaks {
        value
            .chars()
            .filter(|c| !matches!(c, '\r' | '\n' | ' ' | '\t'))
            .collect()
    } else {
        value.to_owned()
    };
    if compact.is_empty() {
        return Err(RequestError::Encoding);
    }
    STANDARD
        .decode(compact.as_bytes())
        .map_err(|_| RequestError::Encoding)
}

/// Refuse a document that contains any markup declaration.
///
/// `<!--` (a comment) and `<![CDATA[` are the only two constructs beginning
/// `<!` that may appear in a document without a DTD; anything else beginning
/// `<!` — `<!DOCTYPE`, `<!ENTITY`, `<!ELEMENT`, `<!ATTLIST`, `<!NOTATION`, in
/// any case — is a declaration, and an `AuthnRequest` needs none.
///
/// # Errors
///
/// [`RequestError::Dtd`].
pub fn refuse_markup_declarations(document: &str) -> Result<(), RequestError> {
    let mut rest = document;
    while let Some(at) = rest.find("<!") {
        let tail = &rest[at..];
        if !(tail.starts_with("<!--") || tail.starts_with("<![CDATA[")) {
            return Err(RequestError::Dtd);
        }
        rest = &rest[at + 2..];
    }
    Ok(())
}

/// Refuse a document that is not plainly UTF-8: one containing a NUL (which is
/// how UTF-16 and UTF-32 spell ASCII, and would hide a `<!DOCTYPE` from
/// [`refuse_markup_declarations`]), or one whose XML declaration names another
/// encoding. The parse here forces UTF-8, and xmlsec's honours the declaration;
/// refusing every other declaration keeps the two reading the same characters.
///
/// # Errors
///
/// [`RequestError::Malformed`].
pub fn refuse_other_encodings(document: &str) -> Result<(), RequestError> {
    if document.contains('\0') {
        return Err(RequestError::Malformed);
    }
    let trimmed = document.trim_start();
    if let Some(rest) = trimmed.strip_prefix("<?xml") {
        let declaration = rest.split("?>").next().unwrap_or_default();
        if let Some(at) = declaration.find("encoding") {
            let value = declaration[at + "encoding".len()..]
                .trim_start()
                .trim_start_matches('=')
                .trim_start()
                .trim_start_matches(['"', '\''])
                .split(['"', '\''])
                .next()
                .unwrap_or_default();
            if !value.eq_ignore_ascii_case("utf-8") {
                return Err(RequestError::Malformed);
            }
        }
    }
    Ok(())
}

/// Parse an `AuthnRequest` and check what needs no SP: shape, `Version`, `ID`,
/// `IssueInstant` against `now`, `Issuer`, and where a signature sits.
///
/// # Errors
///
/// A [`RequestError`]; nothing about the document is in it.
pub fn parse_authn_request(
    document: &str,
    now: DateTime<Utc>,
) -> Result<ParsedAuthnRequest, RequestError> {
    let doc = parse_xml(document)?;
    let root = doc.get_root_element().ok_or(RequestError::Malformed)?;
    if !is_element(&root, NS_PROTOCOL, "AuthnRequest") {
        return Err(RequestError::NotAnAuthnRequest);
    }
    if root.get_attribute("Version").as_deref() != Some("2.0") {
        return Err(RequestError::NotAnAuthnRequest);
    }

    let id = root.get_attribute("ID").ok_or(RequestError::InvalidId)?;
    super::check_request_id(&id).map_err(|_| RequestError::InvalidId)?;

    let issue_instant = fresh_issue_instant(&root, now)?;

    let children = root.get_child_elements();
    let issuer = read_issuer(&children)?;
    if children
        .iter()
        .any(|c| is_element(c, NS_ASSERTION, "Subject"))
    {
        return Err(RequestError::SubjectUnsupported);
    }
    let policies: Vec<_> = children
        .iter()
        .filter(|c| is_element(c, NS_PROTOCOL, "NameIDPolicy"))
        .collect();
    let name_id_format = match policies.as_slice() {
        [] => None,
        [policy] => policy.get_attribute("Format"),
        _ => return Err(RequestError::InvalidField),
    };

    let enveloped_signature = signature_placement(&doc, &root, &id)?;

    Ok(ParsedAuthnRequest {
        id,
        issue_instant,
        destination: root.get_attribute("Destination"),
        issuer,
        force_authn: xs_boolean(root.get_attribute("ForceAuthn"))?,
        is_passive: xs_boolean(root.get_attribute("IsPassive"))?,
        acs_url: root.get_attribute("AssertionConsumerServiceURL"),
        acs_index: root
            .get_attribute("AssertionConsumerServiceIndex")
            .map(|raw| raw.trim().parse::<u16>())
            .transpose()
            .map_err(|_| RequestError::InvalidField)?,
        protocol_binding: root.get_attribute("ProtocolBinding"),
        name_id_format,
        enveloped_signature,
    })
}

/// Parse a document the way every message this IdP receives is parsed: size
/// bound, no markup declaration, no other encoding — all on the bytes, before
/// libxml — then libxml without recovery and without network access.
pub(super) fn parse_xml(document: &str) -> Result<libxml::tree::Document, RequestError> {
    if document.len() > MAX_REQUEST_XML_BYTES {
        return Err(RequestError::TooLarge);
    }
    refuse_markup_declarations(document)?;
    refuse_other_encodings(document)?;

    let options = libxml::parser::ParserOptions {
        recover: false,
        no_net: true,
        no_def_dtd: true,
        ignore_enc: true,
        encoding: Some("UTF-8"),
        ..Default::default()
    };
    libxml::parser::Parser::default()
        .parse_string_with_options(document.as_bytes(), options)
        .map_err(|_| RequestError::Malformed)
}

/// `IssueInstant`, required, and inside the accepted window: at most
/// [`REQUEST_MAX_AGE_SECS`] old and no further ahead than the clock-skew
/// allowance.
pub(super) fn fresh_issue_instant(
    root: &libxml::tree::Node,
    now: DateTime<Utc>,
) -> Result<DateTime<Utc>, RequestError> {
    let issue_instant = root
        .get_attribute("IssueInstant")
        .and_then(|raw| DateTime::parse_from_rfc3339(raw.trim()).ok())
        .map(|t| t.with_timezone(&Utc))
        .ok_or(RequestError::InvalidField)?;
    let skew = Duration::seconds(crate::oidc::CLOCK_SKEW_LEEWAY_SECS as i64);
    if issue_instant > now + skew
        || issue_instant < now - Duration::seconds(REQUEST_MAX_AGE_SECS) - skew
    {
        return Err(RequestError::Stale);
    }
    Ok(issue_instant)
}

/// The one `saml:Issuer` among `children`: its text, the SP's entity id. Exactly
/// one, non-empty, and when it carries a `Format` the entity one.
pub(super) fn read_issuer(children: &[libxml::tree::Node]) -> Result<String, RequestError> {
    let issuers: Vec<_> = children
        .iter()
        .filter(|c| is_element(c, NS_ASSERTION, "Issuer"))
        .collect();
    let [issuer] = issuers.as_slice() else {
        return Err(RequestError::InvalidField);
    };
    if issuer
        .get_attribute("Format")
        .is_some_and(|f| f != NAME_ID_FORMAT_ENTITY)
    {
        return Err(RequestError::InvalidField);
    }
    let issuer = issuer.get_content().trim().to_owned();
    if issuer.is_empty() {
        return Err(RequestError::InvalidField);
    }
    Ok(issuer)
}

/// `xs:boolean`, absent meaning `false`.
fn xs_boolean(raw: Option<String>) -> Result<bool, RequestError> {
    match raw.as_deref().map(str::trim) {
        None | Some("false" | "0") => Ok(false),
        Some("true" | "1") => Ok(true),
        Some(_) => Err(RequestError::InvalidField),
    }
}

/// Where the document's signatures sit: `Ok(false)` for none, `Ok(true)` for
/// exactly one enveloped child of the root referencing the root's `ID`, and
/// [`RequestError::SignaturePlacement`] for anything else.
///
/// **A function over any root element** (D-38): `root` is whatever the caller
/// established the document's root to be — an `AuthnRequest` here, a
/// `LogoutRequest` or `LogoutResponse` in [`super::logout`] — and `root_id` its
/// `ID`. The rule never looks at the root's name, so it cannot differ between
/// message kinds.
pub(crate) fn signature_placement(
    doc: &libxml::tree::Document,
    root: &libxml::tree::Node,
    root_id: &str,
) -> Result<bool, RequestError> {
    let mut context = libxml::xpath::Context::new(doc).map_err(|()| RequestError::Malformed)?;
    let all = context
        .findnodes(
            &format!("//*[local-name()='Signature' and namespace-uri()='{NS_DSIG}']"),
            None,
        )
        .map_err(|()| RequestError::Malformed)?;
    if all.is_empty() {
        return Ok(false);
    }
    let at_root: Vec<_> = root
        .get_child_elements()
        .into_iter()
        .filter(|c| is_element(c, NS_DSIG, "Signature"))
        .collect();
    let ([signature], 1) = (at_root.as_slice(), all.len()) else {
        return Err(RequestError::SignaturePlacement);
    };
    let references: Vec<_> = signature
        .get_child_elements()
        .into_iter()
        .filter(|c| is_element(c, NS_DSIG, "SignedInfo"))
        .flat_map(|info| info.get_child_elements())
        .filter(|c| is_element(c, NS_DSIG, "Reference"))
        .collect();
    let expected = format!("#{root_id}");
    match references.as_slice() {
        [reference] if reference.get_attribute("URI").as_deref() == Some(expected.as_str()) => {
            Ok(true)
        }
        _ => Err(RequestError::SignaturePlacement),
    }
}

pub(super) fn is_element(node: &libxml::tree::Node, namespace: &str, name: &str) -> bool {
    node.get_name() == name
        && node
            .get_namespace()
            .is_some_and(|ns| ns.get_href() == namespace)
}

/// Verify a POST-binding request's enveloped signature against the SP's
/// registered certificate (DER). Call only after [`parse_authn_request`]
/// answered `enveloped_signature: true`, which is what established that the one
/// signature in the document is the root's own.
///
/// # Errors
///
/// [`RequestError::SignatureInvalid`] — a wrong key, a changed byte, a SHA-1
/// algorithm, or anything xmlsec refuses.
pub fn verify_post_signature(document: &str, sp_cert_der: &[u8]) -> Result<(), RequestError> {
    let cert = CertificateDer::from(sp_cert_der.to_vec());
    <XmlSec as CryptoProvider>::reduce_xml_to_signed_with_allowed_algorithms(
        document,
        &[cert],
        ReduceMode::PreDigest,
        Some(&ALLOWED_XML_SIGNATURE_ALGORITHMS),
    )
    .map(|_| ())
    .map_err(|_| RequestError::SignatureInvalid)
}

/// Which message parameter an HTTP-Redirect query carries (SAML Bindings
/// §3.4.4: exactly one of the two).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageParam {
    /// `SAMLRequest`.
    Request,
    /// `SAMLResponse`.
    Response,
}

impl MessageParam {
    /// The parameter's name, which is also the first octets of what a Redirect
    /// signature covers.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Request => "SAMLRequest",
            Self::Response => "SAMLResponse",
        }
    }
}

/// The HTTP-Redirect parameters, **as received** — still percent-encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedirectQuery<'q> {
    /// Which of `SAMLRequest` and `SAMLResponse` the query carries.
    pub param: MessageParam,
    /// The message parameter's value, raw.
    pub message: &'q str,
    /// `RelayState`, raw.
    pub relay_state: Option<&'q str>,
    /// `SigAlg`, raw.
    pub sig_alg: Option<&'q str>,
    /// `Signature`, raw.
    pub signature: Option<&'q str>,
}

impl<'q> RedirectQuery<'q> {
    /// Split a raw query string for the SSO endpoint, which takes a
    /// `SAMLRequest`. Parameters other than the four are ignored (a
    /// `SAMLResponse` among them); each of the four may appear at most once, and
    /// `SAMLRequest` must.
    ///
    /// # Errors
    ///
    /// [`RequestError::DuplicateParameter`], [`RequestError::Encoding`] (no
    /// `SAMLRequest`), [`RequestError::TooLarge`].
    pub fn parse(query: &'q str) -> Result<Self, RequestError> {
        Self::split(query, false)
    }

    /// Split a raw query string for the SLO endpoint, which takes **either**
    /// `SAMLRequest` or `SAMLResponse`, never both: a query naming both is
    /// ambiguous (two readers could pick different ones) and is refused. Each of
    /// the parameters may appear at most once.
    ///
    /// # Errors
    ///
    /// [`RequestError::DuplicateParameter`] (a repeated parameter, or both
    /// messages), [`RequestError::Encoding`] (neither), [`RequestError::TooLarge`].
    pub fn parse_logout(query: &'q str) -> Result<Self, RequestError> {
        Self::split(query, true)
    }

    fn split(query: &'q str, either: bool) -> Result<Self, RequestError> {
        if query.len() > MAX_ENCODED_REQUEST_BYTES * 3 {
            return Err(RequestError::TooLarge);
        }
        let (mut request, mut response, mut relay_state, mut sig_alg, mut signature) =
            (None, None, None, None, None);
        for pair in query.split('&') {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            let slot = match name {
                "SAMLRequest" => &mut request,
                "SAMLResponse" if either => &mut response,
                "RelayState" => &mut relay_state,
                "SigAlg" => &mut sig_alg,
                "Signature" => &mut signature,
                _ => continue,
            };
            if slot.replace(value).is_some() {
                return Err(RequestError::DuplicateParameter);
            }
        }
        let request = request.filter(|v: &&str| !v.is_empty());
        let response = response.filter(|v: &&str| !v.is_empty());
        let (param, message) = match (request, response) {
            (Some(message), None) => (MessageParam::Request, message),
            (None, Some(message)) => (MessageParam::Response, message),
            (Some(_), Some(_)) => return Err(RequestError::DuplicateParameter),
            (None, None) => return Err(RequestError::Encoding),
        };
        Ok(Self {
            param,
            message,
            relay_state,
            sig_alg,
            signature,
        })
    }

    /// Whether the query carries a signature (or a half of one).
    #[must_use]
    pub fn is_signed(&self) -> bool {
        self.sig_alg.is_some() || self.signature.is_some()
    }

    /// The message parameter, URL-decoded. A base64 value contains no space, so a
    /// `+` an SP left unencoded (and form decoding turned into a space) is put
    /// back.
    #[must_use]
    pub fn message(&self) -> String {
        url_decode(self.message).replace(' ', "+")
    }

    /// `RelayState`, URL-decoded, as it will be echoed.
    #[must_use]
    pub fn relay_state(&self) -> Option<String> {
        self.relay_state.map(url_decode)
    }

    /// Verify the query signature against the SP's certificate (DER), over the
    /// octets SAML Bindings §3.4.4.1 names, exactly as received:
    /// `SAMLRequest=…` (or `SAMLResponse=…`)`[&RelayState=…]&SigAlg=…`.
    ///
    /// # Errors
    ///
    /// [`RequestError::SignatureMissing`] (no `SigAlg` or no `Signature`),
    /// [`RequestError::SignatureAlgorithm`], [`RequestError::SignatureInvalid`].
    pub fn verify_signature(&self, sp_cert_der: &[u8]) -> Result<(), RequestError> {
        let (Some(sig_alg_raw), Some(signature_raw)) = (self.sig_alg, self.signature) else {
            return Err(RequestError::SignatureMissing);
        };
        let digest = match url_decode(sig_alg_raw).as_str() {
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => {
                openssl::hash::MessageDigest::sha256()
            }
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => {
                openssl::hash::MessageDigest::sha384()
            }
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => {
                openssl::hash::MessageDigest::sha512()
            }
            _ => return Err(RequestError::SignatureAlgorithm),
        };
        let signature = STANDARD
            .decode(url_decode(signature_raw).replace(' ', "+").as_bytes())
            .map_err(|_| RequestError::SignatureInvalid)?;

        let mut signed = format!("{}={}", self.param.name(), self.message);
        if let Some(relay_state) = self.relay_state {
            signed.push_str("&RelayState=");
            signed.push_str(relay_state);
        }
        signed.push_str("&SigAlg=");
        signed.push_str(sig_alg_raw);

        let public_key = openssl::x509::X509::from_der(sp_cert_der)
            .and_then(|cert| cert.public_key())
            .map_err(|_| RequestError::SignatureInvalid)?;
        if public_key.id() != openssl::pkey::Id::RSA {
            return Err(RequestError::SignatureAlgorithm);
        }
        let mut verifier = openssl::sign::Verifier::new(digest, &public_key)
            .map_err(|_| RequestError::SignatureInvalid)?;
        verifier
            .update(signed.as_bytes())
            .map_err(|_| RequestError::SignatureInvalid)?;
        match verifier.verify(&signature) {
            Ok(true) => Ok(()),
            _ => Err(RequestError::SignatureInvalid),
        }
    }
}

/// `application/x-www-form-urlencoded` decoding of one value.
fn url_decode(raw: &str) -> String {
    url::form_urlencoded::parse(format!("v={raw}").as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

/// Whether `requested` — an `AuthnRequest`'s `NameIDPolicy@Format` — can be
/// honoured by an SP configured for `configured`: absent, `unspecified`, or
/// the configured format's URN.
#[must_use]
pub fn name_id_format_compatible(
    requested: Option<&str>,
    configured: axiam_core::models::saml_sp::NameIdFormat,
) -> bool {
    match requested {
        None => true,
        Some(format) => format == NAME_ID_FORMAT_UNSPECIFIED || format == configured.urn(),
    }
}

#[cfg(test)]
mod tests;
