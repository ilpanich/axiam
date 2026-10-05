//! SAML single logout: receiving an SP's `LogoutRequest` / `LogoutResponse` and
//! building AXIAM's own (G-2, T23.2.4, D-37, D-38, D-39).
//!
//! Pure and synchronous, like the rest of this module: no I/O, no lookups. The
//! SLO endpoint (`handlers::saml_idp_slo`) calls these in order — decode with
//! [`super::request`]'s functions, [`parse_logout_message`], find the SP by the
//! parsed `Issuer`, verify — and every refusal here happens **before** any SP is
//! looked up, any session is touched or anything is sent.
//!
//! # Receiving
//!
//! Exactly [`super::request`]'s receiver: encoded value at most 96 KiB, document
//! at most 64 KiB, the inflate cap, markup declarations and non-UTF-8 encodings
//! refused on the bytes, libxml without recovery and without network. Then:
//!
//! * `Version` 2.0; `ID` a request id ([`super::check_request_id`]); an
//!   `IssueInstant` at most five minutes old and 60 s ahead; one `Issuer`;
//! * a `LogoutRequest`'s `NotOnOrAfter`, when present, has not passed;
//! * a `LogoutRequest` names **exactly one `NameID`**; a `BaseID` or an
//!   `EncryptedID` is refused, because AXIAM issues neither;
//! * at most [`MAX_SESSION_INDEXES`] `SessionIndex` elements; none means every
//!   session in which the SP holds that `NameID`;
//! * a `LogoutResponse` has an `InResponseTo` and a `Status`.
//!
//! The signature is **not** checked here: [`parse_logout_message`] reports where
//! it sits ([`signature_placement`](super::request::signature_placement), the
//! D-23 rule, for whichever root the message has), and the endpoint verifies it
//! with [`super::request::verify_post_signature`] (xmlsec, SHA-1 refused) or
//! [`RedirectQuery::verify_signature`](super::request::RedirectQuery::verify_signature)
//! — never `verify_signed_xml`, which checks only the first signature.
//!
//! # Sending, narrowly
//!
//! AXIAM signs a logout message in two cases only, and the endpoint enforces
//! both before calling here: a `LogoutRequest` for a session that was ended —
//! by its holder, or by a **verified** SP request — and a `LogoutResponse`
//! replying to a verified `LogoutRequest`. Nothing here signs for an unverified
//! party, so the tenant's key is never a signing oracle (T-373).
//!
//! * **HTTP-Redirect**: the signature is the **detached query signature**
//!   (`rsa-sha256` over `SAMLRequest=…|SAMLResponse=…[&RelayState=…]&SigAlg=…`),
//!   so **no XML signature exists** to be harvested as a wrapping gadget.
//! * **HTTP-POST**: enveloped exactly as the assertion's (the root's child, one
//!   reference to the root `ID`, exclusive c14n, `rsa-sha256`/`sha256`), and
//!   **re-verified** — shape and xmlsec — before it is returned.
//!
//! The destination is the SP's registered `slo_url` and the binding its
//! registered `slo_binding`, never a location from a message.

use axiam_core::models::saml_sp::{SamlBinding, SamlServiceProvider};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Duration, SubsecRound, Utc};
use rand::Rng;
use std::io::Write;
use uuid::Uuid;

use super::request::{
    MessageParam, RedirectQuery, RequestError, fresh_issue_instant, is_element, parse_xml,
    read_issuer, signature_placement,
};
use super::xml::{escape, instant};
use super::{
    ASSERTION_LIFETIME_SECS, MAX_RELAY_STATE_BYTES, NS_ASSERTION, NS_PROTOCOL, STATUS_PREFIX,
    SamlIdpError, SamlIdpIssuer, SamlIdpSigningKey, check_request_id, check_session_index, sign,
    xml,
};

/// The most `SessionIndex` elements one `LogoutRequest` may carry (D-38).
pub const MAX_SESSION_INDEXES: usize = 32;

/// The signature algorithm AXIAM signs a Redirect-bound message with.
const SIG_ALG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

/// `urn:…:status:PartialLogout`, the second-level code of a logout that did not
/// complete everywhere (SAML Core §3.7.3.2).
const STATUS_PARTIAL_LOGOUT: &str = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout";

/// The persistent `NameID` format, which carries qualifiers when AXIAM names the
/// principal back to the SP.
const NAME_ID_PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------

/// The fields of a `LogoutRequest` the SLO endpoint acts on.
#[derive(Clone, PartialEq, Eq)]
pub struct ParsedLogoutRequest {
    /// `ID`, already checked as a request id.
    pub id: String,
    /// `IssueInstant`.
    pub issue_instant: DateTime<Utc>,
    /// `Destination`, when present.
    pub destination: Option<String>,
    /// The `Issuer` element's text: the SP's entity id.
    pub issuer: String,
    /// `NotOnOrAfter`, when present (and not yet passed).
    pub not_on_or_after: Option<DateTime<Utc>>,
    /// The `NameID` value (trimmed).
    pub name_id: String,
    /// The `NameID`'s `Format`, when it carries one.
    pub name_id_format: Option<String>,
    /// The `SessionIndex` values, in order, without repeats. Empty means every
    /// session the SP holds for the `NameID`.
    pub session_indexes: Vec<String>,
    /// Whether the document carries the (one admissible) enveloped signature.
    pub enveloped_signature: bool,
}

// A `LogoutRequest` names a person's `NameID` and a live `SessionIndex`.
impl std::fmt::Debug for ParsedLogoutRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedLogoutRequest")
            .field("id", &self.id)
            .field("issuer", &self.issuer)
            .field("name_id", &"[REDACTED]")
            .field("session_indexes", &self.session_indexes.len())
            .finish_non_exhaustive()
    }
}

/// How an SP answered a `LogoutRequest` of AXIAM's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogoutStatus {
    /// Top-level `Success`, nothing nested: the SP ended its session.
    Success,
    /// Top-level `Success` with a nested `PartialLogout`: the SP ended some, not
    /// all.
    PartialLogout,
    /// Anything else: the SP did not log the principal out.
    Failed,
}

/// The fields of a `LogoutResponse` the SLO endpoint acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedLogoutResponse {
    /// `ID`, already checked as a request id.
    pub id: String,
    /// `IssueInstant`.
    pub issue_instant: DateTime<Utc>,
    /// `Destination`, when present.
    pub destination: Option<String>,
    /// The `Issuer` element's text: the SP's entity id.
    pub issuer: String,
    /// `InResponseTo`: the `ID` of AXIAM's request this answers.
    pub in_response_to: String,
    /// What the SP said.
    pub status: LogoutStatus,
    /// Whether the document carries the (one admissible) enveloped signature.
    pub enveloped_signature: bool,
}

/// A received logout message, parsed and not yet trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedLogoutMessage {
    /// An SP asks AXIAM to end a session.
    Request(ParsedLogoutRequest),
    /// An SP answers a request of AXIAM's.
    Response(ParsedLogoutResponse),
}

impl ParsedLogoutMessage {
    /// The message's `Issuer`: the entity id to look the SP up by.
    #[must_use]
    pub fn issuer(&self) -> &str {
        match self {
            Self::Request(r) => &r.issuer,
            Self::Response(r) => &r.issuer,
        }
    }

    /// The message's `Destination`, when it has one.
    #[must_use]
    pub fn destination(&self) -> Option<&str> {
        match self {
            Self::Request(r) => r.destination.as_deref(),
            Self::Response(r) => r.destination.as_deref(),
        }
    }

    /// Whether the document carries an enveloped signature.
    #[must_use]
    pub fn enveloped_signature(&self) -> bool {
        match self {
            Self::Request(r) => r.enveloped_signature,
            Self::Response(r) => r.enveloped_signature,
        }
    }
}

/// Parse a received logout message and check everything that needs no SP:
/// shape, `Version`, `ID`, `IssueInstant` against `now`, `Issuer`, the
/// request's `NotOnOrAfter`, `NameID`, the `SessionIndex` count, a response's
/// `InResponseTo` and `Status`, and where a signature sits.
///
/// # Errors
///
/// A [`RequestError`]; nothing about the document is in it.
pub fn parse_logout_message(
    document: &str,
    now: DateTime<Utc>,
) -> Result<ParsedLogoutMessage, RequestError> {
    let doc = parse_xml(document)?;
    let root = doc.get_root_element().ok_or(RequestError::Malformed)?;
    let is_request = is_element(&root, NS_PROTOCOL, "LogoutRequest");
    let is_response = is_element(&root, NS_PROTOCOL, "LogoutResponse");
    if !is_request && !is_response {
        return Err(RequestError::NotALogoutMessage);
    }
    if root.get_attribute("Version").as_deref() != Some("2.0") {
        return Err(RequestError::NotALogoutMessage);
    }
    let id = root.get_attribute("ID").ok_or(RequestError::InvalidId)?;
    check_request_id(&id).map_err(|_| RequestError::InvalidId)?;
    let issue_instant = fresh_issue_instant(&root, now)?;
    let children = root.get_child_elements();
    let issuer = read_issuer(&children)?;
    let destination = root.get_attribute("Destination");
    let enveloped_signature = signature_placement(&doc, &root, &id)?;

    if is_response {
        let in_response_to = root
            .get_attribute("InResponseTo")
            .ok_or(RequestError::InvalidField)?;
        check_request_id(&in_response_to).map_err(|_| RequestError::InvalidField)?;
        return Ok(ParsedLogoutMessage::Response(ParsedLogoutResponse {
            id,
            issue_instant,
            destination,
            issuer,
            in_response_to,
            status: read_status(&children)?,
            enveloped_signature,
        }));
    }

    let not_on_or_after = root
        .get_attribute("NotOnOrAfter")
        .map(|raw| {
            DateTime::parse_from_rfc3339(raw.trim())
                .map(|t| t.with_timezone(&Utc))
                .map_err(|_| RequestError::InvalidField)
        })
        .transpose()?;
    let skew = Duration::seconds(crate::oidc::CLOCK_SKEW_LEEWAY_SECS as i64);
    if not_on_or_after.is_some_and(|limit| limit + skew <= now) {
        return Err(RequestError::Expired);
    }

    // The principal. AXIAM issues a `NameID` and nothing else, so a `BaseID` or
    // an `EncryptedID` names nobody it knows: refused outright, and never read
    // as "no NameID, therefore every session".
    if children.iter().any(|c| {
        is_element(c, NS_ASSERTION, "BaseID") || is_element(c, NS_ASSERTION, "EncryptedID")
    }) {
        return Err(RequestError::NameIdUnsupported);
    }
    let names: Vec<_> = children
        .iter()
        .filter(|c| is_element(c, NS_ASSERTION, "NameID"))
        .collect();
    let [name_id] = names.as_slice() else {
        return Err(RequestError::NameIdMissing);
    };
    let name_id_format = name_id.get_attribute("Format");
    let name_id = name_id.get_content().trim().to_owned();
    if name_id.is_empty() {
        return Err(RequestError::NameIdMissing);
    }

    let mut session_indexes: Vec<String> = Vec::new();
    let mut seen = 0usize;
    for child in children
        .iter()
        .filter(|c| is_element(c, NS_PROTOCOL, "SessionIndex"))
    {
        seen += 1;
        if seen > MAX_SESSION_INDEXES {
            return Err(RequestError::TooManySessionIndexes);
        }
        let index = child.get_content().trim().to_owned();
        if index.is_empty() || index.len() > super::MAX_SESSION_INDEX_BYTES {
            return Err(RequestError::InvalidField);
        }
        if !session_indexes.contains(&index) {
            session_indexes.push(index);
        }
    }

    Ok(ParsedLogoutMessage::Request(ParsedLogoutRequest {
        id,
        issue_instant,
        destination,
        issuer,
        not_on_or_after,
        name_id,
        name_id_format,
        session_indexes,
        enveloped_signature,
    }))
}

/// The status a `LogoutResponse` reports: one `samlp:Status` with one top-level
/// `StatusCode`, which may carry one nested code.
fn read_status(children: &[libxml::tree::Node]) -> Result<LogoutStatus, RequestError> {
    let statuses: Vec<_> = children
        .iter()
        .filter(|c| is_element(c, NS_PROTOCOL, "Status"))
        .collect();
    let [status] = statuses.as_slice() else {
        return Err(RequestError::InvalidField);
    };
    let codes: Vec<_> = status
        .get_child_elements()
        .into_iter()
        .filter(|c| is_element(c, NS_PROTOCOL, "StatusCode"))
        .collect();
    let [top] = codes.as_slice() else {
        return Err(RequestError::InvalidField);
    };
    let top_value = top
        .get_attribute("Value")
        .ok_or(RequestError::InvalidField)?;
    if top_value != format!("{STATUS_PREFIX}Success") {
        return Ok(LogoutStatus::Failed);
    }
    let nested: Vec<_> = top
        .get_child_elements()
        .into_iter()
        .filter(|c| is_element(c, NS_PROTOCOL, "StatusCode"))
        .collect();
    match nested.as_slice() {
        [] => Ok(LogoutStatus::Success),
        [second] if second.get_attribute("Value").as_deref() == Some(STATUS_PARTIAL_LOGOUT) => {
            Ok(LogoutStatus::PartialLogout)
        }
        _ => Ok(LogoutStatus::Failed),
    }
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

/// Whom a `LogoutRequest` of AXIAM's is about, as the participant record holds
/// it: the `NameID` and `SessionIndex` **this SP** was given.
#[derive(Clone, Copy)]
pub struct LogoutSubject<'a> {
    /// The `NameID` value the SP was given.
    pub name_id: &'a str,
    /// Its format URN.
    pub name_id_format: &'a str,
    /// The per-SP `SessionIndex`.
    pub session_index: &'a str,
}

/// A logout message ready to deliver through the browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundLogout {
    /// The message's `ID`. For a `LogoutRequest`, 256 random bits: the caller
    /// stores only its SHA-256 and expects the SP's `InResponseTo` to name it.
    pub id: String,
    /// How to deliver it.
    pub delivery: LogoutDelivery,
}

/// How an outbound logout message reaches the SP's registered endpoint.
#[derive(Clone, PartialEq, Eq)]
pub enum LogoutDelivery {
    /// HTTP-Redirect: answer with a redirect to this URL — the SP's registered
    /// `slo_url` with the message and its detached signature in the query.
    Redirect {
        /// The full `Location`.
        location: String,
    },
    /// HTTP-POST: render an auto-submitting form posting `value` as `field` to
    /// `destination`.
    Post {
        /// The SP's registered `slo_url`, also the message's `Destination`.
        destination: String,
        /// `SAMLRequest` or `SAMLResponse`.
        field: &'static str,
        /// The signed document, base64, one line.
        value: String,
        /// The `RelayState` to echo, verbatim.
        relay_state: Option<String>,
    },
}

// The message is a signed logout of a person: never formatted.
impl std::fmt::Debug for LogoutDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Redirect { .. } => f.write_str("LogoutDelivery::Redirect([REDACTED])"),
            Self::Post { field, .. } => write!(f, "LogoutDelivery::Post({field}, [REDACTED])"),
        }
    }
}

/// A fresh `LogoutRequest` `ID`: `_` and 64 lower-case hex digits of CSPRNG
/// output — **256 random bits** (D-39), because the SP's `InResponseTo` is the
/// only thing that advances a logout chain, and the run stores its digest.
fn new_logout_request_id() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("_{}", hex::encode(bytes))
}

fn url_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// Raw DEFLATE then base64: an HTTP-Redirect message value before URL encoding.
fn deflate_base64(document: &[u8]) -> Result<String, SamlIdpError> {
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(document)
        .map_err(|_| SamlIdpError::SigningFailed)?;
    let compressed = encoder.finish().map_err(|_| SamlIdpError::SigningFailed)?;
    Ok(STANDARD.encode(compressed))
}

/// The registered endpoint and binding, or [`SamlIdpError::SloNotRegistered`].
fn slo_endpoint(sp: &SamlServiceProvider) -> Result<(&str, SamlBinding), SamlIdpError> {
    match (sp.slo_url.as_deref(), sp.slo_binding) {
        (Some(url), Some(binding)) => Ok((url, binding)),
        _ => Err(SamlIdpError::SloNotRegistered),
    }
}

impl SamlIdpIssuer {
    /// A signed `LogoutRequest` to `sp`, for the session described by `subject`.
    ///
    /// **The caller has established that the session ended** — its holder asked,
    /// or an SP's verified request did — and never calls this for anyone else
    /// (T-373). Delivered to the SP's registered `slo_url` on its registered
    /// `slo_binding`: HTTP-Redirect with a detached query signature (no XML
    /// signature exists), or HTTP-POST with an enveloped one, re-verified here.
    ///
    /// The request carries `NotOnOrAfter` five minutes ahead and the `NameID` and
    /// `SessionIndex` the SP was given, nothing else.
    ///
    /// # Errors
    ///
    /// A [`SamlIdpError`]: [`SamlIdpError::SloNotRegistered`],
    /// [`SamlIdpError::TenantMismatch`], [`SamlIdpError::SessionIndexInvalid`],
    /// the credential's refusals, [`SamlIdpError::SigningFailed`].
    pub fn logout_request(
        &self,
        tenant_id: Uuid,
        sp: &SamlServiceProvider,
        subject: &LogoutSubject<'_>,
        signing_key: &SamlIdpSigningKey,
        now: DateTime<Utc>,
    ) -> Result<OutboundLogout, SamlIdpError> {
        if sp.tenant_id != tenant_id {
            return Err(SamlIdpError::TenantMismatch);
        }
        let (slo_url, binding) = slo_endpoint(sp)?;
        check_session_index(subject.session_index)?;
        if subject.name_id.is_empty() || subject.name_id_format.is_empty() {
            return Err(SamlIdpError::NameIdUnavailable);
        }
        let now = now.trunc_subsecs(0);
        sign::check_credential(&signing_key.credential, tenant_id, now)?;

        let id = new_logout_request_id();
        let issuer = self.entity_id(tenant_id);
        let not_on_or_after = now + Duration::seconds(ASSERTION_LIFETIME_SECS);
        let build = |template: Option<&str>| {
            let mut out = String::with_capacity(2048);
            out.push_str(&format!(
                r#"<samlp:LogoutRequest xmlns:samlp="{NS_PROTOCOL}" xmlns:saml="{NS_ASSERTION}" ID="{id}" Version="2.0" IssueInstant="{}" Destination="{}" NotOnOrAfter="{}">"#,
                instant(now),
                escape(slo_url),
                instant(not_on_or_after),
            ));
            out.push_str(&format!("<saml:Issuer>{}</saml:Issuer>", escape(&issuer)));
            if let Some(template) = template {
                out.push_str(template);
            }
            if subject.name_id_format == NAME_ID_PERSISTENT {
                out.push_str(&format!(
                    r#"<saml:NameID Format="{}" NameQualifier="{}" SPNameQualifier="{}">{}</saml:NameID>"#,
                    escape(subject.name_id_format),
                    escape(&issuer),
                    escape(&sp.entity_id),
                    escape(subject.name_id),
                ));
            } else {
                out.push_str(&format!(
                    r#"<saml:NameID Format="{}">{}</saml:NameID>"#,
                    escape(subject.name_id_format),
                    escape(subject.name_id),
                ));
            }
            out.push_str(&format!(
                "<samlp:SessionIndex>{}</samlp:SessionIndex></samlp:LogoutRequest>",
                escape(subject.session_index)
            ));
            out
        };
        let delivery = deliver(
            MessageParam::Request,
            "LogoutRequest",
            &id,
            slo_url,
            binding,
            None,
            signing_key,
            build,
        )?;
        Ok(OutboundLogout { id, delivery })
    }

    /// A signed `LogoutResponse` to `sp`, answering the **verified**
    /// `LogoutRequest` whose `ID` is `in_response_to`: `Success`, or
    /// `Success` with a nested `PartialLogout` when `partial`.
    ///
    /// The caller has verified that request against the SP's registered
    /// certificate and never calls this for an unverified one (T-373).
    /// `relay_state` is the SP's own, at most 80 bytes, echoed to that SP only.
    ///
    /// # Errors
    ///
    /// As [`Self::logout_request`], and [`SamlIdpError::InvalidRequestId`],
    /// [`SamlIdpError::RelayStateTooLong`].
    pub fn logout_response(
        &self,
        tenant_id: Uuid,
        sp: &SamlServiceProvider,
        in_response_to: &str,
        relay_state: Option<&str>,
        partial: bool,
        signing_key: &SamlIdpSigningKey,
        now: DateTime<Utc>,
    ) -> Result<OutboundLogout, SamlIdpError> {
        if sp.tenant_id != tenant_id {
            return Err(SamlIdpError::TenantMismatch);
        }
        let (slo_url, binding) = slo_endpoint(sp)?;
        check_request_id(in_response_to)?;
        if relay_state.is_some_and(|r| r.len() > MAX_RELAY_STATE_BYTES) {
            return Err(SamlIdpError::RelayStateTooLong);
        }
        let now = now.trunc_subsecs(0);
        sign::check_credential(&signing_key.credential, tenant_id, now)?;

        let id = xml::new_id();
        let issuer = self.entity_id(tenant_id);
        let build = |template: Option<&str>| {
            let mut out = String::with_capacity(1536);
            out.push_str(&format!(
                r#"<samlp:LogoutResponse xmlns:samlp="{NS_PROTOCOL}" xmlns:saml="{NS_ASSERTION}" ID="{id}" Version="2.0" IssueInstant="{}" Destination="{}" InResponseTo="{}">"#,
                instant(now),
                escape(slo_url),
                escape(in_response_to),
            ));
            out.push_str(&format!("<saml:Issuer>{}</saml:Issuer>", escape(&issuer)));
            if let Some(template) = template {
                out.push_str(template);
            }
            out.push_str("<samlp:Status>");
            if partial {
                out.push_str(&format!(
                    r#"<samlp:StatusCode Value="{STATUS_PREFIX}Success"><samlp:StatusCode Value="{STATUS_PARTIAL_LOGOUT}"/></samlp:StatusCode>"#
                ));
            } else {
                out.push_str(&format!(
                    r#"<samlp:StatusCode Value="{STATUS_PREFIX}Success"/>"#
                ));
            }
            out.push_str("</samlp:Status></samlp:LogoutResponse>");
            out
        };
        let delivery = deliver(
            MessageParam::Response,
            "LogoutResponse",
            &id,
            slo_url,
            binding,
            relay_state,
            signing_key,
            build,
        )?;
        Ok(OutboundLogout { id, delivery })
    }
}

/// Sign and package one message for `binding`. `build` renders the document,
/// with the signature template when given one.
#[allow(clippy::too_many_arguments)]
fn deliver(
    param: MessageParam,
    root_name: &str,
    id: &str,
    slo_url: &str,
    binding: SamlBinding,
    relay_state: Option<&str>,
    signing_key: &SamlIdpSigningKey,
    build: impl Fn(Option<&str>) -> String,
) -> Result<LogoutDelivery, SamlIdpError> {
    let cert_der = sign::certificate_der(&signing_key.credential)?;
    let key_der = sign::private_key_der(signing_key)?;
    match binding {
        SamlBinding::HttpRedirect => {
            // No `ds:Signature` template: the signature is detached, over the
            // query octets, so the document carries none (T-373).
            let document = build(None);
            let mut query = format!(
                "{}={}",
                param.name(),
                url_encode(&deflate_base64(document.as_bytes())?)
            );
            if let Some(relay_state) = relay_state {
                query.push_str("&RelayState=");
                query.push_str(&url_encode(relay_state));
            }
            query.push_str("&SigAlg=");
            query.push_str(&url_encode(SIG_ALG_RSA_SHA256));
            let signature = sign::sign_octets(&query, &key_der)?;
            query.push_str("&Signature=");
            query.push_str(&url_encode(&STANDARD.encode(signature)));
            drop(key_der);

            // What an SP will do with it, done here first, over the octets as
            // they will be sent.
            RedirectQuery::parse_logout(&query)
                .and_then(|parsed| parsed.verify_signature(&cert_der))
                .map_err(|_| {
                    tracing::error!("SAML IdP: a Redirect logout failed its own check");
                    SamlIdpError::SigningFailed
                })?;
            let separator = if slo_url.contains('?') { '&' } else { '?' };
            Ok(LogoutDelivery::Redirect {
                location: format!("{slo_url}{separator}{query}"),
            })
        }
        SamlBinding::HttpPost => {
            let template = sign::signature_template(id, &cert_der);
            let signed = sign::sign(&build(Some(&template)), &key_der)?;
            drop(key_der);
            sign::verify_root_signed(&signed, &cert_der, root_name, id)?;
            Ok(LogoutDelivery::Post {
                destination: slo_url.to_owned(),
                field: param.name(),
                value: STANDARD.encode(signed.as_bytes()),
                relay_state: relay_state.map(str::to_owned),
            })
        }
    }
}

#[cfg(test)]
mod tests;
