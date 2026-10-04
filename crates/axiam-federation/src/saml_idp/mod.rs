//! SAML 2.0 identity provider: assertion issuance (G-2, T23.2.2).
//!
//! AXIAM as a SAML IdP turns an authenticated AXIAM session into a signed
//! `<samlp:Response>` for a registered service provider. This module is the
//! **issuance library** — pure, synchronous, no I/O, no routes. The SSO endpoint
//! (T23.2.3) resolves the tenant from the request path, parses and checks the
//! `AuthnRequest`, runs the login hop, loads the user's groups and roles and the
//! tenant's active signing credential, and then calls
//! [`SamlIdpIssuer::issue`]; SLO (T23.2.4) relies on the `SessionIndex` written
//! here being the AXIAM session id.
//!
//! # What is issued
//!
//! | Element | Value |
//! |---|---|
//! | `Response/@Destination`, `SubjectConfirmationData/@Recipient` | the ACS URL used, which must be one the SP registered (exact match) |
//! | `Response/@InResponseTo`, `SubjectConfirmationData/@InResponseTo` | the `AuthnRequest` id when SP-initiated; **absent** when IdP-initiated (SAML Profiles §4.1.4.2) |
//! | `Issuer` (response and assertion) | [`idp_entity_id`] of the tenant from the request path |
//! | `NameID` | persistent pairwise ([`pairwise_name_id`], D-22) by default; the user's email when the SP asks for `emailAddress` |
//! | `SubjectConfirmation/@Method` | bearer |
//! | `SubjectConfirmationData/@NotOnOrAfter`, `Conditions/@NotOnOrAfter` | now + [`ASSERTION_LIFETIME_SECS`] (5 minutes) |
//! | `Conditions/@NotBefore` | now − [`crate::oidc::CLOCK_SKEW_LEEWAY_SECS`] (the existing skew allowance, 60 s) |
//! | `AudienceRestriction/Audience` | the SP's entity id |
//! | `AuthnStatement/@AuthnInstant` | the session's `authenticated_at` |
//! | `AuthnStatement/@SessionIndex` | the AXIAM session id |
//! | `AuthnContextClassRef` | [`authn_context_class_ref`] of the session's `amr` |
//! | `AttributeStatement` | the SP's attribute mapping over user fields, group names and role names |
//!
//! # Signing
//!
//! Enveloped XML-DSig, `rsa-sha256` over a `sha256` digest with exclusive
//! canonicalization, the reference URI naming the signed element's `ID`, and
//! the credential's certificate in `KeyInfo/X509Data`. The **assertion is
//! always signed**; the response is signed as well when the SP's
//! `sign_responses` is set, and then *after* the assertion, so its signature
//! covers the signed assertion. Before anything is returned, every signature in
//! the output is verified against the credential's certificate and the output's
//! shape is checked: exactly one `Assertion`, exactly the signatures intended,
//! each referencing the element it sits in. A builder bug that would emit a
//! wrapped or mis-referenced document fails closed here rather than at an SP.
//!
//! The credential must be the tenant's, `active`, and inside its validity
//! window (`not_before ≤ now < not_after`); anything else is refused, never
//! signed. The private key is turned into DER inside a zeroizing buffer and is
//! never formatted, logged or carried in an error.
//!
//! # Failure responses are never signed
//!
//! [`SamlIdpIssuer::failure`] builds the status-only envelopes the SSO endpoint
//! needs (`Requester`, `Responder`, `NoPassive`, `AuthnFailed`,
//! `RequestDenied`, `InvalidNameIDPolicy`), with no status message or detail.
//! They carry no assertion, and SAML Profiles §4.1.3.5 asks for a signature only
//! over a response that does. Signing them would hand anyone who can send an
//! `AuthnRequest` a document signed with the tenant's key, containing a request
//! id of their choosing and no assertion — exactly the gadget a signature
//! wrapping attack against a lax SP needs. So the key signs one shape of
//! document only: a response carrying exactly one assertion.
//!
//! # Encryption (D-2)
//!
//! Not implemented: `samael` decrypts assertions but has no encryption API, and
//! no oracle in the tree verifies an `EncryptedAssertion` built with AES-256-GCM.
//! An SP registered with `encrypt_assertions` is **refused** with `Responder`
//! ([`SamlIdpError::EncryptionUnsupported`]) — never silently sent plaintext.

pub mod idp_metadata;
mod pairwise;
pub mod request;
mod sign;
pub mod sp_metadata;
pub mod xml;

#[cfg(test)]
mod tests;

use std::collections::BTreeSet;

use axiam_core::models::group::Group;
use axiam_core::models::role::Role;
use axiam_core::models::saml_sp::{
    AttributeSource, NameIdFormat, SamlBinding, SamlServiceProvider,
};
use axiam_core::models::session::{Amr, Session};
use axiam_core::models::user::{ProfileClaims, User};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Duration, SubsecRound, Utc};
use uuid::Uuid;

pub use self::pairwise::{PairwiseKey, pairwise_name_id};
pub use self::xml::MAX_REQUEST_ID_BYTES;
pub use axiam_pki::saml_signing::SamlIdpSigningKey;

/// How long an issued assertion, and its bearer confirmation, may be used:
/// five minutes (plan §4 G-2, *Security rules*).
pub const ASSERTION_LIFETIME_SECS: i64 = 300;

/// The longest `RelayState` the HTTP-POST binding may carry, in bytes (SAML
/// Bindings §3.5.3, which defers to §3.4.3: "MUST NOT exceed 80 bytes").
pub const MAX_RELAY_STATE_BYTES: usize = 80;

/// The `samlp:` protocol namespace.
const NS_PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
/// The `saml:` assertion namespace.
const NS_ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
/// Bearer subject confirmation (SAML Profiles §3.3).
const CM_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

/// `AuthnContextClassRef` for evidence that proves two distinct factors: the
/// REFEDS MFA profile, the multi-factor class SAML service providers recognise
/// (SAML 2.0 defines no generic "MFA" class).
pub const AUTHN_CONTEXT_MFA: &str = "https://refeds.org/profile/mfa";
/// `AuthnContextClassRef` for an X.509 client certificate.
pub const AUTHN_CONTEXT_X509: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:X509";
/// `AuthnContextClassRef` for a password presented over TLS (every AXIAM
/// password login: TLS is mandatory on every external surface).
pub const AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT: &str =
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
/// `AuthnContextClassRef` when AXIAM holds no evidence it can name.
pub const AUTHN_CONTEXT_UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";

// ---------------------------------------------------------------------------
// The IdP's identifiers
// ---------------------------------------------------------------------------

// Defined in `crate::saml_idp_urls`, which is **not** behind the `saml` feature,
// so contract §29's `get_idp` computes the same strings in a build without
// SAML. Re-exported here, where the issuer, the SSO endpoint and the metadata
// document have always imported them from.
pub use crate::saml_idp_urls::{idp_entity_id, idp_slo_url, idp_sso_url};

// ---------------------------------------------------------------------------
// Status codes and errors
// ---------------------------------------------------------------------------

/// The SAML status a refusal is answered with (SAML Core §3.2.2.2).
///
/// Each value is a fixed (top-level, second-level) pair, so the SSO endpoint
/// can only ever say one of these and nothing more: no `StatusMessage`, no
/// `StatusDetail`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SamlStatus {
    /// The request was at fault.
    Requester,
    /// AXIAM could not or would not answer it.
    Responder,
    /// `IsPassive` was set and a passive answer is impossible.
    NoPassive,
    /// The principal could not be authenticated.
    AuthnFailed,
    /// The request is refused by policy.
    RequestDenied,
    /// The requested or configured `NameID` cannot be formed for this user.
    InvalidNameIdPolicy,
}

const STATUS_PREFIX: &str = "urn:oasis:names:tc:SAML:2.0:status:";

impl SamlStatus {
    /// The top-level `StatusCode` URN.
    #[must_use]
    pub const fn top_level(self) -> &'static str {
        match self {
            Self::Requester => "urn:oasis:names:tc:SAML:2.0:status:Requester",
            Self::Responder
            | Self::NoPassive
            | Self::AuthnFailed
            | Self::RequestDenied
            | Self::InvalidNameIdPolicy => "urn:oasis:names:tc:SAML:2.0:status:Responder",
        }
    }

    /// The nested second-level `StatusCode` URN, if there is one.
    #[must_use]
    pub const fn second_level(self) -> Option<&'static str> {
        match self {
            Self::Requester | Self::Responder => None,
            Self::NoPassive => Some("urn:oasis:names:tc:SAML:2.0:status:NoPassive"),
            Self::AuthnFailed => Some("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"),
            Self::RequestDenied => Some("urn:oasis:names:tc:SAML:2.0:status:RequestDenied"),
            Self::InvalidNameIdPolicy => {
                Some("urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy")
            }
        }
    }
}

/// Why an assertion was not issued.
///
/// Every variant is a fixed string with **no value in it** — not the user, the
/// SP, the ACS URL or anything from the key — so it can be logged as is and
/// never leaks through [`SamlIdpError::status`], which is all an SP is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SamlIdpError {
    /// The SP row, user, session, credential, a group or a role belongs to a
    /// tenant other than the one of the request path.
    #[error("a SAML issuance input belongs to another tenant")]
    TenantMismatch,
    /// The session is not the user's, or has expired.
    #[error("the session does not authenticate this user")]
    SessionMismatch,
    /// The account may not act (`axiam_auth::service::account_may_act`).
    #[error("the account may not sign in")]
    AccountMayNotAct,
    /// The SP is registered but disabled.
    #[error("the service provider is disabled")]
    SpDisabled,
    /// The ACS URL is not one the SP registered. The SSO endpoint must not
    /// deliver anything to it — not even a failure response.
    #[error("the ACS URL is not registered for this service provider")]
    AcsNotRegistered,
    /// The ACS endpoint is registered with the HTTP-Redirect binding, which
    /// SAML Profiles §4.1.2 forbids for a response.
    #[error("the ACS endpoint does not accept the HTTP-POST binding")]
    AcsBindingUnsupported,
    /// The `InResponseTo` value is empty, too long or not an `NCName`.
    #[error("the request id is not a valid SAML identifier")]
    InvalidRequestId,
    /// `RelayState` is longer than [`MAX_RELAY_STATE_BYTES`].
    #[error("RelayState exceeds 80 bytes")]
    RelayStateTooLong,
    /// An unsolicited response for an SP that has not opted in (D-3).
    #[error("IdP-initiated sign-on is not enabled for this service provider")]
    IdpInitiatedNotAllowed,
    /// The SP's `allowed_groups` does not include any of the user's groups.
    #[error("the user is not in a group allowed to use this service provider")]
    GroupNotAllowed,
    /// The SP asks for an email `NameID` and the user has no email address.
    #[error("the user has no email address for an emailAddress NameID")]
    NameIdUnavailable,
    /// The SP asks for an email `NameID` and nothing vouches for the user's
    /// address (D-25): it was never verified and the account is not `Active`.
    #[error("the user's email address is not vouched for")]
    NameIdUnverified,
    /// A persistent `NameID` is required and the deployment holds no
    /// `saml_pairwise_key`.
    #[error("the SAML pairwise-identifier key is not configured")]
    PairwiseKeyMissing,
    /// The SP asks for encrypted assertions, which this build cannot produce.
    #[error("assertion encryption is not supported")]
    EncryptionUnsupported,
    /// The tenant has no active signing credential.
    #[error("the tenant has no active SAML signing credential")]
    NoActiveCredential,
    /// The credential is not `active`.
    #[error("the SAML signing credential is not active")]
    CredentialNotActive,
    /// `now` is outside the credential's `not_before..not_after`.
    #[error("the SAML signing credential is outside its validity period")]
    CredentialNotValid,
    /// The signing step, or the check of its output, failed.
    #[error("the SAML response could not be signed")]
    SigningFailed,
}

impl SamlIdpError {
    /// The status an SP is told. Nothing else about the refusal leaves AXIAM.
    #[must_use]
    pub const fn status(self) -> SamlStatus {
        match self {
            Self::AcsNotRegistered
            | Self::AcsBindingUnsupported
            | Self::InvalidRequestId
            | Self::RelayStateTooLong => SamlStatus::Requester,
            Self::SpDisabled | Self::IdpInitiatedNotAllowed | Self::GroupNotAllowed => {
                SamlStatus::RequestDenied
            }
            Self::AccountMayNotAct | Self::SessionMismatch => SamlStatus::AuthnFailed,
            Self::NameIdUnavailable | Self::NameIdUnverified => SamlStatus::InvalidNameIdPolicy,
            Self::TenantMismatch
            | Self::PairwiseKeyMissing
            | Self::EncryptionUnsupported
            | Self::NoActiveCredential
            | Self::CredentialNotActive
            | Self::CredentialNotValid
            | Self::SigningFailed => SamlStatus::Responder,
        }
    }
}

// ---------------------------------------------------------------------------
// Checks the SSO endpoint runs before the login hop
// ---------------------------------------------------------------------------

/// Whether a user in `user_groups` may use `sp`: yes when the SP names no
/// groups, otherwise only when one of the user's groups is listed.
///
/// The SSO endpoint calls this once the user is known and before issuing;
/// [`SamlIdpIssuer::issue`] calls it again, so a caller that forgets cannot
/// issue past it.
///
/// # Errors
///
/// [`SamlIdpError::GroupNotAllowed`] (`RequestDenied`).
pub fn check_allowed_groups(
    sp: &SamlServiceProvider,
    user_groups: &[Group],
) -> Result<(), SamlIdpError> {
    if sp.allowed_groups.is_empty()
        || user_groups
            .iter()
            .any(|g| g.tenant_id == sp.tenant_id && sp.allowed_groups.contains(&g.id))
    {
        Ok(())
    } else {
        Err(SamlIdpError::GroupNotAllowed)
    }
}

/// The ACS endpoint a response may be delivered to: the one `acs_url` names,
/// by exact string equality against the SP's registration, and only with the
/// HTTP-POST binding.
///
/// # Errors
///
/// [`SamlIdpError::AcsNotRegistered`] — **deliver nothing** to that URL, not even
/// a failure response; [`SamlIdpError::AcsBindingUnsupported`].
pub fn check_acs_url(sp: &SamlServiceProvider, acs_url: &str) -> Result<(), SamlIdpError> {
    let endpoint = sp
        .acs_by_url(acs_url)
        .ok_or(SamlIdpError::AcsNotRegistered)?;
    if endpoint.binding != SamlBinding::HttpPost {
        return Err(SamlIdpError::AcsBindingUnsupported);
    }
    Ok(())
}

/// Check an `AuthnRequest` id before it is stored or echoed.
///
/// # Errors
///
/// [`SamlIdpError::InvalidRequestId`] unless [`xml::is_request_id`].
pub fn check_request_id(id: &str) -> Result<(), SamlIdpError> {
    if xml::is_request_id(id) {
        Ok(())
    } else {
        Err(SamlIdpError::InvalidRequestId)
    }
}

/// Check a `RelayState` before the login hop: it is echoed **verbatim** in the
/// response, so one that cannot be echoed is refused up front.
///
/// # Errors
///
/// [`SamlIdpError::RelayStateTooLong`] above [`MAX_RELAY_STATE_BYTES`].
pub fn check_relay_state(relay_state: Option<&str>) -> Result<(), SamlIdpError> {
    match relay_state {
        Some(value) if value.len() > MAX_RELAY_STATE_BYTES => Err(SamlIdpError::RelayStateTooLong),
        _ => Ok(()),
    }
}

/// The `AuthnContextClassRef` an authentication achieved, from its evidence
/// and nothing else.
///
/// Like `axiam_oauth2::acr::acr_for`, this takes the session's `amr` and no
/// request: a `RequestedAuthnContext` cannot move the answer, only the
/// SSO endpoint's decision whether to re-authenticate. The table, first match
/// wins:
///
/// | Evidence | Class |
/// |---|---|
/// | `mfa`, or `hwk`/`swk` with `user` (a passkey or security key that verified the user) | [`AUTHN_CONTEXT_MFA`] |
/// | `x509` | [`AUTHN_CONTEXT_X509`] |
/// | `pwd` | [`AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT`] |
/// | anything else: `fed` alone, a presence-only key, no evidence | [`AUTHN_CONTEXT_UNSPECIFIED`] |
///
/// The multi-factor row is `acr_for`'s multi-factor rule less `x509`, which
/// SAML can name precisely. `fed` is unspecified because what an upstream IdP
/// did is its claim, not AXIAM's evidence (the rule `acr_for` follows too).
#[must_use]
pub fn authn_context_class_ref(amr: &[Amr]) -> &'static str {
    let has = |needle: Amr| amr.contains(&needle);
    if has(Amr::Mfa) || ((has(Amr::Hwk) || has(Amr::Swk)) && has(Amr::User)) {
        AUTHN_CONTEXT_MFA
    } else if has(Amr::X509) {
        AUTHN_CONTEXT_X509
    } else if has(Amr::Pwd) {
        AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT
    } else {
        AUTHN_CONTEXT_UNSPECIFIED
    }
}

// ---------------------------------------------------------------------------
// Issuance
// ---------------------------------------------------------------------------

/// Everything one assertion is about.
///
/// Built by the SSO endpoint from what it verified. `tenant_id` is the tenant
/// **of the request path**; every other input must belong to it, and the
/// issuer refuses otherwise (a row from one tenant must never be signed with
/// another tenant's key, or under another tenant's `Issuer`).
#[derive(Debug, Clone, Copy)]
pub struct SsoIssuance<'a> {
    /// The tenant of the request path.
    pub tenant_id: Uuid,
    /// The registered service provider.
    pub sp: &'a SamlServiceProvider,
    /// The ACS URL the response is delivered to: the `AuthnRequest`'s, resolved
    /// against the registration, or the SP's default endpoint.
    pub acs_url: &'a str,
    /// The `AuthnRequest` id; `None` for IdP-initiated sign-on.
    pub in_response_to: Option<&'a str>,
    /// The `RelayState` to echo, verbatim.
    pub relay_state: Option<&'a str>,
    /// The AXIAM session that authenticated the user.
    pub session: &'a Session,
    /// The user.
    pub user: &'a User,
    /// The user's groups (for `allowed_groups` and the `groups` attribute).
    pub groups: &'a [Group],
    /// The roles the user holds, directly or through a group (for the `roles`
    /// attribute).
    pub roles: &'a [Role],
}

/// An HTTP-POST binding message (SAML Bindings §3.5): what the SSO endpoint
/// renders as an auto-submitting form.
///
/// **The renderer must HTML-escape all three values** — `acs_url` into the
/// form's `action`, the other two into hidden `input` values — even though the
/// response is base64 and the URL was registered: `RelayState` is the SP's
/// string, echoed verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostBinding {
    /// The form's `action`: the ACS URL, also the response's `Destination`.
    pub acs_url: String,
    /// The `SAMLResponse` field: the response XML, base64 (no line breaks).
    pub saml_response: String,
    /// The `RelayState` field, verbatim; omitted from the form when `None`.
    pub relay_state: Option<String>,
}

/// A signed response and the identifiers an audit record or SLO needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedResponse {
    /// What to post.
    pub binding: PostBinding,
    /// The response's `ID`.
    pub response_id: String,
    /// The assertion's `ID`.
    pub assertion_id: String,
    /// The `NameID` issued (pairwise identifier or email address).
    pub name_id: String,
    /// The `SessionIndex`: the AXIAM session id.
    pub session_index: Uuid,
    /// When the assertion stops being usable.
    pub not_on_or_after: DateTime<Utc>,
}

/// The issuing side of the SAML IdP, one per deployment.
///
/// Holds the two deployment-wide inputs: the public base URL every IdP entity id
/// is derived from, and the pairwise-identifier key. The per-tenant input, the
/// signing credential, is passed per call, because it is loaded per tenant.
///
/// Signing is CPU work (an RSA-4096 private-key operation per signature, and the
/// verification of each before returning); the SSO endpoint should call
/// [`Self::issue`] from a blocking task.
pub struct SamlIdpIssuer {
    public_base_url: String,
    pairwise_key: Option<PairwiseKey>,
}

impl std::fmt::Debug for SamlIdpIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SamlIdpIssuer")
            .field("public_base_url", &self.public_base_url)
            .field(
                "pairwise_key",
                &self.pairwise_key.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl SamlIdpIssuer {
    /// Build the issuer. `public_base_url` is `AuthConfig::root_issuer()`;
    /// `pairwise_key` is the secret provider's `saml_pairwise_key`, or `None`
    /// when the deployment holds none (persistent `NameID`s are then refused).
    #[must_use]
    pub fn new(public_base_url: impl Into<String>, pairwise_key: Option<PairwiseKey>) -> Self {
        Self {
            public_base_url: public_base_url.into(),
            pairwise_key,
        }
    }

    /// [`idp_entity_id`] under this deployment's base URL.
    #[must_use]
    pub fn entity_id(&self, tenant_id: Uuid) -> String {
        idp_entity_id(&self.public_base_url, tenant_id)
    }

    /// Issue the signed response for one sign-on.
    ///
    /// Every input check of this module runs again here, so a caller that
    /// skipped one cannot issue past it: tenant agreement, the session, the
    /// account status, the SP being enabled, the ACS URL and its binding, the
    /// request id, `RelayState`, the IdP-initiated opt-in, `allowed_groups`,
    /// the `NameID` policy, encryption, and the credential's tenant, status and
    /// validity window.
    ///
    /// # Errors
    ///
    /// A [`SamlIdpError`]; answer the SP with its [`SamlIdpError::status`] (via
    /// [`Self::failure`]), except for [`SamlIdpError::AcsNotRegistered`] and
    /// [`SamlIdpError::AcsBindingUnsupported`]: with no registered POST
    /// endpoint to deliver to, nothing is posted anywhere — render an error
    /// page.
    pub fn issue(
        &self,
        req: &SsoIssuance<'_>,
        signing_key: &SamlIdpSigningKey,
        now: DateTime<Utc>,
    ) -> Result<IssuedResponse, SamlIdpError> {
        let now = now.trunc_subsecs(0);
        self.check(req, now)?;
        sign::check_credential(&signing_key.credential, req.tenant_id, now)?;
        let name_id = self.name_id(req)?;

        let issuer = self.entity_id(req.tenant_id);
        let response_id = xml::new_id();
        let assertion_id = xml::new_id();
        let not_on_or_after = now + Duration::seconds(ASSERTION_LIFETIME_SECS);
        let cert_der = sign::certificate_der(&signing_key.credential)?;

        let assertion = assertion_template(&AssertionParts {
            id: &assertion_id,
            issuer: &issuer,
            now,
            not_on_or_after,
            name_id: &name_id,
            req,
            cert_der: &cert_der,
        });
        let key_der = sign::private_key_der(signing_key)?;
        let signed_assertion = sign::sign(&assertion, &key_der)?;

        let response = response_envelope(&EnvelopeParts {
            id: &response_id,
            issuer: &issuer,
            now,
            destination: req.acs_url,
            in_response_to: req.in_response_to,
            status: None,
            signature_template: req
                .sp
                .sign_responses
                .then(|| sign::signature_template(&response_id, &cert_der)),
            assertion: Some(&signed_assertion),
        });
        let response = if req.sp.sign_responses {
            sign::sign(&response, &key_der)?
        } else {
            response
        };
        drop(key_der);

        sign::verify_output(
            &response,
            &cert_der,
            &response_id,
            &assertion_id,
            req.sp.sign_responses,
        )?;

        Ok(IssuedResponse {
            binding: PostBinding {
                acs_url: req.acs_url.to_owned(),
                saml_response: STANDARD.encode(response.as_bytes()),
                relay_state: req.relay_state.map(str::to_owned),
            },
            response_id,
            assertion_id,
            name_id,
            session_index: req.session.id,
            not_on_or_after,
        })
    }

    /// A status-only response: no assertion, no signature, no message (see the
    /// module docs for why it is unsigned).
    ///
    /// `acs_url` must be a registered POST endpoint of `sp` — checked here
    /// again, because a failure response to an unregistered URL would make the
    /// SSO endpoint an open redirect with a SAML body. A request id or
    /// `RelayState` that could not be echoed is omitted rather than refused, so
    /// the SP still learns that its request failed.
    ///
    /// # Errors
    ///
    /// [`SamlIdpError::AcsNotRegistered`] and
    /// [`SamlIdpError::AcsBindingUnsupported`]: render an error page instead.
    pub fn failure(
        &self,
        tenant_id: Uuid,
        sp: &SamlServiceProvider,
        acs_url: &str,
        in_response_to: Option<&str>,
        relay_state: Option<&str>,
        status: SamlStatus,
        now: DateTime<Utc>,
    ) -> Result<PostBinding, SamlIdpError> {
        if sp.tenant_id != tenant_id {
            return Err(SamlIdpError::TenantMismatch);
        }
        check_acs_url(sp, acs_url)?;
        let issuer = self.entity_id(tenant_id);
        let response = response_envelope(&EnvelopeParts {
            id: &xml::new_id(),
            issuer: &issuer,
            now: now.trunc_subsecs(0),
            destination: acs_url,
            in_response_to: in_response_to.filter(|id| xml::is_request_id(id)),
            status: Some(status),
            signature_template: None,
            assertion: None,
        });
        Ok(PostBinding {
            acs_url: acs_url.to_owned(),
            saml_response: STANDARD.encode(response.as_bytes()),
            relay_state: relay_state
                .filter(|r| r.len() <= MAX_RELAY_STATE_BYTES)
                .map(str::to_owned),
        })
    }

    /// Every refusal that does not need the key.
    fn check(&self, req: &SsoIssuance<'_>, now: DateTime<Utc>) -> Result<(), SamlIdpError> {
        let tenant = req.tenant_id;
        if req.sp.tenant_id != tenant
            || req.user.tenant_id != tenant
            || req.session.tenant_id != tenant
            || req.groups.iter().any(|g| g.tenant_id != tenant)
            || req.roles.iter().any(|r| r.tenant_id != tenant)
        {
            return Err(SamlIdpError::TenantMismatch);
        }
        if req.session.user_id != req.user.id || req.session.expires_at <= now {
            return Err(SamlIdpError::SessionMismatch);
        }
        axiam_auth::service::account_may_act(req.user)
            .map_err(|_| SamlIdpError::AccountMayNotAct)?;
        if !req.sp.enabled {
            return Err(SamlIdpError::SpDisabled);
        }
        check_acs_url(req.sp, req.acs_url)?;
        match req.in_response_to {
            Some(id) => check_request_id(id)?,
            None if !req.sp.allow_idp_initiated => {
                return Err(SamlIdpError::IdpInitiatedNotAllowed);
            }
            None => {}
        }
        check_relay_state(req.relay_state)?;
        check_allowed_groups(req.sp, req.groups)?;
        if req.sp.encrypt_assertions {
            return Err(SamlIdpError::EncryptionUnsupported);
        }
        Ok(())
    }

    /// The `NameID` value under the SP's policy.
    fn name_id(&self, req: &SsoIssuance<'_>) -> Result<String, SamlIdpError> {
        match req.sp.name_id_format {
            NameIdFormat::Persistent => {
                let pairwise_key = self
                    .pairwise_key
                    .as_ref()
                    .ok_or(SamlIdpError::PairwiseKeyMissing)?;
                Ok(pairwise_name_id(
                    pairwise_key,
                    req.tenant_id,
                    &req.sp.entity_id,
                    req.user.id,
                ))
            }
            NameIdFormat::EmailAddress => {
                let email = user_email(req.user).ok_or(SamlIdpError::NameIdUnavailable)?;
                if !email_is_vouched_for(req.user) {
                    return Err(SamlIdpError::NameIdUnverified);
                }
                Ok(email.to_owned())
            }
        }
    }
}

/// The user's email address, or `None` when the row holds none.
fn user_email(user: &User) -> Option<&str> {
    let email = user.email.trim();
    (!email.is_empty()).then_some(email)
}

/// Whether something vouches for the user's address (D-25, T-313): it was
/// verified (`email_verified_at`), or the account is `Active` — which only the
/// verification flow, an administrator, SCIM or the directory path make it, and
/// each of those either proved the address or wrote it.
///
/// What this refuses is the account T-313 is about: one still
/// `PendingVerification` with an address nobody checked — a self-registration
/// inside its grace period, or an account provisioned pending and never
/// activated. Such an account keeps working at every SP whose `NameID` is the
/// pairwise identifier; at an email-keyed SP it is answered
/// `InvalidNameIDPolicy`, never with a weaker identifier. The `email` attribute
/// is held to the same rule (omitted, not refused), since an SP may key
/// accounts on it just as well.
fn email_is_vouched_for(user: &User) -> bool {
    user.email_verified_at.is_some() || user.status == axiam_core::models::user::UserStatus::Active
}

/// The values of one attribute source for this user, in a stable order, empty
/// values dropped. An attribute with no values is not emitted at all.
fn attribute_values(source: AttributeSource, req: &SsoIssuance<'_>) -> Vec<String> {
    let profile = || ProfileClaims::from_metadata(&req.user.metadata);
    let single = |value: Option<String>| {
        value
            .filter(|v| !v.trim().is_empty())
            .into_iter()
            .collect::<Vec<_>>()
    };
    match source {
        AttributeSource::Username => single(Some(req.user.username.clone())),
        AttributeSource::Email => single(
            user_email(req.user)
                .filter(|_| email_is_vouched_for(req.user))
                .map(str::to_owned),
        ),
        AttributeSource::DisplayName => single(profile().name),
        AttributeSource::GivenName => single(profile().given_name),
        AttributeSource::FamilyName => single(profile().family_name),
        AttributeSource::Groups => names(req.groups.iter().map(|g| g.name.as_str())),
        AttributeSource::Roles => names(req.roles.iter().map(|r| r.name.as_str())),
    }
}

/// Sorted, de-duplicated, non-empty names.
fn names<'n>(iter: impl Iterator<Item = &'n str>) -> Vec<String> {
    iter.filter(|n| !n.trim().is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(str::to_owned)
        .collect()
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

struct AssertionParts<'a> {
    id: &'a str,
    issuer: &'a str,
    now: DateTime<Utc>,
    not_on_or_after: DateTime<Utc>,
    name_id: &'a str,
    req: &'a SsoIssuance<'a>,
    cert_der: &'a [u8],
}

/// The unsigned assertion, with its signature template after `Issuer` (the
/// position SAML Core §2.3.3's schema gives `ds:Signature`).
fn assertion_template(p: &AssertionParts<'_>) -> String {
    use xml::{escape, instant};

    let req = p.req;
    let sp = req.sp;
    let not_before = p.now - Duration::seconds(crate::oidc::CLOCK_SKEW_LEEWAY_SECS as i64);

    let mut out = String::with_capacity(4096);
    out.push_str(&format!(
        r#"<saml:Assertion xmlns:saml="{NS_ASSERTION}" ID="{}" Version="2.0" IssueInstant="{}">"#,
        p.id,
        instant(p.now)
    ));
    out.push_str(&format!("<saml:Issuer>{}</saml:Issuer>", escape(p.issuer)));
    out.push_str(&sign::signature_template(p.id, p.cert_der));

    // --- Subject ---
    out.push_str("<saml:Subject>");
    match sp.name_id_format {
        NameIdFormat::Persistent => out.push_str(&format!(
            r#"<saml:NameID Format="{}" NameQualifier="{}" SPNameQualifier="{}">{}</saml:NameID>"#,
            NameIdFormat::Persistent.urn(),
            escape(p.issuer),
            escape(&sp.entity_id),
            escape(p.name_id)
        )),
        NameIdFormat::EmailAddress => out.push_str(&format!(
            r#"<saml:NameID Format="{}">{}</saml:NameID>"#,
            NameIdFormat::EmailAddress.urn(),
            escape(p.name_id)
        )),
    }
    out.push_str(&format!(
        r#"<saml:SubjectConfirmation Method="{CM_BEARER}">"#
    ));
    out.push_str(&format!(
        r#"<saml:SubjectConfirmationData Recipient="{}" NotOnOrAfter="{}""#,
        escape(req.acs_url),
        instant(p.not_on_or_after)
    ));
    if let Some(request_id) = req.in_response_to {
        out.push_str(&format!(r#" InResponseTo="{}""#, escape(request_id)));
    }
    out.push_str("/></saml:SubjectConfirmation></saml:Subject>");

    // --- Conditions ---
    out.push_str(&format!(
        r#"<saml:Conditions NotBefore="{}" NotOnOrAfter="{}"><saml:AudienceRestriction><saml:Audience>{}</saml:Audience></saml:AudienceRestriction></saml:Conditions>"#,
        instant(not_before),
        instant(p.not_on_or_after),
        escape(&sp.entity_id)
    ));

    // --- AuthnStatement ---
    out.push_str(&format!(
        r#"<saml:AuthnStatement AuthnInstant="{}" SessionIndex="{}"><saml:AuthnContext><saml:AuthnContextClassRef>{}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"#,
        instant(req.session.authenticated_at),
        req.session.id,
        authn_context_class_ref(&req.session.amr)
    ));

    // --- AttributeStatement ---
    let attributes: Vec<String> = sp
        .attribute_mappings
        .iter()
        .filter_map(|mapping| {
            let values = attribute_values(mapping.source, req);
            if values.is_empty() {
                return None;
            }
            let mut attr = format!(r#"<saml:Attribute Name="{}""#, escape(&mapping.saml_name));
            if let Some(format) = &mapping.name_format {
                attr.push_str(&format!(r#" NameFormat="{}""#, escape(format)));
            }
            attr.push('>');
            for value in values {
                attr.push_str(&format!(
                    "<saml:AttributeValue>{}</saml:AttributeValue>",
                    escape(&value)
                ));
            }
            attr.push_str("</saml:Attribute>");
            Some(attr)
        })
        .collect();
    if !attributes.is_empty() {
        out.push_str("<saml:AttributeStatement>");
        for attr in attributes {
            out.push_str(&attr);
        }
        out.push_str("</saml:AttributeStatement>");
    }

    out.push_str("</saml:Assertion>");
    out
}

struct EnvelopeParts<'a> {
    id: &'a str,
    issuer: &'a str,
    now: DateTime<Utc>,
    destination: &'a str,
    in_response_to: Option<&'a str>,
    /// `None` is `Success`.
    status: Option<SamlStatus>,
    signature_template: Option<String>,
    assertion: Option<&'a str>,
}

/// The `samlp:Response` around an (already signed) assertion, or around a
/// status alone.
fn response_envelope(p: &EnvelopeParts<'_>) -> String {
    use xml::{escape, instant};

    let mut out = String::with_capacity(8192);
    out.push_str(&format!(
        r#"<samlp:Response xmlns:samlp="{NS_PROTOCOL}" xmlns:saml="{NS_ASSERTION}" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}""#,
        p.id,
        instant(p.now),
        escape(p.destination)
    ));
    if let Some(request_id) = p.in_response_to {
        out.push_str(&format!(r#" InResponseTo="{}""#, escape(request_id)));
    }
    out.push('>');
    out.push_str(&format!("<saml:Issuer>{}</saml:Issuer>", escape(p.issuer)));
    if let Some(template) = &p.signature_template {
        out.push_str(template);
    }
    out.push_str("<samlp:Status>");
    match p.status {
        None => out.push_str(&format!(
            r#"<samlp:StatusCode Value="{STATUS_PREFIX}Success"/>"#
        )),
        Some(status) => match status.second_level() {
            None => out.push_str(&format!(
                r#"<samlp:StatusCode Value="{}"/>"#,
                status.top_level()
            )),
            Some(second) => out.push_str(&format!(
                r#"<samlp:StatusCode Value="{}"><samlp:StatusCode Value="{second}"/></samlp:StatusCode>"#,
                status.top_level()
            )),
        },
    }
    out.push_str("</samlp:Status>");
    if let Some(assertion) = p.assertion {
        out.push_str(assertion);
    }
    out.push_str("</samlp:Response>");
    out
}

/// Fixtures for tests outside this crate (the SSO endpoint's HTTP tests and the
/// e2e harness): what a service provider's SAML library does — generate a key,
/// sign an `AuthnRequest` enveloped or over a Redirect query, deflate one.
/// AXIAM never signs a request; nothing in a server path calls these.
#[doc(hidden)]
pub mod test_support {
    use std::io::Write;

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use samael::crypto::{CryptoProvider, XmlSec};

    /// A key pair and a self-signed certificate over it.
    pub struct Material {
        /// PKCS#8 DER of the private key.
        pub pkcs8_der: Vec<u8>,
        /// PKCS#8 PEM of the private key.
        pub pkcs8_pem: String,
        /// The certificate, DER.
        pub cert_der: Vec<u8>,
        /// The certificate, PEM.
        pub cert_pem: String,
    }

    /// An RSA key of `bits` and a self-signed certificate for it, valid from an
    /// hour ago for `days`.
    ///
    /// # Panics
    ///
    /// When OpenSSL fails, which a test should surface.
    #[must_use]
    pub fn rsa_material(bits: u32, common_name: &str, days: u32) -> Material {
        use openssl::{asn1, bn, hash, nid, pkey, rsa, x509};
        let pair = pkey::PKey::from_rsa(rsa::Rsa::generate(bits).expect("rsa")).expect("pkey");
        let mut name = x509::X509NameBuilder::new().expect("name");
        name.append_entry_by_nid(nid::Nid::COMMONNAME, common_name)
            .expect("cn");
        let name = name.build();
        let mut builder = x509::X509Builder::new().expect("builder");
        builder.set_version(2).expect("version");
        let mut serial = bn::BigNum::new().expect("bn");
        serial
            .rand(127, bn::MsbOption::MAYBE_ZERO, false)
            .expect("serial");
        builder
            .set_serial_number(&serial.to_asn1_integer().expect("serial"))
            .expect("serial");
        builder.set_subject_name(&name).expect("subject");
        builder.set_issuer_name(&name).expect("issuer");
        builder.set_pubkey(&pair).expect("pubkey");
        let not_before =
            asn1::Asn1Time::from_unix(chrono::Utc::now().timestamp() - 3600).expect("not before");
        builder.set_not_before(&not_before).expect("not before");
        builder
            .set_not_after(&asn1::Asn1Time::days_from_now(days).expect("not after"))
            .expect("not after");
        builder
            .sign(&pair, hash::MessageDigest::sha256())
            .expect("sign");
        let cert = builder.build();
        Material {
            pkcs8_der: pair.private_key_to_pkcs8().expect("pkcs8 der"),
            pkcs8_pem: String::from_utf8(pair.private_key_to_pem_pkcs8().expect("pkcs8 pem"))
                .expect("utf8"),
            cert_der: cert.to_der().expect("der"),
            cert_pem: String::from_utf8(cert.to_pem().expect("pem")).expect("utf8"),
        }
    }

    /// The enveloped `ds:Signature` template for the element whose `ID` is `id`.
    #[must_use]
    pub fn signature_template(id: &str, cert_der: &[u8]) -> String {
        super::sign::signature_template(id, cert_der)
    }

    /// Sign the first signature template in `document` with a PKCS#8 DER key.
    ///
    /// # Panics
    ///
    /// When xmlsec refuses.
    #[must_use]
    pub fn sign_document(document: &str, pkcs8_der: &[u8]) -> String {
        let signed = <XmlSec as CryptoProvider>::sign_xml(document.as_bytes(), pkcs8_der)
            .expect("xmlsec signing");
        super::xml::strip_declaration(&signed).to_owned()
    }

    /// RSA-SHA256 over `octets`, base64: an HTTP-Redirect `Signature`.
    ///
    /// # Panics
    ///
    /// When OpenSSL fails.
    #[must_use]
    pub fn sign_octets(octets: &str, pkcs8_der: &[u8]) -> String {
        let pair = openssl::pkey::PKey::private_key_from_pkcs8(pkcs8_der).expect("key");
        let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &pair)
            .expect("signer");
        signer.update(octets.as_bytes()).expect("update");
        STANDARD.encode(signer.sign_to_vec().expect("sign"))
    }

    /// Raw DEFLATE, then base64: an HTTP-Redirect `SAMLRequest` before URL
    /// encoding.
    ///
    /// # Panics
    ///
    /// Never in practice (writes to memory).
    #[must_use]
    pub fn deflate_base64(document: &[u8]) -> String {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(document).expect("deflate");
        STANDARD.encode(encoder.finish().expect("deflate"))
    }
}
