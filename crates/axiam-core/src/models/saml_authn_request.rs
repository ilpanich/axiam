//! A SAML `AuthnRequest` waiting for its login hop (G-2, T23.2.3).
//!
//! The SAML IdP's SSO endpoint answers a request in two legs. The first parses
//! and checks the `AuthnRequest` — everything that can be decided without a
//! signed-in user — and stores what it decided here, under an opaque handle.
//! The second, `/saml/v2/{tenant_id}/sso/continue?handle=…`, is where the
//! browser comes back (directly, or from the sign-in page) and where the
//! assertion is issued. The split exists because the HTTP-POST binding arrives
//! as a cross-site form post: the browser cannot be sent to sign in and then
//! re-post it, and a `SameSite=Lax` cookie is not sent on it at all.
//!
//! # What a row is, and is not
//!
//! A row is **not a credential**. It names a service provider, an ACS URL that
//! was already checked against the SP's registration, and the request's own
//! parameters. The assertion issued from it is for whoever's OP session cookie
//! arrives at the continue leg, and the continue leg additionally requires the
//! browser-binding cookie the first leg set ([`PendingSamlRequest::binding_hash`]),
//! so a handle copied into another browser buys nothing.
//!
//! # Single use, twice over
//!
//! * The **request id** is single-use per service provider: a second
//!   `AuthnRequest` with an `ID` already seen for that SP is refused by a unique
//!   index on the row (SAML Profiles §4.1.4.5's replay rule, applied on receipt
//!   so a replayed request never reaches a sign-in page). Rows outlive their
//!   consumption until they expire, which is what makes the index cover the
//!   whole freshness window an `IssueInstant` is accepted in.
//! * The **handle** is single-use: consuming it is a guarded transition run on
//!   the X6 two-layer arbiter, so of any number of concurrent continues exactly
//!   one issues an assertion.
//!
//! Only SHA-256 digests of the handle and the binding value are stored, as
//! `sso_handoff_code` stores its code: a database read must not yield a value a
//! browser presents.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// How long a pending request lives: ten minutes, from the first leg.
///
/// Two bounds meet here. It is the time a person has to complete the sign-in
/// page (password, a second factor, a passkey prompt), so it must not be short;
/// and it is the life of the replay guard on the request id, so it must be
/// longer than the window an `IssueInstant` is accepted in (five minutes back
/// and the clock-skew allowance forward), which it is with margin.
pub const PENDING_SAML_REQUEST_TTL_SECS: i64 = 600;

/// What the SSO endpoint's first leg stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPendingSamlRequest {
    /// The tenant of the request path.
    pub tenant_id: Uuid,
    /// The registered service provider the request came from.
    pub sp_id: Uuid,
    /// The `AuthnRequest`'s `ID`, already checked as a request id; `None` for
    /// an IdP-initiated sign-on, which answers no request.
    pub request_id: Option<String>,
    /// The ACS URL the response will be posted to, already resolved against
    /// the SP's registration.
    pub acs_url: String,
    /// `RelayState`, already bounded; echoed verbatim.
    pub relay_state: Option<String>,
    /// `ForceAuthn`: the continue leg must see a sign-in later than
    /// [`Self::created_at`].
    pub force_authn: bool,
    /// `IsPassive`: the continue leg must not show the sign-in page.
    pub is_passive: bool,
    /// SHA-256 (hex) of the opaque handle the browser carries.
    pub handle_hash: String,
    /// SHA-256 (hex) of the browser-binding cookie's value.
    pub binding_hash: String,
    /// The outbound instant: when the first leg accepted the request.
    pub created_at: DateTime<Utc>,
    /// When the row stops being usable (and, after that, sweepable).
    pub expires_at: DateTime<Utc>,
}

/// A stored pending request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingSamlRequest {
    /// Record id.
    pub id: Uuid,
    /// See [`NewPendingSamlRequest::tenant_id`].
    pub tenant_id: Uuid,
    /// See [`NewPendingSamlRequest::sp_id`].
    pub sp_id: Uuid,
    /// See [`NewPendingSamlRequest::request_id`].
    pub request_id: Option<String>,
    /// See [`NewPendingSamlRequest::acs_url`].
    pub acs_url: String,
    /// See [`NewPendingSamlRequest::relay_state`].
    pub relay_state: Option<String>,
    /// See [`NewPendingSamlRequest::force_authn`].
    pub force_authn: bool,
    /// See [`NewPendingSamlRequest::is_passive`].
    pub is_passive: bool,
    /// See [`NewPendingSamlRequest::binding_hash`].
    pub binding_hash: String,
    /// See [`NewPendingSamlRequest::created_at`].
    pub created_at: DateTime<Utc>,
    /// See [`NewPendingSamlRequest::expires_at`].
    pub expires_at: DateTime<Utc>,
}
