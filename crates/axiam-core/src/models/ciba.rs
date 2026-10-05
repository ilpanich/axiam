//! Client-Initiated Backchannel Authentication — G-7 (OpenID Connect CIBA
//! Core 1.0).
//!
//! A relying party that already knows *who* it wants to authenticate — a call
//! centre that has the caller on the phone, a point-of-sale terminal, a
//! back-office service acting for a customer — asks AXIAM over a direct,
//! client-authenticated call (`POST /oauth2/bc-authorize`) to authenticate that
//! user **on another device**. AXIAM notifies the user, the user approves on the
//! identity pages after a full sign-in, and the client obtains tokens from the
//! token endpoint with `grant_type=urn:openid:params:grant-type:ciba`.
//!
//! This module holds the domain types every layer shares: the client metadata
//! (CIBA Core §4), the pending-request row and its state machine, the approval
//! evidence, the ping-mode notification contract (§10.2) and the port the user
//! notification goes through.
//!
//! # The state machine
//!
//! ```text
//! pending ──approve──▶ approved ──redeem──▶ redeemed
//!    │                    │
//!    ├──deny──▶ denied    └──(expiry)──▶ expired
//!    └──(expiry)──▶ expired
//! ```
//!
//! Every arrow is a **conditional write** in the datastore (T-406's lesson):
//! approval and denial are conditional on the version the approving page read
//! and on the request's user being the approving user; redemption is the X6
//! two-layer single-use arbiter, conditional on the client that started the
//! request. Two parties write to one row — the user deciding and the client
//! polling — and neither can put back what the other changed.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AxiamError;
use crate::models::session::Amr;

/// The CIBA grant type (CIBA Core §10.1), as it appears in a client's
/// `grant_types` and in a token request's `grant_type`.
pub const CIBA_GRANT_TYPE: &str = "urn:openid:params:grant-type:ciba";

/// How a CIBA client learns that a request has been decided (CIBA Core §5).
///
/// `push` is deliberately absent: AXIAM does not offer it, and the FAPI-CIBA
/// profile forbids it — push delivers the tokens themselves to a client
/// endpoint, which makes the notification endpoint a token sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum CibaDeliveryMode {
    /// The client polls the token endpoint at `interval` until the request is
    /// decided.
    Poll,
    /// AXIAM calls the client's `backchannel_client_notification_endpoint`
    /// once the request is decided, and the client then calls the token
    /// endpoint once.
    Ping,
}

impl CibaDeliveryMode {
    /// The wire and storage spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Poll => "poll",
            Self::Ping => "ping",
        }
    }

    /// Parse a stored or registered value. `None` for anything else —
    /// including `push`, which is not offered.
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw.trim() {
            "poll" => Some(Self::Poll),
            "ping" => Some(Self::Ping),
            _ => None,
        }
    }
}

/// The JWS algorithm a CIBA client signs its authentication requests with
/// (CIBA Core §4 `backchannel_authentication_request_signing_alg`, §7.1.1).
///
/// Exactly the three algorithms AXIAM verifies on any client-signed JWT
/// (`axiam_oauth2::jose::PERMITTED_ALGORITHMS`): FAPI 2.0 §5.3.1.1's list. A
/// registration naming anything else — `RS256`, `HS256`, `none` — is refused
/// rather than stored, so no row can hold an algorithm the verifier would not
/// honour (D-61).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
pub enum CibaRequestSigningAlg {
    /// RSASSA-PSS with SHA-256.
    #[serde(rename = "PS256")]
    Ps256,
    /// ECDSA on P-256 with SHA-256.
    #[serde(rename = "ES256")]
    Es256,
    /// Ed25519.
    #[serde(rename = "EdDSA")]
    EdDsa,
}

impl CibaRequestSigningAlg {
    /// Every algorithm, in discovery order.
    pub const ALL: [Self; 3] = [Self::Ps256, Self::Es256, Self::EdDsa];

    /// The JOSE spelling, on the wire and in storage.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ps256 => "PS256",
            Self::Es256 => "ES256",
            Self::EdDsa => "EdDSA",
        }
    }

    /// Parse the JOSE spelling, exactly (JOSE names are case-sensitive).
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.as_str() == raw.trim())
    }
}

/// The CIBA client metadata AXIAM stores (CIBA Core §4).
///
/// Three of the four members §4 defines. The fourth,
/// `backchannel_user_code_parameter`, is refused at registration rather than
/// stored, because AXIAM holds no user code to check (D-64). A stored value
/// nothing reads would be a security switch that does nothing — the SEC-097
/// shape.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CibaClientMetadata {
    /// `backchannel_token_delivery_mode` — required when the client holds the
    /// CIBA grant, absent otherwise.
    #[serde(default)]
    pub backchannel_token_delivery_mode: Option<CibaDeliveryMode>,
    /// `backchannel_client_notification_endpoint` — required in `ping` mode,
    /// refused in `poll` mode. Held to the outbound URL policy webhooks use.
    #[serde(default)]
    pub backchannel_client_notification_endpoint: Option<String>,
    /// `backchannel_authentication_request_signing_alg` — when set, **every**
    /// backchannel authentication request from this client must be a signed
    /// `request` JWT under exactly this algorithm (CIBA Core §7.1.1), and an
    /// unsigned one is refused. Required for a `fapi2` client (FAPI-CIBA
    /// §5.2.2). When absent, a `request` parameter is refused.
    #[serde(default)]
    pub backchannel_authentication_request_signing_alg: Option<CibaRequestSigningAlg>,
}

impl CibaClientMetadata {
    /// Whether any member is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.backchannel_token_delivery_mode.is_none()
            && self
                .backchannel_authentication_request_signing_alg
                .is_none()
            && self
                .backchannel_client_notification_endpoint
                .as_deref()
                .is_none_or(|e| e.trim().is_empty())
    }
}

/// Where a backchannel authentication request has got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum CibaRequestStatus {
    /// Stored; the user has not decided. The token endpoint answers
    /// `authorization_pending`.
    Pending,
    /// The user approved after authenticating. The next token request from
    /// the client that started it redeems it.
    Approved,
    /// The user refused. The token endpoint answers `access_denied`.
    Denied,
    /// The request outlived its `expires_in` undecided or unredeemed. The
    /// token endpoint answers `expired_token`.
    Expired,
    /// Exchanged for tokens. Terminal; a second redemption is `invalid_grant`.
    Redeemed,
}

impl CibaRequestStatus {
    /// The storage spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Redeemed => "redeemed",
        }
    }

    /// Parse a stored value. `None` for anything unrecognised: the states
    /// differ by whether they grant access, so the caller fails closed.
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw.trim() {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "denied" => Some(Self::Denied),
            "expired" => Some(Self::Expired),
            "redeemed" => Some(Self::Redeemed),
            _ => None,
        }
    }
}

/// The authentication the approving user performed — what the ID token minted
/// from this request reports (`auth_time`, `acr`, `amr`), the same evidence an
/// authorization code carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CibaApprovalEvidence {
    /// The session the user approved from. The minted access token names it in
    /// `sid`, so ending that session ends the tokens (as for a code grant).
    pub session_id: Uuid,
    /// When the user authenticated (OIDC Core §2 `auth_time`).
    pub auth_time: DateTime<Utc>,
    /// The class the authentication achieved, derived from `amr` by the
    /// service — never supplied by the caller.
    pub acr: String,
    /// RFC 8176 method references of that authentication.
    pub amr: Vec<Amr>,
}

/// A backchannel authentication request, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CibaRequest {
    /// Record id. Also the handle the approval page addresses the request by —
    /// not a secret: approval requires the request's own user to be signed in.
    pub id: Uuid,
    /// The tenant the request belongs to.
    pub tenant_id: Uuid,
    /// The client that started it; the only client that may redeem it.
    pub client_id: String,
    /// SHA-256 of the `auth_req_id`. The raw value is returned once.
    pub auth_req_id_hash: String,
    /// The user the hint resolved to. `None` for a request whose hint named
    /// nobody who may sign in: such a request is stored and answered exactly
    /// like a real one so that `bc-authorize` is not a user oracle (D-63), and
    /// it can only ever expire.
    pub user_id: Option<Uuid>,
    /// The granted scopes (always including `openid`).
    pub scopes: Vec<String>,
    /// The `binding_message` shown to the user on both devices.
    pub binding_message: Option<String>,
    /// The requested `acr_values`, verbatim (unknown values are kept and can
    /// never be satisfied).
    pub acr_values: Vec<String>,
    /// RFC 8707 resource this request was made for, if any.
    pub resource: Option<String>,
    /// The delivery mode the client was registered for when it asked.
    pub delivery_mode: CibaDeliveryMode,
    /// Where the request is.
    pub status: CibaRequestStatus,
    /// Bumped by every status transition. Approval and denial are conditional
    /// on the value the approving page read.
    pub version: u64,
    /// Minimum seconds between token requests; raised by `slow_down`.
    pub interval_secs: u64,
    /// When the client last asked the token endpoint about this request.
    pub last_polled_at: Option<DateTime<Utc>>,
    /// When the request stops being redeemable.
    pub expires_at: DateTime<Utc>,
    /// Set at approval.
    pub approval: Option<CibaApprovalEvidence>,
    /// When the user decided.
    pub decided_at: Option<DateTime<Utc>>,
    /// When the request was stored.
    pub created_at: DateTime<Utc>,
}

impl CibaRequest {
    /// Whether `now` is past the request's expiry.
    #[must_use]
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

/// The two secrets a ping-mode request needs at delivery time.
///
/// Sealed at rest by the repository (AES-256-GCM under `pki_encryption_key`):
/// `client_notification_token` is the bearer credential AXIAM presents to the
/// client's notification endpoint, and `auth_req_id` is the body of that
/// notification — which is why, unlike a poll-mode request, a ping-mode request
/// must keep the identifier recoverable rather than only its hash.
#[derive(Clone, PartialEq, Eq)]
pub struct CibaPingCredentials {
    /// The `auth_req_id` the notification carries (CIBA Core §10.2).
    pub auth_req_id: String,
    /// The bearer token the client supplied at `bc-authorize` (§7.1).
    pub client_notification_token: String,
}

/// Redacting `Debug`: both members are credentials.
impl std::fmt::Debug for CibaPingCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CibaPingCredentials")
            .finish_non_exhaustive()
    }
}

/// Input for storing a new request.
#[derive(Debug, Clone)]
pub struct CreateCibaRequest {
    /// See [`CibaRequest::tenant_id`].
    pub tenant_id: Uuid,
    /// See [`CibaRequest::client_id`].
    pub client_id: String,
    /// See [`CibaRequest::auth_req_id_hash`].
    pub auth_req_id_hash: String,
    /// See [`CibaRequest::user_id`].
    pub user_id: Option<Uuid>,
    /// See [`CibaRequest::scopes`].
    pub scopes: Vec<String>,
    /// See [`CibaRequest::binding_message`].
    pub binding_message: Option<String>,
    /// See [`CibaRequest::acr_values`].
    pub acr_values: Vec<String>,
    /// See [`CibaRequest::resource`].
    pub resource: Option<String>,
    /// See [`CibaRequest::delivery_mode`].
    pub delivery_mode: CibaDeliveryMode,
    /// Present exactly in ping mode; sealed by the repository.
    pub ping: Option<CibaPingCredentials>,
    /// See [`CibaRequest::interval_secs`].
    pub interval_secs: u64,
    /// See [`CibaRequest::expires_at`].
    pub expires_at: DateTime<Utc>,
}

/// The ping-mode notification body (CIBA Core §10.2) — the contract T23.7.2's
/// deliverer sends, as `POST` to the client's
/// `backchannel_client_notification_endpoint` with
/// `Authorization: Bearer <client_notification_token>` and
/// `Content-Type: application/json`.
///
/// Nothing else is in it: the notification says *that* a request was decided,
/// never how; the client learns the outcome from the token endpoint, where it
/// authenticates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CibaPingNotification {
    /// The `auth_req_id` the client was given at `bc-authorize`.
    pub auth_req_id: String,
}

/// What the user is told about a request (the port's payload).
///
/// Carries no secret: not the `auth_req_id`, not a token. The approval page is
/// addressed by `request_id` and requires the user to sign in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CibaUserNotification {
    /// The tenant.
    pub tenant_id: Uuid,
    /// The request to approve, by record id.
    pub request_id: Uuid,
    /// Who to notify.
    pub user_id: Uuid,
    /// The client that asked, by `client_id`.
    pub client_id: String,
    /// The client's display name.
    pub client_name: String,
    /// The `binding_message`, if the client sent one.
    pub binding_message: Option<String>,
    /// The scopes requested.
    pub scopes: Vec<String>,
    /// When the request expires.
    pub expires_at: DateTime<Utc>,
}

/// A boxed future returned by [`CibaUserNotifier`].
pub type CibaNotifyFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), AxiamError>> + Send + 'a>>;

/// The port through which a stored request reaches its user (G-7).
///
/// `bc-authorize` calls it **best effort, after the request is stored, and
/// detached from the response**: a failed notification never fails the request
/// (the user can still find it on the identity pages), and the response does
/// not wait on it, so its timing says nothing about whether the hint named a
/// real user. T23.7.2 implements it over `axiam-email` (later push); until a
/// deployment wires one, [`NoopCibaUserNotifier`] is in place.
pub trait CibaUserNotifier: Send + Sync {
    /// Tell the user a request is waiting.
    fn notify(&self, notification: CibaUserNotification) -> CibaNotifyFuture<'_>;
}

/// The notifier that notifies nobody.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopCibaUserNotifier;

impl CibaUserNotifier for NoopCibaUserNotifier {
    fn notify(&self, _notification: CibaUserNotification) -> CibaNotifyFuture<'_> {
        // The request still waits on the identity pages; nobody is told.
        Box::pin(async { Ok(()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_modes_round_trip_and_push_is_not_one() {
        for mode in [CibaDeliveryMode::Poll, CibaDeliveryMode::Ping] {
            assert_eq!(CibaDeliveryMode::from_wire(mode.as_str()), Some(mode));
        }
        assert_eq!(CibaDeliveryMode::from_wire("push"), None);
        assert_eq!(CibaDeliveryMode::from_wire(""), None);
    }

    #[test]
    fn statuses_round_trip_and_unknown_fails_closed() {
        for s in [
            CibaRequestStatus::Pending,
            CibaRequestStatus::Approved,
            CibaRequestStatus::Denied,
            CibaRequestStatus::Expired,
            CibaRequestStatus::Redeemed,
        ] {
            assert_eq!(CibaRequestStatus::from_wire(s.as_str()), Some(s));
        }
        assert_eq!(CibaRequestStatus::from_wire("APPROVED-ish"), None);
    }

    #[test]
    fn ping_credentials_never_print() {
        let creds = CibaPingCredentials {
            auth_req_id: "visible-only-to-the-deliverer".into(),
            client_notification_token: "bearer-for-the-client-endpoint".into(),
        };
        let rendered = format!("{creds:?}");
        assert!(!rendered.contains("visible-only"));
        assert!(!rendered.contains("bearer-for"));
    }

    #[test]
    fn signing_algs_round_trip_and_nothing_else_parses() {
        for alg in CibaRequestSigningAlg::ALL {
            assert_eq!(CibaRequestSigningAlg::from_wire(alg.as_str()), Some(alg));
            assert_eq!(
                serde_json::to_value(alg).unwrap(),
                serde_json::json!(alg.as_str())
            );
        }
        for bad in ["RS256", "HS256", "none", "ps256", "eddsa", ""] {
            assert_eq!(CibaRequestSigningAlg::from_wire(bad), None, "{bad}");
        }
    }

    #[test]
    fn empty_metadata_is_empty() {
        assert!(CibaClientMetadata::default().is_empty());
        assert!(
            !CibaClientMetadata {
                backchannel_token_delivery_mode: Some(CibaDeliveryMode::Poll),
                ..Default::default()
            }
            .is_empty()
        );
        assert!(
            !CibaClientMetadata {
                backchannel_authentication_request_signing_alg: Some(CibaRequestSigningAlg::EdDsa),
                ..Default::default()
            }
            .is_empty()
        );
    }
}
