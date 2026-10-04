//! Shared Signals Framework transmitter: the stream registry (G-5, T23.5.2).
//!
//! AXIAM transmits CAEP and RISC events as Security Event Tokens (RFC 8417) to
//! receivers a tenant administrator registered. This module is the plain data
//! of that registry and the payload contract every delivery path shares. The
//! protocol — how a SET is built, signed and addressed, what a receiver may
//! change — is `axiam_oauth2::ssf`; storage is `SsfStreamRepository`.
//!
//! The specification followed is **OpenID Shared Signals Framework 1.0**
//! (final, 2025-08-29), with **CAEP 1.0** and **RISC 1.0** for the event
//! types and **RFC 9493** for subject identifiers (decision D-44).
//!
//! # One stream, one receiver, one administrator decision
//!
//! A stream is registered by an administrator, never by a receiver (SSF §8.1.1
//! allows a transmitter to refuse receiver-created streams). The registration
//! fixes what the receiver cannot change:
//!
//! * [`SsfStream::receiver_client_id`] — the OAuth2 client whose
//!   client-credentials token (with [`SSF_MANAGE_SCOPE`]) is the receiver's
//!   identity on the stream management API. A receiver sees and changes only
//!   streams bound to its own `client_id`.
//! * [`SsfStream::audience`] — the SET `aud`. **Unique across the deployment**,
//!   not only per tenant (D-47): on a deployment without per-tenant issuer
//!   paths every tenant's SETs carry the same `iss`, so the audience is what
//!   keeps tenant A's SETs from verifying at tenant B's receiver.
//! * [`SsfStream::events_allowed`] — the ceiling. A receiver's
//!   `events_requested` may narrow it, never widen it.
//! * [`SsfStream::subject_format`] — `iss_sub` by default, `email` only on an
//!   administrator's request, since it decides what personal data leaves.
//! * [`SsfStream::delivery_method`].
//!
//! # No secret in this type
//!
//! The push `Authorization` header a receiver requires is a credential **to the
//! receiver**. It is encrypted at rest by the repository and reaches a caller
//! only through `SsfStreamRepository::decrypt_authorization_header`, the single
//! path to the plaintext, which only the push deliverer calls. [`SsfStream`]
//! says whether one is set and nothing else; the write inputs that carry it
//! redact it from `Debug`.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::user::User;

/// The OAuth2 scope a receiver's client-credentials token must carry on the
/// stream management API and the poll endpoint.
pub const SSF_MANAGE_SCOPE: &str = "ssf.manage";

/// The `spec_version` AXIAM publishes in its transmitter metadata (SSF 1.0 §7.1:
/// the numerical part of the final specification's name).
pub const SSF_SPEC_VERSION: &str = "1_0";

/// RFC 8935 push delivery, as SSF 1.0 §6.1.1 names it.
pub const PUSH_DELIVERY_METHOD_URI: &str = "urn:ietf:rfc:8935";
/// RFC 8936 poll delivery, as SSF 1.0 §6.1.2 names it.
pub const POLL_DELIVERY_METHOD_URI: &str = "urn:ietf:rfc:8936";

/// The SSF verification event (SSF 1.0 §8.1.4.1). Not subscribable: a
/// receiver asks for it on the verification endpoint.
pub const VERIFICATION_EVENT_URI: &str =
    "https://schemas.openid.net/secevent/ssf/event-type/verification";
/// The SSF stream-updated event (SSF 1.0 §8.1.5). Not subscribable: AXIAM
/// sends it when an administrator changes a stream's status.
pub const STREAM_UPDATED_EVENT_URI: &str =
    "https://schemas.openid.net/secevent/ssf/event-type/stream-updated";

/// Seconds a receiver must wait between two verification requests on one
/// stream (`min_verification_interval`, SSF 1.0 §8.1.1). A faster request is
/// `429`.
pub const MIN_VERIFICATION_INTERVAL_SECS: i64 = 60;

/// Most events the poll buffer holds per stream (D-48). When it is full the
/// **oldest** event is dropped to admit the newest; SSF 1.0 §8.1.2 permits a
/// transmitter to drop held events, and the newest state is the one a receiver
/// can act on.
pub const POLL_BUFFER_MAX_EVENTS: usize = 1000;
/// Days an unacknowledged event stays in the poll buffer (D-48).
pub const POLL_BUFFER_RETENTION_DAYS: i64 = 7;
/// Most SETs one poll response carries (RFC 8936 `maxEvents` is clamped to it).
pub const POLL_MAX_EVENTS_PER_RESPONSE: usize = 100;
/// Minutes a step-up record lives (D-53 (1)): the time a person is given to
/// complete the second factor the honour lane asked for.
pub const STEP_UP_RECORD_TTL_MINUTES: i64 = 10;

/// Longest `audience`, in bytes.
pub const MAX_AUDIENCE_BYTES: usize = 512;
/// Longest `description`, in bytes.
pub const MAX_DESCRIPTION_BYTES: usize = 256;
/// Longest push `endpoint_url`, in bytes.
pub const MAX_ENDPOINT_URL_BYTES: usize = 2048;
/// Longest push `authorization_header` value, in bytes.
pub const MAX_AUTHORIZATION_HEADER_BYTES: usize = 4096;
/// Longest status `reason`, in bytes.
pub const MAX_STATUS_REASON_BYTES: usize = 256;

/// The six event types AXIAM transmits (G-5).
///
/// Stored and sent as their event-type URIs; [`Self::ALL`] is the canonical
/// order every list AXIAM returns is sorted in.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    utoipa::ToSchema,
)]
pub enum SsfEventType {
    /// CAEP 1.0 §3.1.
    #[serde(rename = "https://schemas.openid.net/secevent/caep/event-type/session-revoked")]
    SessionRevoked,
    /// CAEP 1.0 §3.3.
    #[serde(rename = "https://schemas.openid.net/secevent/caep/event-type/credential-change")]
    CredentialChange,
    /// CAEP 1.0 §3.4.
    #[serde(rename = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change")]
    AssuranceLevelChange,
    /// RISC 1.0 §2.3.
    #[serde(rename = "https://schemas.openid.net/secevent/risc/event-type/account-disabled")]
    AccountDisabled,
    /// RISC 1.0 §2.4.
    #[serde(rename = "https://schemas.openid.net/secevent/risc/event-type/account-enabled")]
    AccountEnabled,
    /// RISC 1.0 §2.2.
    #[serde(rename = "https://schemas.openid.net/secevent/risc/event-type/account-purged")]
    AccountPurged,
}

impl SsfEventType {
    /// Every event type, in canonical order.
    pub const ALL: [SsfEventType; 6] = [
        Self::SessionRevoked,
        Self::CredentialChange,
        Self::AssuranceLevelChange,
        Self::AccountDisabled,
        Self::AccountEnabled,
        Self::AccountPurged,
    ];

    /// The event-type URI, the key of the SET's `events` claim.
    #[must_use]
    pub const fn uri(self) -> &'static str {
        match self {
            Self::SessionRevoked => {
                "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
            }
            Self::CredentialChange => {
                "https://schemas.openid.net/secevent/caep/event-type/credential-change"
            }
            Self::AssuranceLevelChange => {
                "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
            }
            Self::AccountDisabled => {
                "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
            }
            Self::AccountEnabled => {
                "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
            }
            Self::AccountPurged => {
                "https://schemas.openid.net/secevent/risc/event-type/account-purged"
            }
        }
    }

    /// Parse an event-type URI. Anything else is `None` — the SSF rule is that
    /// a transmitter ignores a requested URI it does not understand.
    #[must_use]
    pub fn from_uri(uri: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.uri() == uri)
    }

    /// The URIs of `events`, deduplicated, in canonical order.
    #[must_use]
    pub fn uris(events: &[SsfEventType]) -> Vec<String> {
        canonical(events)
            .into_iter()
            .map(|e| e.uri().to_owned())
            .collect()
    }
}

/// `events` deduplicated and in canonical order.
#[must_use]
pub fn canonical(events: &[SsfEventType]) -> Vec<SsfEventType> {
    let mut out: Vec<SsfEventType> = events.to_vec();
    out.sort_unstable();
    out.dedup();
    out
}

/// How SETs reach the receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SsfDeliveryMethod {
    /// RFC 8935: AXIAM POSTs each SET to the receiver's `endpoint_url`.
    Push,
    /// RFC 8936: the receiver polls AXIAM and acknowledges what it processed.
    Poll,
}

impl SsfDeliveryMethod {
    /// The spelling stored in the database and used on the management API.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::Poll => "poll",
        }
    }

    /// Parse the stored spelling.
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "push" => Some(Self::Push),
            "poll" => Some(Self::Poll),
            _ => None,
        }
    }

    /// The SSF delivery-method URI.
    #[must_use]
    pub const fn uri(self) -> &'static str {
        match self {
            Self::Push => PUSH_DELIVERY_METHOD_URI,
            Self::Poll => POLL_DELIVERY_METHOD_URI,
        }
    }

    /// Parse an SSF delivery-method URI.
    #[must_use]
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            PUSH_DELIVERY_METHOD_URI => Some(Self::Push),
            POLL_DELIVERY_METHOD_URI => Some(Self::Poll),
            _ => None,
        }
    }
}

/// A stream's SSF status (SSF 1.0 §8.1.2), with AXIAM's meaning pinned by D-51.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SsfStreamStatus {
    /// Events are signed and transmitted.
    Enabled,
    /// Nothing is signed or transmitted; events are **held** in the stream's
    /// bounded buffer and transmitted, oldest first, when the stream is enabled
    /// again.
    Paused,
    /// Nothing is signed, transmitted or held. An event for a disabled stream
    /// is dropped where it is produced, and a queued one is dead-lettered.
    Disabled,
}

impl SsfStreamStatus {
    /// The spelling stored in the database and used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Paused => "paused",
            Self::Disabled => "disabled",
        }
    }

    /// Parse the stored spelling.
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "enabled" => Some(Self::Enabled),
            "paused" => Some(Self::Paused),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }
}

/// Who set a stream's current status. A status an administrator set to
/// anything but `enabled` cannot be changed by the receiver (D-51).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SsfStatusActor {
    /// A tenant administrator, through the management API.
    Admin,
    /// The receiver, through the SSF status endpoint.
    Receiver,
}

impl SsfStatusActor {
    /// The spelling stored in the database.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Receiver => "receiver",
        }
    }

    /// Parse the stored spelling.
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "admin" => Some(Self::Admin),
            "receiver" => Some(Self::Receiver),
            _ => None,
        }
    }
}

/// Which RFC 9493 subject identifier names the user in the SETs of a stream
/// (D-46).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SsfSubjectFormat {
    /// RFC 9493 §3.2.5 `iss_sub`: the tenant's issuer and the `sub` AXIAM's ID
    /// tokens carry (the user id). The default.
    #[default]
    IssSub,
    /// RFC 9493 §3.2.2 `email`: only an address something vouched for (the D-25
    /// rule); for any other account the event is not sent on this stream.
    Email,
}

impl SsfSubjectFormat {
    /// The spelling stored in the database and used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IssSub => "iss_sub",
            Self::Email => "email",
        }
    }

    /// Parse the stored spelling.
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "iss_sub" => Some(Self::IssSub),
            "email" => Some(Self::Email),
            _ => None,
        }
    }
}

/// One registered SSF stream, as stored and as read back.
///
/// Carries no secret: see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsfStream {
    /// The stream id, also the SSF `stream_id`.
    pub id: Uuid,
    /// The owning tenant.
    pub tenant_id: Uuid,
    /// The OAuth2 client (`client_id`) that is this stream's receiver on the
    /// stream management API.
    pub receiver_client_id: String,
    /// The SET `aud`. Unique across the deployment.
    pub audience: String,
    /// A human description (SSF's receiver-supplied `description`).
    pub description: Option<String>,
    /// Push or poll. Set by the administrator only.
    pub delivery_method: SsfDeliveryMethod,
    /// The receiver's push endpoint (push only; `None` for poll).
    pub endpoint_url: Option<String>,
    /// Whether a push `Authorization` header is stored (its value is never
    /// read back through this type).
    pub authorization_header_set: bool,
    /// The administrator's ceiling on the events this stream may carry.
    pub events_allowed: Vec<SsfEventType>,
    /// What the receiver asked for, always a subset of [`Self::events_allowed`].
    pub events_requested: Vec<SsfEventType>,
    /// How the user is named in this stream's SETs.
    pub subject_format: SsfSubjectFormat,
    /// The SSF status.
    pub status: SsfStreamStatus,
    /// Why the status is what it is, if anyone said.
    pub status_reason: Option<String>,
    /// Who set the current status.
    pub status_actor: SsfStatusActor,
    /// When the receiver last asked for a verification event.
    pub last_verification_at: Option<DateTime<Utc>>,
    /// When the stream was registered.
    pub created_at: DateTime<Utc>,
    /// When it was last written.
    pub updated_at: DateTime<Utc>,
}

impl SsfStream {
    /// The events this stream carries: the intersection of what the
    /// administrator allowed and what the receiver requested (SSF
    /// `events_delivered`), in canonical order.
    #[must_use]
    pub fn events_delivered(&self) -> Vec<SsfEventType> {
        canonical(&self.events_allowed)
            .into_iter()
            .filter(|e| self.events_requested.contains(e))
            .collect()
    }

    /// Whether `event` is one this stream carries.
    #[must_use]
    pub fn delivers(&self, event: SsfEventType) -> bool {
        self.events_allowed.contains(&event) && self.events_requested.contains(&event)
    }
}

/// A change to the stored push `Authorization` header.
#[derive(Clone, Default)]
pub enum SecretChange {
    /// Keep what is stored.
    #[default]
    Keep,
    /// Replace it (plaintext, write-only).
    Set(Zeroizing<String>),
    /// Remove it.
    Clear,
}

impl fmt::Debug for SecretChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Keep => "Keep",
            Self::Set(_) => "Set(<redacted>)",
            Self::Clear => "Clear",
        })
    }
}

/// The write input for registering a stream.
#[derive(Clone)]
pub struct NewSsfStream {
    /// See [`SsfStream::tenant_id`].
    pub tenant_id: Uuid,
    /// See [`SsfStream::receiver_client_id`].
    pub receiver_client_id: String,
    /// See [`SsfStream::audience`].
    pub audience: String,
    /// See [`SsfStream::description`].
    pub description: Option<String>,
    /// See [`SsfStream::delivery_method`].
    pub delivery_method: SsfDeliveryMethod,
    /// See [`SsfStream::endpoint_url`].
    pub endpoint_url: Option<String>,
    /// The push `Authorization` header in plaintext, write-only.
    pub authorization_header: Option<Zeroizing<String>>,
    /// See [`SsfStream::events_allowed`].
    pub events_allowed: Vec<SsfEventType>,
    /// See [`SsfStream::events_requested`].
    pub events_requested: Vec<SsfEventType>,
    /// See [`SsfStream::subject_format`].
    pub subject_format: SsfSubjectFormat,
    /// See [`SsfStream::status`].
    pub status: SsfStreamStatus,
    /// See [`SsfStream::status_reason`].
    pub status_reason: Option<String>,
}

/// `Debug` names the header's presence and nothing else.
impl fmt::Debug for NewSsfStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewSsfStream")
            .field("tenant_id", &self.tenant_id)
            .field("receiver_client_id", &self.receiver_client_id)
            .field("audience", &self.audience)
            .field("description", &self.description)
            .field("delivery_method", &self.delivery_method)
            .field("endpoint_url", &self.endpoint_url)
            .field(
                "authorization_header",
                &self.authorization_header.as_ref().map(|_| "<redacted>"),
            )
            .field("events_allowed", &self.events_allowed)
            .field("events_requested", &self.events_requested)
            .field("subject_format", &self.subject_format)
            .field("status", &self.status)
            .field("status_reason", &self.status_reason)
            .finish()
    }
}

/// A full replacement of a stream's configuration, by an administrator or —
/// for the receiver-supplied members only — by the receiver.
///
/// The repository writes exactly these values; who may change which is the
/// caller's rule (`axiam_oauth2::ssf`).
#[derive(Clone)]
pub struct SsfStreamUpdate {
    /// See [`SsfStream::receiver_client_id`].
    pub receiver_client_id: String,
    /// See [`SsfStream::audience`].
    pub audience: String,
    /// See [`SsfStream::description`].
    pub description: Option<String>,
    /// See [`SsfStream::delivery_method`].
    pub delivery_method: SsfDeliveryMethod,
    /// See [`SsfStream::endpoint_url`].
    pub endpoint_url: Option<String>,
    /// What happens to the stored header.
    pub authorization_header: SecretChange,
    /// See [`SsfStream::events_allowed`].
    pub events_allowed: Vec<SsfEventType>,
    /// See [`SsfStream::events_requested`].
    pub events_requested: Vec<SsfEventType>,
    /// See [`SsfStream::subject_format`].
    pub subject_format: SsfSubjectFormat,
    /// See [`SsfStream::status`].
    pub status: SsfStreamStatus,
    /// See [`SsfStream::status_reason`].
    pub status_reason: Option<String>,
    /// See [`SsfStream::status_actor`].
    pub status_actor: SsfStatusActor,
    /// The [`SsfStream::updated_at`] of the read this update was prepared from:
    /// the write lands only if the stream has not been written since, and is
    /// otherwise refused with `Conflict` (F4 W4 P23W4-01, T-406). Every writer
    /// replaces the whole configuration it read, so without this a receiver's
    /// write racing an administrator's would put back the status, allowance,
    /// binding or subject format the administrator had just changed (D-51).
    /// `None` writes unconditionally; nothing in the server does that.
    pub expected_updated_at: Option<DateTime<Utc>>,
}

impl SsfStreamUpdate {
    /// The update that writes `stream` back unchanged (header kept), for a
    /// caller that changes a few members — conditional on `stream` still being
    /// the stream's current version ([`Self::expected_updated_at`]).
    #[must_use]
    pub fn from_stream(stream: &SsfStream) -> Self {
        Self {
            receiver_client_id: stream.receiver_client_id.clone(),
            audience: stream.audience.clone(),
            description: stream.description.clone(),
            delivery_method: stream.delivery_method,
            endpoint_url: stream.endpoint_url.clone(),
            authorization_header: SecretChange::Keep,
            events_allowed: stream.events_allowed.clone(),
            events_requested: stream.events_requested.clone(),
            subject_format: stream.subject_format,
            status: stream.status,
            status_reason: stream.status_reason.clone(),
            status_actor: stream.status_actor,
            expected_updated_at: Some(stream.updated_at),
        }
    }
}

impl fmt::Debug for SsfStreamUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SsfStreamUpdate")
            .field("receiver_client_id", &self.receiver_client_id)
            .field("audience", &self.audience)
            .field("delivery_method", &self.delivery_method)
            .field("endpoint_url", &self.endpoint_url)
            .field("authorization_header", &self.authorization_header)
            .field("events_allowed", &self.events_allowed)
            .field("events_requested", &self.events_requested)
            .field("subject_format", &self.subject_format)
            .field("status", &self.status)
            .field("status_actor", &self.status_actor)
            .field("expected_updated_at", &self.expected_updated_at)
            .finish_non_exhaustive()
    }
}

/// One event on its way to one stream, **before** it is signed: the payload
/// contract of an [`crate::outbound::OutboundKind::SsfPush`] message and the
/// row content of the poll buffer (D-48).
///
/// Everything the SET says is fixed here — `jti`, `iat`, `txn`, the subject
/// member and the event object — and the SET is signed from it at the moment of
/// delivery (`axiam_oauth2::ssf::sign_set`), against the stream **as it is
/// then**. So a stream disabled between the event and the delivery delivers
/// nothing, a stream that narrowed its events drops what it no longer wants,
/// and a queued message holds no signed token. Ed25519 signatures are
/// deterministic, so signing the same pending event twice gives the same bytes:
/// a retried push or a repeated poll carries one SET, one `jti`.
///
/// The subject member is resolved per stream **when the event is produced**
/// (an `account-purged` user no longer exists when it is delivered); it holds
/// an email address only for a stream whose subject format is `email` and an
/// account whose address is vouched for. The queue and the buffer hold what
/// will be sent and nothing more.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SsfPendingEvent {
    /// The SET `jti`: 128 bits from the operating system's CSPRNG, lower-case
    /// hex. Also the push message's `delivery_id` and the poll `ack` key.
    pub jti: String,
    /// The SET `iat`: when the event was produced, seconds since the epoch.
    pub iat: i64,
    /// The event-type URI, the single key of the SET's `events` claim.
    pub event_uri: String,
    /// The event object (the value under `event_uri`).
    pub event: serde_json::Value,
    /// The SSF top-level `sub_id` member.
    pub sub_id: serde_json::Value,
    /// The SET `txn`, shared by every SET one underlying cause produced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txn: Option<String>,
}

/// `Debug` omits the subject, which may be an email address.
impl fmt::Debug for SsfPendingEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SsfPendingEvent")
            .field("jti", &self.jti)
            .field("iat", &self.iat)
            .field("event_uri", &self.event_uri)
            .field("txn", &self.txn)
            .finish_non_exhaustive()
    }
}

/// A boxed, `Send` future, for the object-safe [`SsfOutbox`].
pub type SsfFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Why the outbox did not take an event.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SsfOutboxError {
    /// The stream is disabled: nothing is transmitted or held (D-51).
    #[error("the stream is disabled")]
    Disabled,
    /// The event could not be enqueued or buffered. Never carries a SET, a
    /// subject or a credential.
    #[error("the event could not be submitted: {0}")]
    Failed(String),
}

/// Where a produced event goes: the seam between the producers (the event
/// sources, the verification endpoint, a status change) and delivery (G-5).
///
/// The implementation (T23.5.3) routes by the stream's status and method:
/// `enabled` push → one [`crate::outbound::OutboundKind::SsfPush`] message on
/// the shared dispatcher (D-36) with this event as its payload; `enabled` poll
/// and every `paused` stream → the stream's bounded buffer; `disabled` →
/// [`SsfOutboxError::Disabled`], nothing kept.
pub trait SsfOutbox: Send + Sync {
    /// Submit `event` for `stream`.
    fn submit<'a>(
        &'a self,
        stream: &'a SsfStream,
        event: &'a SsfPendingEvent,
    ) -> SsfFuture<'a, Result<(), SsfOutboxError>>;

    /// Release the events a **paused** push stream held, oldest first, now
    /// that it is enabled again (D-48, D-51): each becomes one
    /// [`crate::outbound::OutboundKind::SsfPush`] message. Returns how many
    /// were released. A poll stream releases nothing — its receiver reads its
    /// own buffer. The default releases nothing, for an outbox with no buffer.
    fn resume<'a>(
        &'a self,
        _stream: &'a SsfStream,
    ) -> SsfFuture<'a, Result<usize, SsfOutboxError>> {
        Box::pin(async { Ok(0) })
    }
}

/// The session-revocation port (D-52): the **only** way a CAEP
/// `session-revoked` event is produced.
///
/// `SessionRepository` calls it from exactly the three paths that publish to
/// the revocation feed — `invalidate`, `invalidate_user_sessions` and
/// `invalidate_user_sessions_except` — **after** the revocation has committed,
/// with the sessions that really were removed. It is never called from
/// `consume` or `consume_by_token_hash` (a redemption is not a revocation), nor
/// by expiry, and it does not depend on `revocation_feed_enabled`.
///
/// A sink must not fail the revocation it reports: it returns nothing, and
/// logs what it cannot do.
pub trait SessionRevocationSink: Send + Sync {
    /// Whether the sink will do anything with a revocation. A repository
    /// reads a session's user (to name it) only when this is `true`, so a
    /// sink that is not wired costs the revocation path nothing.
    fn is_active(&self) -> bool {
        true
    }

    /// `session_ids` of `user_id` in `tenant_id` were revoked just now.
    fn sessions_revoked<'a>(
        &'a self,
        tenant_id: Uuid,
        user_id: Uuid,
        session_ids: &'a [Uuid],
    ) -> SsfFuture<'a, ()>;
}

/// The port the platform's own background jobs report an account's end through
/// (D-52): a directory deactivation (`system`) and a GDPR erasure. Same
/// contract as [`SessionRevocationSink`]: after the change committed, never
/// failing it.
pub trait SsfSystemAccountSink: Send + Sync {
    /// Whether the sink will do anything. A job reads an account to name it
    /// only when this is `true`.
    fn is_active(&self) -> bool {
        true
    }

    /// The account of `user` was set `Inactive` by the platform itself. `user` is
    /// the account as it was **before** the change.
    fn account_disabled<'a>(&'a self, tenant_id: Uuid, user: &'a User) -> SsfFuture<'a, ()>;

    /// The account of `user` was erased (RISC `account-purged`). `user` is the
    /// account as it was **before** the erasure destroyed its address, so the
    /// caller reads it first.
    fn account_purged<'a>(&'a self, tenant_id: Uuid, user: &'a User) -> SsfFuture<'a, ()>;
}

/// A sink bound **after** the objects that hold it exist.
///
/// The session repository is built first and cloned into a dozen services; the
/// emitter that implements the sink needs the repositories and the outbox,
/// which come later. The repository is given a `Late` handle at construction
/// and the composition root binds the real sink once it has one. Until then
/// the handle is inactive and does nothing.
pub struct Late<T: ?Sized>(std::sync::OnceLock<std::sync::Arc<T>>);

impl<T: ?Sized> Default for Late<T> {
    fn default() -> Self {
        Self(std::sync::OnceLock::new())
    }
}

impl<T: ?Sized> Late<T> {
    /// Bind the real implementation. `false` when one was bound already (the
    /// first binding stays).
    pub fn bind(&self, inner: std::sync::Arc<T>) -> bool {
        self.0.set(inner).is_ok()
    }

    /// The bound implementation, if any.
    #[must_use]
    pub fn get(&self) -> Option<&std::sync::Arc<T>> {
        self.0.get()
    }
}

impl SessionRevocationSink for Late<dyn SessionRevocationSink> {
    fn is_active(&self) -> bool {
        self.get().is_some_and(|inner| inner.is_active())
    }

    fn sessions_revoked<'a>(
        &'a self,
        tenant_id: Uuid,
        user_id: Uuid,
        session_ids: &'a [Uuid],
    ) -> SsfFuture<'a, ()> {
        match self.get() {
            Some(inner) => inner.sessions_revoked(tenant_id, user_id, session_ids),
            None => Box::pin(async {}),
        }
    }
}

impl SsfSystemAccountSink for Late<dyn SsfSystemAccountSink> {
    fn is_active(&self) -> bool {
        self.get().is_some_and(|inner| inner.is_active())
    }

    fn account_disabled<'a>(&'a self, tenant_id: Uuid, user: &'a User) -> SsfFuture<'a, ()> {
        match self.get() {
            Some(inner) => inner.account_disabled(tenant_id, user),
            None => Box::pin(async {}),
        }
    }

    fn account_purged<'a>(&'a self, tenant_id: Uuid, user: &'a User) -> SsfFuture<'a, ()> {
        match self.get() {
            Some(inner) => inner.account_purged(tenant_id, user),
            None => Box::pin(async {}),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_uris_are_the_caep_and_risc_ones_and_round_trip() {
        let uris: Vec<&str> = SsfEventType::ALL.iter().map(|e| e.uri()).collect();
        assert_eq!(
            uris,
            vec![
                "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
                "https://schemas.openid.net/secevent/caep/event-type/credential-change",
                "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change",
                "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
                "https://schemas.openid.net/secevent/risc/event-type/account-enabled",
                "https://schemas.openid.net/secevent/risc/event-type/account-purged",
            ]
        );
        for e in SsfEventType::ALL {
            assert_eq!(SsfEventType::from_uri(e.uri()), Some(e));
            let json = serde_json::to_string(&e).unwrap();
            assert_eq!(serde_json::from_str::<SsfEventType>(&json).unwrap(), e);
        }
        assert_eq!(SsfEventType::from_uri(VERIFICATION_EVENT_URI), None);
        assert!(serde_json::from_str::<SsfEventType>("\"urn:x\"").is_err());
    }

    #[test]
    fn wire_spellings_round_trip() {
        for m in [SsfDeliveryMethod::Push, SsfDeliveryMethod::Poll] {
            assert_eq!(SsfDeliveryMethod::from_wire(m.as_str()), Some(m));
            assert_eq!(SsfDeliveryMethod::from_uri(m.uri()), Some(m));
        }
        for s in [
            SsfStreamStatus::Enabled,
            SsfStreamStatus::Paused,
            SsfStreamStatus::Disabled,
        ] {
            assert_eq!(SsfStreamStatus::from_wire(s.as_str()), Some(s));
        }
        for f in [SsfSubjectFormat::IssSub, SsfSubjectFormat::Email] {
            assert_eq!(SsfSubjectFormat::from_wire(f.as_str()), Some(f));
        }
        assert_eq!(SsfSubjectFormat::default(), SsfSubjectFormat::IssSub);
    }

    #[test]
    fn events_delivered_is_the_intersection_in_canonical_order() {
        let now = Utc::now();
        let stream = SsfStream {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            receiver_client_id: "rp".into(),
            audience: "https://rp.example".into(),
            description: None,
            delivery_method: SsfDeliveryMethod::Poll,
            endpoint_url: None,
            authorization_header_set: false,
            events_allowed: vec![
                SsfEventType::AccountPurged,
                SsfEventType::SessionRevoked,
                SsfEventType::CredentialChange,
            ],
            events_requested: vec![SsfEventType::AccountPurged, SsfEventType::SessionRevoked],
            subject_format: SsfSubjectFormat::IssSub,
            status: SsfStreamStatus::Enabled,
            status_reason: None,
            status_actor: SsfStatusActor::Admin,
            last_verification_at: None,
            created_at: now,
            updated_at: now,
        };
        assert_eq!(
            stream.events_delivered(),
            vec![SsfEventType::SessionRevoked, SsfEventType::AccountPurged]
        );
        assert!(stream.delivers(SsfEventType::SessionRevoked));
        assert!(!stream.delivers(SsfEventType::CredentialChange));
        assert!(!stream.delivers(SsfEventType::AccountEnabled));
    }

    #[test]
    fn debug_never_prints_the_header_or_the_subject() {
        let header = Zeroizing::new(format!("Bearer {}", Uuid::new_v4()));
        let printed_change = format!("{:?}", SecretChange::Set(header.clone()));
        assert!(!printed_change.contains(header.as_str()));
        let input = NewSsfStream {
            tenant_id: Uuid::nil(),
            receiver_client_id: "rp".into(),
            audience: "aud".into(),
            description: None,
            delivery_method: SsfDeliveryMethod::Push,
            endpoint_url: Some("https://rp.example/events".into()),
            authorization_header: Some(header.clone()),
            events_allowed: vec![SsfEventType::SessionRevoked],
            events_requested: vec![SsfEventType::SessionRevoked],
            subject_format: SsfSubjectFormat::Email,
            status: SsfStreamStatus::Enabled,
            status_reason: None,
        };
        assert!(!format!("{input:?}").contains(header.as_str()));
        let address = format!("{}@example.test", Uuid::new_v4().simple());
        let pending = SsfPendingEvent {
            jti: "j".into(),
            iat: 1,
            event_uri: SsfEventType::AccountEnabled.uri().into(),
            event: serde_json::json!({}),
            sub_id: serde_json::json!({"format": "email", "email": address}),
            txn: None,
        };
        assert!(!format!("{pending:?}").contains(&address));
    }

    #[test]
    fn the_pending_event_round_trips_and_omits_an_absent_txn() {
        let pending = SsfPendingEvent {
            jti: "0123".into(),
            iat: 1_700_000_000,
            event_uri: SsfEventType::AccountPurged.uri().into(),
            event: serde_json::json!({}),
            sub_id: serde_json::json!({"format": "iss_sub", "iss": "https://i", "sub": "u"}),
            txn: None,
        };
        let json = serde_json::to_value(&pending).unwrap();
        assert!(json.get("txn").is_none());
        assert_eq!(
            serde_json::from_value::<SsfPendingEvent>(json).unwrap(),
            pending
        );
    }
}

/// What the honour lane remembers, server-side, about a step-up it sent a user
/// to perform (D-53 (1), schema v78's `ssf_step_up`): the session the user held
/// and the `acr` that session achieved.
///
/// One row per `(tenant, user)`: a later step-up replaces an earlier one. It is
/// written only for a step-up with a valid OP session, lives
/// [`STEP_UP_RECORD_TTL_MINUTES`] minutes, and is consumed once, by the return
/// leg that arrives with a **new** session of the same user — which is how the
/// CAEP `assurance-level-change` event learns the level it came from without a
/// marker in `return_to` that a relying party could forge or replay. It holds
/// no credential: a session id names a row, it does not open one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsfStepUp {
    /// The tenant.
    pub tenant_id: Uuid,
    /// The user who was sent to step up.
    pub user_id: Uuid,
    /// The OP session the user held when sent.
    pub previous_session_id: Uuid,
    /// The `acr` URN that session achieved (one of the two AXIAM publishes).
    pub previous_acr: String,
}
