//! Shared Signals Framework transmitter: SET issuance, the subject-identifier
//! policy, transmitter metadata and the receiver's change rules (G-5,
//! T23.5.2).
//!
//! Specification: **OpenID Shared Signals Framework 1.0** (final, 2025-08-29),
//! **CAEP 1.0**, **RISC 1.0**, **RFC 8417** (SET), **RFC 9493** (subject
//! identifiers). Decision D-44 names them; D-45 … D-52 pin what they leave open.
//!
//! # What a SET is here, and why each claim
//!
//! | Claim / header | Value | Why |
//! |---|---|---|
//! | `typ` | `secevent+jwt` | SSF §4.1.1, RFC 8417 §2.3: explicit typing, so no SET is mistaken for another JWT. |
//! | `alg`, `kid` | `EdDSA`, the deployment key's `kid` | D-13: one Ed25519 key per deployment, published at the tenant's `jwks_uri`. |
//! | `iss` | the tenant's issuer ([`ssf_issuer`]) | SSF §4.1.6: identical to the stream's `iss` and the metadata's `issuer`. |
//! | `aud` | the stream's audience, one string | SSF §4.1.8; unique per deployment (D-47). |
//! | `iat` | when the event was produced | RFC 8417 §2.2. |
//! | `jti` | 128 bits from the OS CSPRNG, hex | RFC 8417 §2.2; the receiver's de-duplication key. |
//! | `txn` | the producer's cause id, when there is one | SSF §4.1.9: SHOULD; shared by SETs of one cause. |
//! | `sub_id` | the subject member ([`subject_member`]) | SSF §3: REQUIRED top-level. |
//! | `events` | exactly one event-type URI | SSF §4.2.1. |
//! | `sub`, `exp` | **never** | SSF §4.1.2 and §4.1.7: MUST NOT be present (D-45). |
//!
//! # Signed only when it may be sent
//!
//! [`sign_set`] is the only signer and it refuses, for a SET about a user,
//! anything but an **enabled** stream that carries the event — re-checked at
//! the moment of delivery against the stream as it is then, because the
//! unsigned [`SsfPendingEvent`] is what travels through the queue and the
//! buffer (D-48). The two stream-scoped events have their own rule: a
//! verification event needs an enabled stream; a stream-updated event may only
//! announce the status the stream is in (D-51).
//!
//! # Subject identifiers (D-46)
//!
//! `iss_sub` by default — the tenant issuer and the user id, which is the `sub`
//! of AXIAM's ID tokens (`subject_types_supported: ["public"]`), so it discloses
//! nothing a relying party did not already hold. `email` only when an
//! administrator asked for it, and only for an address something vouched for —
//! D-25's rule, `email_verified_at` set or the account `Active`; for any other
//! account the event is **not sent** on that stream ([`SsfError::EmailNotVouched`]),
//! never with a different identifier. `session-revoked` names the session too,
//! as a complex subject (`user` + `session` = the `sid` of the ID token).

use axiam_auth::config::AuthConfig;
use axiam_core::models::ssf::{
    MAX_AUDIENCE_BYTES, MAX_AUTHORIZATION_HEADER_BYTES, MAX_DESCRIPTION_BYTES,
    MAX_ENDPOINT_URL_BYTES, MAX_STATUS_REASON_BYTES, MIN_VERIFICATION_INTERVAL_SECS,
    POLL_DELIVERY_METHOD_URI, PUSH_DELIVERY_METHOD_URI, SSF_SPEC_VERSION, STREAM_UPDATED_EVENT_URI,
    SecretChange, SsfDeliveryMethod, SsfEventType, SsfPendingEvent, SsfStream, SsfStreamStatus,
    SsfStreamUpdate, SsfSubjectFormat, VERIFICATION_EVENT_URI,
};
use axiam_core::models::user::{User, UserStatus};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use uuid::Uuid;
use zeroize::Zeroizing;

/// The JOSE `typ` of every SET (RFC 8417 §2.3, SSF §4.1.1).
pub const SET_TYP: &str = "secevent+jwt";

/// The `namespace` of AXIAM's `assurance-level-change` levels (CAEP 1.0 §3.4
/// allows a transmitter-defined alias). The levels are the two `acr` values
/// AXIAM publishes, [`crate::oidc::ACR_SINGLE_FACTOR`] and
/// [`crate::oidc::ACR_MULTI_FACTOR`] (D-45).
pub const ACR_NAMESPACE: &str = "urn:axiam:acr";

/// The stream management API's path, relative to the deployment's root issuer.
pub const STREAM_PATH: &str = "/ssf/v1/stream";
/// The status endpoint's path.
pub const STATUS_PATH: &str = "/ssf/v1/status";
/// The verification endpoint's path.
pub const VERIFY_PATH: &str = "/ssf/v1/verify";
/// The poll endpoint's path prefix; a stream polls at `{prefix}/{stream_id}`
/// (served by T23.5.3, RFC 8936).
pub const POLL_PATH_PREFIX: &str = "/ssf/v1/poll";

/// Why a SET was not produced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SsfError {
    /// The stream is disabled: nothing is signed, sent or held.
    #[error("the stream is disabled")]
    StreamDisabled,
    /// The stream is not enabled; the event is held (paused) or dropped.
    #[error("the stream is not enabled")]
    StreamNotEnabled,
    /// The stream does not carry this event type (not allowed, or not
    /// requested).
    #[error("the stream does not carry this event")]
    EventNotDelivered,
    /// The stream names users by email and this account's address is not one
    /// anything vouched for (D-46). The event is not sent on this stream.
    #[error("the account's email address is not vouched for")]
    EmailNotVouched,
    /// A `session-revoked` event without a session.
    #[error("a session-revoked event needs the session")]
    SessionRequired,
    /// The stream-scoped event does not match the stream it is signed for.
    #[error("the event does not belong to this stream")]
    WrongStream,
    /// The stream has no audience (a row no write path can produce).
    #[error("the stream has no audience")]
    NoAudience,
    /// The deployment key could not sign.
    #[error("the SET could not be signed: {0}")]
    Signing(String),
}

// ---------------------------------------------------------------------------
// Event shapes (D-45)
// ---------------------------------------------------------------------------

/// CAEP 1.0 §2 `initiating_entity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitiatingEntity {
    /// An administrative action.
    Admin,
    /// The end user.
    User,
    /// A policy evaluation.
    Policy,
    /// The platform itself.
    System,
}

impl InitiatingEntity {
    /// The CAEP spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
            Self::Policy => "policy",
            Self::System => "system",
        }
    }
}

/// CAEP 1.0 §3.3 `credential_type`, the subset AXIAM has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialType {
    /// A password, or an OPAQUE registration (it is a password credential).
    Password,
    /// An X.509 certificate.
    X509,
    /// A platform WebAuthn authenticator (transports include `internal`).
    Fido2Platform,
    /// A roaming WebAuthn authenticator.
    Fido2Roaming,
    /// A TOTP authenticator app.
    App,
}

impl CredentialType {
    /// The CAEP spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::X509 => "x509",
            Self::Fido2Platform => "fido2-platform",
            Self::Fido2Roaming => "fido2-roaming",
            Self::App => "app",
        }
    }
}

/// CAEP 1.0 §3.3 `change_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeType {
    /// A credential was enrolled.
    Create,
    /// A credential was revoked (a certificate).
    Revoke,
    /// A credential was changed (a password change or reset).
    Update,
    /// A credential was removed.
    Delete,
}

impl ChangeType {
    /// The CAEP spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Revoke => "revoke",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }
}

/// An `acr` class AXIAM achieves (the two values it publishes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssuranceLevel {
    /// [`crate::oidc::ACR_SINGLE_FACTOR`].
    SingleFactor,
    /// [`crate::oidc::ACR_MULTI_FACTOR`].
    MultiFactor,
}

impl AssuranceLevel {
    /// The level string in [`ACR_NAMESPACE`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SingleFactor => crate::oidc::ACR_SINGLE_FACTOR,
            Self::MultiFactor => crate::oidc::ACR_MULTI_FACTOR,
        }
    }

    /// The level of an authentication context class the honour lane derived.
    #[must_use]
    pub const fn from_acr(acr: crate::acr::Acr) -> Self {
        match acr {
            crate::acr::Acr::SingleFactor => Self::SingleFactor,
            crate::acr::Acr::MultiFactor => Self::MultiFactor,
        }
    }

    /// The level named by one of the two published `acr` URNs; `None` for
    /// anything else.
    #[must_use]
    pub fn from_urn(urn: &str) -> Option<Self> {
        match urn {
            crate::oidc::ACR_SINGLE_FACTOR => Some(Self::SingleFactor),
            crate::oidc::ACR_MULTI_FACTOR => Some(Self::MultiFactor),
            _ => None,
        }
    }
}

/// RISC 1.0 §2.3 `reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountDisabledReason {
    /// The account was hijacked.
    Hijacking,
    /// The account was created in bulk.
    BulkAccount,
}

impl AccountDisabledReason {
    /// The RISC spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hijacking => "hijacking",
            Self::BulkAccount => "bulk-account",
        }
    }
}

/// One of the six events AXIAM transmits, with exactly the members its SET
/// carries (D-45). No member holds free text a person typed: CAEP's
/// `reason_admin`, `reason_user` and `friendly_name` are never sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsfEvent {
    /// CAEP `session-revoked`: `{ initiating_entity?, event_timestamp }`.
    SessionRevoked {
        /// Who revoked it.
        initiating_entity: Option<InitiatingEntity>,
        /// When, seconds since the epoch.
        event_timestamp: i64,
    },
    /// CAEP `credential-change`: `{ credential_type, change_type,
    /// initiating_entity?, event_timestamp, x509_issuer?, x509_serial?,
    /// fido2_aaguid? }`.
    CredentialChange {
        /// What kind of credential.
        credential_type: CredentialType,
        /// What happened to it.
        change_type: ChangeType,
        /// Who did it.
        initiating_entity: Option<InitiatingEntity>,
        /// When.
        event_timestamp: i64,
        /// The certificate's issuer DN (`x509` only).
        x509_issuer: Option<String>,
        /// The certificate's serial (`x509` only).
        x509_serial: Option<String>,
        /// The authenticator's AAGUID (`fido2-*` only).
        fido2_aaguid: Option<String>,
    },
    /// CAEP `assurance-level-change`: `{ namespace, current_level,
    /// previous_level?, change_direction?, initiating_entity?, event_timestamp }`.
    AssuranceLevelChange {
        /// The level now.
        current_level: AssuranceLevel,
        /// The level before, when known.
        previous_level: Option<AssuranceLevel>,
        /// Who caused it.
        initiating_entity: Option<InitiatingEntity>,
        /// When.
        event_timestamp: i64,
    },
    /// RISC `account-disabled`: `{ reason? }`.
    AccountDisabled {
        /// Why, when AXIAM knows (it rarely does).
        reason: Option<AccountDisabledReason>,
    },
    /// RISC `account-enabled`: `{}`.
    AccountEnabled,
    /// RISC `account-purged`: `{}`.
    AccountPurged,
}

impl SsfEvent {
    /// The event type.
    #[must_use]
    pub fn event_type(&self) -> SsfEventType {
        match self {
            Self::SessionRevoked { .. } => SsfEventType::SessionRevoked,
            Self::CredentialChange { .. } => SsfEventType::CredentialChange,
            Self::AssuranceLevelChange { .. } => SsfEventType::AssuranceLevelChange,
            Self::AccountDisabled { .. } => SsfEventType::AccountDisabled,
            Self::AccountEnabled => SsfEventType::AccountEnabled,
            Self::AccountPurged => SsfEventType::AccountPurged,
        }
    }

    /// The event object, the value under the event-type URI.
    #[must_use]
    pub fn payload(&self) -> Value {
        let mut out = Map::new();
        let mut put = |name: &str, value: Value| {
            out.insert(name.to_owned(), value);
        };
        match self {
            Self::SessionRevoked {
                initiating_entity,
                event_timestamp,
            } => {
                if let Some(who) = initiating_entity {
                    put("initiating_entity", json!(who.as_str()));
                }
                put("event_timestamp", json!(event_timestamp));
            }
            Self::CredentialChange {
                credential_type,
                change_type,
                initiating_entity,
                event_timestamp,
                x509_issuer,
                x509_serial,
                fido2_aaguid,
            } => {
                put("credential_type", json!(credential_type.as_str()));
                put("change_type", json!(change_type.as_str()));
                if let Some(who) = initiating_entity {
                    put("initiating_entity", json!(who.as_str()));
                }
                put("event_timestamp", json!(event_timestamp));
                if *credential_type == CredentialType::X509 {
                    if let Some(issuer) = x509_issuer {
                        put("x509_issuer", json!(issuer));
                    }
                    if let Some(serial) = x509_serial {
                        put("x509_serial", json!(serial));
                    }
                }
                if matches!(
                    credential_type,
                    CredentialType::Fido2Platform | CredentialType::Fido2Roaming
                ) && let Some(aaguid) = fido2_aaguid
                {
                    put("fido2_aaguid", json!(aaguid));
                }
            }
            Self::AssuranceLevelChange {
                current_level,
                previous_level,
                initiating_entity,
                event_timestamp,
            } => {
                put("namespace", json!(ACR_NAMESPACE));
                put("current_level", json!(current_level.as_str()));
                if let Some(previous) = previous_level {
                    put("previous_level", json!(previous.as_str()));
                    // CAEP: SHOULD be given when previous_level is. Equal levels
                    // are not a change and the producer does not emit one.
                    if previous != current_level {
                        let direction = if current_level > previous {
                            "increase"
                        } else {
                            "decrease"
                        };
                        put("change_direction", json!(direction));
                    }
                }
                if let Some(who) = initiating_entity {
                    put("initiating_entity", json!(who.as_str()));
                }
                put("event_timestamp", json!(event_timestamp));
            }
            Self::AccountDisabled { reason } => {
                if let Some(reason) = reason {
                    put("reason", json!(reason.as_str()));
                }
            }
            Self::AccountEnabled | Self::AccountPurged => {}
        }
        Value::Object(out)
    }
}

// ---------------------------------------------------------------------------
// Subjects (D-46)
// ---------------------------------------------------------------------------

/// Who an event is about, as the producer knows it. Resolved per stream by
/// [`subject_member`].
#[derive(Clone, PartialEq, Eq)]
pub struct SsfSubject {
    /// The user id, the `sub` of AXIAM's ID tokens.
    pub user_id: Uuid,
    /// The account's email address, if any.
    pub email: Option<String>,
    /// Whether something vouched for the address (D-25: `email_verified_at`
    /// set, or the account `Active`).
    pub email_vouched: bool,
    /// The session, for `session-revoked` (the ID token's `sid`).
    pub session_id: Option<Uuid>,
}

/// `Debug` omits the address.
impl std::fmt::Debug for SsfSubject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsfSubject")
            .field("user_id", &self.user_id)
            .field("email", &self.email.as_ref().map(|_| "<present>"))
            .field("email_vouched", &self.email_vouched)
            .field("session_id", &self.session_id)
            .finish()
    }
}

/// D-25's rule, the one the SAML IdP applies to an email `NameID`: an address
/// is asserted when something vouches for it.
#[must_use]
pub fn email_is_vouched_for(user: &User) -> bool {
    user.email_verified_at.is_some() || user.status == UserStatus::Active
}

impl SsfSubject {
    /// The subject a user is, as of now. Capture it **before** the change the
    /// event reports when the change destroys the address (an erasure).
    #[must_use]
    pub fn from_user(user: &User) -> Self {
        Self {
            user_id: user.id,
            email: Some(user.email.clone()).filter(|e| !e.trim().is_empty()),
            email_vouched: email_is_vouched_for(user),
            session_id: None,
        }
    }

    /// The same subject, about one session.
    #[must_use]
    pub fn with_session(mut self, session_id: Uuid) -> Self {
        self.session_id = Some(session_id);
        self
    }
}

/// The `iss` of a tenant's SETs and of its transmitter metadata: the tenant's
/// path issuer when the deployment serves them (T21.6), the deployment's root
/// issuer otherwise. Never the per-request issuer: a SET is not minted inside
/// the request that caused it.
#[must_use]
pub fn ssf_issuer(config: &AuthConfig, tenant_id: Uuid) -> String {
    config
        .tenant_issuer(tenant_id)
        .unwrap_or_else(|| config.root_issuer().to_owned())
}

/// The RFC 9493 identifier of the user, in the stream's format.
fn user_identifier(
    format: SsfSubjectFormat,
    issuer: &str,
    subject: &SsfSubject,
) -> Result<Value, SsfError> {
    match format {
        SsfSubjectFormat::IssSub => Ok(json!({
            "format": "iss_sub",
            "iss": issuer,
            "sub": subject.user_id.to_string(),
        })),
        SsfSubjectFormat::Email => match (&subject.email, subject.email_vouched) {
            (Some(address), true) => Ok(json!({ "format": "email", "email": address })),
            _ => Err(SsfError::EmailNotVouched),
        },
    }
}

/// The SSF `sub_id` member for `subject` on `stream` (D-46): a simple
/// subject, or for `session-revoked` a complex one naming the user and the
/// session.
///
/// # Errors
///
/// [`SsfError::EmailNotVouched`] on an `email` stream for an address nothing
/// vouched for; [`SsfError::SessionRequired`] for a `session-revoked` event
/// without a session.
pub fn subject_member(
    stream: &SsfStream,
    issuer: &str,
    subject: &SsfSubject,
    event: SsfEventType,
) -> Result<Value, SsfError> {
    let user = user_identifier(stream.subject_format, issuer, subject)?;
    if event != SsfEventType::SessionRevoked {
        return Ok(user);
    }
    let session = subject.session_id.ok_or(SsfError::SessionRequired)?;
    Ok(json!({
        "format": "complex",
        "user": user,
        "session": { "format": "opaque", "id": session.to_string() },
    }))
}

/// A fresh `jti`: 128 bits from the operating system's CSPRNG (a v4 UUID's
/// random bits come from `getrandom`), as 32 lower-case hex characters, and the
/// same bits as the push message's `delivery_id`.
#[must_use]
pub fn new_jti() -> (Uuid, String) {
    let id = Uuid::new_v4();
    (id, id.simple().to_string())
}

/// The `delivery_id` of a pending event's push message: its `jti` read back as
/// a UUID, so a retried push and the SET it carries name one delivery.
#[must_use]
pub fn delivery_id_of(pending: &SsfPendingEvent) -> Option<Uuid> {
    Uuid::try_parse(&pending.jti).ok()
}

/// Fix everything a SET about `subject` will say, for one stream (D-48).
///
/// # Errors
///
/// [`SsfError::StreamDisabled`] for a disabled stream (nothing is held for
/// it); [`SsfError::EventNotDelivered`] when the stream does not carry the
/// event; the [`subject_member`] errors.
pub fn prepare_event(
    config: &AuthConfig,
    stream: &SsfStream,
    event: &SsfEvent,
    subject: &SsfSubject,
    txn: Option<&str>,
    now: DateTime<Utc>,
) -> Result<SsfPendingEvent, SsfError> {
    if stream.status == SsfStreamStatus::Disabled {
        return Err(SsfError::StreamDisabled);
    }
    let event_type = event.event_type();
    if !stream.delivers(event_type) {
        return Err(SsfError::EventNotDelivered);
    }
    let issuer = ssf_issuer(config, stream.tenant_id);
    let sub_id = subject_member(stream, &issuer, subject, event_type)?;
    let (_, jti) = new_jti();
    Ok(SsfPendingEvent {
        jti,
        iat: now.timestamp(),
        event_uri: event_type.uri().to_owned(),
        event: event.payload(),
        sub_id,
        txn: txn.map(str::to_owned),
    })
}

/// The stream's own subject (SSF §8.1.4.1, §8.1.5): `opaque`, the stream id.
fn stream_subject(stream: &SsfStream) -> Value {
    json!({ "format": "opaque", "id": stream.id.to_string() })
}

/// A verification event (SSF §8.1.4.1): `{ state? }`, subject the stream.
///
/// # Errors
///
/// [`SsfError::StreamDisabled`] for a disabled stream.
pub fn prepare_verification(
    stream: &SsfStream,
    state: Option<&str>,
    now: DateTime<Utc>,
) -> Result<SsfPendingEvent, SsfError> {
    if stream.status == SsfStreamStatus::Disabled {
        return Err(SsfError::StreamDisabled);
    }
    let mut event = Map::new();
    if let Some(state) = state {
        event.insert("state".into(), json!(state));
    }
    let (_, jti) = new_jti();
    Ok(SsfPendingEvent {
        jti,
        iat: now.timestamp(),
        event_uri: VERIFICATION_EVENT_URI.to_owned(),
        event: Value::Object(event),
        sub_id: stream_subject(stream),
        txn: None,
    })
}

/// A stream-updated event announcing the status `stream` is in now (SSF
/// §8.1.5): `{ status, reason? }`, subject the stream. Produced after an
/// administrator changed the status.
#[must_use]
pub fn prepare_stream_updated(stream: &SsfStream, now: DateTime<Utc>) -> SsfPendingEvent {
    let mut event = Map::new();
    event.insert("status".into(), json!(stream.status.as_str()));
    if let Some(reason) = &stream.status_reason {
        event.insert("reason".into(), json!(reason));
    }
    let (_, jti) = new_jti();
    SsfPendingEvent {
        jti,
        iat: now.timestamp(),
        event_uri: STREAM_UPDATED_EVENT_URI.to_owned(),
        event: Value::Object(event),
        sub_id: stream_subject(stream),
        txn: None,
    }
}

/// The claims of a SET. `sub` and `exp` do not exist on this type, so no
/// SET can carry them (SSF §4.1.2, §4.1.7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SetClaims {
    /// The tenant's issuer.
    pub iss: String,
    /// The stream's audience.
    pub aud: String,
    /// Issued at.
    pub iat: i64,
    /// The SET id.
    pub jti: String,
    /// The underlying cause.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txn: Option<String>,
    /// The subject member.
    pub sub_id: Value,
    /// Exactly one event.
    pub events: Map<String, Value>,
}

/// Whether `pending` may be signed for `stream` as the stream is now.
fn check_signable(stream: &SsfStream, pending: &SsfPendingEvent) -> Result<(), SsfError> {
    match pending.event_uri.as_str() {
        STREAM_UPDATED_EVENT_URI => {
            // It may only announce the status the stream is in: that is what
            // lets the announcement of a disable go out after the disable
            // (SSF §8.1.5: "before stopping the stream"), and nothing else.
            if pending.sub_id != stream_subject(stream) {
                return Err(SsfError::WrongStream);
            }
            if pending.event.get("status").and_then(Value::as_str) != Some(stream.status.as_str()) {
                return Err(SsfError::StreamNotEnabled);
            }
            Ok(())
        }
        VERIFICATION_EVENT_URI => {
            if pending.sub_id != stream_subject(stream) {
                return Err(SsfError::WrongStream);
            }
            match stream.status {
                SsfStreamStatus::Enabled => Ok(()),
                SsfStreamStatus::Paused => Err(SsfError::StreamNotEnabled),
                SsfStreamStatus::Disabled => Err(SsfError::StreamDisabled),
            }
        }
        uri => {
            let event = SsfEventType::from_uri(uri).ok_or(SsfError::EventNotDelivered)?;
            match stream.status {
                SsfStreamStatus::Enabled => {}
                SsfStreamStatus::Paused => return Err(SsfError::StreamNotEnabled),
                SsfStreamStatus::Disabled => return Err(SsfError::StreamDisabled),
            }
            if !stream.delivers(event) {
                return Err(SsfError::EventNotDelivered);
            }
            Ok(())
        }
    }
}

/// Sign `pending` as a SET for `stream` with the deployment key (D-13) —
/// **the only SET signer**, called at the moment of delivery.
///
/// # Errors
///
/// See the module documentation: a stream that is not enabled, an event it
/// does not carry, a stream-scoped event of another stream, a status
/// announcement that is not the stream's status, a stream without an
/// audience, or a key that cannot sign.
pub fn sign_set(
    config: &AuthConfig,
    stream: &SsfStream,
    pending: &SsfPendingEvent,
) -> Result<String, SsfError> {
    check_signable(stream, pending)?;
    if stream.audience.trim().is_empty() {
        return Err(SsfError::NoAudience);
    }
    let mut events = Map::new();
    events.insert(pending.event_uri.clone(), pending.event.clone());
    let claims = SetClaims {
        iss: ssf_issuer(config, stream.tenant_id),
        aud: stream.audience.clone(),
        iat: pending.iat,
        jti: pending.jti.clone(),
        txn: pending.txn.clone(),
        sub_id: pending.sub_id.clone(),
        events,
    };
    let owned;
    let key: &EncodingKey = if let Some(ref cached) = config.jwt_encoding_key {
        cached.as_ref()
    } else {
        owned = EncodingKey::from_ed_pem(config.jwt_private_key_pem.as_bytes())
            .map_err(|_| SsfError::Signing("the deployment signing key is unusable".into()))?;
        &owned
    };
    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some(SET_TYP.to_owned());
    header.kid = axiam_auth::token::ed25519_jwk_kid(&config.jwt_public_key_pem);
    jsonwebtoken::encode(&header, &claims, key)
        .map_err(|_| SsfError::Signing("the SET could not be encoded".into()))
}

/// Issue a SET about `subject` for `stream` now: [`prepare_event`] then
/// [`sign_set`]. The unit-testable whole.
///
/// # Errors
///
/// Those of the two steps.
pub fn issue_set(
    config: &AuthConfig,
    stream: &SsfStream,
    event: &SsfEvent,
    subject: &SsfSubject,
    txn: Option<&str>,
) -> Result<String, SsfError> {
    let pending = prepare_event(config, stream, event, subject, txn, Utc::now())?;
    sign_set(config, stream, &pending)
}

// ---------------------------------------------------------------------------
// Transmitter metadata (SSF §7)
// ---------------------------------------------------------------------------

/// One entry of `authorization_schemes` (SSF §7.1.1).
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct SsfAuthorizationScheme {
    /// `urn:ietf:rfc:6749`: an OAuth 2.0 client-credentials token carrying
    /// the `ssf.manage` scope.
    pub spec_urn: String,
}

/// `/.well-known/ssf-configuration` (SSF 1.0 §7.1).
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct SsfConfiguration {
    /// `1_0`.
    pub spec_version: String,
    /// The tenant's issuer, identical to every SET's `iss`.
    pub issuer: String,
    /// Where the deployment key is published.
    pub jwks_uri: String,
    /// Push (RFC 8935) and poll (RFC 8936).
    pub delivery_methods_supported: Vec<String>,
    /// The stream configuration endpoint.
    pub configuration_endpoint: String,
    /// The stream status endpoint.
    pub status_endpoint: String,
    /// The verification endpoint.
    pub verification_endpoint: String,
    /// How a receiver authenticates to the three endpoints and to poll.
    pub authorization_schemes: Vec<SsfAuthorizationScheme>,
    /// `ALL`: every subject appropriate for a stream is on it (there is no
    /// add/remove-subject endpoint).
    pub default_subjects: String,
    /// The event types AXIAM transmits (an extension member; SSF §7.1 allows
    /// other claims).
    pub events_supported: Vec<String>,
}

/// The transmitter metadata of `tenant_id`.
#[must_use]
pub fn build_ssf_configuration(config: &AuthConfig, tenant_id: Uuid) -> SsfConfiguration {
    let issuer = ssf_issuer(config, tenant_id);
    let root = config.root_issuer();
    SsfConfiguration {
        spec_version: SSF_SPEC_VERSION.to_owned(),
        jwks_uri: format!("{issuer}/oauth2/jwks"),
        issuer,
        delivery_methods_supported: vec![
            PUSH_DELIVERY_METHOD_URI.to_owned(),
            POLL_DELIVERY_METHOD_URI.to_owned(),
        ],
        configuration_endpoint: format!("{root}{STREAM_PATH}"),
        status_endpoint: format!("{root}{STATUS_PATH}"),
        verification_endpoint: format!("{root}{VERIFY_PATH}"),
        authorization_schemes: vec![SsfAuthorizationScheme {
            spec_urn: "urn:ietf:rfc:6749".to_owned(),
        }],
        default_subjects: "ALL".to_owned(),
        events_supported: SsfEventType::uris(&SsfEventType::ALL),
    }
}

/// A stream's poll endpoint (RFC 8936), unique per stream.
#[must_use]
pub fn poll_endpoint(config: &AuthConfig, stream_id: Uuid) -> String {
    format!("{}{POLL_PATH_PREFIX}/{stream_id}", config.root_issuer())
}

// ---------------------------------------------------------------------------
// The receiver's view of a stream (SSF §8.1.1)
// ---------------------------------------------------------------------------

/// The `delivery` member of a stream configuration as AXIAM returns it. The
/// `authorization_header` is never returned.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct SsfDeliveryView {
    /// The delivery-method URI.
    pub method: String,
    /// The push endpoint (receiver-supplied) or the poll endpoint
    /// (transmitter-supplied).
    pub endpoint_url: String,
}

/// A stream configuration (SSF 1.0 §8.1.1) as the receiver reads it.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct SsfStreamConfiguration {
    /// The stream id.
    pub stream_id: String,
    /// The tenant's issuer.
    pub iss: String,
    /// The SET audience.
    pub aud: String,
    /// The delivery method and endpoint.
    pub delivery: SsfDeliveryView,
    /// What the administrator allowed this receiver.
    pub events_supported: Vec<String>,
    /// What the receiver asked for.
    pub events_requested: Vec<String>,
    /// What the stream carries.
    pub events_delivered: Vec<String>,
    /// The description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Seconds between two verification requests.
    pub min_verification_interval: i64,
}

/// The receiver's view of `stream`.
#[must_use]
pub fn stream_configuration(config: &AuthConfig, stream: &SsfStream) -> SsfStreamConfiguration {
    let endpoint_url = match stream.delivery_method {
        SsfDeliveryMethod::Push => stream.endpoint_url.clone().unwrap_or_default(),
        SsfDeliveryMethod::Poll => poll_endpoint(config, stream.id),
    };
    SsfStreamConfiguration {
        stream_id: stream.id.to_string(),
        iss: ssf_issuer(config, stream.tenant_id),
        aud: stream.audience.clone(),
        delivery: SsfDeliveryView {
            method: stream.delivery_method.uri().to_owned(),
            endpoint_url,
        },
        events_supported: SsfEventType::uris(&stream.events_allowed),
        events_requested: SsfEventType::uris(&stream.events_requested),
        events_delivered: SsfEventType::uris(&stream.events_delivered()),
        description: stream.description.clone(),
        min_verification_interval: MIN_VERIFICATION_INTERVAL_SECS,
    }
}

// ---------------------------------------------------------------------------
// Value rules shared by the administrator and the receiver
// ---------------------------------------------------------------------------

/// Text without control characters and without surrounding whitespace.
fn plain_text(value: &str) -> bool {
    !value.chars().any(char::is_control) && value.trim() == value
}

/// An audience: 1–512 bytes of plain text.
///
/// # Errors
///
/// A message naming the rule.
pub fn validate_audience(audience: &str) -> Result<(), String> {
    if audience.is_empty() || audience.len() > MAX_AUDIENCE_BYTES {
        return Err(format!("audience must be 1 to {MAX_AUDIENCE_BYTES} bytes"));
    }
    if !plain_text(audience) {
        return Err(
            "audience must not contain control characters or surrounding whitespace".into(),
        );
    }
    Ok(())
}

/// A description: at most 256 bytes of plain text.
///
/// # Errors
///
/// A message naming the rule.
pub fn validate_description(description: &str) -> Result<(), String> {
    if description.len() > MAX_DESCRIPTION_BYTES {
        return Err(format!(
            "description must be at most {MAX_DESCRIPTION_BYTES} bytes"
        ));
    }
    if description.chars().any(char::is_control) {
        return Err("description must not contain control characters".into());
    }
    Ok(())
}

/// A status reason: at most 256 bytes of plain text.
///
/// # Errors
///
/// A message naming the rule.
pub fn validate_status_reason(reason: &str) -> Result<(), String> {
    if reason.len() > MAX_STATUS_REASON_BYTES || reason.chars().any(char::is_control) {
        return Err(format!(
            "reason must be at most {MAX_STATUS_REASON_BYTES} bytes without control characters"
        ));
    }
    Ok(())
}

/// A push `Authorization` header value: 1–4096 bytes of visible ASCII and
/// spaces. Never echoed in the message.
///
/// # Errors
///
/// A message naming the rule.
pub fn validate_authorization_header(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_AUTHORIZATION_HEADER_BYTES {
        return Err(format!(
            "authorization_header must be 1 to {MAX_AUTHORIZATION_HEADER_BYTES} bytes"
        ));
    }
    if !value.bytes().all(|b| b == b' ' || b.is_ascii_graphic()) || value.trim() != value {
        return Err(
            "authorization_header must be visible ASCII without line breaks or surrounding \
             whitespace"
                .into(),
        );
    }
    Ok(())
}

/// A push endpoint, held to the outbound address policy webhooks use (D-49):
/// absolute `https`, a host, no credentials, no fragment, at most 2 048 bytes,
/// no IP literal that is not globally routable
/// (`axiam_core::ip_class::is_disallowed_ip`: loopback, private, link-local,
/// the cloud metadata address and the rest), and no `localhost`, `*.localhost`,
/// `*.local` or `*.internal` name. A name that **resolves** to such an address
/// is refused at delivery by `axiam_pki::ssrf::guarded_fetch`, which pins the
/// address it checked.
///
/// # Errors
///
/// A message naming the rule; never the URL.
pub fn validate_push_endpoint(raw: &str) -> Result<url::Url, String> {
    if raw.is_empty() || raw.len() > MAX_ENDPOINT_URL_BYTES {
        return Err(format!(
            "endpoint_url must be 1 to {MAX_ENDPOINT_URL_BYTES} bytes"
        ));
    }
    let url = url::Url::parse(raw).map_err(|_| "endpoint_url is not an absolute URL".to_owned())?;
    if url.scheme() != "https" {
        return Err("endpoint_url must use https".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("endpoint_url must not carry credentials".into());
    }
    if url.fragment().is_some() {
        return Err("endpoint_url must not carry a fragment".into());
    }
    match url.host() {
        None => return Err("endpoint_url must name a host".into()),
        Some(url::Host::Ipv4(ip)) => {
            if axiam_core::ip_class::is_disallowed_ip(std::net::IpAddr::V4(ip)) {
                return Err("endpoint_url must not point to a non-public address".into());
            }
        }
        Some(url::Host::Ipv6(ip)) => {
            if axiam_core::ip_class::is_disallowed_ip(std::net::IpAddr::V6(ip)) {
                return Err("endpoint_url must not point to a non-public address".into());
            }
        }
        Some(url::Host::Domain(name)) => {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            if name == "localhost"
                || name.ends_with(".localhost")
                || name.ends_with(".local")
                || name.ends_with(".internal")
            {
                return Err("endpoint_url must not point to a local or internal host".into());
            }
        }
    }
    Ok(url)
}

/// Whether two endpoints share an origin (scheme, host, port).
#[must_use]
pub fn same_origin(a: &str, b: &str) -> bool {
    match (url::Url::parse(a), url::Url::parse(b)) {
        (Ok(a), Ok(b)) => a.origin() == b.origin(),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// What a receiver may change (D-50)
// ---------------------------------------------------------------------------

/// `delivery` in a receiver's update.
#[derive(Clone, Default, Deserialize, utoipa::ToSchema)]
pub struct ReceiverDelivery {
    /// The delivery-method URI. It must be the stream's: the method is the
    /// administrator's.
    #[serde(default)]
    pub method: Option<String>,
    /// A push stream's new endpoint; a poll stream may only repeat its own.
    #[serde(default)]
    pub endpoint_url: Option<String>,
    /// The `Authorization` header AXIAM sends to the push endpoint. Write-only.
    #[serde(default)]
    pub authorization_header: Option<String>,
}

impl std::fmt::Debug for ReceiverDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiverDelivery")
            .field("method", &self.method)
            .field("endpoint_url", &self.endpoint_url)
            .field(
                "authorization_header",
                &self.authorization_header.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// A receiver's `PATCH` or `PUT` body on the configuration endpoint (SSF
/// §8.1.1.3, §8.1.1.4). Transmitter-supplied members may be present and must
/// then match.
#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
pub struct ReceiverStreamUpdate {
    /// The stream to change. Required.
    #[serde(default)]
    pub stream_id: Option<String>,
    /// Must match, if present.
    #[serde(default)]
    pub iss: Option<String>,
    /// Must match, if present (a string, or an array of that one string).
    #[serde(default)]
    pub aud: Option<Value>,
    /// Must match, if present.
    #[serde(default)]
    pub events_supported: Option<Vec<String>>,
    /// Must match the value before the update, if present.
    #[serde(default)]
    pub events_delivered: Option<Vec<String>>,
    /// Must match, if present.
    #[serde(default)]
    pub min_verification_interval: Option<i64>,
    /// The events the receiver wants. Unknown URIs are ignored; a known one
    /// the administrator did not allow is refused.
    #[serde(default)]
    pub events_requested: Option<Vec<String>>,
    /// The delivery settings the receiver may supply.
    #[serde(default)]
    pub delivery: Option<ReceiverDelivery>,
    /// A description.
    #[serde(default)]
    pub description: Option<String>,
}

/// `PATCH` changes what is present; `PUT` replaces every receiver-supplied
/// member, and an absent one is deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverUpdateMode {
    /// `PATCH`.
    Patch,
    /// `PUT`.
    Replace,
}

/// Apply a receiver's change to `stream` (D-50), producing the full update to
/// store. The administrator's members — receiver binding, audience,
/// `events_allowed`, subject format, delivery method, status — are copied
/// through unchanged.
///
/// # Errors
///
/// A message naming the rule (`400`); it never echoes a header or a URL.
pub fn apply_receiver_update(
    config: &AuthConfig,
    stream: &SsfStream,
    request: &ReceiverStreamUpdate,
    mode: ReceiverUpdateMode,
) -> Result<SsfStreamUpdate, String> {
    let current = stream_configuration(config, stream);
    if let Some(iss) = &request.iss
        && *iss != current.iss
    {
        return Err("iss does not match the stream's issuer".into());
    }
    if let Some(aud) = &request.aud {
        let matches = match aud {
            Value::String(one) => *one == current.aud,
            Value::Array(many) => many.len() == 1 && many[0] == Value::String(current.aud.clone()),
            _ => false,
        };
        if !matches {
            return Err("aud does not match the stream's audience".into());
        }
    }
    let same_set = |given: &[String], expected: &[String]| {
        let mut a: Vec<&String> = given.iter().collect();
        let mut b: Vec<&String> = expected.iter().collect();
        a.sort();
        a.dedup();
        b.sort();
        a == b
    };
    if let Some(supported) = &request.events_supported
        && !same_set(supported, &current.events_supported)
    {
        return Err("events_supported does not match the stream's".into());
    }
    if let Some(delivered) = &request.events_delivered
        && !same_set(delivered, &current.events_delivered)
    {
        return Err("events_delivered does not match the stream's".into());
    }
    if let Some(interval) = request.min_verification_interval
        && interval != MIN_VERIFICATION_INTERVAL_SECS
    {
        return Err("min_verification_interval does not match the stream's".into());
    }

    let mut update = SsfStreamUpdate::from_stream(stream);

    // events_requested: narrow, never widen.
    match (&request.events_requested, mode) {
        (Some(uris), _) => {
            let mut wanted = Vec::new();
            for uri in uris {
                // SSF §8.1.1: a transmitter ignores a URI it does not understand.
                let Some(event) = SsfEventType::from_uri(uri) else {
                    continue;
                };
                if !stream.events_allowed.contains(&event) {
                    return Err(
                        "events_requested names an event the administrator has not allowed \
                         this stream"
                            .into(),
                    );
                }
                wanted.push(event);
            }
            update.events_requested = axiam_core::models::ssf::canonical(&wanted);
        }
        (None, ReceiverUpdateMode::Replace) => update.events_requested = Vec::new(),
        (None, ReceiverUpdateMode::Patch) => {}
    }

    match (&request.description, mode) {
        (Some(text), _) => {
            validate_description(text)?;
            update.description = Some(text.clone()).filter(|t| !t.is_empty());
        }
        (None, ReceiverUpdateMode::Replace) => update.description = None,
        (None, ReceiverUpdateMode::Patch) => {}
    }

    let delivery = match (&request.delivery, mode) {
        (Some(d), _) => d.clone(),
        (None, ReceiverUpdateMode::Patch) => return Ok(update),
        (None, ReceiverUpdateMode::Replace) => {
            return Err("delivery is required when the configuration is replaced".into());
        }
    };
    if let Some(method) = &delivery.method
        && *method != stream.delivery_method.uri()
    {
        return Err("the delivery method is set by the administrator".into());
    }
    match stream.delivery_method {
        SsfDeliveryMethod::Poll => {
            if delivery.authorization_header.is_some() {
                return Err("a poll stream has no authorization_header".into());
            }
            if let Some(url) = &delivery.endpoint_url
                && *url != poll_endpoint(config, stream.id)
            {
                return Err("a poll stream's endpoint_url is the transmitter's".into());
            }
        }
        SsfDeliveryMethod::Push => {
            let header = match &delivery.authorization_header {
                Some(value) => {
                    validate_authorization_header(value)?;
                    SecretChange::Set(Zeroizing::new(value.clone()))
                }
                None if mode == ReceiverUpdateMode::Replace => SecretChange::Clear,
                None => SecretChange::Keep,
            };
            match &delivery.endpoint_url {
                Some(url) => {
                    validate_push_endpoint(url)?;
                    let previous = stream.endpoint_url.as_deref().unwrap_or_default();
                    // A stored credential never follows the endpoint to another
                    // origin without being supplied again (D-49).
                    if stream.authorization_header_set
                        && matches!(header, SecretChange::Keep)
                        && !same_origin(previous, url)
                    {
                        return Err("moving the push endpoint to another origin requires the \
                             authorization_header again"
                            .into());
                    }
                    update.endpoint_url = Some(url.clone());
                }
                None if mode == ReceiverUpdateMode::Replace => {
                    return Err("a push stream's delivery needs an endpoint_url".into());
                }
                None => {}
            }
            update.authorization_header = header;
        }
    }
    Ok(update)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::ssf::SsfStatusActor;
    use jsonwebtoken::{DecodingKey, Validation};
    use std::sync::OnceLock;

    /// An Ed25519 deployment key generated once per test binary.
    fn pems() -> &'static (String, String) {
        static PEMS: OnceLock<(String, String)> = OnceLock::new();
        PEMS.get_or_init(|| {
            let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519");
            (pair.serialize_pem(), pair.public_key_pem())
        })
    }

    fn config(tenant_paths: bool) -> AuthConfig {
        let (private, public) = pems();
        AuthConfig {
            jwt_private_key_pem: private.clone(),
            jwt_public_key_pem: public.clone(),
            oauth2_issuer_url: "https://id.example.test".into(),
            tenant_issuer_paths: tenant_paths,
            ..AuthConfig::default()
        }
    }

    fn stream(status: SsfStreamStatus, format: SsfSubjectFormat) -> SsfStream {
        let now = Utc::now();
        SsfStream {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            receiver_client_id: "rp".into(),
            audience: "https://rp.example.test/ssf".into(),
            description: None,
            delivery_method: SsfDeliveryMethod::Push,
            endpoint_url: Some("https://rp.example.test/events".into()),
            authorization_header_set: true,
            events_allowed: SsfEventType::ALL.to_vec(),
            events_requested: SsfEventType::ALL.to_vec(),
            subject_format: format,
            status,
            status_reason: None,
            status_actor: SsfStatusActor::Admin,
            last_verification_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn subject(vouched: bool) -> SsfSubject {
        SsfSubject {
            user_id: Uuid::new_v4(),
            email: Some(format!("{}@example.test", Uuid::new_v4().simple())),
            email_vouched: vouched,
            session_id: Some(Uuid::new_v4()),
        }
    }

    /// Verify `set` against the JWKS AXIAM publishes, the way a receiver does.
    fn verify(set: &str, cfg: &AuthConfig, aud: &str, iss: &str) -> Result<Value, String> {
        let jwks = crate::oidc::build_jwks(&cfg.jwt_public_key_pem).unwrap();
        let header = jsonwebtoken::decode_header(set).map_err(|e| e.to_string())?;
        let jwk = jwks
            .keys
            .iter()
            .find(|k| Some(&k.kid) == header.kid.as_ref())
            .ok_or("no key with the header's kid")?;
        let key = DecodingKey::from_ed_components(&jwk.x).map_err(|e| e.to_string())?;
        let mut v = Validation::new(Algorithm::EdDSA);
        v.required_spec_claims.clear();
        v.validate_exp = false;
        v.set_audience(&[aud]);
        v.set_issuer(&[iss]);
        jsonwebtoken::decode::<Value>(set, &key, &v)
            .map(|d| d.claims)
            .map_err(|e| e.to_string())
    }

    fn sample(event: SsfEventType) -> SsfEvent {
        match event {
            SsfEventType::SessionRevoked => SsfEvent::SessionRevoked {
                initiating_entity: Some(InitiatingEntity::Admin),
                event_timestamp: 1_700_000_000,
            },
            SsfEventType::CredentialChange => SsfEvent::CredentialChange {
                credential_type: CredentialType::Password,
                change_type: ChangeType::Update,
                initiating_entity: Some(InitiatingEntity::User),
                event_timestamp: 1_700_000_001,
                x509_issuer: None,
                x509_serial: None,
                fido2_aaguid: None,
            },
            SsfEventType::AssuranceLevelChange => SsfEvent::AssuranceLevelChange {
                current_level: AssuranceLevel::MultiFactor,
                previous_level: Some(AssuranceLevel::SingleFactor),
                initiating_entity: Some(InitiatingEntity::User),
                event_timestamp: 1_700_000_002,
            },
            SsfEventType::AccountDisabled => SsfEvent::AccountDisabled { reason: None },
            SsfEventType::AccountEnabled => SsfEvent::AccountEnabled,
            SsfEventType::AccountPurged => SsfEvent::AccountPurged,
        }
    }

    #[test]
    fn a_set_verifies_against_the_published_jwks_with_the_pinned_header_and_claims() {
        let cfg = config(false);
        let s = stream(SsfStreamStatus::Enabled, SsfSubjectFormat::IssSub);
        let who = subject(true);
        let set = issue_set(
            &cfg,
            &s,
            &sample(SsfEventType::AccountDisabled),
            &who,
            Some("cause-1"),
        )
        .unwrap();

        let header = jsonwebtoken::decode_header(&set).unwrap();
        assert_eq!(header.typ.as_deref(), Some("secevent+jwt"));
        assert_eq!(header.alg, Algorithm::EdDSA);
        assert_eq!(
            header.kid,
            axiam_auth::token::ed25519_jwk_kid(&cfg.jwt_public_key_pem)
        );

        let claims = verify(&set, &cfg, &s.audience, "https://id.example.test").unwrap();
        assert_eq!(claims["iss"], "https://id.example.test");
        assert_eq!(claims["aud"], s.audience.as_str());
        assert_eq!(claims["txn"], "cause-1");
        assert!(claims["iat"].as_i64().unwrap() > 0);
        let jti = claims["jti"].as_str().unwrap();
        assert_eq!(jti.len(), 32);
        assert!(jti.bytes().all(|b| b.is_ascii_hexdigit()));
        // SSF §4.1.2 / §4.1.7: no `sub`, no `exp`.
        assert!(claims.get("sub").is_none());
        assert!(claims.get("exp").is_none());
        let events = claims["events"].as_object().unwrap();
        assert_eq!(events.len(), 1);
        assert!(events.contains_key(SsfEventType::AccountDisabled.uri()));
    }

    #[test]
    fn a_set_does_not_verify_for_another_audience_or_issuer() {
        let cfg = config(false);
        let s = stream(SsfStreamStatus::Enabled, SsfSubjectFormat::IssSub);
        let set = issue_set(
            &cfg,
            &s,
            &sample(SsfEventType::AccountPurged),
            &subject(true),
            None,
        )
        .unwrap();
        assert!(
            verify(
                &set,
                &cfg,
                "https://other-rp.example.test",
                "https://id.example.test"
            )
            .is_err()
        );
        assert!(verify(&set, &cfg, &s.audience, "https://evil.example.test").is_err());
        assert!(verify(&set, &cfg, &s.audience, "https://id.example.test").is_ok());
    }

    #[test]
    fn a_set_is_never_accepted_as_an_axiam_access_token() {
        // Token confusion (T-389): same key, but no `exp`, no `sub`, and an
        // audience that is not an AXIAM one.
        let cfg = config(false);
        let s = stream(SsfStreamStatus::Enabled, SsfSubjectFormat::IssSub);
        let set = issue_set(
            &cfg,
            &s,
            &sample(SsfEventType::AccountEnabled),
            &subject(true),
            None,
        )
        .unwrap();
        assert!(axiam_auth::token::validate_access_token(&set, &cfg).is_err());
    }

    #[test]
    fn every_jti_is_unique() {
        let cfg = config(false);
        let s = stream(SsfStreamStatus::Enabled, SsfSubjectFormat::IssSub);
        let who = subject(true);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let p = prepare_event(
                &cfg,
                &s,
                &sample(SsfEventType::AccountEnabled),
                &who,
                None,
                Utc::now(),
            )
            .unwrap();
            assert!(seen.insert(p.jti.clone()), "a jti repeated");
            assert_eq!(delivery_id_of(&p).unwrap().simple().to_string(), p.jti);
        }
    }

    #[test]
    fn signing_the_same_pending_event_twice_gives_the_same_set() {
        // Ed25519 is deterministic: a retried push or a repeated poll carries
        // one SET (D-48).
        let cfg = config(false);
        let s = stream(SsfStreamStatus::Enabled, SsfSubjectFormat::IssSub);
        let p = prepare_event(
            &cfg,
            &s,
            &sample(SsfEventType::CredentialChange),
            &subject(true),
            Some("t"),
            Utc::now(),
        )
        .unwrap();
        assert_eq!(
            sign_set(&cfg, &s, &p).unwrap(),
            sign_set(&cfg, &s, &p).unwrap()
        );
    }

    #[test]
    fn each_of_the_six_events_has_its_pinned_shape() {
        let expect: [(SsfEventType, Value); 6] = [
            (
                SsfEventType::SessionRevoked,
                json!({"initiating_entity": "admin", "event_timestamp": 1_700_000_000}),
            ),
            (
                SsfEventType::CredentialChange,
                json!({
                    "credential_type": "password",
                    "change_type": "update",
                    "initiating_entity": "user",
                    "event_timestamp": 1_700_000_001
                }),
            ),
            (
                SsfEventType::AssuranceLevelChange,
                json!({
                    "namespace": "urn:axiam:acr",
                    "current_level": "urn:axiam:acr:mfa",
                    "previous_level": "urn:axiam:acr:1fa",
                    "change_direction": "increase",
                    "initiating_entity": "user",
                    "event_timestamp": 1_700_000_002
                }),
            ),
            (SsfEventType::AccountDisabled, json!({})),
            (SsfEventType::AccountEnabled, json!({})),
            (SsfEventType::AccountPurged, json!({})),
        ];
        let cfg = config(false);
        let s = stream(SsfStreamStatus::Enabled, SsfSubjectFormat::IssSub);
        for (event, shape) in expect {
            assert_eq!(sample(event).payload(), shape, "{event:?}");
            let set = issue_set(&cfg, &s, &sample(event), &subject(true), None).unwrap();
            let claims = verify(&set, &cfg, &s.audience, "https://id.example.test").unwrap();
            assert_eq!(claims["events"][event.uri()], shape, "{event:?} in the SET");
        }
        // The optional members appear only for their credential type.
        let cert = SsfEvent::CredentialChange {
            credential_type: CredentialType::X509,
            change_type: ChangeType::Revoke,
            initiating_entity: None,
            event_timestamp: 5,
            x509_issuer: Some("CN=Tenant CA".into()),
            x509_serial: Some("0a1b".into()),
            fido2_aaguid: Some("ignored".into()),
        };
        assert_eq!(
            cert.payload(),
            json!({"credential_type": "x509", "change_type": "revoke", "event_timestamp": 5,
                   "x509_issuer": "CN=Tenant CA", "x509_serial": "0a1b"})
        );
        let key = SsfEvent::CredentialChange {
            credential_type: CredentialType::Fido2Roaming,
            change_type: ChangeType::Create,
            initiating_entity: Some(InitiatingEntity::User),
            event_timestamp: 6,
            x509_issuer: Some("ignored".into()),
            x509_serial: None,
            fido2_aaguid: Some("accced6a-63f5-490a-9eea-e59bc1896cfc".into()),
        };
        assert_eq!(
            key.payload(),
            json!({"credential_type": "fido2-roaming", "change_type": "create",
                   "initiating_entity": "user", "event_timestamp": 6,
                   "fido2_aaguid": "accced6a-63f5-490a-9eea-e59bc1896cfc"})
        );
        let down = SsfEvent::AssuranceLevelChange {
            current_level: AssuranceLevel::SingleFactor,
            previous_level: Some(AssuranceLevel::MultiFactor),
            initiating_entity: None,
            event_timestamp: 7,
        };
        assert_eq!(down.payload()["change_direction"], "decrease");
        let unknown_previous = SsfEvent::AssuranceLevelChange {
            current_level: AssuranceLevel::MultiFactor,
            previous_level: None,
            initiating_entity: None,
            event_timestamp: 8,
        };
        assert!(unknown_previous.payload().get("change_direction").is_none());
        assert_eq!(
            SsfEvent::AccountDisabled {
                reason: Some(AccountDisabledReason::Hijacking)
            }
            .payload(),
            json!({"reason": "hijacking"})
        );
    }

    #[test]
    fn both_subject_formats_are_rfc_9493_and_the_session_is_named() {
        let cfg = config(false);
        let who = subject(true);
        let iss = "https://id.example.test";

        let s = stream(SsfStreamStatus::Enabled, SsfSubjectFormat::IssSub);
        let simple = subject_member(&s, iss, &who, SsfEventType::AccountEnabled).unwrap();
        assert_eq!(
            simple,
            json!({"format": "iss_sub", "iss": iss, "sub": who.user_id.to_string()})
        );
        let complex = subject_member(&s, iss, &who, SsfEventType::SessionRevoked).unwrap();
        assert_eq!(
            complex,
            json!({
                "format": "complex",
                "user": {"format": "iss_sub", "iss": iss, "sub": who.user_id.to_string()},
                "session": {"format": "opaque", "id": who.session_id.unwrap().to_string()}
            })
        );

        let e = stream(SsfStreamStatus::Enabled, SsfSubjectFormat::Email);
        let by_mail = subject_member(&e, iss, &who, SsfEventType::AccountPurged).unwrap();
        assert_eq!(
            by_mail,
            json!({"format": "email", "email": who.email.clone().unwrap()})
        );

        // The member in a signed SET is the same object.
        let set = issue_set(&cfg, &e, &sample(SsfEventType::AccountPurged), &who, None).unwrap();
        let claims = verify(&set, &cfg, &e.audience, iss).unwrap();
        assert_eq!(claims["sub_id"], by_mail);
    }

    #[test]
    fn an_unvouched_address_is_never_sent_and_nothing_else_replaces_it() {
        let cfg = config(false);
        let e = stream(SsfStreamStatus::Enabled, SsfSubjectFormat::Email);
        let pending = subject(false);
        assert_eq!(
            issue_set(
                &cfg,
                &e,
                &sample(SsfEventType::AccountDisabled),
                &pending,
                None
            ),
            Err(SsfError::EmailNotVouched)
        );
        let mut no_address = subject(true);
        no_address.email = None;
        assert_eq!(
            issue_set(
                &cfg,
                &e,
                &sample(SsfEventType::AccountDisabled),
                &no_address,
                None
            ),
            Err(SsfError::EmailNotVouched)
        );
        // On an iss_sub stream the same account is fine.
        let s = stream(SsfStreamStatus::Enabled, SsfSubjectFormat::IssSub);
        assert!(
            issue_set(
                &cfg,
                &s,
                &sample(SsfEventType::AccountDisabled),
                &pending,
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn the_vouching_rule_is_d25s() {
        let mut user = User {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            username: "u".into(),
            email: "u@example.test".into(),
            ..test_user()
        };
        user.status = UserStatus::PendingVerification;
        user.email_verified_at = None;
        assert!(!SsfSubject::from_user(&user).email_vouched);
        user.email_verified_at = Some(Utc::now());
        assert!(SsfSubject::from_user(&user).email_vouched);
        user.email_verified_at = None;
        user.status = UserStatus::Active;
        assert!(SsfSubject::from_user(&user).email_vouched);
        assert_eq!(SsfSubject::from_user(&user).session_id, None);
    }

    fn test_user() -> User {
        let now = Utc::now();
        User {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            username: "u".into(),
            email: "u@example.test".into(),
            // Not a credential: an unusable placeholder generated per run.
            password_hash: Uuid::new_v4().to_string(),
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
            metadata: json!({}),
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn a_session_revoked_event_needs_its_session() {
        let cfg = config(false);
        let s = stream(SsfStreamStatus::Enabled, SsfSubjectFormat::IssSub);
        let mut who = subject(true);
        who.session_id = None;
        assert_eq!(
            issue_set(&cfg, &s, &sample(SsfEventType::SessionRevoked), &who, None),
            Err(SsfError::SessionRequired)
        );
    }

    #[test]
    fn no_set_for_a_disabled_or_paused_stream_or_an_event_it_does_not_carry() {
        let cfg = config(false);
        let who = subject(true);
        let disabled = stream(SsfStreamStatus::Disabled, SsfSubjectFormat::IssSub);
        let paused = stream(SsfStreamStatus::Paused, SsfSubjectFormat::IssSub);
        for event in SsfEventType::ALL {
            assert_eq!(
                issue_set(&cfg, &disabled, &sample(event), &who, None),
                Err(SsfError::StreamDisabled),
                "{event:?}"
            );
            // Paused: prepared (to be held), never signed.
            let held =
                prepare_event(&cfg, &paused, &sample(event), &who, None, Utc::now()).unwrap();
            assert_eq!(
                sign_set(&cfg, &paused, &held),
                Err(SsfError::StreamNotEnabled)
            );
        }
        // An event prepared while enabled is not signed once the stream is
        // disabled: the check runs at delivery (D-48).
        let mut s = stream(SsfStreamStatus::Enabled, SsfSubjectFormat::IssSub);
        let queued = prepare_event(
            &cfg,
            &s,
            &sample(SsfEventType::AccountPurged),
            &who,
            None,
            Utc::now(),
        )
        .unwrap();
        s.status = SsfStreamStatus::Disabled;
        assert_eq!(sign_set(&cfg, &s, &queued), Err(SsfError::StreamDisabled));
        // Narrowed in the meantime: dropped.
        s.status = SsfStreamStatus::Enabled;
        s.events_requested = vec![SsfEventType::SessionRevoked];
        assert_eq!(
            sign_set(&cfg, &s, &queued),
            Err(SsfError::EventNotDelivered)
        );
        assert_eq!(
            issue_set(&cfg, &s, &sample(SsfEventType::AccountPurged), &who, None),
            Err(SsfError::EventNotDelivered)
        );
    }

    #[test]
    fn the_verification_event_echoes_the_state_and_names_the_stream() {
        let cfg = config(false);
        let s = stream(SsfStreamStatus::Enabled, SsfSubjectFormat::Email);
        let state = Uuid::new_v4().to_string();
        let p = prepare_verification(&s, Some(&state), Utc::now()).unwrap();
        let set = sign_set(&cfg, &s, &p).unwrap();
        let claims = verify(&set, &cfg, &s.audience, "https://id.example.test").unwrap();
        assert_eq!(
            claims["sub_id"],
            json!({"format": "opaque", "id": s.id.to_string()})
        );
        assert_eq!(
            claims["events"][VERIFICATION_EVENT_URI],
            json!({"state": state})
        );
        assert!(claims.get("txn").is_none());
        // Without a state: an empty event object.
        let bare = prepare_verification(&s, None, Utc::now()).unwrap();
        assert_eq!(bare.event, json!({}));
        // Not for another stream, and not for a disabled one.
        let other = stream(SsfStreamStatus::Enabled, SsfSubjectFormat::IssSub);
        assert_eq!(sign_set(&cfg, &other, &p), Err(SsfError::WrongStream));
        let disabled = stream(SsfStreamStatus::Disabled, SsfSubjectFormat::IssSub);
        assert_eq!(
            prepare_verification(&disabled, None, Utc::now()),
            Err(SsfError::StreamDisabled)
        );
    }

    #[test]
    fn a_stream_updated_event_may_only_announce_the_current_status() {
        let cfg = config(false);
        let mut s = stream(SsfStreamStatus::Disabled, SsfSubjectFormat::IssSub);
        s.status_reason = Some("maintenance".into());
        let p = prepare_stream_updated(&s, Utc::now());
        assert_eq!(
            p.event,
            json!({"status": "disabled", "reason": "maintenance"})
        );
        // The announcement of a disable goes out after the disable.
        let set = sign_set(&cfg, &s, &p).unwrap();
        let claims = verify(&set, &cfg, &s.audience, "https://id.example.test").unwrap();
        assert_eq!(
            claims["events"][STREAM_UPDATED_EVENT_URI]["status"],
            "disabled"
        );
        // But not once the stream is something else.
        s.status = SsfStreamStatus::Enabled;
        assert_eq!(sign_set(&cfg, &s, &p), Err(SsfError::StreamNotEnabled));
    }

    #[test]
    fn the_issuer_follows_the_tenant_issuer_mode() {
        let s = stream(SsfStreamStatus::Enabled, SsfSubjectFormat::IssSub);
        let root = config(false);
        assert_eq!(ssf_issuer(&root, s.tenant_id), "https://id.example.test");
        let paths = config(true);
        let tenant_iss = format!("https://id.example.test/t/{}", s.tenant_id);
        assert_eq!(ssf_issuer(&paths, s.tenant_id), tenant_iss);
        let set = issue_set(
            &paths,
            &s,
            &sample(SsfEventType::AccountEnabled),
            &subject(true),
            None,
        )
        .unwrap();
        let claims = verify(&set, &paths, &s.audience, &tenant_iss).unwrap();
        assert_eq!(claims["sub_id"]["iss"], tenant_iss.as_str());
    }

    #[test]
    fn discovery_lists_the_endpoints_methods_and_events_for_both_issuer_modes() {
        let tenant = Uuid::new_v4();
        let root = build_ssf_configuration(&config(false), tenant);
        assert_eq!(root.spec_version, "1_0");
        assert_eq!(root.issuer, "https://id.example.test");
        assert_eq!(root.jwks_uri, "https://id.example.test/oauth2/jwks");
        assert_eq!(
            root.configuration_endpoint,
            "https://id.example.test/ssf/v1/stream"
        );
        assert_eq!(
            root.status_endpoint,
            "https://id.example.test/ssf/v1/status"
        );
        assert_eq!(
            root.verification_endpoint,
            "https://id.example.test/ssf/v1/verify"
        );
        assert_eq!(
            root.delivery_methods_supported,
            vec!["urn:ietf:rfc:8935", "urn:ietf:rfc:8936"]
        );
        assert_eq!(root.events_supported.len(), 6);
        for e in SsfEventType::ALL {
            assert!(root.events_supported.contains(&e.uri().to_owned()));
        }
        assert_eq!(root.default_subjects, "ALL");
        assert_eq!(root.authorization_schemes[0].spec_urn, "urn:ietf:rfc:6749");

        let paths = build_ssf_configuration(&config(true), tenant);
        let iss = format!("https://id.example.test/t/{tenant}");
        assert_eq!(paths.issuer, iss);
        assert_eq!(paths.jwks_uri, format!("{iss}/oauth2/jwks"));
        // The management endpoints are the deployment's, whichever mode.
        assert_eq!(
            paths.configuration_endpoint,
            "https://id.example.test/ssf/v1/stream"
        );
    }

    #[test]
    fn the_push_endpoint_policy_is_the_webhook_one() {
        for refused in [
            "http://rp.example.test/events",
            "https://127.0.0.1/events",
            "https://10.0.0.5/events",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/events",
            "https://[::ffff:169.254.169.254]/x",
            "https://localhost/events",
            "https://svc.internal/events",
            "https://printer.local/events",
            "https://user:pw@rp.example.test/events",
            "https://rp.example.test/events#frag",
            "not a url",
            "",
        ] {
            assert!(validate_push_endpoint(refused).is_err(), "{refused}");
        }
        let long = format!("https://rp.example.test/{}", "a".repeat(2100));
        assert!(validate_push_endpoint(&long).is_err());
        assert!(validate_push_endpoint("https://rp.example.test/ssf/events?x=1").is_ok());
        assert!(validate_push_endpoint("https://203.0.113.10/x").is_err());
        assert!(validate_push_endpoint("https://8.8.8.8/x").is_ok());
    }

    fn patch(f: impl FnOnce(&mut ReceiverStreamUpdate)) -> ReceiverStreamUpdate {
        let mut r = ReceiverStreamUpdate::default();
        f(&mut r);
        r
    }

    #[test]
    fn a_receiver_may_narrow_but_not_widen_its_events() {
        let cfg = config(false);
        let mut s = stream(SsfStreamStatus::Enabled, SsfSubjectFormat::IssSub);
        s.events_allowed = vec![SsfEventType::SessionRevoked, SsfEventType::AccountDisabled];
        s.events_requested = s.events_allowed.clone();
        let narrowed = apply_receiver_update(
            &cfg,
            &s,
            &patch(|r| {
                r.events_requested = Some(vec![
                    SsfEventType::SessionRevoked.uri().into(),
                    "urn:example:unknown".into(),
                ])
            }),
            ReceiverUpdateMode::Patch,
        )
        .unwrap();
        assert_eq!(
            narrowed.events_requested,
            vec![SsfEventType::SessionRevoked]
        );
        assert_eq!(narrowed.events_allowed, s.events_allowed);

        let widened = apply_receiver_update(
            &cfg,
            &s,
            &patch(|r| r.events_requested = Some(vec![SsfEventType::AccountPurged.uri().into()])),
            ReceiverUpdateMode::Patch,
        );
        assert!(widened.unwrap_err().contains("not allowed"));
    }

    #[test]
    fn transmitter_supplied_members_must_match() {
        let cfg = config(false);
        let s = stream(SsfStreamStatus::Enabled, SsfSubjectFormat::IssSub);
        for bad in [
            patch(|r| r.iss = Some("https://other.example.test".into())),
            patch(|r| r.aud = Some(json!("https://other.example.test"))),
            patch(|r| r.events_supported = Some(vec![])),
            patch(|r| r.events_delivered = Some(vec![])),
            patch(|r| r.min_verification_interval = Some(1)),
            patch(|r| {
                r.delivery = Some(ReceiverDelivery {
                    method: Some(POLL_DELIVERY_METHOD_URI.into()),
                    ..Default::default()
                })
            }),
        ] {
            assert!(
                apply_receiver_update(&cfg, &s, &bad, ReceiverUpdateMode::Patch).is_err(),
                "{bad:?}"
            );
        }
        let matching = patch(|r| {
            r.iss = Some("https://id.example.test".into());
            r.aud = Some(json!([s.audience.clone()]));
            r.events_supported = Some(SsfEventType::uris(&SsfEventType::ALL));
        });
        assert!(apply_receiver_update(&cfg, &s, &matching, ReceiverUpdateMode::Patch).is_ok());
    }

    #[test]
    fn repointing_the_endpoint_is_held_to_the_address_policy_and_the_credential_rule() {
        let cfg = config(false);
        let s = stream(SsfStreamStatus::Enabled, SsfSubjectFormat::IssSub);
        let to = |url: &str, header: Option<String>| {
            patch(|r| {
                r.delivery = Some(ReceiverDelivery {
                    method: None,
                    endpoint_url: Some(url.into()),
                    authorization_header: header,
                })
            })
        };
        // A refused address.
        assert!(
            apply_receiver_update(
                &cfg,
                &s,
                &to("https://169.254.169.254/latest", None),
                ReceiverUpdateMode::Patch
            )
            .is_err()
        );
        // Same origin: the stored header stays.
        let same = apply_receiver_update(
            &cfg,
            &s,
            &to("https://rp.example.test/v2/events", None),
            ReceiverUpdateMode::Patch,
        )
        .unwrap();
        assert!(matches!(same.authorization_header, SecretChange::Keep));
        // Another origin without the header again: refused (D-49).
        let err = apply_receiver_update(
            &cfg,
            &s,
            &to("https://elsewhere.example.test/events", None),
            ReceiverUpdateMode::Patch,
        )
        .unwrap_err();
        assert!(err.contains("authorization_header again"));
        // With it: accepted, and set.
        let fresh = format!("Bearer {}", Uuid::new_v4().simple());
        let moved = apply_receiver_update(
            &cfg,
            &s,
            &to("https://elsewhere.example.test/events", Some(fresh.clone())),
            ReceiverUpdateMode::Patch,
        )
        .unwrap();
        assert_eq!(
            moved.endpoint_url.as_deref(),
            Some("https://elsewhere.example.test/events")
        );
        assert!(matches!(&moved.authorization_header, SecretChange::Set(v) if v.as_str() == fresh));
        // A header with a line break is refused, and the message does not echo it.
        let crlf = format!("Bearer {}\r\nX-Injected: 1", Uuid::new_v4().simple());
        let err = apply_receiver_update(
            &cfg,
            &s,
            &to("https://rp.example.test/events", Some(crlf.clone())),
            ReceiverUpdateMode::Patch,
        )
        .unwrap_err();
        assert!(!err.contains(&crlf));
    }

    #[test]
    fn replace_deletes_what_it_omits_and_needs_a_delivery() {
        let cfg = config(false);
        let mut s = stream(SsfStreamStatus::Enabled, SsfSubjectFormat::IssSub);
        s.description = Some("old".into());
        assert!(
            apply_receiver_update(&cfg, &s, &patch(|_| {}), ReceiverUpdateMode::Replace)
                .unwrap_err()
                .contains("delivery is required")
        );
        let replaced = apply_receiver_update(
            &cfg,
            &s,
            &patch(|r| {
                r.delivery = Some(ReceiverDelivery {
                    method: Some(PUSH_DELIVERY_METHOD_URI.into()),
                    endpoint_url: Some("https://rp.example.test/events".into()),
                    authorization_header: None,
                })
            }),
            ReceiverUpdateMode::Replace,
        )
        .unwrap();
        assert!(replaced.events_requested.is_empty());
        assert_eq!(replaced.description, None);
        assert!(matches!(replaced.authorization_header, SecretChange::Clear));
        // Administrator members untouched.
        assert_eq!(replaced.audience, s.audience);
        assert_eq!(replaced.events_allowed, s.events_allowed);
        assert_eq!(replaced.status, s.status);
        assert_eq!(replaced.subject_format, s.subject_format);
    }

    #[test]
    fn a_poll_stream_keeps_the_transmitters_endpoint_and_takes_no_header() {
        let cfg = config(false);
        let mut s = stream(SsfStreamStatus::Enabled, SsfSubjectFormat::IssSub);
        s.delivery_method = SsfDeliveryMethod::Poll;
        s.endpoint_url = None;
        s.authorization_header_set = false;
        let view = stream_configuration(&cfg, &s);
        assert_eq!(
            view.delivery.endpoint_url,
            format!("https://id.example.test/ssf/v1/poll/{}", s.id)
        );
        assert_eq!(view.delivery.method, POLL_DELIVERY_METHOD_URI);
        let repeat = patch(|r| {
            r.delivery = Some(ReceiverDelivery {
                method: Some(POLL_DELIVERY_METHOD_URI.into()),
                endpoint_url: Some(view.delivery.endpoint_url.clone()),
                authorization_header: None,
            })
        });
        assert!(apply_receiver_update(&cfg, &s, &repeat, ReceiverUpdateMode::Patch).is_ok());
        let elsewhere = patch(|r| {
            r.delivery = Some(ReceiverDelivery {
                method: None,
                endpoint_url: Some("https://rp.example.test/poll".into()),
                authorization_header: None,
            })
        });
        assert!(apply_receiver_update(&cfg, &s, &elsewhere, ReceiverUpdateMode::Patch).is_err());
        let with_header = patch(|r| {
            r.delivery = Some(ReceiverDelivery {
                method: None,
                endpoint_url: None,
                authorization_header: Some(format!("Bearer {}", Uuid::new_v4().simple())),
            })
        });
        assert!(apply_receiver_update(&cfg, &s, &with_header, ReceiverUpdateMode::Patch).is_err());
    }

    #[test]
    fn the_receiver_view_never_carries_the_header() {
        let cfg = config(false);
        let s = stream(SsfStreamStatus::Enabled, SsfSubjectFormat::IssSub);
        let view = serde_json::to_value(stream_configuration(&cfg, &s)).unwrap();
        assert!(view["delivery"].get("authorization_header").is_none());
        assert_eq!(view["min_verification_interval"], 60);
        assert_eq!(view["events_delivered"].as_array().unwrap().len(), 6);
    }

    #[test]
    fn debug_never_prints_a_subjects_address_or_a_receivers_header() {
        let who = subject(true);
        let printed = format!("{who:?}");
        assert!(!printed.contains(who.email.as_deref().unwrap()));
        let header = format!("Bearer {}", Uuid::new_v4().simple());
        let d = ReceiverDelivery {
            method: None,
            endpoint_url: None,
            authorization_header: Some(header.clone()),
        };
        assert!(!format!("{d:?}").contains(&header));
    }
}
