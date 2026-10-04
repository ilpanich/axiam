//! What SAML single logout needs the datastore to remember (G-2, T23.2.4,
//! schema v76): which service providers hold which session, and where a logout
//! chain stands.
//!
//! Two tables, both tenant-scoped, both short-lived by construction.
//!
//! # `saml_sp_session` — the participant record (D-37)
//!
//! One row per (tenant, AXIAM session, service provider), written by the SSO
//! endpoint's second leg **before** the assertion is signed. It holds the
//! `NameID` and the `SessionIndex` the SP was given, because:
//!
//! * a pairwise `NameID` is an HMAC (D-22) and cannot be resolved back to a user
//!   without a record, and
//! * single logout must know, for every logout, which SPs hold a session and
//!   what each was told.
//!
//! The `SessionIndex` is 32 bytes from the OS CSPRNG, base64url without padding,
//! **per SP** — so two SPs that compare notes cannot correlate a person's
//! sessions through it (T-312) — and it is **not** the AXIAM session id. A row
//! is not a credential: a `LogoutRequest` must be signed by the SP's registered
//! certificate, so an index alone ends nothing.
//!
//! # `saml_logout_run` — the logout chain (D-39)
//!
//! One row per verified logout. It is the replay guard for a `LogoutRequest`
//! `ID` (`replay_key`, UNIQUE per tenant, kept until the row expires) and the
//! state of the front-channel propagation: the participant rows still to be
//! told, and the SHA-256 of the **one** outbound request `ID` the browser is
//! carrying. The raw `ID` is never stored (T-383); the response that answers it
//! is consumed once on the X6 two-layer arbiter and must come from the SP the
//! request went to.
//!
//! The queue holds participant row ids, not copies of their `NameID`s: the
//! personal data lives in one table, and the rows it names are deleted when the
//! chain ends.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// How long a logout run lives: ten minutes (D-38, D-39).
///
/// It is the life of the replay guard on a `LogoutRequest` `ID`, so it must
/// exceed the window an `IssueInstant` is accepted in (five minutes back, the
/// clock-skew allowance forward) — which it does with margin — and it bounds how
/// long a stranded chain (an SP that never answers) holds its rows.
pub const SAML_LOGOUT_RUN_TTL_SECS: i64 = 600;

/// The most service providers one logout run tells (D-38, D-39). A session that
/// took part in more ends the run `PartialLogout`.
pub const MAX_LOGOUT_RUN_PARTICIPANTS: usize = 32;

/// What the SSO endpoint records before it signs an assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSamlSpSession {
    /// The tenant of the request path.
    pub tenant_id: Uuid,
    /// The AXIAM session the assertion is for.
    pub session_id: Uuid,
    /// The session's user.
    pub user_id: Uuid,
    /// The registered service provider.
    pub sp_id: Uuid,
    /// The SP's entity id, as registered (it is immutable, D-37).
    pub sp_entity_id: String,
    /// The `NameID` value the SP is given.
    pub name_id: String,
    /// The `NameID` format URN the SP is given.
    pub name_id_format: String,
    /// A candidate `SessionIndex`: 32 CSPRNG bytes, base64url without padding.
    /// Used only when the session has no row for this SP yet; a second sign-on
    /// to the same SP in one session keeps the first index (SAML Core §2.7.2.1
    /// allows it).
    pub session_index: String,
    /// When the session ends; the row never outlives it.
    pub expires_at: DateTime<Utc>,
}

/// A stored participant row.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamlSpSession {
    /// Record id.
    pub id: Uuid,
    /// See [`NewSamlSpSession::tenant_id`].
    pub tenant_id: Uuid,
    /// See [`NewSamlSpSession::session_id`].
    pub session_id: Uuid,
    /// See [`NewSamlSpSession::user_id`].
    pub user_id: Uuid,
    /// See [`NewSamlSpSession::sp_id`].
    pub sp_id: Uuid,
    /// See [`NewSamlSpSession::sp_entity_id`].
    pub sp_entity_id: String,
    /// See [`NewSamlSpSession::name_id`].
    pub name_id: String,
    /// See [`NewSamlSpSession::name_id_format`].
    pub name_id_format: String,
    /// The `SessionIndex` the SP was given.
    pub session_index: String,
    /// When the row was first written.
    pub created_at: DateTime<Utc>,
    /// See [`NewSamlSpSession::expires_at`].
    pub expires_at: DateTime<Utc>,
}

// A participant row names a person's `NameID` (an email address at an
// `emailAddress` SP). Never formatted, even by a stray `{:?}`.
impl std::fmt::Debug for SamlSpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SamlSpSession")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("session_id", &self.session_id)
            .field("sp_id", &self.sp_id)
            .field("name_id", &"[REDACTED]")
            .field("session_index", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Who started a logout run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamlLogoutInitiator {
    /// A service provider, by a verified `LogoutRequest`.
    ServiceProvider(Uuid),
    /// The session's holder, through the IdP-initiated trigger.
    Idp,
}

/// What claims a run: the replay guard of a `LogoutRequest`, or a fresh
/// IdP-initiated run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSamlLogoutRun {
    /// The tenant of the request path.
    pub tenant_id: Uuid,
    /// Who started it.
    pub initiator: SamlLogoutInitiator,
    /// The initiating SP's `LogoutRequest` `ID`, for the final response's
    /// `InResponseTo`; `None` for an IdP-initiated run. Already checked as a
    /// request id.
    pub initiator_request_id: Option<String>,
    /// The initiating SP's `RelayState` (at most 80 bytes), echoed to that SP
    /// only.
    pub initiator_relay_state: Option<String>,
}

/// A stored logout run, as the chain needs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamlLogoutRun {
    /// Record id.
    pub id: Uuid,
    /// The tenant.
    pub tenant_id: Uuid,
    /// The user whose sessions ended; `None` until the run is planned.
    pub user_id: Option<Uuid>,
    /// The initiating service provider; `None` for an IdP-initiated run.
    pub initiator_sp_id: Option<Uuid>,
    /// See [`NewSamlLogoutRun::initiator_request_id`].
    pub initiator_request_id: Option<String>,
    /// See [`NewSamlLogoutRun::initiator_relay_state`].
    pub initiator_relay_state: Option<String>,
    /// The participant rows still to be told, next first.
    pub queue: Vec<Uuid>,
    /// The AXIAM sessions the run ended (their participant rows go with it).
    pub session_ids: Vec<Uuid>,
    /// The service provider the outbound request in the browser went to.
    pub current_sp_id: Option<Uuid>,
    /// Whether any part of the logout is known not to have completed.
    pub partial: bool,
    /// How many AXIAM sessions the run ended.
    pub sessions_ended: u32,
    /// How many service providers have been sent a `LogoutRequest`.
    pub sps_told: u32,
    /// When the run was claimed.
    pub created_at: DateTime<Utc>,
    /// When it expires (and, after that, is swept).
    pub expires_at: DateTime<Utc>,
}

/// What a run's plan sets once the sessions have been resolved and revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlLogoutPlan {
    /// The user whose sessions ended.
    pub user_id: Uuid,
    /// The participant rows to tell, in order. At most
    /// [`MAX_LOGOUT_RUN_PARTICIPANTS`].
    pub queue: Vec<Uuid>,
    /// The sessions ended.
    pub session_ids: Vec<Uuid>,
    /// Partial already: the cap was exceeded.
    pub partial: bool,
}

/// Where the chain stands after a hop: what is still queued and which request
/// the browser now carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlLogoutProgress {
    /// The participant rows still to be told.
    pub queue: Vec<Uuid>,
    /// The SP the outbound request goes to and the SHA-256 (hex) of its `ID`;
    /// `None` when nothing is outstanding (the chain is ending).
    pub outbound: Option<(Uuid, String)>,
    /// Whether the run is now partial.
    pub partial: bool,
    /// SPs sent a request so far.
    pub sps_told: u32,
}
