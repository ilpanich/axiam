//! Session domain model.
//!
//! # Authentication evidence (X7.2, plan §4.3)
//!
//! A session used to record only *when the row was written*
//! ([`Session::created_at`]) — and refresh rotation writes a new row on every
//! refresh, so that timestamp resets several times an hour. It therefore
//! cannot stand in for the OpenID Connect `auth_time`, which asserts when the
//! **end user last authenticated**: an RP that sent `max_age=60` and received
//! a token minted from a week-old login that happened to be refreshed a minute
//! ago has been told a freshness guarantee it did not get.
//!
//! So the authentication event is recorded where it happens, once, and
//! survives rotation:
//!
//! | Field | Written by | Copied across refresh rotation |
//! |---|---|---|
//! | [`Session::authenticated_at`] | the login that created the session | **yes** |
//! | [`Session::amr`] | the same login, from the factors it actually verified | **yes** |
//! | [`Session::browser_token_hash`] | the OP browser session (W3) | **yes** |
//!
//! Nothing in this wave *reads* the evidence into a token. The claims
//! (`auth_time`, `acr`, `amr`) are emitted for no client at all — see
//! `axiam_auth::token::IdTokenEvidence` — because emitting them is the honour
//! lane, which is a later wave. What lands here is the record, so that when
//! the lane opens there is a truthful answer to give.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An authentication method reference (RFC 8176), as recorded on a session.
///
/// A closed enum rather than a free string, for two reasons. The values are
/// evidence a later wave turns into an `acr` claim, and a claim derived from
/// `"otp "` or `"passkey"` is one that silently never satisfies the ACR the
/// operator configured — a typo at one of the five login call sites would be
/// discovered by a relying party rather than by the compiler. And a closed set
/// is the only one that can be mapped exhaustively: `acr_for` (a later wave)
/// must answer for every value that can reach it.
///
/// Only the values AXIAM can actually *prove* are modelled. Anything a stored
/// row carries that is not one of them decodes to nothing at all
/// ([`Amr::from_wire`] returns `None` and the decoder drops it), which is the
/// strict direction: less evidence can only ever lower the assurance a session
/// is credited with, never raise it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Amr {
    /// RFC 8176 `pwd` — a password (or equivalent shared secret) was verified.
    #[serde(rename = "pwd")]
    Pwd,
    /// RFC 8176 `otp` — a one-time passcode, i.e. AXIAM's TOTP second factor.
    #[serde(rename = "otp")]
    Otp,
    /// RFC 8176 `mfa` — more than one distinct factor was verified in this
    /// authentication. Recorded *in addition to* the factors themselves, as
    /// RFC 8176 §2 intends.
    #[serde(rename = "mfa")]
    Mfa,
    /// RFC 8176 `hwk` — proof of possession of a hardware-secured key, i.e. a
    /// WebAuthn authenticator.
    #[serde(rename = "hwk")]
    Hwk,
    /// RFC 8176 `swk` — proof of possession of a software-secured key.
    #[serde(rename = "swk")]
    Swk,
    /// RFC 8176 `user` — user verification (PIN, biometric) was performed by
    /// the authenticator, not merely user *presence*.
    #[serde(rename = "user")]
    User,
    /// RFC 8176 `x509` — an X.509 certificate was verified (mTLS).
    #[serde(rename = "x509")]
    X509,
    /// RFC 8176 `fed` — the authentication was performed by an upstream
    /// identity provider and AXIAM verified its assertion.
    #[serde(rename = "fed")]
    Fed,
}

impl Amr {
    /// The RFC 8176 spelling, which is what is stored and what an `amr` claim
    /// would carry.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pwd => "pwd",
            Self::Otp => "otp",
            Self::Mfa => "mfa",
            Self::Hwk => "hwk",
            Self::Swk => "swk",
            Self::User => "user",
            Self::X509 => "x509",
            Self::Fed => "fed",
        }
    }

    /// Parse a stored value. `None` for anything unrecognised — see the type
    /// docs for why an unknown value is dropped rather than kept.
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw.trim() {
            "pwd" => Some(Self::Pwd),
            "otp" => Some(Self::Otp),
            "mfa" => Some(Self::Mfa),
            "hwk" => Some(Self::Hwk),
            "swk" => Some(Self::Swk),
            "user" => Some(Self::User),
            "x509" => Some(Self::X509),
            "fed" => Some(Self::Fed),
            _ => None,
        }
    }

    /// Decode a stored list, dropping values this build does not know.
    ///
    /// The drop is deliberate and is the whole reason this is not a `TryFrom`:
    /// a row written by a newer binary must still be *readable* by an older
    /// one, and the older one must not credit a session with evidence it
    /// cannot interpret.
    pub fn decode_list<S: AsRef<str>>(raw: &[S]) -> Vec<Self> {
        raw.iter()
            .filter_map(|v| Self::from_wire(v.as_ref()))
            .collect()
    }

    /// Render a list for storage.
    pub fn encode_list(values: &[Self]) -> Vec<String> {
        values.iter().map(|v| v.as_str().to_owned()).collect()
    }
}

/// What a login proved, and when.
///
/// Passed to `AuthService::create_session_and_tokens` by each of the five
/// sign-in paths, so that the choke point every browser login funnels through
/// records the event rather than inferring it.
///
/// [`Self::authenticated_at`] is separate from "now" because a federated login
/// did not happen now: the upstream identity provider may have authenticated
/// the user hours ago and be replaying a long-lived SSO session. Stamping the
/// local clock there would overstate freshness, which is the one direction
/// this record must never err in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationEvidence {
    /// When the end user actually authenticated.
    pub authenticated_at: DateTime<Utc>,
    /// Which methods were verified, RFC 8176 style.
    pub amr: Vec<Amr>,
}

impl AuthenticationEvidence {
    /// Evidence for an authentication that just happened here.
    pub fn now(amr: Vec<Amr>) -> Self {
        Self {
            authenticated_at: Utc::now(),
            amr,
        }
    }

    /// Evidence for an authentication that happened elsewhere, at a time the
    /// upstream asserted.
    ///
    /// `upstream` is `None` when the assertion carried no authentication
    /// instant (a plain OAuth2 provider has no ID token; a SAML IdP need not
    /// send `AuthnInstant`); the fallback is the moment AXIAM verified the
    /// assertion, per plan §4.3.
    pub fn upstream(upstream: Option<DateTime<Utc>>, amr: Vec<Amr>) -> Self {
        Self {
            authenticated_at: upstream.unwrap_or_else(Utc::now),
            amr,
        }
    }
}

/// An authenticated session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    /// X7.2 — when the end user authenticated, which is **not**
    /// [`Self::created_at`] on a session produced by refresh rotation.
    ///
    /// A row written before schema v55 decodes to its `created_at`: the
    /// closest truthful answer available, and never later than the real
    /// authentication, so it can only understate freshness.
    #[serde(default = "epoch")]
    pub authenticated_at: DateTime<Utc>,
    /// X7.2 — the methods [`Self::authenticated_at`] refers to.
    ///
    /// Empty for a row written before schema v55, and for any login path that
    /// recorded none. An empty list is the floor: it satisfies no assurance
    /// level above the weakest.
    #[serde(default)]
    pub amr: Vec<Amr>,
    /// W3 — SHA-256 of the OP browser-session token this session is bound to.
    ///
    /// The column exists from schema v55; W3 is what writes it and what indexes
    /// it (v56). It is the stored half of the `axiam_op_session` cookie: the
    /// browser holds 256 random bits, the row holds their digest, and
    /// `/oauth2/authorize` resolves one to the other for a client registered
    /// `browser_sso`.
    ///
    /// `None` for every session created before W3, for every session created by
    /// a path that is not a browser login, and for every deployment that never
    /// registers a `browser_sso` client — the hash is written unconditionally
    /// at login, but no client consults it unless it opted in.
    ///
    /// **Copied across refresh rotation**, like [`Self::authenticated_at`] and
    /// [`Self::amr`] and for a related reason: rotation replaces the row, and a
    /// browser whose OP cookie stopped resolving because its access token was
    /// renewed would be silently signed out of the authorization endpoint
    /// alone.
    #[serde(default)]
    pub browser_token_hash: Option<String>,
}

/// Serde fallback for [`Session::authenticated_at`] on a payload that predates
/// the field.
///
/// The database decoder substitutes `created_at`, which is strictly better;
/// this exists only so that a serialized `Session` from an older build
/// deserializes at all, and it deliberately yields the *oldest* representable
/// instant so nothing can read it as fresh.
fn epoch() -> DateTime<Utc> {
    DateTime::UNIX_EPOCH
}

/// Input for creating a session.
#[derive(Debug, Clone)]
pub struct CreateSession {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: DateTime<Utc>,
    /// X7.2 — see [`Session::authenticated_at`].
    ///
    /// Refresh rotation **copies** this from the session it consumed instead
    /// of stamping the clock: a refresh is not an authentication event, and a
    /// freshness claim that resets on every refresh is worse than none.
    pub authenticated_at: DateTime<Utc>,
    /// X7.2 — see [`Session::amr`]. Copied across rotation for the same
    /// reason.
    pub amr: Vec<Amr>,
    /// W3 — see [`Session::browser_token_hash`].
    ///
    /// `None` on every path that is not a browser sign-in, and on rotation it
    /// carries the consumed session's value rather than a fresh one: the cookie
    /// in the browser did not change, so neither may the digest it is matched
    /// against.
    pub browser_token_hash: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_amr_value_round_trips_through_its_rfc_8176_spelling() {
        for value in [
            Amr::Pwd,
            Amr::Otp,
            Amr::Mfa,
            Amr::Hwk,
            Amr::Swk,
            Amr::User,
            Amr::X509,
            Amr::Fed,
        ] {
            assert_eq!(Amr::from_wire(value.as_str()), Some(value));
            assert_eq!(
                serde_json::to_value(value).unwrap(),
                serde_json::json!(value.as_str()),
                "the JSON spelling must be the RFC 8176 one"
            );
        }
    }

    /// An unknown stored value is dropped, not guessed at and not an error:
    /// less evidence lowers assurance, which is the safe direction.
    #[test]
    fn an_unknown_amr_value_is_dropped_rather_than_kept() {
        let decoded = Amr::decode_list(&["pwd", "quantum-telepathy", "mfa"]);
        assert_eq!(decoded, vec![Amr::Pwd, Amr::Mfa]);
    }

    #[test]
    fn encode_and_decode_are_inverse_for_known_values() {
        let values = vec![Amr::Pwd, Amr::Hwk, Amr::User];
        assert_eq!(
            Amr::decode_list(&Amr::encode_list(&values)),
            values,
            "storage round trip must preserve order and content"
        );
    }

    /// The federated case the plan calls out: an upstream that authenticated
    /// the user hours ago must not have its session dated "now".
    #[test]
    fn upstream_evidence_prefers_the_upstream_instant() {
        let long_ago = Utc::now() - chrono::Duration::hours(9);
        let evidence = AuthenticationEvidence::upstream(Some(long_ago), vec![Amr::Fed]);
        assert_eq!(evidence.authenticated_at, long_ago);

        let none = AuthenticationEvidence::upstream(None, vec![Amr::Fed]);
        assert!(
            (Utc::now() - none.authenticated_at).num_seconds() < 5,
            "with no upstream instant the fallback is the verification moment"
        );
    }

    /// A `Session` serialized by a build that predates the evidence fields
    /// must still deserialize — and must not read as freshly authenticated.
    #[test]
    fn a_pre_v55_session_payload_decodes_to_the_strict_defaults() {
        let legacy = serde_json::json!({
            "id": Uuid::nil(),
            "tenant_id": Uuid::nil(),
            "user_id": Uuid::nil(),
            "token_hash": "hash",
            "ip_address": null,
            "user_agent": null,
            "expires_at": "2030-01-01T00:00:00Z",
            "created_at": "2026-01-01T00:00:00Z",
        });
        let session: Session = serde_json::from_value(legacy).unwrap();
        assert_eq!(session.authenticated_at, DateTime::UNIX_EPOCH);
        assert!(session.amr.is_empty());
        assert!(session.browser_token_hash.is_none());
    }
}
