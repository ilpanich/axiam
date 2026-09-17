//! Initial access tokens for RFC 7591 dynamic client registration (T21.4).
//!
//! RFC 7591 §1.2 names two profiles for the registration endpoint: **open**,
//! where anybody may register, and **protected**, where the request carries an
//! "initial access token" the authorization server issued out of band. This is
//! that token, and it exists because the difference between the two profiles
//! is the difference between a deployment that lets Claude Code register
//! itself and a deployment that lets anybody on the internet write a row.
//!
//! Three properties, and each one is the answer to a question the SCIM
//! provisioning token (`models::scim_token`) answers the other way — worth
//! stating side by side, because the two are the same shape and not the same
//! credential:
//!
//! 1. **Single use.** A SCIM token authenticates an ongoing integration; this
//!    one authorises exactly one registration. It is consumed by the request
//!    that succeeds, so a token that leaks after use is a token that does
//!    nothing.
//! 2. **Short lived.** Days, not a year. An administrator mints one when they
//!    are about to hand it to somebody, not to leave in a console.
//! 3. **It carries no identity.** A SCIM token resolves to a tenant user whose
//!    RBAC decides everything. This one resolves to a *tenant* and nothing
//!    else: what the registration may ask for is the tenant's
//!    `dcr_allowed_scopes` and `external_client_allowed_resources`, never the
//!    minting administrator's own authority. A stolen initial access token can
//!    therefore create a client and cannot do anything an anonymous
//!    registration on the same tenant could not.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Prefix on every issued handle.
///
/// Load-bearing for the reason `SCIM_TOKEN_PREFIX` is: a credential that gets
/// pasted into a terminal, a chat message or an MCP client's configuration
/// will eventually be pasted somewhere it is committed, and a fixed greppable
/// prefix is what lets a secret scanner or an operator with `grep` find it.
pub const REGISTRATION_TOKEN_PREFIX: &str = "axiam_dcr_";

/// Entropy behind the handle. 256 bits, as every other opaque bearer handle in
/// the system (refresh tokens, device codes, UMA tickets, SCIM tokens).
pub const REGISTRATION_TOKEN_ENTROPY_BYTES: usize = 32;

/// Default lifetime, in hours, when the minting request names none.
///
/// Twenty-four hours: an administrator mints one of these in the same sitting
/// as they hand it over. A token that outlives the conversation it was created
/// for is a token nobody remembers issuing.
pub const DEFAULT_REGISTRATION_TOKEN_TTL_HOURS: u32 = 24;

/// The longest lifetime the server will mint.
///
/// A week. Past that the credential is not an "initial access token" any more,
/// it is a shared secret for the registration endpoint — and a deployment that
/// wants one of those wants `dynamic_registration: anonymous` with a host
/// glob, which is at least visible as the decision it is.
pub const MAX_REGISTRATION_TOKEN_TTL_HOURS: u32 = 24 * 7;

/// An initial access token as stored. The plaintext handle is **not** a field:
/// only its hash is ever persisted, and the plaintext is returned exactly once
/// at creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2RegistrationToken {
    /// Row identity.
    pub id: Uuid,
    /// The tenant this token may register a client in. The only authority it
    /// carries.
    pub tenant_id: Uuid,
    /// Operator-facing label, e.g. `"mcp-inspector-demo"`, so a tenant with
    /// several outstanding tokens can tell them apart.
    pub name: String,
    /// SHA-256 of the handle, hex-encoded — the same treatment
    /// `axiam_auth::token::hash_refresh_token` gives a refresh token.
    pub token_hash: String,
    /// The administrator who minted it. Recorded for the audit trail: a
    /// registration that arrives on this token is attributable to the person
    /// who handed it out.
    pub created_by: Uuid,
    /// When it stops being usable, whether or not it was ever spent.
    pub expires_at: DateTime<Utc>,
    /// When it was spent.
    ///
    /// A field rather than a delete, because a spent token is evidence: an
    /// operator asking "was this handle ever used, and when" gets an answer,
    /// and reaches the administrator who handed it out through
    /// [`Self::created_by`]. A row that deleted itself on use would answer
    /// neither question.
    pub used_at: Option<DateTime<Utc>>,
    /// The `client_id` the spending registration produced — **reserved, and
    /// always `None` in this build.**
    ///
    /// The column exists because the shape is right and RFC 7592 (deferred)
    /// will want it, and it is left unwritten because nothing can write it
    /// truthfully: the token must be spent *before* the client is created (the
    /// single-use guarantee depends on that order), so no `client_id` exists at
    /// the moment there is a row to put it in. Writing a placeholder and
    /// replacing it afterwards would leave the placeholder behind on any
    /// failure, in a list an operator reads.
    ///
    /// The link a person actually needs is in the audit log, which records
    /// `oauth2.client_registered` with the `client_id`, the source address and
    /// the time, and is append-only.
    pub used_by_client_id: Option<String>,
    /// Row creation time.
    pub created_at: DateTime<Utc>,
}

impl OAuth2RegistrationToken {
    /// Whether this token may still authorise a registration, as of `now`.
    ///
    /// Spent and expired are checked together and answer the same way, because
    /// the wire response does not distinguish them either: a caller probing
    /// handles must not learn which arm rejected them.
    pub fn is_usable(&self, now: DateTime<Utc>) -> bool {
        self.used_at.is_none() && self.expires_at > now
    }
}

/// Input for minting a token. `token_hash` is computed by the caller so this
/// type never holds the plaintext.
#[derive(Debug, Clone)]
pub struct CreateOAuth2RegistrationToken {
    /// The tenant the token may register into.
    pub tenant_id: Uuid,
    /// Operator-facing label.
    pub name: String,
    /// SHA-256 of the handle, hex-encoded.
    pub token_hash: String,
    /// The minting administrator.
    pub created_by: Uuid,
    /// When it stops being usable.
    pub expires_at: DateTime<Utc>,
}
