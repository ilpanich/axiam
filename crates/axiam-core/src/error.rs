//! Error types for the AXIAM system.

use thiserror::Error;

/// Every variant carries only owned text, so an error can be cloned: one
/// outcome handed to several waiters (the CRL re-sign shared by every request
/// for the same CA's list, #616) is one value, not one per waiter.
#[derive(Debug, Clone, Error)]
pub enum AxiamError {
    #[error("Entity not found: {entity} with id {id}")]
    NotFound { entity: String, id: String },

    #[error("Entity already exists: {entity}")]
    AlreadyExists { entity: String },

    /// The request is well-formed and authorized, but the resource is not in a
    /// state that permits it — a precondition the caller can satisfy and retry.
    ///
    /// Distinct from [`Self::Validation`] (400: the *request* is wrong, and
    /// resending it unchanged will always fail) and from
    /// [`Self::AlreadyExists`] (409, but specifically a uniqueness violation).
    /// Maps to `409 Conflict`, which `sdks/CONTRACT.md` §27.4 already binds to
    /// `ConflictError` and marks non-retriable — correct here: the caller must
    /// *do something else first*, not resend.
    #[error("{reason}")]
    Conflict { reason: String },

    #[error("Authentication failed: {reason}")]
    AuthenticationFailed { reason: String },

    #[error("Authorization denied: {reason}")]
    AuthorizationDenied {
        reason: String,
        /// The action being checked (e.g. `"users:create"`), when known at
        /// the denial site. Surfaced to clients so SDKs can parse it from
        /// the 403 response body (SDK-Q02).
        action: Option<String>,
        /// The resource id being checked, when known and not the
        /// "global" nil-UUID sentinel. Surfaced to clients alongside
        /// `action` (SDK-Q02).
        resource_id: Option<String>,
    },

    #[error("Validation error: {message}")]
    Validation { message: String },

    #[error("Password policy violation: {message}")]
    PasswordPolicy { message: String },

    #[error("Database error: {0}")]
    Database(String),

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error("Email delivery failed: {0}")]
    EmailDelivery(String),

    #[error("Email configuration error: {0}")]
    EmailConfig(String),

    #[error("Webhook delivery failed: {0}")]
    WebhookDelivery(String),

    #[error("Tenant context missing or invalid")]
    TenantContext,

    #[error("Rate limit exceeded")]
    RateLimited,

    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    /// The tenant requires OPAQUE, so password login is refused
    /// (`OpaqueMode::Required`).
    ///
    /// Its own variant rather than an `AuthenticationFailed` because it is the
    /// opposite kind of answer: nothing about the caller's credentials was
    /// wrong, they used the wrong *protocol*. A client that cannot distinguish
    /// the two would show "invalid username or password" to a user whose
    /// password is perfectly good, and an SDK could not auto-switch to the
    /// OPAQUE endpoints. It reveals only a tenant-level policy, never anything
    /// about which accounts exist — see `models::opaque::OpaqueMode::Required`.
    #[error("this tenant requires OPAQUE authentication")]
    OpaqueRequired,

    /// A self-service action would take the caller's own account below the MFA
    /// floor their tenant enforces (`MfaPolicy::mfa_enforced`, T-267).
    ///
    /// Its own variant rather than an [`Self::AuthorizationDenied`] for the
    /// reason [`Self::OpaqueRequired`] above is its own: nothing about the
    /// caller's permissions is wrong. They hold every permission the action
    /// needs — it is their own account — and the refusal is a *policy* their
    /// administrator set, which only their administrator can act against. A
    /// client that could not tell the two apart would show "forbidden" where
    /// the true sentence is "your organization requires MFA; ask an
    /// administrator to reset it", and `authorization_denied` carries an
    /// `action`/`resource_id` pair that would be meaningless here.
    ///
    /// It reveals only a tenant-level policy the caller is already subject to
    /// and can observe from their own login flow, and nothing about any other
    /// account.
    #[error(
        "your tenant requires multi-factor authentication; an administrator must reset it for you"
    )]
    MfaEnforced,

    /// A write that lost an optimistic-concurrency race in the datastore and
    /// stayed lost after every retry `retry_on_write_conflict` was willing to
    /// spend on it (T-262).
    ///
    /// Maps to `503 Service Unavailable` with `Retry-After: 1`, and to gRPC
    /// `UNAVAILABLE`. It is a statement about the **server** — come back in a
    /// moment — which is what makes `503` right and the two nearby answers
    /// wrong:
    ///
    /// - `500`, which is what this was, tells a client to stop when the
    ///   correct advice is to retry. An IdP driving SCIM provisioning (Okta,
    ///   Entra) reads it as a failed sync and re-sends the whole record.
    /// - `409`, which [`Self::Conflict`] and [`Self::AlreadyExists`] keep,
    ///   means "your request conflicts with the resource's state" — SCIM
    ///   RFC 7644 §3.12 — and a caller who believes that will change the
    ///   request rather than resend it, which cannot help here.
    ///
    /// **It carries no payload.** The engine's own words ("Transaction write
    /// conflict…") belong in the log, where `DbError::Conflict` keeps them,
    /// and nowhere near a response body.
    #[error("the datastore is busy; retry this request")]
    WriteContention,

    /// A refusal of a network route (segment, reply profile, policy, or a
    /// network role write), typed so the REST layer maps it to its `409`
    /// `reason_code` without reading the sentence back.
    ///
    /// `Display` is the exact sentence the wire carries; `409` like
    /// [`Self::Conflict`] and [`Self::AlreadyExists`].
    #[error("{0}")]
    Network(NetworkConflict),

    #[error("SAML assertion replay detected")]
    ReplayDetected,

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type AxiamResult<T> = Result<T, AxiamError>;

/// Why a network write was refused with `409`.
///
/// Raised at the repository boundary, from the markers the write transactions
/// `THROW` and the checks the repositories make themselves; the REST layer maps
/// each variant to its `reason_code` in one place. `Display` is the sentence
/// the response carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkConflict {
    /// The segment's version is not the one the writer read.
    StaleSegment,
    /// The reply profile's version is not the one the writer read.
    StaleProfile,
    /// The tenant network policy's version is not the one the writer read.
    StalePolicy,
    /// A reply profile was written on the segment between the gate's read and
    /// the write.
    PlacementRaced,
    /// The role changed between the gate's read and the write; `what_landed`
    /// says what.
    StaleRole { what_landed: String },
    /// The new `filter_ids` would leave the segment's reply profile outside its
    /// envelope. `segment_id` and `filter_id` name the profile and the
    /// `filter_id` it uses, once the caller has looked them up.
    StrandsProfile {
        segment_id: Option<uuid::Uuid>,
        filter_id: Option<String>,
    },
    /// The segment still has child resources.
    HasChildren,
    /// The segment's site was removed while the segment was being written.
    SiteGone,
    /// The site already has a segment with this `vlan_id`.
    DuplicateVlan,
    /// The site already has a segment with this rank.
    DuplicateRank,
    /// The site already has a segment of this name.
    DuplicateName,
    /// The segment already has a reply profile.
    ProfileExists,
}

impl NetworkConflict {
    /// `true` for a uniqueness clash, which answers the `already_exists` slug;
    /// every other variant answers `conflict`.
    #[must_use]
    pub fn is_uniqueness(&self) -> bool {
        matches!(
            self,
            Self::DuplicateVlan | Self::DuplicateRank | Self::DuplicateName | Self::ProfileExists
        )
    }

    /// `true` when the write lost to another one: read again and retry.
    #[must_use]
    pub fn is_stale(&self) -> bool {
        matches!(
            self,
            Self::StaleSegment
                | Self::StaleProfile
                | Self::StalePolicy
                | Self::PlacementRaced
                | Self::StaleRole { .. }
        )
    }
}

impl std::fmt::Display for NetworkConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StaleSegment => f.write_str(
                "the network segment changed since it was read; read it again and retry",
            ),
            Self::StaleProfile => {
                f.write_str("the reply profile changed since it was read; read it again and retry")
            }
            Self::StalePolicy => {
                f.write_str("the network policy changed since it was read; read it again and retry")
            }
            Self::PlacementRaced => f.write_str(
                "the network segment changed since it was read (a reply profile was written on \
                 it); read it again and retry",
            ),
            Self::StaleRole { what_landed } => write!(
                f,
                "the role changed since it was read ({what_landed}); read it again and retry"
            ),
            Self::StrandsProfile {
                segment_id: Some(segment_id),
                filter_id: Some(filter_id),
            } => write!(
                f,
                "the segment's reply profile {segment_id} uses filter_id '{filter_id}', which \
                 the new filter_ids remove; change or delete the profile first"
            ),
            Self::StrandsProfile {
                segment_id: Some(segment_id),
                filter_id: None,
            } => write!(
                f,
                "the new filter_ids would leave the segment's reply profile {segment_id} \
                 outside its envelope; change or delete the profile first"
            ),
            Self::StrandsProfile { .. } => f.write_str(
                "the new filter_ids would leave the segment's reply profile outside its \
                 envelope; change or delete the profile first",
            ),
            Self::HasChildren => f.write_str("the network segment has child resources"),
            Self::SiteGone => f.write_str(
                "the network site was removed while the segment was being written; retry",
            ),
            Self::DuplicateVlan => f.write_str(
                "Entity already exists: network_segment: the site already has a segment with \
                 this vlan_id",
            ),
            Self::DuplicateRank => f.write_str(
                "Entity already exists: network_segment: the site already has a segment with \
                 this rank",
            ),
            Self::DuplicateName => f.write_str(
                "Entity already exists: network_segment: the site already has a segment of \
                 this name",
            ),
            Self::ProfileExists => f.write_str("Entity already exists: reply_profile"),
        }
    }
}
