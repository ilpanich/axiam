//! Outbound SCIM provisioning: the target registry, the link rows and the
//! per-target delivery state (G-6, T23.6.1; decisions D-57 and D-58).
//!
//! A tenant registers downstream SCIM 2.0 service providers ([`ScimTarget`]);
//! AXIAM pushes user and group lifecycle changes to them. This module is the
//! plain data of that registry. What is pushed, and how, is the deliverer's
//! (`axiam-scim`, T23.6.2); storage is [`crate::repository::ScimTargetRepository`],
//! [`crate::repository::ScimTargetLinkRepository`] and
//! [`crate::repository::ScimTargetStateRepository`].
//!
//! # Three tables, three writers
//!
//! * **The target** ([`ScimTarget`]) is written by an administrator only.
//!   Its update is conditional on the `updated_at` the administrator read
//!   ([`ScimTargetUpdate::expected_updated_at`]), as the SSF stream's is.
//! * **The link rows** ([`ScimTargetLink`]) map an AXIAM user or group to the
//!   downstream resource AXIAM created or adopted. They hold ids and a digest,
//!   never an attribute of a person, so they can outlive an erasure until the
//!   downstream `DELETE` has been sent.
//! * **The delivery state** ([`ScimTargetState`]) is written by the deliverer
//!   and the reconciliation job with atomic increments and plain sets, never
//!   by read-modify-write, and **never touches the target row**.
//!
//! # No credential in a read model
//!
//! The bearer token or OAuth2 client secret is a credential **to the
//! downstream service provider**. It is encrypted at rest by the repository and
//! reaches a caller only through
//! [`crate::repository::ScimTargetRepository::decrypt_credential`], the single
//! path to the plaintext, which only the deliverer calls. [`ScimTarget`] holds
//! no field for it; [`NewScimTarget`] and [`ScimTargetUpdate`], which carry it
//! on the way in, redact it from `Debug`.
//!
//! # The credential is bound to its URL
//!
//! A write that changes the URL the credential is sent to — `base_url` of a
//! bearer target, `token_url` of a client-credentials target, and that
//! target's `base_url` too, where every access token the secret yields is sent
//! (W5 F4 review, T-409) — or that switches the authentication kind, must
//! supply the credential in the same write
//! ([`ScimTargetUpdate::credential`]); the repository refuses it otherwise
//! with `Validation`. Without that, an administrator who may edit a target
//! but not read its credential could aim the stored one at a host they control.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

/// How AXIAM authenticates to the downstream service provider, without the
/// credential itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScimTargetAuth {
    /// A static bearer token, sent as `Authorization: Bearer <token>` to
    /// `base_url`.
    Bearer,
    /// OAuth2 client credentials: AXIAM obtains an access token from
    /// `token_url` with its client id and a stored client secret.
    #[serde(rename = "oauth2_client_credentials")]
    OAuth2ClientCredentials {
        /// The token endpoint the client secret is sent to.
        token_url: String,
        /// The OAuth2 client id.
        client_id: String,
        /// The scope requested, if any.
        scope: Option<String>,
    },
}

impl ScimTargetAuth {
    /// The spelling stored in the database and used on the wire for the kind.
    #[must_use]
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::Bearer => "bearer",
            Self::OAuth2ClientCredentials { .. } => "oauth2_client_credentials",
        }
    }
}

/// Which users a target provisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "type", content = "group_ids", rename_all = "snake_case")]
pub enum ScimTargetScope {
    /// Every user of the tenant.
    AllUsers,
    /// Users who are direct members of any listed group.
    Groups(Vec<Uuid>),
}

impl ScimTargetScope {
    /// The spelling stored in the database for the kind.
    #[must_use]
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::AllUsers => "all_users",
            Self::Groups(_) => "groups",
        }
    }
}

/// Which AXIAM attribute becomes the downstream `userName`. The mapping is a
/// fixed attribute set, not a mapping language (D-57).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UserNameSource {
    /// The AXIAM username. The default.
    #[default]
    Username,
    /// The user's email address.
    Email,
}

impl UserNameSource {
    /// The spelling stored in the database and used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Email => "email",
        }
    }

    /// Parse the stored spelling.
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "username" => Some(Self::Username),
            "email" => Some(Self::Email),
            _ => None,
        }
    }
}

/// What happens downstream to a user who falls out of scope or is no longer
/// active. Erasure always deletes, whatever this says.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeprovisionPolicy {
    /// `PATCH active=false`. The default.
    #[default]
    Deactivate,
    /// `DELETE`.
    Delete,
}

impl DeprovisionPolicy {
    /// The spelling stored in the database and used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deactivate => "deactivate",
            Self::Delete => "delete",
        }
    }

    /// Parse the stored spelling.
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "deactivate" => Some(Self::Deactivate),
            "delete" => Some(Self::Delete),
            _ => None,
        }
    }
}

/// One registered downstream SCIM service provider, as stored and as read back.
///
/// Carries no credential: see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimTarget {
    /// The target id. Also the `target_id` of its outbound messages, link rows
    /// and delivery state.
    pub id: Uuid,
    /// The owning tenant.
    pub tenant_id: Uuid,
    /// A human name.
    pub name: String,
    /// The SCIM service root of the downstream (e.g. `https://idp.example/scim/v2`).
    pub base_url: String,
    /// Whether AXIAM pushes to it. A disabled target receives nothing.
    pub enabled: bool,
    /// How AXIAM authenticates to it.
    pub auth: ScimTargetAuth,
    /// Which users it provisions.
    pub scope: ScimTargetScope,
    /// Whether groups are pushed too: every group for
    /// [`ScimTargetScope::AllUsers`], the listed ones otherwise.
    pub push_groups: bool,
    /// Which attribute becomes `userName`.
    pub user_name_from: UserNameSource,
    /// What happens to a user who leaves scope or is no longer active.
    pub deprovision: DeprovisionPolicy,
    /// When the target was registered.
    pub created_at: DateTime<Utc>,
    /// When it was last written. The version an administrator's update is
    /// conditional on.
    pub updated_at: DateTime<Utc>,
}

/// The write input for registering a target.
#[derive(Clone)]
pub struct NewScimTarget {
    /// See [`ScimTarget::tenant_id`].
    pub tenant_id: Uuid,
    /// See [`ScimTarget::name`].
    pub name: String,
    /// See [`ScimTarget::base_url`].
    pub base_url: String,
    /// See [`ScimTarget::enabled`].
    pub enabled: bool,
    /// See [`ScimTarget::auth`].
    pub auth: ScimTargetAuth,
    /// The bearer token or the OAuth2 client secret, in plaintext, write-only.
    pub credential: Zeroizing<String>,
    /// See [`ScimTarget::scope`].
    pub scope: ScimTargetScope,
    /// See [`ScimTarget::push_groups`].
    pub push_groups: bool,
    /// See [`ScimTarget::user_name_from`].
    pub user_name_from: UserNameSource,
    /// See [`ScimTarget::deprovision`].
    pub deprovision: DeprovisionPolicy,
}

/// `Debug` names the credential's presence and nothing else.
impl fmt::Debug for NewScimTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewScimTarget")
            .field("tenant_id", &self.tenant_id)
            .field("name", &self.name)
            .field("base_url", &self.base_url)
            .field("enabled", &self.enabled)
            .field("auth", &self.auth)
            .field("credential", &"<redacted>")
            .field("scope", &self.scope)
            .field("push_groups", &self.push_groups)
            .field("user_name_from", &self.user_name_from)
            .field("deprovision", &self.deprovision)
            .finish()
    }
}

/// A full replacement of a target's configuration by an administrator.
#[derive(Clone)]
pub struct ScimTargetUpdate {
    /// See [`ScimTarget::name`].
    pub name: String,
    /// See [`ScimTarget::base_url`].
    pub base_url: String,
    /// See [`ScimTarget::enabled`].
    pub enabled: bool,
    /// See [`ScimTarget::auth`].
    pub auth: ScimTargetAuth,
    /// A new credential in plaintext, write-only; `None` keeps the stored one.
    /// Required whenever the write moves the credential to a different URL or
    /// switches the authentication kind (see the module documentation).
    pub credential: Option<Zeroizing<String>>,
    /// See [`ScimTarget::scope`].
    pub scope: ScimTargetScope,
    /// See [`ScimTarget::push_groups`].
    pub push_groups: bool,
    /// See [`ScimTarget::user_name_from`].
    pub user_name_from: UserNameSource,
    /// See [`ScimTarget::deprovision`].
    pub deprovision: DeprovisionPolicy,
    /// The [`ScimTarget::updated_at`] of the read this update was prepared
    /// from: the write lands only if the target has not been written since,
    /// and is otherwise refused with `Conflict` (T-406). `None` writes
    /// unconditionally (against the version the repository itself reads, so
    /// the URL-binding rule still holds); nothing in the server does that.
    pub expected_updated_at: Option<DateTime<Utc>>,
}

impl ScimTargetUpdate {
    /// The update that writes `target` back unchanged (credential kept), for a
    /// caller that changes a few members — conditional on `target` still being
    /// the target's current version.
    #[must_use]
    pub fn from_target(target: &ScimTarget) -> Self {
        Self {
            name: target.name.clone(),
            base_url: target.base_url.clone(),
            enabled: target.enabled,
            auth: target.auth.clone(),
            credential: None,
            scope: target.scope.clone(),
            push_groups: target.push_groups,
            user_name_from: target.user_name_from,
            deprovision: target.deprovision,
            expected_updated_at: Some(target.updated_at),
        }
    }
}

/// `Debug` names the credential's presence and nothing else.
impl fmt::Debug for ScimTargetUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScimTargetUpdate")
            .field("name", &self.name)
            .field("base_url", &self.base_url)
            .field("enabled", &self.enabled)
            .field("auth", &self.auth)
            .field(
                "credential",
                &self.credential.as_ref().map(|_| "<redacted>"),
            )
            .field("scope", &self.scope)
            .field("push_groups", &self.push_groups)
            .field("user_name_from", &self.user_name_from)
            .field("deprovision", &self.deprovision)
            .field("expected_updated_at", &self.expected_updated_at)
            .finish()
    }
}

/// What a link row maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScimResourceType {
    /// An AXIAM user and a downstream `/Users` resource.
    User,
    /// An AXIAM group and a downstream `/Groups` resource.
    Group,
}

impl ScimResourceType {
    /// The spelling stored in the database and used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Group => "group",
        }
    }

    /// Parse the stored spelling.
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "user" => Some(Self::User),
            "group" => Some(Self::Group),
            _ => None,
        }
    }
}

/// Where a linked resource stands downstream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScimLinkState {
    /// Present downstream and in scope. The default.
    #[default]
    Active,
    /// Deactivated downstream (or an erasure `DELETE` that has not succeeded
    /// yet, with [`ScimTargetLink::erase_pending`] set).
    Deprovisioned,
}

impl ScimLinkState {
    /// The spelling stored in the database and used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Deprovisioned => "deprovisioned",
        }
    }

    /// Parse the stored spelling.
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "active" => Some(Self::Active),
            "deprovisioned" => Some(Self::Deprovisioned),
            _ => None,
        }
    }
}

/// The link between an AXIAM resource and its downstream counterpart on one
/// target. Holds ids and a digest only — no attribute of a person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimTargetLink {
    /// The owning tenant.
    pub tenant_id: Uuid,
    /// The target this link belongs to.
    pub target_id: Uuid,
    /// User or group.
    pub resource_type: ScimResourceType,
    /// The AXIAM user or group id; sent downstream as `externalId`.
    pub axiam_id: Uuid,
    /// The id the downstream service provider assigned.
    pub downstream_id: String,
    /// SHA-256 (lower-case hex) of the last representation sent; an unchanged
    /// digest skips the `PATCH`. `None` forces the next sync to send.
    pub synced_digest: Option<String>,
    /// Active or deprovisioned downstream.
    pub state: ScimLinkState,
    /// An erasure `DELETE` was dead-lettered and reconciliation must retry it.
    pub erase_pending: bool,
    /// When the link was made.
    pub created_at: DateTime<Utc>,
    /// When it was last written.
    pub updated_at: DateTime<Utc>,
}

/// The write input for a link row. A new link is [`ScimLinkState::Active`], with
/// no digest and no pending erasure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewScimTargetLink {
    /// See [`ScimTargetLink::tenant_id`].
    pub tenant_id: Uuid,
    /// See [`ScimTargetLink::target_id`].
    pub target_id: Uuid,
    /// See [`ScimTargetLink::resource_type`].
    pub resource_type: ScimResourceType,
    /// See [`ScimTargetLink::axiam_id`].
    pub axiam_id: Uuid,
    /// See [`ScimTargetLink::downstream_id`].
    pub downstream_id: String,
}

/// The audit action of a dead-lettered outbound SCIM delivery: the row the
/// dispatcher writes (`<slug>.delivery_failed`), and the one the
/// `scim_delivery_failed` notification event maps from.
pub const SCIM_DEAD_LETTER_AUDIT_ACTION: &str = "scim_push.delivery_failed";

/// At most one `scim_delivery_failed` notification per target per this many
/// seconds (W5 F4 review, T-418). Every dead letter keeps its audit row and its
/// count on [`ScimTargetState::dead_lettered_total`]; only the mail is
/// coalesced, so a target that is down, or that refuses AXIAM's credential,
/// mails each recipient of a rule once an hour instead of once per reference.
pub const FAILURE_NOTIFICATION_INTERVAL_SECS: i64 = 60 * 60;

/// What the deliverer and the reconciliation job record about a target's
/// deliveries. One row per target, created with the target.
///
/// The `last_failure_reason` is a fixed-vocabulary string chosen by the
/// deliverer; it never holds a URL, a response body or a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimTargetState {
    /// The target this state belongs to.
    pub target_id: Uuid,
    /// The owning tenant.
    pub tenant_id: Uuid,
    /// When a delivery last succeeded.
    pub last_success_at: Option<DateTime<Utc>>,
    /// When a delivery attempt last failed or dead-lettered.
    pub last_failure_at: Option<DateTime<Utc>>,
    /// Why, in the deliverer's fixed vocabulary.
    pub last_failure_reason: Option<String>,
    /// Failed attempts since the last success.
    pub consecutive_failures: u64,
    /// Deliveries dead-lettered over the target's lifetime.
    pub dead_lettered_total: u64,
    /// When reconciliation last ran (the schedule anchor the claim is
    /// conditional on).
    pub last_reconciled_at: Option<DateTime<Utc>>,
    /// When a reconciliation run last claimed the target.
    pub reconcile_claimed_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ScimTarget {
        ScimTarget {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Downstream".into(),
            base_url: "https://idp.example.com/scim/v2".into(),
            enabled: true,
            auth: ScimTargetAuth::OAuth2ClientCredentials {
                token_url: "https://idp.example.com/oauth/token".into(),
                client_id: "axiam".into(),
                scope: Some("scim".into()),
            },
            scope: ScimTargetScope::Groups(vec![Uuid::new_v4()]),
            push_groups: true,
            user_name_from: UserNameSource::Email,
            deprovision: DeprovisionPolicy::Delete,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn defaults_are_the_decided_ones() {
        assert_eq!(UserNameSource::default(), UserNameSource::Username);
        assert_eq!(DeprovisionPolicy::default(), DeprovisionPolicy::Deactivate);
        assert_eq!(ScimLinkState::default(), ScimLinkState::Active);
    }

    #[test]
    fn stored_spellings_round_trip() {
        for v in [UserNameSource::Username, UserNameSource::Email] {
            assert_eq!(UserNameSource::from_wire(v.as_str()), Some(v));
        }
        for v in [DeprovisionPolicy::Deactivate, DeprovisionPolicy::Delete] {
            assert_eq!(DeprovisionPolicy::from_wire(v.as_str()), Some(v));
        }
        for v in [ScimResourceType::User, ScimResourceType::Group] {
            assert_eq!(ScimResourceType::from_wire(v.as_str()), Some(v));
        }
        for v in [ScimLinkState::Active, ScimLinkState::Deprovisioned] {
            assert_eq!(ScimLinkState::from_wire(v.as_str()), Some(v));
        }
        assert_eq!(UserNameSource::from_wire("Email"), None);
    }

    #[test]
    fn the_target_serializes_with_the_decided_names_and_no_credential_member() {
        let json = serde_json::to_value(sample()).unwrap();
        let obj = json.as_object().unwrap();
        let mut members: Vec<&str> = obj.keys().map(String::as_str).collect();
        members.sort_unstable();
        assert_eq!(
            members,
            [
                "auth",
                "base_url",
                "created_at",
                "deprovision",
                "enabled",
                "id",
                "name",
                "push_groups",
                "scope",
                "tenant_id",
                "updated_at",
                "user_name_from"
            ]
        );
        assert_eq!(json["auth"]["type"], "oauth2_client_credentials");
        assert_eq!(json["scope"]["type"], "groups");
        assert_eq!(json["user_name_from"], "email");
        assert_eq!(json["deprovision"], "delete");
        assert_eq!(
            serde_json::to_value(ScimTargetAuth::Bearer).unwrap()["type"],
            "bearer"
        );
        assert_eq!(
            serde_json::to_value(ScimTargetScope::AllUsers).unwrap()["type"],
            "all_users"
        );
    }

    #[test]
    fn the_target_round_trips_through_json() {
        let t = sample();
        let back: ScimTarget = serde_json::from_value(serde_json::to_value(&t).unwrap()).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn debug_of_the_write_inputs_never_prints_the_credential() {
        let marker = Uuid::new_v4().simple().to_string();
        let new = NewScimTarget {
            tenant_id: Uuid::new_v4(),
            name: "n".into(),
            base_url: "https://idp.example.com/scim/v2".into(),
            enabled: true,
            auth: ScimTargetAuth::Bearer,
            credential: Zeroizing::new(marker.clone()),
            scope: ScimTargetScope::AllUsers,
            push_groups: false,
            user_name_from: UserNameSource::Username,
            deprovision: DeprovisionPolicy::Deactivate,
        };
        let rendered = format!("{new:?}");
        assert!(!rendered.contains(&marker));
        assert!(rendered.contains("<redacted>"));

        let mut update = ScimTargetUpdate::from_target(&sample());
        update.credential = Some(Zeroizing::new(marker.clone()));
        let rendered = format!("{update:?}");
        assert!(!rendered.contains(&marker));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn from_target_keeps_the_credential_and_pins_the_version() {
        let t = sample();
        let update = ScimTargetUpdate::from_target(&t);
        assert!(update.credential.is_none());
        assert_eq!(update.expected_updated_at, Some(t.updated_at));
        assert_eq!(update.base_url, t.base_url);
        assert_eq!(update.auth, t.auth);
    }
}
