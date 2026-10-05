//! The documents the outbound client sends (RFC 7643 §4 resources, RFC 7644
//! §3.5.2 `PatchOp`) and the digest of a representation.
//!
//! These are `Serialize`-only types of their own: the inbound wire types of
//! this crate are `Deserialize`-only and private to their handlers, and bending
//! them to serve both directions would couple the two.
//!
//! A representation is built from the AXIAM [`User`] or [`Group`] and the
//! target's mapping — a **fixed attribute set**, not a mapping language:
//!
//! | Downstream | From |
//! |---|---|
//! | `userName` | the username, or the email when the target says `user_name_from = email` |
//! | `name.givenName`, `name.familyName`, `displayName` | `metadata.scim.givenName`, `…familyName`, `…formatted` — where the inbound SCIM server stores them ([`crate::scim_metadata`]) |
//! | `emails` | the primary email |
//! | `active` | the desired state computed by the deliverer |
//! | `externalId` | the AXIAM id |
//!
//! An attribute AXIAM does not hold is **omitted**, never sent empty and never
//! removed: the downstream may own it.

use axiam_core::models::group::Group;
use axiam_core::models::scim_target::{ScimTarget, UserNameSource};
use axiam_core::models::user::User;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::patch::PATCH_OP_SCHEMA;
use crate::schema::{GROUP_SCHEMA, USER_SCHEMA};
use crate::scim_metadata;

/// RFC 7644 §3.1: the media type of every request and response body.
pub const SCIM_CONTENT_TYPE: &str = "application/scim+json";

/// `name` of an RFC 7643 §4.1.1 User.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NameRepresentation {
    /// `name.givenName`.
    #[serde(rename = "givenName", skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// `name.familyName`.
    #[serde(rename = "familyName", skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
}

/// One `emails` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EmailRepresentation {
    /// The address.
    pub value: String,
    /// Always `true`: AXIAM holds one address.
    pub primary: bool,
}

/// What `POST /Users` carries and what a `PATCH` is derived from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserRepresentation {
    schemas: [&'static str; 1],
    /// The AXIAM user id.
    #[serde(rename = "externalId")]
    pub external_id: String,
    /// See the module documentation.
    #[serde(rename = "userName")]
    pub user_name: String,
    /// `name.givenName` / `name.familyName`, when AXIAM holds either.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<NameRepresentation>,
    /// `displayName`, when AXIAM holds one.
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// The primary email, when there is one.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<EmailRepresentation>,
    /// Whether the account is enabled downstream.
    pub active: bool,
}

impl UserRepresentation {
    /// The representation of `user` under `target`'s mapping, with `active` as
    /// the deliverer decided it.
    #[must_use]
    pub fn new(user: &User, target: &ScimTarget, active: bool) -> Self {
        let user_name = match target.user_name_from {
            UserNameSource::Email if !user.email.is_empty() => user.email.clone(),
            _ => user.username.clone(),
        };
        let given_name = scim_metadata::get_str(&user.metadata, "givenName");
        let family_name = scim_metadata::get_str(&user.metadata, "familyName");
        let name = (given_name.is_some() || family_name.is_some()).then_some(NameRepresentation {
            given_name,
            family_name,
        });
        Self {
            schemas: [USER_SCHEMA],
            external_id: user.id.to_string(),
            user_name,
            name,
            display_name: scim_metadata::get_str(&user.metadata, "formatted"),
            emails: if user.email.is_empty() {
                Vec::new()
            } else {
                vec![EmailRepresentation {
                    value: user.email.clone(),
                    primary: true,
                }]
            },
            active,
        }
    }

    /// The `replace` operations of a `PATCH` for this representation: the
    /// mapped attributes only (`userName`, `name.givenName`, `name.familyName`,
    /// `displayName`, the primary `emails` value, `active`, `externalId`).
    #[must_use]
    pub fn patch(&self) -> PatchRequest {
        let mut operations = vec![PatchOperation::replace("userName", json!(self.user_name))];
        if let Some(name) = &self.name {
            if let Some(given) = &name.given_name {
                operations.push(PatchOperation::replace("name.givenName", json!(given)));
            }
            if let Some(family) = &name.family_name {
                operations.push(PatchOperation::replace("name.familyName", json!(family)));
            }
        }
        if let Some(display) = &self.display_name {
            operations.push(PatchOperation::replace("displayName", json!(display)));
        }
        if !self.emails.is_empty() {
            operations.push(PatchOperation::replace("emails", json!(self.emails)));
        }
        operations.push(PatchOperation::replace("active", json!(self.active)));
        operations.push(PatchOperation::replace(
            "externalId",
            json!(self.external_id),
        ));
        PatchRequest::new(operations)
    }
}

/// One `members` entry of a Group: the **downstream** id of a linked user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemberRepresentation {
    /// The downstream user id.
    pub value: String,
}

/// What `POST /Groups` carries and what a group `PATCH` is derived from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GroupRepresentation {
    schemas: [&'static str; 1],
    /// The AXIAM group id.
    #[serde(rename = "externalId")]
    pub external_id: String,
    /// The group's name.
    #[serde(rename = "displayName")]
    pub display_name: String,
    /// The downstream ids of the group's **linked** members, sorted (so the
    /// digest does not depend on the order the datastore returned them in).
    pub members: Vec<MemberRepresentation>,
}

impl GroupRepresentation {
    /// The representation of `group` with `member_ids` (downstream user ids).
    #[must_use]
    pub fn new(group: &Group, mut member_ids: Vec<String>) -> Self {
        member_ids.sort_unstable();
        member_ids.dedup();
        Self {
            schemas: [GROUP_SCHEMA],
            external_id: group.id.to_string(),
            display_name: group.name.clone(),
            members: member_ids
                .into_iter()
                .map(|value| MemberRepresentation { value })
                .collect(),
        }
    }

    /// The `replace` operations of a `PATCH`: `displayName`, `externalId` and
    /// `members` (the whole list, so a removed member leaves).
    #[must_use]
    pub fn patch(&self) -> PatchRequest {
        PatchRequest::new(vec![
            PatchOperation::replace("displayName", json!(self.display_name)),
            PatchOperation::replace("externalId", json!(self.external_id)),
            PatchOperation::replace("members", json!(self.members)),
        ])
    }
}

/// One RFC 7644 §3.5.2 operation. Only `replace` is ever sent: a `PUT` would
/// clobber attributes the downstream owns, and an `add` of a single-valued
/// attribute is a `replace` by another name.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PatchOperation {
    op: &'static str,
    path: &'static str,
    value: Value,
}

impl PatchOperation {
    fn replace(path: &'static str, value: Value) -> Self {
        Self {
            op: "replace",
            path,
            value,
        }
    }

    /// The attribute path the operation names.
    #[must_use]
    pub fn path(&self) -> &'static str {
        self.path
    }
}

/// An RFC 7644 §3.5.2 `PatchOp` message.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PatchRequest {
    schemas: [&'static str; 1],
    #[serde(rename = "Operations")]
    operations: Vec<PatchOperation>,
}

impl PatchRequest {
    fn new(operations: Vec<PatchOperation>) -> Self {
        Self {
            schemas: [PATCH_OP_SCHEMA],
            operations,
        }
    }

    /// The operations, in the order they are sent.
    #[must_use]
    pub fn operations(&self) -> &[PatchOperation] {
        &self.operations
    }
}

/// SHA-256 (lower-case hex) over the canonical serialisation of a
/// representation: serde writes a struct's members in declaration order, so the
/// bytes depend on the content and on nothing else.
#[must_use]
pub fn digest_of<T: Serialize>(representation: &T) -> String {
    // A struct of strings, booleans and vectors of them cannot fail to
    // serialise; the empty fallback would only ever change a digest, which
    // re-sends, never loses an update.
    let bytes = serde_json::to_vec(representation).unwrap_or_default();
    hex::encode(Sha256::digest(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::scim_target::{
        DeprovisionPolicy, ScimTargetAuth, ScimTargetScope, UserNameSource,
    };
    use axiam_core::models::user::UserStatus;
    use chrono::Utc;
    use uuid::Uuid;

    fn target(user_name_from: UserNameSource) -> ScimTarget {
        ScimTarget {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "t".into(),
            base_url: "https://scim.example.com/v2".into(),
            enabled: true,
            auth: ScimTargetAuth::Bearer,
            scope: ScimTargetScope::AllUsers,
            push_groups: true,
            user_name_from,
            deprovision: DeprovisionPolicy::Deactivate,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn user() -> User {
        User {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            password_hash: String::new(),
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
            metadata: json!({"scim": {"givenName": "Alice", "familyName": "Example", "formatted": "Alice Example"}}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn the_user_is_mapped_from_the_places_the_inbound_server_stores_it() {
        let u = user();
        let repr = UserRepresentation::new(&u, &target(UserNameSource::Username), true);
        let json = serde_json::to_value(&repr).unwrap();
        assert_eq!(json["externalId"], u.id.to_string());
        assert_eq!(json["userName"], "alice");
        assert_eq!(json["name"]["givenName"], "Alice");
        assert_eq!(json["name"]["familyName"], "Example");
        assert_eq!(json["displayName"], "Alice Example");
        assert_eq!(
            json["emails"],
            json!([{"value": "alice@example.com", "primary": true}])
        );
        assert_eq!(json["active"], true);
        assert_eq!(json["schemas"], json!([USER_SCHEMA]));

        let by_email = UserRepresentation::new(&u, &target(UserNameSource::Email), true);
        assert_eq!(by_email.user_name, "alice@example.com");
    }

    #[test]
    fn an_attribute_axiam_does_not_hold_is_omitted() {
        let mut u = user();
        u.metadata = json!({});
        u.email = String::new();
        let repr = UserRepresentation::new(&u, &target(UserNameSource::Email), false);
        let json = serde_json::to_value(&repr).unwrap();
        // No email: userName falls back to the username.
        assert_eq!(json["userName"], "alice");
        for absent in ["name", "displayName", "emails"] {
            assert!(json.get(absent).is_none(), "{absent}");
        }
        let paths: Vec<_> = repr.patch().operations().iter().map(|o| o.path()).collect();
        assert_eq!(paths, ["userName", "active", "externalId"]);
    }

    #[test]
    fn a_patch_replaces_the_mapped_attributes_only() {
        let repr = UserRepresentation::new(&user(), &target(UserNameSource::Username), true);
        let patch = serde_json::to_value(repr.patch()).unwrap();
        assert_eq!(patch["schemas"], json!([PATCH_OP_SCHEMA]));
        let paths: Vec<_> = patch["Operations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| {
                assert_eq!(o["op"], "replace");
                o["path"].as_str().unwrap().to_owned()
            })
            .collect();
        assert_eq!(
            paths,
            [
                "userName",
                "name.givenName",
                "name.familyName",
                "displayName",
                "emails",
                "active",
                "externalId"
            ]
        );
    }

    #[test]
    fn the_digest_follows_the_content_and_nothing_else() {
        let u = user();
        let t = target(UserNameSource::Username);
        let a = digest_of(&UserRepresentation::new(&u, &t, true));
        assert_eq!(a, digest_of(&UserRepresentation::new(&u, &t, true)));
        assert_eq!(a.len(), 64);
        assert_ne!(a, digest_of(&UserRepresentation::new(&u, &t, false)));
        let mut renamed = u.clone();
        renamed.username = "alice2".into();
        assert_ne!(a, digest_of(&UserRepresentation::new(&renamed, &t, true)));
        // Fields the mapping does not carry do not move it.
        let mut other = u.clone();
        other.mfa_enabled = true;
        other.updated_at = Utc::now() + chrono::Duration::days(1);
        assert_eq!(a, digest_of(&UserRepresentation::new(&other, &t, true)));
    }

    #[test]
    fn group_members_are_sorted_and_the_digest_is_order_independent() {
        let group = Group {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "staff".into(),
            description: String::new(),
            metadata: json!({}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let a = GroupRepresentation::new(&group, vec!["b".into(), "a".into(), "b".into()]);
        let b = GroupRepresentation::new(&group, vec!["a".into(), "b".into()]);
        assert_eq!(a, b);
        assert_eq!(digest_of(&a), digest_of(&b));
        assert_eq!(
            serde_json::to_value(&a).unwrap()["members"],
            json!([{"value": "a"}, {"value": "b"}])
        );
        let paths: Vec<_> = a.patch().operations().iter().map(|o| o.path()).collect();
        assert_eq!(paths, ["displayName", "externalId", "members"]);
        let grown = GroupRepresentation::new(&group, vec!["a".into(), "b".into(), "c".into()]);
        assert_ne!(digest_of(&a), digest_of(&grown));
    }
}
