//! Directory (LDAP / Active Directory) identity-source configuration (G-3).
//!
//! One row per tenant. The model carries **no secret material**: the bind
//! secret is encrypted at rest by the repository (decision D-15, the same way
//! the per-tenant SMTP password is) and reaches the caller only through the
//! dedicated [`DirectoryConfigRepository::decrypt_bind_secret`] method. That
//! is why [`DirectoryConfig`], the type every read returns and every API
//! response will be built from, has no secret field to redact in the first
//! place; the only type that holds the plaintext is [`NewDirectoryConfig`], the
//! write input, and its `Debug` redacts it.
//!
//! Validation of the values (the URL, the filter template, the trust anchors)
//! lives in `axiam-directory::config`, which sits above this crate; this module
//! only declares the shape and the per-[`DirectoryKind`] defaults.
//!
//! [`DirectoryConfigRepository::decrypt_bind_secret`]: crate::repository::DirectoryConfigRepository::decrypt_bind_secret

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Which kind of directory server a configuration points at.
///
/// It drives **defaults only**: the external-id attribute, the group-membership
/// strategy and the change attribute the sync job reads. Every one of them is
/// still an explicit, editable field of the configuration (or, for the
/// strategy and change attribute, derived from this value at the point of use);
/// nothing about the kind changes what is *allowed*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryKind {
    /// OpenLDAP and other RFC 4519 directories with `entryUUID`.
    OpenLdap,
    /// Microsoft Active Directory (`objectGUID`, `memberOf`, `uSNChanged`).
    ActiveDirectory,
}

/// How a user's directory groups are discovered.
///
/// Derived from [`DirectoryKind`]; see [`DirectoryKind::group_strategy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GroupStrategy {
    /// Read the groups straight off the user entry (`memberOf` on AD).
    MemberOf,
    /// Search the group subtree for groups whose `member` attribute names the
    /// user's DN (OpenLDAP, which has no `memberOf` unless an overlay is on).
    ReverseMember,
}

impl DirectoryKind {
    /// The wire/storage spelling. One function so the repository, the schema
    /// `ASSERT` and the REST layer cannot drift apart.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenLdap => "open_ldap",
            Self::ActiveDirectory => "active_directory",
        }
    }

    /// Parse a wire value. Unknown values yield `None` so a caller refuses
    /// them rather than defaulting: a typo must not become OpenLDAP.
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "open_ldap" => Some(Self::OpenLdap),
            "active_directory" => Some(Self::ActiveDirectory),
            _ => None,
        }
    }

    /// The attribute that holds the directory's immutable identifier for an
    /// entry: `entryUUID` (RFC 4530) or `objectGUID`. This is what AXIAM stores
    /// as the user's `external_id`, because a DN or a username can change when
    /// an account is renamed or moved and the identifier cannot.
    pub const fn external_id_attribute(self) -> &'static str {
        match self {
            Self::OpenLdap => "entryUUID",
            Self::ActiveDirectory => "objectGUID",
        }
    }

    /// How group membership is discovered for this kind of directory.
    pub const fn group_strategy(self) -> GroupStrategy {
        match self {
            Self::OpenLdap => GroupStrategy::ReverseMember,
            Self::ActiveDirectory => GroupStrategy::MemberOf,
        }
    }

    /// The attribute the incremental sync orders changes by: the operational
    /// `modifyTimestamp` (OpenLDAP) or the per-server `uSNChanged` (AD).
    pub const fn change_attribute(self) -> &'static str {
        match self {
            Self::OpenLdap => "modifyTimestamp",
            Self::ActiveDirectory => "uSNChanged",
        }
    }

    /// The default for [`DirectoryConfig::group_member_attribute`]: the
    /// user-side `memberOf` on AD, the group-side `member` on OpenLDAP.
    pub const fn default_group_member_attribute(self) -> &'static str {
        match self.group_strategy() {
            GroupStrategy::MemberOf => "memberOf",
            GroupStrategy::ReverseMember => "member",
        }
    }

    /// The default for [`DirectoryConfig::user_attribute_map`].
    pub fn default_user_attribute_map(self) -> UserAttributeMap {
        UserAttributeMap {
            username: match self {
                Self::OpenLdap => "uid",
                Self::ActiveDirectory => "sAMAccountName",
            }
            .to_string(),
            email: "mail".to_string(),
            display_name: "displayName".to_string(),
            external_id: self.external_id_attribute().to_string(),
        }
    }
}

/// Which directory attribute feeds each AXIAM user field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserAttributeMap {
    /// The attribute holding the login name (`uid`, `sAMAccountName`).
    pub username: String,
    /// The attribute holding the e-mail address.
    pub email: String,
    /// The attribute holding the human-readable name.
    pub display_name: String,
    /// The attribute holding the immutable entry identifier
    /// (`entryUUID`, `objectGUID`).
    pub external_id: String,
}

/// A tenant's directory configuration, as stored and as read back.
///
/// Carries no secret: see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryConfig {
    /// Row identifier.
    pub id: Uuid,
    /// The owning tenant. At most one configuration exists per tenant.
    pub tenant_id: Uuid,
    /// Whether the directory is used for sign-in and sync.
    pub enabled: bool,
    /// The kind of directory, which selects defaults.
    pub kind: DirectoryKind,
    /// `ldaps://host[:port]` or `ldap://host[:port]` together with
    /// [`Self::start_tls`]. A plaintext URL is refused at configuration time.
    pub url: String,
    /// Upgrade an `ldap://` connection with StartTLS before any bind.
    pub start_tls: bool,
    /// The service account AXIAM binds as to search. It should hold read-only
    /// rights: AXIAM never writes to a directory.
    pub bind_dn: String,
    /// Where users are searched for.
    pub base_dn: String,
    /// The user-lookup filter template. It contains exactly one `{username}`
    /// placeholder, which the bind path replaces with the RFC 4515-escaped
    /// login name; the template itself is never formatted with raw input.
    pub user_filter: String,
    /// Which attribute feeds which user field.
    pub user_attribute_map: UserAttributeMap,
    /// Where groups are searched for (reverse-`member` lookups, group sync).
    pub group_base_dn: Option<String>,
    /// Restricts which entries under [`Self::group_base_dn`] are groups.
    pub group_filter: Option<String>,
    /// `memberOf` (user-side, AD) or `member` (group-side, OpenLDAP).
    pub group_member_attribute: String,
    /// How many levels of nested groups are followed, `0..=10`.
    pub group_nesting_depth: u8,
    /// Seconds between incremental sync runs.
    pub sync_interval_secs: u64,
    /// Provision an AXIAM user on first successful directory sign-in.
    pub jit_provisioning: bool,
    /// PEM CA certificates that anchor trust in the directory's server
    /// certificate. Empty means the platform roots used by the rest of the
    /// workspace's outbound TLS. An organisation CA's PEM can be pasted here.
    pub trust_anchors_pem: Vec<String>,
    /// When the row was created.
    pub created_at: DateTime<Utc>,
    /// When the row was last written.
    pub updated_at: DateTime<Utc>,
}

/// The write input for creating or replacing a tenant's directory
/// configuration.
///
/// Both `create` and `update` take this: an update is a full replacement of
/// the non-secret fields, which is what a `PUT` of the configuration is.
#[derive(Clone)]
pub struct NewDirectoryConfig {
    /// The owning tenant. Names the row an update replaces.
    pub tenant_id: Uuid,
    /// See [`DirectoryConfig::enabled`].
    pub enabled: bool,
    /// See [`DirectoryConfig::kind`].
    pub kind: DirectoryKind,
    /// See [`DirectoryConfig::url`].
    pub url: String,
    /// See [`DirectoryConfig::start_tls`].
    pub start_tls: bool,
    /// See [`DirectoryConfig::bind_dn`].
    pub bind_dn: String,
    /// The bind password in plaintext, write-only.
    ///
    /// **Required by `create`; on `update`, `None` keeps the stored secret.**
    /// An empty value is refused by validation, because a DN with an empty
    /// password is an RFC 4513 "unauthenticated bind" that many servers treat
    /// as success.
    pub bind_secret: Option<Zeroizing<String>>,
    /// See [`DirectoryConfig::base_dn`].
    pub base_dn: String,
    /// See [`DirectoryConfig::user_filter`].
    pub user_filter: String,
    /// See [`DirectoryConfig::user_attribute_map`].
    pub user_attribute_map: UserAttributeMap,
    /// See [`DirectoryConfig::group_base_dn`].
    pub group_base_dn: Option<String>,
    /// See [`DirectoryConfig::group_filter`].
    pub group_filter: Option<String>,
    /// See [`DirectoryConfig::group_member_attribute`].
    pub group_member_attribute: String,
    /// See [`DirectoryConfig::group_nesting_depth`].
    pub group_nesting_depth: u8,
    /// See [`DirectoryConfig::sync_interval_secs`].
    pub sync_interval_secs: u64,
    /// See [`DirectoryConfig::jit_provisioning`].
    pub jit_provisioning: bool,
    /// See [`DirectoryConfig::trust_anchors_pem`].
    pub trust_anchors_pem: Vec<String>,
}

/// `Debug` names the secret's presence and nothing else: `Zeroizing<String>`
/// delegates `Debug` to the inner string, so a derived impl would print the
/// bind password the first time anyone logged an input with `{:?}`.
impl fmt::Debug for NewDirectoryConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewDirectoryConfig")
            .field("tenant_id", &self.tenant_id)
            .field("enabled", &self.enabled)
            .field("kind", &self.kind)
            .field("url", &self.url)
            .field("start_tls", &self.start_tls)
            .field("bind_dn", &self.bind_dn)
            .field(
                "bind_secret",
                &self.bind_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("base_dn", &self.base_dn)
            .field("user_filter", &self.user_filter)
            .field("user_attribute_map", &self.user_attribute_map)
            .field("group_base_dn", &self.group_base_dn)
            .field("group_filter", &self.group_filter)
            .field("group_member_attribute", &self.group_member_attribute)
            .field("group_nesting_depth", &self.group_nesting_depth)
            .field("sync_interval_secs", &self.sync_interval_secs)
            .field("jit_provisioning", &self.jit_provisioning)
            .field("trust_anchors_pem", &self.trust_anchors_pem.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kind_selects_the_documented_defaults() {
        let ad = DirectoryKind::ActiveDirectory;
        assert_eq!(ad.external_id_attribute(), "objectGUID");
        assert_eq!(ad.group_strategy(), GroupStrategy::MemberOf);
        assert_eq!(ad.change_attribute(), "uSNChanged");
        assert_eq!(ad.default_group_member_attribute(), "memberOf");
        assert_eq!(ad.default_user_attribute_map().username, "sAMAccountName");
        assert_eq!(ad.default_user_attribute_map().external_id, "objectGUID");

        let ol = DirectoryKind::OpenLdap;
        assert_eq!(ol.external_id_attribute(), "entryUUID");
        assert_eq!(ol.group_strategy(), GroupStrategy::ReverseMember);
        assert_eq!(ol.change_attribute(), "modifyTimestamp");
        assert_eq!(ol.default_group_member_attribute(), "member");
        assert_eq!(ol.default_user_attribute_map().username, "uid");
        assert_eq!(ol.default_user_attribute_map().external_id, "entryUUID");
    }

    #[test]
    fn the_wire_spelling_round_trips_and_refuses_unknowns() {
        for kind in [DirectoryKind::OpenLdap, DirectoryKind::ActiveDirectory] {
            assert_eq!(DirectoryKind::from_wire(kind.as_str()), Some(kind));
        }
        assert_eq!(DirectoryKind::from_wire("openldap"), None);
        assert_eq!(DirectoryKind::from_wire(""), None);
    }

    #[test]
    fn debug_of_the_write_input_redacts_the_secret() {
        let marker = "debug-marker-not-a-real-secret";
        let input = NewDirectoryConfig {
            tenant_id: Uuid::nil(),
            enabled: true,
            kind: DirectoryKind::OpenLdap,
            url: "ldaps://ldap.example.com".into(),
            start_tls: false,
            bind_dn: "cn=svc,dc=example,dc=com".into(),
            bind_secret: Some(Zeroizing::new(marker.to_string())),
            base_dn: "dc=example,dc=com".into(),
            user_filter: "(uid={username})".into(),
            user_attribute_map: DirectoryKind::OpenLdap.default_user_attribute_map(),
            group_base_dn: None,
            group_filter: None,
            group_member_attribute: "member".into(),
            group_nesting_depth: 5,
            sync_interval_secs: 3600,
            jit_provisioning: true,
            trust_anchors_pem: vec![],
        };
        let rendered = format!("{input:?}");
        assert!(
            !rendered.contains(marker),
            "Debug of NewDirectoryConfig must not print the bind secret"
        );
        assert!(rendered.contains("<redacted>"));
    }
}
