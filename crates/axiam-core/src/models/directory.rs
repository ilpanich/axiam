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

// ---------------------------------------------------------------------------
// The authentication port (T23.3.2)
// ---------------------------------------------------------------------------

/// What a successful directory bind established about a user.
///
/// Returned by [`DirectoryAuthenticator::authenticate`] only after the
/// directory accepted a bind **as that entry, with the presented password**.
/// `external_id` is the entry's immutable identifier (`entryUUID`, or the AD
/// `objectGUID` decoded to its canonical text form), which is what AXIAM keys
/// a directory account on; the other fields are the mapped attributes, which
/// just-in-time provisioning (T23.3.3) copies and group mapping (T23.3.4)
/// starts from.
///
/// Every field but the identifier names a person, so `Debug` prints presence
/// only.
#[derive(Clone, PartialEq, Eq)]
pub struct DirectoryIdentity {
    /// The entry's immutable identifier, normalised: a lowercase hyphenated
    /// UUID for `entryUUID` and `objectGUID`, the attribute's text otherwise.
    pub external_id: String,
    /// The entry's distinguished name, exactly as the directory returned it
    /// from the user search (never constructed by AXIAM).
    pub dn: String,
    /// The mapped login-name attribute, when the entry carried one.
    pub username: Option<String>,
    /// The mapped e-mail attribute, when the entry carried one.
    pub email: Option<String>,
    /// The mapped display-name attribute, when the entry carried one.
    pub display_name: Option<String>,
}

impl fmt::Debug for DirectoryIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectoryIdentity")
            .field("external_id", &"<redacted>")
            .field("dn", &"<redacted>")
            .field("username", &self.username.as_ref().map(|_| "<redacted>"))
            .field("email", &self.email.as_ref().map(|_| "<redacted>"))
            .field(
                "display_name",
                &self.display_name.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Why the directory accepted the password but refused the account.
///
/// Read from Active Directory's `data XXX` sub-code in the bind diagnostic
/// (`533`, `701`, `775`, `532`, `773`, `530`/`531`), or from the LDAP result
/// code where the directory uses one for a refusal (`unwillingToPerform`,
/// `insufficientAccessRights`). The end user never learns which: every variant
/// is answered with the generic sign-in failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DirectoryAccountRestriction {
    /// The account is disabled (AD `533`, or a directory that refuses the bind
    /// outright with `unwillingToPerform` / `insufficientAccessRights`).
    Disabled,
    /// The directory has locked the account (AD `775`).
    Locked,
    /// The account has expired (AD `701`).
    Expired,
    /// The password has expired (AD `532`).
    PasswordExpired,
    /// The password must be changed before the next sign-in (AD `773`).
    PasswordMustChange,
    /// Sign-in is not permitted at this time or from this workstation
    /// (AD `530`, `531`).
    NotPermittedNow,
}

/// Why a directory authentication did not succeed.
///
/// A small, closed set. It is the vocabulary between the directory client and
/// the login path, never a response: the login path answers **every** variant
/// with the same generic failure, so an unauthenticated caller cannot tell a
/// wrong password from an unknown entry, a disabled account or an unreachable
/// directory. The variants exist so the login path can decide what to **count**
/// (only [`Self::InvalidCredentials`] moves the brute-force counter) and what
/// to tell the **operator** in a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum DirectoryAuthError {
    /// The tenant has no directory configuration, or it is disabled.
    #[error("no enabled directory is configured for this tenant")]
    NotConfigured,
    /// The password is wrong, the login name matched no entry or more than
    /// one, the matched entry is not the account AXIAM holds, or the password
    /// was empty (refused before any network I/O).
    #[error("invalid credentials")]
    InvalidCredentials,
    /// The directory accepted the credentials but refuses the account.
    #[error("the directory refused the account")]
    AccountRestricted(DirectoryAccountRestriction),
    /// The directory could not be reached or did not answer in time: a
    /// connection, TLS or timeout failure, a busy server, an exhausted
    /// connection pool, or the encryption key for the bind secret missing.
    /// A TLS verification failure is reported here too — it is
    /// indistinguishable from an interception attempt, and is never retried in
    /// a weaker form.
    #[error("the directory is unavailable")]
    Unavailable,
    /// The directory answered, but the configuration cannot work: the service
    /// bind was refused, the search base does not exist, the directory sent a
    /// referral (never followed), the entry lacks its identifier attribute, or
    /// the stored configuration is unusable.
    #[error("the directory configuration is unusable")]
    Misconfigured,
}

/// The port the login path authenticates a directory account through.
///
/// Declared here, in layer 0, because the login path lives in `axiam-auth`
/// (layer 1) and the LDAP client in `axiam-directory` (layer 3): the client
/// implements this trait and the composition root injects it, so no production
/// dependency points outward. It is object-safe (a boxed future rather than
/// `impl Future`) because `AuthService` holds it as an optional field rather
/// than a fifth type parameter, the same seam [`super::reactor::DynReactorGate`]
/// is for the reactor gate.
///
/// # Contract for implementations
///
/// * Resolve the entry by the tenant's user filter with `login_name`
///   RFC 4515-escaped, require **exactly one** match, then bind **as that
///   entry** with `password`. Success means that bind succeeded.
/// * Refuse an empty `password` with [`DirectoryAuthError::InvalidCredentials`]
///   before any network I/O: an empty password is an RFC 4513 unauthenticated
///   bind, which many servers report as success.
/// * Never send anything over an unencrypted connection, never follow a
///   referral, and never return a connection that is bound as the user to a
///   pool.
/// * Never log `password`, and never surface the directory's diagnostic text
///   above `debug`.
pub trait DirectoryAuthenticator: Send + Sync {
    /// Authenticate `login_name` / `password` against `tenant_id`'s directory.
    fn authenticate<'a>(
        &'a self,
        tenant_id: Uuid,
        login_name: &'a str,
        password: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<DirectoryIdentity, DirectoryAuthError>>
                + Send
                + 'a,
        >,
    >;
}

/// What `AuthService` holds: a shared, type-erased authenticator.
pub type SharedDirectoryAuthenticator = std::sync::Arc<dyn DirectoryAuthenticator>;

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

    #[test]
    fn debug_of_a_directory_identity_prints_presence_only() {
        let identity = DirectoryIdentity {
            external_id: "marker-external-id".into(),
            dn: "marker-dn".into(),
            username: Some("marker-username".into()),
            email: Some("marker-email".into()),
            display_name: None,
        };
        let rendered = format!("{identity:?}");
        assert!(
            !rendered.contains("marker-"),
            "Debug of DirectoryIdentity must not print personal data"
        );
        assert!(rendered.contains("display_name: None"));
    }
}
