//! Directory (LDAP / Active Directory) management routes (G-3, T23.3.8,
//! contract §30).
//!
//! One configuration per tenant, read and written under
//! `/api/v1/tenants/{tenant_id}/directory`, plus the administrator's act of
//! linking an existing local account to its directory entry and a read-only view
//! of the sync job's state. The routes are thin: everything that decides what a
//! configuration may be lives in `axiam_directory` (`config::validate`, the
//! address guard) and in the repositories; this module only **calls** it on
//! every write and turns the answers into the statuses §30.3 pins.
//!
//! # What every write does, in this order
//!
//! 1. **`503`** when the write carries a bind secret and the deployment has no
//!    `directory_encryption_key` (§30.3 rule 4). The response does not name the
//!    key; the operator's log does.
//! 2. **`config::validate`** — the same function the bind path trusts. The
//!    repository does not run it (F4 §12 item 3).
//! 3. **The address guard** on `url` *as written*, even when it did not change:
//!    a name re-pointed since the last save is caught on the next write (T-300) —
//!    for a write whose resulting configuration is **enabled** (D-33); a write
//!    that leaves it disabled opens no connection and skips it.
//!    An IPv6 literal, an unresolvable host, loopback, link-local, the metadata
//!    service, AXIAM's own listener and an unlisted private address are each a
//!    `400`. An IP literal's answer names the rule; a host **name**'s answer is
//!    one message and one audit rule whatever the name resolved to, so the
//!    route is not an oracle for internal DNS (F4 P23W3-04); the specific rule
//!    is in the operator's log.
//! 4. **P23W2-01**: moving `url`, `start_tls`, `bind_dn` or `trust_anchors_pem`
//!    without a `bind_secret` is a `400` naming the rule. Checked here first so
//!    the refusal can be audited, and enforced again by the repository in the
//!    same statement as the write so a concurrent change is refused the same way.
//! 5. **`409`** when an *enabled* directory would coexist with an effective
//!    `opaque_mode = required` (§30.3 rule 3); the `settings` writes enforce the
//!    other direction.
//! 6. The write, and an audit row that names the fields that changed and whether
//!    the connection moved — and never the secret nor any trust anchor.
//!
//! # The secret
//!
//! `bind_secret` exists on exactly two request types and nowhere else
//! (D-15, §30.5). It is a [`SecretString`], so a derived `Debug` prints
//! `[REDACTED]`; it is moved into a `Zeroizing` buffer for the repository; no
//! response type has a member for it, a flag for it or a hash of it; and these
//! routes use their own JSON error handler so that a body in which the secret
//! has the wrong type is not echoed back in a `400` (serde's own message quotes
//! the offending value).

use actix_web::error::JsonPayloadError;
use actix_web::{HttpRequest, HttpResponse, web};
use axiam_core::error::AxiamError;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::directory::{
    CONNECTION_MOVED_WITHOUT_SECRET, DirectoryConfig, DirectoryKind, GroupMapping,
    NewDirectoryConfig, UserAttributeMap,
};
use axiam_core::models::opaque::OpaqueMode;
use axiam_core::repository::{
    AuditLogRepository, DirectoryConfigRepository, DirectorySyncStateRepository,
    SettingsRepository, UserRepository,
};
use axiam_directory::GuardError;
use axiam_directory::config::{
    GROUP_NESTING_DEPTH_DEFAULT, SYNC_INTERVAL_DEFAULT_SECS, validate as validate_config,
};
use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize};
use surrealdb::Connection;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::extractors::client_info::client_ip;
use crate::state::AppState;

/// Audit action: a tenant's directory configuration was created.
pub const AUDIT_CONFIG_CREATED: &str = "directory.config_created";
/// Audit action: a tenant's directory configuration was replaced or edited.
pub const AUDIT_CONFIG_UPDATED: &str = "directory.config_updated";
/// Audit action: a tenant's directory configuration was deleted.
pub const AUDIT_CONFIG_DELETED: &str = "directory.config_deleted";

// ---------------------------------------------------------------------------
// Request and response shapes (CONTRACT §30.2)
// ---------------------------------------------------------------------------

/// `null` is not absent: `Some(None)` clears a nullable member, `None` leaves it.
fn double_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

/// `PUT /api/v1/tenants/{tenant_id}/directory` — a **replacement**.
///
/// Every `DirectoryConfig` member except `id`, `tenant_id` and the two
/// timestamps, plus the write-only `bind_secret`. An omitted optional member is
/// **reset to its default**, not kept.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SetDirectoryConfig {
    /// A disabled directory serves no sign-in and is not synced.
    pub enabled: bool,
    /// Chooses defaults only.
    pub kind: DirectoryKind,
    /// `ldaps://host[:port]`, or `ldap://host[:port]` with `start_tls`.
    pub url: String,
    /// Upgrade an `ldap://` connection with StartTLS before any bind.
    pub start_tls: bool,
    /// The service account the search runs as.
    pub bind_dn: String,
    /// The service account's password: **write-only**, 1 to 4096 octets.
    /// Required when the tenant has no configuration yet; on a replacement,
    /// absent means *keep the stored secret* — unless the write moves the
    /// connection (`url`, `start_tls`, `bind_dn` or `trust_anchors_pem`), which
    /// then requires it (`400`, P23W2-01).
    #[serde(default)]
    #[schema(value_type = Option<String>, write_only, min_length = 1, max_length = 4096)]
    pub bind_secret: Option<SecretString>,
    /// Where users are searched for.
    pub base_dn: String,
    /// One `{username}` placeholder in value position.
    pub user_filter: String,
    /// Defaults by `kind`.
    #[serde(default)]
    pub user_attribute_map: Option<UserAttributeMap>,
    /// Defaults to null.
    #[serde(default)]
    pub group_base_dn: Option<String>,
    /// Defaults to null.
    #[serde(default)]
    pub group_filter: Option<String>,
    /// Defaults by `kind`.
    #[serde(default)]
    pub group_member_attribute: Option<String>,
    /// `0..=10`, default 5.
    #[serde(default)]
    #[schema(minimum = 0, maximum = 10)]
    pub group_nesting_depth: Option<u8>,
    /// At most 500; every `group_id` a group of the tenant. Default empty.
    #[serde(default)]
    #[schema(max_items = 500)]
    pub group_mappings: Option<Vec<GroupMapping>>,
    /// `300..=86400`, default 3600.
    #[serde(default)]
    #[schema(minimum = 300, maximum = 86400)]
    pub sync_interval_secs: Option<u64>,
    /// Default false.
    #[serde(default)]
    pub jit_provisioning: Option<bool>,
    /// At most 16 CA certificates in PEM. Default empty (the public roots).
    #[serde(default)]
    #[schema(max_items = 16)]
    pub trust_anchors_pem: Option<Vec<String>>,
}

/// `PATCH /api/v1/tenants/{tenant_id}/directory` — a **sparse** update.
///
/// Every member optional: absent leaves the stored value, and for the two
/// nullable members an explicit `null` clears it.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateDirectoryConfig {
    /// See [`SetDirectoryConfig::enabled`].
    #[serde(default)]
    pub enabled: Option<bool>,
    /// See [`SetDirectoryConfig::kind`].
    #[serde(default)]
    pub kind: Option<DirectoryKind>,
    /// See [`SetDirectoryConfig::url`].
    #[serde(default)]
    pub url: Option<String>,
    /// See [`SetDirectoryConfig::start_tls`].
    #[serde(default)]
    pub start_tls: Option<bool>,
    /// See [`SetDirectoryConfig::bind_dn`].
    #[serde(default)]
    pub bind_dn: Option<String>,
    /// See [`SetDirectoryConfig::bind_secret`]; absent keeps the stored secret,
    /// subject to the same P23W2-01 rule.
    #[serde(default)]
    #[schema(value_type = Option<String>, write_only, min_length = 1, max_length = 4096)]
    pub bind_secret: Option<SecretString>,
    /// See [`SetDirectoryConfig::base_dn`].
    #[serde(default)]
    pub base_dn: Option<String>,
    /// See [`SetDirectoryConfig::user_filter`].
    #[serde(default)]
    pub user_filter: Option<String>,
    /// Replaces the whole map when present.
    #[serde(default)]
    pub user_attribute_map: Option<UserAttributeMap>,
    /// Explicit `null` clears it.
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>, nullable)]
    pub group_base_dn: Option<Option<String>>,
    /// Explicit `null` clears it.
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>, nullable)]
    pub group_filter: Option<Option<String>>,
    /// See [`SetDirectoryConfig::group_member_attribute`].
    #[serde(default)]
    pub group_member_attribute: Option<String>,
    /// See [`SetDirectoryConfig::group_nesting_depth`].
    #[serde(default)]
    #[schema(minimum = 0, maximum = 10)]
    pub group_nesting_depth: Option<u8>,
    /// Replaces the whole table when present.
    #[serde(default)]
    #[schema(max_items = 500)]
    pub group_mappings: Option<Vec<GroupMapping>>,
    /// See [`SetDirectoryConfig::sync_interval_secs`].
    #[serde(default)]
    #[schema(minimum = 300, maximum = 86400)]
    pub sync_interval_secs: Option<u64>,
    /// See [`SetDirectoryConfig::jit_provisioning`].
    #[serde(default)]
    pub jit_provisioning: Option<bool>,
    /// Replaces the whole list when present.
    #[serde(default)]
    #[schema(max_items = 16)]
    pub trust_anchors_pem: Option<Vec<String>>,
}

/// `POST /api/v1/tenants/{tenant_id}/directory/links` body.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct LinkDirectoryAccount {
    /// The local account to link. The directory entry is found by the
    /// directory, from the account's own username; the caller names no entry.
    pub user_id: Uuid,
}

/// What linking did.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DirectoryLinkResult {
    /// The account that was linked.
    pub user_id: Uuid,
    /// The entry's `entryUUID` or `objectGUID` as text: an identifier, not a
    /// secret.
    pub directory_external_id: String,
    /// Passkeys and security keys deleted.
    pub webauthn_credentials_deleted: u64,
    /// `User`-type certificates revoked.
    pub certificates_revoked: u64,
    /// `true` when the account was already linked to that very entry and the
    /// call only re-ran the revocations (an interrupted link completed).
    pub was_already_linked: bool,
}

/// A read-only view of the sync job's state for one tenant. Counts of what a
/// run did are in its audit rows, and no account id is here.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DirectorySyncStatus {
    /// `ok`, `partial`, `failed` or `safety_valve` (an open set: decode another
    /// value without failing), or null before the first run.
    pub last_result: Option<String>,
    /// When the last attempt started, or null before the first run.
    pub last_attempt_at: Option<DateTime<Utc>>,
    /// When the last complete full run finished, or null.
    pub last_full_run_at: Option<DateTime<Utc>>,
    /// The next run must be a full reconciliation.
    pub full_required: bool,
    /// An incremental run has a starting point.
    pub has_watermark: bool,
}

// ---------------------------------------------------------------------------
// Request bodies: defaults, merging and the JSON error handler
// ---------------------------------------------------------------------------

impl SetDirectoryConfig {
    /// The repository's write input, every omitted member at its default.
    fn into_input(self, tenant_id: Uuid) -> NewDirectoryConfig {
        let kind = self.kind;
        NewDirectoryConfig {
            tenant_id,
            enabled: self.enabled,
            kind,
            url: self.url,
            start_tls: self.start_tls,
            bind_dn: self.bind_dn,
            bind_secret: self.bind_secret.map(secret_buffer),
            base_dn: self.base_dn,
            user_filter: self.user_filter,
            user_attribute_map: self
                .user_attribute_map
                .unwrap_or_else(|| kind.default_user_attribute_map()),
            group_base_dn: self.group_base_dn,
            group_filter: self.group_filter,
            group_member_attribute: self
                .group_member_attribute
                .unwrap_or_else(|| kind.default_group_member_attribute().to_string()),
            group_nesting_depth: self
                .group_nesting_depth
                .unwrap_or(GROUP_NESTING_DEPTH_DEFAULT),
            group_mappings: self.group_mappings.unwrap_or_default(),
            sync_interval_secs: self
                .sync_interval_secs
                .unwrap_or(SYNC_INTERVAL_DEFAULT_SECS),
            jit_provisioning: self.jit_provisioning.unwrap_or(false),
            trust_anchors_pem: self.trust_anchors_pem.unwrap_or_default(),
        }
    }
}

impl UpdateDirectoryConfig {
    /// The repository's write input: the stored configuration with every member
    /// this body carries laid over it.
    fn merge_onto(self, stored: &DirectoryConfig) -> NewDirectoryConfig {
        NewDirectoryConfig {
            tenant_id: stored.tenant_id,
            enabled: self.enabled.unwrap_or(stored.enabled),
            kind: self.kind.unwrap_or(stored.kind),
            url: self.url.unwrap_or_else(|| stored.url.clone()),
            start_tls: self.start_tls.unwrap_or(stored.start_tls),
            bind_dn: self.bind_dn.unwrap_or_else(|| stored.bind_dn.clone()),
            bind_secret: self.bind_secret.map(secret_buffer),
            base_dn: self.base_dn.unwrap_or_else(|| stored.base_dn.clone()),
            user_filter: self
                .user_filter
                .unwrap_or_else(|| stored.user_filter.clone()),
            user_attribute_map: self
                .user_attribute_map
                .unwrap_or_else(|| stored.user_attribute_map.clone()),
            group_base_dn: self
                .group_base_dn
                .unwrap_or_else(|| stored.group_base_dn.clone()),
            group_filter: self
                .group_filter
                .unwrap_or_else(|| stored.group_filter.clone()),
            group_member_attribute: self
                .group_member_attribute
                .unwrap_or_else(|| stored.group_member_attribute.clone()),
            group_nesting_depth: self
                .group_nesting_depth
                .unwrap_or(stored.group_nesting_depth),
            group_mappings: self
                .group_mappings
                .unwrap_or_else(|| stored.group_mappings.clone()),
            sync_interval_secs: self.sync_interval_secs.unwrap_or(stored.sync_interval_secs),
            jit_provisioning: self.jit_provisioning.unwrap_or(stored.jit_provisioning),
            trust_anchors_pem: self
                .trust_anchors_pem
                .unwrap_or_else(|| stored.trust_anchors_pem.clone()),
        }
    }
}

/// Move the secret out of its [`SecretString`] into the buffer the repository
/// takes, which zeroes itself on drop.
fn secret_buffer(secret: SecretString) -> Zeroizing<String> {
    Zeroizing::new(secret.expose_secret().to_owned())
}

/// Remove what sits between backticks and double quotes, keeping the
/// delimiters: serde's messages quote the offending *value* (`invalid type:
/// integer `12345`, expected a string`), and on these routes that value may be
/// the bind secret. `missing field` names a member of the schema, not a value,
/// so it is kept as it is.
pub(crate) fn scrub_serde_message(raw: &str) -> String {
    if raw.starts_with("missing field") {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut closing: Option<char> = None;
    for c in raw.chars() {
        match closing {
            Some(end) if c == end => {
                closing = None;
                out.push(c);
            }
            Some(_) => {}
            None => {
                out.push(c);
                if c == '`' || c == '"' {
                    closing = Some(c);
                }
            }
        }
    }
    out
}

/// The JSON extractor configuration of the routes that carry a bind secret:
/// the ordinary 64 KiB limit and an error handler that never echoes a value.
pub fn directory_json_config() -> web::JsonConfig {
    web::JsonConfig::default().limit(65_536).error_handler(
        |err: JsonPayloadError, _req: &HttpRequest| {
            let message = match &err {
                JsonPayloadError::Deserialize(inner) => format!(
                    "the request body is not a valid directory configuration: {}",
                    scrub_serde_message(&inner.to_string())
                ),
                JsonPayloadError::ContentType => {
                    "the request body must be application/json".to_string()
                }
                JsonPayloadError::Overflow { .. }
                | JsonPayloadError::OverflowKnownLength { .. } => {
                    "the request body is too large".to_string()
                }
                _ => "the request body could not be read".to_string(),
            };
            AxiamApiError(AxiamError::Validation { message }).into()
        },
    )
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// `{tenant_id}` must be the caller's tenant, as for `email_config`.
fn require_own_tenant(
    user: &AuthenticatedUser,
    tenant_id: Uuid,
    what: &str,
) -> Result<(), AxiamApiError> {
    if tenant_id != user.tenant_id {
        return Err(AxiamApiError(AxiamError::AuthorizationDenied {
            reason: format!("cannot {what} for a different tenant"),
            action: None,
            resource_id: None,
        }));
    }
    Ok(())
}

/// The machine-readable name of an address-guard rule, for the audit row.
const fn guard_rule(error: &GuardError) -> &'static str {
    match error {
        GuardError::InvalidUrl => "address_guard.invalid_url",
        GuardError::Ipv6Literal => "address_guard.ipv6_literal",
        GuardError::Unresolvable => "address_guard.unresolvable",
        GuardError::TooManyAddresses => "address_guard.too_many_addresses",
        GuardError::Loopback => "address_guard.loopback",
        GuardError::Unspecified => "address_guard.unspecified",
        GuardError::LinkLocal => "address_guard.link_local",
        GuardError::Multicast => "address_guard.multicast",
        GuardError::SpecialPurpose => "address_guard.special_purpose",
        GuardError::Metadata => "address_guard.metadata",
        GuardError::PrivateNotAllowed => "address_guard.private_not_allowed",
        GuardError::OwnListener => "address_guard.own_listener",
    }
}

/// The one audit rule every resolution-dependent refusal of a host **name**
/// is recorded under (F4 P23W3-04).
const RULE_NOT_PERMITTED: &str = "address_guard.not_permitted";

/// The one answer every resolution-dependent refusal of a host **name** gets
/// (F4 P23W3-04).
const HOST_NOT_PERMITTED: &str = "directory url: the directory host does not resolve to an \
     address this deployment permits a directory connection to; check the name, or ask the \
     deployment's operator whether its network is allowed";

/// Whether the URL's host is an IP literal (bracketed IPv6 included), so a
/// refusal that names the address's class reveals nothing the administrator did
/// not type.
fn host_is_ip_literal(url: &str) -> bool {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .is_some_and(|host| {
            host.trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok()
        })
}

/// What a tenant administrator is told about an address-guard refusal: the
/// `400` message and the audit rule (F4 P23W3-04).
///
/// For a host **name**, every refusal that depends on what the name resolved to
/// — it did not resolve, it resolved to too many addresses, to loopback,
/// link-local or the metadata service, unspecified, multicast or
/// special-purpose space, AXIAM's own listener, or a private range outside the
/// operator's allow-list — is **one** message and **one** rule, so the answer
/// cannot be used to map the deployment's internal DNS (which names exist, and
/// into which range they point). The specific rule goes to the operator's log
/// only. For an IP literal, and for a URL that is refused for its own text
/// (unparseable, IPv6 literal), the specific rule is the answer: it reveals
/// nothing the administrator did not type.
fn guard_refusal(error: &GuardError, url: &str) -> (&'static str, String) {
    let about_the_text = matches!(error, GuardError::InvalidUrl | GuardError::Ipv6Literal);
    if about_the_text || host_is_ip_literal(url) {
        (guard_rule(error), format!("directory url: {error}"))
    } else {
        (RULE_NOT_PERMITTED, HOST_NOT_PERMITTED.to_owned())
    }
}

/// The audit rule name of the P23W2-01 refusal.
const RULE_CONNECTION_MOVED: &str = "connection_moved_without_secret";

/// Every member name a configuration has, for a create's audit row.
const ALL_FIELDS: [&str; 16] = [
    "enabled",
    "kind",
    "url",
    "start_tls",
    "bind_dn",
    "base_dn",
    "user_filter",
    "user_attribute_map",
    "group_base_dn",
    "group_filter",
    "group_member_attribute",
    "group_nesting_depth",
    "group_mappings",
    "sync_interval_secs",
    "jit_provisioning",
    "trust_anchors_pem",
];

/// The **names** of the members `new` changes relative to `old`. Names only:
/// never a value, so no filter, DN, URL or anchor reaches the audit log through
/// this list.
fn changed_fields(old: Option<&DirectoryConfig>, new: &NewDirectoryConfig) -> Vec<&'static str> {
    let Some(old) = old else {
        return ALL_FIELDS.to_vec();
    };
    let mut out = Vec::new();
    let mut note = |differs: bool, name: &'static str| {
        if differs {
            out.push(name);
        }
    };
    note(old.enabled != new.enabled, "enabled");
    note(old.kind != new.kind, "kind");
    note(old.url != new.url, "url");
    note(old.start_tls != new.start_tls, "start_tls");
    note(old.bind_dn != new.bind_dn, "bind_dn");
    note(old.base_dn != new.base_dn, "base_dn");
    note(old.user_filter != new.user_filter, "user_filter");
    note(
        old.user_attribute_map != new.user_attribute_map,
        "user_attribute_map",
    );
    note(old.group_base_dn != new.group_base_dn, "group_base_dn");
    note(old.group_filter != new.group_filter, "group_filter");
    note(
        old.group_member_attribute != new.group_member_attribute,
        "group_member_attribute",
    );
    note(
        old.group_nesting_depth != new.group_nesting_depth,
        "group_nesting_depth",
    );
    note(old.group_mappings != new.group_mappings, "group_mappings");
    note(
        old.sync_interval_secs != new.sync_interval_secs,
        "sync_interval_secs",
    );
    note(
        old.jit_provisioning != new.jit_provisioning,
        "jit_provisioning",
    );
    note(
        old.trust_anchors_pem != new.trust_anchors_pem,
        "trust_anchors_pem",
    );
    out
}

/// Whether `new` moves the connection the stored secret is used on: the URL,
/// StartTLS, the bind DN or the trust anchors (CONTRACT §30.3 rule 2). A
/// configuration that does not exist yet has no stored secret to misdirect, but
/// is reported as moved, because the connection is new.
fn connection_moved(old: Option<&DirectoryConfig>, new: &NewDirectoryConfig) -> bool {
    old.is_none_or(|old| {
        old.url != new.url
            || old.start_tls != new.start_tls
            || old.bind_dn != new.bind_dn
            || old.trust_anchors_pem != new.trust_anchors_pem
    })
}

/// One audit row for a configuration change, never failing the request: the
/// write it describes has been done, or refused, already.
#[allow(clippy::too_many_arguments)] // an audit row is this wide
async fn audit<C: Connection + Clone>(
    state: &AppState<C>,
    http_req: &HttpRequest,
    user: &AuthenticatedUser,
    tenant_id: Uuid,
    action: &str,
    resource_id: Option<Uuid>,
    outcome: AuditOutcome,
    metadata: serde_json::Value,
) {
    if let Err(error) = state
        .audit_repo
        .append(CreateAuditLogEntry {
            tenant_id,
            actor_id: user.user_id,
            actor_type: ActorType::User,
            action: action.to_string(),
            resource_id,
            outcome,
            ip_address: client_ip(http_req),
            metadata: Some(metadata),
        })
        .await
    {
        tracing::error!(
            target: "axiam::directory",
            %tenant_id,
            action,
            %error,
            "a directory configuration audit row could not be written"
        );
    }
}

/// `409` when an enabled directory would sit under an effective
/// `opaque_mode = required` (CONTRACT §30.3 rule 3). A disabled configuration
/// may coexist; enabling it is then the refused write.
async fn refuse_under_opaque_required<C: Connection + Clone>(
    state: &AppState<C>,
    user: &AuthenticatedUser,
    tenant_id: Uuid,
    enabled: bool,
) -> Result<(), AxiamApiError> {
    if !enabled {
        return Ok(());
    }
    let settings = state
        .settings_repo
        .get_effective_settings(user.org_id, tenant_id)
        .await?;
    if settings.opaque.opaque_mode == OpaqueMode::Required {
        return Err(AxiamApiError(AxiamError::Conflict {
            reason: "an enabled directory cannot coexist with opaque_mode `required`: under \
                     `required` the tenant refuses password sign-in before reading a password, \
                     so directory accounts could not sign in at all. Lower opaque_mode, or save \
                     the directory with enabled set to false"
                .into(),
        }));
    }
    Ok(())
}

/// The whole write pipeline shared by `PUT` and `PATCH` (see the module docs for
/// the order). Returns the stored configuration and whether it was created.
async fn write_config<C: Connection + Clone>(
    state: &AppState<C>,
    http_req: &HttpRequest,
    user: &AuthenticatedUser,
    tenant_id: Uuid,
    stored: Option<DirectoryConfig>,
    input: NewDirectoryConfig,
) -> Result<(DirectoryConfig, bool), AxiamApiError> {
    let repo = &state.directory.config_repo;
    let action = if stored.is_some() {
        AUDIT_CONFIG_UPDATED
    } else {
        AUDIT_CONFIG_CREATED
    };
    let moved = connection_moved(stored.as_ref(), &input);
    let changed = changed_fields(stored.as_ref(), &input);
    let secret_replaced = input.bind_secret.is_some();
    let resource_id = stored.as_ref().map(|c| c.id);

    // 1. The deployment may not have the feature. Only a write that carries a
    //    secret needs the key; the response does not name it.
    if secret_replaced && !repo.has_encryption_key() {
        tracing::warn!(
            target: "axiam::directory",
            %tenant_id,
            "a directory write was refused: directory_encryption_key \
             (AXIAM__AUTH__DIRECTORY_ENCRYPTION_KEY) is not configured"
        );
        return Err(AxiamApiError(AxiamError::ServiceUnavailable(
            "the directory feature is not available on this deployment".into(),
        )));
    }

    // 2. The same validation the bind path trusts. The message names the field
    //    and the rule and never a value.
    validate_config(&input).map_err(AxiamError::from)?;

    // 3. The address guard, on the URL as written — for a write whose
    //    *resulting* configuration is enabled (D-33). A disabled directory opens
    //    no connection, so an administrator can always switch one off, even when
    //    its stored name has since been re-pointed to a refused address; the
    //    connect-time guard still covers anything that does connect, and
    //    re-enabling runs this check. `validate` above and P23W2-01 below apply
    //    to every write, enabled or not.
    let guarded: Result<(), GuardError> = if input.enabled {
        state.directory.client.guard(&input.url).await.map(|_| ())
    } else {
        Ok(())
    };
    if let Err(error) = guarded {
        let (rule, message) = guard_refusal(&error, &input.url);
        // The specific rule, for the operator; the administrator's answer and
        // audit row carry `rule` (P23W3-04).
        tracing::info!(
            target: "axiam::directory",
            %tenant_id,
            rule = guard_rule(&error),
            "a directory write was refused by the address guard"
        );
        audit(
            state,
            http_req,
            user,
            tenant_id,
            action,
            resource_id,
            AuditOutcome::Failure,
            serde_json::json!({
                "rule": rule,
                "connection_moved": moved,
                "changed_fields": changed,
                "secret_replaced": secret_replaced,
            }),
        )
        .await;
        return Err(AxiamApiError(AxiamError::Validation { message }));
    }

    // 4. P23W2-01. A configuration that does not exist yet needs its secret
    //    whatever it moves.
    if stored.is_none() && !secret_replaced {
        return Err(AxiamApiError(AxiamError::Validation {
            message: "a directory configuration requires a bind_secret when it is created".into(),
        }));
    }
    if stored.is_some() && moved && !secret_replaced {
        audit_connection_refusal(
            state,
            http_req,
            user,
            tenant_id,
            action,
            resource_id,
            &changed,
        )
        .await;
        return Err(AxiamApiError(AxiamError::Validation {
            message: CONNECTION_MOVED_WITHOUT_SECRET.into(),
        }));
    }

    // 5. A directory and `opaque_mode = required` never coexist.
    refuse_under_opaque_required(state, user, tenant_id, input.enabled).await?;

    // The live-account count rides the audit row of a disable (§30.3 rule 5).
    let disabling = stored.as_ref().is_some_and(|c| c.enabled) && !input.enabled;
    let live_accounts = if disabling {
        state
            .user_repo
            .count_live_directory_accounts(tenant_id)
            .await
            .ok()
    } else {
        None
    };

    // 6. The write.
    let (config, created) = if stored.is_some() {
        match repo.update(input).await {
            Ok(config) => (config, false),
            // The repository compares against the stored row in the same
            // statement as the write, so a connection that moved between the
            // read above and the write is refused here, with the same rule.
            Err(AxiamError::Validation { message })
                if message == CONNECTION_MOVED_WITHOUT_SECRET =>
            {
                audit_connection_refusal(
                    state,
                    http_req,
                    user,
                    tenant_id,
                    action,
                    resource_id,
                    &changed,
                )
                .await;
                return Err(AxiamApiError(AxiamError::Validation { message }));
            }
            Err(other) => return Err(other.into()),
        }
    } else {
        (repo.create(input).await?, true)
    };

    let mut metadata = serde_json::json!({
        "changed_fields": changed,
        "connection_moved": moved,
        "secret_replaced": secret_replaced,
        "enabled": config.enabled,
    });
    if let (Some(count), Some(object)) = (live_accounts, metadata.as_object_mut()) {
        object.insert("live_directory_accounts".into(), count.into());
    }
    audit(
        state,
        http_req,
        user,
        tenant_id,
        action,
        Some(config.id),
        AuditOutcome::Success,
        metadata,
    )
    .await;
    Ok((config, created))
}

async fn audit_connection_refusal<C: Connection + Clone>(
    state: &AppState<C>,
    http_req: &HttpRequest,
    user: &AuthenticatedUser,
    tenant_id: Uuid,
    action: &str,
    resource_id: Option<Uuid>,
    changed: &[&'static str],
) {
    audit(
        state,
        http_req,
        user,
        tenant_id,
        action,
        resource_id,
        AuditOutcome::Failure,
        serde_json::json!({
            "rule": RULE_CONNECTION_MOVED,
            "connection_moved": true,
            "changed_fields": changed,
            "secret_replaced": false,
        }),
    )
    .await;
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/tenants/{tenant_id}/directory`
#[utoipa::path(
    get,
    path = "/api/v1/tenants/{tenant_id}/directory",
    tag = "directory",
    params(("tenant_id" = Uuid, Path, description = "Tenant ID")),
    responses(
        (status = 200, description = "The tenant's directory configuration (the bind secret is never returned)",
         body = DirectoryConfig),
        (status = 404, description = "The tenant has no directory configuration"),
    ),
    security(("bearer" = []))
)]
pub async fn get_directory<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("directory:read", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();
    require_own_tenant(&user, tenant_id, "read the directory configuration")?;

    match state.directory.config_repo.get_by_tenant(tenant_id).await? {
        Some(config) => Ok(HttpResponse::Ok().json(config)),
        None => Err(AxiamApiError(AxiamError::NotFound {
            entity: "directory_config".into(),
            id: tenant_id.to_string(),
        })),
    }
}

/// `PUT /api/v1/tenants/{tenant_id}/directory` — create or **replace**.
///
/// A replacement resets every omitted optional member to its default. `bind_secret`
/// is required on create; on a replacement, absent keeps the stored secret —
/// unless the write moves `url`, `start_tls`, `bind_dn` or `trust_anchors_pem`,
/// which is a `400` without it.
#[utoipa::path(
    put,
    path = "/api/v1/tenants/{tenant_id}/directory",
    tag = "directory",
    params(("tenant_id" = Uuid, Path, description = "Tenant ID")),
    request_body = SetDirectoryConfig,
    responses(
        (status = 201, description = "The configuration was created", body = DirectoryConfig),
        (status = 200, description = "The configuration was replaced", body = DirectoryConfig),
        (status = 400, description = "Validation or address-guard refusal, or the connection \
                                      moved without the bind secret"),
        (status = 403, description = "Another tenant's configuration"),
        (status = 409, description = "An enabled directory under opaque_mode `required`"),
        (status = 503, description = "The deployment has no directory encryption key"),
    ),
    security(("bearer" = []))
)]
pub async fn set_directory<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<SetDirectoryConfig>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("directory:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();
    require_own_tenant(&user, tenant_id, "modify the directory configuration")?;

    let stored = state.directory.config_repo.get_by_tenant(tenant_id).await?;
    let input = body.into_inner().into_input(tenant_id);
    let (config, created) =
        write_config(&state, &http_req, &user, tenant_id, stored, input).await?;
    Ok(if created {
        HttpResponse::Created().json(config)
    } else {
        HttpResponse::Ok().json(config)
    })
}

/// `PATCH /api/v1/tenants/{tenant_id}/directory` — a **sparse** update.
#[utoipa::path(
    patch,
    path = "/api/v1/tenants/{tenant_id}/directory",
    tag = "directory",
    params(("tenant_id" = Uuid, Path, description = "Tenant ID")),
    request_body = UpdateDirectoryConfig,
    responses(
        (status = 200, description = "The configuration after the change", body = DirectoryConfig),
        (status = 400, description = "Validation or address-guard refusal, or the connection \
                                      moved without the bind secret"),
        (status = 403, description = "Another tenant's configuration"),
        (status = 404, description = "The tenant has no directory configuration"),
        (status = 409, description = "An enabled directory under opaque_mode `required`"),
        (status = 503, description = "The deployment has no directory encryption key"),
    ),
    security(("bearer" = []))
)]
pub async fn update_directory<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<UpdateDirectoryConfig>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("directory:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();
    require_own_tenant(&user, tenant_id, "modify the directory configuration")?;

    let stored = state
        .directory
        .config_repo
        .get_by_tenant(tenant_id)
        .await?
        .ok_or_else(|| {
            AxiamApiError(AxiamError::NotFound {
                entity: "directory_config".into(),
                id: tenant_id.to_string(),
            })
        })?;
    let input = body.into_inner().merge_onto(&stored);
    let (config, _created) =
        write_config(&state, &http_req, &user, tenant_id, Some(stored), input).await?;
    Ok(HttpResponse::Ok().json(config))
}

/// `DELETE /api/v1/tenants/{tenant_id}/directory`
///
/// Removes the configuration and its sync state. Directory accounts can no
/// longer sign in with a password (there is no fallback to a local hash) and the
/// sync job stops for the tenant; sessions, refresh tokens and passkeys they
/// already hold keep working until they expire or an administrator deactivates
/// the accounts. There is no unlink.
#[utoipa::path(
    delete,
    path = "/api/v1/tenants/{tenant_id}/directory",
    tag = "directory",
    params(("tenant_id" = Uuid, Path, description = "Tenant ID")),
    responses(
        (status = 204, description = "The configuration and its sync state are gone"),
        (status = 403, description = "Another tenant's configuration"),
    ),
    security(("bearer" = []))
)]
pub async fn delete_directory<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("directory:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();
    require_own_tenant(&user, tenant_id, "delete the directory configuration")?;

    let stored = state.directory.config_repo.get_by_tenant(tenant_id).await?;
    // Counted before the configuration goes: what the delete leaves behind.
    let live_accounts = if stored.is_some() {
        state
            .user_repo
            .count_live_directory_accounts(tenant_id)
            .await
            .ok()
    } else {
        None
    };

    state.directory.config_repo.delete(tenant_id).await?;
    state.directory.sync_state_repo.delete(tenant_id).await?;

    if let Some(stored) = stored {
        audit(
            &state,
            &http_req,
            &user,
            tenant_id,
            AUDIT_CONFIG_DELETED,
            Some(stored.id),
            AuditOutcome::Success,
            serde_json::json!({
                "enabled_before": stored.enabled,
                "live_directory_accounts": live_accounts,
            }),
        )
        .await;
    }
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /api/v1/tenants/{tenant_id}/directory/links` — link a local account to
/// its directory entry (D-28).
///
/// The directory resolves the entry from the account's own username; the caller
/// supplies only the account. Marks the account, deletes its WebAuthn
/// credentials and federation links, revokes its `User`-type certificates and
/// then all its sessions
/// and OAuth2 refresh tokens (TOTP is kept): **the owner is signed out
/// everywhere**. Idempotent: an account already linked to that entry gets `200`
/// with `was_already_linked: true` and the revocations run again.
#[utoipa::path(
    post,
    path = "/api/v1/tenants/{tenant_id}/directory/links",
    tag = "directory",
    params(("tenant_id" = Uuid, Path, description = "Tenant ID")),
    request_body = LinkDirectoryAccount,
    responses(
        (status = 200, description = "The account is linked", body = DirectoryLinkResult),
        (status = 400, description = "The account is deleted"),
        (status = 403, description = "Another tenant's account"),
        (status = 404, description = "Unknown account, or the directory has no single entry for it"),
        (status = 409, description = "No enabled directory, the entry is linked to another \
                                      account, or the account to a different entry"),
        (status = 503, description = "The directory cannot be asked"),
    ),
    security(("bearer" = []))
)]
pub async fn link_account<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<LinkDirectoryAccount>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("directory:link", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();
    require_own_tenant(&user, tenant_id, "link an account")?;

    let outcome = state
        .auth_service
        .link_local_account_to_directory(
            tenant_id,
            body.user_id,
            user.user_id,
            client_ip(&http_req),
            &state.webauthn.webauthn_credential_repo,
            &state.pki.cert_repo,
        )
        .await?;
    Ok(HttpResponse::Ok().json(DirectoryLinkResult {
        user_id: outcome.user.id,
        directory_external_id: outcome.user.directory_external_id.unwrap_or_default(),
        webauthn_credentials_deleted: outcome.webauthn_credentials_deleted,
        certificates_revoked: outcome.certificates_revoked,
        was_already_linked: outcome.was_already_linked,
    }))
}

/// `GET /api/v1/tenants/{tenant_id}/directory/sync-status`
#[utoipa::path(
    get,
    path = "/api/v1/tenants/{tenant_id}/directory/sync-status",
    tag = "directory",
    params(("tenant_id" = Uuid, Path, description = "Tenant ID")),
    responses(
        (status = 200, description = "The sync job's state; nulls before the first run",
         body = DirectorySyncStatus),
        (status = 404, description = "The tenant has no directory configuration"),
    ),
    security(("bearer" = []))
)]
pub async fn get_sync_status<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("directory:read", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();
    require_own_tenant(&user, tenant_id, "read the directory sync status")?;

    if state
        .directory
        .config_repo
        .get_by_tenant(tenant_id)
        .await?
        .is_none()
    {
        return Err(AxiamApiError(AxiamError::NotFound {
            entity: "directory_config".into(),
            id: tenant_id.to_string(),
        }));
    }
    let status = match state.directory.sync_state_repo.get(tenant_id).await? {
        Some(sync) => DirectorySyncStatus {
            last_result: sync.last_result.map(|r| r.as_str().to_string()),
            last_attempt_at: sync.last_attempt_at,
            last_full_run_at: sync.last_full_run_at,
            full_required: sync.full_required,
            has_watermark: sync.watermark.is_some(),
        },
        None => DirectorySyncStatus {
            last_result: None,
            last_attempt_at: None,
            last_full_run_at: None,
            full_required: false,
            has_watermark: false,
        },
    };
    Ok(HttpResponse::Ok().json(status))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_removes_quoted_values_and_keeps_the_shape() {
        let scrubbed = scrub_serde_message(
            "invalid type: integer `987654321`, expected a string at line 1 column 40",
        );
        assert!(!scrubbed.contains("987654321"));
        assert!(scrubbed.contains("expected a string"));

        let scrubbed = scrub_serde_message("invalid type: string \"hunter22\", expected a boolean");
        assert!(!scrubbed.contains("hunter22"));
        assert!(scrubbed.contains("expected a boolean"));
    }

    #[test]
    fn scrub_keeps_a_missing_field_name() {
        assert_eq!(
            scrub_serde_message("missing field `url` at line 1 column 2"),
            "missing field `url` at line 1 column 2"
        );
    }

    #[test]
    fn the_request_types_print_no_secret() {
        let marker = format!("marker-{}", Uuid::new_v4().simple());
        let body: SetDirectoryConfig = serde_json::from_value(serde_json::json!({
            "enabled": true, "kind": "open_ldap", "url": "ldaps://ldap.example.com",
            "start_tls": false, "bind_dn": "cn=svc,dc=example,dc=com",
            "bind_secret": marker, "base_dn": "dc=example,dc=com",
            "user_filter": "(uid={username})"
        }))
        .unwrap();
        assert!(!format!("{body:?}").contains(&marker));
        let patch: UpdateDirectoryConfig =
            serde_json::from_value(serde_json::json!({ "bind_secret": marker })).unwrap();
        assert!(!format!("{patch:?}").contains(&marker));
    }

    #[test]
    fn patch_tells_null_from_absent() {
        let absent: UpdateDirectoryConfig = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(absent.group_filter.is_none());
        let cleared: UpdateDirectoryConfig =
            serde_json::from_value(serde_json::json!({ "group_filter": null })).unwrap();
        assert_eq!(cleared.group_filter, Some(None));
        let set: UpdateDirectoryConfig =
            serde_json::from_value(serde_json::json!({ "group_filter": "(cn=*)" })).unwrap();
        assert_eq!(set.group_filter, Some(Some("(cn=*)".to_string())));
    }
}
