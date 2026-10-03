//! Configuration-time validation of a directory configuration.
//!
//! [`validate`] is a pure function over a [`NewDirectoryConfig`], so every
//! refusal can be unit-tested without a directory and without a database. It
//! is the single place the rules live: the REST handler (a later task) calls it
//! before the repository is reached, and the repository, which sits a layer
//! below this crate, deliberately does not repeat them.
//!
//! # What is refused, and why here
//!
//! * **Plaintext transport.** An `ldap://` URL without StartTLS, any other
//!   scheme, and the contradictory `ldaps://` with StartTLS. A directory bind
//!   carries the user's password, so a configuration that could ever send it in
//!   the clear is refused when it is *saved*, not discovered at the first login.
//! * **A URL that smuggles anything else:** userinfo (a credential in a URL is
//!   a credential in a log), a path, a query, a fragment.
//! * **A filter template that cannot be made safe.** The user filter must carry
//!   exactly one `{username}` placeholder, in value position (directly after
//!   `=`), inside a single balanced filter. The bind path substitutes the
//!   RFC 4515-escaped login name there; the template is never formatted with raw
//!   input. A placeholder in attribute-name position would make that escaping
//!   meaningless, so it is refused.
//! * **An empty bind secret.** A DN with an empty password is an RFC 4513
//!   "unauthenticated bind", which many servers accept as success.
//! * **Trust anchors that are not CA certificates.** A leaf pasted as an anchor
//!   would pin one server certificate and fail at the next renewal, or, worse,
//!   be mistaken for a CA by whoever reads the configuration.
//!
//! Error messages are fixed text. They never repeat the offending value: a URL
//! may carry a password, and a refusal must not be the thing that logs it.
//!
//! # DN syntax is checked loosely on purpose
//!
//! A distinguished name is non-empty, free of control characters and bounded in
//! length, and nothing more. In particular a DN is **not** required to contain
//! `=`: Active Directory accepts a User Principal Name (`svc@corp.example.com`)
//! as the bind identity, and a stricter check would refuse a common, correct
//! configuration. Whether the server accepts the DN is learned by binding.

use axiam_core::error::AxiamError;
use axiam_core::models::directory::NewDirectoryConfig;
use url::Url;
use x509_parser::prelude::{FromDer, X509Certificate};

/// Longest accepted server URL, in bytes.
pub const URL_MAX_LEN: usize = 2048;
/// Longest accepted distinguished name, in bytes.
pub const DN_MAX_LEN: usize = 1024;
/// Longest accepted filter template, in bytes.
pub const FILTER_MAX_LEN: usize = 512;
/// Longest accepted attribute name, in bytes.
pub const ATTRIBUTE_MAX_LEN: usize = 64;
/// Longest accepted bind secret, in bytes.
pub const BIND_SECRET_MAX_LEN: usize = 4096;
/// Most trust anchors one configuration may carry.
pub const TRUST_ANCHORS_MAX: usize = 16;
/// Longest accepted PEM text for a single trust anchor, in bytes.
pub const TRUST_ANCHOR_MAX_LEN: usize = 32 * 1024;

/// The placeholder the user filter template must carry exactly once.
pub const USERNAME_PLACEHOLDER: &str = "{username}";

/// Deepest group nesting that may be configured.
pub const GROUP_NESTING_DEPTH_MAX: u8 = 10;
/// Group nesting depth a new configuration starts with.
pub const GROUP_NESTING_DEPTH_DEFAULT: u8 = 5;

/// Shortest sync interval, in seconds (five minutes). Shorter would let a
/// misconfigured tenant turn the sync job into a load generator against its own
/// directory.
pub const SYNC_INTERVAL_MIN_SECS: u64 = 300;
/// Longest sync interval, in seconds (one day).
pub const SYNC_INTERVAL_MAX_SECS: u64 = 86_400;
/// Sync interval a new configuration starts with (one hour).
pub const SYNC_INTERVAL_DEFAULT_SECS: u64 = 3_600;

/// Why a directory configuration was refused. The first defect found is
/// reported; the messages are fixed text and never echo the offending value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The server URL is unacceptable.
    #[error("directory url: {0}")]
    Url(UrlDefect),
    /// A distinguished name is unacceptable.
    #[error("directory {field}: {defect}")]
    Dn {
        /// The configuration field that carried the DN.
        field: &'static str,
        /// What is wrong with it.
        defect: DnDefect,
    },
    /// The bind secret is unacceptable.
    #[error("directory bind secret: {0}")]
    BindSecret(SecretDefect),
    /// A filter (the user filter template or the group filter) is unacceptable.
    #[error("directory {field}: {defect}")]
    Filter {
        /// The configuration field that carried the filter.
        field: &'static str,
        /// What is wrong with it.
        defect: FilterDefect,
    },
    /// An attribute name is unacceptable.
    #[error("directory {field}: {defect}")]
    Attribute {
        /// The configuration field that carried the attribute name.
        field: &'static str,
        /// What is wrong with it.
        defect: AttributeDefect,
    },
    /// The group nesting depth is outside `0..=GROUP_NESTING_DEPTH_MAX`.
    #[error("directory group_nesting_depth must be between 0 and {GROUP_NESTING_DEPTH_MAX}")]
    NestingDepth,
    /// The sync interval is outside the permitted bounds.
    #[error(
        "directory sync_interval_secs must be between {SYNC_INTERVAL_MIN_SECS} and \
         {SYNC_INTERVAL_MAX_SECS} seconds"
    )]
    SyncInterval,
    /// More trust anchors than [`TRUST_ANCHORS_MAX`].
    #[error("directory trust_anchors_pem may hold at most {TRUST_ANCHORS_MAX} certificates")]
    TooManyTrustAnchors,
    /// One trust anchor is unacceptable.
    #[error("directory trust anchor #{index}: {defect}")]
    TrustAnchor {
        /// Zero-based position in `trust_anchors_pem`.
        index: usize,
        /// What is wrong with it.
        defect: AnchorDefect,
    },
}

/// What is wrong with a server URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UrlDefect {
    /// Longer than [`URL_MAX_LEN`].
    #[error("is too long")]
    TooLong,
    /// Contains whitespace or a control character, which the URL parser would
    /// silently strip or normalise, so the stored text and the parsed URL could
    /// differ.
    #[error("must not contain whitespace or control characters")]
    WhitespaceOrControl,
    /// Not parseable as a URL.
    #[error("is not a valid URL")]
    Malformed,
    /// A scheme other than `ldap` or `ldaps`.
    #[error("scheme must be ldaps:// or ldap:// with start_tls")]
    UnsupportedScheme,
    /// No host.
    #[error("must name a host")]
    MissingHost,
    /// Carries a user name or password.
    #[error("must not carry user information")]
    HasUserinfo,
    /// Has a path other than `/`.
    #[error("must not have a path")]
    HasPath,
    /// Has a query.
    #[error("must not have a query")]
    HasQuery,
    /// Has a fragment.
    #[error("must not have a fragment")]
    HasFragment,
    /// `ldap://` without `start_tls`: the bind would be sent in the clear.
    #[error("plaintext ldap:// is refused; use ldaps:// or enable start_tls")]
    PlaintextWithoutStartTls,
    /// `ldaps://` together with `start_tls`: the connection is already
    /// encrypted from the first byte, so StartTLS is contradictory.
    #[error("ldaps:// is already encrypted; start_tls must be false")]
    StartTlsOnLdaps,
}

/// What is wrong with a distinguished name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DnDefect {
    /// Empty or only whitespace.
    #[error("must not be empty")]
    Empty,
    /// Contains a control character.
    #[error("must not contain control characters")]
    ControlCharacter,
    /// Longer than [`DN_MAX_LEN`].
    #[error("is too long")]
    TooLong,
}

/// What is wrong with a bind secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SecretDefect {
    /// Empty, which many directories treat as an unauthenticated bind.
    #[error("must not be empty")]
    Empty,
    /// Longer than [`BIND_SECRET_MAX_LEN`].
    #[error("is too long")]
    TooLong,
}

/// What is wrong with a filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FilterDefect {
    /// Empty.
    #[error("must not be empty")]
    Empty,
    /// Longer than [`FILTER_MAX_LEN`].
    #[error("is too long")]
    TooLong,
    /// Contains a control character.
    #[error("must not contain control characters")]
    ControlCharacter,
    /// Does not start with `(` and end with `)`.
    #[error("must be a parenthesised filter such as (uid={{username}})")]
    NotParenthesised,
    /// Parentheses do not balance.
    #[error("has unbalanced parentheses")]
    Unbalanced,
    /// More than one top-level filter, e.g. `(a=b)(c=d)`.
    #[error("must be a single filter; combine several with (&...) or (|...)")]
    NotSingleFilter,
    /// The user filter does not contain `{username}` exactly once.
    #[error("must contain the {{username}} placeholder exactly once")]
    PlaceholderCount,
    /// A `{` or `}` outside the one `{username}` placeholder.
    #[error("must not contain braces other than the {{username}} placeholder")]
    StrayBrace,
    /// The placeholder is not directly after `=`, so the escaping applied to
    /// the substituted value would not be protecting an attribute *value*.
    #[error("the {{username}} placeholder must directly follow '=' (attribute value position)")]
    PlaceholderPosition,
    /// The group filter has no placeholder: it is static.
    #[error("must not contain a {{username}} placeholder or braces")]
    PlaceholderNotAllowed,
}

/// What is wrong with an attribute name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AttributeDefect {
    /// Empty.
    #[error("must not be empty")]
    Empty,
    /// Longer than [`ATTRIBUTE_MAX_LEN`].
    #[error("is too long")]
    TooLong,
    /// Not a plain attribute name: a letter followed by letters, digits and
    /// hyphens.
    #[error("must be a plain attribute name (letters, digits and '-', starting with a letter)")]
    InvalidCharacters,
}

/// What is wrong with a trust anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AnchorDefect {
    /// Longer than [`TRUST_ANCHOR_MAX_LEN`].
    #[error("is too large")]
    TooLarge,
    /// Not PEM text.
    #[error("is not PEM-encoded")]
    NotPem,
    /// PEM, but not a `CERTIFICATE` block.
    #[error("is not a CERTIFICATE PEM block")]
    NotCertificateBlock,
    /// More than one PEM block in a single entry; one certificate per entry.
    #[error("must contain exactly one certificate per entry")]
    MoreThanOneBlock,
    /// The DER inside does not parse as an X.509 certificate.
    #[error("is not a parseable X.509 certificate")]
    Unparseable,
    /// A certificate whose Basic Constraints do not say `CA:TRUE`.
    #[error("is not a CA certificate (Basic Constraints must say CA:TRUE)")]
    NotCa,
}

impl From<ConfigError> for AxiamError {
    fn from(err: ConfigError) -> Self {
        AxiamError::Validation {
            message: err.to_string(),
        }
    }
}

/// Validate a directory configuration before it is stored.
///
/// Pure: no network, no database, no clock. Returns the first defect found.
/// The secret is checked only when present, because an update that omits it
/// keeps the stored one; that `create` requires a secret is the repository's
/// rule.
///
/// # Errors
///
/// A [`ConfigError`] naming the field and the defect, never its value.
pub fn validate(input: &NewDirectoryConfig) -> Result<(), ConfigError> {
    validate_url(&input.url, input.start_tls).map_err(ConfigError::Url)?;
    validate_dn("bind_dn", &input.bind_dn)?;
    validate_dn("base_dn", &input.base_dn)?;
    if let Some(secret) = &input.bind_secret {
        if secret.is_empty() {
            return Err(ConfigError::BindSecret(SecretDefect::Empty));
        }
        if secret.len() > BIND_SECRET_MAX_LEN {
            return Err(ConfigError::BindSecret(SecretDefect::TooLong));
        }
    }
    validate_user_filter(&input.user_filter)?;

    let map = &input.user_attribute_map;
    validate_attribute("user_attribute_map.username", &map.username)?;
    validate_attribute("user_attribute_map.email", &map.email)?;
    validate_attribute("user_attribute_map.display_name", &map.display_name)?;
    validate_attribute("user_attribute_map.external_id", &map.external_id)?;

    if let Some(group_base_dn) = &input.group_base_dn {
        validate_dn("group_base_dn", group_base_dn)?;
    }
    if let Some(group_filter) = &input.group_filter {
        validate_group_filter(group_filter)?;
    }
    validate_attribute("group_member_attribute", &input.group_member_attribute)?;

    if input.group_nesting_depth > GROUP_NESTING_DEPTH_MAX {
        return Err(ConfigError::NestingDepth);
    }
    if !(SYNC_INTERVAL_MIN_SECS..=SYNC_INTERVAL_MAX_SECS).contains(&input.sync_interval_secs) {
        return Err(ConfigError::SyncInterval);
    }

    validate_trust_anchors(&input.trust_anchors_pem)
}

fn validate_url(raw: &str, start_tls: bool) -> Result<(), UrlDefect> {
    if raw.len() > URL_MAX_LEN {
        return Err(UrlDefect::TooLong);
    }
    // The URL parser strips surrounding whitespace and removes tabs and
    // newlines anywhere. Accepting such text would store one string and
    // connect to another, so it is refused rather than normalised.
    if raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(UrlDefect::WhitespaceOrControl);
    }
    let url = Url::parse(raw).map_err(|_| UrlDefect::Malformed)?;
    let ldaps = match url.scheme() {
        "ldaps" => true,
        "ldap" => false,
        _ => return Err(UrlDefect::UnsupportedScheme),
    };
    if url.host_str().is_none_or(str::is_empty) {
        return Err(UrlDefect::MissingHost);
    }
    // Checked on the raw text as well as on the parsed URL: the parser drops an
    // empty userinfo (`ldaps://@host`, `ldaps://:@host`), so the parsed form
    // looks clean while the stored string, which is what a client would be
    // handed, still carries the `@`.
    let raw_authority = raw.split_once("://").map_or("", |(_, rest)| {
        rest.split(['/', '?', '#']).next().unwrap_or("")
    });
    if raw_authority.contains('@') || url.authority().contains('@') {
        return Err(UrlDefect::HasUserinfo);
    }
    if !matches!(url.path(), "" | "/") {
        return Err(UrlDefect::HasPath);
    }
    if url.query().is_some() {
        return Err(UrlDefect::HasQuery);
    }
    if url.fragment().is_some() {
        return Err(UrlDefect::HasFragment);
    }
    match (ldaps, start_tls) {
        (true, true) => Err(UrlDefect::StartTlsOnLdaps),
        (false, false) => Err(UrlDefect::PlaintextWithoutStartTls),
        _ => Ok(()),
    }
}

fn validate_dn(field: &'static str, dn: &str) -> Result<(), ConfigError> {
    let defect = if dn.trim().is_empty() {
        DnDefect::Empty
    } else if dn.chars().any(char::is_control) {
        DnDefect::ControlCharacter
    } else if dn.len() > DN_MAX_LEN {
        DnDefect::TooLong
    } else {
        return Ok(());
    };
    Err(ConfigError::Dn { field, defect })
}

fn validate_attribute(field: &'static str, name: &str) -> Result<(), ConfigError> {
    let defect = if name.is_empty() {
        AttributeDefect::Empty
    } else if name.len() > ATTRIBUTE_MAX_LEN {
        AttributeDefect::TooLong
    } else if !name.starts_with(|c: char| c.is_ascii_alphabetic())
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        AttributeDefect::InvalidCharacters
    } else {
        return Ok(());
    };
    Err(ConfigError::Attribute { field, defect })
}

/// The shape every filter must have: one parenthesised, balanced expression.
fn check_filter_shape(filter: &str) -> Result<(), FilterDefect> {
    if filter.is_empty() {
        return Err(FilterDefect::Empty);
    }
    if filter.len() > FILTER_MAX_LEN {
        return Err(FilterDefect::TooLong);
    }
    if filter.chars().any(char::is_control) {
        return Err(FilterDefect::ControlCharacter);
    }
    if !filter.starts_with('(') || !filter.ends_with(')') {
        return Err(FilterDefect::NotParenthesised);
    }
    // RFC 4515 writes a literal parenthesis inside a value as `\28` / `\29`,
    // so every raw parenthesis is structural and a plain depth count is exact.
    let last = filter.len() - 1;
    let mut depth: usize = 0;
    for (i, c) in filter.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth = depth.checked_sub(1).ok_or(FilterDefect::Unbalanced)?;
                if depth == 0 && i != last {
                    // Closed before the end: either a second filter follows or
                    // the remainder is stray closing parentheses.
                    return Err(if filter[i + 1..].contains('(') {
                        FilterDefect::NotSingleFilter
                    } else {
                        FilterDefect::Unbalanced
                    });
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(FilterDefect::Unbalanced);
    }
    Ok(())
}

fn validate_user_filter(template: &str) -> Result<(), ConfigError> {
    let err = |defect| ConfigError::Filter {
        field: "user_filter",
        defect,
    };
    check_filter_shape(template).map_err(err)?;

    if template.matches(USERNAME_PLACEHOLDER).count() != 1 {
        return Err(err(FilterDefect::PlaceholderCount));
    }
    let without = template.replacen(USERNAME_PLACEHOLDER, "", 1);
    if without.contains(['{', '}']) {
        return Err(err(FilterDefect::StrayBrace));
    }
    // Value position only. The one occurrence is guaranteed above, so `find`
    // cannot miss; `unwrap_or(0)` keeps the function total without a panic.
    let at = template.find(USERNAME_PLACEHOLDER).unwrap_or(0);
    if !template[..at].ends_with('=') {
        return Err(err(FilterDefect::PlaceholderPosition));
    }
    Ok(())
}

fn validate_group_filter(filter: &str) -> Result<(), ConfigError> {
    let err = |defect| ConfigError::Filter {
        field: "group_filter",
        defect,
    };
    check_filter_shape(filter).map_err(err)?;
    if filter.contains(['{', '}']) {
        return Err(err(FilterDefect::PlaceholderNotAllowed));
    }
    Ok(())
}

fn validate_trust_anchors(anchors: &[String]) -> Result<(), ConfigError> {
    if anchors.len() > TRUST_ANCHORS_MAX {
        return Err(ConfigError::TooManyTrustAnchors);
    }
    for (index, pem) in anchors.iter().enumerate() {
        validate_trust_anchor(pem).map_err(|defect| ConfigError::TrustAnchor { index, defect })?;
    }
    Ok(())
}

fn validate_trust_anchor(pem: &str) -> Result<(), AnchorDefect> {
    if pem.len() > TRUST_ANCHOR_MAX_LEN {
        return Err(AnchorDefect::TooLarge);
    }
    let (rest, block) =
        x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|_| AnchorDefect::NotPem)?;
    if block.label != "CERTIFICATE" {
        return Err(AnchorDefect::NotCertificateBlock);
    }
    if !rest.iter().all(u8::is_ascii_whitespace) {
        return Err(AnchorDefect::MoreThanOneBlock);
    }
    let (_, cert) =
        X509Certificate::from_der(&block.contents).map_err(|_| AnchorDefect::Unparseable)?;
    let is_ca = cert
        .basic_constraints()
        .ok()
        .flatten()
        .is_some_and(|bc| bc.value.ca);
    if !is_ca {
        return Err(AnchorDefect::NotCa);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::directory::DirectoryKind;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    use uuid::Uuid;
    use zeroize::Zeroizing;

    /// A configuration that validates; each test breaks exactly one thing.
    fn valid() -> NewDirectoryConfig {
        NewDirectoryConfig {
            tenant_id: Uuid::nil(),
            enabled: true,
            kind: DirectoryKind::OpenLdap,
            url: "ldaps://ldap.example.com:636".into(),
            start_tls: false,
            bind_dn: "cn=svc-axiam,dc=example,dc=com".into(),
            bind_secret: Some(Zeroizing::new("fixture-bind-secret".to_string())),
            base_dn: "ou=people,dc=example,dc=com".into(),
            user_filter: "(&(objectClass=inetOrgPerson)(uid={username}))".into(),
            user_attribute_map: DirectoryKind::OpenLdap.default_user_attribute_map(),
            group_base_dn: Some("ou=groups,dc=example,dc=com".into()),
            group_filter: Some("(objectClass=groupOfNames)".into()),
            group_member_attribute: "member".into(),
            group_nesting_depth: GROUP_NESTING_DEPTH_DEFAULT,
            sync_interval_secs: SYNC_INTERVAL_DEFAULT_SECS,
            jit_provisioning: true,
            trust_anchors_pem: vec![],
        }
    }

    fn with_url(url: &str, start_tls: bool) -> NewDirectoryConfig {
        NewDirectoryConfig {
            url: url.into(),
            start_tls,
            ..valid()
        }
    }

    fn url_defect(url: &str, start_tls: bool) -> UrlDefect {
        match validate(&with_url(url, start_tls)) {
            Err(ConfigError::Url(defect)) => defect,
            other => panic!("expected a URL refusal for the case under test, got {other:?}"),
        }
    }

    fn ca_pem() -> String {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.self_signed(&key).unwrap().pem()
    }

    fn leaf_pem() -> String {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["ldap.example.com".to_string()]).unwrap();
        params.is_ca = IsCa::NoCa;
        params.self_signed(&key).unwrap().pem()
    }

    // --- accepted shapes -------------------------------------------------

    #[test]
    fn the_baseline_configuration_is_accepted() {
        assert_eq!(validate(&valid()), Ok(()));
    }

    #[test]
    fn ldaps_with_a_port_is_accepted() {
        assert_eq!(
            validate(&with_url("ldaps://host.example.com:636", false)),
            Ok(())
        );
    }

    #[test]
    fn ldaps_without_a_port_is_accepted() {
        assert_eq!(
            validate(&with_url("ldaps://host.example.com", false)),
            Ok(())
        );
    }

    #[test]
    fn ldap_with_start_tls_is_accepted() {
        assert_eq!(
            validate(&with_url("ldap://host.example.com:389", true)),
            Ok(())
        );
    }

    #[test]
    fn an_ipv6_host_is_accepted_over_both_tls_shapes() {
        assert_eq!(
            validate(&with_url("ldaps://[2001:db8::10]:636", false)),
            Ok(())
        );
        assert_eq!(validate(&with_url("ldap://[::1]:389", true)), Ok(()));
    }

    #[test]
    fn a_single_trailing_slash_is_accepted() {
        assert_eq!(
            validate(&with_url("ldaps://host.example.com/", false)),
            Ok(())
        );
    }

    #[test]
    fn an_update_that_omits_the_secret_validates() {
        let input = NewDirectoryConfig {
            bind_secret: None,
            ..valid()
        };
        assert_eq!(validate(&input), Ok(()));
    }

    #[test]
    fn an_active_directory_shape_with_a_upn_bind_identity_is_accepted() {
        let input = NewDirectoryConfig {
            kind: DirectoryKind::ActiveDirectory,
            bind_dn: "svc-axiam@corp.example.com".into(),
            user_filter: "(&(objectClass=user)(sAMAccountName={username}))".into(),
            user_attribute_map: DirectoryKind::ActiveDirectory.default_user_attribute_map(),
            group_filter: Some("(objectClass=group)".into()),
            group_member_attribute: "memberOf".into(),
            ..valid()
        };
        assert_eq!(validate(&input), Ok(()));
    }

    #[test]
    fn a_ca_certificate_is_accepted_as_an_anchor() {
        let input = NewDirectoryConfig {
            trust_anchors_pem: vec![ca_pem(), ca_pem()],
            ..valid()
        };
        assert_eq!(validate(&input), Ok(()));
    }

    #[test]
    fn the_bounds_themselves_are_accepted() {
        for (depth, interval) in [
            (0, SYNC_INTERVAL_MIN_SECS),
            (GROUP_NESTING_DEPTH_MAX, SYNC_INTERVAL_MAX_SECS),
        ] {
            let input = NewDirectoryConfig {
                group_nesting_depth: depth,
                sync_interval_secs: interval,
                ..valid()
            };
            assert_eq!(validate(&input), Ok(()));
        }
    }

    // --- transport -------------------------------------------------------

    #[test]
    fn plaintext_ldap_without_start_tls_is_refused() {
        assert_eq!(
            url_defect("ldap://host.example.com:389", false),
            UrlDefect::PlaintextWithoutStartTls
        );
    }

    #[test]
    fn ldaps_with_start_tls_is_refused_as_contradictory() {
        assert_eq!(
            url_defect("ldaps://host.example.com:636", true),
            UrlDefect::StartTlsOnLdaps
        );
    }

    #[test]
    fn any_other_scheme_is_refused() {
        for url in [
            "http://host.example.com",
            "https://host.example.com",
            "ldapi://host.example.com",
            "ldap+tls://host.example.com",
            "ftp://host.example.com",
        ] {
            assert_eq!(url_defect(url, true), UrlDefect::UnsupportedScheme, "{url}");
            assert_eq!(
                url_defect(url, false),
                UrlDefect::UnsupportedScheme,
                "{url}"
            );
        }
    }

    #[test]
    fn text_that_is_not_a_url_is_refused() {
        assert_eq!(
            url_defect("not a url", false),
            UrlDefect::WhitespaceOrControl
        );
        assert_eq!(url_defect("host.example.com", false), UrlDefect::Malformed);
        assert_eq!(url_defect("", false), UrlDefect::Malformed);
    }

    #[test]
    fn whitespace_the_parser_would_strip_is_refused_rather_than_normalised() {
        for url in [
            " ldaps://host.example.com",
            "ldaps://host.example.com ",
            "ldaps://host.example.com\n",
            "ldaps://host.exa\tmple.com",
        ] {
            assert_eq!(url_defect(url, false), UrlDefect::WhitespaceOrControl);
        }
    }

    #[test]
    fn a_url_without_a_host_is_refused() {
        assert_eq!(url_defect("ldaps://", false), UrlDefect::MissingHost);
        assert_eq!(url_defect("ldaps:///", false), UrlDefect::MissingHost);
    }

    #[test]
    fn userinfo_is_refused_in_every_spelling() {
        for url in [
            "ldaps://user:pw@host.example.com",
            "ldaps://user@host.example.com",
            "ldaps://@host.example.com",
            "ldaps://:@host.example.com",
        ] {
            assert_eq!(url_defect(url, false), UrlDefect::HasUserinfo, "{url}");
        }
    }

    #[test]
    fn a_path_a_query_and_a_fragment_are_refused() {
        assert_eq!(
            url_defect("ldaps://host.example.com/dc=example,dc=com", false),
            UrlDefect::HasPath
        );
        assert_eq!(
            url_defect("ldaps://host.example.com/x", false),
            UrlDefect::HasPath
        );
        assert_eq!(
            url_defect("ldaps://host.example.com/?sub", false),
            UrlDefect::HasQuery
        );
        assert_eq!(
            url_defect("ldaps://host.example.com?sub", false),
            UrlDefect::HasQuery
        );
        assert_eq!(
            url_defect("ldaps://host.example.com/#frag", false),
            UrlDefect::HasFragment
        );
    }

    #[test]
    fn an_overlong_url_is_refused() {
        let url = format!("ldaps://{}.example.com", "a".repeat(URL_MAX_LEN));
        assert_eq!(url_defect(&url, false), UrlDefect::TooLong);
    }

    #[test]
    fn a_refusal_never_echoes_the_url() {
        // A URL may carry a password; the refusal must not be what logs it.
        let marker = "userinfo-marker-not-a-real-credential";
        let url = format!("ldaps://admin:{marker}@host.example.com");
        let err = validate(&with_url(&url, false)).unwrap_err();
        assert!(
            !err.to_string().contains(marker),
            "a URL refusal must not repeat the URL's userinfo"
        );
    }

    // --- DNs -------------------------------------------------------------

    fn dn_defect(input: NewDirectoryConfig) -> (&'static str, DnDefect) {
        match validate(&input) {
            Err(ConfigError::Dn { field, defect }) => (field, defect),
            other => panic!("expected a DN refusal for the case under test, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_bind_dn_or_base_dn_is_refused() {
        for blank in ["", "   "] {
            assert_eq!(
                dn_defect(NewDirectoryConfig {
                    bind_dn: blank.into(),
                    ..valid()
                }),
                ("bind_dn", DnDefect::Empty)
            );
            assert_eq!(
                dn_defect(NewDirectoryConfig {
                    base_dn: blank.into(),
                    ..valid()
                }),
                ("base_dn", DnDefect::Empty)
            );
        }
    }

    #[test]
    fn a_dn_with_a_control_character_is_refused() {
        assert_eq!(
            dn_defect(NewDirectoryConfig {
                bind_dn: "cn=svc\u{0}x,dc=example".into(),
                ..valid()
            }),
            ("bind_dn", DnDefect::ControlCharacter)
        );
        assert_eq!(
            dn_defect(NewDirectoryConfig {
                base_dn: "dc=example\n,dc=com".into(),
                ..valid()
            }),
            ("base_dn", DnDefect::ControlCharacter)
        );
    }

    #[test]
    fn an_overlong_dn_is_refused() {
        assert_eq!(
            dn_defect(NewDirectoryConfig {
                base_dn: format!("dc={}", "a".repeat(DN_MAX_LEN)),
                ..valid()
            }),
            ("base_dn", DnDefect::TooLong)
        );
    }

    #[test]
    fn a_present_but_empty_group_base_dn_is_refused() {
        assert_eq!(
            dn_defect(NewDirectoryConfig {
                group_base_dn: Some(String::new()),
                ..valid()
            }),
            ("group_base_dn", DnDefect::Empty)
        );
    }

    // --- bind secret -----------------------------------------------------

    #[test]
    fn an_empty_or_overlong_bind_secret_is_refused() {
        let empty = NewDirectoryConfig {
            bind_secret: Some(Zeroizing::new(String::new())),
            ..valid()
        };
        assert_eq!(
            validate(&empty),
            Err(ConfigError::BindSecret(SecretDefect::Empty))
        );
        let long = NewDirectoryConfig {
            bind_secret: Some(Zeroizing::new("x".repeat(BIND_SECRET_MAX_LEN + 1))),
            ..valid()
        };
        assert_eq!(
            validate(&long),
            Err(ConfigError::BindSecret(SecretDefect::TooLong))
        );
    }

    // --- filters ---------------------------------------------------------

    fn filter_defect(template: &str) -> FilterDefect {
        match validate(&NewDirectoryConfig {
            user_filter: template.into(),
            ..valid()
        }) {
            Err(ConfigError::Filter {
                field: "user_filter",
                defect,
            }) => defect,
            other => {
                panic!("expected a user_filter refusal for the case under test, got {other:?}")
            }
        }
    }

    #[test]
    fn the_user_filter_templates_in_use_are_accepted() {
        for template in [
            "(uid={username})",
            "(&(objectClass=person)(uid={username}))",
            "(|(uid={username})(mail=x@example.com))",
            "(&(objectClass=user)(sAMAccountName={username})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ] {
            assert_eq!(
                validate(&NewDirectoryConfig {
                    user_filter: template.into(),
                    ..valid()
                }),
                Ok(()),
                "{template}"
            );
        }
    }

    #[test]
    fn a_filter_template_must_not_be_empty_or_overlong_or_hold_control_characters() {
        assert_eq!(filter_defect(""), FilterDefect::Empty);
        let long = format!("(uid={{username}}{})", "a".repeat(FILTER_MAX_LEN));
        assert_eq!(filter_defect(&long), FilterDefect::TooLong);
        assert_eq!(
            filter_defect("(uid={username}\n)"),
            FilterDefect::ControlCharacter
        );
    }

    #[test]
    fn a_filter_template_must_start_and_end_with_a_parenthesis() {
        assert_eq!(
            filter_defect("uid={username}"),
            FilterDefect::NotParenthesised
        );
        assert_eq!(
            filter_defect("(uid={username}"),
            FilterDefect::NotParenthesised
        );
        assert_eq!(
            filter_defect("uid={username})"),
            FilterDefect::NotParenthesised
        );
    }

    #[test]
    fn a_filter_template_must_have_balanced_parentheses() {
        assert_eq!(filter_defect("((uid={username})"), FilterDefect::Unbalanced);
        assert_eq!(filter_defect("(uid={username}))"), FilterDefect::Unbalanced);
        assert_eq!(
            filter_defect("(&(uid={username})"),
            FilterDefect::Unbalanced
        );
    }

    #[test]
    fn a_filter_template_must_be_a_single_filter() {
        assert_eq!(
            filter_defect("(uid={username})(objectClass=*)"),
            FilterDefect::NotSingleFilter
        );
    }

    #[test]
    fn a_filter_template_needs_exactly_one_placeholder() {
        assert_eq!(filter_defect("(uid=bob)"), FilterDefect::PlaceholderCount);
        assert_eq!(
            filter_defect("(|(uid={username})(mail={username}))"),
            FilterDefect::PlaceholderCount
        );
    }

    #[test]
    fn a_filter_template_refuses_any_other_brace() {
        assert_eq!(
            filter_defect("(uid={user})"),
            FilterDefect::PlaceholderCount
        );
        assert_eq!(
            filter_defect("(&(cn={x})(uid={username}))"),
            FilterDefect::StrayBrace
        );
        assert_eq!(
            filter_defect("(&(uid={username})(cn=a}b))"),
            FilterDefect::StrayBrace
        );
    }

    #[test]
    fn the_placeholder_must_be_in_value_position() {
        assert_eq!(
            filter_defect("({username}=bob)"),
            FilterDefect::PlaceholderPosition
        );
        assert_eq!(
            filter_defect("(&{username})"),
            FilterDefect::PlaceholderPosition
        );
    }

    #[test]
    fn a_group_filter_is_shape_checked_and_static() {
        let defect = |filter: &str| match validate(&NewDirectoryConfig {
            group_filter: Some(filter.into()),
            ..valid()
        }) {
            Err(ConfigError::Filter {
                field: "group_filter",
                defect,
            }) => defect,
            other => {
                panic!("expected a group_filter refusal for the case under test, got {other:?}")
            }
        };
        assert_eq!(defect(""), FilterDefect::Empty);
        assert_eq!(defect("objectClass=group"), FilterDefect::NotParenthesised);
        assert_eq!(defect("((objectClass=group)"), FilterDefect::Unbalanced);
        assert_eq!(
            defect("(objectClass=group)(cn=x)"),
            FilterDefect::NotSingleFilter
        );
        assert_eq!(
            defect("(member={username})"),
            FilterDefect::PlaceholderNotAllowed
        );
    }

    // --- attributes ------------------------------------------------------

    fn attribute_defect(input: NewDirectoryConfig) -> (&'static str, AttributeDefect) {
        match validate(&input) {
            Err(ConfigError::Attribute { field, defect }) => (field, defect),
            other => panic!("expected an attribute refusal for the case under test, got {other:?}"),
        }
    }

    #[test]
    fn attribute_names_must_be_plain_names() {
        let mut input = valid();
        input.user_attribute_map.email = String::new();
        assert_eq!(
            attribute_defect(input),
            ("user_attribute_map.email", AttributeDefect::Empty)
        );

        let mut input = valid();
        input.user_attribute_map.username = "uid)(objectClass=*".into();
        assert_eq!(
            attribute_defect(input),
            (
                "user_attribute_map.username",
                AttributeDefect::InvalidCharacters
            )
        );

        let mut input = valid();
        input.user_attribute_map.display_name = "1displayName".into();
        assert_eq!(
            attribute_defect(input),
            (
                "user_attribute_map.display_name",
                AttributeDefect::InvalidCharacters
            )
        );

        let mut input = valid();
        input.user_attribute_map.external_id = "a".repeat(ATTRIBUTE_MAX_LEN + 1);
        assert_eq!(
            attribute_defect(input),
            ("user_attribute_map.external_id", AttributeDefect::TooLong)
        );

        assert_eq!(
            attribute_defect(NewDirectoryConfig {
                group_member_attribute: "member Of".into(),
                ..valid()
            }),
            ("group_member_attribute", AttributeDefect::InvalidCharacters)
        );
    }

    // --- bounds ----------------------------------------------------------

    #[test]
    fn a_nesting_depth_above_the_maximum_is_refused() {
        assert_eq!(
            validate(&NewDirectoryConfig {
                group_nesting_depth: GROUP_NESTING_DEPTH_MAX + 1,
                ..valid()
            }),
            Err(ConfigError::NestingDepth)
        );
    }

    #[test]
    fn a_sync_interval_outside_the_bounds_is_refused() {
        for interval in [0, SYNC_INTERVAL_MIN_SECS - 1, SYNC_INTERVAL_MAX_SECS + 1] {
            assert_eq!(
                validate(&NewDirectoryConfig {
                    sync_interval_secs: interval,
                    ..valid()
                }),
                Err(ConfigError::SyncInterval)
            );
        }
    }

    // --- trust anchors ---------------------------------------------------

    fn anchor_defect(pem: String) -> AnchorDefect {
        match validate(&NewDirectoryConfig {
            trust_anchors_pem: vec![ca_pem(), pem],
            ..valid()
        }) {
            Err(ConfigError::TrustAnchor { index: 1, defect }) => defect,
            other => panic!("expected a refusal of trust anchor #1, got {other:?}"),
        }
    }

    #[test]
    fn a_trust_anchor_that_is_not_pem_is_refused() {
        assert_eq!(
            anchor_defect("not a certificate".into()),
            AnchorDefect::NotPem
        );
        assert_eq!(anchor_defect(String::new()), AnchorDefect::NotPem);
    }

    #[test]
    fn a_pem_block_that_is_not_a_certificate_is_refused() {
        let key = KeyPair::generate().unwrap().serialize_pem();
        assert_eq!(anchor_defect(key), AnchorDefect::NotCertificateBlock);
    }

    #[test]
    fn a_pem_block_with_garbage_inside_is_refused_as_unparseable() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAAAAAAA\n-----END CERTIFICATE-----\n";
        assert_eq!(anchor_defect(pem.into()), AnchorDefect::Unparseable);
    }

    #[test]
    fn a_leaf_certificate_is_refused_as_an_anchor() {
        assert_eq!(anchor_defect(leaf_pem()), AnchorDefect::NotCa);
    }

    #[test]
    fn two_certificates_in_one_entry_are_refused() {
        let bundle = format!("{}{}", ca_pem(), ca_pem());
        assert_eq!(anchor_defect(bundle), AnchorDefect::MoreThanOneBlock);
    }

    #[test]
    fn an_oversized_anchor_and_too_many_anchors_are_refused() {
        assert_eq!(
            anchor_defect(format!("{}{}", ca_pem(), " ".repeat(TRUST_ANCHOR_MAX_LEN))),
            AnchorDefect::TooLarge
        );
        let many = NewDirectoryConfig {
            trust_anchors_pem: vec![ca_pem(); TRUST_ANCHORS_MAX + 1],
            ..valid()
        };
        assert_eq!(validate(&many), Err(ConfigError::TooManyTrustAnchors));
    }

    // --- conversion ------------------------------------------------------

    #[test]
    fn a_refusal_becomes_a_validation_error() {
        let err: AxiamError = validate(&with_url("ldap://host.example.com", false))
            .unwrap_err()
            .into();
        match err {
            AxiamError::Validation { message } => assert!(message.contains("plaintext")),
            other => panic!("expected AxiamError::Validation, got {other:?}"),
        }
    }
}
