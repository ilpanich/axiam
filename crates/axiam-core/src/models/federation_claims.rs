//! Mapping an external identity provider's claims onto an AXIAM user.
//!
//! This module is the fix for the defect where `attribute_map` was collected by
//! the admin UI, stored by the database, and read by nothing: `provision_new_user`
//! took the username and email straight off the `email` claim and the configured
//! map was inert. An operator could write a mapping, save it, see it come back
//! on the next page load, and have it change nothing.
//!
//! It is deliberately **one** mechanism for all three protocols. OIDC ID-token
//! claims, SAML assertion attributes and an OAuth2 userinfo response all arrive
//! here as a `serde_json::Value` object and leave as a [`MappedIdentity`]. A
//! claim-mapping bug should be fixable in one place, and an operator should not
//! have to learn two syntaxes because AXIAM happened to implement two protocols
//! in different years.
//!
//! See `claude_dev/federation-sso-login-design.md` §8.

use serde_json::Value;

use super::federation::ProviderKind;

/// The AXIAM-side fields an attribute map may set.
///
/// A key outside this list is a **validation error** at write time, not a
/// silently ignored one. The whole defect being closed here is a field that
/// looked configured and did nothing; accepting `"e-mail": "mail"` and quietly
/// dropping it would recreate that failure one typo down.
pub const ATTRIBUTE_MAP_FIELDS: &[&str] = &[
    "external_subject",
    "username",
    "email",
    "email_verified",
    "display_name",
];

/// Prefix marking a mapping value as a literal rather than a claim path.
///
/// `{"email_verified": "@true"}` states "I accept this provider's unflagged
/// email as verified" in a place that shows up in an audit diff, rather than
/// AXIAM making that decision silently on the operator's behalf.
pub const LITERAL_PREFIX: char = '@';

/// Bound on the number of entries in an attribute map.
///
/// Not tidiness: the map is walked once per federated login, so an unbounded
/// map is an unbounded per-login cost an admin can set. Five recognised fields
/// makes anything past a handful a mistake anyway.
pub const MAX_ATTRIBUTE_MAP_ENTRIES: usize = 32;

/// Why a submitted `attribute_map` was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeMapError {
    /// The map was not a JSON object.
    NotAnObject,
    /// The map names an AXIAM field that does not exist.
    UnknownField(String),
    /// A value was not a string (paths and literals are both strings).
    NonStringValue(String),
    /// A value was empty, or a literal with nothing after the `@`.
    EmptyValue(String),
    /// Too many entries.
    TooManyEntries(usize),
}

impl std::fmt::Display for AttributeMapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnObject => write!(f, "attribute_map must be a JSON object"),
            Self::UnknownField(k) => write!(
                f,
                "attribute_map key '{k}' is not an AXIAM user field; the recognised \
                 keys are {}",
                ATTRIBUTE_MAP_FIELDS.join(", ")
            ),
            Self::NonStringValue(k) => write!(
                f,
                "attribute_map entry '{k}' must be a string — either a claim path \
                 like 'user.email' or a literal like '@true'"
            ),
            Self::EmptyValue(k) => {
                write!(f, "attribute_map entry '{k}' is empty; remove it instead")
            }
            Self::TooManyEntries(n) => write!(
                f,
                "attribute_map has {n} entries; the maximum is {MAX_ATTRIBUTE_MAP_ENTRIES}"
            ),
        }
    }
}

/// Reject an attribute map that cannot be applied.
///
/// An absent map (`null`) and an empty object are both fine and both mean
/// "use the per-kind defaults".
pub fn validate_attribute_map(map: &Value) -> Result<(), AttributeMapError> {
    if map.is_null() {
        return Ok(());
    }
    let Some(obj) = map.as_object() else {
        return Err(AttributeMapError::NotAnObject);
    };
    if obj.len() > MAX_ATTRIBUTE_MAP_ENTRIES {
        return Err(AttributeMapError::TooManyEntries(obj.len()));
    }
    for (key, value) in obj {
        if !ATTRIBUTE_MAP_FIELDS.contains(&key.as_str()) {
            return Err(AttributeMapError::UnknownField(key.clone()));
        }
        let Some(raw) = value.as_str() else {
            return Err(AttributeMapError::NonStringValue(key.clone()));
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed == LITERAL_PREFIX.to_string() {
            return Err(AttributeMapError::EmptyValue(key.clone()));
        }
    }
    Ok(())
}

/// The per-kind default mapping, as `(axiam_field, claim_path)` pairs.
///
/// The OIDC rows reproduce `provision_new_user`'s pre-existing behaviour
/// exactly — username from `email`, email from `email` — so an existing Google
/// config behaves identically before and after this change. That is asserted by
/// a test, not merely intended.
pub fn default_attribute_map(kind: ProviderKind) -> &'static [(&'static str, &'static str)] {
    match kind {
        ProviderKind::Github => &[
            // GitHub's numeric `id` is the stable subject; `login` is renameable
            // and must never be the identity key.
            ("external_subject", "id"),
            ("username", "login"),
            // Injected by the GitHub path from `GET /user/emails` — see
            // `MappedIdentity`'s doc comment.
            ("email", "email"),
            ("email_verified", "email_verified"),
            ("display_name", "name"),
        ],
        ProviderKind::Facebook => &[
            ("external_subject", "id"),
            ("username", "email"),
            ("email", "email"),
            // Deliberately no `email_verified` entry: the Graph API carries no
            // verification flag, so absent reads as unverified and the login is
            // refused unless the operator writes `"email_verified": "@true"`.
            ("display_name", "name"),
        ],
        ProviderKind::GenericSaml => &[
            ("external_subject", "sub"),
            ("username", "email"),
            ("email", "email"),
            ("display_name", "displayName"),
        ],
        // Google, Microsoft, Apple, generic OIDC and generic OAuth2 all use the
        // standard OIDC claim names.
        _ => &[
            ("external_subject", "sub"),
            ("username", "email"),
            ("email", "email"),
            ("email_verified", "email_verified"),
            ("display_name", "name"),
        ],
    }
}

/// What an external identity resolved to, before any AXIAM user exists.
///
/// `email` and `email_verified` travel together on purpose. An email the
/// provider has not affirmatively marked verified is never adopted as an AXIAM
/// identity: AXIAM keys account recovery, verification and administrative
/// notification on the address, and adopting an unverified one is account
/// takeover by whoever typed it into the provider first.
///
/// For GitHub, `GET /user` frequently returns a null or unverified `email`, so
/// the GitHub path resolves the primary **verified** address from
/// `GET /user/emails` and writes it into the userinfo object under the ordinary
/// `email` / `email_verified` keys before mapping runs. That keeps one syntax:
/// a default map and an operator's custom map both name `email`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedIdentity {
    /// The external subject identifier. Without it there is no identity, which
    /// is why [`map_identity`] returns `None` rather than a partial result.
    pub external_subject: String,
    /// Preferred username, if the provider supplied one.
    pub username: Option<String>,
    /// Email address, if the provider supplied one.
    pub email: Option<String>,
    /// Whether the provider affirmatively said the address is verified.
    /// Absent, null or falsey all read as `false`.
    pub email_verified: bool,
    /// Human-readable name, if supplied. Stored in the user's `metadata` —
    /// `User` has no column for it.
    pub display_name: Option<String>,
}

/// Resolve one AXIAM field from the map (or the per-kind default), against a
/// claims object.
///
/// Returns `None` when the field has no mapping, when the path is absent from
/// the claims, or when the value present is not something a string can be made
/// of (an array or an object).
pub fn resolve_field(
    kind: ProviderKind,
    attribute_map: &Value,
    claims: &Value,
    field: &str,
) -> Option<String> {
    let configured = attribute_map
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let path = match configured {
        Some(p) => p,
        None => default_attribute_map(kind)
            .iter()
            .find(|(f, _)| *f == field)
            .map(|(_, p)| *p)?,
    };

    if let Some(literal) = path.strip_prefix(LITERAL_PREFIX) {
        let literal = literal.trim();
        return (!literal.is_empty()).then(|| literal.to_string());
    }

    lookup_path(claims, path).and_then(stringify_claim)
}

/// Look a claim path up in a claims object.
///
/// The **whole path is tried as a single key first**, and that ordering is
/// load-bearing rather than an optimisation: SAML attribute names are routinely
/// OIDs like `urn:oid:0.9.2342.19200300.100.1.3`, which contain dots and are not
/// nested paths. Only if no such key exists is the value split on `.` and walked
/// as a path, which is what makes `user.email` work for a nested userinfo
/// response.
pub fn lookup_path<'a>(claims: &'a Value, path: &str) -> Option<&'a Value> {
    if let Some(direct) = claims.get(path) {
        return Some(direct);
    }
    if !path.contains('.') {
        return None;
    }
    let mut cursor = claims;
    for segment in path.split('.') {
        cursor = cursor.get(segment)?;
    }
    Some(cursor)
}

/// Coerce a claim value to a string.
///
/// Strings, numbers and booleans convert; arrays, objects and null do not.
/// GitHub's `id` is a JSON number and is a subject identifier, so numbers must
/// convert or GitHub has no `external_subject`.
fn stringify_claim(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => {
            let t = s.trim();
            (!t.is_empty()).then(|| t.to_string())
        }
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

/// Whether a resolved `email_verified` value means "verified".
///
/// Deliberately narrow. `true`, `"true"` and `1` are affirmative; everything
/// else — including absent, `null`, `"unknown"` and `0` — is not. A provider
/// that does not say yes has not said yes.
fn is_affirmative(raw: &str) -> bool {
    matches!(raw.trim().to_ascii_lowercase().as_str(), "true" | "1")
}

/// Map a provider's claims onto an AXIAM identity.
///
/// Returns `None` when no `external_subject` can be resolved. There is no
/// partial success here: an identity with no subject is not an identity, and
/// falling back to some other field would silently key the account on something
/// the provider is free to let the user change.
pub fn map_identity(
    kind: ProviderKind,
    attribute_map: &Value,
    claims: &Value,
) -> Option<MappedIdentity> {
    let external_subject = resolve_field(kind, attribute_map, claims, "external_subject")?;
    Some(MappedIdentity {
        external_subject,
        username: resolve_field(kind, attribute_map, claims, "username"),
        email: resolve_field(kind, attribute_map, claims, "email"),
        email_verified: resolve_field(kind, attribute_map, claims, "email_verified")
            .as_deref()
            .is_some_and(is_affirmative),
        display_name: resolve_field(kind, attribute_map, claims, "display_name"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn google_claims() -> Value {
        json!({
            "sub": "108371829371",
            "email": "ada@example.com",
            "email_verified": true,
            "name": "Ada Lovelace",
        })
    }

    /// The headline compatibility property: with no map configured, an OIDC
    /// config produces exactly what `provision_new_user` produced before this
    /// module existed — username and email both from the `email` claim.
    #[test]
    fn an_empty_map_reproduces_the_previous_oidc_behaviour() {
        let m = map_identity(ProviderKind::Google, &json!({}), &google_claims()).unwrap();
        assert_eq!(m.external_subject, "108371829371");
        assert_eq!(m.username.as_deref(), Some("ada@example.com"));
        assert_eq!(m.email.as_deref(), Some("ada@example.com"));
        assert!(m.email_verified);
        assert_eq!(m.display_name.as_deref(), Some("Ada Lovelace"));
    }

    /// …and a `null` map (the shape a row with no attribute_map hydrates to)
    /// behaves identically to an empty object.
    #[test]
    fn a_null_map_is_the_same_as_an_empty_one() {
        assert_eq!(
            map_identity(ProviderKind::Google, &Value::Null, &google_claims()),
            map_identity(ProviderKind::Google, &json!({}), &google_claims()),
        );
    }

    #[test]
    fn a_configured_map_overrides_the_default() {
        let map = json!({"username": "preferred_username", "display_name": "given_name"});
        let claims = json!({
            "sub": "s-1",
            "email": "ada@example.com",
            "preferred_username": "ada",
            "given_name": "Ada",
            "name": "Ada Lovelace",
        });
        let m = map_identity(ProviderKind::GenericOidc, &map, &claims).unwrap();
        assert_eq!(m.username.as_deref(), Some("ada"));
        assert_eq!(m.display_name.as_deref(), Some("Ada"));
        // Unmapped fields still fall through to the default.
        assert_eq!(m.email.as_deref(), Some("ada@example.com"));
    }

    #[test]
    fn dotted_paths_reach_nested_claims() {
        let map = json!({"email": "user.contact.email"});
        let claims = json!({"sub": "s", "user": {"contact": {"email": "a@b.test"}}});
        let m = map_identity(ProviderKind::GenericOauth2, &map, &claims).unwrap();
        assert_eq!(m.email.as_deref(), Some("a@b.test"));
    }

    /// The ordering that matters: a SAML attribute name is an OID full of dots
    /// and is a key, not a path. Splitting first would make it unreachable.
    #[test]
    fn a_dotted_key_wins_over_a_dotted_path() {
        let oid = "urn:oid:0.9.2342.19200300.100.1.3";
        let map = json!({ "email": oid });
        let claims = json!({ "sub": "s", oid: "ada@example.com" });
        let m = map_identity(ProviderKind::GenericSaml, &map, &claims).unwrap();
        assert_eq!(m.email.as_deref(), Some("ada@example.com"));
    }

    #[test]
    fn a_literal_states_a_decision_rather_than_reading_one() {
        let map = json!({"email_verified": "@true"});
        let claims = json!({"id": 42, "email": "a@b.test", "name": "A"});
        let m = map_identity(ProviderKind::Facebook, &map, &claims).unwrap();
        assert!(
            m.email_verified,
            "the operator wrote the decision down; it must be honoured"
        );
        // …and without it, Facebook's flagless email reads as unverified.
        let m = map_identity(ProviderKind::Facebook, &json!({}), &claims).unwrap();
        assert!(!m.email_verified);
    }

    #[test]
    fn githubs_numeric_id_is_the_subject() {
        let claims = json!({
            "id": 583231,
            "login": "octocat",
            "name": "The Octocat",
            "email": "octocat@users.noreply.github.com",
            "email_verified": true,
        });
        let m = map_identity(ProviderKind::Github, &json!({}), &claims).unwrap();
        assert_eq!(m.external_subject, "583231");
        assert_eq!(m.username.as_deref(), Some("octocat"));
        assert!(m.email_verified);
    }

    #[test]
    fn no_subject_means_no_identity() {
        let claims = json!({"email": "ada@example.com", "name": "Ada"});
        assert!(map_identity(ProviderKind::Google, &json!({}), &claims).is_none());
    }

    #[test]
    fn only_affirmative_verification_counts() {
        for (raw, expected) in [
            (json!(true), true),
            (json!("true"), true),
            (json!(1), true),
            (json!(false), false),
            (json!("unknown"), false),
            (json!(0), false),
            (Value::Null, false),
        ] {
            let claims = json!({"sub": "s", "email": "a@b.test", "email_verified": raw});
            let m = map_identity(ProviderKind::GenericOidc, &json!({}), &claims).unwrap();
            assert_eq!(m.email_verified, expected, "for {raw:?}");
        }
    }

    #[test]
    fn structured_values_do_not_become_identities() {
        // A `sub` that arrives as an array is not a subject; treating it as
        // `["a","b"]`-stringified would key an account on a debug format.
        let claims = json!({"sub": ["a", "b"]});
        assert!(map_identity(ProviderKind::Google, &json!({}), &claims).is_none());
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        let err = validate_attribute_map(&json!({"e-mail": "mail"})).unwrap_err();
        assert_eq!(err, AttributeMapError::UnknownField("e-mail".into()));
        // The message names the recognised keys, because the operator's next
        // question is "then what is it called".
        assert!(err.to_string().contains("email_verified"));
    }

    #[test]
    fn validation_accepts_what_mapping_accepts() {
        assert!(validate_attribute_map(&Value::Null).is_ok());
        assert!(validate_attribute_map(&json!({})).is_ok());
        assert!(
            validate_attribute_map(&json!({"email": "mail", "email_verified": "@true"})).is_ok()
        );
        assert_eq!(
            validate_attribute_map(&json!([])).unwrap_err(),
            AttributeMapError::NotAnObject
        );
        assert_eq!(
            validate_attribute_map(&json!({"email": 3})).unwrap_err(),
            AttributeMapError::NonStringValue("email".into())
        );
        assert_eq!(
            validate_attribute_map(&json!({"email": "  "})).unwrap_err(),
            AttributeMapError::EmptyValue("email".into())
        );
        assert_eq!(
            validate_attribute_map(&json!({"email": "@"})).unwrap_err(),
            AttributeMapError::EmptyValue("email".into())
        );
    }

    #[test]
    fn every_default_map_names_only_recognised_fields() {
        for kind in ProviderKind::ALL {
            for (field, path) in default_attribute_map(*kind) {
                assert!(
                    ATTRIBUTE_MAP_FIELDS.contains(field),
                    "{kind:?} default names unknown field {field}"
                );
                assert!(!path.is_empty(), "{kind:?} default has an empty path");
            }
            // Every kind must be able to produce a subject, or no login through
            // it can ever succeed.
            assert!(
                default_attribute_map(*kind)
                    .iter()
                    .any(|(f, _)| *f == "external_subject"),
                "{kind:?} has no default external_subject mapping"
            );
        }
    }
}
