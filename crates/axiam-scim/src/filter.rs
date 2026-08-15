//! SCIM `filter` query-parameter parsing — **subset only** (RFC 7644 §3.4.2.2).
//!
//! B4's scope is explicit: `userName eq`, `externalId eq`, and paging. No
//! `and`/`or`, no `co`/`sw`/`pr`/comparison operators, no attribute-path
//! filters (`emails[type eq "work"]`), no parentheses. Anything outside
//! `<attr> eq "<value>"` is rejected with the RFC's own `invalidFilter`
//! `scimType` (§3.12) rather than silently ignored or partially honored —
//! a caller that thinks it filtered and didn't would see the wrong page of
//! results, which is worse than an explicit 400.

use crate::error::ScimError;

/// A parsed `<attr> eq "<value>"` filter — the only shape this crate accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EqFilter {
    /// Lower-cased attribute name (`userName` and `username` are the same
    /// filter — SCIM attribute names are case-insensitive per RFC 7643 §2.1).
    pub attr: String,
    pub value: String,
}

/// Parse `raw` (the raw `filter=` query value, already URL-decoded by
/// actix's `web::Query`) as `<attr> eq "<value>"`.
///
/// `allowed_attrs` lists the attribute names (lower-case) this resource type
/// supports filtering on — `Users` passes `["username", "externalid"]`,
/// `Groups` passes `["externalid"]` — so an out-of-scope-but-otherwise-valid
/// filter (e.g. `displayName eq "..."` on Groups) gets the same
/// `invalidFilter` treatment as a syntactically broken one, per B4's
/// "complex filters — out of scope" line.
pub fn parse_eq_filter(raw: &str, allowed_attrs: &[&str]) -> Result<EqFilter, ScimError> {
    let trimmed = raw.trim();

    // Split into exactly 3 whitespace-separated tokens: attr, "eq", "value".
    // The quoted value may itself contain spaces, so split only the first two
    // tokens off and treat the remainder as the (still-quoted) value.
    let mut parts = trimmed.splitn(3, char::is_whitespace);
    let attr = parts.next().unwrap_or("").trim();
    let op = parts.next().unwrap_or("").trim();
    let raw_value = parts.next().unwrap_or("").trim();

    if attr.is_empty() || raw_value.is_empty() {
        return Err(ScimError::invalid_filter(format!(
            "unsupported filter expression: {raw:?} — only \"<attr> eq \\\"<value>\\\"\" is supported"
        )));
    }
    if !op.eq_ignore_ascii_case("eq") {
        return Err(ScimError::invalid_filter(format!(
            "unsupported filter operator {op:?} — only \"eq\" is supported"
        )));
    }

    let attr_lower = attr.to_ascii_lowercase();
    if !allowed_attrs.contains(&attr_lower.as_str()) {
        return Err(ScimError::invalid_filter(format!(
            "filtering on {attr:?} is not supported — supported attributes: {allowed_attrs:?}"
        )));
    }

    let value = unquote(raw_value).ok_or_else(|| {
        ScimError::invalid_filter(format!(
            "filter value must be a double-quoted string, got: {raw_value:?}"
        ))
    })?;

    Ok(EqFilter {
        attr: attr_lower,
        value,
    })
}

/// Parse `s` as a single double-quoted string with the two escapes SCIM
/// filter values commonly carry (`\"`, `\\`) and nothing else — unicode
/// escapes, an unmatched quote, or trailing content after the closing quote
/// (e.g. a smuggled `" and externalId eq "b"` conjunction) are all rejected.
/// This is a deliberately strict subset parser, not a general JSON string
/// literal parser: a `None` here must always mean "not a single quoted
/// value", never "close enough".
fn unquote(s: &str) -> Option<String> {
    let mut chars = s.chars();
    if chars.next() != Some('"') {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    let mut escaped = false;
    let mut closed = false;
    for c in chars.by_ref() {
        if escaped {
            match c {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                // Any other escape (\n, \uXXXX, ...) is outside this
                // subset's scope.
                _ => return None,
            }
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            closed = true;
            break;
        } else {
            out.push(c);
        }
    }
    // Unterminated string (ran out of input still escaping or before a
    // closing quote), or trailing content after the closing quote.
    if !closed || escaped || chars.next().is_some() {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_ATTRS: &[&str] = &["username", "externalid"];

    #[test]
    fn parses_username_eq() {
        let f = parse_eq_filter(r#"userName eq "alice""#, USER_ATTRS).unwrap();
        assert_eq!(f.attr, "username");
        assert_eq!(f.value, "alice");
    }

    #[test]
    fn parses_externalid_eq_case_insensitive_op() {
        let f = parse_eq_filter(r#"externalId EQ "ext-42""#, USER_ATTRS).unwrap();
        assert_eq!(f.attr, "externalid");
        assert_eq!(f.value, "ext-42");
    }

    #[test]
    fn value_with_embedded_space_is_preserved() {
        let f = parse_eq_filter(r#"userName eq "alice smith""#, USER_ATTRS).unwrap();
        assert_eq!(f.value, "alice smith");
    }

    #[test]
    fn unsupported_attribute_is_invalid_filter() {
        let err = parse_eq_filter(r#"displayName eq "x""#, USER_ATTRS).unwrap_err();
        assert_eq!(err.scim_type, Some("invalidFilter"));
    }

    #[test]
    fn unsupported_operator_is_invalid_filter() {
        let err = parse_eq_filter(r#"userName co "ali""#, USER_ATTRS).unwrap_err();
        assert_eq!(err.scim_type, Some("invalidFilter"));
    }

    #[test]
    fn and_conjunction_is_invalid_filter() {
        let err =
            parse_eq_filter(r#"userName eq "a" and externalId eq "b""#, USER_ATTRS).unwrap_err();
        // The value portion becomes `"a" and externalId eq "b"`, which fails
        // unquoting (trailing content after the closing quote) — still a
        // rejected filter, which is the property under test.
        assert_eq!(err.scim_type, Some("invalidFilter"));
    }

    #[test]
    fn unquoted_value_is_invalid_filter() {
        let err = parse_eq_filter(r#"userName eq alice"#, USER_ATTRS).unwrap_err();
        assert_eq!(err.scim_type, Some("invalidFilter"));
    }

    #[test]
    fn complex_attribute_path_filter_is_rejected() {
        // Explicitly out of scope (B4): `emails[type eq "work"]`.
        let err = parse_eq_filter(r#"emails[type eq "work"].value eq "x@y.com""#, USER_ATTRS)
            .unwrap_err();
        assert_eq!(err.scim_type, Some("invalidFilter"));
    }
}
