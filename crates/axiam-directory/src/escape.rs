//! RFC 4515 filter-value escaping, and the one function that puts a login
//! name into a search filter.
//!
//! # The rule
//!
//! A value that came from outside AXIAM — a login name typed into a form —
//! reaches an LDAP filter **only** through [`escape_filter_value`], and only
//! through [`user_filter_for`], which substitutes the escaped value into the
//! single `{username}` placeholder of the tenant's template. Nothing in this
//! crate builds a filter with `format!` around raw input, and nothing builds a
//! distinguished name at all: the DN the user binds as is the one the directory
//! returned from the search, so RFC 4514 DN escaping is never needed and is not
//! implemented (a DN that is never constructed cannot be injected into).
//!
//! # What is escaped
//!
//! RFC 4515 §3 requires the five octets `*`, `(`, `)`, `\` and NUL to be
//! written as `\XX` inside an assertion value. This function escapes those
//! **and every octet outside printable ASCII** (`0x20..=0x7E`): control
//! characters and every byte of a multi-byte UTF-8 sequence. The RFC permits
//! UTF-8 to appear literally, and `\XX` is equally valid for any octet, so the
//! stricter form costs nothing in interoperability and buys an output that is
//! pure printable ASCII — no byte in it can be read as filter syntax by a
//! server, a proxy or a log viewer, whatever its notion of encoding.
//!
//! The server decodes each `\XX` back to the original octet, so `é`
//! (`c3 a9`) is matched as `é`: escaping changes how the value is written,
//! never which value is asserted.

use crate::config::USERNAME_PLACEHOLDER;

/// Longest login name, in bytes, that is ever sent to a directory.
///
/// Longer input is refused before any network I/O, as a generic failure. Real
/// directory login names are short (`sAMAccountName` is at most 20 characters,
/// a UPN at most a few hundred); the bound exists so a hostile caller cannot
/// make AXIAM ship a multi-kilobyte filter, three times inflated by escaping,
/// to a tenant's directory on every attempt.
pub const LOGIN_NAME_MAX_LEN: usize = 256;

/// Escape `value` for use as an RFC 4515 assertion value.
///
/// See the module documentation for exactly which octets are escaped. The
/// output is always printable ASCII and never contains `*`, `(`, `)` or an
/// unescaped `\`, so it cannot widen, close or extend the filter it is placed
/// in.
#[must_use]
pub fn escape_filter_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for &byte in value.as_bytes() {
        let literal = matches!(byte, 0x20..=0x7E) && !matches!(byte, b'*' | b'(' | b')' | b'\\');
        if literal {
            out.push(char::from(byte));
        } else {
            out.push('\\');
            out.push(hex_digit(byte >> 4));
            out.push(hex_digit(byte & 0x0F));
        }
    }
    out
}

fn hex_digit(nibble: u8) -> char {
    char::from(match nibble {
        0..=9 => b'0' + nibble,
        _ => b'a' + (nibble - 10),
    })
}

/// Why a user filter could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserFilterError {
    /// The login name is empty or longer than [`LOGIN_NAME_MAX_LEN`]. Answered
    /// as a generic sign-in failure, before any network I/O.
    UnusableLoginName,
    /// The stored template does not carry exactly one placeholder. Validation
    /// refuses such a template at configuration time, so reaching this means
    /// the row was written by something that skipped validation; it is a
    /// misconfiguration, never a reason to send an unparameterised filter.
    TemplateWithoutSinglePlaceholder,
}

/// Build the user-lookup filter: the tenant's template with its single
/// `{username}` placeholder replaced by the RFC 4515-escaped login name.
///
/// This is the only way a login name enters a filter.
///
/// # Errors
///
/// [`UserFilterError`] when the login name is unusable or the template does not
/// carry exactly one placeholder.
pub fn user_filter_for(template: &str, login_name: &str) -> Result<String, UserFilterError> {
    if login_name.is_empty() || login_name.len() > LOGIN_NAME_MAX_LEN {
        return Err(UserFilterError::UnusableLoginName);
    }
    if template.matches(USERNAME_PLACEHOLDER).count() != 1 {
        return Err(UserFilterError::TemplateWithoutSinglePlaceholder);
    }
    Ok(template.replacen(USERNAME_PLACEHOLDER, &escape_filter_value(login_name), 1))
}

/// Most DNs one reverse-member search carries in its `(|...)` filter. Bounds
/// the size of a filter built from directory-supplied names.
pub const REVERSE_MEMBER_BATCH: usize = 16;

/// Build the reverse group-membership filter (T23.3.4, D-30): the groups, under
/// the group base, whose member attribute names one of `dns`.
///
/// ```text
/// (&<group_filter>(<attribute>=<escaped dn>))            one DN
/// (&<group_filter>(|(<attribute>=<dn>)(<attribute>=<dn>)))   several
/// ```
///
/// Without a `group_filter` the `(&...)` wrapper is dropped. **Each DN enters
/// the filter only through [`escape_filter_value`]**, exactly as a login name
/// does: a user's DN is a directory-supplied string and may carry `*`, `(`,
/// `)`, `\` or NUL, none of which can then widen the search. `group_filter` is
/// the tenant's own, validated, static filter; `attribute` is checked to be a
/// plain attribute name here as well, because it too is placed in the filter.
///
/// `None` when `dns` is empty or `attribute` is not a plain attribute name
/// (letters, digits and `-`, starting with a letter) — the caller treats it as
/// a misconfiguration and refuses; an unparameterised filter is never sent.
#[must_use]
pub fn reverse_member_filter(
    group_filter: Option<&str>,
    attribute: &str,
    dns: &[&str],
) -> Option<String> {
    let plain = attribute.starts_with(|c: char| c.is_ascii_alphabetic())
        && attribute
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-');
    if dns.is_empty() || !plain {
        return None;
    }
    let clauses: Vec<String> = dns
        .iter()
        .map(|dn| format!("({attribute}={})", escape_filter_value(dn)))
        .collect();
    let membership = match clauses.as_slice() {
        [only] => only.clone(),
        many => format!("(|{})", many.concat()),
    };
    Some(match group_filter {
        Some(group_filter) => format!("(&{group_filter}{membership})"),
        None => membership,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The five octets RFC 4515 §3 names, each on its own.
    #[test]
    fn the_rfc_4515_octets_are_escaped() {
        assert_eq!(escape_filter_value("*"), "\\2a");
        assert_eq!(escape_filter_value("("), "\\28");
        assert_eq!(escape_filter_value(")"), "\\29");
        assert_eq!(escape_filter_value("\\"), "\\5c");
        assert_eq!(escape_filter_value("\0"), "\\00");
    }

    #[test]
    fn ordinary_login_names_pass_through_unchanged() {
        for name in [
            "alice",
            "j.doe",
            "svc-backup_01",
            "alice@corp.example.com",
            "a b",
        ] {
            assert_eq!(escape_filter_value(name), name);
        }
    }

    /// The hostile list from the task, each pinned to its exact escaped form.
    #[test]
    fn hostile_inputs_are_neutralised() {
        let cases = [
            ("*", "\\2a"),
            (")(uid=*", "\\29\\28uid=\\2a"),
            ("*)(|(objectClass=*", "\\2a\\29\\28|\\28objectClass=\\2a"),
            ("\\", "\\5c"),
            ("\0", "\\00"),
            ("admin)(&", "admin\\29\\28&"),
            ("\\2a", "\\5c2a"),
        ];
        for (input, expected) in cases {
            assert_eq!(escape_filter_value(input), expected, "case {expected}");
        }
    }

    /// Every byte of a multi-byte sequence is escaped, so the output is ASCII;
    /// the server decodes the octets back to the same UTF-8.
    #[test]
    fn utf8_is_escaped_octet_by_octet() {
        assert_eq!(escape_filter_value("é"), "\\c3\\a9");
        assert_eq!(escape_filter_value("josé"), "jos\\c3\\a9");
        assert_eq!(escape_filter_value("用户"), "\\e7\\94\\a8\\e6\\88\\b7");
        assert_eq!(escape_filter_value("\u{7f}\t\n"), "\\7f\\09\\0a");
    }

    /// The structural property, over a wide sample: no output ever contains a
    /// byte that could be filter syntax, and an escape is always a full `\XX`.
    #[test]
    fn no_output_contains_a_syntax_byte() {
        let mut inputs: Vec<String> = (0u8..=0x7F).map(|b| char::from(b).to_string()).collect();
        inputs.push("x".repeat(LOGIN_NAME_MAX_LEN * 4));
        inputs.push("é*)(\\\0ü".repeat(50));
        for input in inputs {
            let out = escape_filter_value(&input);
            assert!(out.bytes().all(|b| (0x20..=0x7E).contains(&b)));
            assert!(!out.contains(['*', '(', ')']));
            let bytes = out.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    assert!(i + 2 < bytes.len(), "a truncated escape");
                    assert!(bytes[i + 1].is_ascii_hexdigit() && bytes[i + 2].is_ascii_hexdigit());
                    i += 3;
                } else {
                    i += 1;
                }
            }
        }
    }

    /// Cross-check against the escaper `ldap3` ships: on everything the RFC
    /// requires, the two agree; this one only escapes more.
    #[test]
    fn agrees_with_ldap3_on_ascii_input() {
        for input in ["*", ")(uid=*", "admin)(&", "\\", "\0", "plain"] {
            assert_eq!(escape_filter_value(input), ldap3::ldap_escape(input));
        }
    }

    #[test]
    fn the_filter_is_built_only_by_substitution_of_the_escaped_value() {
        assert_eq!(
            user_filter_for("(uid={username})", "alice").unwrap(),
            "(uid=alice)"
        );
        assert_eq!(
            user_filter_for(
                "(&(objectClass=person)(sAMAccountName={username}))",
                "*)(|(objectClass=*"
            )
            .unwrap(),
            "(&(objectClass=person)(sAMAccountName=\\2a\\29\\28|\\28objectClass=\\2a))"
        );
        // A placeholder spelled inside the login name is data, not a second
        // substitution site.
        assert_eq!(
            user_filter_for("(uid={username})", "{username}").unwrap(),
            "(uid={username})"
        );
    }

    #[test]
    fn an_empty_or_overlong_login_name_is_refused_before_anything_is_built() {
        assert_eq!(
            user_filter_for("(uid={username})", ""),
            Err(UserFilterError::UnusableLoginName)
        );
        assert_eq!(
            user_filter_for("(uid={username})", &"a".repeat(LOGIN_NAME_MAX_LEN + 1)),
            Err(UserFilterError::UnusableLoginName)
        );
        assert!(user_filter_for("(uid={username})", &"a".repeat(LOGIN_NAME_MAX_LEN)).is_ok());
    }

    #[test]
    fn a_template_without_exactly_one_placeholder_is_never_used() {
        for template in ["(uid=alice)", "(|(uid={username})(mail={username}))"] {
            assert_eq!(
                user_filter_for(template, "alice"),
                Err(UserFilterError::TemplateWithoutSinglePlaceholder)
            );
        }
    }
    #[test]
    fn the_reverse_member_filter_escapes_every_dn_and_never_widens() {
        let hostile = "uid=a*)(uid=*\\,ou=\u{0}x,dc=example,dc=com";
        let filter =
            reverse_member_filter(Some("(objectClass=groupOfNames)"), "member", &[hostile])
                .unwrap();
        assert_eq!(
            filter,
            "(&(objectClass=groupOfNames)(member=uid=a\\2a\\29\\28uid=\\2a\\5c,ou=\\00x,dc=example,dc=com))"
        );
        // The only parentheses are the filter's own: 3 opens, 3 closes.
        assert_eq!(filter.matches('(').count(), 3);
        assert_eq!(filter.matches(')').count(), 3);
        assert!(!filter.contains('*'));
    }

    #[test]
    fn several_dns_share_one_or_and_none_is_refused() {
        let filter = reverse_member_filter(None, "member", &["cn=a,dc=x", "cn=b,dc=x"]).unwrap();
        assert_eq!(filter, "(|(member=cn=a,dc=x)(member=cn=b,dc=x))");
        assert_eq!(
            reverse_member_filter(None, "member", &["cn=a,dc=x"]).unwrap(),
            "(member=cn=a,dc=x)"
        );
        assert_eq!(reverse_member_filter(None, "member", &[]), None);
    }

    #[test]
    fn an_attribute_that_is_not_plain_is_never_placed_in_a_filter() {
        for attribute in ["", "me mber", "member)(uid=*", "1member", "member=", "mem*"] {
            assert_eq!(
                reverse_member_filter(None, attribute, &["cn=a,dc=x"]),
                None,
                "{attribute:?}"
            );
        }
        assert!(reverse_member_filter(None, "uniqueMember", &["cn=a,dc=x"]).is_some());
    }
}
