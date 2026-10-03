//! RFC 4514 distinguished-name normalisation, for **comparing** DNs.
//!
//! The group-mapping table (D-30) names a directory group by DN, and the
//! directory names the groups a user belongs to by DN. Two spellings of one DN
//! — `CN=Staff, OU=Groups` and `cn=staff,ou=groups` — must match, and two
//! different DNs must never. [`normalize`] turns a DN into a canonical key
//! with exactly that property; nothing else in AXIAM compares DNs, and **no DN
//! is ever built** (the escape module's rule stands): a DN that reaches a
//! search came back from the directory.
//!
//! # What is folded
//!
//! * **Attribute types** are case-folded (`CN` = `cn`). A numeric OID is kept
//!   as written, and a leading `oid.` is dropped (RFC 2253's spelling).
//! * **Values** are unescaped (`\,` and `\2C` are the same comma; a run of
//!   `\C3\A9` bytes is the one character `é`), then case-folded and had their
//!   insignificant space handled the way `caseIgnoreMatch` does: unescaped
//!   leading and trailing spaces are dropped and every inner run of white space
//!   is one space. A `#`-prefixed BER value is compared as its lowercase hex.
//! * **Spacing around the separators** (`,` `;` `+` and `=`) is ignored. RFC
//!   4514 itself writes none, but RFC 2253 and the tools that print DNs for
//!   people put a space after the comma, and a mapping an administrator pasted
//!   from `ldapsearch` must match.
//! * The members of a **multi-valued RDN** (`cn=a+uid=b`) are unordered, so
//!   they are sorted.
//!
//! # What is not folded
//!
//! The order of the RDNs (it is the path), and anything beyond simple case
//! folding — no Unicode normalisation form is applied, because the directory's
//! own matching rule is not known here. A DN the directory writes in another
//! normal form simply fails to match, which maps nothing: the failure is on the
//! side of granting less.
//!
//! # Refused
//!
//! An unparseable DN is an [`DnError`], never a best-effort key: a DN that is
//! not understood must not be treated as equal to anything. An unescaped `"`
//! (RFC 2253's quoted form) is refused rather than guessed at.

use std::collections::BTreeSet;

/// Longest DN, in bytes, that [`normalize`] will look at. Longer is refused:
/// the bound is on text that came from a directory, which is another party's
/// system.
pub const NORMALIZE_MAX_LEN: usize = 4096;

/// Why a string is not a DN [`normalize`] understands. Fixed text; the
/// offending value is never echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DnError {
    /// Empty (the root DSE is not a group).
    #[error("is empty")]
    Empty,
    /// Longer than [`NORMALIZE_MAX_LEN`].
    #[error("is too long")]
    TooLong,
    /// An RDN without `type=value`, or an empty type.
    #[error("has an attribute without a type")]
    MissingType,
    /// An attribute type that is neither a name nor a numeric OID.
    #[error("has an attribute type that is not a name or an OID")]
    BadType,
    /// A `\` that is not followed by a special character or two hex digits.
    #[error("has a malformed escape")]
    BadEscape,
    /// A `#` value that is not an even number of hex digits.
    #[error("has a malformed hex value")]
    BadHexValue,
    /// An unescaped `"`.
    #[error("has an unescaped quotation mark")]
    UnescapedQuote,
    /// The unescaped bytes of a value are not UTF-8.
    #[error("has a value that is not UTF-8")]
    NotUtf8,
    /// An empty RDN (`cn=a,,dc=x` or a trailing separator).
    #[error("has an empty RDN")]
    EmptyRdn,
}

/// One attribute-and-value pair of an RDN, folded.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Ava {
    kind: String,
    value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Value {
    /// A string value, unescaped and folded.
    Text(String),
    /// A `#` value: lowercase hex of the BER encoding.
    Hex(String),
}

/// The canonical comparison key of `dn`.
///
/// Two DNs name the same entry for the purposes of the mapping table exactly
/// when their keys are equal. The key is itself an RFC 4514 string, so it can
/// be logged for the operator, but it is for comparing, not for sending to a
/// directory.
///
/// # Errors
///
/// A [`DnError`] when `dn` is not a DN this module understands.
pub fn normalize(dn: &str) -> Result<String, DnError> {
    if dn.trim().is_empty() {
        return Err(DnError::Empty);
    }
    if dn.len() > NORMALIZE_MAX_LEN {
        return Err(DnError::TooLong);
    }
    let rdns = parse(dn)?;
    let rendered: Vec<String> = rdns
        .into_iter()
        .map(|rdn| {
            rdn.iter()
                .map(|ava| format!("{}={}", ava.kind, render(&ava.value)))
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect();
    Ok(rendered.join(","))
}

/// Whether two DNs are the same entry's name. `false` when either is not a DN
/// [`normalize`] understands.
#[must_use]
pub fn same_dn(a: &str, b: &str) -> bool {
    matches!((normalize(a), normalize(b)), (Ok(a), Ok(b)) if a == b)
}

/// Normalise a set of DNs into the keys they compare as, dropping (and
/// counting) the ones that cannot be understood.
#[must_use]
pub fn normalized_set<'a>(dns: impl IntoIterator<Item = &'a str>) -> (BTreeSet<String>, usize) {
    let mut keys = BTreeSet::new();
    let mut skipped = 0;
    for dn in dns {
        match normalize(dn) {
            Ok(key) => {
                keys.insert(key);
            }
            Err(_) => skipped += 1,
        }
    }
    (keys, skipped)
}

fn render(value: &Value) -> String {
    match value {
        Value::Hex(hex) => format!("#{hex}"),
        Value::Text(text) => {
            let chars: Vec<char> = text.chars().collect();
            let last = chars.len().saturating_sub(1);
            let mut out = String::with_capacity(text.len() + 4);
            for (i, c) in chars.iter().enumerate() {
                match c {
                    // Every character with a meaning in the syntax is escaped
                    // wherever it sits, so the key is unambiguous and no two
                    // different values can render alike.
                    '\\' | ',' | '+' | '"' | '<' | '>' | ';' | '=' | '#' => {
                        out.push('\\');
                        out.push(*c);
                    }
                    ' ' if i == 0 || i == last => out.push_str("\\ "),
                    c if c.is_control() => {
                        let mut buf = [0u8; 4];
                        for byte in c.encode_utf8(&mut buf).bytes() {
                            out.push_str(&format!("\\{byte:02x}"));
                        }
                    }
                    c => out.push(*c),
                }
            }
            out
        }
    }
}

/// Split into RDNs of AVAs, in order.
fn parse(dn: &str) -> Result<Vec<Vec<Ava>>, DnError> {
    let bytes = dn.as_bytes();
    let mut rdns: Vec<Vec<Ava>> = Vec::new();
    let mut current: Vec<Ava> = Vec::new();
    let mut at = 0;
    loop {
        let (ava, next, separator) = parse_ava(bytes, at)?;
        current.push(ava);
        at = next;
        match separator {
            Separator::Plus => {}
            Separator::Rdn => {
                current.sort();
                rdns.push(std::mem::take(&mut current));
            }
            Separator::End => {
                current.sort();
                rdns.push(current);
                return Ok(rdns);
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Separator {
    /// `+`: another AVA of the same RDN follows.
    Plus,
    /// `,` or `;`: the next RDN follows.
    Rdn,
    /// End of input.
    End,
}

fn skip_spaces(bytes: &[u8], mut at: usize) -> usize {
    while bytes.get(at) == Some(&b' ') {
        at += 1;
    }
    at
}

/// One `type=value`, starting at `at`. Returns it, where the next one starts,
/// and what ended it.
fn parse_ava(bytes: &[u8], at: usize) -> Result<(Ava, usize, Separator), DnError> {
    let start = skip_spaces(bytes, at);
    // The type runs to the `=`.
    let mut end = start;
    while end < bytes.len() && bytes[end] != b'=' {
        if matches!(bytes[end], b',' | b';' | b'+') {
            return Err(DnError::MissingType);
        }
        end += 1;
    }
    if end >= bytes.len() {
        // Either nothing is left (an empty RDN) or a type without a value.
        return Err(if start >= bytes.len() {
            DnError::EmptyRdn
        } else {
            DnError::MissingType
        });
    }
    let kind = fold_type(std::str::from_utf8(&bytes[start..end]).map_err(|_| DnError::BadType)?)?;

    let value_start = skip_spaces(bytes, end + 1);
    if bytes.get(value_start) == Some(&b'#') {
        let (hex, next, separator) = parse_hex_value(bytes, value_start + 1)?;
        return Ok((
            Ava {
                kind,
                value: Value::Hex(hex),
            },
            next,
            separator,
        ));
    }
    let (value, next, separator) = parse_string_value(bytes, value_start)?;
    Ok((
        Ava {
            kind,
            value: Value::Text(value),
        },
        next,
        separator,
    ))
}

fn fold_type(raw: &str) -> Result<String, DnError> {
    let raw = raw.trim_matches(' ');
    if raw.is_empty() {
        return Err(DnError::MissingType);
    }
    let raw = match raw.get(..4) {
        Some(prefix) if prefix.eq_ignore_ascii_case("oid.") => &raw[4..],
        _ => raw,
    };
    let numeric = raw.chars().all(|c| c.is_ascii_digit() || c == '.')
        && raw.starts_with(|c: char| c.is_ascii_digit())
        && !raw.ends_with('.')
        && !raw.contains("..");
    let descr = raw.starts_with(|c: char| c.is_ascii_alphabetic())
        && raw.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if numeric {
        Ok(raw.to_string())
    } else if descr {
        Ok(raw.to_ascii_lowercase())
    } else {
        Err(DnError::BadType)
    }
}

fn parse_hex_value(bytes: &[u8], at: usize) -> Result<(String, usize, Separator), DnError> {
    let mut end = at;
    while end < bytes.len() && !matches!(bytes[end], b',' | b';' | b'+') {
        end += 1;
    }
    let raw = std::str::from_utf8(&bytes[at..end]).map_err(|_| DnError::BadHexValue)?;
    let hex = raw.trim_end_matches(' ');
    if hex.is_empty() || hex.len() % 2 != 0 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(DnError::BadHexValue);
    }
    let (next, separator) = separator_at(bytes, end);
    Ok((hex.to_ascii_lowercase(), next, separator))
}

fn separator_at(bytes: &[u8], at: usize) -> (usize, Separator) {
    match bytes.get(at) {
        None => (at, Separator::End),
        Some(b'+') => (at + 1, Separator::Plus),
        Some(_) => (at + 1, Separator::Rdn),
    }
}

/// A string value: unescape, trim and fold.
fn parse_string_value(bytes: &[u8], at: usize) -> Result<(String, usize, Separator), DnError> {
    // Each byte remembers whether it was escaped: only an *unescaped* space is
    // insignificant at either end.
    let mut raw: Vec<(u8, bool)> = Vec::new();
    let mut i = at;
    while i < bytes.len() {
        match bytes[i] {
            b',' | b';' | b'+' => break,
            b'"' => return Err(DnError::UnescapedQuote),
            b'\\' => {
                let next = *bytes.get(i + 1).ok_or(DnError::BadEscape)?;
                if matches!(
                    next,
                    b' ' | b'"' | b'#' | b'+' | b',' | b';' | b'<' | b'=' | b'>' | b'\\'
                ) {
                    raw.push((next, true));
                    i += 2;
                } else {
                    let hi = hex_value(next).ok_or(DnError::BadEscape)?;
                    let lo = bytes
                        .get(i + 2)
                        .copied()
                        .and_then(hex_value)
                        .ok_or(DnError::BadEscape)?;
                    raw.push((hi << 4 | lo, true));
                    i += 3;
                }
            }
            other => {
                raw.push((other, false));
                i += 1;
            }
        }
    }
    let (next, separator) = separator_at(bytes, i);
    while raw
        .last()
        .is_some_and(|&(b, escaped)| b == b' ' && !escaped)
    {
        raw.pop();
    }
    let kept: Vec<u8> = raw.into_iter().map(|(b, _)| b).collect();
    let text = String::from_utf8(kept).map_err(|_| DnError::NotUtf8)?;
    Ok((fold_value(&text), next, separator))
}

/// Case-fold and collapse white space runs to one space. Unescaped spaces at
/// either end were already dropped by the caller, so a space that is still at
/// an end was escaped and is kept (as one).
fn fold_value(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_space = false;
    for c in text.chars() {
        if c.is_whitespace() {
            in_space = true;
            continue;
        }
        if in_space {
            out.push(' ');
        }
        in_space = false;
        out.extend(c.to_lowercase());
    }
    if in_space {
        out.push(' ');
    }
    out
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(dn: &str) -> String {
        normalize(dn).unwrap_or_else(|e| panic!("a DN under test must parse: {e}"))
    }

    #[test]
    fn case_of_types_and_values_is_folded() {
        assert_eq!(
            key("CN=Staff,OU=Groups,DC=Example,DC=COM"),
            key("cn=staff,ou=groups,dc=example,dc=com")
        );
        assert_eq!(key("cn=staff,dc=x"), "cn=staff,dc=x");
    }

    #[test]
    fn spacing_around_separators_is_ignored() {
        let want = key("cn=staff,ou=groups,dc=example,dc=com");
        assert_eq!(key("cn=staff, ou=groups, dc=example, dc=com"), want);
        assert_eq!(key("cn = staff , ou = groups,dc=example ,dc=com"), want);
        assert_eq!(key("cn=staff;ou=groups;dc=example;dc=com"), want);
        assert_eq!(key("  cn=staff,ou=groups,dc=example,dc=com  "), want);
    }

    #[test]
    fn inner_space_runs_collapse_and_an_escaped_edge_space_is_kept() {
        assert_eq!(key("cn=Domain   Admins,dc=x"), key("cn=domain admins,dc=x"));
        assert_ne!(key("cn=a\\ ,dc=x"), key("cn=a,dc=x"));
        assert_ne!(key("cn=\\ a,dc=x"), key("cn=a,dc=x"));
    }

    #[test]
    fn escapes_are_resolved_whatever_their_spelling() {
        // A comma in a value: backslash form and hex form are one value.
        assert_eq!(key("cn=Smith\\, John,dc=x"), key("cn=smith\\2C john,dc=x"));
        // ... and it is not a separator: unescaped, the same text is two RDNs,
        // the second of which has no type, so it is refused rather than read.
        assert_eq!(normalize("cn=smith, john,dc=x"), Err(DnError::MissingType));
        // Multi-byte characters: the UTF-8 bytes in hex are the character.
        assert_eq!(key("cn=Z\\C3\\BCrich,dc=x"), key("cn=zürich,dc=x"));
        assert_eq!(key("cn=ZÜRICH,dc=x"), key("cn=z\\c3\\bcrich,dc=x"));
    }

    #[test]
    fn different_dns_stay_different() {
        assert_ne!(key("cn=a,dc=x"), key("cn=b,dc=x"));
        assert_ne!(
            key("cn=a,ou=p,dc=x"),
            key("ou=p,cn=a,dc=x"),
            "RDN order is the path"
        );
        assert_ne!(key("cn=a,dc=x"), key("cn=a,dc=x,dc=y"));
        // A prefix or a parent is not the group.
        assert_ne!(key("cn=staff,ou=groups,dc=x"), key("ou=groups,dc=x"));
        // A special character inside a value cannot be told from structure.
        assert_ne!(key("cn=a\\,dc=x"), key("cn=a,dc=x"));
        assert_ne!(key("cn=a\\+uid=b,dc=x"), key("cn=a+uid=b,dc=x"));
        // A value that merely contains another DN is that value.
        assert_ne!(key("cn=a\\,ou=b,dc=x"), key("cn=a,ou=b,dc=x"));
    }

    #[test]
    fn a_multi_valued_rdn_is_unordered() {
        assert_eq!(key("cn=a+uid=b,dc=x"), key("UID=b+CN=a,dc=x"));
        assert_ne!(key("cn=a+uid=b,dc=x"), key("cn=a,uid=b,dc=x"));
    }

    #[test]
    fn oids_and_hex_values_compare_as_themselves() {
        assert_eq!(key("2.5.4.3=staff,dc=x"), key("OID.2.5.4.3=Staff,dc=x"));
        assert_ne!(
            key("2.5.4.3=staff,dc=x"),
            key("cn=staff,dc=x"),
            "no OID aliasing"
        );
        assert_eq!(key("cn=#04024869,dc=x"), key("CN=#04024869 ,dc=x"));
        assert_eq!(key("cn=#04024869,dc=x"), key("cn=#04024869,dc=x"));
        // A string that begins with `#` is not a hex value.
        assert_ne!(key("cn=\\#0402,dc=x"), key("cn=#0402,dc=x"));
    }

    #[test]
    fn an_empty_value_is_a_value() {
        assert_eq!(key("cn=,dc=x"), "cn=,dc=x");
    }

    #[test]
    fn what_is_not_a_dn_is_refused_not_guessed() {
        let cases = [
            ("", DnError::Empty),
            ("   ", DnError::Empty),
            ("staff", DnError::MissingType),
            ("=staff,dc=x", DnError::MissingType),
            ("cn,dc=x", DnError::MissingType),
            ("cn=a,,dc=x", DnError::MissingType),
            ("cn=a,", DnError::EmptyRdn),
            ("c n=a,dc=x", DnError::BadType),
            ("cn$=a,dc=x", DnError::BadType),
            ("1..2=a,dc=x", DnError::BadType),
            ("cn=a\\", DnError::BadEscape),
            ("cn=a\\zz,dc=x", DnError::BadEscape),
            ("cn=a\\4,dc=x", DnError::BadEscape),
            ("cn=#0,dc=x", DnError::BadHexValue),
            ("cn=#zz,dc=x", DnError::BadHexValue),
            ("cn=\"a\",dc=x", DnError::UnescapedQuote),
            ("cn=a\\ff,dc=x", DnError::NotUtf8),
        ];
        for (dn, want) in cases {
            assert_eq!(normalize(dn), Err(want), "case {dn:?}");
        }
        assert_eq!(
            normalize(&format!("cn={},dc=x", "a".repeat(NORMALIZE_MAX_LEN))),
            Err(DnError::TooLong)
        );
    }

    #[test]
    fn same_dn_is_false_for_anything_it_cannot_read() {
        assert!(same_dn("CN=A, DC=X", "cn=a,dc=x"));
        assert!(!same_dn("cn=a,dc=x", "cn=b,dc=x"));
        // Two unreadable strings are not equal merely because both are broken.
        assert!(!same_dn("garbage", "garbage"));
        assert!(!same_dn("", ""));
    }

    #[test]
    fn a_set_counts_what_it_could_not_read() {
        let (set, skipped) = normalized_set(["cn=a,dc=x", "CN=A,DC=X", "garbage", "cn=b,dc=x"]);
        assert_eq!(set.len(), 2);
        assert_eq!(skipped, 1);
    }

    /// Characters that are filter or DN syntax inside a value never escape the
    /// value: the key stays one RDN with one value.
    #[test]
    fn hostile_characters_in_a_value_stay_inside_it() {
        let k = key("cn=a)(uid=\\2a\\5c,dc=x");
        assert_eq!(k.matches(',').count(), 1, "still two RDNs: {k}");
        assert!(normalize("cn=a)(uid=*\\00,dc=x").is_ok());
    }
}
