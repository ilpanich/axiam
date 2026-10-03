//! Cleaning of the values a directory entry contributes to an account
//! (G-3, T23.3.3 and T23.3.5).
//!
//! The directory is another party's system: whoever administers it chooses
//! every attribute, so a value is bounded, stripped of control and
//! bidirectional-override characters, and refused when it cannot be made into
//! what a local account holds, **before** it is stored or shown to anyone.
//!
//! Two callers share these rules and must not drift apart: just-in-time
//! provisioning (`axiam-auth`), which builds a new account from an entry, and
//! the sync job (`axiam-directory`), which keeps an existing account's
//! username, email address and display name equal to the entry's. They live in
//! this layer-0 crate because the second cannot reach the first (layering) and
//! a copy would be a second definition of "an acceptable username".

use crate::models::directory::DirectoryIdentity;

/// Longest username or display name taken from a directory, in characters.
pub const MAX_NAME_CHARS: usize = 255;
/// Longest e-mail address taken from a directory (RFC 5321 §4.5.3.1.3).
pub const MAX_EMAIL_CHARS: usize = 254;

/// A username or an address: trimmed, non-empty, bounded, and with no control
/// or whitespace characters at all. Refused rather than repaired — a repaired
/// name is a different name.
#[must_use]
pub fn clean_identifier(raw: &str, max_chars: usize) -> Option<String> {
    let trimmed = raw.trim();
    let valid = !trimmed.is_empty()
        && trimmed.chars().count() <= max_chars
        && !trimmed
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || is_bidi_control(c));
    valid.then(|| trimmed.to_string())
}

/// One `@`, something on each side, a dot in the domain.
#[must_use]
pub fn plausible_email(email: &str) -> bool {
    let mut parts = email.splitn(2, '@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.contains('@')
}

/// A display name: control and bidirectional-override characters removed (a
/// right-to-left override makes a name render as something else), whitespace
/// runs collapsed, bounded. Dropped when nothing is left.
#[must_use]
pub fn clean_display_name(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !is_bidi_control(*c) && (!c.is_control() || c.is_whitespace()))
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect();
    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return None;
    }
    Some(collapsed.chars().take(MAX_NAME_CHARS).collect())
}

/// The Unicode directional formatting characters (UAX #9): embeddings,
/// overrides, isolates and the marks.
#[must_use]
pub fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// The cleaned attributes of an entry, **each independently optional**: an
/// attribute the entry does not carry, or carries in a form that cannot be
/// cleaned, is `None`, and the sync job leaves the account's value alone
/// (T23.3.5). Provisioning, which needs a username and an address, has its own
/// stricter constructor in `axiam-auth`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CleanedAttributes {
    /// The entry's username attribute, cleaned.
    pub username: Option<String>,
    /// The entry's e-mail address, cleaned and plausible.
    pub email: Option<String>,
    /// The entry's display name, cleaned.
    pub display_name: Option<String>,
}

impl CleanedAttributes {
    /// Clean what `identity` carries.
    #[must_use]
    pub fn from_identity(identity: &DirectoryIdentity) -> Self {
        Self {
            username: identity
                .username
                .as_deref()
                .and_then(|raw| clean_identifier(raw, MAX_NAME_CHARS)),
            email: identity
                .email
                .as_deref()
                .and_then(|raw| clean_identifier(raw, MAX_EMAIL_CHARS))
                .filter(|email| plausible_email(email)),
            display_name: identity
                .display_name
                .as_deref()
                .and_then(clean_display_name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(username: &str, email: &str, display: &str) -> DirectoryIdentity {
        DirectoryIdentity {
            external_id: "id".into(),
            dn: "uid=x,dc=example,dc=com".into(),
            username: Some(username.into()),
            email: Some(email.into()),
            display_name: Some(display.into()),
        }
    }

    #[test]
    fn an_ordinary_entry_is_taken_as_it_is() {
        let cleaned =
            CleanedAttributes::from_identity(&identity("alice", "alice@example.com", "Alice A"));
        assert_eq!(cleaned.username.as_deref(), Some("alice"));
        assert_eq!(cleaned.email.as_deref(), Some("alice@example.com"));
        assert_eq!(cleaned.display_name.as_deref(), Some("Alice A"));
    }

    #[test]
    fn a_value_that_cannot_be_cleaned_is_absent_not_repaired() {
        let cleaned = CleanedAttributes::from_identity(&identity(
            "ali ce",
            "not-an-address",
            "\u{202E}\u{200F}",
        ));
        assert_eq!(cleaned, CleanedAttributes::default());
    }

    #[test]
    fn a_display_name_loses_its_overrides_and_collapses_whitespace() {
        assert_eq!(
            clean_display_name("  Al\u{202E}ice \n  A\u{0007}  ").as_deref(),
            Some("Alice A")
        );
        assert_eq!(
            clean_display_name(&"x".repeat(400)).map(|s| s.len()),
            Some(255)
        );
    }

    #[test]
    fn an_overlong_identifier_is_refused() {
        assert!(clean_identifier(&"a".repeat(MAX_NAME_CHARS + 1), MAX_NAME_CHARS).is_none());
        assert!(clean_identifier(&"a".repeat(MAX_NAME_CHARS), MAX_NAME_CHARS).is_some());
    }
}
