//! The one field a caller names a certificate by, and what AXIAM does with it.
//!
//! Every AXIAM certificate — root CA, signing CA, leaf — has exactly one
//! distinguished-name component: a common name. The API field that carries it
//! is called `subject`, and every example in the documentation spelled it
//! `CN=device-001`, so callers sent that. rcgen then pushed the whole string as
//! the *value* of a `CommonName` RDN, and the certificate came out with a DN of
//! `CN=CN=device-001` while the row said `CN=device-001` (DF-023). Two wrong
//! answers, disagreeing with each other.
//!
//! **Decision D-2: a bare common name, or exactly one `CN=` component.**
//! Anything else containing `=` is refused. A full RFC 4514 distinguished-name
//! parser is scope with no consumer: the certificate has one CN, so a parser
//! that accepted `O=Acme, OU=Devices, CN=device-001` would have to discard
//! everything it parsed — which is a worse outcome than saying so.
//!
//! **What the name may be made of (#649).** A common name is rendered, by
//! people and programs AXIAM does not control, into places that read it as
//! something other than a name: a log line, a FreeRADIUS `files` entry, an
//! ACL file, an operator's terminal. A CN holding a newline writes a line of
//! its own into any of them. So the name is a short run of *printable*
//! characters: no control character (`char::is_control`: C0, DEL, C1), no
//! whitespace other than a single U+0020 between words, no Unicode format
//! character that renders as nothing or reorders what is around it (see
//! [`is_invisible_format`]), and at most [`MAX_COMMON_NAME_CHARS`] characters.
//! The same rules apply to the common name of a caller's CSR, which is the
//! other way a name reaches a certificate ([`check_common_name_value`]).

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::directory_profile::is_bidi_control;

/// The longest common name AXIAM issues, **in characters** (Unicode scalar
/// values, `str::chars().count()`), not bytes.
///
/// RFC 5280 Appendix A defines `ub-common-name INTEGER ::= 64` and types the
/// attribute `DirectoryString (SIZE (1..ub-common-name))`; for `UTF8String` the
/// size constraint counts characters. Counting bytes would refuse a 30-character
/// name in a non-Latin script that RFC 5280 admits, and counting anything but
/// characters would let a verifier that enforces the bound refuse a certificate
/// AXIAM signed. (A 64-character name can be up to 256 octets of UTF-8; that is
/// what the standard says.)
pub const MAX_COMMON_NAME_CHARS: usize = 64;

/// The common name to put in a certificate's DN, and in the row beside it.
///
/// - `device-001` → `device-001` (unchanged; the I4 twin pins this)
/// - `CN=device-001` → `device-001` (the prefix is understood, once)
/// - `cn=device-001` → `device-001` (RFC 4514 attribute types are
///   case-insensitive)
/// - `O=Acme, CN=device-001` → refused
/// - `CN=` , `` , `   ` → refused
/// - `device\n001`, `a\tb`, `a\u{0}b`, a name of more than 64 characters,
///   `a  b` (two spaces), a name with a bidi override → refused (#649; see
///   [`check_common_name_value`] and [`MAX_COMMON_NAME_CHARS`])
///
/// Only spaces are trimmed from the two ends, and what is left is checked as
/// sent: a trailing newline is a refusal, not something quietly removed.
///
/// The refusal is a [`AxiamError::Validation`], so the REST surface answers
/// `400` with the reason rather than issuing a certificate nobody asked for.
pub fn subject_common_name(subject: &str) -> AxiamResult<String> {
    // Only U+0020 is trimmed. `str::trim` would also drop a trailing `\n` or
    // tab, quietly turning a subject with a control character in it into one
    // without — the refusal below must see what the caller sent.
    let trimmed = subject.trim_matches(' ');

    if trimmed.is_empty() {
        return Err(AxiamError::Validation {
            message: "subject must not be empty".into(),
        });
    }

    // No attribute-type syntax at all: the caller named the certificate
    // directly, which is the form the documentation now shows.
    if !trimmed.contains('=') {
        check_common_name_value(trimmed, "subject")?;
        return Ok(trimmed.to_owned());
    }

    // Exactly one `CN=` component. `+` is RFC 4514's multi-valued RDN
    // separator and `,` its RDN separator; either means the caller meant a
    // distinguished name, which this deliberately does not parse.
    if let Some(value) = strip_cn_prefix(trimmed) {
        let value = value.trim_matches(' ');
        if !value.is_empty() && !value.contains(',') && !value.contains('+') {
            check_common_name_value(value, "subject")?;
            return Ok(value.to_owned());
        }
    }

    Err(AxiamError::Validation {
        message: "subject must be a bare common name or a single CN= component".into(),
    })
}

/// The rules a common name must meet whatever way it reached AXIAM, as a
/// check that changes nothing.
///
/// [`subject_common_name`] runs it on the normalised name of a request; the
/// CSR path runs it on the common name the CSR carries, which it cannot
/// rewrite (a remote signer signs the CSR's own bytes, so a rewritten name
/// would make the row and the certificate disagree). `what` names the field in
/// the refusal. **The refusal never quotes the value**: the value is exactly
/// what failed to be safe to print.
///
/// A name is refused when it is empty, longer than [`MAX_COMMON_NAME_CHARS`]
/// characters, has a space at either end or two spaces in a row (a name that
/// differs from another only in its spacing is a look-alike, not a different
/// device), or holds a control character, a whitespace character other than
/// U+0020, or an invisible or reordering format character.
pub(crate) fn check_common_name_value(value: &str, what: &str) -> AxiamResult<()> {
    if value.is_empty() {
        return Err(AxiamError::Validation {
            message: format!("{what} must not be empty"),
        });
    }
    if value.chars().count() > MAX_COMMON_NAME_CHARS {
        return Err(AxiamError::Validation {
            message: format!(
                "{what} must be at most {MAX_COMMON_NAME_CHARS} characters \
                 (RFC 5280 ub-common-name)"
            ),
        });
    }
    if value
        .chars()
        .any(|c| c.is_control() || (c.is_whitespace() && c != ' ') || is_invisible_format(c))
    {
        return Err(AxiamError::Validation {
            message: format!(
                "{what} must be printable: no control, line-break, tab or other whitespace \
                 character except a single space between words, and no invisible or \
                 bidirectional formatting character"
            ),
        });
    }
    if value.starts_with(' ') || value.ends_with(' ') || value.contains("  ") {
        return Err(AxiamError::Validation {
            message: format!(
                "{what} must not start or end with a space or contain two spaces in a row"
            ),
        });
    }
    Ok(())
}

/// A Unicode format (`Cf`) or separator character that is not `is_control` and
/// not whitespace-by-`is_whitespace`, yet is invisible or changes how the text
/// around it is laid out.
///
/// **Decision (#649): refused.** Evidence: AXIAM already refuses the bidi
/// controls in a user name and an e-mail address from a directory (T-335,
/// `directory_profile::is_bidi_control`) and in a CIBA binding message
/// (T23.7.1), for the reason that applies here — a name that displays as
/// `press-07` but is `70-sserp` in memory, or a zero-width character that makes
/// two names look equal, defeats an operator reading a log, an ACL or a
/// FreeRADIUS placement table. No legitimate device or service name needs
/// them; a person's name in a script that does needs the joiners only in
/// shapes a `Device`/`Service` CN does not take, and `User` certificates are
/// keyed on the account, not on this string (#533). The set: the bidi controls
/// (U+200E/F, U+202A–E, U+2066–9), U+061C, the zero-width and joiner characters
/// U+200B–D, the line and paragraph separators U+2028/9, the invisible
/// operators U+2060–4 and the deprecated U+206A–F, U+00AD soft hyphen, U+180E,
/// the BOM U+FEFF, the interlinear annotation marks U+FFF9–B and the tag
/// characters U+E0000–E007F.
fn is_invisible_format(c: char) -> bool {
    is_bidi_control(c)
        || matches!(
            c,
            '\u{00AD}'
                | '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200D}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{2060}'..='\u{2064}'
                | '\u{206A}'..='\u{206F}'
                | '\u{FEFF}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{E0000}'..='\u{E007F}'
        )
}

/// `CN=` / `cn=` / `Cn=` at the very start, and what follows it.
fn strip_cn_prefix(s: &str) -> Option<&str> {
    let (head, rest) = s.split_at_checked(3)?;
    head.eq_ignore_ascii_case("CN=").then_some(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The I4 twin: the form the documentation now shows is passed through
    /// untouched, so a deployment that was already correct sees no change.
    #[test]
    fn a_bare_subject_is_unchanged() {
        for s in [
            "device-001",
            "jdoe@example.com",
            "ACME Corp Root CA",
            "svc.internal",
        ] {
            assert_eq!(subject_common_name(s).unwrap(), s);
        }
    }

    #[test]
    fn a_single_cn_component_is_understood_once() {
        assert_eq!(subject_common_name("CN=device-001").unwrap(), "device-001");
        assert_eq!(subject_common_name("cn=device-001").unwrap(), "device-001");
        assert_eq!(subject_common_name("Cn=device-001").unwrap(), "device-001");
        assert_eq!(
            subject_common_name("  CN=  ACME Corp Root CA  ").unwrap(),
            "ACME Corp Root CA"
        );
    }

    /// Idempotent, which is what makes it safe to apply on every path: a value
    /// that has already been through it passes through unchanged.
    #[test]
    fn normalisation_is_idempotent() {
        let once = subject_common_name("CN=device-001").unwrap();
        assert_eq!(subject_common_name(&once).unwrap(), once);
    }

    #[test]
    fn a_multi_rdn_subject_is_refused() {
        for s in [
            "O=Acme, CN=device-001",
            "CN=device-001, O=Acme",
            "CN=device-001+OU=Devices",
            "OU=Devices",
            "device=001",
        ] {
            let err = subject_common_name(s).unwrap_err();
            assert!(
                matches!(&err, AxiamError::Validation { message }
                    if message.contains("bare common name")),
                "{s} should have been refused, got {err:?}"
            );
        }
    }

    #[test]
    fn an_empty_subject_is_refused() {
        for s in ["", "   ", "CN=", "CN=   "] {
            assert!(
                matches!(subject_common_name(s), Err(AxiamError::Validation { .. })),
                "{s:?} should have been refused"
            );
        }
    }

    /// The refusal names the field and the rule, because the caller's next
    /// action is to edit one string.
    #[test]
    fn the_refusal_says_what_is_accepted() {
        let err = subject_common_name("O=Acme, CN=x").unwrap_err();
        let AxiamError::Validation { message } = err else {
            panic!("expected a validation error");
        };
        assert!(message.contains("subject"), "{message}");
        assert!(message.contains("CN="), "{message}");
    }

    #[test]
    fn a_control_character_is_refused() {
        for s in [
            "device\n001",
            "device-001\n",
            "\ndevice-001",
            "dev\tice",
            "device-001\t",
            "dev\u{0}ice",
            "device-001\u{0}",
            "dev\rice",
            "dev\u{7f}ice",
            "dev\u{85}ice",
            "CN=dev\nice",
            "CN=device-001\r\nCN=other",
        ] {
            let err = subject_common_name(s).unwrap_err();
            assert!(
                matches!(&err, AxiamError::Validation { message } if message.contains("printable")),
                "{s:?} should have been refused as unprintable, got {err:?}"
            );
        }
    }

    #[test]
    fn a_refusal_never_quotes_the_subject() {
        let err = subject_common_name("evil\nINJECTED").unwrap_err();
        let AxiamError::Validation { message } = err else {
            panic!("expected a validation error");
        };
        assert!(!message.contains("INJECTED"), "{message}");
        assert!(!message.contains('\n'), "{message}");
    }

    #[test]
    fn the_length_bound_is_64_characters() {
        let ok = "a".repeat(64);
        assert_eq!(subject_common_name(&ok).unwrap(), ok);
        assert_eq!(subject_common_name(&format!("CN={ok}")).unwrap(), ok);

        let too_long = "a".repeat(65);
        for s in [too_long.clone(), format!("CN={too_long}")] {
            let err = subject_common_name(&s).unwrap_err();
            assert!(
                matches!(&err, AxiamError::Validation { message }
                    if message.contains("64 characters")),
                "{err:?}"
            );
        }
    }

    /// The bound counts characters, not bytes: 64 two-byte characters (128
    /// octets) are within `ub-common-name`, 65 are not.
    #[test]
    fn the_length_bound_counts_characters_not_bytes() {
        let ok = "é".repeat(64);
        assert_eq!(ok.len(), 128);
        assert_eq!(subject_common_name(&ok).unwrap(), ok);
        assert!(subject_common_name(&"é".repeat(65)).is_err());
        // A scalar value outside the BMP is one character, not two UTF-16 units.
        assert!(subject_common_name(&"\u{1F512}".repeat(64)).is_ok());
        assert!(subject_common_name(&"\u{1F512}".repeat(65)).is_err());
    }

    #[test]
    fn invisible_and_reordering_characters_are_refused() {
        for c in [
            '\u{202E}',
            '\u{202D}',
            '\u{2066}',
            '\u{2069}',
            '\u{200E}',
            '\u{200B}',
            '\u{200D}',
            '\u{2028}',
            '\u{2029}',
            '\u{FEFF}',
            '\u{00AD}',
            '\u{2060}',
            '\u{061C}',
            '\u{E0041}',
            '\u{00A0}',
            '\u{3000}',
        ] {
            let s = format!("press{c}07");
            assert!(
                matches!(subject_common_name(&s), Err(AxiamError::Validation { .. })),
                "{:?} should have been refused",
                c
            );
        }
    }

    /// What stays legal: spaces between words, and printable non-ASCII.
    #[test]
    fn printable_names_with_spaces_and_non_ascii_pass() {
        for s in [
            "Plant A line 1 devices",
            "Müller Gerät 7",
            "ルート CA",
            "svc_x-1.y",
        ] {
            assert_eq!(subject_common_name(s).unwrap(), s);
        }
    }

    #[test]
    fn spacing_that_makes_a_look_alike_is_refused() {
        for s in ["press  07", "CN=press  07", "CN=  press  07"] {
            assert!(subject_common_name(s).is_err(), "{s:?}");
        }
        // Spaces at the two ends are trimmed, as before.
        assert_eq!(subject_common_name("  press 07  ").unwrap(), "press 07");
    }

    #[test]
    fn the_csr_check_rewrites_nothing_and_applies_the_same_rules() {
        assert!(check_common_name_value("press-07", "x").is_ok());
        for v in [
            "",
            " press",
            "press ",
            "pr\ness",
            &"a".repeat(65),
            "a\u{202E}b",
        ] {
            assert!(check_common_name_value(v, "x").is_err(), "{v:?}");
        }
    }
}
