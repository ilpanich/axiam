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

use axiam_core::error::{AxiamError, AxiamResult};

/// The common name to put in a certificate's DN, and in the row beside it.
///
/// - `device-001` → `device-001` (unchanged; the I4 twin pins this)
/// - `CN=device-001` → `device-001` (the prefix is understood, once)
/// - `cn=device-001` → `device-001` (RFC 4514 attribute types are
///   case-insensitive)
/// - `O=Acme, CN=device-001` → refused
/// - `CN=` , `` , `   ` → refused
///
/// The refusal is a [`AxiamError::Validation`], so the REST surface answers
/// `400` with the reason rather than issuing a certificate nobody asked for.
pub fn subject_common_name(subject: &str) -> AxiamResult<String> {
    let trimmed = subject.trim();

    if trimmed.is_empty() {
        return Err(AxiamError::Validation {
            message: "subject must not be empty".into(),
        });
    }

    // No attribute-type syntax at all: the caller named the certificate
    // directly, which is the form the documentation now shows.
    if !trimmed.contains('=') {
        return Ok(trimmed.to_owned());
    }

    // Exactly one `CN=` component. `+` is RFC 4514's multi-valued RDN
    // separator and `,` its RDN separator; either means the caller meant a
    // distinguished name, which this deliberately does not parse.
    if let Some(value) = strip_cn_prefix(trimmed) {
        let value = value.trim();
        if !value.is_empty() && !value.contains(',') && !value.contains('+') {
            return Ok(value.to_owned());
        }
    }

    Err(AxiamError::Validation {
        message: "subject must be a bare common name or a single CN= component".into(),
    })
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
}
