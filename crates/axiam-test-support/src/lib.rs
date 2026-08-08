//! Shared fixtures for AXIAM's test suites.
//!
//! Dev-dependency only, and deliberately a leaf: it pulls in `uuid` and
//! nothing else, so no crate under test can ever cycle back through it.

use std::sync::OnceLock;

use uuid::Uuid;

static TEST_PASSWORD: OnceLock<String> = OnceLock::new();

/// The password every test fixture user is created with.
///
/// # Why this exists
///
/// This helper was previously re-declared in fourteen test files across six
/// crates, with **four** different implementations — a per-call random, a
/// process-stable env-var lookup, and two different split-string literals.
/// Nothing reconciled them, so which semantics a given test got depended on
/// which file it lived in. Alongside them sat raw literals, and one of those —
/// a four-word passphrase repeated 21 times across two suites — was what a
/// secret scanner eventually flagged as a critical finding on a pull request.
///
/// The finding was a false positive — the value guards nothing but an
/// in-memory database that is created and dropped inside a single test — but
/// the underlying problem was real: the convention that avoided it was
/// followable only from memory, so each new test file re-decided it, and some
/// decided wrong.
///
/// The offending literal is deliberately not reproduced above: quoting it,
/// even in a doc comment, would re-trip the very scanner this helper exists to
/// satisfy.
///
/// # Semantics
///
/// **Random per process, stable within one.** Both halves are load-bearing:
///
/// - *Random per process* means no credential-shaped literal appears in the
///   source at all, so the scanner finding cannot recur by construction rather
///   than by everyone remembering a rule.
/// - *Stable within a process* is what makes this a safe replacement for the
///   deterministic helpers it subsumes. Many callers create a user with this
///   password and then authenticate as them, calling this function once per
///   step and relying on the two agreeing. A naive per-call random would
///   compile everywhere and fail those tests at runtime.
///
/// Callers that were previously per-call random now share one value within a
/// binary. That is harmless: fixture users may share a password, and Argon2id
/// salts per hash regardless, so no two stored hashes collide.
///
/// `AXIAM_TEST_PASSWORD` overrides it, preserving the escape hatch six of the
/// previous helpers offered — useful when reproducing a failure against a
/// database seeded by an earlier run.
///
/// # Composition
///
/// `Fx1!` prefixes a UUID's simple form, which satisfies every password policy
/// in the codebase — upper, lower, digit, symbol, and comfortably past any
/// length floor — so this is usable for the strict registration paths and not
/// only for direct repository inserts.
pub fn test_password() -> String {
    TEST_PASSWORD
        .get_or_init(|| {
            std::env::var("AXIAM_TEST_PASSWORD")
                .unwrap_or_else(|_| format!("Fx1!{}", Uuid::new_v4().simple()))
        })
        .clone()
}

/// A policy-valid password that is *not* [`test_password`], fresh per call.
///
/// Two uses, both wanting the same thing:
///
/// - the wrong-credentials half of an authentication test, where staying
///   policy-valid is what keeps the negative case honest — a rejection then
///   proves the credential check ran, rather than a length or complexity rule
///   tripping first and passing the test for the wrong reason;
/// - the replacement value in a change-password flow.
///
/// Unlike [`test_password`] this is *not* memoised: a caller rotating a
/// password twice needs two distinct values, and a caller wanting one stable
/// value can bind it to a variable.
pub fn other_password() -> String {
    format!("Nx9?{}", Uuid::new_v4().simple())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_stable_within_a_process() {
        // The property the deterministic call sites depend on.
        assert_eq!(test_password(), test_password());
    }

    #[test]
    fn other_password_differs_from_the_fixture_and_from_itself() {
        assert_ne!(test_password(), other_password());
        // Fresh per call — a double rotation needs two distinct values.
        assert_ne!(other_password(), other_password());
    }

    #[test]
    fn other_password_also_satisfies_the_policy() {
        // Load-bearing for negative tests: a wrong password that is *invalid*
        // proves nothing, because the policy check would reject it before the
        // credential check ever ran.
        let pw = other_password();
        assert!(pw.len() >= 12);
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(pw.chars().any(|c| !c.is_ascii_alphanumeric()));
    }

    #[test]
    fn satisfies_the_strictest_policy_in_the_codebase() {
        let pw = test_password();
        assert!(pw.len() >= 12, "length floor: {pw}");
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()), "upper: {pw}");
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()), "lower: {pw}");
        assert!(pw.chars().any(|c| c.is_ascii_digit()), "digit: {pw}");
        assert!(
            pw.chars().any(|c| !c.is_ascii_alphanumeric()),
            "symbol: {pw}"
        );
    }
}
