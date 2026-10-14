//! The retry policy of the Vault revocation sweep (T-470, #603).
//!
//! A revocation Vault refuses is not retried at every tick: each refusal pushes
//! the row's next attempt out (1 minute, doubling, to 6 hours), a replica claims
//! a row before it attempts it, and a row that keeps failing past
//! [`FAILING_AFTER_ATTEMPTS`] is reported as its own job-health error. The
//! constants and the two pure functions live here, apart from the sweep, so the
//! next consumer of the same bookkeeping (a CA certificate's revocation) does
//! not copy them.

use std::time::Duration;

/// The wait after a row's first refusal.
pub const BACKOFF_BASE: Duration = Duration::from_secs(60);

/// The longest wait between two attempts at one row.
pub const BACKOFF_CAP: Duration = Duration::from_secs(6 * 60 * 60);

/// Refusals after which a row counts as failing for good, and `/health/jobs`
/// reports it (as `vault_revocation_failing`) instead of failing the pass that
/// retries it. Twelve attempts span about a day: the first nine back off from
/// one minute to a little over four hours, the rest wait the six-hour cap.
pub const FAILING_AFTER_ATTEMPTS: u32 = 12;

/// How long a replica holds a claimed row. Longer than one sweep pass
/// ([`crate::cert`] bounds it to 30 seconds), so a row being attempted is not
/// due for anyone else; a replica that dies mid-attempt loses the row for this
/// long and no longer, with nothing counted against the row.
pub const CLAIM_LEASE: Duration = Duration::from_secs(120);

/// The longest reason a row keeps, in characters: a status and a short message.
pub const MAX_REASON_CHARS: usize = 256;

/// How long to wait before the next attempt at a row that has now failed
/// `attempts` times (1 for the first refusal): [`BACKOFF_BASE`] doubled for each
/// earlier refusal, capped at [`BACKOFF_CAP`].
pub fn backoff(attempts: u32) -> Duration {
    let doublings = attempts.saturating_sub(1).min(20);
    BACKOFF_BASE
        .saturating_mul(1u32 << doublings)
        .min(BACKOFF_CAP)
}

/// A custodian's error as a row may keep it: control characters and runs of
/// whitespace collapsed, anything that reads like a Vault token replaced, and
/// the whole cut to [`MAX_REASON_CHARS`].
///
/// The stored reason is read by operators and may reach a log or an export, so
/// it carries neither a credential nor a response body. The Vault client never
/// puts its token in an error; this is the second line, for a message a server
/// echoed back or a future change.
pub fn sanitise_reason(raw: &str) -> String {
    let words: Vec<&str> = raw.split_whitespace().collect();
    let mut out = String::new();
    for word in words {
        if !out.is_empty() {
            out.push(' ');
        }
        let word: String = word.chars().filter(|c| !c.is_control()).collect();
        if looks_like_a_token(&word) {
            out.push_str("[redacted]");
        } else {
            out.push_str(&word);
        }
    }
    if out.chars().count() > MAX_REASON_CHARS {
        let mut cut: String = out.chars().take(MAX_REASON_CHARS - 1).collect();
        cut.push('…');
        return cut;
    }
    out
}

/// A Vault token as Vault spells one: `hvs.`, `hvb.` or `hvr.` and a body, or
/// the older `s.` followed by a long run of token characters.
fn looks_like_a_token(word: &str) -> bool {
    let word =
        word.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '_' && c != '-');
    let body = |prefix: &str| word.strip_prefix(prefix).filter(|rest| rest.len() >= 8);
    ["hvs.", "hvb.", "hvr.", "s."]
        .iter()
        .any(|prefix| body(prefix).is_some_and(|rest| rest.chars().all(is_token_char)))
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_from_a_minute_to_the_cap() {
        let minutes: Vec<u64> = (1..=11).map(|n| backoff(n).as_secs() / 60).collect();
        assert_eq!(minutes, [1, 2, 4, 8, 16, 32, 64, 128, 256, 360, 360]);
        assert_eq!(backoff(0), BACKOFF_BASE, "no failure yet waits the base");
        assert_eq!(
            backoff(u32::MAX),
            BACKOFF_CAP,
            "a huge count cannot overflow"
        );
    }

    #[test]
    fn a_reason_is_one_bounded_line_without_a_token() {
        let reason = sanitise_reason(
            "vault pki: http://v:8200/v1/pki/revoke answered 403 Forbidden:\n\tpermission denied \
             for hvs.CAESIAbcdefghijklmnop012345",
        );
        assert!(!reason.contains('\n') && !reason.contains('\t'));
        assert!(reason.contains("403 Forbidden") && reason.contains("permission denied"));
        assert!(!reason.contains("hvs."), "{reason}");
        assert!(reason.contains("[redacted]"));

        let long = sanitise_reason(&"x".repeat(10_000));
        assert_eq!(long.chars().count(), MAX_REASON_CHARS);
        // Multi-byte text is cut on a character, not a byte.
        let wide = sanitise_reason(&"é".repeat(1_000));
        assert_eq!(wide.chars().count(), MAX_REASON_CHARS);
        // Ordinary words that merely start like a prefix are left alone.
        assert_eq!(sanitise_reason("s.o.s. hvs.x"), "s.o.s. hvs.x");
    }
}
