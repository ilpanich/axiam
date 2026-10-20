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
        out.push_str(&redact_tokens(&word));
    }
    if out.chars().count() > MAX_REASON_CHARS {
        let mut cut: String = out.chars().take(MAX_REASON_CHARS - 1).collect();
        cut.push('…');
        return cut;
    }
    out
}

/// The shortest body a token must have after its prefix.
const MIN_TOKEN_BODY: usize = 8;

/// `word` with every Vault token in it replaced, the token's span only.
///
/// A token starts at any position whose previous character is not a token
/// character (`=`, `"`, `:`, `'`, or the start), so `token=hvs.…` and
/// `{"token":"hvs.…"}` are masked and the text around them is kept.
fn redact_tokens(word: &str) -> String {
    let chars: Vec<char> = word.chars().collect();
    let mut out = String::with_capacity(word.len());
    let mut i = 0;
    while i < chars.len() {
        let at_boundary = i == 0 || !is_token_char(chars[i - 1]);
        match at_boundary.then(|| token_len(&chars[i..])).flatten() {
            Some(len) => {
                out.push_str("[redacted]");
                i += len;
            }
            None => {
                out.push(chars[i]);
                i += 1;
            }
        }
    }
    out
}

/// The length of the Vault token that `s` starts with, if it starts with one.
///
/// `hvs.`, `hvb.` and `hvr.` take a body of token characters (which include
/// `.`: the modern body is base64url and may carry the separator). The older
/// `s.` (service) and `b.` (batch) take a body of base62/base64url characters
/// without `.`, so a host name such as `b.vault-internal.example.com` is not a
/// token. A `.` that ends the match is punctuation and stays out of the span.
fn token_len(s: &[char]) -> Option<usize> {
    let starts =
        |prefix: &str| prefix.len() <= s.len() && prefix.chars().zip(s).all(|(p, c)| p == *c);
    let run = |from: usize, accept: fn(char) -> bool| {
        s[from..].iter().take_while(|c| accept(**c)).count()
    };
    if ["hvs.", "hvb.", "hvr."].iter().any(|p| starts(p)) {
        let body = s[4..].iter().take_while(|c| is_token_char(**c)).count();
        let body = s[4..4 + body]
            .iter()
            .rposition(|c| *c != '.')
            .map_or(0, |last| last + 1);
        return (body >= MIN_TOKEN_BODY).then_some(4 + body);
    }
    if starts("s.") || starts("b.") {
        let body = run(2, is_legacy_body_char);
        let continues = s.get(2 + body) == Some(&'.')
            && s.get(3 + body)
                .is_some_and(|c| is_token_char(*c) && *c != '.');
        return (body >= MIN_TOKEN_BODY && !continues).then_some(2 + body);
    }
    None
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'
}

fn is_legacy_body_char(c: char) -> bool {
    is_token_char(c) && c != '.'
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `prefix` and a low-entropy body of `12 * parts` token characters, built
    /// at run time: a literal looks like a credential to secret scanners.
    fn fake_token(prefix: &str, parts: usize) -> String {
        format!(
            "{prefix}{}",
            ["fake", "body", "0123"].concat().repeat(parts)
        )
    }

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
        let reason = sanitise_reason(&format!(
            "vault pki: http://v:8200/v1/pki/revoke answered 403 Forbidden:\n\tpermission denied \
             for {}",
            fake_token("hvs.", 3)
        ));
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
        assert_eq!(sanitise_reason("b.c. b.short"), "b.c. b.short");
    }

    /// #665 (R110W1-05): a token is masked wherever a non-token character
    /// precedes it, the span only; a host name that starts like a legacy
    /// prefix is left alone.
    #[test]
    fn a_token_is_masked_at_any_boundary_and_the_text_around_it_stays() {
        let tok = fake_token("hvs.", 3);
        let tok = tok.as_str();
        assert_eq!(sanitise_reason(&format!("token={tok}")), "token=[redacted]");
        assert_eq!(
            sanitise_reason(&format!("{{\"token\":\"{tok}\"}}")),
            "{\"token\":\"[redacted]\"}"
        );
        assert_eq!(sanitise_reason(&format!("\"{tok}\".")), "\"[redacted]\".");
        assert_eq!(sanitise_reason(&format!("'{tok}'.")), "'[redacted]'.");
        assert_eq!(sanitise_reason(&format!("x:{tok}.")), "x:[redacted].");
        assert_eq!(
            sanitise_reason(&format!("token={},", fake_token("b.", 1))),
            "token=[redacted],"
        );
        // Preceded by a token character it is part of a longer word.
        assert_eq!(sanitise_reason(&format!("abc{tok}")), format!("abc{tok}"));

        assert_eq!(
            sanitise_reason("b.vault-internal.example.com"),
            "b.vault-internal.example.com"
        );
        assert_eq!(
            sanitise_reason("s.vault-1.eu-west.internal"),
            "s.vault-1.eu-west.internal"
        );
    }

    /// R101W1-06: a legacy batch token (`b.` and a body) is masked as `s.` is.
    #[test]
    fn a_legacy_batch_token_is_masked() {
        let (long, short) = (fake_token("b.", 2), fake_token("b.", 1));
        let reason = sanitise_reason(&format!("denied for {long} and \"{short}\""));
        assert!(!reason.contains(&short), "{reason}");
        assert_eq!(reason.matches("[redacted]").count(), 2, "{reason}");
        assert!(reason.starts_with("denied for "));
    }

    /// The row, the audit append and the log each apply the sanitiser to what
    /// the sweep or the handler already sanitised: a second pass changes nothing.
    #[test]
    fn sanitising_is_idempotent() {
        let tokens = format!(
            "denied for {} {}",
            fake_token("hvs.", 3),
            fake_token("b.", 1)
        );
        for raw in [&tokens, &"y ".repeat(5_000), &"é".repeat(1_000)] {
            let once = sanitise_reason(raw);
            assert_eq!(sanitise_reason(&once), once);
        }
    }
}
