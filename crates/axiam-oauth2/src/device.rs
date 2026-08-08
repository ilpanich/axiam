//! OAuth2 Device Authorization Grant (RFC 8628) — B2.
//!
//! The grant for input-constrained devices: a TV, a CLI, a headless IoT
//! sensor. The device shows a short code, the user types it on a phone or
//! laptop, and the device polls until the user has approved.
//!
//! # The two codes, and why they are shaped so differently
//!
//! | | `device_code` | `user_code` |
//! |---|---|---|
//! | who handles it | the device, over TLS | a **human**, by reading and typing |
//! | entropy | 256 bits | ~34 bits |
//! | stored as | SHA-256 hash | normalised plaintext |
//! | lifetime | the grant's | the grant's |
//!
//! The device code is an ordinary bearer secret and is treated like one: CSPRNG,
//! hashed at rest, never logged.
//!
//! The user code cannot be. It has to be read off a screen and typed on a
//! phone, so it is short, and short means guessable — which makes **rate
//! limiting the verification endpoint a security control, not a courtesy**.
//! See [`brute_force_attempts_required`] for the arithmetic that sizes it.

use rand::RngExt;
use sha2::{Digest, Sha256};

/// Alphabet for the user code (RFC 8628 §6.1 recommends exactly this shape).
///
/// 20 uppercase consonants. What is excluded, and why:
///
/// - **every digit.** This is what removes the `O`/`0` and `I`/`1`/`L`
///   confusions at the root: with no digits in the alphabet, a user squinting
///   at a television cannot mistake a letter for one.
/// - **every vowel** (`A E I O U`) **and `Y`.** Partly the `O` confusion
///   again, but mainly so the generated code cannot spell a word — nobody
///   should have to read an obscenity off their screen to sign in.
///
/// Excluding characters costs entropy, and that is the right trade: a user who
/// misreads a character retries, and a retry is an *attempt* against the rate
/// limit — so ambiguity does not merely annoy, it consumes the budget that
/// protects the code (see [`brute_force_attempts_required`]).
pub const USER_CODE_CHARSET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

/// Length of the generated user code, excluding the display hyphen.
pub const USER_CODE_LEN: usize = 8;

/// Default lifetime of a device grant (RFC 8628 `expires_in`).
///
/// Long enough for a user to find their phone, short enough that a code left
/// on a screen in a public place is not a standing invitation.
pub const DEFAULT_EXPIRES_IN_SECS: u64 = 600;

/// Default minimum seconds between token polls (RFC 8628 `interval`).
pub const DEFAULT_INTERVAL_SECS: u64 = 5;

/// Generate a `user_code` in its display form, e.g. `BCDF-GHJK`.
///
/// The hyphen is presentation only — [`normalize_user_code`] strips it, so a
/// user may type it either way.
pub fn generate_user_code() -> String {
    let mut rng = rand::rng();
    let raw: String = (0..USER_CODE_LEN)
        .map(|_| {
            let idx = rng.random_range(0..USER_CODE_CHARSET.len());
            USER_CODE_CHARSET[idx] as char
        })
        .collect();
    format!("{}-{}", &raw[..4], &raw[4..])
}

/// Normalise a user-typed code for lookup.
///
/// Uppercases, and drops everything that is not in the charset — hyphens,
/// spaces, and the stray characters a phone keyboard inserts. Without this a
/// user typing `bcdf ghjk` would simply not be found, and would reasonably
/// conclude the code was wrong rather than that they had typed it in a form
/// the server did not accept.
pub fn normalize_user_code(input: &str) -> String {
    input
        .chars()
        .flat_map(|c| c.to_uppercase())
        .filter(|c| USER_CODE_CHARSET.contains(&(*c as u8)))
        .collect()
}

/// Generate a `device_code`: 256 bits of CSPRNG, base64url, unpadded.
pub fn generate_device_code() -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rng.random();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// SHA-256 of a device code, hex-encoded — what is stored.
///
/// SHA-256 rather than a KDF for the same reason refresh tokens use it: the
/// value is a 256-bit CSPRNG string, so there is no offline-guessing threat
/// for a KDF to defend against, and the poll path runs every few seconds per
/// device by design.
pub fn hash_device_code(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

/// How many guesses an attacker needs, on average, to hit a live user code —
/// given `rate_per_minute` verification attempts and a `lifetime_secs` window.
///
/// # The number this exists to keep honest
///
/// The user code is ~34 bits (`20^8 ≈ 2.56 × 10^10`), which sounds ample and
/// is not the relevant figure. What matters is how many guesses an attacker
/// can *make* while a code is live, against how many codes are live — a
/// deployment with many concurrent pending grants shrinks the search space
/// proportionally.
///
/// The OWASP bar this implements: `charset^len / (rate × lifetime)` must
/// exceed `10^6`. At the shipped 10-minute lifetime, that caps the
/// verification endpoint at roughly `2.56 × 10^10 / (10^6 × 600) ≈ 42` attempts
/// per second — orders of magnitude above any human, and the reason the
/// verification endpoint gets its own rate-limit bucket rather than sharing
/// the generic one.
pub fn brute_force_attempts_required(rate_per_minute: u64, lifetime_secs: u64) -> f64 {
    let space = (USER_CODE_CHARSET.len() as f64).powi(USER_CODE_LEN as i32);
    let attempts_in_window = (rate_per_minute as f64) * (lifetime_secs as f64) / 60.0;
    if attempts_in_window <= 0.0 {
        return f64::INFINITY;
    }
    space / attempts_in_window
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn user_codes_use_only_the_unambiguous_charset() {
        for _ in 0..200 {
            let code = generate_user_code();
            for c in code.chars().filter(|c| *c != '-') {
                assert!(
                    USER_CODE_CHARSET.contains(&(c as u8)),
                    "generated {c:?}, which is not in the unambiguous charset"
                );
            }
        }
    }

    /// Every excluded character is excluded for a reason a user would hit.
    #[test]
    fn ambiguous_characters_are_absent() {
        // No digits at all — this is what kills the O/0 and I/1/L confusions
        // at the root rather than case by case.
        for c in '0'..='9' {
            assert!(
                !USER_CODE_CHARSET.contains(&(c as u8)),
                "{c:?}: the alphabet must contain no digits, so no letter can \
                 be mistaken for one"
            );
        }
        // No vowels or Y — so a generated code cannot spell a word.
        for c in ['A', 'E', 'I', 'O', 'U', 'Y'] {
            assert!(
                !USER_CODE_CHARSET.contains(&(c as u8)),
                "{c:?} must be absent so a code cannot spell a word"
            );
        }
    }

    /// The alphabet size is what the brute-force arithmetic is computed
    /// against, so shrinking it silently would silently weaken that bound.
    #[test]
    fn alphabet_size_is_what_the_brute_force_math_assumes() {
        assert_eq!(USER_CODE_CHARSET.len(), 20);
        assert_eq!(
            USER_CODE_CHARSET.len(),
            USER_CODE_CHARSET
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            "duplicate characters would inflate the assumed key space"
        );
    }

    #[test]
    fn user_codes_are_displayed_hyphenated() {
        let code = generate_user_code();
        assert_eq!(code.len(), USER_CODE_LEN + 1);
        assert_eq!(code.chars().nth(4), Some('-'));
    }

    /// A user typing the code back in any reasonable form must be found.
    #[test]
    fn normalisation_accepts_what_a_human_actually_types() {
        let canonical = normalize_user_code("BCDF-GHJK");
        assert_eq!(canonical, "BCDFGHJK");

        for variant in [
            "bcdf-ghjk",
            "BCDFGHJK",
            "bcdf ghjk",
            " BCDF-GHJK ",
            "b c d f - g h j k",
            "BCDF—GHJK", // em dash, which some phone keyboards substitute
        ] {
            assert_eq!(
                normalize_user_code(variant),
                canonical,
                "{variant:?} must normalise to the same code — otherwise the \
                 user retries, and a retry spends the rate-limit budget that \
                 protects the code"
            );
        }
    }

    /// Normalisation must not invent characters that are not in the alphabet.
    #[test]
    fn normalisation_drops_out_of_charset_characters() {
        assert_eq!(normalize_user_code("BC0DF1GH"), "BCDFGH");
        assert_eq!(normalize_user_code("!!!!"), "");
    }

    #[test]
    fn device_codes_are_high_entropy_and_unique() {
        let codes: HashSet<String> = (0..500).map(|_| generate_device_code()).collect();
        assert_eq!(codes.len(), 500, "device codes must not collide");
        // 32 bytes base64url-unpadded.
        assert_eq!(generate_device_code().len(), 43);
    }

    #[test]
    fn device_code_hashing_is_stable_and_not_reversible_by_length() {
        let raw = generate_device_code();
        assert_eq!(hash_device_code(&raw), hash_device_code(&raw));
        assert_ne!(hash_device_code(&raw), raw);
        assert_eq!(hash_device_code(&raw).len(), 64);
    }

    /// The shipped posture must clear the OWASP bar with room to spare.
    ///
    /// This is the test that stops someone raising the verification rate limit
    /// "because users complain" without noticing what it costs.
    #[test]
    fn shipped_rate_limit_clears_the_owasp_brute_force_bar() {
        // The verification endpoint's own bucket, sized like the other human
        // endpoints rather than like the machine ones.
        let shipped_rate_per_min = 10;
        let required = brute_force_attempts_required(shipped_rate_per_min, DEFAULT_EXPIRES_IN_SECS);

        assert!(
            required > 1e6,
            "OWASP bar: charset^len / (rate x lifetime) must exceed 10^6, got {required:e}"
        );
    }

    /// ...and the bar is genuinely a bar: a wide-open verification endpoint
    /// fails it, which is what makes the assertion above meaningful.
    #[test]
    fn an_unthrottled_verification_endpoint_fails_the_bar() {
        // 100k attempts/min is what an unthrottled endpoint on this hardware
        // would comfortably serve.
        let required = brute_force_attempts_required(100_000, DEFAULT_EXPIRES_IN_SECS);
        assert!(
            required < 1e6,
            "the bar must actually reject an unthrottled endpoint, got {required:e}"
        );
    }

    /// A longer lifetime widens the attack window linearly — worth pinning, so
    /// that raising `expires_in` is a decision rather than a tweak.
    #[test]
    fn a_longer_lifetime_lowers_the_margin() {
        let ten_min = brute_force_attempts_required(10, 600);
        let one_hour = brute_force_attempts_required(10, 3_600);
        assert!(one_hour < ten_min);
        assert!((ten_min / one_hour - 6.0).abs() < 0.01);
    }
}
