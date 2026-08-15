//! TOTP generation, verification, and AES-256-GCM secret encryption.

use totp_rs::{Algorithm, Builder, Secret, Totp};

use crate::crypto;
use crate::error::AuthError;

/// Encrypt a TOTP secret with AES-256-GCM.
///
/// Returns `base64(nonce || ciphertext || tag)`.
///
/// Delegates to [`crate::crypto::aes256gcm_encrypt`] — the bundled format
/// is shared; changing the wire format here would break existing TOTP secrets
/// stored in the database.
pub fn encrypt_secret(key: &[u8; 32], plaintext: &[u8]) -> Result<String, AuthError> {
    crypto::aes256gcm_encrypt(key, plaintext)
}

/// Decrypt an AES-256-GCM encrypted TOTP secret.
///
/// Delegates to [`crate::crypto::aes256gcm_decrypt`].
pub fn decrypt_secret(key: &[u8; 32], encoded: &str) -> Result<Vec<u8>, AuthError> {
    crypto::aes256gcm_decrypt(key, encoded)
}

/// TOTP step size in seconds (RFC 6238 default), shared by every [`build`]
/// call in this module.
const TOTP_STEP_SECS: u64 = 30;

/// TOTP skew tolerance (±1 step), shared by every [`build`] call in this
/// module.
///
/// `u16` since totp-rs 6.0, which widened `Builder::with_skew`. The tolerated
/// window is unchanged.
const TOTP_SKEW: u16 = 1;

/// Digits in a generated code (RFC 6238 default).
const TOTP_DIGITS: u8 = 6;

/// Build a configured [`Totp`] over the given raw secret.
///
/// One constructor for the whole module. totp-rs 6.0 replaced `TOTP::new`'s
/// seven positional arguments with a builder, and seven positional arguments --
/// three of which were bare numbers -- repeated at four call sites was exactly
/// the shape a silent parameter swap lives in. Centralising it means the
/// algorithm, digit count, skew and step duration are stated once and every
/// caller gets the same ones by construction.
fn build(secret_bytes: Vec<u8>, issuer: &str, account: &str) -> Result<Totp, AuthError> {
    Builder::new()
        .with_algorithm(Algorithm::SHA1) // RFC 6238 default
        .with_digits(TOTP_DIGITS)
        .with_skew(TOTP_SKEW)
        .with_step_duration(TOTP_STEP_SECS)
        .with_secret(secret_bytes)
        .with_issuer(Some(issuer))
        .with_account_name(account)
        .build()
        .map_err(|e| AuthError::Crypto(format!("TOTP init: {e}")))
}

/// Generate a TOTP enrollment: secret + otpauth URI.
///
/// Returns `(base32_secret, otpauth_uri)`.
pub fn generate_enrollment(issuer: &str, account: &str) -> Result<(String, String), AuthError> {
    let secret = Secret::generate();
    // 6.0's `as_bytes` is infallible; 5.x's `to_bytes` returned a
    // `Result` whose error branch a freshly generated secret could not
    // reach, so the `map_err` it forced is gone with it.
    let secret_bytes = secret.as_bytes().to_vec();

    let totp = build(secret_bytes, issuer, account)?;

    let base32 = secret.to_base32();
    // 6.0 renamed `get_url` to `to_url` and made it fallible: rendering an
    // otpauth URI can fail on an issuer or account name that cannot be encoded.
    // Propagating that beats 5.x's infallible signature, which could not report
    // it at all.
    let uri = totp
        .to_url()
        .map_err(|e| AuthError::Crypto(format!("TOTP otpauth URL: {e}")))?;

    Ok((base32, uri))
}

/// Verify a TOTP code against a raw secret.
pub fn verify_code(
    secret_bytes: &[u8],
    code: &str,
    issuer: &str,
    account: &str,
) -> Result<bool, AuthError> {
    let totp = build(secret_bytes.to_vec(), issuer, account)?;
    // 6.0 changed `check_current` from `Result<bool, SystemTimeError>` to
    // `Option<u64>`, where `Some(step)` names WHICH step matched. Only the
    // pass/fail is wanted here; `verify_code_with_replay_check` is where the
    // step itself becomes load-bearing.
    Ok(totp.check_current(code).is_some())
}

/// Verify a TOTP code with replay protection.
///
/// Determines WHICH step in the tolerated ±1-step skew window actually matched
/// (`current_step - 1`, `current_step`, or `current_step + 1`) rather than
/// assuming it was always `current_step`. This matters because recording
/// `current_step` unconditionally would let a code accepted via the -1-skew
/// step be replayed again once the wall clock advances past it (T-24-02).
///
/// Under totp-rs 5.x, `check_current` reported only pass/fail for the whole
/// window, so this function re-derived `generate()` across the three candidate
/// steps to identify the match. **6.0 answers with the matched step directly**
/// (`Option<u64>`), so that probe is gone — and with it the only place in this
/// module that compared a generated code against user input outside the
/// library's own constant-time path.
///
/// The code is rejected (even though the HMAC is correct) unless the matched
/// step is strictly greater than `last_used_step.unwrap_or(0)`.
///
/// Returns `Ok((valid, matched_step))` on success. The caller MUST persist
/// `matched_step` via the atomic `user_repo.update_totp_step` CAS when
/// `valid` is `true`, and MUST treat a lost CAS (`Ok(false)`) as an invalid
/// code (SECHRD-01) — this function cannot see concurrent submissions by
/// itself, so the persisted-step compare-and-set is the actual replay guard.
///
/// Per SEC-008 / SECHRD-01 (REQ-14 AC-5).
pub fn verify_code_with_replay_check(
    secret_bytes: &[u8],
    code: &str,
    issuer: &str,
    account: &str,
    last_used_step: Option<u64>,
) -> Result<(bool, u64), AuthError> {
    let totp = build(secret_bytes.to_vec(), issuer, account)?;

    // Computed independently of totp-rs internals, because it is the value
    // reported alongside a REJECTION -- where there is no matched step to
    // report.
    let current_step = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| AuthError::Crypto(format!("system time error: {e}")))?
        .as_secs()
        / TOTP_STEP_SECS;

    // Check the HMAC across the tolerated ±1-step skew window. Since 6.0 this
    // answers with the matched step rather than a bare bool, which is exactly
    // the value T-24-02 needs and which 5.x forced this function to re-derive.
    let Some(matched_step) = totp.check_current(code) else {
        return Ok((false, current_step));
    };

    // Replay check: reject unless the ACTUAL matched step (incl. -1 skew) is
    // strictly greater than the last-used step.
    let last = last_used_step.unwrap_or(0);
    if matched_step <= last {
        return Ok((false, matched_step));
    }

    Ok((true, matched_step))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"totp-secret-bytes";
        let encrypted = encrypt_secret(&key, plaintext).unwrap();
        let decrypted = decrypt_secret(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let key1 = [42u8; 32];
        let key2 = [99u8; 32];
        let encrypted = encrypt_secret(&key1, b"secret").unwrap();
        assert!(decrypt_secret(&key2, &encrypted).is_err());
    }

    #[test]
    fn enrollment_produces_valid_uri() {
        let (base32, uri) = generate_enrollment("AXIAM", "alice@example.com").unwrap();
        assert!(!base32.is_empty());
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("AXIAM"));
        assert!(uri.contains("alice"));
    }

    #[test]
    fn verify_code_with_valid_totp() {
        let secret = Secret::generate();
        let secret_bytes = secret.as_bytes().to_vec();

        let totp = build(secret_bytes.clone(), "AXIAM", "test@test.com").unwrap();

        // 6.0's `generate_current` is infallible and answers a `Token`; render it
        // to the string a client would actually submit.
        let code = totp.generate_current().to_string();
        assert!(verify_code(&secret_bytes, &code, "AXIAM", "test@test.com").unwrap());
    }

    #[test]
    fn verify_code_wrong_code() {
        let secret = Secret::generate();
        let secret_bytes = secret.as_bytes().to_vec();
        assert!(!verify_code(&secret_bytes, "000000", "AXIAM", "test@test.com").unwrap());
    }

    /// Regression: a TOTP code produced by the SAME base32 secret returned to the
    /// client (the live enroll path encrypts `Secret::try_from_base32(base32)?.as_bytes()`
    /// and confirm verifies those bytes) must validate. Guards the enroll→confirm
    /// round-trip end to end (RFC 6238 dynamic-truncation compliant).
    #[test]
    fn enroll_base32_roundtrip_confirms() {
        let (base32, _uri) = generate_enrollment("AXIAM", "admin@axiam.dev").unwrap();
        let secret_bytes = Secret::try_from_base32(base32).unwrap().as_bytes().to_vec();
        let totp = build(secret_bytes.clone(), "AXIAM", "admin@axiam.dev").unwrap();
        // 6.0's `generate_current` is infallible and answers a `Token`; render it
        // to the string a client would actually submit.
        let code = totp.generate_current().to_string();
        assert!(verify_code(&secret_bytes, &code, "AXIAM", "admin@axiam.dev").unwrap());
    }

    /// T-24-02: a code that only validates against the -1 skew step must have
    /// `current_step - 1` (not `current_step`) recorded as the matched step,
    /// and once persisted, the SAME code must not be replayable — even though
    /// it still falls inside the ±1 skew window relative to a later call.
    #[test]
    fn totp_skew_step_recorded() {
        let secret = Secret::generate();
        let secret_bytes = secret.as_bytes().to_vec();

        let totp = build(secret_bytes.clone(), "AXIAM", "skew@test.com").unwrap();

        let current_step = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 30;
        let prev_step = current_step - 1;

        // Hand-generate a code for the PREVIOUS step (simulates a client
        // that entered a code right at a step boundary) — this is the -1
        // skew case `TOTP::check` tolerates.
        // 6.0's `generate` answers a `Token` rather than a String.
        let prev_code = totp.generate(prev_step * 30).to_string();

        let (valid, matched_step) = verify_code_with_replay_check(
            &secret_bytes,
            &prev_code,
            "AXIAM",
            "skew@test.com",
            None,
        )
        .unwrap();
        assert!(valid, "code from the -1 skew step should be accepted");
        assert_eq!(
            matched_step, prev_step,
            "matched step must be current_step - 1 (the step that actually \
             matched), not always current_step"
        );

        // Persist `matched_step` (as the real caller does via
        // `update_totp_step`) and resubmit the SAME code. It is still inside
        // the ±1 skew window relative to `check()`, but must now be rejected
        // because its matched step is not strictly greater than the
        // persisted last-used step.
        let (replay_valid, _) = verify_code_with_replay_check(
            &secret_bytes,
            &prev_code,
            "AXIAM",
            "skew@test.com",
            Some(matched_step),
        )
        .unwrap();
        assert!(
            !replay_valid,
            "a skew-accepted code must not be replayable at a later step"
        );
    }
}
