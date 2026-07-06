//! TOTP generation, verification, and AES-256-GCM secret encryption.

use totp_rs::{Algorithm, Secret, TOTP};

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

/// Generate a TOTP enrollment: secret + otpauth URI.
///
/// Returns `(base32_secret, otpauth_uri)`.
pub fn generate_enrollment(issuer: &str, account: &str) -> Result<(String, String), AuthError> {
    let secret = Secret::generate_secret();
    let secret_bytes = secret
        .to_bytes()
        .map_err(|e| AuthError::Crypto(format!("secret bytes: {e}")))?;

    let totp = TOTP::new(
        Algorithm::SHA1, // RFC 6238 default
        6,               // digits
        1,               // skew (±1 step)
        30,              // step seconds
        secret_bytes,
        Some(issuer.to_string()),
        account.to_string(),
    )
    .map_err(|e| AuthError::Crypto(format!("TOTP init: {e}")))?;

    let base32 = secret.to_encoded().to_string();
    let uri = totp.get_url();

    Ok((base32, uri))
}

/// Verify a TOTP code against a raw secret.
pub fn verify_code(
    secret_bytes: &[u8],
    code: &str,
    issuer: &str,
    account: &str,
) -> Result<bool, AuthError> {
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes.to_vec(),
        Some(issuer.to_string()),
        account.to_string(),
    )
    .map_err(|e| AuthError::Crypto(format!("TOTP init: {e}")))?;

    totp.check_current(code)
        .map_err(|e| AuthError::Crypto(format!("TOTP check: {e}")))
}

/// TOTP step size in seconds (RFC 6238 default), shared by every `TOTP::new`
/// call in this module.
const TOTP_STEP_SECS: u64 = 30;

/// TOTP skew tolerance (±1 step), shared by every `TOTP::new` call in this
/// module.
const TOTP_SKEW: u8 = 1;

/// Verify a TOTP code with replay protection.
///
/// Computes the current time-step (`unix_timestamp / 30`) and, if the HMAC is
/// valid within the tolerated ±1-step skew window, determines WHICH step
/// actually matched (`current_step - 1`, `current_step`, or
/// `current_step + 1`) rather than assuming it was always `current_step`.
/// This matters because `totp-rs`'s `check()`/`check_current()` only report
/// pass/fail for the whole skew window, not the matched step — recording
/// `current_step` unconditionally would let a code accepted via the -1-skew
/// step be replayed again once the wall clock advances past it (T-24-02).
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
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        TOTP_SKEW,
        TOTP_STEP_SECS,
        secret_bytes.to_vec(),
        Some(issuer.to_string()),
        account.to_string(),
    )
    .map_err(|e| AuthError::Crypto(format!("TOTP init: {e}")))?;

    // Compute current step independently of totp-rs internals.
    let current_step = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| AuthError::Crypto(format!("system time error: {e}")))?
        .as_secs()
        / TOTP_STEP_SECS;

    // Check the HMAC across the tolerated ±1-step skew window.
    let hmac_valid = totp
        .check_current(code)
        .map_err(|e| AuthError::Crypto(format!("TOTP check: {e}")))?;

    if !hmac_valid {
        return Ok((false, current_step));
    }

    // Determine which candidate step actually matched, probing in the same
    // order totp-rs's own `check()` does for skew=1: current_step - 1,
    // current_step, current_step + 1. The code has already passed the
    // constant-time HMAC check above, so re-deriving `generate()` here to
    // identify the matched candidate does not introduce a new secret-timing
    // side channel — it only distinguishes between three already-known-valid
    // outcomes.
    let matched_step = [
        current_step.checked_sub(1),
        Some(current_step),
        current_step.checked_add(1),
    ]
    .into_iter()
    .flatten()
    .find(|&candidate_step| totp.generate(candidate_step * TOTP_STEP_SECS) == code)
    .unwrap_or(current_step);

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
        let secret = Secret::generate_secret();
        let secret_bytes = secret.to_bytes().unwrap();

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes.clone(),
            Some("AXIAM".into()),
            "test@test.com".into(),
        )
        .unwrap();

        let code = totp.generate_current().unwrap();
        assert!(verify_code(&secret_bytes, &code, "AXIAM", "test@test.com").unwrap());
    }

    #[test]
    fn verify_code_wrong_code() {
        let secret = Secret::generate_secret();
        let secret_bytes = secret.to_bytes().unwrap();
        assert!(!verify_code(&secret_bytes, "000000", "AXIAM", "test@test.com").unwrap());
    }

    /// Regression: a TOTP code produced by the SAME base32 secret returned to the
    /// client (the live enroll path encrypts `Secret::Encoded(base32).to_bytes()`
    /// and confirm verifies those bytes) must validate. Guards the enroll→confirm
    /// round-trip end to end (RFC 6238 dynamic-truncation compliant).
    #[test]
    fn enroll_base32_roundtrip_confirms() {
        let (base32, _uri) = generate_enrollment("AXIAM", "admin@axiam.dev").unwrap();
        let secret_bytes = Secret::Encoded(base32).to_bytes().unwrap();
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes.clone(),
            Some("AXIAM".into()),
            "admin@axiam.dev".into(),
        )
        .unwrap();
        let code = totp.generate_current().unwrap();
        assert!(verify_code(&secret_bytes, &code, "AXIAM", "admin@axiam.dev").unwrap());
    }

    /// T-24-02: a code that only validates against the -1 skew step must have
    /// `current_step - 1` (not `current_step`) recorded as the matched step,
    /// and once persisted, the SAME code must not be replayable — even though
    /// it still falls inside the ±1 skew window relative to a later call.
    #[test]
    fn totp_skew_step_recorded() {
        let secret = Secret::generate_secret();
        let secret_bytes = secret.to_bytes().unwrap();

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes.clone(),
            Some("AXIAM".into()),
            "skew@test.com".into(),
        )
        .unwrap();

        let current_step = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 30;
        let prev_step = current_step - 1;

        // Hand-generate a code for the PREVIOUS step (simulates a client
        // that entered a code right at a step boundary) — this is the -1
        // skew case `TOTP::check` tolerates.
        let prev_code = totp.generate(prev_step * 30);

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
