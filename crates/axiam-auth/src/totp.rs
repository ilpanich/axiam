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

/// Verify a TOTP code with replay protection.
///
/// Computes the current time-step (`unix_timestamp / 30`) and, if the code
/// is valid, checks that the step is strictly greater than
/// `last_used_step.unwrap_or(0)`.  If the step is equal (same window) or
/// less, the code is rejected even though the HMAC is correct.
///
/// Returns `Ok((valid, current_step))` on success.  The caller MUST persist
/// `current_step` via `user_repo.update_totp_step` when `valid` is `true`.
///
/// Per SEC-008 (REQ-14 AC-5).
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
        1,
        30,
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
        / 30;

    // Check the HMAC.
    let hmac_valid = totp
        .check_current(code)
        .map_err(|e| AuthError::Crypto(format!("TOTP check: {e}")))?;

    if !hmac_valid {
        return Ok((false, current_step));
    }

    // Replay check: reject codes from the same or an earlier step.
    let last = last_used_step.unwrap_or(0);
    if current_step <= last {
        return Ok((false, current_step));
    }

    Ok((true, current_step))
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
}
