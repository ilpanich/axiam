//! TOTP generation, verification, and AES-256-GCM secret encryption.

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::error::AuthError;

/// Encrypt a TOTP secret with AES-256-GCM.
///
/// Returns `base64(nonce || ciphertext || tag)`.
pub fn encrypt_secret(key: &[u8; 32], plaintext: &[u8]) -> Result<String, AuthError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| AuthError::Crypto(format!("AES-GCM encrypt: {e}")))?;

    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);
    Ok(STANDARD.encode(combined))
}

/// Decrypt an AES-256-GCM encrypted TOTP secret.
pub fn decrypt_secret(key: &[u8; 32], encoded: &str) -> Result<Vec<u8>, AuthError> {
    let combined = STANDARD
        .decode(encoded)
        .map_err(|e| AuthError::Crypto(format!("base64 decode: {e}")))?;

    if combined.len() < 13 {
        return Err(AuthError::Crypto("ciphertext too short".into()));
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| AuthError::Crypto(format!("AES-GCM decrypt: {e}")))
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
