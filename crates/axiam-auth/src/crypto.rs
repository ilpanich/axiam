//! Domain-neutral AES-256-GCM encryption helpers.
//!
//! Provides two variants:
//!
//! - **Bundled** (`aes256gcm_encrypt` / `aes256gcm_decrypt`): encodes
//!   `nonce || ciphertext || tag` as a single base64 string. Used by TOTP
//!   secret storage.
//! - **Split-output** (`encrypt_separate` / `decrypt_separate`): returns
//!   nonce and ciphertext+tag as separate base64 strings. Used by federation
//!   config storage (D-11) where each piece lives in its own DB column.
//!
//! Both variants use a fresh 12-byte nonce from `OsRng` and AES-256-GCM.

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::error::AuthError;

// ---------------------------------------------------------------------------
// Private helper
// ---------------------------------------------------------------------------

fn build_cipher(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
}

// ---------------------------------------------------------------------------
// Bundled variant (TOTP wire format — MUST NOT change)
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` with AES-256-GCM.
///
/// Returns `base64(nonce(12) || ciphertext || tag)`.
///
/// This is the bundled-format variant. The wire format is shared with
/// TOTP secret storage — do **not** change the layout.
pub fn aes256gcm_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<String, AuthError> {
    let cipher = build_cipher(key);
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

/// Decrypt AES-256-GCM ciphertext in the bundled format.
///
/// Accepts `base64(nonce(12) || ciphertext || tag)`.
pub fn aes256gcm_decrypt(key: &[u8; 32], encoded: &str) -> Result<Vec<u8>, AuthError> {
    let combined = STANDARD
        .decode(encoded)
        .map_err(|e| AuthError::Crypto(format!("base64 decode: {e}")))?;

    if combined.len() < 13 {
        return Err(AuthError::Crypto("ciphertext too short".into()));
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let cipher = build_cipher(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| AuthError::Crypto(format!("AES-GCM decrypt: {e}")))
}

// ---------------------------------------------------------------------------
// Split-output variant (federation_config storage — D-11)
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` with AES-256-GCM, returning nonce and ciphertext
/// as **separate** base64 strings.
///
/// Returns `(nonce_b64, ciphertext_with_tag_b64)`. The ciphertext output
/// is `ciphertext || tag` (no nonce prefix). Each output can be stored in
/// its own DB column, enabling column-level key rotation without re-encoding.
///
/// # Separation from bundled format
///
/// Values encrypted with this function **cannot** be decrypted by
/// [`aes256gcm_decrypt`] — the formats are intentionally incompatible.
/// Always use matching encrypt/decrypt pairs.
pub fn encrypt_separate(key: &[u8; 32], plaintext: &[u8]) -> Result<(String, String), AuthError> {
    let cipher = build_cipher(key);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| AuthError::Crypto(format!("AES-GCM encrypt: {e}")))?;

    let nonce_b64 = STANDARD.encode(nonce_bytes);
    let ct_b64 = STANDARD.encode(&ciphertext);
    Ok((nonce_b64, ct_b64))
}

/// Decrypt AES-256-GCM ciphertext from the split-output format.
///
/// Accepts separately base64-encoded `nonce_b64` and `ciphertext_b64`
/// (where `ciphertext_b64` is `ciphertext || tag`, no nonce prefix).
pub fn decrypt_separate(
    key: &[u8; 32],
    nonce_b64: &str,
    ciphertext_b64: &str,
) -> Result<Vec<u8>, AuthError> {
    let nonce_bytes = STANDARD
        .decode(nonce_b64)
        .map_err(|e| AuthError::Crypto(format!("nonce base64 decode: {e}")))?;
    let ciphertext = STANDARD
        .decode(ciphertext_b64)
        .map_err(|e| AuthError::Crypto(format!("ciphertext base64 decode: {e}")))?;

    if nonce_bytes.len() != 12 {
        return Err(AuthError::Crypto(format!(
            "nonce must be 12 bytes, got {}",
            nonce_bytes.len()
        )));
    }

    let cipher = build_cipher(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|e| AuthError::Crypto(format!("AES-GCM decrypt: {e}")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_round_trip() {
        let key = [0x42u8; 32];
        let plaintext = b"hello-axiam";
        let enc = aes256gcm_encrypt(&key, plaintext).unwrap();
        let dec = aes256gcm_decrypt(&key, &enc).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn separate_round_trip() {
        let key = [0x55u8; 32];
        let plaintext = b"federation-secret";
        let (nonce_b64, ct_b64) = encrypt_separate(&key, plaintext).unwrap();
        assert!(!nonce_b64.is_empty());
        assert!(!ct_b64.is_empty());
        let dec = decrypt_separate(&key, &nonce_b64, &ct_b64).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn separate_wrong_nonce_fails() {
        let key = [0xAAu8; 32];
        let plaintext = b"sensitive-data";
        let (_, ct_b64) = encrypt_separate(&key, plaintext).unwrap();
        // Generate a different nonce
        let (other_nonce, _) = encrypt_separate(&key, b"other").unwrap();
        let result = decrypt_separate(&key, &other_nonce, &ct_b64);
        assert!(result.is_err(), "decryption with wrong nonce must fail");
    }

    #[test]
    fn bundled_and_separate_are_independent_formats() {
        let key = [0x11u8; 32];
        let plaintext = b"format-check";
        // Encrypt with bundled format: nonce || ct+tag all in one base64
        let bundled = aes256gcm_encrypt(&key, plaintext).unwrap();
        // Treat the entire bundled string as if it were the ct_b64 in split format.
        // The nonce we pass is independent of the real nonce in the bundled blob.
        // This MUST fail (wrong nonce / mangled ciphertext).
        let fake_nonce = STANDARD.encode([0u8; 12]);
        let result = decrypt_separate(&key, &fake_nonce, &bundled);
        assert!(
            result.is_err(),
            "bundled format must not be decryptable by decrypt_separate with a zero nonce"
        );
    }
}
