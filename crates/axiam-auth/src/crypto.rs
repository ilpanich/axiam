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

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, Generate, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

use crate::error::AuthError;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Private helper
// ---------------------------------------------------------------------------

fn build_cipher(key: &[u8; 32]) -> Aes256Gcm {
    // 32-byte key is guaranteed by the `[u8; 32]` type — `new_from_slice`
    // cannot fail here. Behavior is identical to the previous
    // `Aes256Gcm::new(Key::from_slice(key))` (same key schedule).
    Aes256Gcm::new_from_slice(key).expect("AES-256-GCM key must be exactly 32 bytes")
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
    // Fresh 12-byte random nonce from the system CSPRNG (getrandom-backed),
    // same source and layout as before.
    let nonce = Nonce::<Aes256Gcm>::generate();

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| AuthError::Crypto(format!("AES-GCM encrypt: {e}")))?;

    let mut combined = nonce.to_vec();
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
    let nonce = Nonce::<Aes256Gcm>::try_from(nonce_bytes)
        .expect("split_at(12) yields exactly 12 nonce bytes");

    cipher
        .decrypt(&nonce, ciphertext)
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
    let nonce = Nonce::<Aes256Gcm>::generate();

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| AuthError::Crypto(format!("AES-GCM encrypt: {e}")))?;

    let nonce_b64 = STANDARD.encode(&nonce[..]);
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
    let nonce = Nonce::<Aes256Gcm>::try_from(nonce_bytes.as_slice())
        .expect("nonce length validated to be 12 bytes above");

    cipher
        .decrypt(&nonce, ciphertext.as_slice())
        .map_err(|e| AuthError::Crypto(format!("AES-GCM decrypt: {e}")))
}

// ---------------------------------------------------------------------------
// GDPR pseudonym helper (D-02)
// ---------------------------------------------------------------------------

/// Compute a deterministic, keyed GDPR audit pseudonym for a deleted user.
///
/// Returns `"DELETED_USER_{16-char-hex}"` (64 bits from HMAC-SHA256).
///
/// - **Deterministic**: the same `(pepper, tenant_id, user_id)` triple always
///   produces the same pseudonym, so all audit entries for a deleted user can
///   still be correlated post-erasure without re-identifying the subject.
/// - **Brute-force resistant**: the pepper must be secret. Without it, an
///   attacker cannot map candidate `user_id` values back to a pseudonym.
/// - **Per-tenant**: `tenant_id` is part of the HMAC input, so the same
///   `user_id` in two different tenants produces different pseudonyms.
pub fn gdpr_pseudonym(pepper: &[u8; 32], tenant_id: Uuid, user_id: Uuid) -> String {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(pepper).expect("HMAC accepts any key length");
    mac.update(tenant_id.as_bytes());
    mac.update(user_id.as_bytes());
    let tag = mac.finalize().into_bytes();
    format!("DELETED_USER_{}", hex::encode(&tag[..8]))
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
    fn gdpr_pseudonym_deterministic() {
        let pepper = [0x42u8; 32];
        let tenant = Uuid::nil();
        let user = Uuid::new_v4();
        let p1 = gdpr_pseudonym(&pepper, tenant, user);
        let p2 = gdpr_pseudonym(&pepper, tenant, user);
        assert_eq!(p1, p2, "same inputs must produce the same pseudonym");
        assert!(
            p1.starts_with("DELETED_USER_"),
            "format must match DELETED_USER_<hex>"
        );
        assert_eq!(
            p1.len(),
            "DELETED_USER_".len() + 16,
            "must be 16 hex chars (8 bytes)"
        );
    }

    #[test]
    fn gdpr_pseudonym_differs_for_different_users() {
        let pepper = [0x42u8; 32];
        let tenant = Uuid::nil();
        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();
        let p1 = gdpr_pseudonym(&pepper, tenant, user1);
        let p2 = gdpr_pseudonym(&pepper, tenant, user2);
        assert_ne!(
            p1, p2,
            "different user_ids must produce different pseudonyms"
        );
    }

    #[test]
    fn gdpr_pseudonym_differs_for_different_tenants() {
        let pepper = [0x42u8; 32];
        let user = Uuid::new_v4();
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        let p1 = gdpr_pseudonym(&pepper, t1, user);
        let p2 = gdpr_pseudonym(&pepper, t2, user);
        assert_ne!(
            p1, p2,
            "different tenant_ids must produce different pseudonyms"
        );
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
