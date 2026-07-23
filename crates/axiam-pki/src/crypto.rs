//! Shared cryptographic helpers for CA/certificate key generation, fingerprinting,
//! and AES-256-GCM secret encryption — consolidated from the byte-identical
//! implementations previously triplicated across `ca.rs`, `cert.rs`, and `pgp.rs`
//! (QUAL-05/D-08).
//!
//! `pgp.rs` intentionally does NOT use [`generate_keypair`] here: its keypair
//! generation produces a distinct `PgpKeyAlgorithm` + `user_id` -> `SignedSecretKey`
//! type that is not X.509/rcgen-based and must not be merged into this module.

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, Generate};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::certificate::KeyAlgorithm;
use rcgen::KeyPair;
use sha2::{Digest, Sha256};

/// Generate an X.509 key pair for the given algorithm.
pub(crate) fn generate_keypair(algorithm: &KeyAlgorithm) -> AxiamResult<KeyPair> {
    match algorithm {
        KeyAlgorithm::Ed25519 => KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| AxiamError::Certificate(format!("Ed25519 keygen failed: {e}"))),
        KeyAlgorithm::Rsa4096 => KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
            .map_err(|e| AxiamError::Certificate(format!("RSA-4096 keygen failed: {e}"))),
    }
}

/// Compute SHA-256 fingerprint from DER-encoded certificate bytes.
pub(crate) fn compute_fingerprint(der: &[u8]) -> String {
    let hash = Sha256::digest(der);
    hex::encode(hash)
}

/// Encrypt data with AES-256-GCM. The 12-byte nonce is prepended to the
/// ciphertext so the caller doesn't need to store it separately.
pub(crate) fn encrypt_secret(plaintext: &[u8], key_bytes: &[u8; 32]) -> AxiamResult<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from(*key_bytes);
    let cipher = Aes256Gcm::new(&key);
    let nonce_bytes: [u8; 12] = Generate::generate();
    let nonce = Nonce::<U12>::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| AxiamError::Crypto(format!("AES-256-GCM encryption failed: {e}")))?;

    let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt AES-256-GCM encrypted data (12-byte nonce prepended to ciphertext).
pub(crate) fn decrypt_secret(data: &[u8], key_bytes: &[u8; 32]) -> AxiamResult<Vec<u8>> {
    if data.len() < 12 {
        return Err(AxiamError::Crypto(
            "encrypted data too short (missing nonce)".into(),
        ));
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let key = Key::<Aes256Gcm>::from(*key_bytes);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::<U12>::try_from(nonce_bytes)
        .map_err(|_| AxiamError::Crypto("invalid nonce length".into()))?;
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| AxiamError::Crypto(format!("AES-256-GCM decryption failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keypair_ed25519_produces_usable_pem() {
        let kp = generate_keypair(&KeyAlgorithm::Ed25519).expect("ed25519 keygen must succeed");
        let pem = kp.serialize_pem();
        assert!(pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn generate_keypair_rsa4096_errors_under_ring_backend() {
        // SURFACED LIMITATION (not endorsed): rcgen's `ring` backend cannot
        // *generate* RSA keys, so `generate_keypair(Rsa4096)` returns an error
        // today, even though RSA-4096 is a documented certificate target. This
        // test pins the current behavior and covers the RSA error arm; if RSA
        // key generation becomes available, update this assertion.
        let result = generate_keypair(&KeyAlgorithm::Rsa4096);
        assert!(
            result.is_err(),
            "expected RSA-4096 keygen to error under the ring backend"
        );
    }

    #[test]
    fn compute_fingerprint_is_deterministic_sha256_hex() {
        let der = b"some-fake-der-bytes";
        let fp1 = compute_fingerprint(der);
        let fp2 = compute_fingerprint(der);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64, "SHA-256 hex digest must be 64 chars");
        assert!(fp1.chars().all(|c| c.is_ascii_hexdigit()));

        let expected = hex::encode(Sha256::digest(der));
        assert_eq!(fp1, expected);
    }

    #[test]
    fn compute_fingerprint_differs_for_different_input() {
        let fp_a = compute_fingerprint(b"input-a");
        let fp_b = compute_fingerprint(b"input-b");
        assert_ne!(fp_a, fp_b);
    }

    #[test]
    fn encrypt_decrypt_secret_round_trip() {
        let key = [7u8; 32];
        let plaintext = b"top secret pem data".to_vec();
        let ciphertext = encrypt_secret(&plaintext, &key).expect("encryption must succeed");
        // Nonce (12 bytes) is prepended, so ciphertext must be longer than plaintext.
        assert!(ciphertext.len() > plaintext.len());
        let decrypted = decrypt_secret(&ciphertext, &key).expect("decryption must succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_produces_distinct_ciphertext_each_call() {
        let key = [1u8; 32];
        let plaintext = b"same plaintext".to_vec();
        let c1 = encrypt_secret(&plaintext, &key).unwrap();
        let c2 = encrypt_secret(&plaintext, &key).unwrap();
        assert_ne!(c1, c2, "random nonce must make ciphertexts differ");
    }

    #[test]
    fn decrypt_secret_rejects_too_short_data() {
        let key = [2u8; 32];
        let err = decrypt_secret(&[0u8; 5], &key).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("missing nonce"), "got: {msg}");
    }

    #[test]
    fn decrypt_secret_rejects_wrong_key() {
        let key_a = [3u8; 32];
        let key_b = [4u8; 32];
        let ciphertext = encrypt_secret(b"data", &key_a).unwrap();
        let err = decrypt_secret(&ciphertext, &key_b).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("decryption failed"), "got: {msg}");
    }

    #[test]
    fn decrypt_secret_rejects_tampered_ciphertext() {
        let key = [5u8; 32];
        let mut ciphertext = encrypt_secret(b"authentic data", &key).unwrap();
        // Flip a bit in the ciphertext body (after the 12-byte nonce) to break the
        // AES-GCM authentication tag.
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;
        let err = decrypt_secret(&ciphertext, &key).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("decryption failed"), "got: {msg}");
    }

    #[test]
    fn decrypt_secret_exact_12_bytes_no_nonce_error_but_ciphertext_empty_fails_auth() {
        // Exactly 12 bytes means an empty ciphertext body — this is not the
        // "too short" branch (data.len() == 12, not < 12) but auth still fails
        // because there is no valid tag.
        let key = [6u8; 32];
        let err = decrypt_secret(&[0u8; 12], &key).unwrap_err();
        let msg = format!("{err:?}");
        assert!(!msg.contains("missing nonce"), "got: {msg}");
        assert!(msg.contains("decryption failed"), "got: {msg}");
    }
}
