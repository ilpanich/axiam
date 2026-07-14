//! Shared cryptographic helpers for CA/certificate key generation, fingerprinting,
//! and AES-256-GCM secret encryption — consolidated from the byte-identical
//! implementations previously triplicated across `ca.rs`, `cert.rs`, and `pgp.rs`
//! (QUAL-05/D-08).
//!
//! `pgp.rs` intentionally does NOT use [`generate_keypair`] here: its keypair
//! generation produces a distinct `PgpKeyAlgorithm` + `user_id` -> `SignedSecretKey`
//! type that is not X.509/rcgen-based and must not be merged into this module.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, Generate, KeyInit, Nonce};
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
    let cipher = Aes256Gcm::new_from_slice(key_bytes)
        .map_err(|e| AxiamError::Crypto(format!("AES-256-GCM key: {e}")))?;
    // Fresh 12-byte random nonce from the system CSPRNG (getrandom-backed),
    // same length and prepend layout as before.
    let nonce = Nonce::<Aes256Gcm>::generate();
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
    let cipher = Aes256Gcm::new_from_slice(key_bytes)
        .map_err(|e| AxiamError::Crypto(format!("AES-256-GCM key: {e}")))?;
    let nonce = Nonce::<Aes256Gcm>::try_from(nonce_bytes)
        .map_err(|e| AxiamError::Crypto(format!("invalid nonce length: {e}")))?;
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| AxiamError::Crypto(format!("AES-256-GCM decryption failed: {e}")))
}
