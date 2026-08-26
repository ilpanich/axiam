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
use rcgen::{KeyPair, PKCS_RSA_SHA256};
use rsa::RsaPrivateKey;
use rsa::pkcs8::EncodePrivateKey;
use sha2::{Digest, Sha256};

/// Modulus size, in bits, of the RSA keys AXIAM issues.
///
/// Named rather than inlined because it also documents the lower bound *ring*
/// will accept when it later loads the key back for signing: ring refuses a
/// PKCS#8 RSA key below 2048 bits outright, so a future "RSA-2048 for
/// constrained devices" option is a change to this constant plus a new
/// [`KeyAlgorithm`] variant, not a change to the mechanism below.
const RSA_MODULUS_BITS: usize = 4096;

/// Generate an X.509 key pair for the given algorithm.
///
/// # Why RSA takes the long way round
///
/// rcgen delegates its crypto to *ring*, and ring deliberately implements no
/// RSA key **generation** — only signing and verification. `KeyPair::generate_for`
/// therefore answered every RSA-4096 request with
/// `"There is no support for generating keys for the given algorithm"`, which
/// reached the operator as a 500 on an algorithm the API advertises. Ring *can*
/// sign with an RSA key it is handed (see rcgen's `PKCS_RSA_SHA256` arm of
/// `from_pkcs8_der_and_sign_algo`), so the missing half is generation alone.
///
/// The `rsa` crate supplies exactly that half: generate the key, serialize it as
/// PKCS#8 DER, and hand it to rcgen with the signature algorithm named
/// explicitly. The resulting [`KeyPair`] is indistinguishable from one rcgen
/// generated itself — same type, same `serialize_pem`, same signing path — so no
/// caller needs to know which algorithm it asked for.
///
/// Switching rcgen to its `aws_lc_rs` backend would also work and is the more
/// usual answer, but it swaps the crypto provider under *every* algorithm and
/// pulls a C toolchain (cmake, and NASM on Windows) into the build. This keeps
/// the provider, the build, and the Ed25519 path exactly as they were.
///
/// # Cost
///
/// RSA-4096 generation is seconds of CPU, not milliseconds, and it is a
/// rejection-sampling loop whose duration varies run to run. Every call site in
/// this crate already runs inside `tokio::task::spawn_blocking`, which is what
/// keeps that off the async runtime's worker threads; a new call site must do
/// the same.
///
/// # Examples
///
/// ```ignore
/// // Inside a blocking context — never directly on an async worker.
/// let key_pair = tokio::task::spawn_blocking(move || {
///     generate_keypair(&KeyAlgorithm::Rsa4096)
/// })
/// .await??;
/// assert!(key_pair.serialize_pem().contains("PRIVATE KEY"));
/// ```
pub(crate) fn generate_keypair(algorithm: &KeyAlgorithm) -> AxiamResult<KeyPair> {
    match algorithm {
        KeyAlgorithm::Ed25519 => KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| AxiamError::Certificate(format!("Ed25519 keygen failed: {e}"))),
        KeyAlgorithm::Rsa4096 => generate_rsa_keypair(),
    }
}

/// Generate an RSA-4096 key pair and load it into rcgen for signing.
fn generate_rsa_keypair() -> AxiamResult<KeyPair> {
    let mut rng = rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, RSA_MODULUS_BITS)
        .map_err(|e| AxiamError::Certificate(format!("RSA-4096 keygen failed: {e}")))?;

    // PKCS#8 PEM rather than DER purely to keep the hand-off inside rcgen's own
    // public API: `from_pkcs8_der_and_sign_algo` takes a `PrivatePkcs8KeyDer`,
    // a rustls-pki-types type rcgen does not re-export, so reaching it would
    // mean depending on rustls-pki-types directly and pinning its version
    // against rcgen's. `pkcs8::LineEnding` is already in the tree via `rsa`.
    //
    // `to_pkcs8_pem` returns a `Zeroizing<String>`, so the intermediate copy of
    // the private key is wiped when this scope ends. rcgen keeps its own copy
    // inside the returned `KeyPair` for as long as it needs to sign.
    let pkcs8_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| {
            AxiamError::Certificate(format!("RSA-4096 key could not be encoded as PKCS#8: {e}"))
        })?;

    KeyPair::from_pkcs8_pem_and_sign_algo(&pkcs8_pem, &PKCS_RSA_SHA256).map_err(|e| {
        AxiamError::Certificate(format!("RSA-4096 key was rejected by the signer: {e}"))
    })
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
    fn generate_keypair_rsa4096_produces_a_usable_signing_key() {
        // The regression this pins: rcgen's `ring` backend cannot *generate*
        // RSA keys, so this arm used to fail with "There is no support for
        // generating keys for the given algorithm" and surface as a 500 on an
        // algorithm the certificate API advertises. Generating with the `rsa`
        // crate and handing ring the PKCS#8 gets a key ring will sign with.
        let kp = generate_keypair(&KeyAlgorithm::Rsa4096).expect("RSA-4096 keygen must succeed");
        let pem = kp.serialize_pem();
        assert!(
            pem.contains("PRIVATE KEY"),
            "expected a PKCS#8 PEM, got: {pem}"
        );
        assert!(
            KeyPair::from_pem(&pem).is_ok(),
            "the serialized key must round-trip back through rcgen"
        );
    }

    #[test]
    fn generate_keypair_rsa4096_signs_a_self_signed_certificate() {
        // Loading the key is not the same fact as ring accepting it for
        // signature generation: `from_pkcs8_der_and_sign_algo` only parses.
        // Actually signing something is what proves the whole path works.
        let kp = generate_keypair(&KeyAlgorithm::Rsa4096).expect("RSA-4096 keygen must succeed");
        let mut params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("empty SAN list is valid");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "rsa-keygen-test");
        let cert = params
            .self_signed(&kp)
            .expect("an RSA-4096 key must be able to self-sign");
        assert!(cert.pem().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn generate_keypair_rsa4096_is_not_deterministic() {
        // A generator that returned the same key twice would be catastrophic
        // and is exactly the shape a stubbed-out implementation takes.
        let a = generate_keypair(&KeyAlgorithm::Rsa4096)
            .unwrap()
            .serialize_pem();
        let b = generate_keypair(&KeyAlgorithm::Rsa4096)
            .unwrap()
            .serialize_pem();
        assert_ne!(a, b, "two RSA keygens must not produce the same key");
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
