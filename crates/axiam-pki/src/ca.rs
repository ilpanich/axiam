//! CA certificate generation and management service.

use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::certificate::{
    CaCertificate, CreateCaCertificate, GeneratedCaCertificate, KeyAlgorithm, StoreCaCertificate,
};
use axiam_core::repository::{CaCertificateRepository, PaginatedResult, Pagination};
use chrono::{Duration, Utc};
use rcgen::{CertificateParams, DnType, IsCa, KeyPair};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::Semaphore;
use uuid::Uuid;

pub use crate::config::PkiConfig;

/// Maximum validity for CA certificates: 20 years (7300 days).
///
/// Aligns with NIST SP 800-57 Part 1 Rev 5 recommendations for root CA
/// certificate lifetimes. Values above this are rejected to prevent
/// chrono/time overflow and to enforce security best practice.
pub const MAX_CA_VALIDITY_DAYS: u32 = 7300;

/// Service for CA certificate operations.
#[derive(Clone)]
pub struct CaService<R> {
    repo: R,
    config: PkiConfig,
    /// Shared bounding semaphore for CPU-bound crypto (CQ-B02).
    crypto_semaphore: Arc<Semaphore>,
}

impl<R: CaCertificateRepository> CaService<R> {
    pub fn new(repo: R, config: PkiConfig, crypto_semaphore: Arc<Semaphore>) -> Self {
        Self {
            repo,
            config,
            crypto_semaphore,
        }
    }

    /// Generate a new self-signed CA certificate.
    ///
    /// Returns the stored certificate **and** the private key PEM (returned
    /// once, never stored in plaintext).
    pub async fn generate(
        &self,
        input: CreateCaCertificate,
    ) -> AxiamResult<GeneratedCaCertificate> {
        if input.validity_days == 0 || input.validity_days > MAX_CA_VALIDITY_DAYS {
            return Err(AxiamError::Validation {
                message: format!(
                    "validity_days must be between 1 and {MAX_CA_VALIDITY_DAYS} \
                     (NIST SP 800-57 max for CA certificates)"
                ),
            });
        }

        // CPU-bound: key generation + self-signing run in spawn_blocking behind semaphore (CQ-B02).
        let _permit = self
            .crypto_semaphore
            .acquire()
            .await
            .map_err(|_| AxiamError::Internal("crypto semaphore closed".into()))?;

        let now = Utc::now();
        let not_before = now;
        let not_after = now
            .checked_add_signed(Duration::days(i64::from(input.validity_days)))
            .ok_or_else(|| AxiamError::Validation {
                message: "validity_days produces a date out of range".into(),
            })?;

        let key_algorithm = input.key_algorithm.clone();
        let subject = input.subject.clone();
        let not_before_ts = not_before.timestamp();
        let not_after_ts = not_after.timestamp();

        let (private_key_pem, public_cert_pem, fingerprint) =
            tokio::task::spawn_blocking(move || -> AxiamResult<(String, String, String)> {
                let key_pair = generate_keypair(&key_algorithm)?;
                let private_key_pem = key_pair.serialize_pem();

                let mut params = CertificateParams::new(Vec::<String>::new())
                    .map_err(|e| AxiamError::Certificate(e.to_string()))?;
                params.distinguished_name.push(DnType::CommonName, &subject);
                params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
                params.not_before = time::OffsetDateTime::from_unix_timestamp(not_before_ts)
                    .expect("valid timestamp");
                params.not_after = time::OffsetDateTime::from_unix_timestamp(not_after_ts)
                    .expect("valid timestamp");
                let cert = params
                    .self_signed(&key_pair)
                    .map_err(|e| AxiamError::Certificate(e.to_string()))?;

                let public_cert_pem = cert.pem();
                let fingerprint = compute_fingerprint(cert.der());
                Ok((private_key_pem, public_cert_pem, fingerprint))
            })
            .await
            .map_err(|e| AxiamError::Internal(format!("spawn_blocking join error: {e}")))??;

        let enc_key = self.config.encryption_key.ok_or_else(|| {
            AxiamError::Internal(
                "AXIAM__PKI__ENCRYPTION_KEY not set — CA/cert key encryption unavailable".into(),
            )
        })?;
        let encrypted_private_key = encrypt_private_key(private_key_pem.as_bytes(), &enc_key)?;

        let store = StoreCaCertificate {
            organization_id: input.organization_id,
            subject: input.subject,
            public_cert_pem,
            fingerprint,
            key_algorithm: input.key_algorithm,
            not_before,
            not_after,
            encrypted_private_key: Some(encrypted_private_key),
        };

        let certificate = self.repo.create(store).await?;

        Ok(GeneratedCaCertificate {
            certificate,
            private_key_pem,
        })
    }

    pub async fn get(&self, organization_id: Uuid, id: Uuid) -> AxiamResult<CaCertificate> {
        self.repo.get_by_id(organization_id, id).await
    }

    pub async fn revoke(&self, organization_id: Uuid, id: Uuid) -> AxiamResult<()> {
        self.repo.revoke(organization_id, id).await
    }

    pub async fn list(
        &self,
        organization_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<CaCertificate>> {
        self.repo
            .list_by_organization(organization_id, pagination)
            .await
    }
}

/// Generate a key pair for the given algorithm.
fn generate_keypair(algorithm: &KeyAlgorithm) -> AxiamResult<KeyPair> {
    match algorithm {
        KeyAlgorithm::Ed25519 => KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| AxiamError::Certificate(format!("Ed25519 keygen failed: {e}"))),
        KeyAlgorithm::Rsa4096 => KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
            .map_err(|e| AxiamError::Certificate(format!("RSA-4096 keygen failed: {e}"))),
    }
}

/// Compute SHA-256 fingerprint from DER-encoded certificate bytes.
fn compute_fingerprint(der: &[u8]) -> String {
    let hash = Sha256::digest(der);
    hex::encode(hash)
}

/// Encrypt data with AES-256-GCM. The 12-byte nonce is prepended to the
/// ciphertext so the caller doesn't need to store it separately.
fn encrypt_private_key(plaintext: &[u8], key_bytes: &[u8; 32]) -> AxiamResult<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| AxiamError::Crypto(format!("AES-256-GCM encryption failed: {e}")))?;

    let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}
