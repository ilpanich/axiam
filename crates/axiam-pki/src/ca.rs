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
use uuid::Uuid;

/// PKI configuration — holds the AES-256-GCM key for encrypting CA private keys.
#[derive(Clone)]
pub struct PkiConfig {
    pub encryption_key: [u8; 32],
}

/// Service for CA certificate operations.
#[derive(Clone)]
pub struct CaService<R> {
    repo: R,
    config: PkiConfig,
}

impl<R: CaCertificateRepository> CaService<R> {
    pub fn new(repo: R, config: PkiConfig) -> Self {
        Self { repo, config }
    }

    /// Generate a new self-signed CA certificate.
    ///
    /// Returns the stored certificate **and** the private key PEM (returned
    /// once, never stored in plaintext).
    pub async fn generate(
        &self,
        input: CreateCaCertificate,
    ) -> AxiamResult<GeneratedCaCertificate> {
        let key_pair = generate_keypair(&input.key_algorithm)?;
        let private_key_pem = key_pair.serialize_pem();

        let now = Utc::now();
        let not_before = now;
        let not_after = now + Duration::days(i64::from(input.validity_days));

        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| AxiamError::Certificate(e.to_string()))?;
        params
            .distinguished_name
            .push(DnType::CommonName, &input.subject);
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.not_before = to_rcgen_time(not_before);
        params.not_after = to_rcgen_time(not_after);
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| AxiamError::Certificate(e.to_string()))?;

        let public_cert_pem = cert.pem();
        let fingerprint = compute_fingerprint(cert.der());

        let encrypted_private_key =
            encrypt_private_key(private_key_pem.as_bytes(), &self.config.encryption_key)?;

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

/// Convert chrono DateTime to `time::OffsetDateTime` (used by rcgen).
fn to_rcgen_time(dt: chrono::DateTime<chrono::Utc>) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(dt.timestamp()).expect("valid timestamp")
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
