//! Tenant certificate generation service — signs certificates with a CA key.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::certificate::{
    Certificate, CertificateStatus, CreateCertificate, GeneratedCertificate, StoreCertificate,
};
use axiam_core::repository::{
    CaCertificateRepository, CertificateRepository, PaginatedResult, Pagination,
};
use chrono::{Duration, Utc};
use rcgen::{CertificateParams, DnType, IsCa, KeyPair};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::PkiConfig;

/// Hard cap for leaf certificate validity: 825 days (~27 months).
///
/// Aligns with CA/Browser Forum Baseline Requirements and Apple/Mozilla
/// root program policies. Internal PKI may allow up to this limit;
/// tenants can configure a lower per-tenant maximum via the
/// `max_certificate_validity_days` key in their metadata.
pub const MAX_LEAF_CERT_VALIDITY_DAYS: u32 = 825;

/// Default leaf certificate validity when no tenant override is set: 365 days.
pub const DEFAULT_LEAF_CERT_VALIDITY_DAYS: u32 = 365;

/// Service for tenant-level certificate operations.
#[derive(Clone)]
pub struct CertService<CA, CR> {
    ca_repo: CA,
    cert_repo: CR,
    config: PkiConfig,
}

impl<CA: CaCertificateRepository, CR: CertificateRepository> CertService<CA, CR> {
    pub fn new(ca_repo: CA, cert_repo: CR, config: PkiConfig) -> Self {
        Self {
            ca_repo,
            cert_repo,
            config,
        }
    }

    /// Generate a new certificate signed by an organization CA.
    ///
    /// `org_id` is required to look up the CA certificate and its encrypted
    /// private key for signing.
    ///
    /// `max_validity_days` is the tenant-level cap (from tenant metadata).
    /// Pass `None` to use the default ([`DEFAULT_LEAF_CERT_VALIDITY_DAYS`]).
    /// The hard cap ([`MAX_LEAF_CERT_VALIDITY_DAYS`], 825 days) is always
    /// enforced per CA/Browser Forum Baseline Requirements.
    pub async fn generate(
        &self,
        org_id: Uuid,
        input: CreateCertificate,
        max_validity_days: Option<u32>,
    ) -> AxiamResult<GeneratedCertificate> {
        // Enforce validity_days bounds: > 0 and <= tenant/hard cap
        let effective_max = max_validity_days
            .unwrap_or(DEFAULT_LEAF_CERT_VALIDITY_DAYS)
            .min(MAX_LEAF_CERT_VALIDITY_DAYS);
        if input.validity_days == 0 || input.validity_days > effective_max {
            return Err(AxiamError::Validation {
                message: format!(
                    "validity_days must be between 1 and {effective_max} \
                     (CA/Browser Forum BR hard cap: {MAX_LEAF_CERT_VALIDITY_DAYS} days)"
                ),
            });
        }

        // Fetch the CA cert to get the encrypted private key.
        let ca_cert = self.ca_repo.get_by_id(org_id, input.issuer_ca_id).await?;

        if ca_cert.status != CertificateStatus::Active {
            return Err(AxiamError::Certificate(
                "CA certificate is not active".into(),
            ));
        }

        // Validate CA certificate validity window
        let now = Utc::now();
        if now < ca_cert.not_before || now > ca_cert.not_after {
            return Err(AxiamError::Certificate(
                "CA certificate is expired or not yet valid".into(),
            ));
        }

        let encrypted_key = ca_cert.encrypted_private_key.ok_or_else(|| {
            AxiamError::Certificate("CA certificate has no stored private key".into())
        })?;

        // Decrypt the CA private key.
        let ca_private_key_pem = decrypt_private_key(&encrypted_key, &self.config.encryption_key)?;
        let ca_key_pair = KeyPair::from_pem(&ca_private_key_pem)
            .map_err(|e| AxiamError::Certificate(format!("invalid CA private key: {e}")))?;

        // Build the CA signing parameters (needed by rcgen to issue a signed cert).
        let ca_params = build_ca_params(&ca_cert.subject)?;
        let ca_certificate = ca_params
            .self_signed(&ca_key_pair)
            .map_err(|e| AxiamError::Certificate(format!("CA self-sign failed: {e}")))?;

        // Generate end-entity key pair.
        let ee_key_pair = generate_keypair(&input.key_algorithm)?;
        let private_key_pem = ee_key_pair.serialize_pem();

        let not_before = now;
        let requested_not_after = now
            .checked_add_signed(Duration::days(i64::from(input.validity_days)))
            .ok_or_else(|| AxiamError::Validation {
                message: "validity_days produces a date out of range".into(),
            })?;
        // Cap leaf validity to CA validity window
        let not_after = std::cmp::min(requested_not_after, ca_cert.not_after);

        // Build end-entity certificate request.
        let mut ee_params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| AxiamError::Certificate(e.to_string()))?;
        ee_params
            .distinguished_name
            .push(DnType::CommonName, &input.subject);
        ee_params.is_ca = IsCa::NoCa;
        ee_params.not_before = to_rcgen_time(not_before);
        ee_params.not_after = to_rcgen_time(not_after);

        let cert = ee_params
            .signed_by(&ee_key_pair, &ca_certificate, &ca_key_pair)
            .map_err(|e| AxiamError::Certificate(format!("certificate signing failed: {e}")))?;

        let public_cert_pem = cert.pem();
        let fingerprint = compute_fingerprint(cert.der());

        let store = StoreCertificate {
            tenant_id: input.tenant_id,
            issuer_ca_id: input.issuer_ca_id,
            subject: input.subject,
            public_cert_pem,
            fingerprint,
            cert_type: input.cert_type,
            key_algorithm: input.key_algorithm,
            not_before,
            not_after,
            metadata: input.metadata.unwrap_or(serde_json::json!({})),
        };

        let certificate = self.cert_repo.create(store).await?;

        Ok(GeneratedCertificate {
            certificate,
            private_key_pem,
        })
    }

    pub async fn get(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Certificate> {
        self.cert_repo.get_by_id(tenant_id, id).await
    }

    pub async fn get_by_fingerprint(
        &self,
        tenant_id: Uuid,
        fingerprint: &str,
    ) -> AxiamResult<Certificate> {
        self.cert_repo
            .get_by_fingerprint(tenant_id, fingerprint)
            .await
    }

    pub async fn revoke(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        self.cert_repo.revoke(tenant_id, id).await
    }

    pub async fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<Certificate>> {
        self.cert_repo.list(tenant_id, pagination).await
    }
}

/// Build minimal CA params for rcgen (used to reconstruct CA certificate for signing).
fn build_ca_params(subject: &str) -> AxiamResult<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| AxiamError::Certificate(e.to_string()))?;
    params.distinguished_name.push(DnType::CommonName, subject);
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    Ok(params)
}

/// Generate a key pair for the given algorithm.
fn generate_keypair(
    algorithm: &axiam_core::models::certificate::KeyAlgorithm,
) -> AxiamResult<KeyPair> {
    use axiam_core::models::certificate::KeyAlgorithm;
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

/// Decrypt AES-256-GCM encrypted data (12-byte nonce prepended to ciphertext).
fn decrypt_private_key(data: &[u8], key_bytes: &[u8; 32]) -> AxiamResult<String> {
    if data.len() < 12 {
        return Err(AxiamError::Crypto(
            "encrypted data too short (missing nonce)".into(),
        ));
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| AxiamError::Crypto(format!("AES-256-GCM decryption failed: {e}")))?;
    String::from_utf8(plaintext)
        .map_err(|e| AxiamError::Crypto(format!("decrypted key is not valid UTF-8: {e}")))
}
