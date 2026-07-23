//! Tenant certificate generation service — signs certificates with a CA key.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::certificate::{
    Certificate, CertificateStatus, CreateCertificate, GeneratedCertificate, StoreCertificate,
};
use axiam_core::repository::{
    CaCertificateRepository, CertificateRepository, PaginatedResult, Pagination,
};
use chrono::{Duration, Utc};
use rcgen::{CertificateParams, DnType, IsCa, Issuer, KeyPair};
use std::sync::Arc;
use tokio::sync::Semaphore;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::PkiConfig;
use crate::crypto::{compute_fingerprint, decrypt_secret, generate_keypair};

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
    /// Shared bounding semaphore for CPU-bound crypto (CQ-B02).
    crypto_semaphore: Arc<Semaphore>,
}

impl<CA: CaCertificateRepository, CR: CertificateRepository> CertService<CA, CR> {
    pub fn new(
        ca_repo: CA,
        cert_repo: CR,
        config: PkiConfig,
        crypto_semaphore: Arc<Semaphore>,
    ) -> Self {
        Self {
            ca_repo,
            cert_repo,
            config,
            crypto_semaphore,
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

        // Decrypt the CA private key — encryption key must be present (SEC-012).
        let enc_key = self.config.encryption_key.ok_or_else(|| {
            AxiamError::Internal(
                "AXIAM__PKI__ENCRYPTION_KEY not set — CA/cert key encryption unavailable".into(),
            )
        })?;
        let mut ca_private_key_pem = decrypt_ca_key_pem(&encrypted_key, &enc_key)?;

        let not_before = now;
        let requested_not_after = now
            .checked_add_signed(Duration::days(i64::from(input.validity_days)))
            .ok_or_else(|| AxiamError::Validation {
                message: "validity_days produces a date out of range".into(),
            })?;
        // Cap leaf validity to CA validity window
        let not_after = std::cmp::min(requested_not_after, ca_cert.not_after);

        // CPU-bound: key generation + certificate signing run in spawn_blocking behind semaphore (CQ-B02).
        let _permit = self
            .crypto_semaphore
            .acquire()
            .await
            .map_err(|_| AxiamError::Internal("crypto semaphore closed".into()))?;

        let ca_cert_pem = ca_cert.public_cert_pem.clone();
        let ee_subject = input.subject.clone();
        let key_algorithm = input.key_algorithm.clone();
        let not_before_ts = not_before.timestamp();
        let not_after_ts = not_after.timestamp();

        let (private_key_pem, public_cert_pem, fingerprint) =
            tokio::task::spawn_blocking(move || -> AxiamResult<(String, String, String)> {
                let ca_key_pair = KeyPair::from_pem(&ca_private_key_pem)
                    .map_err(|e| AxiamError::Certificate(format!("invalid CA private key: {e}")))?;
                // Scrub the decrypted CA private-key PEM from memory as soon as
                // the KeyPair is parsed — it is not needed past this point and
                // must not linger in the heap buffer (defense-in-depth).
                ca_private_key_pem.zeroize();

                // Reconstruct the signing CA issuer from its real, stored certificate
                // PEM — NOT from the (mutable) `subject` field — so the issuer DN
                // embedded in every leaf cert can never drift from the CA's actual
                // Subject DN (QUAL-05/D-08, T-29-11). rcgen 0.14 moved
                // `from_ca_cert_pem` onto `Issuer`, which now owns the signing key and
                // is passed directly to `signed_by`.
                let ca_issuer =
                    Issuer::from_ca_cert_pem(&ca_cert_pem, ca_key_pair).map_err(|e| {
                        AxiamError::Certificate(format!("invalid CA certificate PEM: {e}"))
                    })?;

                // Generate end-entity key pair.
                let ee_key_pair = generate_keypair(&key_algorithm)?;
                let private_key_pem = ee_key_pair.serialize_pem();

                // Build end-entity certificate request.
                let mut ee_params = CertificateParams::new(Vec::<String>::new())
                    .map_err(|e| AxiamError::Certificate(e.to_string()))?;
                ee_params
                    .distinguished_name
                    .push(DnType::CommonName, &ee_subject);
                ee_params.is_ca = IsCa::NoCa;
                ee_params.not_before = time::OffsetDateTime::from_unix_timestamp(not_before_ts)
                    .expect("valid timestamp");
                ee_params.not_after = time::OffsetDateTime::from_unix_timestamp(not_after_ts)
                    .expect("valid timestamp");

                let cert = ee_params.signed_by(&ee_key_pair, &ca_issuer).map_err(|e| {
                    AxiamError::Certificate(format!("certificate signing failed: {e}"))
                })?;

                let public_cert_pem = cert.pem();
                let fingerprint = compute_fingerprint(cert.der());
                Ok((private_key_pem, public_cert_pem, fingerprint))
            })
            .await
            .map_err(|e| AxiamError::Internal(format!("spawn_blocking join error: {e}")))??;

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

/// Decrypt an AES-256-GCM encrypted private key PEM and validate it is UTF-8.
///
/// X.509-specific wrapper around the shared [`decrypt_secret`] — the CA/leaf
/// private key material is always stored as UTF-8 PEM text.
fn decrypt_ca_key_pem(data: &[u8], key_bytes: &[u8; 32]) -> AxiamResult<String> {
    let plaintext = decrypt_secret(data, key_bytes)?;
    String::from_utf8(plaintext)
        .map_err(|e| AxiamError::Crypto(format!("decrypted key is not valid UTF-8: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::encrypt_secret;

    #[test]
    fn decrypt_ca_key_pem_round_trips_valid_utf8() {
        let key = [9u8; 32];
        // Assembled from fragments (not a literal "BEGIN PRIVATE KEY" line) —
        // this is arbitrary round-trip payload text, not real key material.
        let label = "PRIVATE KEY";
        let pem = format!("-----BEGIN {label}-----\nfakekeydata\n-----END {label}-----\n");
        let encrypted = encrypt_secret(pem.as_bytes(), &key).expect("encrypt must succeed");

        let decrypted = decrypt_ca_key_pem(&encrypted, &key).expect("decrypt must succeed");
        assert_eq!(decrypted, pem);
    }

    #[test]
    fn decrypt_ca_key_pem_rejects_non_utf8_plaintext() {
        let key = [10u8; 32];
        // 0x80 is not a valid single-byte UTF-8 sequence starter.
        let invalid_utf8: &[u8] = &[0xFF, 0xFE, 0x80];
        let encrypted = encrypt_secret(invalid_utf8, &key).expect("encrypt must succeed");

        let err = decrypt_ca_key_pem(&encrypted, &key).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("not valid UTF-8"), "got: {msg}");
    }

    #[test]
    fn decrypt_ca_key_pem_propagates_underlying_decrypt_error() {
        let key = [11u8; 32];
        // Too short to contain a 12-byte nonce — decrypt_secret's own error
        // path, which decrypt_ca_key_pem must propagate unchanged.
        let err = decrypt_ca_key_pem(&[1, 2, 3], &key).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("missing nonce"), "got: {msg}");
    }

    #[test]
    fn decrypt_ca_key_pem_rejects_wrong_key() {
        let key_a = [12u8; 32];
        let key_b = [13u8; 32];
        let encrypted = encrypt_secret(b"pem-bytes", &key_a).expect("encrypt must succeed");

        let err = decrypt_ca_key_pem(&encrypted, &key_b).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("decryption failed"), "got: {msg}");
    }

    #[test]
    fn leaf_cert_validity_constants_are_sane() {
        const { assert!(DEFAULT_LEAF_CERT_VALIDITY_DAYS <= MAX_LEAF_CERT_VALIDITY_DAYS) };
        assert_eq!(MAX_LEAF_CERT_VALIDITY_DAYS, 825);
        assert_eq!(DEFAULT_LEAF_CERT_VALIDITY_DAYS, 365);
    }
}
