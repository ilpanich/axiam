//! mTLS device authentication — validates client certificates via fingerprint lookup.
//!
//! CA chain validation is delegated to the TLS-terminating reverse proxy.
//! This module verifies the certificate is known, active, not expired,
//! and bound to a service account.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::certificate::{CertificateStatus, DeviceIdentity};
use axiam_core::repository::CertificateRepository;
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x509_parser::pem::parse_x509_pem;

/// Service for mTLS device certificate authentication.
#[derive(Clone)]
pub struct DeviceAuthService<CR> {
    cert_repo: CR,
}

impl<CR: CertificateRepository> DeviceAuthService<CR> {
    pub fn new(cert_repo: CR) -> Self {
        Self { cert_repo }
    }

    /// Authenticate a device by its PEM-encoded client certificate.
    ///
    /// 1. Parse PEM and compute SHA-256 fingerprint
    /// 2. Look up certificate by fingerprint (global, cross-tenant)
    /// 3. Validate status (Active) and expiry
    /// 4. Resolve the bound service account
    ///
    /// Returns a [`DeviceIdentity`] with the service account and tenant.
    /// The caller is responsible for resolving `org_id` from the tenant.
    pub async fn authenticate(&self, pem: &str) -> AxiamResult<DeviceIdentity> {
        // Parse PEM
        let (_, pem_obj) = parse_x509_pem(pem.as_bytes())
            .map_err(|e| AxiamError::Certificate(format!("invalid client certificate PEM: {e}")))?;

        // Compute SHA-256 fingerprint from DER
        let fingerprint = hex::encode(Sha256::digest(&pem_obj.contents));

        // Look up by fingerprint globally
        let cert = self
            .cert_repo
            .get_by_fingerprint_global(&fingerprint)
            .await?;

        // Validate status
        if cert.status != CertificateStatus::Active {
            return Err(AxiamError::Certificate("certificate is not active".into()));
        }

        // Validate expiry
        let now = Utc::now();
        if now < cert.not_before || now > cert.not_after {
            return Err(AxiamError::Certificate(
                "certificate is expired or not yet valid".into(),
            ));
        }

        // Resolve bound service account
        let sa_id = self
            .cert_repo
            .get_bound_service_account(cert.id)
            .await?
            .ok_or_else(|| {
                AxiamError::Certificate("certificate is not bound to a service account".into())
            })?;

        Ok(DeviceIdentity {
            service_account_id: sa_id,
            tenant_id: cert.tenant_id,
            org_id: Uuid::nil(), // Resolved by the caller via TenantRepository
            certificate_id: cert.id,
        })
    }
}
