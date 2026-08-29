//! mTLS device authentication — validates client certificates via fingerprint
//! lookup and verifies the full chain to the tenant/org CA.
//!
//! SEC-024: After the fingerprint lookup, the client cert is cryptographically
//! verified against the CA cert returned by the `CaCertificateRepository`.
//! If no active CA cert exists the call fails closed — a cert with a matching
//! fingerprint but NOT signed by the tenant CA is rejected.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::certificate::{CertificateStatus, DeviceIdentity};
use axiam_core::repository::{CaCertificateRepository, CertificateRepository};
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::parse_x509_certificate;

/// Service for mTLS device certificate authentication.
#[derive(Clone)]
pub struct DeviceAuthService<CR, CCR> {
    cert_repo: CR,
    /// Repository for CA certificates — used to verify the client cert chain
    /// (SEC-024). When `None`, chain verification is skipped (legacy path).
    ca_cert_repo: CCR,
}

impl<CR: CertificateRepository, CCR: CaCertificateRepository> DeviceAuthService<CR, CCR> {
    pub fn new(cert_repo: CR, ca_cert_repo: CCR) -> Self {
        Self {
            cert_repo,
            ca_cert_repo,
        }
    }

    /// Authenticate a device by its PEM-encoded client certificate.
    ///
    /// 1. Parse PEM and compute SHA-256 fingerprint
    /// 2. Look up certificate by fingerprint (global, cross-tenant)
    /// 3. Validate status (Active) and expiry
    /// 4. Verify certificate chain to the tenant/org CA (SEC-024)
    /// 5. Resolve the bound service account
    ///
    /// Returns a [`DeviceIdentity`] with the service account and tenant.
    /// The caller is responsible for resolving `org_id` from the tenant.
    pub async fn authenticate(&self, pem: &str) -> AxiamResult<DeviceIdentity> {
        // Parse PEM, then delegate to the DER path so the PEM (proxy header) and
        // native-mTLS (verified peer cert, D3) flows share one validation chain.
        let (_, pem_obj) = parse_x509_pem(pem.as_bytes())
            .map_err(|e| AxiamError::Certificate(format!("invalid client certificate PEM: {e}")))?;
        self.authenticate_der(&pem_obj.contents).await
    }

    /// Authenticate a device from a DER-encoded client certificate.
    ///
    /// This is the shared core of [`Self::authenticate`]: it is called directly
    /// by the REST layer with the certificate rustls **verified** during the
    /// native-mTLS handshake (D3), so the verified peer certificate — not a
    /// proxy header — drives certificate-based identity.
    ///
    /// Steps mirror [`Self::authenticate`]: fingerprint lookup, status/expiry
    /// checks, chain verification to the tenant/org CA (SEC-024/SECHRD-05), and
    /// service-account resolution.
    pub async fn authenticate_der(&self, der: &[u8]) -> AxiamResult<DeviceIdentity> {
        // Compute SHA-256 fingerprint from DER
        let fingerprint = hex::encode(Sha256::digest(der));

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

        // SEC-024: Verify the client cert chain to the issuing CA.
        // Fails closed: if no CA is found for the issuer, authentication is denied.
        let ca_cert = self
            .ca_cert_repo
            .get_by_issuer_id(cert.issuer_ca_id)
            .await
            .map_err(|_| {
                AxiamError::Certificate(
                    "no CA certificate found for the issuing authority — chain verify failed"
                        .into(),
                )
            })?;

        // SECHRD-05: Assert the issuing CA itself is Active and within its
        // validity window before trusting it to verify the client cert's
        // signature. Mirrors the leaf-cert check above (:59-70) applied to
        // the immediate issuer. Full chain-walk beyond the immediate issuer
        // is out of scope (D-02 — flat org/tenant-CA -> device hierarchy).
        if ca_cert.status != CertificateStatus::Active {
            return Err(AxiamError::Certificate("issuing CA is not active".into()));
        }
        if now < ca_cert.not_before || now > ca_cert.not_after {
            return Err(AxiamError::Certificate(
                "issuing CA certificate is expired or not yet valid".into(),
            ));
        }

        // Parse the CA PEM to obtain the public key.
        let (_, ca_pem_obj) = parse_x509_pem(ca_cert.public_cert_pem.as_bytes())
            .map_err(|e| AxiamError::Certificate(format!("invalid CA certificate PEM: {e}")))?;
        let (_, ca_x509) = parse_x509_certificate(&ca_pem_obj.contents)
            .map_err(|e| AxiamError::Certificate(format!("failed to parse CA certificate: {e}")))?;

        // Parse the client cert DER.
        let (_, client_x509) = parse_x509_certificate(der).map_err(|e| {
            AxiamError::Certificate(format!("failed to parse client certificate: {e}"))
        })?;

        // Cryptographic chain verify — reject if the client cert was not signed by the CA.
        client_x509
            .verify_signature(Some(ca_x509.public_key()))
            .map_err(|_| {
                AxiamError::Certificate(
                    "certificate chain verify failed — client cert not signed by tenant CA".into(),
                )
            })?;

        // The certificate must chain to a CA an operator flagged as an mTLS
        // trust anchor.
        //
        // Without this, every CA in the organization was equally good: proving
        // the leaf was signed by *some* CA that exists says nothing about
        // whether that CA was ever meant to authenticate anyone. On the native
        // path rustls enforces it, because the client-CA bundle is built from
        // exactly the flagged anchors — but this function is also the
        // proxy-terminated path (`X-Client-Certificate`), which is what the
        // shipped Compose and Kubernetes deployments use, and there nothing
        // consulted the flag at all. Un-flagging a CA — the documented way to
        // stop trusting it — left every certificate under it authenticating.
        //
        // The check is a walk, not a test of the immediate issuer, because a
        // tenant signing CA is an intermediate and is deliberately NOT itself
        // an anchor: trust flows from the organization root it hangs beneath.
        // Requiring the immediate issuer to be flagged would refuse every
        // legitimately intermediate-issued certificate.
        self.require_trust_anchor(&ca_cert).await?;

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

    /// Walks up from `issuer` until a CA flagged `mtls_trust_anchor` is found.
    ///
    /// Every CA on the way must itself be usable — `Active` and inside its
    /// validity window — because an anchor reached through a revoked
    /// intermediate is not reached at all.
    ///
    /// The walk is bounded. `parent_ca_id` is data, and data can describe a
    /// cycle; an unbounded loop over it would hang the request handler rather
    /// than refuse it. The bound is generous next to any real hierarchy
    /// (root -> tenant signing CA -> leaf is two hops) and small enough that a
    /// malformed chain fails fast.
    async fn require_trust_anchor(
        &self,
        issuer: &axiam_core::models::certificate::CaCertificate,
    ) -> AxiamResult<()> {
        const MAX_CHAIN_DEPTH: usize = 8;
        let now = Utc::now();
        let mut node = issuer.clone();

        for _ in 0..MAX_CHAIN_DEPTH {
            if node.mtls_trust_anchor {
                return Ok(());
            }
            let Some(parent_id) = node.parent_ca_id else {
                return Err(AxiamError::Certificate(
                    "certificate does not chain to any CA enabled as an mTLS trust anchor".into(),
                ));
            };
            node = self
                .ca_cert_repo
                .get_by_id(node.organization_id, parent_id)
                .await
                .map_err(|_| {
                    AxiamError::Certificate(
                        "issuing CA names a parent that does not exist — chain verify failed"
                            .into(),
                    )
                })?;
            if node.status != CertificateStatus::Active
                || now < node.not_before
                || now > node.not_after
            {
                return Err(AxiamError::Certificate(
                    "a CA in the issuing chain is revoked or outside its validity window".into(),
                ));
            }
        }

        Err(AxiamError::Certificate(
            "issuing CA chain is longer than the supported depth — chain verify failed".into(),
        ))
    }
}
