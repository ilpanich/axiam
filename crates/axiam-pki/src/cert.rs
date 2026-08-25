//! Tenant certificate generation service — signs certificates with a CA key.

use axiam_core::ca_keys::LeafSigningRequest;
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::certificate::{
    Certificate, CertificateStatus, CreateCertificate, GeneratedCertificate, StoreCertificate,
};
use axiam_core::repository::{
    CaCertificateRepository, CertificateRepository, PaginatedResult, Pagination,
};
use chrono::{DateTime, Duration, Utc};
use rcgen::{CertificateParams, DnType, IsCa, Issuer, KeyPair};
use std::sync::Arc;
use tokio::sync::Semaphore;
use uuid::Uuid;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;
use zeroize::Zeroize;

use crate::PkiConfig;
use crate::ca::{CaService, join_pem};
use crate::ca_key_store::CaKeyCustodians;
use crate::crypto::{compute_fingerprint, generate_keypair};

/// Hard cap for leaf certificate validity: 825 days (~27 months).
///
/// Aligns with CA/Browser Forum Baseline Requirements and Apple/Mozilla
/// root program policies. Internal PKI may allow up to this limit;
/// tenants can configure a lower per-tenant maximum via the
/// `max_certificate_validity_days` key in their metadata.
pub const MAX_LEAF_CERT_VALIDITY_DAYS: u32 = 825;

/// Default leaf certificate validity when no tenant override is set: 365 days.
pub const DEFAULT_LEAF_CERT_VALIDITY_DAYS: u32 = 365;

/// The longest validity, in whole days, an issuer expiring at `issuer_not_after`
/// can still grant to something issued at `now`.
///
/// A certificate must not outlive the CA that signed it — past the issuer's
/// notAfter the chain stops validating, so the extra days are not merely
/// useless, they are days the holder believes they have and does not. Both the
/// leaf path ([`CertService::generate`]) and the intermediate path
/// (`ca::generate_intermediate`) refuse a request above this number and quote it
/// back, and the certificates API returns it per CA so the admin UI can cap its
/// own input rather than discovering the limit on submit.
///
/// Rounded **down** to whole days, and floored at zero: an issuer with 36 hours
/// left can grant one day, not two, and an expired issuer can grant nothing.
/// (Callers reject an expired or not-yet-valid issuer before reaching here; the
/// zero is a total function's answer, not a code path anyone rides.)
///
/// # Examples
///
/// ```
/// use axiam_pki::cert::issuer_bounded_validity_days;
/// use chrono::{Duration, Utc};
///
/// let now = Utc::now();
/// // A CA with 90 days and 12 hours left grants 90 days, never 91.
/// let ca_expiry = now + Duration::days(90) + Duration::hours(12);
/// assert_eq!(issuer_bounded_validity_days(now, ca_expiry), 90);
///
/// // An issuer already past its notAfter grants nothing.
/// assert_eq!(issuer_bounded_validity_days(now, now - Duration::days(1)), 0);
/// ```
pub fn issuer_bounded_validity_days(now: DateTime<Utc>, issuer_not_after: DateTime<Utc>) -> u32 {
    let remaining = (issuer_not_after - now).num_days();
    u32::try_from(remaining.max(0)).unwrap_or(u32::MAX)
}

/// Service for tenant-level certificate operations.
#[derive(Clone)]
pub struct CertService<CA, CR> {
    ca_repo: CA,
    cert_repo: CR,
    #[allow(dead_code)]
    config: PkiConfig,
    /// Shared bounding semaphore for CPU-bound crypto (CQ-B02).
    crypto_semaphore: Arc<Semaphore>,
    /// Who holds the CA signing keys. See [`crate::ca_key_store`].
    custodians: Arc<CaKeyCustodians>,
}

impl<CA: CaCertificateRepository, CR: CertificateRepository> CertService<CA, CR> {
    pub fn new(
        ca_repo: CA,
        cert_repo: CR,
        config: PkiConfig,
        crypto_semaphore: Arc<Semaphore>,
        custodians: Arc<CaKeyCustodians>,
    ) -> Self {
        Self {
            ca_repo,
            cert_repo,
            config,
            crypto_semaphore,
            custodians,
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

        // Fetch the signing key from whichever custodian this CA's row names —
        // not from whichever is currently configured. A deployment that adopted
        // Vault still has CAs whose keys are sealed into their rows, and asking
        // the current setting about them would fail to find a key that is
        // perfectly present.
        //
        // An imported CA with no key at all resolves to the `External`
        // custodian, whose error says it has no private key and therefore
        // cannot issue — rather than the bare "no stored private key" this used
        // to produce for both that case and a genuine decryption failure.
        let store = self.custodians.store_for(ca_cert.key_custody)?;

        let not_before = now;
        let requested_not_after = now
            .checked_add_signed(Duration::days(i64::from(input.validity_days)))
            .ok_or_else(|| AxiamError::Validation {
                message: "validity_days produces a date out of range".into(),
            })?;
        // A leaf must not outlive the CA that signed it: a relying party stops
        // trusting the chain the moment the issuer expires, so the extra days
        // buy nothing and the certificate would fail every handshake made after
        // the issuer's notAfter.
        //
        // This used to be a silent `min(requested, ca_cert.not_after)`. Silent
        // was the wrong call: an operator asking for two years against a CA with
        // three months left got a three-month certificate, no warning, and a
        // renewal calendar built on a date the certificate does not carry. Say
        // no and name the number they can actually have — see
        // `issuer_bounded_validity_days`, which the API also exposes so the
        // form can cap its own input before anyone submits it.
        let not_after = requested_not_after;
        if requested_not_after > ca_cert.not_after {
            let available = issuer_bounded_validity_days(now, ca_cert.not_after);
            return Err(AxiamError::Validation {
                message: format!(
                    "validity_days is {} but the issuing CA expires on {} — a certificate \
                     cannot outlive its issuer. The most this CA can grant today is {} day{}.",
                    input.validity_days,
                    ca_cert.not_after.format("%Y-%m-%d"),
                    available,
                    if available == 1 { "" } else { "s" },
                ),
            });
        }

        // A custodian that signs on AXIAM's behalf never hands the key over, so
        // there is nothing to load and nothing to sign with here: the leaf key
        // is generated locally, its public half goes out in a CSR, and a
        // certificate comes back. See [`axiam_core::ca_keys`].
        if store.signs_remotely() {
            return self
                .generate_remotely(&ca_cert, input, not_before, not_after)
                .await;
        }

        // Fetch the signing key from whichever custodian this CA's row named.
        let key_ref = CaService::<CA>::key_ref(&ca_cert);
        let mut ca_private_key_pem = store
            .load(&key_ref, ca_cert.encrypted_private_key.as_deref())
            .await?
            .to_string();

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
            // Signed in-process by a CA whose certificate the caller can fetch;
            // there is no chain here they cannot already assemble.
            chain_pem: None,
        })
    }

    /// Issue against a CA whose key lives in — and stays in — its custodian.
    ///
    /// The end-entity key is still generated here and still returned once: what
    /// moves to the custodian is the *signature*, not the subscriber's key. The
    /// CSR carries the public half and nothing else.
    async fn generate_remotely(
        &self,
        ca_cert: &axiam_core::models::certificate::CaCertificate,
        input: CreateCertificate,
        not_before: DateTime<Utc>,
        not_after: DateTime<Utc>,
    ) -> AxiamResult<GeneratedCertificate> {
        // Only the keygen and CSR are CPU-bound. The permit is dropped before
        // the call to the custodian: holding it across a network round trip
        // would let one slow signer block every other issuance in the
        // deployment, which is the opposite of what the semaphore is for.
        let (private_key_pem, csr_pem) = {
            let _permit = self
                .crypto_semaphore
                .acquire()
                .await
                .map_err(|_| AxiamError::Internal("crypto semaphore closed".into()))?;

            let ee_subject = input.subject.clone();
            let key_algorithm = input.key_algorithm.clone();
            tokio::task::spawn_blocking(move || -> AxiamResult<(String, String)> {
                let ee_key_pair = generate_keypair(&key_algorithm)?;
                let private_key_pem = ee_key_pair.serialize_pem();

                let mut params = CertificateParams::new(Vec::<String>::new())
                    .map_err(|e| AxiamError::Certificate(e.to_string()))?;
                params
                    .distinguished_name
                    .push(DnType::CommonName, &ee_subject);
                params.is_ca = IsCa::NoCa;
                // No validity window: a PKCS#10 request cannot carry one. The
                // signer is told the lifetime out of band, as a TTL.
                let csr = params.serialize_request(&ee_key_pair).map_err(|e| {
                    AxiamError::Certificate(format!("certificate request failed: {e}"))
                })?;
                let csr_pem = csr
                    .pem()
                    .map_err(|e| AxiamError::Certificate(format!("CSR encoding failed: {e}")))?;
                Ok((private_key_pem, csr_pem))
            })
            .await
            .map_err(|e| AxiamError::Internal(format!("spawn_blocking join error: {e}")))??
        };

        let key_ref = CaService::<CA>::key_ref(ca_cert);
        let store = self.custodians.store_for(ca_cert.key_custody)?;
        let signed = store
            .sign_csr(
                &key_ref,
                &LeafSigningRequest {
                    csr_pem,
                    ttl_seconds: (not_after - not_before).num_seconds(),
                },
            )
            .await?;

        // What the signer produced, not what was asked for. A remote signer
        // caps a TTL to its mount's own maximum without failing the call, so a
        // row built from the request would claim a window the certificate does
        // not have — and the fingerprint has to be of the real bytes or every
        // lookup by fingerprint misses.
        let issued = parse_issued_leaf(&signed.certificate_pem)?;

        let store_record = StoreCertificate {
            tenant_id: input.tenant_id,
            issuer_ca_id: input.issuer_ca_id,
            subject: input.subject,
            public_cert_pem: signed.certificate_pem,
            fingerprint: issued.fingerprint,
            cert_type: input.cert_type,
            key_algorithm: input.key_algorithm,
            not_before: issued.not_before,
            not_after: issued.not_after,
            metadata: input.metadata.unwrap_or(serde_json::json!({})),
        };

        let certificate = self.cert_repo.create(store_record).await?;

        Ok(GeneratedCertificate {
            certificate,
            private_key_pem,
            chain_pem: (!signed.chain_pem.is_empty()).then(|| join_pem(&signed.chain_pem)),
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

/// What a certificate a remote signer returned actually says about itself.
struct IssuedLeaf {
    fingerprint: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

/// Read back a signed leaf, so the row describes the certificate rather than
/// the request that produced it.
fn parse_issued_leaf(pem: &str) -> AxiamResult<IssuedLeaf> {
    let (_, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|e| {
        AxiamError::Certificate(format!(
            "the signer returned something that is not a PEM certificate: {e}"
        ))
    })?;
    let (_, cert) = X509Certificate::from_der(&block.contents).map_err(|e| {
        AxiamError::Certificate(format!("the signed certificate could not be parsed: {e}"))
    })?;

    let to_utc = |t: i64, what: &str| -> AxiamResult<DateTime<Utc>> {
        DateTime::from_timestamp(t, 0).ok_or_else(|| {
            AxiamError::Certificate(format!("the signed certificate's {what} is out of range"))
        })
    };

    Ok(IssuedLeaf {
        fingerprint: compute_fingerprint(&block.contents),
        not_before: to_utc(cert.validity().not_before.timestamp(), "notBefore")?,
        not_after: to_utc(cert.validity().not_after.timestamp(), "notAfter")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_cert_validity_constants_are_sane() {
        const { assert!(DEFAULT_LEAF_CERT_VALIDITY_DAYS <= MAX_LEAF_CERT_VALIDITY_DAYS) };
        assert_eq!(MAX_LEAF_CERT_VALIDITY_DAYS, 825);
        assert_eq!(DEFAULT_LEAF_CERT_VALIDITY_DAYS, 365);
    }
}
