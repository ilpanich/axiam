//! Tenant certificate generation service — signs certificates with a CA key.

use axiam_core::ca_keys::LeafSigningRequest;
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::certificate::{
    Certificate, CertificateStatus, CreateCertificate, GeneratedCertificate, SignCertificateCsr,
    StoreCertificate,
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
use crate::ca::{self, CaService, join_pem};
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

/// What [`CertService::prepare_leaf_issuance`] establishes for both leaf paths.
///
/// Borrowed rather than owned for `store`: [`CaKeyCustodians::store_for`] hands
/// back a reference into the service's own custodian table, and cloning a
/// custodian to avoid one lifetime would duplicate a Vault client per issuance.
struct LeafIssuance<'a> {
    ca_cert: axiam_core::models::certificate::CaCertificate,
    store: &'a dyn axiam_core::ca_keys::CaKeyStore,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
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

    /// Everything both leaf paths must establish before a certificate can be
    /// signed: the validity bounds, the issuing CA, and which custodian holds
    /// its key.
    ///
    /// Factored out of [`Self::generate`] when [`Self::sign_csr`] arrived,
    /// rather than copied into it. Every check here is a refusal that must read
    /// the same on both paths — a CSR-signed certificate that could be issued
    /// under a revoked CA, or outlive its issuer, while a generated one could
    /// not, would be a hole with the shape of a second implementation.
    /// `generate`'s own tests are the regression net for the move.
    async fn prepare_leaf_issuance(
        &self,
        org_id: Uuid,
        issuer_ca_id: Uuid,
        validity_days: u32,
        max_validity_days: Option<u32>,
    ) -> AxiamResult<LeafIssuance<'_>> {
        // Enforce validity_days bounds: > 0 and <= tenant/hard cap
        let effective_max = max_validity_days
            .unwrap_or(DEFAULT_LEAF_CERT_VALIDITY_DAYS)
            .min(MAX_LEAF_CERT_VALIDITY_DAYS);
        if validity_days == 0 || validity_days > effective_max {
            return Err(AxiamError::Validation {
                message: format!(
                    "validity_days must be between 1 and {effective_max} \
                     (CA/Browser Forum BR hard cap: {MAX_LEAF_CERT_VALIDITY_DAYS} days)"
                ),
            });
        }

        // Scoped to the organization, so a CA id from another organization is
        // not found rather than usable (T-98).
        let ca_cert = self.ca_repo.get_by_id(org_id, issuer_ca_id).await?;

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
            .checked_add_signed(Duration::days(i64::from(validity_days)))
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
        if requested_not_after > ca_cert.not_after {
            let available = issuer_bounded_validity_days(now, ca_cert.not_after);
            return Err(AxiamError::Validation {
                message: format!(
                    "validity_days is {} but the issuing CA expires on {} — a certificate \
                     cannot outlive its issuer. The most this CA can grant today is {} day{}.",
                    validity_days,
                    ca_cert.not_after.format("%Y-%m-%d"),
                    available,
                    if available == 1 { "" } else { "s" },
                ),
            });
        }

        Ok(LeafIssuance {
            ca_cert,
            store,
            not_before,
            not_after: requested_not_after,
        })
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
        let LeafIssuance {
            ca_cert,
            store,
            not_before,
            not_after,
        } = self
            .prepare_leaf_issuance(
                org_id,
                input.issuer_ca_id,
                input.validity_days,
                max_validity_days,
            )
            .await?;

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

                // Build end-entity certificate request — from the same
                // function `sign_csr` overwrites a caller's parameters with, so
                // the two paths cannot issue different shapes.
                let ee_params = leaf_params(&ee_subject, not_before_ts, not_after_ts)?;

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
                    // AXIAM built this request, three lines up, from a key it
                    // just generated: there is nothing in it a caller chose.
                    csr_is_caller_supplied: false,
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

    /// The minimum RSA modulus AXIAM will sign a certificate over, in bits.
    ///
    /// Stated here rather than inferred from [`KeyAlgorithm::Rsa4096`]'s name,
    /// because that variant is a label and not a measurement:
    /// `ca::parse_ca_certificate` maps *any* RSA OID onto it, deliberately, so
    /// that an imported root of some other size is still a usable root. A path
    /// that enforces a floor cannot reuse that mapping, and an RSA-2048 CSR
    /// signed and then recorded as `Rsa4096` is the exact shape of T-96.
    const MIN_CSR_RSA_MODULUS_BITS: usize = 4096;

    /// Sign a caller's certificate signing request, issuing an end-entity
    /// certificate for a key AXIAM never sees.
    ///
    /// The BYOK counterpart to [`Self::generate`]. The subscriber's private key
    /// is generated by whoever made the CSR and never crosses the wire in
    /// either direction — which is why the answer is a [`Certificate`] and not
    /// a `GeneratedCertificate`: there is no key to return.
    ///
    /// # What the caller decides, and what AXIAM decides
    ///
    /// The caller decides the key and the subject. AXIAM decides everything
    /// else, and the difference is enforced rather than documented:
    ///
    /// - **Possession** is proved by the request's own self-signature, checked
    ///   by [`ca::inspect_csr`] before anything else happens. Without it a
    ///   caller could have a certificate minted over somebody else's public key.
    /// - **The key** must be Ed25519, or RSA with a modulus of at least
    ///   [`Self::MIN_CSR_RSA_MODULUS_BITS`] bits. The modulus is measured, not
    ///   taken from a label.
    /// - **The extensions** are AXIAM's. A CSR requesting `subjectAltName`,
    ///   `keyUsage` or `extendedKeyUsage` is refused by name rather than
    ///   silently stripped; every other requested extension is discarded when
    ///   the parameter set is overwritten with the leaf parameters
    ///   [`Self::generate`] builds. A CSR asking to be an unconstrained CA
    ///   comes back a leaf.
    /// - **The validity, the issuer and the tenant** come from
    ///   [`Self::prepare_leaf_issuance`], the same function `generate` uses, so
    ///   the two paths cannot drift on a revoked CA, an expired one, a CA
    ///   belonging to another organization, or a certificate that would outlive
    ///   its issuer.
    ///
    /// # Why `keyUsage` is refused rather than dropped
    ///
    /// On the in-process path it could be dropped: `request.params` is replaced
    /// wholesale before signing and nothing the caller asked for survives. Under
    /// [`CaKeyCustody::VaultPki`] it could not. Vault's `sign-verbatim`
    /// discards the `key_usage` and `ext_key_usage` request parameters when the
    /// CSR carries those extensions, and issues what the CSR asked for — so a
    /// silent strip would be a promise AXIAM keeps on one custodian and breaks
    /// on the other, for the same CSR. One rule that holds everywhere is worth
    /// more than a convenience that holds in one deployment.
    ///
    /// `basicConstraints` needs no such rule: the in-process path overwrites it
    /// and Vault ignores a CSR's basic constraints outright.
    pub async fn sign_csr(
        &self,
        org_id: Uuid,
        input: SignCertificateCsr,
        max_validity_days: Option<u32>,
    ) -> AxiamResult<Certificate> {
        // Parsed before the CA is even looked up, and outside the blocking
        // task: a malformed or unsigned request is by far the likeliest failure
        // on an endpoint whose input is pasted by hand, and it must be a 400
        // naming the CSR rather than a 500 out of a custodian.
        let facts = ca::inspect_csr(&input.csr_pem)?;

        if let Some(bits) = facts.rsa_modulus_bits
            && bits < Self::MIN_CSR_RSA_MODULUS_BITS
        {
            return Err(AxiamError::Validation {
                message: format!(
                    "the certificate signing request carries an RSA key with a {bits}-bit \
                     modulus; AXIAM signs Ed25519 keys and RSA keys of at least {} bits",
                    Self::MIN_CSR_RSA_MODULUS_BITS
                ),
            });
        }

        if !facts.refused_extensions.is_empty() {
            return Err(AxiamError::Validation {
                message: format!(
                    "the certificate signing request asks for {}, which AXIAM does not sign \
                     over on an end-entity certificate. It is refused rather than dropped \
                     because a certificate issued without what you asked for, and with \
                     nothing said, would fail where you deploy it. Remove the extension \
                     request and submit the CSR again.",
                    facts.refused_extensions.join(" and ")
                ),
            });
        }

        let LeafIssuance {
            ca_cert,
            store,
            not_before,
            not_after,
        } = self
            .prepare_leaf_issuance(
                org_id,
                input.issuer_ca_id,
                input.validity_days,
                max_validity_days,
            )
            .await?;

        let (public_cert_pem, fingerprint, chain_pem, issued_window) = if store.signs_remotely() {
            let key_ref = CaService::<CA>::key_ref(&ca_cert);
            let signed = store
                .sign_csr(
                    &key_ref,
                    &LeafSigningRequest {
                        csr_pem: input.csr_pem.clone(),
                        ttl_seconds: (not_after - not_before).num_seconds(),
                        // These bytes are the caller's. See the custodian's own
                        // doc comment for what it does about that.
                        csr_is_caller_supplied: true,
                    },
                )
                .await?;
            // What the signer produced, not what was asked for: a remote signer
            // caps a TTL to its mount's own maximum without failing the call.
            let issued = parse_issued_leaf(&signed.certificate_pem)?;
            let chain = (!signed.chain_pem.is_empty()).then(|| join_pem(&signed.chain_pem));
            (
                signed.certificate_pem,
                issued.fingerprint,
                chain,
                Some((issued.not_before, issued.not_after)),
            )
        } else {
            let key_ref = CaService::<CA>::key_ref(&ca_cert);
            let mut ca_private_key_pem = store
                .load(&key_ref, ca_cert.encrypted_private_key.as_deref())
                .await?
                .to_string();

            let _permit = self
                .crypto_semaphore
                .acquire()
                .await
                .map_err(|_| AxiamError::Internal("crypto semaphore closed".into()))?;

            let ca_cert_pem = ca_cert.public_cert_pem.clone();
            let csr_pem = input.csr_pem.clone();
            let subject = facts.common_name.clone();
            let not_before_ts = not_before.timestamp();
            let not_after_ts = not_after.timestamp();

            let (pem, fingerprint) =
                tokio::task::spawn_blocking(move || -> AxiamResult<(String, String)> {
                    let ca_key_pair = KeyPair::from_pem(&ca_private_key_pem).map_err(|e| {
                        AxiamError::Certificate(format!("invalid CA private key: {e}"))
                    })?;
                    ca_private_key_pem.zeroize();

                    let ca_issuer =
                        Issuer::from_ca_cert_pem(&ca_cert_pem, ca_key_pair).map_err(|e| {
                            AxiamError::Certificate(format!("invalid CA certificate PEM: {e}"))
                        })?;

                    // Parsed a second time, inside the task, because rcgen's
                    // signing API needs its own representation. The answer that
                    // matters — whether the signature verifies — was already
                    // established above, on the same bytes; this is not a
                    // second opinion about it.
                    let mut request = rcgen::CertificateSigningRequestParams::from_pem(&csr_pem)
                        .map_err(|e| AxiamError::Validation {
                            message: format!("the certificate signing request was rejected: {e}"),
                        })?;
                    // Everything the request asked to be, overwritten by what
                    // AXIAM has decided it is — the same leaf parameters
                    // `generate` builds, so the two paths issue the same shape
                    // of certificate for the same request.
                    request.params = leaf_params(&subject, not_before_ts, not_after_ts)?;
                    // Deliberately **not** `use_authority_key_identifier_extension`,
                    // which the intermediate CSR path sets. Setting it here put
                    // an authorityKeyIdentifier on a CSR-signed leaf that a
                    // generated leaf does not carry, which is exactly the
                    // divergence D-5 forbids: two ways of asking for the same
                    // certificate producing two different certificates. An AKI
                    // on leaves is worth having and is a change to make on both
                    // paths at once, with the KU/EKU profiles, not a side
                    // effect of how the key was made.

                    let cert = request.signed_by(&ca_issuer).map_err(|e| {
                        AxiamError::Certificate(format!("certificate signing failed: {e}"))
                    })?;
                    let pem = cert.pem();
                    let fingerprint = compute_fingerprint(cert.der());
                    Ok((pem, fingerprint))
                })
                .await
                .map_err(|e| AxiamError::Internal(format!("spawn_blocking join error: {e}")))??;

            // Signed in-process by a CA whose certificate the caller can fetch;
            // there is no chain here they cannot already assemble.
            (pem, fingerprint, None, None)
        };

        let (row_not_before, row_not_after) = issued_window.unwrap_or((not_before, not_after));

        let certificate = self
            .cert_repo
            .create(StoreCertificate {
                tenant_id: input.tenant_id,
                issuer_ca_id: input.issuer_ca_id,
                // What the certificate says, never what the caller said
                // separately — there is no separate field for them to say it in
                // (T-194: the row and the certificate cannot disagree).
                subject: facts.common_name,
                public_cert_pem,
                fingerprint,
                cert_type: input.cert_type,
                // Read off the CSR's own public key, not asserted by the caller.
                key_algorithm: facts.key_algorithm,
                not_before: row_not_before,
                not_after: row_not_after,
                metadata: input.metadata.unwrap_or(serde_json::json!({})),
            })
            .await?;

        // `chain_pem` has nowhere to go on a `Certificate` and is not dropped
        // silently: under the custodians that return one, the chain is the
        // issuing CA's own certificate, which `GET /certificates/{id}` already
        // resolves through `issuer_ca_id`. A caller holding the certificate can
        // assemble the chain from data the API already gives them.
        let _ = chain_pem;

        Ok(certificate)
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
/// The parameters every AXIAM leaf certificate is built from: the common name,
/// the validity window, and `CA:FALSE`.
///
/// No subjectAltName, no key usage, no extended key usage — deliberately, and
/// identically on both leaf paths. Adding a usage profile to one of them only
/// would be a worse outcome than the status quo: two ways of asking for the
/// same certificate would produce two different certificates. Giving *both*
/// paths a per-`cert_type` profile is a follow-up to be decided once, for both,
/// with a migration note for everything already issued without one.
///
/// Shared by [`CertService::generate`], which builds a key to go with it, and
/// by [`CertService::sign_csr`], which overwrites a caller's requested
/// parameters with it. That sharing is the enforcement: "a CSR-signed leaf is
/// the same shape as a generated one" is true because there is one function
/// that says what the shape is.
fn leaf_params(
    subject: &str,
    not_before_ts: i64,
    not_after_ts: i64,
) -> AxiamResult<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| AxiamError::Certificate(e.to_string()))?;
    params.distinguished_name.push(DnType::CommonName, subject);
    params.is_ca = IsCa::NoCa;
    params.not_before = time::OffsetDateTime::from_unix_timestamp(not_before_ts)
        .map_err(|e| AxiamError::Certificate(format!("invalid notBefore: {e}")))?;
    params.not_after = time::OffsetDateTime::from_unix_timestamp(not_after_ts)
        .map_err(|e| AxiamError::Certificate(format!("invalid notAfter: {e}")))?;
    Ok(params)
}

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
