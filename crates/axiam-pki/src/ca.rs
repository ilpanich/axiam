//! CA certificate generation and management service.

use axiam_core::ca_keys::{
    CaGenerationRequest, CaKeyCustody, CaKeyRef, IntermediateCaRequest, IntermediateSigningRequest,
    IntermediateSpec, StoredCaKey,
};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::certificate::{
    CaCertificate, CertificateStatus, CreateCaCertificate, CreateIntermediateCa,
    GeneratedCaCertificate, ImportCaCertificate, KeyAlgorithm, SignIntermediateCsr,
    StoreCaCertificate,
};
use axiam_core::repository::{CaCertificateRepository, PaginatedResult, Pagination};
use chrono::{DateTime, Duration, Utc};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};
use std::sync::Arc;
use tokio::sync::Semaphore;
use uuid::Uuid;
// Named imports rather than the prelude: the prelude re-exports a `time`
// module that shadows the `time` *crate` rcgen's validity fields are typed
// against, and the resulting error names a private struct rather than the
// shadowing.
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;
use x509_parser::time::ASN1Time;
use zeroize::Zeroize;

use crate::ca_key_store::CaKeyCustodians;
use crate::cert::{
    CUSTODIAN_REVOKE_ATTEMPTS, CUSTODIAN_REVOKE_BUDGET, CustodianRevocation, attempt_custodian,
    serial_hex,
};
use crate::crl::CrlDistribution;
use crate::crypto::{compute_fingerprint, generate_keypair, private_key_pem};
use crate::subject::subject_common_name;

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
    #[allow(dead_code)]
    config: PkiConfig,
    /// Shared bounding semaphore for CPU-bound crypto (CQ-B02).
    crypto_semaphore: Arc<Semaphore>,
    /// Who holds the signing keys. See [`crate::ca_key_store`].
    custodians: Arc<CaKeyCustodians>,
    /// Where a parent CA's revocation list is published (#565). See
    /// [`Self::with_crl_distribution`].
    crl_distribution: Option<CrlDistribution>,
}

impl<R: CaCertificateRepository> CaService<R> {
    pub fn new(
        repo: R,
        config: PkiConfig,
        crypto_semaphore: Arc<Semaphore>,
        custodians: Arc<CaKeyCustodians>,
    ) -> Self {
        Self {
            repo,
            config,
            crypto_semaphore,
            custodians,
            crl_distribution: None,
        }
    }

    /// Write a CRL distribution point naming the parent's revocation list into
    /// every subordinate CA this service signs in-process (#565, T-102).
    ///
    /// The parent's list names a revoked tenant signing CA, and a relying party
    /// that walks the chain finds that list through this extension. The same
    /// rules as `CertService::with_crl_distribution`: `None` writes nothing,
    /// and an intermediate Vault's PKI engine creates carries Vault's profile.
    #[must_use]
    pub fn with_crl_distribution(mut self, distribution: Option<CrlDistribution>) -> Self {
        self.crl_distribution = distribution;
        self
    }

    /// Generate a new CA certificate.
    ///
    /// Two shapes, chosen by the configured custodian rather than by the
    /// caller, because the difference is a property of where keys live and not
    /// of what was asked for:
    ///
    /// * **AXIAM generates it.** A self-signed root, whose private key is
    ///   handed to the custodian and returned to the caller once. What every
    ///   custodian but one does.
    /// * **The custodian generates it.** Under `vault_pki`, Vault creates a
    ///   root and a signing intermediate beneath it, and there is no private
    ///   key to return because none ever existed here. [`GeneratedCaCertificate`]
    ///   omits the field rather than sending an empty one.
    pub async fn generate(
        &self,
        mut input: CreateCaCertificate,
    ) -> AxiamResult<GeneratedCaCertificate> {
        // DF-023. `subject` is a common name, not a distinguished name.
        // Normalised here, at the top, rather than where the DN is built:
        // this one value reaches the certificate, the `subject` column, and —
        // through the default below — the intermediate's subject too, and the
        // three have to agree. See [`crate::subject_common_name`].
        input.subject = subject_common_name(&input.subject)?;
        if let Some(intermediate) = input.intermediate_subject.take() {
            input.intermediate_subject = Some(subject_common_name(&intermediate)?);
        }

        if input.validity_days == 0 || input.validity_days > MAX_CA_VALIDITY_DAYS {
            return Err(AxiamError::Validation {
                message: format!(
                    "validity_days must be between 1 and {MAX_CA_VALIDITY_DAYS} \
                     (NIST SP 800-57 max for CA certificates)"
                ),
            });
        }
        if let Some(days) = input.intermediate_validity_days
            && (days == 0 || days > MAX_CA_VALIDITY_DAYS)
        {
            return Err(AxiamError::Validation {
                message: format!(
                    "intermediate_validity_days must be between 1 and {MAX_CA_VALIDITY_DAYS} \
                     (NIST SP 800-57 max for CA certificates)"
                ),
            });
        }

        // The id is minted here rather than by the repository because a
        // custodian outside the database addresses the key *by CA id*: the id
        // has to exist before the key is stored, and the key has to be stored
        // before the row. A custodian that refuses therefore stops the CA
        // existing at all, rather than leaving a certificate whose key is
        // nowhere and whose failure surfaces at the first issuance.
        let ca_id = Uuid::new_v4();
        let store = self.custodians.default_store()?;

        if store.generates_cas() {
            return self.generate_in_custodian(ca_id, input).await;
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
                let private_key_pem = private_key_pem(&key_pair)?;

                let mut params = CertificateParams::new(Vec::<String>::new())
                    .map_err(|e| AxiamError::Certificate(e.to_string()))?;
                params.distinguished_name.push(DnType::CommonName, &subject);
                params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
                // #653: rcgen's default is a hash of the public key.
                params.serial_number = Some(crate::serial::random_serial());
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

        let stored = store
            .store(input.organization_id, ca_id, &private_key_pem)
            .await?;
        let (encrypted_private_key, key_locator) = split_stored(stored);

        let record = StoreCaCertificate {
            id: ca_id,
            organization_id: input.organization_id,
            // An organization-level CA: the anchor, not something under a
            // tenant, and with no parent inside AXIAM.
            tenant_id: None,
            parent_ca_id: None,
            subject: input.subject,
            public_cert_pem,
            // A self-signed root is its own chain.
            chain_pem: None,
            fingerprint,
            key_algorithm: input.key_algorithm,
            not_before,
            not_after,
            encrypted_private_key,
            key_custody: store.custody(),
            key_locator,
        };

        let certificate = self.repo.create(record).await?;

        Ok(GeneratedCaCertificate {
            certificate,
            private_key_pem: Some(private_key_pem),
        })
    }

    /// The `vault_pki` path: Vault makes the key, the root and the intermediate.
    ///
    /// Nothing here is CPU-bound — no key is generated in this process — so it
    /// deliberately does not take the crypto semaphore. Holding it across a
    /// network round trip to Vault would let one slow CA generation block every
    /// certificate issuance in the deployment, which is the opposite of what
    /// the semaphore is for.
    ///
    /// Everything the row records is parsed back out of the certificate Vault
    /// returned rather than taken from the request, for the same reason
    /// [`Self::import`] does it: Vault caps a TTL to the mount's
    /// `max_lease_ttl` and to the signing root's own expiry without failing the
    /// call, so a row built from the request would claim a validity window the
    /// certificate does not have.
    async fn generate_in_custodian(
        &self,
        ca_id: Uuid,
        input: CreateCaCertificate,
    ) -> AxiamResult<GeneratedCaCertificate> {
        let store = self.custodians.default_store()?;
        let intermediate = if input.issue_from_root {
            None
        } else {
            let subject = match &input.intermediate_subject {
                // Already through `subject_common_name` in `generate`.
                Some(given) => given.clone(),
                None => {
                    // #649 — the one name AXIAM composes itself. The root's
                    // subject passed the 64-character bound; the root's subject
                    // plus this suffix might not, and would otherwise reach the
                    // custodian (and the row) as an over-long common name.
                    let derived = format!("{} Intermediate Authority", input.subject);
                    if derived.chars().count() > crate::subject::MAX_COMMON_NAME_CHARS {
                        return Err(AxiamError::Validation {
                            message: format!(
                                "the default intermediate subject (the subject plus \" \
                                 Intermediate Authority\") would exceed {} characters; give \
                                 intermediate_subject",
                                crate::subject::MAX_COMMON_NAME_CHARS
                            ),
                        });
                    }
                    derived
                }
            };
            Some(IntermediateSpec {
                subject,
                validity_days: input
                    .intermediate_validity_days
                    .unwrap_or(input.validity_days),
            })
        };

        let generated = store
            .generate_ca(&CaGenerationRequest {
                organization_id: input.organization_id,
                ca_id,
                subject: input.subject,
                key_algorithm: input.key_algorithm,
                validity_days: input.validity_days,
                intermediate,
            })
            .await?;

        let parsed = parse_ca_certificate(&generated.certificate_pem)?;
        let record = StoreCaCertificate {
            id: ca_id,
            organization_id: input.organization_id,
            tenant_id: None,
            parent_ca_id: None,
            subject: parsed.subject,
            public_cert_pem: generated.certificate_pem,
            chain_pem: (!generated.chain_pem.is_empty()).then(|| join_pem(&generated.chain_pem)),
            fingerprint: parsed.fingerprint,
            key_algorithm: parsed.key_algorithm,
            not_before: parsed.not_before,
            not_after: parsed.not_after,
            encrypted_private_key: None,
            key_custody: store.custody(),
            key_locator: Some(generated.locator),
        };

        let certificate = self.repo.create(record).await?;
        Ok(GeneratedCaCertificate {
            certificate,
            // There is nothing to return, and that is the point of this
            // custodian rather than an omission.
            private_key_pem: None,
        })
    }

    /// Import a CA an organization already has (BYOK).
    ///
    /// The other way a CA comes to exist. Generation makes a key AXIAM chose;
    /// this takes one from an offline root, an existing internal PKI or an HSM
    /// ceremony, and puts AXIAM in the chain rather than at the top of it.
    ///
    /// Everything the row records — subject, validity window, key algorithm,
    /// fingerprint — is parsed out of the supplied certificate rather than
    /// taken from the request. A caller could otherwise claim a subject or a
    /// validity window the certificate does not have, and AXIAM would enforce
    /// the claim while every relying party read the certificate.
    ///
    /// A supplied private key is verified to belong to the certificate before
    /// anything is written. Storing a mismatched pair would produce a CA that
    /// looks issuable and fails at the first signature, with a message about
    /// key parsing that names nothing an operator did.
    pub async fn import(&self, input: ImportCaCertificate) -> AxiamResult<CaCertificate> {
        let parsed = parse_ca_certificate(&input.public_cert_pem)?;

        if let Some(ref key_pem) = input.private_key_pem {
            verify_key_matches_certificate(key_pem, &input.public_cert_pem)?;
        }

        let ca_id = Uuid::new_v4();
        let (encrypted_private_key, key_locator, custody) = match input.private_key_pem {
            Some(ref key_pem) => {
                let store = self.custodians.default_store()?;
                // `import_ca` rather than `store`: a custodian that is itself a
                // PKI — Vault's engine — takes the key and the certificate it
                // belongs to as one bundle and has nowhere to put a key alone.
                // Every other custodian ignores the certificate.
                let stored = store
                    .import_ca(
                        input.organization_id,
                        ca_id,
                        &input.public_cert_pem,
                        key_pem,
                    )
                    .await?;
                let (inline, locator) = split_stored(stored);
                (inline, locator, store.custody())
            }
            // No key: a trust anchor and nothing more. Recorded as `External`
            // so the signing path can say why it cannot issue instead of
            // failing on an absent ciphertext.
            None => (None, None, CaKeyCustody::External),
        };

        let record = StoreCaCertificate {
            id: ca_id,
            organization_id: input.organization_id,
            tenant_id: None,
            parent_ca_id: None,
            subject: parsed.subject,
            public_cert_pem: input.public_cert_pem,
            // Whatever chain an imported CA has is held by whoever imported it;
            // AXIAM records what it was given and does not invent the rest.
            chain_pem: None,
            fingerprint: parsed.fingerprint,
            key_algorithm: parsed.key_algorithm,
            not_before: parsed.not_before,
            not_after: parsed.not_after,
            encrypted_private_key,
            key_custody: custody,
            key_locator,
        };

        self.repo.create(record).await
    }

    /// Create a tenant signing CA beneath one of the organization's CAs.
    ///
    /// The intermediate that stands between the organization's trust anchor and
    /// a tenant's user, service and device certificates. AXIAM generates its
    /// key — or the custodian does, under `vault_pki` — and the parent signs
    /// it. The private key is returned exactly once, on the same terms as any
    /// other generated key, and under `vault_pki` there is none to return.
    ///
    /// It is constrained to a path length of zero: it signs leaves and cannot
    /// mint further CAs. Nothing in AXIAM issues a third tier, and an
    /// unconstrained intermediate would be a capability every relying party
    /// downstream had to trust for no gain.
    pub async fn generate_intermediate(
        &self,
        mut input: CreateIntermediateCa,
    ) -> AxiamResult<GeneratedCaCertificate> {
        // DF-023, as in [`Self::generate`]: one common name, agreed between
        // the certificate's DN and the row that describes it.
        input.subject = subject_common_name(&input.subject)?;

        if input.validity_days == 0 || input.validity_days > MAX_CA_VALIDITY_DAYS {
            return Err(AxiamError::Validation {
                message: format!(
                    "validity_days must be between 1 and {MAX_CA_VALIDITY_DAYS} \
                     (NIST SP 800-57 max for CA certificates)"
                ),
            });
        }

        let parent = self
            .load_signing_parent(input.organization_id, input.parent_ca_id)
            .await?;
        let (not_before, not_after) = intermediate_window(&parent, input.validity_days)?;

        let ca_id = Uuid::new_v4();
        // Two custodians, and they are not always the same one. The parent's is
        // where its key *is* — recorded per CA, so a deployment that adopted
        // Vault after generating a root still finds that root's key sealed into
        // its row. The default is where the deployment keeps keys *now*, and
        // that is where this new key belongs: an intermediate generated today
        // under a Vault-configured server goes to Vault, whatever the parent
        // predates.
        let parent_store = self.custodians.store_for(parent.key_custody)?;
        let child_store = self.custodians.default_store()?;

        // A custodian that signs on AXIAM's behalf also *creates* on AXIAM's
        // behalf: asking it to sign a key generated here would defeat the
        // property that makes it worth using.
        if parent_store.signs_remotely() {
            let parent_ref = Self::key_ref(&parent);
            let created = parent_store
                .generate_intermediate_ca(
                    &parent_ref,
                    &IntermediateCaRequest {
                        organization_id: input.organization_id,
                        ca_id,
                        subject: input.subject.clone(),
                        key_algorithm: input.key_algorithm,
                        validity_days: window_days(not_before, not_after),
                    },
                )
                .await?;

            // What the custodian produced, not what was asked for — Vault caps
            // a TTL to the mount's maximum and to the signer's own expiry
            // without failing the call.
            let parsed = parse_ca_certificate(&created.certificate_pem)?;
            let certificate = self
                .repo
                .create(StoreCaCertificate {
                    id: ca_id,
                    organization_id: input.organization_id,
                    tenant_id: Some(input.tenant_id),
                    parent_ca_id: Some(parent.id),
                    subject: parsed.subject,
                    public_cert_pem: created.certificate_pem,
                    chain_pem: (!created.chain_pem.is_empty())
                        .then(|| join_pem(&created.chain_pem)),
                    fingerprint: parsed.fingerprint,
                    key_algorithm: parsed.key_algorithm,
                    not_before: parsed.not_before,
                    not_after: parsed.not_after,
                    encrypted_private_key: None,
                    key_custody: parent_store.custody(),
                    key_locator: Some(created.locator),
                })
                .await?;
            return Ok(GeneratedCaCertificate {
                certificate,
                private_key_pem: None,
            });
        }

        let parent_ref = Self::key_ref(&parent);
        let mut parent_key_pem = parent_store
            .load(&parent_ref, parent.encrypted_private_key.as_deref())
            .await?
            .to_string();

        let _permit = self
            .crypto_semaphore
            .acquire()
            .await
            .map_err(|_| AxiamError::Internal("crypto semaphore closed".into()))?;

        let parent_cert_pem = parent.public_cert_pem.clone();
        let subject = input.subject.clone();
        let key_algorithm = input.key_algorithm.clone();
        let not_before_ts = not_before.timestamp();
        let not_after_ts = not_after.timestamp();
        let crl_points = self.crl_points_under(&parent);

        let (private_key_pem, public_cert_pem, fingerprint) =
            tokio::task::spawn_blocking(move || -> AxiamResult<(String, String, String)> {
                let parent_key = KeyPair::from_pem(&parent_key_pem).map_err(|e| {
                    AxiamError::Certificate(format!("invalid parent CA private key: {e}"))
                })?;
                // Scrubbed as soon as it is parsed, the same as the leaf path.
                parent_key_pem.zeroize();

                // The issuer DN comes from the parent's stored certificate, not
                // its mutable `subject` column, so what the child names as its
                // issuer can never drift from what the parent actually is.
                let issuer =
                    Issuer::from_ca_cert_pem(&parent_cert_pem, parent_key).map_err(|e| {
                        AxiamError::Certificate(format!("invalid parent CA certificate PEM: {e}"))
                    })?;

                let key_pair = generate_keypair(&key_algorithm)?;
                let private_key_pem = private_key_pem(&key_pair)?;

                let mut params = intermediate_params(&subject, not_before_ts, not_after_ts)?;
                params.use_authority_key_identifier_extension = true;
                params.crl_distribution_points = crl_points;

                let cert = params.signed_by(&key_pair, &issuer).map_err(|e| {
                    AxiamError::Certificate(format!("intermediate CA signing failed: {e}"))
                })?;
                let public_cert_pem = cert.pem();
                let fingerprint = compute_fingerprint(cert.der());
                Ok((private_key_pem, public_cert_pem, fingerprint))
            })
            .await
            .map_err(|e| AxiamError::Internal(format!("spawn_blocking join error: {e}")))??;

        // `import_ca` rather than `store`, because the certificate and the key
        // are both in hand and a custodian that is itself a PKI takes them
        // together: under `vault_pki` this imports the intermediate into Vault
        // as an issuer Vault can then sign leaves with, and under `vault` it
        // falls through to `store` and the key goes to Vault's KV engine. The
        // one custodian that keeps it here is `database`, and only because that
        // is what the deployment asked for.
        let stored = child_store
            .import_ca(
                input.organization_id,
                ca_id,
                &public_cert_pem,
                &private_key_pem,
            )
            .await?;
        let (encrypted_private_key, key_locator) = split_stored(stored);

        let certificate = self
            .repo
            .create(StoreCaCertificate {
                id: ca_id,
                organization_id: input.organization_id,
                tenant_id: Some(input.tenant_id),
                parent_ca_id: Some(parent.id),
                subject: input.subject,
                public_cert_pem,
                chain_pem: Some(chain_below(&parent)),
                fingerprint,
                key_algorithm: input.key_algorithm,
                not_before,
                not_after,
                encrypted_private_key,
                key_custody: child_store.custody(),
                key_locator,
            })
            .await?;

        Ok(GeneratedCaCertificate {
            certificate,
            private_key_pem: Some(private_key_pem),
        })
    }

    /// Sign a tenant's own certificate signing request as a signing CA.
    ///
    /// The BYOK counterpart to [`Self::generate_intermediate`]. The key behind
    /// the CSR was generated by whoever produced it and never reaches AXIAM, so
    /// there is nothing to return once and nothing to take custody of: the row
    /// records custody `External`, and issuance against this CA happens
    /// wherever the key actually lives.
    ///
    /// The CSR's subject is honoured; its requested extensions are not. A
    /// request that asked to be an unconstrained CA, or a TLS server, would
    /// otherwise decide its own powers — AXIAM decides them, and they are
    /// exactly "sign leaves".
    pub async fn sign_intermediate_csr(
        &self,
        input: SignIntermediateCsr,
    ) -> AxiamResult<CaCertificate> {
        if input.validity_days == 0 || input.validity_days > MAX_CA_VALIDITY_DAYS {
            return Err(AxiamError::Validation {
                message: format!(
                    "validity_days must be between 1 and {MAX_CA_VALIDITY_DAYS} \
                     (NIST SP 800-57 max for CA certificates)"
                ),
            });
        }

        let parent = self
            .load_signing_parent(input.organization_id, input.parent_ca_id)
            .await?;
        let (not_before, not_after) = intermediate_window(&parent, input.validity_days)?;

        // Parsed here rather than inside the signing task so that a malformed
        // CSR — by far the likeliest failure on this endpoint — is a 400 naming
        // the request, not a 500 out of a custodian.
        let csr_subject = csr_common_name(&input.csr_pem)?;

        let ca_id = Uuid::new_v4();
        let parent_store = self.custodians.store_for(parent.key_custody)?;

        if parent_store.signs_remotely() {
            let parent_ref = Self::key_ref(&parent);
            let signed = parent_store
                .sign_intermediate_csr(
                    &parent_ref,
                    &IntermediateSigningRequest {
                        csr_pem: input.csr_pem,
                        subject: csr_subject,
                        ttl_seconds: (not_after - not_before).num_seconds(),
                    },
                )
                .await?;

            let parsed = parse_ca_certificate(&signed.certificate_pem)?;
            return self
                .repo
                .create(StoreCaCertificate {
                    id: ca_id,
                    organization_id: input.organization_id,
                    tenant_id: Some(input.tenant_id),
                    parent_ca_id: Some(parent.id),
                    subject: parsed.subject,
                    public_cert_pem: signed.certificate_pem,
                    chain_pem: (!signed.chain_pem.is_empty()).then(|| join_pem(&signed.chain_pem)),
                    fingerprint: parsed.fingerprint,
                    key_algorithm: parsed.key_algorithm,
                    not_before: parsed.not_before,
                    not_after: parsed.not_after,
                    encrypted_private_key: None,
                    // AXIAM never held this key and never will. `External` is
                    // what stops the issuance path offering to sign with a key
                    // that is not here.
                    key_custody: CaKeyCustody::External,
                    key_locator: None,
                })
                .await;
        }

        let parent_ref = Self::key_ref(&parent);
        let mut parent_key_pem = parent_store
            .load(&parent_ref, parent.encrypted_private_key.as_deref())
            .await?
            .to_string();

        let _permit = self
            .crypto_semaphore
            .acquire()
            .await
            .map_err(|_| AxiamError::Internal("crypto semaphore closed".into()))?;

        let parent_cert_pem = parent.public_cert_pem.clone();
        let csr_pem = input.csr_pem.clone();
        let subject = csr_subject.clone();
        let not_before_ts = not_before.timestamp();
        let not_after_ts = not_after.timestamp();
        let crl_points = self.crl_points_under(&parent);

        let (public_cert_pem, fingerprint) =
            tokio::task::spawn_blocking(move || -> AxiamResult<(String, String)> {
                let parent_key = KeyPair::from_pem(&parent_key_pem).map_err(|e| {
                    AxiamError::Certificate(format!("invalid parent CA private key: {e}"))
                })?;
                parent_key_pem.zeroize();

                let issuer =
                    Issuer::from_ca_cert_pem(&parent_cert_pem, parent_key).map_err(|e| {
                        AxiamError::Certificate(format!("invalid parent CA certificate PEM: {e}"))
                    })?;

                // `from_pem` verifies the request's own signature, which is the
                // only proof that whoever sent it holds the matching private
                // key. Without that check a caller could have a CA minted for
                // somebody else's public key.
                let mut request =
                    CertificateSigningRequestParams::from_pem(&csr_pem).map_err(|e| {
                        AxiamError::Validation {
                            message: format!("the certificate signing request was rejected: {e}"),
                        }
                    })?;
                // Everything the request asked to be, overwritten by what AXIAM
                // has decided it is — the DN included, so the row and the
                // certificate cannot disagree.
                request.params = intermediate_params(&subject, not_before_ts, not_after_ts)?;
                request.params.use_authority_key_identifier_extension = true;
                request.params.crl_distribution_points = crl_points;

                let cert = request.signed_by(&issuer).map_err(|e| {
                    AxiamError::Certificate(format!("intermediate CA signing failed: {e}"))
                })?;
                let public_cert_pem = cert.pem();
                let fingerprint = compute_fingerprint(cert.der());
                Ok((public_cert_pem, fingerprint))
            })
            .await
            .map_err(|e| AxiamError::Internal(format!("spawn_blocking join error: {e}")))??;

        // Read back out of the certificate that was produced: the key algorithm
        // is the CSR's, not anything the caller stated, and the row must say
        // what the certificate says.
        let parsed = parse_ca_certificate(&public_cert_pem)?;

        self.repo
            .create(StoreCaCertificate {
                id: ca_id,
                organization_id: input.organization_id,
                tenant_id: Some(input.tenant_id),
                parent_ca_id: Some(parent.id),
                subject: parsed.subject,
                public_cert_pem,
                chain_pem: Some(chain_below(&parent)),
                fingerprint,
                key_algorithm: parsed.key_algorithm,
                not_before: parsed.not_before,
                not_after: parsed.not_after,
                encrypted_private_key: None,
                key_custody: CaKeyCustody::External,
                key_locator: None,
            })
            .await
    }

    /// Load the CA that is about to sign, refusing every state it cannot sign in.
    ///
    /// Each refusal exists because the alternative is a certificate that looks
    /// issued and is not trusted: an expired parent produces a chain no
    /// validator accepts, a revoked one produces a chain every validator
    /// rejects on purpose, and a parent AXIAM holds no key for produces a
    /// failure several layers down that names a decryption error rather than
    /// the missing key.
    async fn load_signing_parent(
        &self,
        organization_id: Uuid,
        parent_ca_id: Uuid,
    ) -> AxiamResult<CaCertificate> {
        let parent = self.repo.get_by_id(organization_id, parent_ca_id).await?;

        if parent.tenant_id.is_some() {
            return Err(AxiamError::Validation {
                message: "that CA is itself a tenant signing CA, which is constrained to a \
                          path length of zero and cannot sign another CA: choose an \
                          organization CA as the parent"
                    .into(),
            });
        }
        if parent.status != CertificateStatus::Active {
            return Err(AxiamError::Validation {
                message: "the parent CA is not active".into(),
            });
        }
        let now = Utc::now();
        if now < parent.not_before || now > parent.not_after {
            return Err(AxiamError::Validation {
                message: "the parent CA is expired or not yet valid".into(),
            });
        }
        if parent.key_custody == CaKeyCustody::External {
            return Err(AxiamError::Validation {
                message: "AXIAM holds no private key for that CA — it was imported as a trust \
                          anchor only, so it can be trusted but cannot sign"
                    .into(),
            });
        }
        Ok(parent)
    }

    /// The signing CAs belonging to one tenant.
    pub async fn list_by_tenant(
        &self,
        organization_id: Uuid,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<CaCertificate>> {
        self.repo
            .list_by_tenant(organization_id, tenant_id, pagination)
            .await
    }

    /// A [`CaKeyRef`] for one CA, for the signing path to load its key with.
    /// The distribution point a certificate `parent` signs carries — its
    /// list's URL — or none when the deployment publishes no base URL.
    fn crl_points_under(&self, parent: &CaCertificate) -> Vec<rcgen::CrlDistributionPoint> {
        self.crl_distribution
            .as_ref()
            .map(|d| d.point_for(parent))
            .into_iter()
            .collect()
    }

    pub fn key_ref(certificate: &CaCertificate) -> CaKeyRef {
        CaKeyRef {
            organization_id: certificate.organization_id,
            ca_id: certificate.id,
            custody: certificate.key_custody,
            locator: certificate.key_locator.clone().unwrap_or_default(),
        }
    }

    pub async fn get(&self, organization_id: Uuid, id: Uuid) -> AxiamResult<CaCertificate> {
        self.repo.get_by_id(organization_id, id).await
    }

    /// Move a CA's signing key to the deployment's currently configured
    /// custodian.
    ///
    /// # Why this exists
    ///
    /// Custody is recorded per CA, not read from configuration, and that is
    /// deliberate: a deployment that adopts Vault keeps issuing from the CAs it
    /// already has, whose keys are still sealed into their rows. The cost of
    /// that design is that adopting Vault changes nothing about the keys you
    /// already have — they stay in the database, forever, unless something
    /// moves them. This is that something.
    ///
    /// Without it the only route from database custody to Vault is to generate
    /// a new CA and re-issue every leaf certificate beneath it, which for a
    /// trust anchor means touching every relying party. That is a real
    /// migration for a real reason; it is not a reasonable price for changing
    /// where a key is filed.
    ///
    /// # Order of operations
    ///
    /// Copy first, record second, delete last:
    ///
    /// 1. Load the key from the custodian the **row** names.
    /// 2. Hand it to the configured custodian.
    /// 3. Update the row — new custody, new locator, and the row's own
    ///    ciphertext cleared in the same statement.
    /// 4. Best-effort release from the old custodian.
    ///
    /// A failure at step 1 or 2 leaves the CA exactly as it was: the row still
    /// names the old custodian, which still holds the key, and issuance is
    /// unaffected. A failure at step 4 leaves an orphaned secret behind — a
    /// cleanup task, not a security failure, and the same trade-off revocation
    /// already makes. What must never happen is the reverse order, which would
    /// delete a key the new custodian had not accepted.
    ///
    /// # Errors
    ///
    /// - No custodian configured, or the CA is already under the configured one.
    /// - The CA is under `external` custody: AXIAM holds no key to move.
    /// - The CA is under a custodian that will not hand its key over
    ///   (`vault_pki`). That is the stronger property, not a limitation to work
    ///   around, and moving *out* of it would weaken the CA.
    pub async fn migrate_key_custody(
        &self,
        organization_id: Uuid,
        id: Uuid,
    ) -> AxiamResult<CaCertificate> {
        let certificate = self.repo.get_by_id(organization_id, id).await?;
        let target = self.custodians.default_store()?;

        if certificate.key_custody == target.custody() {
            return Err(AxiamError::Validation {
                message: format!(
                    "this CA's key is already held by the `{}` custodian",
                    target.custody()
                ),
            });
        }
        if certificate.key_custody == CaKeyCustody::External {
            return Err(AxiamError::Validation {
                message: "AXIAM holds no private key for this CA, so there is nothing to \
                          move. It was imported as a trust anchor only."
                    .into(),
            });
        }

        let source = self.custodians.store_for(certificate.key_custody)?;
        if source.signs_remotely() {
            return Err(AxiamError::Validation {
                message: format!(
                    "this CA's key is held by the `{}` custodian, which never hands it \
                     over — that is a stronger property than the target offers, and \
                     moving out of it would weaken the CA",
                    certificate.key_custody
                ),
            });
        }

        let key_ref = Self::key_ref(&certificate);
        let private_key_pem = source
            .load(&key_ref, certificate.encrypted_private_key.as_deref())
            .await?;

        // `import_ca` rather than `store`: a custodian that is a PKI rather
        // than a safe needs the certificate alongside the key, and every other
        // custodian's default body ignores it and calls `store`.
        let stored = target
            .import_ca(
                organization_id,
                id,
                &certificate.public_cert_pem,
                &private_key_pem,
            )
            .await?;
        // Both halves, not just the locator: an inlining custodian (database)
        // hands back ciphertext and no locator, and the row's column is the
        // only place it has to live. Discarding it here wrote `custody =
        // database` beside an empty key column and then released the source
        // copy, which destroyed the signing key.
        let (ciphertext, locator) = split_stored(stored);

        let updated = self
            .repo
            .update_key_custody(organization_id, id, target.custody(), locator, ciphertext)
            .await?;

        if let Err(e) = source.delete(&key_ref).await {
            tracing::warn!(
                error = %e,
                %organization_id,
                ca_id = %id,
                from = %certificate.key_custody,
                "could not release the CA key from its previous custodian after \
                 migration; the key has moved and this leaves an orphaned copy to \
                 clean up"
            );
        }

        tracing::info!(
            %organization_id,
            ca_id = %id,
            from = %certificate.key_custody,
            to = %updated.key_custody,
            "CA signing key custody migrated"
        );
        Ok(updated)
    }

    /// Revoke a CA: the row first, then its key at its custodian, then — for a
    /// subordinate CA its parent signed through Vault's PKI engine — the CA's
    /// serial on the parent's list in Vault (#612).
    ///
    /// AXIAM's revocation stands whatever the custodians answer: the row is
    /// what AXIAM signs with and what its own list for the parent reads (#565).
    /// The forward is the leaf path's (T-470): within
    /// [`CUSTODIAN_REVOKE_ATTEMPTS`] attempts and [`CUSTODIAN_REVOKE_BUDGET`],
    /// and a refusal or an unreachable Vault is answered as
    /// [`CustodianRevocation::Pending`], for the caller to record, and retried by
    /// the cleanup job's `vault_revocation` sweep from the row — which keeps the
    /// certificate and `parent_ca_id`, everything the retry needs, after the
    /// key is gone.
    ///
    /// The forward comes **after** the key is released, not before. Vault
    /// refuses `revoke` for a serial that is still an issuer in the same mount
    /// ("adding issuer to its own CRL is not allowed"), and a parent whose
    /// locator records no root (imported, or created with `issue_from_root`
    /// and imported into the issuing mount) signs its subordinates from the
    /// very mount that holds their issuers. Once the subordinate's issuer is
    /// deleted, its serial is a stored certificate like a leaf's, and the
    /// parent's mount accepts it; where the mounts differ (the usual two-tier
    /// organization CA) the order changes nothing.
    ///
    /// A release that failed here (logged and swallowed) or never ran (the
    /// process died after the revocation) leaves that issuer in the parent's
    /// mount, and Vault then refuses every forward. The sweep recognises the
    /// refusal and runs the release again before it forwards
    /// ([`forward_ca_revocation_releasing`], R101W1-04).
    pub async fn revoke(
        &self,
        organization_id: Uuid,
        id: Uuid,
    ) -> AxiamResult<CustodianRevocation> {
        self.revoke_within(organization_id, id, CUSTODIAN_REVOKE_ATTEMPTS, None)
            .await
    }

    /// [`Self::revoke`], forwarding within `attempts` and before `deadline` —
    /// `None` for [`CUSTODIAN_REVOKE_BUDGET`] from the moment the key is
    /// released, so a slow release does not eat the forward's budget.
    async fn revoke_within(
        &self,
        organization_id: Uuid,
        id: Uuid,
        attempts: u32,
        deadline: Option<tokio::time::Instant>,
    ) -> AxiamResult<CustodianRevocation> {
        let certificate = self.repo.get_by_id(organization_id, id).await?;
        self.repo.revoke(organization_id, id).await?;

        // Release custody after the revocation, and never before: the row is
        // the record of what exists, and a custodian that could not be reached
        // must not leave a CA marked active whose key is gone. What a failure
        // here leaves behind is an orphaned secret — a cleanup task, not a
        // security failure, because AXIAM will not sign with a revoked CA
        // whatever the custodian still holds.
        if let Ok(store) = self.custodians.store_for(certificate.key_custody) {
            let key_ref = Self::key_ref(&certificate);
            if let Err(e) = store.delete(&key_ref).await {
                tracing::warn!(
                    ca_id = %id,
                    custody = %certificate.key_custody,
                    error = %e,
                    "CA revoked, but its key could not be removed from the custodian"
                );
            }
        }

        // The row as read before the revocation: neither the revocation nor
        // the release changes what the forward reads (the certificate, the
        // custody, the parent).
        let deadline =
            deadline.unwrap_or_else(|| tokio::time::Instant::now() + CUSTODIAN_REVOKE_BUDGET);
        Ok(forward_ca_revocation(
            &self.repo,
            &self.custodians,
            &certificate,
            attempts,
            deadline,
        )
        .await)
    }

    /// Revoke every active signing CA of a tenant that is being deleted, each
    /// through [`Self::revoke`] — so its custodian releases the key — and
    /// return how many (R1W1-01).
    ///
    /// A deleted tenant's CA is disowned with it: it goes on its parent's
    /// revocation list, so every leaf it signed stops chaining for relying
    /// parties outside AXIAM, instead of staying valid until it expires. Its row
    /// outlives the tenant until it expires (`tenant_purge` keeps a revoked,
    /// unexpired CA, without its key), so the parent's list keeps naming it.
    ///
    /// Each subordinate CA's forward to its parent's list in Vault (#612) takes
    /// one attempt, inside one [`CUSTODIAN_REVOKE_BUDGET`] for all of them, as
    /// the tenant's leaves do (`CertService::revoke_tenant`); one Vault did not
    /// take is counted in [`TenantCasRevoked::vault_pending`] and retried by
    /// the cleanup job's sweep.
    pub async fn revoke_tenant_cas(
        &self,
        organization_id: Uuid,
        tenant_id: Uuid,
    ) -> AxiamResult<TenantCasRevoked> {
        const PAGE: u64 = 100;
        let mut active = Vec::new();
        let mut offset = 0;
        loop {
            let page = self
                .repo
                .list_by_tenant(
                    organization_id,
                    tenant_id,
                    Pagination {
                        offset,
                        limit: PAGE,
                        search: None,
                    },
                )
                .await?;
            let read = page.items.len() as u64;
            active.extend(
                page.items
                    .into_iter()
                    .filter(|ca| ca.status == CertificateStatus::Active)
                    .map(|ca| ca.id),
            );
            offset += read;
            if read < PAGE || offset >= page.total {
                break;
            }
        }
        let deadline = tokio::time::Instant::now() + CUSTODIAN_REVOKE_BUDGET;
        let mut vault_pending = 0usize;
        for id in &active {
            if let CustodianRevocation::Pending { .. } = self
                .revoke_within(organization_id, *id, 1, Some(deadline))
                .await?
            {
                vault_pending += 1;
            }
        }
        Ok(TenantCasRevoked {
            revoked: active.len(),
            vault_pending,
        })
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

/// What [`CaService::revoke_tenant_cas`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TenantCasRevoked {
    /// Signing CAs this revoked.
    pub revoked: usize,
    /// Of those, CAs whose revocation the parent's list in Vault does not have
    /// yet (#612); the cleanup job's sweep forwards them.
    pub vault_pending: usize,
}

/// Tell Vault that `revoked`, a revoked subordinate CA, is revoked — on the
/// list of the parent that signed it, when that parent's key Vault's PKI engine
/// holds (#612). Never fails: the outcome is the answer.
///
/// [`CustodianRevocation::NotNeeded`] for a CA with no parent, a parent that is
/// gone, not `vault_pki` (its list is AXIAM's, which reads the row) or itself
/// revoked (revoking it deleted its issuers from Vault, so there is no list
/// there left to name the child), and for a CA Vault never signed: one in
/// `database` or `vault` custody under a `vault_pki` parent was signed in
/// AXIAM before the parent's key moved into Vault. On success the row records
/// `vault_revoked_at` (schema v96).
///
/// Shared by [`CaService::revoke`] and the cleanup job's sweep
/// (`CertService::forward_pending_revocations`), which reads only the row: the
/// certificate (its serial) and `parent_ca_id`, both kept by a revoked CA's row
/// after its key is released and until eight days after it expires
/// (`tenant_purge`), past the sweep's own window (`not_after`).
pub(crate) async fn forward_ca_revocation<R: CaCertificateRepository>(
    repo: &R,
    custodians: &CaKeyCustodians,
    revoked: &CaCertificate,
    attempts: u32,
    deadline: tokio::time::Instant,
) -> CustodianRevocation {
    let pending = |reason: String| {
        tracing::error!(
            ca_id = %revoked.id,
            organization_id = %revoked.organization_id,
            parent_ca_id = ?revoked.parent_ca_id,
            reason = %crate::vault_forward::sanitise_reason(&reason),
            "CA revoked in AXIAM but not yet on its parent's revocation list in Vault, which \
             therefore does not name it; the cleanup job retries"
        );
        CustodianRevocation::Pending { reason }
    };

    let Some(parent_id) = revoked.parent_ca_id else {
        return CustodianRevocation::NotNeeded;
    };
    if !matches!(
        revoked.key_custody,
        CaKeyCustody::VaultPki | CaKeyCustody::External
    ) {
        return CustodianRevocation::NotNeeded;
    }
    let parent = match repo.get_by_issuer_id(parent_id).await {
        Ok(parent) => parent,
        Err(AxiamError::NotFound { .. }) => return CustodianRevocation::NotNeeded,
        Err(e) => return pending(format!("the parent CA could not be read: {e}")),
    };
    if parent.key_custody != CaKeyCustody::VaultPki || parent.status != CertificateStatus::Active {
        return CustodianRevocation::NotNeeded;
    }
    let store = match custodians.store_for(parent.key_custody) {
        Ok(store) if store.signs_remotely() => store,
        Ok(_) => return CustodianRevocation::NotNeeded,
        Err(e) => return pending(e.to_string()),
    };
    let serial = match serial_hex(&revoked.public_cert_pem) {
        Ok(serial) => serial,
        Err(e) => return pending(e.to_string()),
    };

    let parent_ref = CaService::<R>::key_ref(&parent);
    if let Err(reason) = attempt_custodian(attempts, deadline, || {
        store.revoke_signed_ca(&parent_ref, &serial)
    })
    .await
    {
        return pending(reason);
    }
    if let Err(e) = repo
        .mark_revocation_forwarded(revoked.organization_id, revoked.id)
        .await
    {
        // Vault has it; the next sweep forwards it again, which Vault answers
        // with success.
        tracing::warn!(
            ca_id = %revoked.id,
            error = %e,
            "Vault accepted the CA's revocation, but recording that failed"
        );
    }
    CustodianRevocation::Forwarded
}

/// The refusal Vault's PKI engine answers `revoke` with for a serial that is
/// still an issuer of the mount it is revoked in: "adding issuer (id: …) to its
/// own CRL is not allowed" (issuers are revoked through `issuer/<ref>/revoke`).
/// Matched case-insensitively and without the issuer's id, which is the part
/// that varies.
const ISSUER_ON_ITS_OWN_CRL: &str = "to its own crl is not allowed";

/// Whether `reason`, the text of a failed forward, is Vault saying the revoked
/// CA is still an issuer in the mount it is being revoked in (R101W1-04).
///
/// That is the single-mount layout — a parent that signs from the mount that
/// also holds its subordinates' issuers — and it means the release
/// [`CaService::revoke`] makes after the revocation did not happen: the delete
/// failed (logged and swallowed there) or the process died between the two.
pub(crate) fn is_issuer_on_its_own_crl_refusal(reason: &str) -> bool {
    reason.to_ascii_lowercase().contains(ISSUER_ON_ITS_OWN_CRL)
}

/// Run the custodian's release of a revoked subordinate CA again — the
/// issuer(s) and key its own locator names, and nothing else — and say whether
/// the custodian accepted it (R101W1-04).
///
/// For the sweep, when Vault refused a forward because the CA is still an issuer
/// in the parent's mount ([`is_issuer_on_its_own_crl_refusal`]). Idempotent: the
/// Vault store treats an issuer or key that is already gone as released, so a
/// release that had in fact succeeded costs two `404`s and no error. Never
/// releases a CA that is not revoked, nor one whose key is not in Vault's PKI
/// engine (an `external` CA's key is not Vault's to delete), and gives up at
/// `deadline`. A failure is logged and answered `false`; the forward then
/// stays pending as it was.
pub(crate) async fn release_revoked_ca<R: CaCertificateRepository>(
    custodians: &CaKeyCustodians,
    revoked: &CaCertificate,
    deadline: tokio::time::Instant,
) -> bool {
    if revoked.status != CertificateStatus::Revoked || revoked.key_custody != CaKeyCustody::VaultPki
    {
        return false;
    }
    let store = match custodians.store_for(revoked.key_custody) {
        Ok(store) => store,
        Err(e) => {
            tracing::warn!(ca_id = %revoked.id, error = %e, "the revoked CA's key custodian is not available");
            return false;
        }
    };
    let key_ref = CaService::<R>::key_ref(revoked);
    match tokio::time::timeout_at(deadline, store.delete(&key_ref)).await {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            tracing::warn!(
                ca_id = %revoked.id,
                error = %e,
                "a revoked CA's issuer could not be removed from Vault again"
            );
            false
        }
        Err(_) => {
            tracing::warn!(ca_id = %revoked.id, "Vault did not answer the removal of a revoked CA's issuer in time");
            false
        }
    }
}

/// [`forward_ca_revocation`] for the cleanup job's sweep, which also finishes
/// the release a revocation left undone (R101W1-04).
///
/// Where the parent signs from the mount that holds its subordinates' issuers,
/// Vault refuses to revoke a serial that is still an issuer there, so a CA whose
/// release failed is refused at every forward. `last_error` is the sanitised
/// reason the row recorded at its previous failed attempt. When it names that
/// refusal the release is run again before the forward; when it does not (the
/// request that revoked the CA records nothing on the row, and the reason is cut
/// to 256 characters), a forward that is refused that way is followed by the
/// release and one more forward, inside the same claim and `deadline`. Once
/// per attempt either way: the row's claim, backoff and failure count are the
/// caller's and unchanged.
pub(crate) async fn forward_ca_revocation_releasing<R: CaCertificateRepository>(
    repo: &R,
    custodians: &CaKeyCustodians,
    revoked: &CaCertificate,
    last_error: Option<&str>,
    attempts: u32,
    deadline: tokio::time::Instant,
) -> CustodianRevocation {
    let refused_before = last_error.is_some_and(is_issuer_on_its_own_crl_refusal);
    if refused_before {
        release_revoked_ca::<R>(custodians, revoked, deadline).await;
    }
    let outcome = forward_ca_revocation(repo, custodians, revoked, attempts, deadline).await;
    if !refused_before
        && matches!(&outcome, CustodianRevocation::Pending { reason } if is_issuer_on_its_own_crl_refusal(reason))
        && release_revoked_ca::<R>(custodians, revoked, deadline).await
    {
        return forward_ca_revocation(repo, custodians, revoked, attempts, deadline).await;
    }
    outcome
}

// ---------------------------------------------------------------------------
// Import helpers
// ---------------------------------------------------------------------------

/// Split a [`StoredCaKey`] into the two columns the CA row has for it.
///
/// The database custodian hands back material to persist; every other one hands
/// back a path and keeps the material. Exactly one of the pair is ever `Some`.
fn split_stored(stored: StoredCaKey) -> (Option<Vec<u8>>, Option<String>) {
    match stored {
        StoredCaKey::Inline(ciphertext) => (Some(ciphertext), None),
        StoredCaKey::Referenced(locator) => (None, Some(locator)),
    }
}

/// Concatenate PEM blocks into the single string a record holds.
///
/// Each block already ends in a newline from every producer AXIAM sees, but
/// trimming and rejoining is what makes that true rather than assumed: two
/// certificates run together on one line parse as neither.
pub(crate) fn join_pem(blocks: &[String]) -> String {
    blocks
        .iter()
        .map(|b| b.trim_end())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// The certificate a tenant signing CA gets, whoever generated its key.
///
/// One place, so the generate path and the sign-a-CSR path cannot produce two
/// differently-powered CAs from the same endpoint pair. Path length zero and
/// `keyCertSign`/`cRLSign` and nothing else: it signs leaves and revokes them,
/// and cannot mint a further tier. RFC 5280 §4.2.1.3 wants Key Usage marked
/// critical on a CA, which rcgen does whenever the list is non-empty — leaving
/// it empty omits the extension entirely and produces a CA whose powers are
/// unstated.
fn intermediate_params(
    subject: &str,
    not_before_ts: i64,
    not_after_ts: i64,
) -> AxiamResult<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| AxiamError::Certificate(e.to_string()))?;
    params.distinguished_name.push(DnType::CommonName, subject);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    // #653: rcgen's default is a hash of the public key, so two intermediates on
    // one key would share a serial.
    params.serial_number = Some(crate::serial::random_serial());
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = time::OffsetDateTime::from_unix_timestamp(not_before_ts)
        .map_err(|e| AxiamError::Certificate(format!("invalid notBefore: {e}")))?;
    params.not_after = time::OffsetDateTime::from_unix_timestamp(not_after_ts)
        .map_err(|e| AxiamError::Certificate(format!("invalid notAfter: {e}")))?;
    Ok(params)
}

/// The chain a certificate signed by `parent` needs: the parent, then whatever
/// the parent itself chains to.
fn chain_below(parent: &CaCertificate) -> String {
    let mut blocks = vec![parent.public_cert_pem.clone()];
    if let Some(ref above) = parent.chain_pem {
        blocks.push(above.clone());
    }
    join_pem(&blocks)
}

/// The validity window for a certificate signed by `parent`.
///
/// Capped to the parent's own expiry, because a certificate that outlives its
/// issuer is one every validator rejects for the whole of its extra life —
/// silently, and long after anybody remembers asking for it.
fn intermediate_window(
    parent: &CaCertificate,
    validity_days: u32,
) -> AxiamResult<(DateTime<Utc>, DateTime<Utc>)> {
    let not_before = Utc::now();
    let requested = not_before
        .checked_add_signed(Duration::days(i64::from(validity_days)))
        .ok_or_else(|| AxiamError::Validation {
            message: "validity_days produces a date out of range".into(),
        })?;
    // Same rule, and the same reasoning, as the leaf path in `cert.rs`: an
    // intermediate that outlives its parent stops validating the day the parent
    // expires, so the surplus is time the operator thinks they have and does
    // not. This used to silently truncate to the parent's notAfter; refusing and
    // naming the achievable number is what lets them pick a real one.
    if requested > parent.not_after {
        let available = crate::cert::issuer_bounded_validity_days(not_before, parent.not_after);
        return Err(AxiamError::Validation {
            message: format!(
                "validity_days is {validity_days} but the parent CA expires on {} — an \
                 intermediate cannot outlive the CA that signs it. The most this parent can \
                 grant today is {available} day{}.",
                parent.not_after.format("%Y-%m-%d"),
                if available == 1 { "" } else { "s" },
            ),
        });
    }
    Ok((not_before, requested))
}

/// A window expressed back in whole days, for a custodian whose API takes a TTL.
///
/// Rounded up, and floored at one: a window shorter than a day would otherwise
/// become a TTL of zero, which Vault reads as "the mount's default" rather than
/// "no time at all".
fn window_days(not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> u32 {
    let hours = (not_after - not_before).num_hours().max(1);
    u32::try_from((hours + 23) / 24).unwrap_or(u32::MAX).max(1)
}

/// What a certificate signing request says about itself, once its signature has
/// been checked.
///
/// Everything here comes from a **single** parse and a **single** signature
/// verification. Reading the common name in one function, the key in another
/// and the requested extensions in a third would verify possession up to three
/// times on the way to three different answers, and would let a future caller
/// reach one of the facts without having verified anything at all.
#[derive(Debug)]
pub(crate) struct CsrFacts {
    /// The common name the request asks for. Non-empty: a subject is what
    /// distinguishes one certificate from another in every list that shows
    /// them.
    pub(crate) common_name: String,
    /// The key algorithm, read from the request's own public key rather than
    /// taken from the caller.
    pub(crate) key_algorithm: KeyAlgorithm,
    /// The RSA modulus size in bits, or `None` for a key that is not RSA.
    ///
    /// Separate from `key_algorithm` because [`KeyAlgorithm`] has no way to say
    /// "RSA, 2048" — the variant is named `Rsa4096` — and a caller enforcing a
    /// modulus floor must see the real number rather than the label.
    pub(crate) rsa_modulus_bits: Option<usize>,
    /// The names of the requested extensions AXIAM refuses to sign over, in
    /// the order they appear. Empty when the request asks for none of them.
    ///
    /// Exactly `subjectAltName`, `keyUsage` and `extendedKeyUsage` — the three
    /// a leaf caller can put in a CSR that would otherwise reach the
    /// certificate, and the three that must be refused rather than dropped.
    ///
    /// Refused, and not silently stripped, for two reasons. A caller who put
    /// SANs in a leaf CSR meant them, and a certificate issued without them
    /// and with nothing said is a credential that fails where it is deployed.
    /// And a caller who put a key usage in one **would get it** under
    /// `vault_pki` custody: Vault's `sign-verbatim` discards the `key_usage`
    /// and `ext_key_usage` request parameters when the CSR carries those
    /// extensions and issues what the CSR asked for. Dropping them would
    /// therefore be a promise AXIAM can keep on one custodian and not the
    /// other, which is worse than a rule that holds everywhere.
    ///
    /// `basicConstraints` is deliberately **not** here: the DB path overwrites
    /// the whole parameter set before signing, and Vault ignores a CSR's basic
    /// constraints outright (warning that it did). A CSR asking to be a CA is
    /// signed as a leaf on both, which is the test
    /// `a_csr_that_asked_to_be_a_ca_does_not_get_to_be_one` asserts.
    pub(crate) refused_extensions: Vec<&'static str>,
}

/// Read a CSR, refusing anything that does not prove possession of its own key.
///
/// Called outside the signing task so a malformed request — by far the likeliest
/// failure on an endpoint whose input is pasted by hand — is a `400` naming the
/// CSR rather than a `500` out of a custodian.
pub(crate) fn inspect_csr(pem: &str) -> AxiamResult<CsrFacts> {
    let block = pem::parse(pem).map_err(|e| AxiamError::Validation {
        message: format!("the certificate signing request is not PEM-encoded: {e}"),
    })?;
    let (_, csr) =
        x509_parser::certification_request::X509CertificationRequest::from_der(block.contents())
            .map_err(|e| AxiamError::Validation {
                message: format!("the certificate signing request could not be parsed: {e}"),
            })?;
    // The whole point of the endpoint: this is the only evidence that whoever
    // sent the request holds the matching private key. Without it a caller
    // could have a certificate minted for somebody else's public key.
    csr.verify_signature().map_err(|_| AxiamError::Validation {
        message: "the certificate signing request's signature does not verify against the \
                  public key it carries, so nothing proves the sender holds the matching \
                  private key"
            .into(),
    })?;

    let subject = &csr.certification_request_info.subject;
    // R110W1-02 — the name is single-valued. A `vault_pki` CA sends this very
    // CSR to `sign-verbatim`, which copies the whole subject, and a relying
    // party that reads the *last* common name (Go's `crypto/x509` overwrites
    // `Subject.CommonName` with each in turn) would authenticate the holder
    // under a name the row, which records the first, does not show.
    if subject.iter_common_name().nth(1).is_some() {
        return Err(AxiamError::Validation {
            message: "the certificate signing request's subject has more than one common name"
                .into(),
        });
    }
    let common_name = subject
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_string)
        .filter(|cn| !cn.trim().is_empty())
        .ok_or_else(|| AxiamError::Validation {
            message: "the certificate signing request has no common name in its subject".into(),
        })?;
    // #649 — the other way a name reaches a certificate. The name is the CSR's
    // and is not rewritten (a remote signer signs these very bytes), so it is
    // refused, not repaired, by the rules a request's `subject` meets.
    crate::subject::check_common_name_value(
        &common_name,
        "the certificate signing request's common name",
    )?;
    // R110W1-02 — and so is every other attribute of the subject. The local
    // signing paths keep nothing of the subject but the common name (the DN is
    // rebuilt from it), so an `O=`/`OU=` is dropped there; but `sign-verbatim`
    // writes them into the certificate as given, so a newline or a bidi
    // override in an `OU` would reach an issued subject exactly as #649 closed
    // for the CN. Refused on every custodian, so the same CSR is not accepted
    // on one and refused on another, by the same value rules and not by a
    // narrower list: an ordinary `openssl req -subj /C=…/O=…/CN=…` request,
    // which is signed today, keeps being signed. A value that is not a string
    // type cannot be checked and is refused (fail closed).
    for attr in subject.iter().flat_map(|rdn| rdn.iter()) {
        if attr.attr_type() == &x509_parser::oid_registry::OID_X509_COMMON_NAME {
            continue;
        }
        let what = format!(
            "the certificate signing request's subject attribute {}",
            attr.attr_type().to_id_string()
        );
        let value = attr.as_str().map_err(|_| AxiamError::Validation {
            message: format!("{what} is not a text string"),
        })?;
        crate::subject::check_common_name_value(value, &what)?;
    }

    let spki = &csr.certification_request_info.subject_pki;
    let (key_algorithm, rsa_modulus_bits) = match spki.algorithm.algorithm.to_id_string().as_str() {
        // RFC 8410 §3 — id-Ed25519.
        "1.3.101.112" => (KeyAlgorithm::Ed25519, None),
        // RFC 8017 — rsaEncryption. The modulus is read here and checked by the
        // caller: `KeyAlgorithm::Rsa4096` is a label and not a measurement, and
        // `parse_ca_certificate` above maps *any* RSA OID onto it deliberately
        // (an imported root of another size is still a usable root). A path
        // that enforces a floor cannot reuse that mapping.
        "1.2.840.113549.1.1.1" => {
            let bits = match spki.parsed() {
                Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => rsa.key_size(),
                // A key whose OID says RSA but whose bytes will not parse as an
                // RSA key reports zero, which fails every floor. Fail closed:
                // the alternative is treating "unreadable" as "large enough".
                _ => 0,
            };
            (KeyAlgorithm::Rsa4096, Some(bits))
        }
        other => {
            return Err(AxiamError::Validation {
                message: format!(
                    "the certificate signing request carries a {other} public key; AXIAM signs \
                     Ed25519 and RSA keys only"
                ),
            });
        }
    };

    let mut refused_extensions = Vec::new();
    if let Some(exts) = csr.requested_extensions() {
        use x509_parser::extensions::ParsedExtension;
        for ext in exts {
            match ext {
                ParsedExtension::SubjectAlternativeName(_) => {
                    refused_extensions.push("subjectAltName")
                }
                ParsedExtension::KeyUsage(_) => refused_extensions.push("keyUsage"),
                ParsedExtension::ExtendedKeyUsage(_) => refused_extensions.push("extendedKeyUsage"),
                _ => {}
            }
        }
        refused_extensions.dedup();
    }

    Ok(CsrFacts {
        common_name,
        key_algorithm,
        rsa_modulus_bits,
        refused_extensions,
    })
}

/// The common name a CSR asks for, with its signature verified.
///
/// A thin reading of [`inspect_csr`], kept because the intermediate path wants
/// only this one fact. The verification is the shared part, and sharing it is
/// the point: two possession checks are two places for one to be forgotten.
fn csr_common_name(pem: &str) -> AxiamResult<String> {
    Ok(inspect_csr(pem)?.common_name)
}

/// What an imported certificate actually says about itself.
#[derive(Debug)]
struct ParsedCa {
    subject: String,
    fingerprint: String,
    key_algorithm: KeyAlgorithm,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

/// Read an imported CA certificate, refusing anything AXIAM cannot use as one.
///
/// Three checks, and each exists because skipping it produces a CA that fails
/// later in a way that names nothing:
///
/// 1. It parses as X.509 at all.
/// 2. Its Basic Constraints say `CA:TRUE`. A leaf certificate imported as a CA
///    would be offered in the issuing-CA dropdown and rejected by every relying
///    party that checked the chain.
/// 3. Its public key is one AXIAM can issue against. `KeyAlgorithm` has two
///    variants, and a P-256 CA stored as "Ed25519" would mislead every reader
///    of the row.
fn parse_ca_certificate(pem: &str) -> AxiamResult<ParsedCa> {
    let (_, der) =
        x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|e| AxiamError::Validation {
            message: format!(
                "the supplied CA certificate is not a PEM-encoded X.509 certificate: {e}"
            ),
        })?;
    let (_, cert) =
        X509Certificate::from_der(&der.contents).map_err(|e| AxiamError::Validation {
            message: format!("the supplied CA certificate could not be parsed: {e}"),
        })?;

    let is_ca = cert
        .basic_constraints()
        .ok()
        .flatten()
        .map(|bc| bc.value.ca)
        .unwrap_or(false);
    if !is_ca {
        return Err(AxiamError::Validation {
            message: "the supplied certificate is not a CA: its Basic Constraints extension does \
             not say CA:TRUE, so nothing that validates a chain would accept a \
             certificate it signed"
                .into(),
        });
    }

    let key_algorithm = match cert
        .public_key()
        .algorithm
        .algorithm
        .to_id_string()
        .as_str()
    {
        // RFC 8410 §3 — id-Ed25519.
        "1.3.101.112" => KeyAlgorithm::Ed25519,
        // RFC 8017 — rsaEncryption. Import is the only way an RSA CA reaches
        // AXIAM: rcgen's `ring` backend cannot *generate* RSA keys (see
        // `crypto::generate_keypair`), so `POST .../ca-certificates` with
        // `Rsa4096` fails, while an RSA root from an existing PKI is exactly
        // the thing this endpoint is for.
        //
        // The variant is named for the size AXIAM would generate; an imported
        // RSA CA of another size is still RSA and still usable, and refusing it
        // would reject a perfectly good existing root over a label.
        "1.2.840.113549.1.1.1" => KeyAlgorithm::Rsa4096,
        other => {
            return Err(AxiamError::Validation {
                message: format!(
                    "the supplied CA uses public key algorithm {other}, which AXIAM cannot \
                 issue against — only Ed25519 and RSA are supported"
                ),
            });
        }
    };

    let subject = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_string)
        // A CA with no CN is unusual but legal; the full DN is a truthful
        // stand-in and better than refusing the import over a display string.
        .unwrap_or_else(|| cert.subject().to_string());

    let to_utc = |t: ASN1Time, what: &str| -> AxiamResult<DateTime<Utc>> {
        DateTime::from_timestamp(t.timestamp(), 0).ok_or_else(|| AxiamError::Validation {
            message: format!("the supplied CA's {what} is out of range"),
        })
    };
    let not_before = to_utc(cert.validity().not_before, "notBefore")?;
    let not_after = to_utc(cert.validity().not_after, "notAfter")?;
    if not_after <= not_before {
        return Err(AxiamError::Validation {
            message: "the supplied CA's validity window ends before it starts".into(),
        });
    }
    if not_after <= Utc::now() {
        return Err(AxiamError::Validation {
            message: "the supplied CA has already expired: it could be imported but could never \
             issue a certificate, since leaf validity is capped to the CA's"
                .into(),
        });
    }

    Ok(ParsedCa {
        subject,
        fingerprint: compute_fingerprint(&der.contents),
        key_algorithm,
        not_before,
        not_after,
    })
}

/// Prove the supplied private key is the one this certificate was issued with.
///
/// By comparing SubjectPublicKeyInfo: the DER rcgen derives from the private
/// key against the DER the certificate carries. A private key determines its
/// public key, so equal SPKI is exactly the question being asked.
///
/// Note what this deliberately does *not* rely on:
/// `rcgen::Issuer::from_ca_cert_pem` accepts a key and a certificate that have
/// nothing to do with each other — it parses the certificate and pairs it with
/// whatever key it was handed, deferring the mismatch to a signature that no
/// relying party will verify. Using it as the check here would have looked
/// right and passed everything.
///
/// Without this, a mismatched pair produces a CA that lists as issuable and
/// dies at the first signature, with an error about key parsing that names
/// nothing the operator did.
fn verify_key_matches_certificate(key_pem: &str, cert_pem: &str) -> AxiamResult<()> {
    let key_pair = rcgen::KeyPair::from_pem(key_pem).map_err(|e| AxiamError::Validation {
        message: format!("the supplied private key is not a PEM-encoded key AXIAM can read: {e}"),
    })?;

    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).map_err(|e| {
        AxiamError::Validation {
            message: format!(
                "the supplied CA certificate is not a PEM-encoded X.509 certificate: {e}"
            ),
        }
    })?;
    let (_, cert) =
        X509Certificate::from_der(&pem.contents).map_err(|e| AxiamError::Validation {
            message: format!("the supplied CA certificate could not be parsed: {e}"),
        })?;

    // rcgen exposes the SPKI as PEM; `x509_parser` gives the certificate's as
    // DER. Decode the former rather than re-encoding the latter, so the
    // comparison is over the bytes a parser produced on both sides.
    let key_spki = pem::parse(key_pair.public_key_pem()).map_err(|e| {
        AxiamError::Internal(format!(
            "could not re-encode the supplied key's public half: {e}"
        ))
    })?;

    if key_spki.contents() != cert.public_key().raw {
        return Err(AxiamError::Validation {
            message: "the supplied private key does not match the supplied CA certificate".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod import_tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, IsCa, KeyPair};

    /// Build a self-signed CA the way an external PKI would hand one over.
    fn self_signed_ca(cn: &str, days: i64) -> (String, String) {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, cn);
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days);
        let cert = params.self_signed(&key_pair).unwrap();
        (key_pair.serialize_pem(), cert.pem())
    }

    /// A leaf, for the "this is not a CA" case.
    fn leaf() -> (String, String) {
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Issuer");
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::from_ca_cert_pem(&ca.pem(), ca_key).unwrap();

        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut leaf_params = CertificateParams::new(vec!["leaf.example".into()]).unwrap();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "leaf.example");
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        (leaf_key.serialize_pem(), leaf.pem())
    }

    #[test]
    fn an_imported_ca_is_described_by_itself_not_by_the_request() {
        let (_, cert_pem) = self_signed_ca("Acme Offline Root", 3650);
        let parsed = parse_ca_certificate(&cert_pem).unwrap();

        assert_eq!(parsed.subject, "Acme Offline Root");
        assert_eq!(parsed.key_algorithm, KeyAlgorithm::Ed25519);
        assert!(parsed.not_after > Utc::now());
        assert!(parsed.not_before < parsed.not_after);
        assert_eq!(parsed.fingerprint.len(), 64, "SHA-256 hex");
    }

    #[test]
    fn a_leaf_certificate_is_refused_as_a_ca() {
        // Otherwise it appears in the issuing-CA dropdown and everything it
        // signs is rejected by every relying party that checks the chain.
        let (_, leaf_pem) = leaf();
        let err = parse_ca_certificate(&leaf_pem).unwrap_err();
        assert!(err.to_string().contains("CA:TRUE"), "{err}");
    }

    #[test]
    fn something_that_is_not_a_certificate_is_refused_with_a_readable_message() {
        let err = parse_ca_certificate("not a certificate").unwrap_err();
        assert!(err.to_string().contains("PEM-encoded X.509"), "{err}");
    }

    #[test]
    fn an_expired_ca_is_refused_at_import_rather_than_at_first_issuance() {
        // Leaf validity is capped to the CA's, so an expired CA could never
        // issue anything. Refusing here says why; refusing later says
        // "certificate is expired" about a CA the operator just added.
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "Expired Root");
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(30);
        params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        let cert = params.self_signed(&key_pair).unwrap();

        let err = parse_ca_certificate(&cert.pem()).unwrap_err();
        assert!(err.to_string().contains("already expired"), "{err}");
    }

    #[test]
    fn a_matching_key_and_certificate_are_accepted() {
        let (key_pem, cert_pem) = self_signed_ca("Acme Offline Root", 3650);
        assert!(verify_key_matches_certificate(&key_pem, &cert_pem).is_ok());
    }

    #[test]
    fn a_key_from_a_different_ca_is_refused() {
        // The failure this prevents: a CA that lists as issuable and dies at
        // the first signature with a message about key parsing.
        let (_, cert_pem) = self_signed_ca("Acme Offline Root", 3650);
        let (other_key_pem, _) = self_signed_ca("Somebody Else", 3650);
        let err = verify_key_matches_certificate(&other_key_pem, &cert_pem).unwrap_err();
        assert!(err.to_string().contains("does not match"), "{err}");
    }

    #[test]
    fn something_that_is_not_a_key_is_refused_with_a_readable_message() {
        let (_, cert_pem) = self_signed_ca("Acme Offline Root", 3650);
        let err = verify_key_matches_certificate(
            "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----",
            &cert_pem,
        )
        .unwrap_err();
        assert!(err.to_string().contains("private key"), "{err}");
    }

    #[test]
    fn split_stored_puts_each_custodians_answer_in_its_own_column() {
        let (inline, locator) = split_stored(StoredCaKey::Inline(vec![1, 2, 3]));
        assert_eq!(inline, Some(vec![1, 2, 3]));
        assert_eq!(locator, None);

        let (inline, locator) = split_stored(StoredCaKey::Referenced("axiam/ca/x".into()));
        assert_eq!(inline, None);
        assert_eq!(locator.as_deref(), Some("axiam/ca/x"));
    }
}
