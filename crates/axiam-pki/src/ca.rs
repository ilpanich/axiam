//! CA certificate generation and management service.

use axiam_core::ca_keys::{CaKeyCustody, CaKeyRef, StoredCaKey};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::certificate::{
    CaCertificate, CreateCaCertificate, GeneratedCaCertificate, ImportCaCertificate, KeyAlgorithm,
    StoreCaCertificate,
};
use axiam_core::repository::{CaCertificateRepository, PaginatedResult, Pagination};
use chrono::{DateTime, Duration, Utc};
use rcgen::{CertificateParams, DnType, IsCa};
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

use crate::ca_key_store::CaKeyCustodians;
use crate::crypto::{compute_fingerprint, generate_keypair};

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

        // The id is minted here rather than by the repository because a
        // custodian outside the database addresses the key *by CA id*: the id
        // has to exist before the key is stored, and the key has to be stored
        // before the row. A custodian that refuses therefore stops the CA
        // existing at all, rather than leaving a certificate whose key is
        // nowhere and whose failure surfaces at the first issuance.
        let ca_id = Uuid::new_v4();
        let store = self.custodians.default_store()?;
        let stored = store
            .store(input.organization_id, ca_id, &private_key_pem)
            .await?;
        let (encrypted_private_key, key_locator) = split_stored(stored);

        let record = StoreCaCertificate {
            id: ca_id,
            organization_id: input.organization_id,
            subject: input.subject,
            public_cert_pem,
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
            private_key_pem,
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
                let stored = store.store(input.organization_id, ca_id, key_pem).await?;
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
            subject: parsed.subject,
            public_cert_pem: input.public_cert_pem,
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

    /// A [`CaKeyRef`] for one CA, for the signing path to load its key with.
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

    pub async fn revoke(&self, organization_id: Uuid, id: Uuid) -> AxiamResult<()> {
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
        Ok(())
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
