//! The tenant's SAML identity-provider signing credential — issuance, sealing,
//! lookup and retirement (G-2, T23.2.1, D-21).
//!
//! One RSA-4096 leaf per tenant, signed by a signing CA of the tenant's
//! organization, carrying
//! [`CertificateType::SamlSigning`](axiam_core::models::certificate::CertificateType::SamlSigning)'s
//! profile (`digitalSignature` only, `documentSigning`, no SANs). The signing is
//! [`CertService`](crate::cert::CertService)'s own — the same CA lookup, tenant
//! fence, issuer-bounded validity, custodian resolution and leaf construction,
//! through `CertService::issue_leaf_material` — and what differs is only
//! where the result goes: **not** a `certificate` row (D-21), but a
//! `saml_idp_credential` row whose private key is sealed AES-256-GCM under
//! `pki_encryption_key` by [`DatabaseCaKeyStore`](crate::DatabaseCaKeyStore).
//!
//! # What this does not do
//!
//! * **No lazy creation.** Nothing issues a credential as a side effect of
//!   serving metadata or an SSO request: an SP pins the metadata certificate, so
//!   it changes only by an administrator's act, and [`SamlIdpCredentialService::issue`]
//!   is that act.
//! * **No automatic rotation.** The `next` slot exists so rotation needs no
//!   schema change; nothing promotes it.
//! * **No REST route.** T23.2.5 adds the admin route.
//!
//! # The key
//!
//! Never returned by any API and never in a `Debug`. [`SamlIdpSigningKey`] is the
//! one place plaintext exists: a [`Zeroizing`] buffer, returned by
//! [`SamlIdpCredentialService::get_active_signing_key`] for the signer.

use std::sync::Arc;

use axiam_core::ca_keys::{CaKeyCustody, CaKeyRef, StoredCaKey};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::id::new_id;
use axiam_core::models::certificate::{CertificateType, CreateCertificate, KeyAlgorithm};
use axiam_core::models::saml_idp_credential::{
    SamlIdpCredential, SamlIdpCredentialStatus, SealedSamlIdpKey, StoreSamlIdpCredential,
};
use axiam_core::repository::{
    CaCertificateRepository, CertificateRepository, SamlIdpCredentialRepository,
};
use uuid::Uuid;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;
use zeroize::Zeroizing;

use crate::ca_key_store::CaKeyCustodians;
use crate::cert::{CertService, IssuingScope};
use crate::subject::subject_common_name;

/// The longest a SAML IdP signing certificate may be valid: two years, in days.
///
/// Shorter than the 825-day cap on generic leaves, because this key signs every
/// assertion the tenant issues and an SP pins the certificate: the window a
/// leaked key stays useful for is the window it is valid for. Also bounded by
/// the issuing CA's own `not_after`, as for every leaf.
pub const MAX_SAML_IDP_CREDENTIAL_VALIDITY_DAYS: u32 = 730;

/// The algorithm of the SAML signing key (D-21): RSA-4096 with `rsa-sha256`,
/// the XML-DSig pair every service provider accepts.
const KEY_ALGORITHM: KeyAlgorithm = KeyAlgorithm::Rsa4096;

/// The credential's private key in the clear, for the signer.
///
/// A [`Zeroizing`] buffer, so the PEM is overwritten when this is dropped, and a
/// `Debug` that prints the public facts and no key.
pub struct SamlIdpSigningKey {
    /// The credential the key belongs to.
    pub credential: SamlIdpCredential,
    /// PKCS#8 PEM of the RSA-4096 private key.
    pub private_key_pem: Zeroizing<String>,
}

impl std::fmt::Debug for SamlIdpSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SamlIdpSigningKey")
            .field("credential", &self.credential)
            .field("private_key_pem", &"[REDACTED]")
            .finish()
    }
}

/// Issues, seals, looks up and retires a tenant's SAML signing credentials.
///
/// Holds a [`CertService`] only for its issuing path — it never calls the
/// service's `generate`, so no `certificate` row is written — and the
/// custodians the database custodian is resolved from.
#[derive(Clone)]
pub struct SamlIdpCredentialService<CA, CR, SR> {
    leaf_issuer: CertService<CA, CR>,
    custodians: Arc<CaKeyCustodians>,
    repo: SR,
}

impl<CA, CR, SR> SamlIdpCredentialService<CA, CR, SR>
where
    CA: CaCertificateRepository,
    CR: CertificateRepository,
    SR: SamlIdpCredentialRepository,
{
    /// Build the service over the certificate service whose issuing path it
    /// reuses, the CA key custodians the rest of the PKI already shares, and the
    /// credential repository.
    pub fn new(
        leaf_issuer: CertService<CA, CR>,
        custodians: Arc<CaKeyCustodians>,
        repo: SR,
    ) -> Self {
        Self {
            leaf_issuer,
            custodians,
            repo,
        }
    }

    /// Issue the tenant's SAML signing credential from the named CA, and store
    /// it with its key sealed.
    ///
    /// `issuer_ca_id` must name an **active signing CA** the caller may use: a CA
    /// of another organization is `NotFound`; one of another tenant, or the
    /// organization anchor for a [`IssuingScope::Tenant`] caller, is `NotFound`
    /// too (the rule `CertService` applies to every leaf); a revoked one, an
    /// expired one, or one whose key AXIAM does not hold (an imported CA, which
    /// cannot sign) is refused. `validity_days` is 1 to
    /// [`MAX_SAML_IDP_CREDENTIAL_VALIDITY_DAYS`] and cannot outlive the CA.
    ///
    /// `status` is [`SamlIdpCredentialStatus::Active`] or
    /// [`SamlIdpCredentialStatus::Next`]. A tenant already holding one in that
    /// slot is `AlreadyExists` — checked first so an occupied slot does not cost
    /// an RSA-4096 key generation, and enforced by the database for the race the
    /// check cannot see.
    pub async fn issue(
        &self,
        org_id: Uuid,
        tenant_id: Uuid,
        scope: IssuingScope,
        issuer_ca_id: Uuid,
        validity_days: u32,
        status: SamlIdpCredentialStatus,
    ) -> AxiamResult<SamlIdpCredential> {
        if status == SamlIdpCredentialStatus::Retired {
            return Err(AxiamError::Validation {
                message: "a SAML IdP credential is issued active or next, never retired".into(),
            });
        }
        if self
            .repo
            .list(tenant_id)
            .await?
            .iter()
            .any(|c| c.status == status)
        {
            return Err(AxiamError::AlreadyExists {
                entity: "saml_idp_credential".into(),
            });
        }

        let id = new_id();
        let subject = subject_common_name(&format!("AXIAM SAML IdP {tenant_id}"))?;

        // The same issuing path `CertService::generate` runs, stopped before it
        // writes an inventory row. `generate` itself refuses `SamlSigning` by
        // name; this is the one caller that may name it.
        let mut leaf = self
            .leaf_issuer
            .issue_leaf_material(
                org_id,
                scope,
                &CreateCertificate {
                    tenant_id,
                    issuer_ca_id,
                    subject,
                    cert_type: CertificateType::SamlSigning,
                    key_algorithm: KEY_ALGORITHM,
                    validity_days,
                    metadata: None,
                    // A SAML signing leaf names no host.
                    subject_alt_names: Vec::new(),
                },
                Some(MAX_SAML_IDP_CREDENTIAL_VALIDITY_DAYS),
                &[],
            )
            .await?;
        // Into a zeroizing buffer at once. The move leaves no second copy.
        let private_key_pem = Zeroizing::new(std::mem::take(&mut leaf.private_key_pem));
        let serial = leaf_serial_hex(&leaf.public_cert_pem)?;

        // D-21: sealed through the database custodian, explicitly — not
        // through whichever custodian is the deployment's default. The key
        // signs on every assertion, so a Vault round trip per sign-in is the
        // wrong latency, and `VaultPki` cannot hold an exported key at all.
        let custodian = self.custodians.store_for(CaKeyCustody::Database)?;
        let key = match custodian.store(org_id, id, &private_key_pem).await? {
            StoredCaKey::Inline(ciphertext) => SealedSamlIdpKey {
                custody: custodian.custody(),
                locator: None,
                ciphertext: Some(ciphertext),
            },
            StoredCaKey::Referenced(locator) => SealedSamlIdpKey {
                custody: custodian.custody(),
                locator: Some(locator),
                ciphertext: None,
            },
        };

        self.repo
            .create(StoreSamlIdpCredential {
                id,
                tenant_id,
                issuer_ca_id,
                certificate_pem: leaf.public_cert_pem,
                serial,
                fingerprint: leaf.fingerprint,
                not_before: leaf.not_before,
                not_after: leaf.not_after,
                status,
                key,
            })
            .await
    }

    /// The tenant's active credential with its private key opened, for the
    /// assertion signer; `None` when the tenant has no active credential.
    ///
    /// The key is decrypted into a [`Zeroizing`] buffer and nowhere else. This
    /// does **not** refuse an expired credential: whether to sign with a
    /// certificate past its `not_after` is the signer's decision, made where it
    /// can say why.
    pub async fn get_active_signing_key(
        &self,
        org_id: Uuid,
        tenant_id: Uuid,
    ) -> AxiamResult<Option<SamlIdpSigningKey>> {
        let Some(sealed) = self.repo.get_active_sealed(tenant_id).await? else {
            return Ok(None);
        };
        let key_ref = CaKeyRef {
            organization_id: org_id,
            ca_id: sealed.credential.id,
            custody: sealed.key.custody,
            locator: sealed.key.locator.clone().unwrap_or_default(),
        };
        let private_key_pem = self
            .custodians
            .store_for(sealed.key.custody)?
            .load(&key_ref, sealed.key.ciphertext.as_deref())
            .await?;
        Ok(Some(SamlIdpSigningKey {
            credential: sealed.credential,
            private_key_pem,
        }))
    }

    /// The tenant's active credential, without its key; `None` when there is
    /// none.
    pub async fn get_active(&self, tenant_id: Uuid) -> AxiamResult<Option<SamlIdpCredential>> {
        self.repo.get_active(tenant_id).await
    }

    /// Every credential of the tenant, oldest first, without key material.
    pub async fn list(&self, tenant_id: Uuid) -> AxiamResult<Vec<SamlIdpCredential>> {
        self.repo.list(tenant_id).await
    }

    /// Retire a credential: out of its slot, out of metadata, key destroyed.
    ///
    /// The sealed key is cleared in the same write that takes the row out of its
    /// slot, so database custody — the only custody [`Self::issue`] uses — leaves
    /// nothing behind. No CRL entry is made: service providers pin the metadata
    /// certificate, so removing it from metadata is what ends their trust. A
    /// custodian that kept the key outside the row would need its own delete
    /// here; none is reachable today, and the row records the custody so adding
    /// one is a code change and not a migration.
    ///
    /// Retiring a retired credential returns it unchanged. `NotFound` for an id
    /// that is not this tenant's.
    pub async fn retire(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<SamlIdpCredential> {
        self.repo.retire(tenant_id, id).await
    }
}

/// The serial number of a PEM certificate as lower-case hex.
fn leaf_serial_hex(pem: &str) -> AxiamResult<String> {
    let (_, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|e| {
        AxiamError::Certificate(format!("the signed certificate is not a PEM: {e}"))
    })?;
    let (_, cert) = X509Certificate::from_der(&block.contents).map_err(|e| {
        AxiamError::Certificate(format!("the signed certificate could not be parsed: {e}"))
    })?;
    Ok(hex::encode(cert.raw_serial()))
}
