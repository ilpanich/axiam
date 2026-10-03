//! The SAML identity provider's signing credential (G-2, T23.2.1, D-21).
//!
//! One tenant signs every SAML assertion it issues with one RSA-4096 key, and
//! the service providers it talks to pin the matching certificate from the IdP
//! metadata. This module is the plain data of that credential; the issuance
//! (leaf signing under the tenant's CA, key sealing) is
//! `axiam_pki::SamlIdpCredentialService`, and the storage is
//! [`SamlIdpCredentialRepository`](crate::repository::SamlIdpCredentialRepository).
//!
//! # Not a `certificate`, not on the wire
//!
//! The leaf carries [`CertificateType::SamlSigning`](crate::models::certificate::CertificateType::SamlSigning)
//! in its profile but is **never a `certificate` row**, so no certificate list
//! or get can return it, and nothing in this module derives `Serialize` or
//! `ToSchema`: a response type for the credential is a decision for the route
//! that exposes it, taken on purpose, not a derive away.
//!
//! # The private key
//!
//! [`SealedSamlIdpKey`] is what the repository stores and returns: ciphertext
//! plus the custody that sealed it, with a `Debug` that prints neither. The
//! plaintext exists only as a `Zeroizing` buffer inside the issuing service, at
//! the moment a key is generated or an assertion is signed.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::ca_keys::CaKeyCustody;

/// Where a credential is in its life.
///
/// At most one credential per tenant is [`Self::Active`] and at most one is
/// [`Self::Next`] — enforced by the datastore, not by the service. `Next` is
/// the slot rotation publishes in metadata ahead of promoting it, so an SP that
/// pins certificates has the new one before any assertion carries it; no
/// rotation exists in W3, but the slot does, so adding it needs no migration.
/// `Retired` is terminal and unbounded in number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SamlIdpCredentialStatus {
    /// Signs the assertions the tenant issues now.
    Active,
    /// Published in metadata, not yet signing.
    Next,
    /// Out of metadata and out of use. Its key material is destroyed.
    Retired,
}

impl SamlIdpCredentialStatus {
    /// The spelling stored in the datastore.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Next => "next",
            Self::Retired => "retired",
        }
    }

    /// Parse the stored spelling.
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "active" => Some(Self::Active),
            "next" => Some(Self::Next),
            "retired" => Some(Self::Retired),
            _ => None,
        }
    }
}

/// A tenant's SAML signing credential, without its private key.
///
/// This is everything a list, a metadata document or an admin page may show.
/// The key travels separately, as a [`SealedSamlIdpKey`], on the one path that
/// asks for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlIdpCredential {
    /// Credential id.
    pub id: Uuid,
    /// The tenant this credential signs for.
    pub tenant_id: Uuid,
    /// The signing CA that issued the leaf.
    pub issuer_ca_id: Uuid,
    /// The leaf certificate, PEM. Public.
    pub certificate_pem: String,
    /// The certificate's serial number, lower-case hex.
    pub serial: String,
    /// SHA-256 fingerprint of the certificate's DER, lower-case hex.
    pub fingerprint: String,
    /// Start of the certificate's validity.
    pub not_before: DateTime<Utc>,
    /// End of the certificate's validity.
    pub not_after: DateTime<Utc>,
    /// Lifecycle position.
    pub status: SamlIdpCredentialStatus,
    /// Which custodian sealed the private key. Recorded on the row, as for CAs,
    /// so a later custodian is a new value and not a migration.
    pub key_custody: CaKeyCustody,
    /// When the credential was created.
    pub created_at: DateTime<Utc>,
    /// When it was retired, if it was.
    pub retired_at: Option<DateTime<Utc>>,
}

/// A private key as the datastore holds it: sealed, with the custody that
/// sealed it.
///
/// `Debug` prints neither the ciphertext nor its length.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedSamlIdpKey {
    /// The custodian that holds (or sealed) the key.
    pub custody: CaKeyCustody,
    /// Where a custodian that keeps the key itself put it; `None` for database
    /// custody, whose material is [`Self::ciphertext`].
    pub locator: Option<String>,
    /// AES-256-GCM ciphertext, database custody only.
    pub ciphertext: Option<Vec<u8>>,
}

impl std::fmt::Debug for SealedSamlIdpKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedSamlIdpKey")
            .field("custody", &self.custody)
            .field("locator", &self.locator)
            .field(
                "ciphertext",
                &self.ciphertext.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// A credential and its sealed key: what the signer's lookup returns.
///
/// Deliberately a different type from [`SamlIdpCredential`], so the one
/// repository method that returns key material cannot be mistaken, by type, for
/// the ones that never do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedSamlIdpCredential {
    /// The credential's public facts.
    pub credential: SamlIdpCredential,
    /// Its sealed private key.
    pub key: SealedSamlIdpKey,
}

/// A credential to be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreSamlIdpCredential {
    /// The id the row will have. Chosen by the caller, before the key is
    /// sealed, so a custodian that names what it stores can name it after the
    /// credential that owns it.
    pub id: Uuid,
    /// The tenant it signs for.
    pub tenant_id: Uuid,
    /// The signing CA that issued the leaf.
    pub issuer_ca_id: Uuid,
    /// The leaf certificate, PEM.
    pub certificate_pem: String,
    /// The certificate's serial, lower-case hex.
    pub serial: String,
    /// SHA-256 fingerprint of the DER, lower-case hex.
    pub fingerprint: String,
    /// Start of validity.
    pub not_before: DateTime<Utc>,
    /// End of validity.
    pub not_after: DateTime<Utc>,
    /// [`SamlIdpCredentialStatus::Active`] or [`SamlIdpCredentialStatus::Next`];
    /// a credential is never created retired.
    pub status: SamlIdpCredentialStatus,
    /// The sealed private key.
    pub key: SealedSamlIdpKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_spellings_round_trip() {
        for status in [
            SamlIdpCredentialStatus::Active,
            SamlIdpCredentialStatus::Next,
            SamlIdpCredentialStatus::Retired,
        ] {
            assert_eq!(
                SamlIdpCredentialStatus::from_wire(status.as_str()),
                Some(status)
            );
        }
        assert_eq!(SamlIdpCredentialStatus::from_wire("Active"), None);
    }

    #[test]
    fn a_sealed_key_debug_prints_no_ciphertext() {
        let marker = Uuid::new_v4().simple().to_string();
        let sealed = SealedSamlIdpKey {
            custody: CaKeyCustody::Database,
            locator: None,
            ciphertext: Some(marker.clone().into_bytes()),
        };
        let shown = format!(
            "{sealed:?} {:?}",
            StoreSamlIdpCredential {
                id: Uuid::nil(),
                tenant_id: Uuid::nil(),
                issuer_ca_id: Uuid::nil(),
                certificate_pem: String::new(),
                serial: String::new(),
                fingerprint: String::new(),
                not_before: DateTime::<Utc>::UNIX_EPOCH,
                not_after: DateTime::<Utc>::UNIX_EPOCH,
                status: SamlIdpCredentialStatus::Active,
                key: sealed.clone(),
            }
        );
        assert!(shown.contains("[REDACTED]"));
        assert!(!shown.contains(&marker));
        assert!(!shown.contains(&format!("{:?}", marker.as_bytes())));
    }
}
