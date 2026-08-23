//! Where an organization's CA signing keys are kept.
//!
//! A **port**, like [`crate::secrets`], and for a related reason — but a
//! different shape, and the difference is the point of having two.
//!
//! [`crate::secrets::SecretProvider`] serves a fixed set of process-wide keys,
//! resolved once during composition and answered from memory thereafter. That
//! works because those keys are known at startup and never change.
//!
//! CA signing keys are neither. There is one per CA certificate, they are
//! created while the process is running, and there is no bound on how many an
//! organization has. So this port is asynchronous, addressed by key reference,
//! and read on the path that issues a certificate.
//!
//! # Why this exists at all
//!
//! Until this port, a CA private key was AES-256-GCM ciphertext in a
//! `ca_certificate` row, sealed under one process-wide `pki_encryption_key`.
//! That is a real control and it stays available, but it puts the key and the
//! thing that unlocks it inside the same blast radius: whoever reads the
//! database and the environment of one process holds every CA in the
//! deployment, and nothing anywhere records that they used it.
//!
//! A key held in Vault (and later a KMS) is a different proposition. Access is
//! a policy that can be scoped and revoked, every read is audited by something
//! that is not AXIAM, and a database dump on its own is inert.
//!
//! # What this port does *not* do
//!
//! Sign anything. Every implementation here hands back a private key PEM, which
//! means the key does reach AXIAM's memory to sign with. The stronger property
//! — a key that never leaves the custodian, with signing done by Vault's PKI
//! engine or a KMS — needs certificate *issuance* to move there too, not just
//! custody, which is a change to a different part of the system. Designing the
//! port around a key reference rather than a key is what leaves room for that:
//! a future implementation can answer a `sign` call without ever answering a
//! `load` one.
//!
//! Nothing here decides *which* custodian a deployment uses. The composition
//! root picks one and the CA row records which answered, so a deployment that
//! adopts Vault does not strand the CAs it created before.

use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::AxiamResult;

/// Which custodian holds a CA's private key.
///
/// Recorded per CA rather than inferred from configuration, because the two
/// diverge the moment an operator changes custodian: CAs created before the
/// change are still where they were, and a lookup that consulted only the
/// current setting would fail to find them — or, worse, look in the right place
/// and get a different key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CaKeyCustody {
    /// AES-256-GCM ciphertext in the `ca_certificate` row itself, sealed under
    /// the process-wide `pki_encryption_key`. The original arrangement, and
    /// still the default for a deployment that has configured no custodian.
    Database,
    /// A HashiCorp Vault KV v2 secret. The row holds the path and no key
    /// material at all.
    Vault,
    /// No private key is held by AXIAM. An imported CA whose key stays with
    /// whoever generated it: the certificate is a trust anchor here and
    /// AXIAM cannot issue against it.
    External,
}

impl std::fmt::Display for CaKeyCustody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database => write!(f, "database"),
            Self::Vault => write!(f, "vault"),
            Self::External => write!(f, "external"),
        }
    }
}

impl std::str::FromStr for CaKeyCustody {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "database" => Ok(Self::Database),
            "vault" => Ok(Self::Vault),
            "external" => Ok(Self::External),
            other => Err(format!("unknown CA key custody: {other}")),
        }
    }
}

/// Everything needed to find one CA's private key again.
///
/// Carries the custodian as well as the locator, so a caller holding one of
/// these does not have to consult configuration to know how to read it — which
/// is what makes a mixed deployment work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaKeyRef {
    pub organization_id: Uuid,
    pub ca_id: Uuid,
    pub custody: CaKeyCustody,
    /// Where the custodian put it. A Vault path; empty for `Database`, whose
    /// locator is the row itself.
    pub locator: String,
}

/// What a [`CaKeyStore::store`] call produced.
///
/// Two variants because the database custodian's "locator" *is* the material:
/// it hands back ciphertext for the caller to write into the CA row, where
/// every other custodian hands back a path and keeps the material itself.
#[derive(Debug, Clone)]
pub enum StoredCaKey {
    /// Ciphertext the caller must persist in the CA row.
    Inline(Vec<u8>),
    /// The key is with the custodian; this is where.
    Referenced(String),
}

/// A custodian for CA signing keys.
///
/// Object-safe on purpose — the composition root chooses an implementation at
/// runtime from configuration, so this is held as `Arc<dyn CaKeyStore>` and
/// cannot use RPITIT the way the repository traits do. Hence the boxed futures
/// rather than `impl Future`, matching [`crate::models::email`]'s provider
/// trait, which is object-safe for the same reason.
pub trait CaKeyStore: Send + Sync {
    /// Take custody of `private_key_pem` for a CA that is about to be created.
    ///
    /// Called before the CA row is written, so a custodian that refuses stops
    /// the CA existing at all rather than leaving a certificate whose key is
    /// nowhere.
    fn store<'a>(
        &'a self,
        organization_id: Uuid,
        ca_id: Uuid,
        private_key_pem: &'a str,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<StoredCaKey>> + Send + 'a>>;

    /// Retrieve a key previously stored under `key_ref`.
    ///
    /// `inline` carries the row's own ciphertext, which only the database
    /// custodian reads; every other implementation ignores it. Passing it
    /// unconditionally is what lets the caller stay ignorant of which custodian
    /// it is talking to.
    fn load<'a>(
        &'a self,
        key_ref: &'a CaKeyRef,
        inline: Option<&'a [u8]>,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<Zeroizing<String>>> + Send + 'a>>;

    /// Release custody. A no-op for the database custodian, whose material goes
    /// away with the row.
    ///
    /// Best-effort by contract: a CA row is the record of what exists, and a
    /// custodian that could not be reached must not stop a revocation. What is
    /// left behind is an orphaned secret, which is a cleanup task, not a
    /// security failure — it signs nothing that AXIAM will honour.
    fn delete<'a>(
        &'a self,
        key_ref: &'a CaKeyRef,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<()>> + Send + 'a>>;

    /// Which custodian this is. Recorded on the CA row at creation.
    fn custody(&self) -> CaKeyCustody;

    /// A short label for logs and startup diagnostics, e.g. `"vault"`.
    fn describe(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custody_round_trips_through_its_string_form() {
        for custody in [
            CaKeyCustody::Database,
            CaKeyCustody::Vault,
            CaKeyCustody::External,
        ] {
            let s = custody.to_string();
            assert_eq!(s.parse::<CaKeyCustody>().unwrap(), custody);
        }
    }

    #[test]
    fn an_unknown_custody_is_refused_rather_than_defaulted() {
        // Defaulting would silently move a CA's key to a different custodian in
        // the reader's mind, and the lookup would then miss or hit the wrong
        // secret.
        let err = "kms".parse::<CaKeyCustody>().unwrap_err();
        assert!(err.contains("kms"));
    }

    #[test]
    fn custody_serializes_snake_case_for_the_wire() {
        assert_eq!(
            serde_json::to_string(&CaKeyCustody::Vault).unwrap(),
            "\"vault\""
        );
        assert_eq!(
            serde_json::from_str::<CaKeyCustody>("\"external\"").unwrap(),
            CaKeyCustody::External
        );
    }
}
