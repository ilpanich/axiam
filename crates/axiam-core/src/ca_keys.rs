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
//! # Custody, and the stronger thing beyond it
//!
//! Most implementations hand back a private key PEM, which means the key does
//! reach AXIAM's memory to sign with. That is *custody*: the key is somewhere
//! better than a database column, and reading it is an audited, revocable act
//! — but AXIAM still reads it.
//!
//! One implementation does not. Vault's PKI secrets engine generates the key
//! inside itself and exposes no API that exports it, so a
//! [`CaKeyCustody::VaultPki`] CA answers [`CaKeyStore::load`] with a refusal
//! and answers [`CaKeyStore::sign_csr`] instead. Designing the port around a
//! key *reference* rather than a key is what left room for that, and the three
//! capability questions below — [`CaKeyStore::generates_cas`],
//! [`CaKeyStore::signs_remotely`] — are how a caller finds out which kind of
//! custodian it is holding without knowing the concrete type.
//!
//! The default bodies are the whole point of those methods being on this trait
//! rather than a second one: a custodian that holds keys the ordinary way
//! implements none of them and behaves exactly as it did before.
//!
//! Nothing here decides *which* custodian a deployment uses. The composition
//! root picks one and the CA row records which answered, so a deployment that
//! adopts Vault does not strand the CAs it created before.

use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{AxiamError, AxiamResult};
use crate::models::certificate::KeyAlgorithm;

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
    /// A HashiCorp Vault **PKI secrets engine** issuer. The key is generated
    /// inside Vault by `root/generate/internal` and
    /// `intermediate/generate/internal`, and there is no API that exports it —
    /// so unlike every other variant here, AXIAM never holds this key at all.
    ///
    /// Signing therefore moves to Vault too: the leaf key is generated here, a
    /// CSR goes to `sign-verbatim`, and a certificate comes back. That is the
    /// difference between *custody* and the stronger property this module's
    /// header describes, and it is the reason the port is addressed by key
    /// reference rather than by key.
    VaultPki,
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
            Self::VaultPki => write!(f, "vault_pki"),
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
            "vault_pki" => Ok(Self::VaultPki),
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

/// What a caller asks a key-generating custodian to create.
///
/// Only [`CaKeyCustody::VaultPki`] answers this today. Every field is a
/// *request*: the row that ends up describing the CA is parsed back out of the
/// certificate the custodian returns, because Vault caps a TTL to the mount's
/// `max_lease_ttl` and to the signing root's own expiry without failing the
/// call. A row built from the request would then claim a validity window the
/// certificate does not have.
#[derive(Debug, Clone)]
pub struct CaGenerationRequest {
    pub organization_id: Uuid,
    /// The id the CA row will have. Chosen before the call so the custodian can
    /// name what it creates after the CA that owns it.
    pub ca_id: Uuid,
    /// Common name for the root.
    pub subject: String,
    pub key_algorithm: KeyAlgorithm,
    /// Requested root validity.
    pub validity_days: u32,
    /// The signing intermediate to create beneath the root, if any.
    ///
    /// `Some` is the ordinary case and what HashiCorp's own PKI walkthrough
    /// does: the root signs one intermediate and then issues nothing else, so
    /// a compromised issuer is replaced without redistributing the trust
    /// anchor. `None` issues straight from the root, which is a smaller thing
    /// to operate and a worse thing to lose.
    pub intermediate: Option<IntermediateSpec>,
}

/// The signing intermediate created beneath a generated root.
#[derive(Debug, Clone)]
pub struct IntermediateSpec {
    pub subject: String,
    pub validity_days: u32,
}

/// A CA the custodian generated and still holds the key for.
#[derive(Debug, Clone)]
pub struct GeneratedCa {
    /// The certificate that will sign leaves — the intermediate when one was
    /// asked for, the root otherwise. PEM.
    pub certificate_pem: String,
    /// Everything above it, nearest issuer first, root last. Empty when the
    /// issuing certificate *is* the root.
    ///
    /// Kept because a relying party validating an AXIAM-issued leaf needs it
    /// and cannot get it from anywhere else: the root's certificate exists only
    /// inside Vault.
    pub chain_pem: Vec<String>,
    /// What to put in the CA row's `key_locator`.
    pub locator: String,
}

/// A leaf certificate to be signed by a custodian that holds the CA key.
#[derive(Debug, Clone)]
pub struct LeafSigningRequest {
    /// PEM-encoded PKCS#10 request. The end-entity key is generated by AXIAM
    /// and never sent — only its public half, inside this.
    pub csr_pem: String,
    /// How long the certificate should be valid for, in seconds. Already capped
    /// to the CA's own remaining validity by the caller; the custodian may cap
    /// it further, which is why the answer is parsed rather than assumed.
    pub ttl_seconds: i64,
}

/// What a remote signer returned.
#[derive(Debug, Clone)]
pub struct SignedLeaf {
    /// The signed certificate, PEM.
    pub certificate_pem: String,
    /// The issuing chain, nearest issuer first.
    pub chain_pem: Vec<String>,
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

    /// Whether this custodian creates CA keys itself, rather than being handed
    /// one AXIAM generated.
    ///
    /// A capability question rather than a match on [`Self::custody`], so that
    /// adding a KMS does not mean revisiting every caller that wanted to know.
    fn generates_cas(&self) -> bool {
        false
    }

    /// Create a CA whose private key is born inside the custodian.
    ///
    /// Only called when [`Self::generates_cas`] is true. The default refuses
    /// rather than silently generating a key here, which would produce exactly
    /// the property — a CA key that passed through AXIAM — that a caller
    /// reaching for this method was trying to avoid.
    fn generate_ca<'a>(
        &'a self,
        request: &'a CaGenerationRequest,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<GeneratedCa>> + Send + 'a>> {
        let _ = request;
        Box::pin(async {
            Err(AxiamError::Internal(
                "this CA key custodian cannot generate a CA: it takes custody of a key \
                 AXIAM generated"
                    .into(),
            ))
        })
    }

    /// Take custody of a CA an organization already has — BYOK.
    ///
    /// Separate from [`Self::store`] only because the certificate matters to a
    /// custodian that is a PKI rather than a safe: Vault's PKI engine imports a
    /// key and the certificate it belongs to as one bundle, and has nowhere to
    /// put a key on its own. Every other custodian ignores the certificate,
    /// which is what the default body does.
    fn import_ca<'a>(
        &'a self,
        organization_id: Uuid,
        ca_id: Uuid,
        certificate_pem: &'a str,
        private_key_pem: &'a str,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<StoredCaKey>> + Send + 'a>> {
        let _ = certificate_pem;
        self.store(organization_id, ca_id, private_key_pem)
    }

    /// Whether signing happens inside the custodian.
    ///
    /// True means [`Self::load`] will refuse and [`Self::sign_csr`] is the only
    /// way to issue against this CA — not a degraded mode but the stronger one,
    /// where the signing key has never existed in this process.
    fn signs_remotely(&self) -> bool {
        false
    }

    /// Sign a CSR with a CA key the custodian holds and will not hand over.
    ///
    /// Only called when [`Self::signs_remotely`] is true.
    fn sign_csr<'a>(
        &'a self,
        key_ref: &'a CaKeyRef,
        request: &'a LeafSigningRequest,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<SignedLeaf>> + Send + 'a>> {
        let _ = (key_ref, request);
        Box::pin(async {
            Err(AxiamError::Internal(
                "this CA key custodian does not sign: load the key and sign here".into(),
            ))
        })
    }

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
            CaKeyCustody::VaultPki,
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
        // `snake_case` on a two-word variant: the wire form, the `Display`
        // form, the `FromStr` form and the value the schema's ASSERT allows all
        // have to be the same string, and `vaultPki` would break three of them.
        assert_eq!(
            serde_json::to_string(&CaKeyCustody::VaultPki).unwrap(),
            "\"vault_pki\""
        );
    }
}
