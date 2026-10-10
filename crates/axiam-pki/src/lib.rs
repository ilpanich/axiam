//! AXIAM PKI — Certificate management, CA operations, and GnuPG integration.
//!
//! Provides X.509 certificate lifecycle management (generation, signing,
//! revocation, rotation), CA certificate management at organization level,
//! IoT device certificate authentication, a certificate revocation list per
//! issuing CA, and GnuPG/OpenPGP key management for audit signing and encrypted
//! data exports.

pub mod address;
pub mod ca;
pub mod ca_key_store;
pub mod cert;
pub mod config;
pub mod crl;
mod crypto;
pub mod mds;
pub mod mtls;
pub mod pgp;
pub mod saml_signing;
pub mod ssrf;
pub mod subject;
pub mod vault_pki;

pub use ca::{CaService, MAX_CA_VALIDITY_DAYS};
pub use ca_key_store::{
    CaKeyCustodians, DatabaseCaKeyStore, ExternalCaKeyStore, VaultCaKeyConfig, VaultCaKeyStore,
    custodians_from_env,
};
pub use cert::{
    CertService, CustodianRevocation, DEFAULT_LEAF_CERT_VALIDITY_DAYS, IssuingScope,
    MAX_LEAF_CERT_VALIDITY_DAYS, TenantCertificatesRevoked,
};
pub use config::PkiConfig;
pub use crl::{CrlDistribution, CrlService, PublishedCrl};
pub use mtls::DeviceAuthService;
pub use pgp::PgpService;
pub use saml_signing::{
    MAX_SAML_IDP_CREDENTIAL_VALIDITY_DAYS, SamlIdpCredentialService, SamlIdpSigningKey,
};
pub use subject::subject_common_name;
pub use vault_pki::{VaultPkiCaKeyStore, VaultPkiConfig, VaultPkiIssuer, VaultPkiLocator};
