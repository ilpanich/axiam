//! AXIAM PKI — Certificate management, CA operations, and GnuPG integration.
//!
//! Provides X.509 certificate lifecycle management (generation, signing,
//! revocation, rotation), CA certificate management at organization level,
//! IoT device certificate authentication, and GnuPG/OpenPGP key management
//! for audit signing and encrypted data exports.

pub mod ca;
pub mod cert;
pub mod mtls;
pub mod pgp;

pub use ca::{CaService, MAX_CA_VALIDITY_DAYS, PkiConfig};
pub use cert::{CertService, DEFAULT_LEAF_CERT_VALIDITY_DAYS, MAX_LEAF_CERT_VALIDITY_DAYS};
pub use mtls::DeviceAuthService;
pub use pgp::PgpService;
