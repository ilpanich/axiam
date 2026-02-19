//! Certificate domain models.
//!
//! AXIAM provides a hierarchical PKI: organization-level CA certificates
//! sign tenant-level certificates for users, services, and IoT devices.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Status of a certificate in its lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CertificateStatus {
    Active,
    Revoked,
    Expired,
}

/// The type of key algorithm used for a certificate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Rsa4096,
    Ed25519,
}

/// The purpose for which a certificate was issued.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CertificateType {
    /// Certificate for authenticating a user.
    User,
    /// Certificate for authenticating a service or application.
    Service,
    /// Certificate for authenticating an IoT device.
    Device,
}

/// A CA (Certificate Authority) certificate at the organization level.
///
/// CA certificates are the root of trust for all tenant certificates
/// within the organization. Private keys for signing CAs are encrypted
/// with AES-256-GCM and stored separately; non-signing CAs only store
/// the public certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaCertificate {
    pub id: Uuid,
    /// The organization this CA belongs to.
    pub organization_id: Uuid,
    /// The certificate subject (e.g., `CN=ACME Corp Root CA`).
    pub subject: String,
    /// PEM-encoded public certificate.
    pub public_cert_pem: String,
    /// SHA-256 fingerprint of the certificate.
    pub fingerprint: String,
    pub key_algorithm: KeyAlgorithm,
    /// Validity start.
    pub not_before: DateTime<Utc>,
    /// Validity end.
    pub not_after: DateTime<Utc>,
    pub status: CertificateStatus,
    /// AES-256-GCM encrypted private key (only for signing CAs).
    /// `None` for uploaded CAs where the private key is not stored.
    pub encrypted_private_key: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
}

/// Fields required to generate a new CA certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCaCertificate {
    pub organization_id: Uuid,
    pub subject: String,
    pub key_algorithm: KeyAlgorithm,
    /// Validity duration in days.
    pub validity_days: u32,
}

/// A tenant-level certificate for users, services, or IoT devices.
///
/// Certificates are signed by the organization's CA. The private key is
/// returned once on generation and never stored by AXIAM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub id: Uuid,
    /// The tenant this certificate belongs to.
    pub tenant_id: Uuid,
    /// The CA certificate that signed this certificate.
    pub issuer_ca_id: Uuid,
    /// The certificate subject (e.g., `CN=device-001`).
    pub subject: String,
    /// PEM-encoded public certificate.
    pub public_cert_pem: String,
    /// SHA-256 fingerprint of the certificate.
    pub fingerprint: String,
    pub cert_type: CertificateType,
    pub key_algorithm: KeyAlgorithm,
    /// Validity start.
    pub not_before: DateTime<Utc>,
    /// Validity end.
    pub not_after: DateTime<Utc>,
    pub status: CertificateStatus,
    /// Arbitrary key-value metadata (e.g., device serial, user ID binding).
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// Fields required to generate a new tenant certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCertificate {
    pub tenant_id: Uuid,
    pub issuer_ca_id: Uuid,
    pub subject: String,
    pub cert_type: CertificateType,
    pub key_algorithm: KeyAlgorithm,
    /// Validity duration in days.
    pub validity_days: u32,
    pub metadata: Option<serde_json::Value>,
}
