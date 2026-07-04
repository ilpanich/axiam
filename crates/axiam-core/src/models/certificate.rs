//! Certificate domain models.
//!
//! AXIAM provides a hierarchical PKI: organization-level CA certificates
//! sign tenant-level certificates for users, services, and IoT devices.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Status of a certificate in its lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub enum CertificateStatus {
    Active,
    Revoked,
    Expired,
}

/// The type of key algorithm used for a certificate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub enum KeyAlgorithm {
    Rsa4096,
    Ed25519,
}

/// The purpose for which a certificate was issued.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
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
#[derive(Clone, Serialize, Deserialize, utoipa::ToSchema)]
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
    #[serde(skip_serializing)]
    #[schema(read_only)]
    pub encrypted_private_key: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
}

/// Manual `Debug` impl (SECHRD-09 / D-06): `#[serde(skip_serializing)]` only
/// affects `Serialize`, not `{:?}` — this closes that residual leak by
/// redacting `encrypted_private_key` while keeping other fields readable.
impl std::fmt::Debug for CaCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaCertificate")
            .field("id", &self.id)
            .field("organization_id", &self.organization_id)
            .field("subject", &self.subject)
            .field("public_cert_pem", &self.public_cert_pem)
            .field("fingerprint", &self.fingerprint)
            .field("key_algorithm", &self.key_algorithm)
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("status", &self.status)
            .field(
                "encrypted_private_key",
                &self.encrypted_private_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Fields required to generate a new CA certificate (user-facing DTO).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateCaCertificate {
    #[serde(default)]
    pub organization_id: Uuid,
    pub subject: String,
    pub key_algorithm: KeyAlgorithm,
    /// Validity duration in days.
    pub validity_days: u32,
}

/// All fields required to store a CA certificate in the database.
///
/// Produced by the PKI service after generating the keypair and cert.
#[derive(Debug, Clone)]
pub struct StoreCaCertificate {
    pub organization_id: Uuid,
    pub subject: String,
    pub public_cert_pem: String,
    pub fingerprint: String,
    pub key_algorithm: KeyAlgorithm,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub encrypted_private_key: Option<Vec<u8>>,
}

/// Response returned when a CA certificate is generated.
///
/// Includes the private key PEM, which is returned **once** and never
/// stored or retrievable again.
#[derive(Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct GeneratedCaCertificate {
    #[serde(flatten)]
    pub certificate: CaCertificate,
    /// PEM-encoded private key — returned only on generation.
    pub private_key_pem: String,
}

/// Manual `Debug` impl (SECHRD-09 / D-06): redacts `private_key_pem` (raw
/// key material returned only once on generation); delegates to
/// `CaCertificate`'s own redacting `Debug` for the nested `certificate` field.
impl std::fmt::Debug for GeneratedCaCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedCaCertificate")
            .field("certificate", &self.certificate)
            .field("private_key_pem", &"[REDACTED]")
            .finish()
    }
}

/// A tenant-level certificate for users, services, or IoT devices.
///
/// Certificates are signed by the organization's CA. The private key is
/// returned once on generation and never stored by AXIAM.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
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

/// Fields required to generate a new tenant certificate (user-facing DTO).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateCertificate {
    #[serde(default)]
    pub tenant_id: Uuid,
    pub issuer_ca_id: Uuid,
    pub subject: String,
    pub cert_type: CertificateType,
    pub key_algorithm: KeyAlgorithm,
    /// Validity duration in days.
    pub validity_days: u32,
    pub metadata: Option<serde_json::Value>,
}

/// All fields required to store a tenant certificate in the database.
///
/// Produced by the PKI service after generating and signing the certificate.
#[derive(Debug, Clone)]
pub struct StoreCertificate {
    pub tenant_id: Uuid,
    pub issuer_ca_id: Uuid,
    pub subject: String,
    pub public_cert_pem: String,
    pub fingerprint: String,
    pub cert_type: CertificateType,
    pub key_algorithm: KeyAlgorithm,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub metadata: serde_json::Value,
}

/// Request to bind a certificate to a service account.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BindCertificate {
    pub certificate_id: Uuid,
}

/// A certificate-to-service-account binding record.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CertificateBinding {
    pub certificate_id: Uuid,
    pub service_account_id: Uuid,
    pub created_at: DateTime<Utc>,
}

/// Identity resolved from a device certificate during mTLS authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub service_account_id: Uuid,
    pub tenant_id: Uuid,
    pub org_id: Uuid,
    pub certificate_id: Uuid,
}

/// Response returned when a device authenticates via certificate.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DeviceAuthResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// Response returned when a tenant certificate is generated.
///
/// Includes the private key PEM, returned **once** and never stored.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct GeneratedCertificate {
    #[serde(flatten)]
    pub certificate: Certificate,
    /// PEM-encoded private key — returned only on generation.
    pub private_key_pem: String,
}
