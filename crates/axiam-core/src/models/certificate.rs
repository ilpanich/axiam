//! Certificate domain models.
//!
//! AXIAM provides a hierarchical PKI: organization-level CA certificates
//! sign tenant-level certificates for users, services, and IoT devices.

use chrono::{DateTime, Utc};

use crate::ca_keys::CaKeyCustody;
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
    /// AES-256-GCM encrypted private key — only for CAs under
    /// [`CaKeyCustody::Database`]. `None` under every other custodian, and for
    /// an imported CA whose key AXIAM never held.
    #[serde(skip_serializing)]
    #[schema(read_only)]
    pub encrypted_private_key: Option<Vec<u8>>,
    /// Which custodian holds this CA's signing key.
    ///
    /// Recorded per CA rather than read from configuration, so adopting a new
    /// custodian does not strand the CAs that already exist. Not secret — an
    /// operator needs to see it, and it discloses only where a key is kept.
    #[serde(default = "default_key_custody")]
    #[schema(value_type = String, example = "database")]
    pub key_custody: CaKeyCustody,
    /// Where the custodian put the key. A Vault path under its mount; `None`
    /// for database custody, whose locator is the row itself.
    pub key_locator: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// What a CA row with no recorded custodian means.
///
/// Every row written before custody was a concept holds its key sealed into
/// itself, so `Database` is the only reading that finds those keys. A row that
/// genuinely has no key is `External`, and the v45 migration distinguishes the
/// two by whether `encrypted_private_key` is present.
fn default_key_custody() -> CaKeyCustody {
    CaKeyCustody::Database
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
            .field("key_custody", &self.key_custody)
            .field("key_locator", &self.key_locator)
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
    /// Chosen by the service, not the repository.
    ///
    /// A custodian outside the database addresses the key *by CA id*, so the id
    /// has to exist before the key is stored — and the key has to be stored
    /// before the row, or a failed write leaves a CA certificate whose key is
    /// nowhere. Letting the repository mint the id made that ordering
    /// impossible to express.
    pub id: Uuid,
    pub organization_id: Uuid,
    pub subject: String,
    pub public_cert_pem: String,
    pub fingerprint: String,
    pub key_algorithm: KeyAlgorithm,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub encrypted_private_key: Option<Vec<u8>>,
    pub key_custody: CaKeyCustody,
    pub key_locator: Option<String>,
}

/// Import an externally-generated CA (BYOK).
///
/// The other way a CA comes to exist. Generation makes a key AXIAM chose;
/// this takes one an organization already has — from an offline root, an
/// existing internal PKI, or an HSM ceremony — and puts AXIAM in the chain
/// rather than at the top of it.
///
/// `private_key_pem` is optional, and the two cases are genuinely different
/// rather than one being a degraded form of the other:
///
/// * **With a key**, AXIAM takes custody of it (Vault, or sealed into the row)
///   and can issue certificates against this CA.
/// * **Without one**, the certificate is a trust anchor and nothing more.
///   `/api/v1/certificates` cannot sign against it, and says so rather than
///   failing at the point of use.
#[derive(Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ImportCaCertificate {
    #[serde(default)]
    pub organization_id: Uuid,
    /// PEM-encoded CA certificate.
    pub public_cert_pem: String,
    /// PEM-encoded private key, if AXIAM is to hold it.
    ///
    /// Write-only: it goes to the configured custodian on the way in and is
    /// never returned by any endpoint.
    #[serde(default, skip_serializing)]
    pub private_key_pem: Option<String>,
}

/// Manual `Debug` (SECHRD-09 / D-06): `#[serde(skip_serializing)]` governs
/// `Serialize` only, and this struct reaches a `{:?}` in any handler-level
/// tracing span.
impl std::fmt::Debug for ImportCaCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportCaCertificate")
            .field("organization_id", &self.organization_id)
            .field("public_cert_pem", &self.public_cert_pem)
            .field(
                "private_key_pem",
                &self.private_key_pem.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
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
