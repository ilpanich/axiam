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
    /// The tenant this CA signs for, when it is a tenant signing CA.
    ///
    /// `None` for an organization-level CA — the trust anchor, and the only
    /// kind that existed before tenant signing CAs. `Some` for an intermediate
    /// created under one, which exists so a tenant's user, service and device
    /// certificates chain through a CA that can be revoked and replaced
    /// without touching the anchor the rest of the estate trusts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<Uuid>,
    /// The CA in this organization that signed this one.
    ///
    /// `None` for an organization-level CA, which is either self-signed or
    /// imported and has no parent inside AXIAM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_ca_id: Option<Uuid>,
    /// The certificate subject (e.g., `CN=ACME Corp Root CA`).
    pub subject: String,
    /// PEM-encoded public certificate.
    ///
    /// The certificate that *signs*, which under `vault_pki` custody is the
    /// intermediate rather than the root beneath which it was created.
    pub public_cert_pem: String,
    /// The issuers above [`Self::public_cert_pem`], concatenated PEM, nearest
    /// issuer first and the root last.
    ///
    /// `None` for a CA that is its own root, which is every CA AXIAM generated
    /// before Vault's PKI engine was an option. Present for a `vault_pki` CA,
    /// where it is the only copy of the root certificate anything outside Vault
    /// will ever see — a relying party cannot validate an AXIAM-issued leaf
    /// without it, and `root/generate/internal` returns it exactly once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<String>,
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
            .field("tenant_id", &self.tenant_id)
            .field("parent_ca_id", &self.parent_ca_id)
            .field("subject", &self.subject)
            .field("public_cert_pem", &self.public_cert_pem)
            .field("chain_pem", &self.chain_pem)
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
    /// Common name for the signing intermediate, under `vault_pki` custody.
    ///
    /// Ignored by every other custodian, which generates one self-signed CA and
    /// has no second certificate to name. Defaults to the root's subject with
    /// `Intermediate Authority` appended, which is what HashiCorp's own PKI
    /// walkthrough calls it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediate_subject: Option<String>,
    /// Validity of the signing intermediate, in days. Defaults to the root's.
    ///
    /// Vault caps it to the root's own expiry regardless, so asking for more
    /// than the root has is not an error — it is quietly shortened, and the
    /// stored record describes what came back rather than what was asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediate_validity_days: Option<u32>,
    /// Issue directly from the generated root instead of creating an
    /// intermediate. `vault_pki` custody only.
    ///
    /// Off by default, and the default is the safer one: a root that signs only
    /// one intermediate can have that intermediate revoked and replaced without
    /// redistributing the trust anchor, while a root that signs leaves directly
    /// cannot be rotated without touching every relying party.
    #[serde(default)]
    pub issue_from_root: bool,
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
    /// Set only for a tenant signing CA. See [`CaCertificate::tenant_id`].
    pub tenant_id: Option<Uuid>,
    /// Set only for a CA signed by another CA in this organization. See
    /// [`CaCertificate::parent_ca_id`].
    pub parent_ca_id: Option<Uuid>,
    pub subject: String,
    pub public_cert_pem: String,
    /// The issuers above `public_cert_pem`, concatenated PEM. See
    /// [`CaCertificate::chain_pem`].
    pub chain_pem: Option<String>,
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

/// Create a tenant signing CA, with AXIAM generating the key.
///
/// The tenant counterpart to [`CreateCaCertificate`]. The organization CA named
/// by `parent_ca_id` signs it, and the resulting intermediate is what the
/// tenant's user, service and device certificates are issued from — so a
/// tenant's issuance can be revoked, rotated or handed to a different operator
/// without redistributing the anchor every relying party trusts.
///
/// `key_algorithm` is the *intermediate's* own key, not the parent's; the two
/// need not match, and an Ed25519 intermediate under an RSA root is a perfectly
/// ordinary shape.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateIntermediateCa {
    /// Taken from the path, not the body.
    #[serde(default)]
    pub organization_id: Uuid,
    /// Taken from the path, not the body.
    #[serde(default)]
    pub tenant_id: Uuid,
    /// The organization CA that signs it. Must be Active, in its validity
    /// window, and hold a key AXIAM can sign with.
    pub parent_ca_id: Uuid,
    /// The intermediate's subject (e.g., `CN=ACME R&D Signing CA`).
    pub subject: String,
    pub key_algorithm: KeyAlgorithm,
    /// Validity duration in days. Capped to the parent's own expiry — an
    /// intermediate that outlives its issuer is a certificate nothing accepts.
    pub validity_days: u32,
}

/// Sign a certificate signing request the tenant produced elsewhere.
///
/// The BYOK counterpart to [`CreateIntermediateCa`]: the private key is
/// generated by whoever made the CSR — an offline ceremony, an HSM, a
/// tenant-side tool — and never reaches AXIAM at all. What comes back is a
/// certificate and its chain, and the response carries no `private_key_pem`
/// because there is none to carry.
///
/// The CSR's subject is what the certificate says. Its requested extensions are
/// not: AXIAM decides that this is a CA, and constrains it to sign leaves only.
#[derive(Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SignIntermediateCsr {
    /// Taken from the path, not the body.
    #[serde(default)]
    pub organization_id: Uuid,
    /// Taken from the path, not the body.
    #[serde(default)]
    pub tenant_id: Uuid,
    /// The organization CA that signs it.
    pub parent_ca_id: Uuid,
    /// PEM-encoded PKCS#10 certificate signing request.
    pub csr_pem: String,
    /// Validity duration in days. Capped to the parent's own expiry.
    pub validity_days: u32,
}

/// A CSR is public by construction — it carries a public key and a signature
/// proving possession of the private one — but it is bulky and appears in
/// handler-level tracing spans, so it is elided rather than redacted.
impl std::fmt::Debug for SignIntermediateCsr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignIntermediateCsr")
            .field("organization_id", &self.organization_id)
            .field("tenant_id", &self.tenant_id)
            .field("parent_ca_id", &self.parent_ca_id)
            .field("csr_pem", &format_args!("[{} bytes]", self.csr_pem.len()))
            .field("validity_days", &self.validity_days)
            .finish()
    }
}

/// Response returned when a CA certificate is generated.
///
/// Includes the private key PEM, which is returned **once** and never
/// stored or retrievable again — when the custodian produced one at all. Under
/// `vault_pki` custody the key was born inside Vault and there is nothing to
/// return, which is the point of that custodian rather than a shortcoming of
/// this response.
#[derive(Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct GeneratedCaCertificate {
    #[serde(flatten)]
    pub certificate: CaCertificate,
    /// PEM-encoded private key — returned only on generation, and only when
    /// there is one to return.
    ///
    /// Absent under `vault_pki` custody, where the key was generated inside
    /// Vault and no API exports it. The field is omitted rather than sent as
    /// `null` so a client that has always read it keeps working unchanged for
    /// every custodian that does produce a key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_pem: Option<String>,
}

/// Manual `Debug` impl (SECHRD-09 / D-06): redacts `private_key_pem` (raw
/// key material returned only once on generation); delegates to
/// `CaCertificate`'s own redacting `Debug` for the nested `certificate` field.
impl std::fmt::Debug for GeneratedCaCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedCaCertificate")
            .field("certificate", &self.certificate)
            // `Option`-aware rather than an unconditional `[REDACTED]`: a
            // `vault_pki` CA has no key, and printing the redaction marker for
            // one would say a key was withheld when none exists.
            .field(
                "private_key_pem",
                &self.private_key_pem.as_ref().map(|_| "[REDACTED]"),
            )
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
    /// The issuing chain, concatenated PEM, nearest issuer first.
    ///
    /// Present only when the signer returned one — which is the `vault_pki`
    /// case, where the root's certificate exists nowhere a client could fetch
    /// it from. For a CA AXIAM signed with itself the chain is the CA
    /// certificate, which `GET .../ca-certificates/{id}` already serves, so the
    /// field is omitted rather than restating it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<String>,
    /// PEM-encoded private key — returned only on generation.
    pub private_key_pem: String,
}
