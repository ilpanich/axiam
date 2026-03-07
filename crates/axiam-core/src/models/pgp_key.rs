//! OpenPGP key domain models.
//!
//! AXIAM manages two kinds of PGP keys:
//! - **AuditSigning**: server-side signing keys with encrypted private keys
//!   stored for batch-signing audit log entries.
//! - **Export**: zero-knowledge keys where only the public key is stored.
//!   The private key is returned once on generation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The purpose of an OpenPGP key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub enum PgpKeyPurpose {
    /// Server-side audit log signing (encrypted private key stored).
    AuditSigning,
    /// PGP-encrypted data exports (zero-knowledge, public key only).
    Export,
}

/// Status of an OpenPGP key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub enum PgpKeyStatus {
    Active,
    Revoked,
}

/// Key algorithm for OpenPGP keys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub enum PgpKeyAlgorithm {
    Rsa4096,
    Ed25519,
}

/// An OpenPGP key stored by AXIAM.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PgpKey {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub purpose: PgpKeyPurpose,
    pub public_key_armored: String,
    /// OpenPGP key fingerprint (hex).
    pub fingerprint: String,
    pub algorithm: PgpKeyAlgorithm,
    pub status: PgpKeyStatus,
    /// AES-256-GCM encrypted private key (only for AuditSigning keys).
    #[serde(skip_serializing)]
    #[schema(read_only)]
    pub encrypted_private_key: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
}

/// User-facing DTO for generating a new PGP key.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreatePgpKey {
    #[serde(default)]
    pub tenant_id: Uuid,
    pub name: String,
    pub purpose: PgpKeyPurpose,
    pub algorithm: PgpKeyAlgorithm,
    /// Email for the OpenPGP User ID.
    pub email: String,
}

/// All fields required to store a PGP key in the database.
#[derive(Debug, Clone)]
pub struct StorePgpKey {
    pub tenant_id: Uuid,
    pub name: String,
    pub purpose: PgpKeyPurpose,
    pub public_key_armored: String,
    pub fingerprint: String,
    pub algorithm: PgpKeyAlgorithm,
    pub encrypted_private_key: Option<Vec<u8>>,
}

/// Response returned when a PGP key is generated.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct GeneratedPgpKey {
    #[serde(flatten)]
    pub key: PgpKey,
    /// ASCII-armored private key — returned only on generation.
    pub private_key_armored: String,
}

/// A signed batch of audit log entries.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SignedAuditBatch {
    pub batch_id: Uuid,
    pub tenant_id: Uuid,
    pub signing_key_id: Uuid,
    pub entry_ids: Vec<Uuid>,
    /// Detached ASCII-armored PGP signature.
    pub signature_armored: String,
    pub signed_at: DateTime<Utc>,
}

/// Request body for signing an audit batch.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SignAuditBatchRequest {
    pub entry_ids: Vec<Uuid>,
}

/// Result of encrypting data with a PGP public key.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EncryptedExport {
    pub recipient_key_id: Uuid,
    /// ASCII-armored PGP encrypted data.
    pub ciphertext_armored: String,
}

/// Request body for encrypting data.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EncryptRequest {
    /// Base64-encoded plaintext to encrypt.
    pub data_base64: String,
}
