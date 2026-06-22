//! GDPR data-subject rights domain models.
//!
//! Covers consent tracking (REQ-8), account deletion with grace period (D-08),
//! async data export (D-12/D-13), and erasure proof (D-06).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// -----------------------------------------------------------------------
// Consent (REQ-8)
// -----------------------------------------------------------------------

/// An immutable consent record created at registration or whenever a user
/// explicitly accepts a terms/policy version.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Consent {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    /// What the user consented to (e.g. `"terms_of_service"`, `"privacy_policy"`).
    pub consent_type: String,
    /// Version string of the document (e.g. `"2026-01-01"`).
    pub version: String,
    pub accepted_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Input for recording a new consent.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateConsent {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub consent_type: String,
    pub version: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

// -----------------------------------------------------------------------
// Account Deletion Request (D-08/D-09)
// -----------------------------------------------------------------------

/// Status of an account deletion request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccountDeletionStatus {
    Pending,
    Cancelled,
    Completed,
}

/// An account deletion request with cancel-token (D-09).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AccountDeletion {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    /// SHA-256 of the opaque cancel token. Raw token is returned once at creation.
    pub cancel_token_hash: String,
    pub scheduled_purge_at: DateTime<Utc>,
    pub status: AccountDeletionStatus,
    pub created_at: DateTime<Utc>,
}

/// Input for creating a deletion request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAccountDeletion {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    /// SHA-256 hex of the cancel token. Caller generates and hashes the token.
    pub cancel_token_hash: String,
    pub scheduled_purge_at: DateTime<Utc>,
}

// -----------------------------------------------------------------------
// Export Job (D-12/D-13)
// -----------------------------------------------------------------------

/// Status of a GDPR data-export job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExportJobStatus {
    Queued,
    Ready,
    Downloaded,
    Expired,
    /// Processing failed; the job may be re-queued for retry (CQ-B38/REQ-14 AC-5).
    Failed,
}

/// A GDPR Art. 15 data-export job.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ExportJob {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub status: ExportJobStatus,
    /// AES-256-GCM encrypted JSON blob stored in DB (or file path on disk).
    pub encrypted_blob: Option<String>,
    pub file_path: Option<String>,
    pub blob_nonce: Option<String>,
    /// SHA-256 of the single-use download token.
    pub download_token_hash: Option<String>,
    /// Expiry of the download link (D-13: 24-hour TTL).
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Input for creating a new queued export job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateExportJob {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
}

// -----------------------------------------------------------------------
// Erasure Proof (D-06)
// -----------------------------------------------------------------------

/// PII-free record proving that an erasure happened (GDPR accountability).
/// Contains only the pseudonym and timestamp — no identifying data.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ErasureProof {
    pub id: Uuid,
    pub pseudonym: String,
    pub tenant_id: Uuid,
    pub erased_at: DateTime<Utc>,
}

/// Input for creating an erasure proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateErasureProof {
    pub pseudonym: String,
    pub tenant_id: Uuid,
    pub erased_at: DateTime<Utc>,
}
