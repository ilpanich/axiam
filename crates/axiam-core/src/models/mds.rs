//! FIDO Alliance Metadata Service (MDS3) domain models (X3, D1/D5/D8).
//!
//! These types are the *parsed, storage-shaped* view of a verified MDS3
//! BLOB — the cryptographic verification and JWT/JSON parsing that produces
//! them live in `axiam-pki::mds` (PKI owns trust-anchor concerns), but the
//! resulting domain types live here per the repo's convention that
//! `axiam-core` holds every model a `Repository` trait moves in or out of
//! storage.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// FIDO certification level, as recorded in an MDS `statusReports` entry's
/// `FIDO_CERTIFIED*` status.
///
/// Variant order is significant: `derive(PartialOrd, Ord)` gives `L1 < L1Plus
/// < L2 < L2Plus < L3 < L3Plus`, which `WebauthnAttestationPolicy::evaluate`
/// (D8 step 9) relies on directly for the `min_certification` boundary
/// check (`entry_level >= policy_min`).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    utoipa::ToSchema,
)]
pub enum CertificationLevel {
    L1,
    L1Plus,
    L2,
    L2Plus,
    L3,
    L3Plus,
}

/// The `status` field of a FIDO MDS `StatusReport`
/// (<https://fidoalliance.org/metadata/metadata-schema/#authenticatorstatus-enum>).
///
/// `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]` maps every unit variant
/// onto the exact wire string the MDS schema uses (with three explicit
/// renames for the `L1plus`/`L2plus`/`L3plus` variants, which are not
/// SCREAMING_SNAKE — the schema itself is inconsistent here). `Other` is a
/// deliberate, fail-safe catch-all (`#[serde(other)]`) for status values not
/// in the schema at the time this was written: an entry whose status we
/// don't recognize is treated as neither FIDO-certified nor
/// compromised/revoked by every helper below, rather than erroring the whole
/// ingestion run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MdsAuthenticatorStatus {
    NotFidoCertified,
    FidoCertified,
    UserVerificationBypass,
    AttestationKeyCompromise,
    UserKeyRemoteCompromise,
    UserKeyPhysicalCompromise,
    UpdateAvailable,
    Revoked,
    SelfAssertionSubmitted,
    #[serde(rename = "FIDO_CERTIFIED_L1")]
    FidoCertifiedL1,
    #[serde(rename = "FIDO_CERTIFIED_L1plus")]
    FidoCertifiedL1Plus,
    #[serde(rename = "FIDO_CERTIFIED_L2")]
    FidoCertifiedL2,
    #[serde(rename = "FIDO_CERTIFIED_L2plus")]
    FidoCertifiedL2Plus,
    #[serde(rename = "FIDO_CERTIFIED_L3")]
    FidoCertifiedL3,
    #[serde(rename = "FIDO_CERTIFIED_L3plus")]
    FidoCertifiedL3Plus,
    /// Fail-safe catch-all for any status string not covered above.
    #[serde(other)]
    Other,
}

impl MdsAuthenticatorStatus {
    /// `true` for the compromise/revocation statuses D8 step 7 treats as
    /// **sticky** — any occurrence anywhere in an entry's `statusReports`
    /// history counts, regardless of a later benign report.
    pub fn is_compromise_or_revoked(self) -> bool {
        matches!(
            self,
            Self::Revoked
                | Self::UserKeyPhysicalCompromise
                | Self::UserKeyRemoteCompromise
                | Self::AttestationKeyCompromise
        )
    }

    /// The `CertificationLevel` this status represents, if it is one of the
    /// `FIDO_CERTIFIED*` family. Bare `FIDO_CERTIFIED` (no level suffix) is
    /// FIDO's own Level 1 designation, so it maps to `CertificationLevel::L1`.
    pub fn certification_level(self) -> Option<CertificationLevel> {
        match self {
            Self::FidoCertified | Self::FidoCertifiedL1 => Some(CertificationLevel::L1),
            Self::FidoCertifiedL1Plus => Some(CertificationLevel::L1Plus),
            Self::FidoCertifiedL2 => Some(CertificationLevel::L2),
            Self::FidoCertifiedL2Plus => Some(CertificationLevel::L2Plus),
            Self::FidoCertifiedL3 => Some(CertificationLevel::L3),
            Self::FidoCertifiedL3Plus => Some(CertificationLevel::L3Plus),
            _ => None,
        }
    }

    /// `true` for any `FIDO_CERTIFIED*` status (any level, including the
    /// bare `FIDO_CERTIFIED`).
    pub fn is_fido_certified(self) -> bool {
        self.certification_level().is_some()
    }
}

/// One entry in an MDS `StatusReport` array — the certification/compromise
/// history of an authenticator model.
///
/// `rename_all = "camelCase"` makes this deserialize directly from the raw
/// FIDO MDS3 wire JSON (`effectiveDate`, `certificationDescriptor`) — the
/// same struct doubles as both the storage-shaped domain type and the raw
/// wire type, since its shape happens to already match.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MdsStatusReport {
    pub status: MdsAuthenticatorStatus,
    /// ISO 8601 date (`YYYY-MM-DD`) the status took effect, kept as the raw
    /// MDS string rather than parsed — it is display/audit metadata only,
    /// never compared against `now`.
    pub effective_date: Option<String>,
    /// Free-text certification descriptor (e.g. a lab report reference),
    /// present on some `FIDO_CERTIFIED*` reports.
    pub certification_descriptor: Option<String>,
}

/// A parsed FIDO MDS3 metadata entry, keyed by AAGUID.
///
/// UAF/U2F entries (keyed by `aaid`/`attestationCertificateKeyIdentifiers`
/// instead of `aaguid`) never reach this type — `axiam-pki::mds` skips them
/// during payload parsing and logs the skipped count (D1).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MdsEntry {
    pub aaguid: Uuid,
    /// `metadataStatement.description` — human-readable authenticator model
    /// name, captured at registration time as `authenticator_name` (D6).
    pub description: Option<String>,
    /// `metadataStatement.attestationRootCertificates` (base64-encoded DER,
    /// as MDS ships them) — the seed material for the per-tenant
    /// `AttestationCaList` webauthn-rs verifies registrations against (D7).
    #[serde(default)]
    pub attestation_root_certificates: Vec<String>,
    #[serde(default)]
    pub status_reports: Vec<MdsStatusReport>,
    /// `timeOfLastStatusChange`, kept as the raw MDS date string (display
    /// metadata only, same rationale as `MdsStatusReport::effective_date`).
    pub time_of_last_status_change: Option<String>,
}

impl MdsEntry {
    /// D8 step 7: sticky compromise/revocation check across the *entire*
    /// status history, not just the latest report.
    pub fn is_compromised_or_revoked(&self) -> bool {
        self.status_reports
            .iter()
            .any(|r| r.status.is_compromise_or_revoked())
    }

    /// D8 step 8: `true` if any status report is a `FIDO_CERTIFIED*` status
    /// (any level).
    pub fn is_fido_certified(&self) -> bool {
        self.status_reports
            .iter()
            .any(|r| r.status.is_fido_certified())
    }

    /// D8 step 9: the **highest** `FIDO_CERTIFIED*` level appearing anywhere
    /// in the status history, or `None` if the entry was never certified.
    pub fn highest_certification_level(&self) -> Option<CertificationLevel> {
        self.status_reports
            .iter()
            .filter_map(|r| r.status.certification_level())
            .max()
    }
}

/// Metadata about the last successfully verified MDS3 BLOB (server-global,
/// single row — D10).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MdsBlobMeta {
    /// The BLOB's `no` (serial number) claim — monotonically increasing;
    /// drives rollback protection (D4 step 8).
    pub no: i64,
    /// The BLOB's `nextUpdate` claim (`YYYY-MM-DD`).
    pub next_update: chrono::NaiveDate,
    pub entry_count: u64,
    pub last_refreshed_at: chrono::DateTime<chrono::Utc>,
    /// `true` when `next_update` is in the past as of the last refresh
    /// (D4 step 9). Staleness never hard-fails ingestion — it is logged at
    /// WARN and left for policy/ops to act on.
    pub stale: bool,
}
