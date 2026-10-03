//! The directory sync job's vocabulary (G-3, T23.3.5, D-31): its audit actions
//! and the per-tenant state it keeps between runs.
//!
//! What the job does is written once, in `axiam_directory::sync`. What lives
//! here is what other crates must agree on: the storage shape of the state row
//! (schema v75) and the action names that appear in the audit log, which
//! operators filter on and the threat model refers to.
//!
//! **No row carries a name, an address or a DN.** Every audit row the job
//! writes names accounts by id and directory entries by their immutable
//! identifier, and says *why*, never *who*.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Audit action: the sync job set a directory account `Inactive` because its
/// entry has vanished from the directory or the directory has disabled it
/// (D-31). `metadata.reason` is `vanished` or `disabled`; `metadata.run` is
/// `full` or `incremental`.
pub const AUDIT_ACCOUNT_DEACTIVATED: &str = "directory.account_deactivated";
/// Audit action: an account that is `Inactive` in AXIAM has an entry that is
/// present and enabled in the directory. **Sync never re-enables** (D-31), so
/// the row says that an administrator must act if the account should be live
/// again. Written once per account until the situation changes.
pub const AUDIT_ACCOUNT_REAPPEARED: &str = "directory.account_reappeared";
/// Audit action: a username or email change the directory made was **not**
/// applied because it would collide with another account (D-28, D-31).
pub const AUDIT_SYNC_ATTRIBUTE_SKIPPED: &str = "directory.sync_attribute_skipped";
/// Audit action: the sync job skipped one account and changed nothing for it —
/// its group mapping could not be applied, or its entry was ambiguous.
pub const AUDIT_SYNC_USER_SKIPPED: &str = "directory.sync_user_skipped";
/// Audit action: applying the group mapping changed a user's memberships. The
/// same action the sign-in path writes (`metadata.source` tells them apart).
pub const AUDIT_GROUPS_MAPPED: &str = "directory.groups_mapped";
/// Audit action: a full run would have deactivated more of the tenant's
/// directory accounts than the safety valve allows and **applied nothing**
/// (D-31).
pub const AUDIT_SYNC_SAFETY_VALVE: &str = "directory.sync_safety_valve";
/// Audit action: one row per full run, with counts only.
pub const AUDIT_SYNC_RUN: &str = "directory.sync_run";

/// The most accounts the state row remembers having reported as re-enabled.
pub const REPORTED_USER_IDS_MAX: usize = 5_000;

/// How a tenant's last sync attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectorySyncResult {
    /// Every account was handled.
    Ok,
    /// The run completed but skipped at least one account; the next attempt is
    /// a full run.
    Partial,
    /// The run could not be performed (directory unreachable, misconfigured,
    /// deadline) and changed nothing, or stopped part-way.
    Failed,
    /// A full run tripped the safety valve and applied nothing.
    SafetyValve,
}

impl DirectorySyncResult {
    /// The storage spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::SafetyValve => "safety_valve",
        }
    }

    /// Parse the storage spelling; unknown values are refused, never defaulted.
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "ok" => Some(Self::Ok),
            "partial" => Some(Self::Partial),
            "failed" => Some(Self::Failed),
            "safety_valve" => Some(Self::SafetyValve),
            _ => None,
        }
    }
}

/// What the sync job remembers about one tenant between runs (schema v75, one
/// row per tenant, deleted with the tenant).
///
/// It holds **no personal data**: a watermark, the identity of the server the
/// watermark belongs to, timestamps, and account ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectorySyncState {
    /// The owning tenant.
    pub tenant_id: Uuid,
    /// Where the next incremental run starts: a generalized-time value for
    /// `modifyTimestamp` (OpenLDAP), a decimal USN for `uSNChanged` (AD).
    /// `None` means there is no usable watermark, so the next run is a full one.
    pub watermark: Option<String>,
    /// The server the watermark belongs to: AD's `dsServiceName`, which names
    /// the domain controller whose USNs the watermark counts. `None` for
    /// directories whose change attribute is a timestamp.
    pub server_identity: Option<String>,
    /// The next run must be a full one: a previous run skipped an account or
    /// hit a bound.
    pub full_required: bool,
    /// When the last attempt started, successful or not; the incremental
    /// schedule counts from here.
    pub last_attempt_at: Option<DateTime<Utc>>,
    /// When the last **complete** full run finished; the nightly schedule counts
    /// from here.
    pub last_full_run_at: Option<DateTime<Utc>>,
    /// How the last attempt ended.
    pub last_result: Option<DirectorySyncResult>,
    /// Accounts already reported as `Inactive` while the directory shows them
    /// present and enabled, so the audit log says it once, not nightly.
    pub reported_user_ids: Vec<Uuid>,
    /// When the row was last written.
    pub updated_at: DateTime<Utc>,
}

impl DirectorySyncState {
    /// The state of a tenant that has never been synced.
    #[must_use]
    pub fn new(tenant_id: Uuid) -> Self {
        Self {
            tenant_id,
            watermark: None,
            server_identity: None,
            full_required: false,
            last_attempt_at: None,
            last_full_run_at: None,
            last_result: None,
            reported_user_ids: Vec::new(),
            updated_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_result_spelling_round_trips_and_refuses_unknowns() {
        for result in [
            DirectorySyncResult::Ok,
            DirectorySyncResult::Partial,
            DirectorySyncResult::Failed,
            DirectorySyncResult::SafetyValve,
        ] {
            assert_eq!(
                DirectorySyncResult::from_wire(result.as_str()),
                Some(result)
            );
        }
        assert_eq!(DirectorySyncResult::from_wire("OK"), None);
        assert_eq!(DirectorySyncResult::from_wire(""), None);
    }

    #[test]
    fn a_new_state_has_nothing_to_resume_from() {
        let state = DirectorySyncState::new(Uuid::nil());
        assert!(state.watermark.is_none() && state.last_attempt_at.is_none());
        assert!(!state.full_required && state.reported_user_ids.is_empty());
    }
}
