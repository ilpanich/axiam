//! Per-tenant WebAuthn attestation policy and the pure policy decision
//! function (X3, D5/D6/D8).
//!
//! This does **not** live inside `SecuritySettings`
//! (`crate::models::settings`): that model's org/tenant inheritance is
//! validated "tenant override may only be more restrictive than the org
//! baseline", which requires a total order on every field. AAGUID
//! allow/block lists have no such order — comparing two arbitrary lists for
//! "more restrictive" has no obviously-correct semantics — so a bespoke
//! comparator would have to be invented with no clear right answer. Org-level
//! baselining of the attestation policy is deferred; this ships tenant-only
//! for now (see the admin guide for the documented trade-off).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AxiamError, AxiamResult};
use crate::models::mds::MdsEntry;

// ---------------------------------------------------------------------------
// Policy fields
// ---------------------------------------------------------------------------

/// What attestation conveyance a registration ceremony requests, and whether
/// the policy is enforced at all.
///
/// `None` is the default and reproduces today's behavior byte-for-byte:
/// `evaluate` allows every registration unconditionally, with no MDS lookup
/// (D8 step 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttestationMode {
    #[default]
    None,
    Indirect,
    DirectRequired,
}

/// What to do with an AAGUID that has no MDS entry (i.e. FIDO Alliance has
/// no metadata for it — not necessarily malicious, MDS coverage is
/// incomplete for some legitimate authenticators).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnknownAaguidAction {
    Allow,
    Deny,
}

/// Per-tenant WebAuthn attestation policy (D5). One row per tenant; an
/// absent row means [`WebauthnAttestationPolicy::default`], which is
/// today's behavior unchanged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct WebauthnAttestationPolicy {
    pub mode: AttestationMode,
    /// Require *some* `FIDO_CERTIFIED*` status, any level. Independent of
    /// (and checked before) `min_certification`.
    pub require_fido_certified: bool,
    pub min_certification: Option<super::mds::CertificationLevel>,
    /// `None` = every AAGUID is allowed except `blocked_aaguids`.
    ///
    /// `Some(vec![])` is a deliberate "nothing may register" policy and is
    /// accepted as such: `evaluate` denies every AAGUID against an empty
    /// allow-list. Nothing rejects it, precisely because the failure
    /// direction is safe — a client that sends `[]` when it meant `null`
    /// gets a locked-down tenant, which is visible immediately, rather than
    /// an open one, which is not.
    pub allowed_aaguids: Option<Vec<Uuid>>,
    #[serde(default)]
    pub blocked_aaguids: Vec<Uuid>,
    /// Deny registration if the MDS entry has ever reported `REVOKED` or any
    /// `*_COMPROMISE` status (sticky — D8 step 7).
    pub block_revoked_status: bool,
    /// What to do with an AAGUID MDS has no metadata for.
    ///
    /// `None` means "use the default for this `mode`", which is **deny under
    /// `direct_required` and allow otherwise** — see
    /// [`WebauthnAttestationPolicy::effective_unknown_aaguid`]. It is
    /// deliberately an `Option` rather than a plain value with a fixed
    /// default: a single struct-level default cannot be correct for both
    /// modes, and the one that is wrong is wrong in the dangerous direction.
    /// A tenant that opts into the strictest posture and does not mention
    /// this field would otherwise admit every authenticator FIDO has no
    /// metadata for — silently, with no error and nothing in the audit trail
    /// to suggest the policy was not doing what its name says.
    ///
    /// An explicit `Some(_)` always wins, in both directions: an admin who
    /// deliberately wants `direct_required` *and* lenient handling of
    /// unlisted authenticators can still say so.
    #[serde(default)]
    pub unknown_aaguid: Option<UnknownAaguidAction>,
}

impl Default for WebauthnAttestationPolicy {
    /// `mode: None` makes every other field inert (D8 step 1 short-circuits
    /// before any of them are read), so this reproduces today's behavior
    /// exactly.
    fn default() -> Self {
        Self {
            mode: AttestationMode::None,
            require_fido_certified: false,
            min_certification: None,
            allowed_aaguids: None,
            blocked_aaguids: Vec::new(),
            block_revoked_status: true,
            // `None` = derive from mode, so this default stays correct if a
            // tenant later switches mode without revisiting this field.
            unknown_aaguid: None,
        }
    }
}

impl WebauthnAttestationPolicy {
    /// The unknown-AAGUID action actually applied, resolving `None` to the
    /// mode's default: **deny** under `direct_required`, **allow** otherwise.
    ///
    /// This is the only place the mode-dependent default lives; `evaluate`
    /// calls it rather than reading the field directly, so no caller can
    /// accidentally read an unset policy as "allow".
    pub fn effective_unknown_aaguid(&self) -> UnknownAaguidAction {
        self.unknown_aaguid.unwrap_or(match self.mode {
            AttestationMode::DirectRequired => UnknownAaguidAction::Deny,
            AttestationMode::None | AttestationMode::Indirect => UnknownAaguidAction::Allow,
        })
    }
}

/// Validate internal invariants of an attestation policy (D5).
///
/// `require_fido_certified`/`min_certification` are meaningless when
/// `mode == None` — no attestation is ever requested, so there is nothing to
/// certify — and are rejected as a config error rather than silently
/// ignored, so an admin who sets them doesn't believe they are enforced when
/// they are not.
pub fn validate_attestation_policy(policy: &WebauthnAttestationPolicy) -> AxiamResult<()> {
    if policy.mode == AttestationMode::None {
        let mut violations = Vec::new();
        if policy.require_fido_certified {
            violations.push("require_fido_certified cannot be enforced when mode is \"none\" (no attestation is requested)".to_string());
        }
        if policy.min_certification.is_some() {
            violations.push("min_certification cannot be enforced when mode is \"none\" (no attestation is requested)".to_string());
        }
        if !violations.is_empty() {
            return Err(AxiamError::Validation {
                message: violations.join("; "),
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Decision function (D8)
// ---------------------------------------------------------------------------

/// The attestation-relevant facts of a single registration attempt, resolved
/// by the caller before invoking [`evaluate`]. Pure input — no I/O, no
/// lookups happen inside `evaluate` itself.
#[derive(Debug, Clone, Copy)]
pub struct AttestationCandidate<'a> {
    pub aaguid: Option<Uuid>,
    /// The WebAuthn attestation statement format identifier (e.g. `"packed"`,
    /// `"none"`, `"tpm"`), when attestation was requested at all.
    pub attestation_format: Option<&'a str>,
    /// The resolved MDS entry for `aaguid`, if MDS has metadata for it.
    pub mds_entry: Option<&'a MdsEntry>,
}

/// Why [`evaluate`] denied a registration. Machine-readable — goes to the
/// audit record; the end user sees a fixed, non-specific message (D7/D11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttestationDenyReason {
    /// `mode == DirectRequired` and the attestation was absent or `"none"`.
    AttestationRequired,
    /// The AAGUID is in `blocked_aaguids` (beats `allowed_aaguids` — D8 step 4).
    AaguidBlocked,
    /// `allowed_aaguids` is `Some(list)` and the AAGUID is not in it.
    AaguidNotAllowed,
    /// The AAGUID has no MDS entry and `unknown_aaguid == Deny`.
    UnknownAuthenticator,
    /// The MDS entry has a sticky compromise/revocation status.
    AuthenticatorRevoked,
    /// `require_fido_certified` and the MDS entry has no `FIDO_CERTIFIED*` status.
    NotFidoCertified,
    /// `min_certification` and the MDS entry's highest certified level is below it.
    CertificationTooLow,
    /// T-153: the ingested MDS BLOB is further past its `nextUpdate` than
    /// `mds_max_stale_days` permits, so the metadata this decision would rest
    /// on is too old to be trusted.
    ///
    /// Distinct from the other reasons on purpose. Every one of those is a
    /// statement about the authenticator; this one is a statement about *our
    /// own* data being too old to make such a statement. An operator reading
    /// `AuthenticatorRevoked` should go look at the device, and one reading
    /// this should go look at their MDS refresh.
    MetadataStale,
}

/// The outcome of evaluating a [`WebauthnAttestationPolicy`] against an
/// [`AttestationCandidate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationDecision {
    Allow,
    Deny(AttestationDenyReason),
}

/// Evaluate an attestation policy against a single registration attempt
/// (D8). Pure function, no I/O — every input the decision needs is already
/// resolved in `candidate`.
///
/// The check order below is normative (D8) and every branch is exercised by
/// the tests in this module — do not reorder without updating both.
pub fn evaluate(
    policy: &WebauthnAttestationPolicy,
    candidate: &AttestationCandidate<'_>,
) -> AttestationDecision {
    use AttestationDecision::{Allow, Deny};
    use AttestationDenyReason::{
        AaguidBlocked, AaguidNotAllowed, AttestationRequired, AuthenticatorRevoked,
        CertificationTooLow, NotFidoCertified, UnknownAuthenticator,
    };

    // 1. mode == None -> Allow unconditionally. No MDS lookup, no other
    //    field is consulted — this is the "today's behavior" guarantee, and
    //    it holds even if e.g. blocked_aaguids happens to contain this
    //    AAGUID: no attestation was requested, so there is nothing to police.
    if policy.mode == AttestationMode::None {
        return Allow;
    }

    // 2. DirectRequired + absent/none attestation -> Deny(AttestationRequired).
    if policy.mode == AttestationMode::DirectRequired {
        let no_attestation = match candidate.attestation_format {
            None => true,
            Some(fmt) => fmt == "none",
        };
        if no_attestation {
            return Deny(AttestationRequired);
        }
    }

    // 3. AAGUID missing or nil -> treated as unknown from here on.
    let aaguid = candidate.aaguid.filter(|id| !id.is_nil());

    // 4. blocked_aaguids beats allowed_aaguids (deny-override posture,
    //    matching the engine-wide RBAC precedence —
    //    claude_dev/deny-override-design.md).
    if let Some(id) = aaguid
        && policy.blocked_aaguids.contains(&id)
    {
        return Deny(AaguidBlocked);
    }

    // 5. allowed_aaguids = Some(list) and the AAGUID is not in it (including
    //    an unknown/nil AAGUID, which can never be "in" an explicit list).
    if let Some(allowed) = &policy.allowed_aaguids {
        let in_list = aaguid.is_some_and(|id| allowed.contains(&id));
        if !in_list {
            return Deny(AaguidNotAllowed);
        }
    }

    // 6. No MDS entry: if we got here with allowed_aaguids = Some(..), step 5
    //    already proved the AAGUID is explicitly listed — an admin has
    //    vouched for it, so it is allowed regardless of unknown_aaguid.
    //    Otherwise fall back to the unknown_aaguid action.
    let Some(entry) = candidate.mds_entry else {
        let admin_vouched = match (&policy.allowed_aaguids, aaguid) {
            (Some(allowed), Some(id)) => allowed.contains(&id),
            _ => false,
        };
        if admin_vouched {
            return Allow;
        }
        return match policy.effective_unknown_aaguid() {
            UnknownAaguidAction::Allow => Allow,
            UnknownAaguidAction::Deny => Deny(UnknownAuthenticator),
        };
    };

    // 7. Sticky compromise/revocation: any occurrence anywhere in
    //    statusReports counts, regardless of a later benign report.
    if policy.block_revoked_status && entry.is_compromised_or_revoked() {
        return Deny(AuthenticatorRevoked);
    }

    // 8. require_fido_certified: any FIDO_CERTIFIED* status, any level.
    if policy.require_fido_certified && !entry.is_fido_certified() {
        return Deny(NotFidoCertified);
    }

    // 9. min_certification: highest FIDO_CERTIFIED* level must meet the bar.
    //    An entry that was never certified (`highest_certification_level()
    //    == None`) fails this unconditionally.
    if let Some(min) = policy.min_certification {
        let meets_bar = entry
            .highest_certification_level()
            .is_some_and(|level| level >= min);
        if !meets_bar {
            return Deny(CertificationTooLow);
        }
    }

    // 10. Nothing denied it.
    Allow
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::mds::{CertificationLevel, MdsAuthenticatorStatus, MdsStatusReport};

    fn uuid(n: u8) -> Uuid {
        Uuid::from_bytes([n; 16])
    }

    fn status(s: MdsAuthenticatorStatus) -> MdsStatusReport {
        MdsStatusReport {
            status: s,
            effective_date: None,
            certification_descriptor: None,
        }
    }

    fn entry_with_statuses(statuses: Vec<MdsAuthenticatorStatus>) -> MdsEntry {
        MdsEntry {
            aaguid: uuid(1),
            description: Some("Test Authenticator".into()),
            attestation_root_certificates: Vec::new(),
            status_reports: statuses.into_iter().map(status).collect(),
            time_of_last_status_change: None,
        }
    }

    fn candidate<'a>(
        aaguid: Option<Uuid>,
        format: Option<&'a str>,
        entry: Option<&'a MdsEntry>,
    ) -> AttestationCandidate<'a> {
        AttestationCandidate {
            aaguid,
            attestation_format: format,
            mds_entry: entry,
        }
    }

    // --- step 1: mode == None short-circuits everything ---

    #[test]
    fn mode_none_allows_unconditionally() {
        let policy = WebauthnAttestationPolicy::default();
        let c = candidate(None, None, None);
        assert_eq!(evaluate(&policy, &c), AttestationDecision::Allow);
    }

    #[test]
    fn mode_none_allows_even_with_blocked_aaguid_present() {
        // Intentional per D8: no attestation is requested under mode=none,
        // so there is nothing for blocked_aaguids to police.
        let id = uuid(2);
        let policy = WebauthnAttestationPolicy {
            blocked_aaguids: vec![id],
            ..WebauthnAttestationPolicy::default()
        };
        let c = candidate(Some(id), Some("none"), None);
        assert_eq!(evaluate(&policy, &c), AttestationDecision::Allow);
    }

    #[test]
    fn default_policy_is_todays_behavior() {
        let policy = WebauthnAttestationPolicy::default();
        assert_eq!(policy.mode, AttestationMode::None);
        let c = candidate(Some(uuid(9)), Some("none"), None);
        assert_eq!(evaluate(&policy, &c), AttestationDecision::Allow);
    }

    // --- step 2: DirectRequired needs real attestation ---

    #[test]
    fn direct_required_denies_absent_attestation() {
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::DirectRequired,
            ..WebauthnAttestationPolicy::default()
        };
        let c = candidate(Some(uuid(1)), None, None);
        assert_eq!(
            evaluate(&policy, &c),
            AttestationDecision::Deny(AttestationDenyReason::AttestationRequired)
        );
    }

    #[test]
    fn direct_required_denies_none_format() {
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::DirectRequired,
            ..WebauthnAttestationPolicy::default()
        };
        let c = candidate(Some(uuid(1)), Some("none"), None);
        assert_eq!(
            evaluate(&policy, &c),
            AttestationDecision::Deny(AttestationDenyReason::AttestationRequired)
        );
    }

    #[test]
    fn direct_required_with_real_attestation_and_no_entry_falls_through_to_unknown_action() {
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::DirectRequired,
            unknown_aaguid: Some(UnknownAaguidAction::Deny),
            ..WebauthnAttestationPolicy::default()
        };
        let c = candidate(Some(uuid(1)), Some("packed"), None);
        assert_eq!(
            evaluate(&policy, &c),
            AttestationDecision::Deny(AttestationDenyReason::UnknownAuthenticator)
        );
    }

    #[test]
    fn indirect_mode_does_not_require_attestation() {
        // Only DirectRequired triggers step 2 — Indirect with format "none"
        // (a passkey provider) proceeds to the rest of the checks.
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::Indirect,
            unknown_aaguid: Some(UnknownAaguidAction::Allow),
            ..WebauthnAttestationPolicy::default()
        };
        let c = candidate(Some(uuid(1)), Some("none"), None);
        assert_eq!(evaluate(&policy, &c), AttestationDecision::Allow);
    }

    // --- step 3: nil/missing AAGUID treated as unknown ---

    #[test]
    fn nil_aaguid_is_treated_as_unknown() {
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::Indirect,
            unknown_aaguid: Some(UnknownAaguidAction::Deny),
            ..WebauthnAttestationPolicy::default()
        };
        let c = candidate(Some(Uuid::nil()), Some("packed"), None);
        assert_eq!(
            evaluate(&policy, &c),
            AttestationDecision::Deny(AttestationDenyReason::UnknownAuthenticator)
        );
    }

    // --- step 4: blocklist beats allowlist ---

    #[test]
    fn blocked_aaguid_denies_even_when_also_allowed() {
        let id = uuid(3);
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::Indirect,
            allowed_aaguids: Some(vec![id]),
            blocked_aaguids: vec![id],
            ..WebauthnAttestationPolicy::default()
        };
        let c = candidate(Some(id), Some("packed"), None);
        assert_eq!(
            evaluate(&policy, &c),
            AttestationDecision::Deny(AttestationDenyReason::AaguidBlocked)
        );
    }

    // --- step 5: allowlist ---

    #[test]
    fn allowlist_denies_aaguid_not_in_list() {
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::Indirect,
            allowed_aaguids: Some(vec![uuid(5)]),
            ..WebauthnAttestationPolicy::default()
        };
        let c = candidate(Some(uuid(6)), Some("packed"), None);
        assert_eq!(
            evaluate(&policy, &c),
            AttestationDecision::Deny(AttestationDenyReason::AaguidNotAllowed)
        );
    }

    #[test]
    fn empty_allowlist_denies_everything() {
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::Indirect,
            allowed_aaguids: Some(vec![]),
            ..WebauthnAttestationPolicy::default()
        };
        let c = candidate(Some(uuid(7)), Some("packed"), None);
        assert_eq!(
            evaluate(&policy, &c),
            AttestationDecision::Deny(AttestationDenyReason::AaguidNotAllowed)
        );
    }

    #[test]
    fn allowlist_denies_unknown_aaguid_even_before_reaching_the_unknown_action() {
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::Indirect,
            allowed_aaguids: Some(vec![uuid(5)]),
            unknown_aaguid: Some(UnknownAaguidAction::Allow),
            ..WebauthnAttestationPolicy::default()
        };
        let c = candidate(None, Some("packed"), None);
        assert_eq!(
            evaluate(&policy, &c),
            AttestationDecision::Deny(AttestationDenyReason::AaguidNotAllowed)
        );
    }

    // --- step 6: no MDS entry, admin-vouched override + unknown_aaguid ---

    #[test]
    fn no_mds_entry_admin_vouched_allows_despite_deny_default() {
        let id = uuid(8);
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::DirectRequired,
            allowed_aaguids: Some(vec![id]),
            unknown_aaguid: Some(UnknownAaguidAction::Deny),
            ..WebauthnAttestationPolicy::default()
        };
        let c = candidate(Some(id), Some("packed"), None);
        assert_eq!(evaluate(&policy, &c), AttestationDecision::Allow);
    }

    #[test]
    fn no_mds_entry_unknown_action_allow() {
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::Indirect,
            unknown_aaguid: Some(UnknownAaguidAction::Allow),
            ..WebauthnAttestationPolicy::default()
        };
        let c = candidate(Some(uuid(9)), Some("packed"), None);
        assert_eq!(evaluate(&policy, &c), AttestationDecision::Allow);
    }

    #[test]
    fn no_mds_entry_unknown_action_deny() {
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::Indirect,
            unknown_aaguid: Some(UnknownAaguidAction::Deny),
            ..WebauthnAttestationPolicy::default()
        };
        let c = candidate(Some(uuid(9)), Some("packed"), None);
        assert_eq!(
            evaluate(&policy, &c),
            AttestationDecision::Deny(AttestationDenyReason::UnknownAuthenticator)
        );
    }

    // --- step 7: sticky compromise/revocation ---

    #[test]
    fn revoked_status_denies_when_block_revoked_status_true() {
        let entry = entry_with_statuses(vec![MdsAuthenticatorStatus::Revoked]);
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::Indirect,
            ..WebauthnAttestationPolicy::default()
        };
        let c = candidate(Some(entry.aaguid), Some("packed"), Some(&entry));
        assert_eq!(
            evaluate(&policy, &c),
            AttestationDecision::Deny(AttestationDenyReason::AuthenticatorRevoked)
        );
    }

    #[test]
    fn each_compromise_status_denies() {
        for compromise_status in [
            MdsAuthenticatorStatus::Revoked,
            MdsAuthenticatorStatus::UserKeyPhysicalCompromise,
            MdsAuthenticatorStatus::UserKeyRemoteCompromise,
            MdsAuthenticatorStatus::AttestationKeyCompromise,
        ] {
            let entry = entry_with_statuses(vec![compromise_status]);
            let policy = WebauthnAttestationPolicy {
                mode: AttestationMode::Indirect,
                ..WebauthnAttestationPolicy::default()
            };
            let c = candidate(Some(entry.aaguid), Some("packed"), Some(&entry));
            assert_eq!(
                evaluate(&policy, &c),
                AttestationDecision::Deny(AttestationDenyReason::AuthenticatorRevoked),
                "status {compromise_status:?} must deny"
            );
        }
    }

    #[test]
    fn compromise_status_is_sticky_despite_later_benign_report() {
        // Order matters not: a REVOKED anywhere in history counts, even if
        // it is followed by an update-available or self-assertion report.
        let entry = entry_with_statuses(vec![
            MdsAuthenticatorStatus::Revoked,
            MdsAuthenticatorStatus::UpdateAvailable,
            MdsAuthenticatorStatus::SelfAssertionSubmitted,
        ]);
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::Indirect,
            ..WebauthnAttestationPolicy::default()
        };
        let c = candidate(Some(entry.aaguid), Some("packed"), Some(&entry));
        assert_eq!(
            evaluate(&policy, &c),
            AttestationDecision::Deny(AttestationDenyReason::AuthenticatorRevoked)
        );
    }

    #[test]
    fn block_revoked_status_false_does_not_deny_revoked() {
        let entry = entry_with_statuses(vec![MdsAuthenticatorStatus::Revoked]);
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::Indirect,
            block_revoked_status: false,
            ..WebauthnAttestationPolicy::default()
        };
        let c = candidate(Some(entry.aaguid), Some("packed"), Some(&entry));
        assert_eq!(evaluate(&policy, &c), AttestationDecision::Allow);
    }

    // --- step 8: require_fido_certified ---

    #[test]
    fn require_fido_certified_denies_uncertified_entry() {
        let entry = entry_with_statuses(vec![MdsAuthenticatorStatus::NotFidoCertified]);
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::Indirect,
            require_fido_certified: true,
            ..WebauthnAttestationPolicy::default()
        };
        let c = candidate(Some(entry.aaguid), Some("packed"), Some(&entry));
        assert_eq!(
            evaluate(&policy, &c),
            AttestationDecision::Deny(AttestationDenyReason::NotFidoCertified)
        );
    }

    #[test]
    fn require_fido_certified_allows_certified_entry() {
        let entry = entry_with_statuses(vec![MdsAuthenticatorStatus::FidoCertified]);
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::Indirect,
            require_fido_certified: true,
            ..WebauthnAttestationPolicy::default()
        };
        let c = candidate(Some(entry.aaguid), Some("packed"), Some(&entry));
        assert_eq!(evaluate(&policy, &c), AttestationDecision::Allow);
    }

    // --- step 9: min_certification boundaries ---

    #[test]
    fn min_certification_denies_entry_never_certified() {
        let entry = entry_with_statuses(vec![MdsAuthenticatorStatus::NotFidoCertified]);
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::Indirect,
            min_certification: Some(CertificationLevel::L1),
            ..WebauthnAttestationPolicy::default()
        };
        let c = candidate(Some(entry.aaguid), Some("packed"), Some(&entry));
        assert_eq!(
            evaluate(&policy, &c),
            AttestationDecision::Deny(AttestationDenyReason::CertificationTooLow)
        );
    }

    #[test]
    fn min_certification_boundary_each_level() {
        let levels = [
            (
                MdsAuthenticatorStatus::FidoCertifiedL1,
                CertificationLevel::L1,
            ),
            (
                MdsAuthenticatorStatus::FidoCertifiedL1Plus,
                CertificationLevel::L1Plus,
            ),
            (
                MdsAuthenticatorStatus::FidoCertifiedL2,
                CertificationLevel::L2,
            ),
            (
                MdsAuthenticatorStatus::FidoCertifiedL2Plus,
                CertificationLevel::L2Plus,
            ),
            (
                MdsAuthenticatorStatus::FidoCertifiedL3,
                CertificationLevel::L3,
            ),
            (
                MdsAuthenticatorStatus::FidoCertifiedL3Plus,
                CertificationLevel::L3Plus,
            ),
        ];

        for (status_at, level_at) in levels {
            let entry = entry_with_statuses(vec![status_at]);

            // Exactly at the minimum -> Allow.
            let policy_eq = WebauthnAttestationPolicy {
                mode: AttestationMode::Indirect,
                min_certification: Some(level_at),
                ..WebauthnAttestationPolicy::default()
            };
            let c = candidate(Some(entry.aaguid), Some("packed"), Some(&entry));
            assert_eq!(
                evaluate(&policy_eq, &c),
                AttestationDecision::Allow,
                "level {level_at:?} must satisfy min_certification == itself"
            );

            // One level above the entry's level -> Deny(CertificationTooLow),
            // except at the top of the scale where there is no level above.
            if let Some(above) = next_level(level_at) {
                let policy_above = WebauthnAttestationPolicy {
                    mode: AttestationMode::Indirect,
                    min_certification: Some(above),
                    ..WebauthnAttestationPolicy::default()
                };
                assert_eq!(
                    evaluate(&policy_above, &c),
                    AttestationDecision::Deny(AttestationDenyReason::CertificationTooLow),
                    "level {level_at:?} must fail min_certification {above:?}"
                );
            }
        }
    }

    fn next_level(level: CertificationLevel) -> Option<CertificationLevel> {
        use CertificationLevel::*;
        match level {
            L1 => Some(L1Plus),
            L1Plus => Some(L2),
            L2 => Some(L2Plus),
            L2Plus => Some(L3),
            L3 => Some(L3Plus),
            L3Plus => None,
        }
    }

    #[test]
    fn min_certification_uses_highest_level_in_history() {
        // Entry was L1 at first, later upgraded to L2plus — evaluate must
        // use the highest, not the first or last chronologically.
        let entry = entry_with_statuses(vec![
            MdsAuthenticatorStatus::FidoCertifiedL1,
            MdsAuthenticatorStatus::FidoCertifiedL2Plus,
        ]);
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::Indirect,
            min_certification: Some(CertificationLevel::L2),
            ..WebauthnAttestationPolicy::default()
        };
        let c = candidate(Some(entry.aaguid), Some("packed"), Some(&entry));
        assert_eq!(evaluate(&policy, &c), AttestationDecision::Allow);
    }

    // --- step 10: everything passes ---

    #[test]
    fn fully_compliant_entry_is_allowed() {
        let entry = entry_with_statuses(vec![MdsAuthenticatorStatus::FidoCertifiedL2]);
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::DirectRequired,
            require_fido_certified: true,
            min_certification: Some(CertificationLevel::L1Plus),
            block_revoked_status: true,
            unknown_aaguid: Some(UnknownAaguidAction::Deny),
            ..WebauthnAttestationPolicy::default()
        };
        let c = candidate(Some(entry.aaguid), Some("packed"), Some(&entry));
        assert_eq!(evaluate(&policy, &c), AttestationDecision::Allow);
    }

    // --- validate_attestation_policy ---

    #[test]
    fn validate_rejects_require_fido_certified_with_mode_none() {
        let policy = WebauthnAttestationPolicy {
            require_fido_certified: true,
            ..WebauthnAttestationPolicy::default()
        };
        let err = validate_attestation_policy(&policy).unwrap_err();
        assert!(err.to_string().contains("require_fido_certified"));
    }

    #[test]
    fn validate_rejects_min_certification_with_mode_none() {
        let policy = WebauthnAttestationPolicy {
            min_certification: Some(CertificationLevel::L1),
            ..WebauthnAttestationPolicy::default()
        };
        let err = validate_attestation_policy(&policy).unwrap_err();
        assert!(err.to_string().contains("min_certification"));
    }

    #[test]
    fn validate_accepts_both_fields_with_mode_direct_required() {
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::DirectRequired,
            require_fido_certified: true,
            min_certification: Some(CertificationLevel::L1),
            ..WebauthnAttestationPolicy::default()
        };
        assert!(validate_attestation_policy(&policy).is_ok());
    }

    #[test]
    fn validate_accepts_default_policy() {
        assert!(validate_attestation_policy(&WebauthnAttestationPolicy::default()).is_ok());
    }
}

#[cfg(test)]
mod unknown_aaguid_default_tests {
    use super::*;

    /// The whole reason `unknown_aaguid` is an `Option`: a tenant that opts
    /// into the strictest mode without mentioning this field must not admit
    /// authenticators FIDO has no metadata for.
    #[test]
    fn unset_defaults_to_deny_under_direct_required() {
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::DirectRequired,
            ..WebauthnAttestationPolicy::default()
        };
        assert_eq!(policy.unknown_aaguid, None, "precondition: field is unset");
        assert_eq!(
            policy.effective_unknown_aaguid(),
            UnknownAaguidAction::Deny,
            "an unset unknown_aaguid must fail CLOSED under direct_required"
        );
    }

    #[test]
    fn unset_defaults_to_allow_under_indirect_and_none() {
        for mode in [AttestationMode::None, AttestationMode::Indirect] {
            let policy = WebauthnAttestationPolicy {
                mode,
                ..WebauthnAttestationPolicy::default()
            };
            assert_eq!(
                policy.effective_unknown_aaguid(),
                UnknownAaguidAction::Allow,
                "{mode:?} keeps the lenient default"
            );
        }
    }

    #[test]
    fn an_explicit_value_wins_over_the_mode_default_in_both_directions() {
        let lenient_strict_mode = WebauthnAttestationPolicy {
            mode: AttestationMode::DirectRequired,
            unknown_aaguid: Some(UnknownAaguidAction::Allow),
            ..WebauthnAttestationPolicy::default()
        };
        assert_eq!(
            lenient_strict_mode.effective_unknown_aaguid(),
            UnknownAaguidAction::Allow,
            "an admin may deliberately opt out of the strict default"
        );

        let strict_lenient_mode = WebauthnAttestationPolicy {
            mode: AttestationMode::Indirect,
            unknown_aaguid: Some(UnknownAaguidAction::Deny),
            ..WebauthnAttestationPolicy::default()
        };
        assert_eq!(
            strict_lenient_mode.effective_unknown_aaguid(),
            UnknownAaguidAction::Deny
        );
    }

    /// End-to-end through `evaluate`, not just the accessor: an unknown
    /// AAGUID at a `direct_required` tenant with no explicit setting is
    /// denied.
    #[test]
    fn evaluate_denies_an_unknown_aaguid_under_an_unset_direct_required_policy() {
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::DirectRequired,
            ..WebauthnAttestationPolicy::default()
        };
        let candidate = AttestationCandidate {
            aaguid: Some(Uuid::from_bytes([9; 16])),
            attestation_format: Some("packed"),
            mds_entry: None,
        };
        assert_eq!(
            evaluate(&policy, &candidate),
            AttestationDecision::Deny(AttestationDenyReason::UnknownAuthenticator)
        );
    }
}
