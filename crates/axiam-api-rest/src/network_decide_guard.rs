//! The decision route's two pieces of per-process state (RADIUS Live profile, W6.4;
//! `claude_dev/radius-reply-profile-design.md` §3.4, §6.3).
//!
//! # The caller's bucket
//!
//! `POST /api/v1/network/decide` is metered **per authenticated caller** — the
//! token's `sub`, a FreeRADIUS server's service account — at
//! `network_decide_per_min` (maintainer decision D-6). The caller exists only
//! once the handler has authenticated its certificate-bound token, so the bucket
//! cannot be route middleware: the handler spends
//! `network_decide:{tenant}:{sub}` from the shared counter, and when that counter
//! is switched off (`AXIAM__RATE_LIMIT__SHARED=off`, which admits everything)
//! from the in-process keyed limiter held here, exactly as the CIBA pending list
//! does (R101W3-04; [`crate::ciba_list_limiter`], whose limiter is reused: it is
//! a keyed `(tenant, subject)` limiter, and nothing in it is about CIBA). A key
//! reaches it only after authentication, so the map is bounded by the number of
//! callers, never by what a caller can invent.
//!
//! # One `reply_profile.invalid` row per profile per window
//!
//! A stored profile that no longer validates (one edited in the datastore behind
//! the API) makes its segment no candidate, and the design note asks for **one
//! audit row per profile per window** (§3.4), not one per decision: a site's
//! power-restore storm would otherwise write a hundred identical rows a second.
//! The window is [`INVALID_PROFILE_AUDIT_WINDOW`]; the key is the tenant, the
//! segment, the profile's version and the rule it fails, so a profile rewritten
//! (a new version) or failing a different rule is reported again at once. It is
//! per process, as every in-process limiter is: N replicas write at most N rows
//! a window.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::ciba_list_limiter::CibaListLimiter;

/// How long one `reply_profile.invalid` row covers a defective profile.
pub const INVALID_PROFILE_AUDIT_WINDOW: Duration = Duration::from_secs(3600);

/// The key of one defective profile's window.
type DefectKey = (Uuid, Uuid, u64, &'static str);

/// The decision route's per-process state. One per process, in `AppState`.
#[derive(Debug, Default)]
pub struct NetworkDecideGuards {
    callers: CibaListLimiter,
    defects: Mutex<HashMap<DefectKey, Instant>>,
}

impl NetworkDecideGuards {
    /// Spend one decision of `(tenant_id, caller)`'s `per_min` allowance in the
    /// in-process limiter; `false` means it is spent and the route answers `429`.
    pub fn admit(&self, tenant_id: Uuid, caller: Uuid, per_min: u32) -> bool {
        self.callers.check(tenant_id, caller, per_min)
    }

    /// Whether a defective profile should be audited now: `true` the first time
    /// `(tenant, segment, version, rule)` is seen in a window, `false` for the
    /// rest of it.
    pub fn first_in_window(
        &self,
        tenant_id: Uuid,
        segment_id: Uuid,
        version: u64,
        rule: &'static str,
    ) -> bool {
        self.first_in_window_at(tenant_id, segment_id, version, rule, Instant::now())
    }

    fn first_in_window_at(
        &self,
        tenant_id: Uuid,
        segment_id: Uuid,
        version: u64,
        rule: &'static str,
        now: Instant,
    ) -> bool {
        // A poisoned lock means a panic elsewhere mid-update; audit rather than
        // stay silent (one extra row is the safe failure).
        let Ok(mut seen) = self.defects.lock() else {
            return true;
        };
        // Expired windows go before the lookup, so the map holds only the
        // defects of the last window: bounded by the tenant's profiles.
        seen.retain(|_, at| now.duration_since(*at) < INVALID_PROFILE_AUDIT_WINDOW);
        let key = (tenant_id, segment_id, version, rule);
        if seen.contains_key(&key) {
            return false;
        }
        seen.insert(key, now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_defect_is_audited_once_per_window_and_again_after_it() {
        let g = NetworkDecideGuards::default();
        let (t, s) = (Uuid::new_v4(), Uuid::new_v4());
        let start = Instant::now();
        assert!(g.first_in_window_at(t, s, 3, "3.4:value", start));
        assert!(!g.first_in_window_at(t, s, 3, "3.4:value", start + Duration::from_secs(5)));
        // A new version, or another rule, is another defect.
        assert!(g.first_in_window_at(t, s, 4, "3.4:value", start));
        assert!(g.first_in_window_at(t, s, 3, "3.4:dictionary", start));
        // After the window, the same defect is reported again.
        assert!(g.first_in_window_at(
            t,
            s,
            3,
            "3.4:value",
            start + INVALID_PROFILE_AUDIT_WINDOW + Duration::from_secs(1)
        ));
    }

    #[test]
    fn each_caller_has_a_bucket_of_its_own() {
        let g = NetworkDecideGuards::default();
        let (t, a, b) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        assert!(g.admit(t, a, 1));
        assert!(!g.admit(t, a, 1));
        assert!(g.admit(t, b, 1));
    }
}
