//! A lockout for login names AXIAM holds no account for (F4 P23W3-02, T-332).
//!
//! With just-in-time provisioning on, a sign-in for a name that matches no
//! local account is answered by the tenant's directory (T23.3.3). The brake on
//! password guessing everywhere else is the per-account counter (T-302), and an
//! unknown name has no account to carry one: before this module, every guess at
//! a never-signed-in directory user reached the directory, held back only by the
//! per-IP limits and whatever lockout the directory itself enforces.
//!
//! [`UnknownNameLockout`] is that missing counter. It is keyed on the tenant and
//! the login name as typed, trimmed and lower-cased — directories compare names
//! without regard to case, so `Alice` and `ALICE` are one guess target — and
//! applies **the tenant's own lockout policy**, the numbers an account would
//! get: after `max_failed_login_attempts` failures the name is locked for
//! `lockout_duration_secs`, growing by the policy's backoff to its maximum on
//! each failure after that. A locked name never reaches the directory; the
//! caller answers it exactly as an unknown user, dummy verify included. A
//! successful sign-in clears the name.
//!
//! # Bounds, and what is not covered
//!
//! * **Per process.** The state lives in memory. With N replicas a name gets at
//!   most N times the policy's attempts per lockout window — the same bound the
//!   in-memory rate-limit governor has, and far below "unbounded". A restart
//!   forgets it.
//! * **Bounded memory.** At most [`DEFAULT_CAPACITY`] names are tracked; an
//!   entry is forgotten once it has been idle for the policy's maximum lockout
//!   duration (or an hour, whichever is longer). When the table is full after
//!   pruning, the least recently failed unlocked name makes room; when every
//!   tracked name is locked, a new name is not tracked — filling the table takes
//!   that many names' worth of attempts, which the per-IP limits meter.
//! * **Only failures the directory decided count**: a wrong password or no such
//!   entry. A directory that cannot be reached counts against nobody, as for
//!   accounts.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axiam_core::models::settings::LockoutPolicy;
use uuid::Uuid;

/// How many names one process tracks at most.
pub const DEFAULT_CAPACITY: usize = 50_000;

/// The shortest idle time after which an entry is forgotten.
const MIN_IDLE: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Copy)]
struct Entry {
    failures: u32,
    locked_until: Option<Instant>,
    last_failure: Instant,
}

/// See the module documentation.
#[derive(Debug)]
pub struct UnknownNameLockout {
    entries: Mutex<HashMap<(Uuid, String), Entry>>,
    capacity: usize,
}

impl Default for UnknownNameLockout {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }
}

fn key(tenant_id: Uuid, login_name: &str) -> (Uuid, String) {
    (tenant_id, login_name.trim().to_lowercase())
}

fn idle_limit(policy: &LockoutPolicy) -> Duration {
    Duration::from_secs(
        policy
            .max_lockout_duration_secs
            .max(policy.lockout_duration_secs),
    )
    .max(MIN_IDLE)
}

/// The lock a name earns at its `failures`-th failure: none below the
/// threshold, then the base duration times the backoff for each failure past
/// it, capped — the shape `UserRepository::increment_failed_logins` gives an
/// account.
fn lock_for(policy: &LockoutPolicy, failures: u32) -> Option<Duration> {
    if policy.max_failed_login_attempts == 0 || failures < policy.max_failed_login_attempts {
        return None;
    }
    let past = failures - policy.max_failed_login_attempts;
    let multiplier = policy
        .lockout_backoff_multiplier
        .max(1.0)
        .powi(i32::try_from(past).unwrap_or(i32::MAX));
    let base = policy.lockout_duration_secs as f64;
    let cap = policy
        .max_lockout_duration_secs
        .max(policy.lockout_duration_secs) as f64;
    let secs = (base * multiplier).min(cap);
    Some(Duration::from_secs_f64(if secs.is_finite() {
        secs
    } else {
        cap
    }))
}

impl UnknownNameLockout {
    /// A lockout tracking at most `capacity` names.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    /// Whether `login_name` is locked in `tenant_id` at `now`.
    pub fn is_locked(&self, tenant_id: Uuid, login_name: &str, now: Instant) -> bool {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries
            .get(&key(tenant_id, login_name))
            .and_then(|e| e.locked_until)
            .is_some_and(|until| until > now)
    }

    /// Count one failure the directory decided for `login_name` in `tenant_id`.
    pub fn record_failure(
        &self,
        tenant_id: Uuid,
        login_name: &str,
        policy: &LockoutPolicy,
        now: Instant,
    ) {
        let k = key(tenant_id, login_name);
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        if !entries.contains_key(&k) && entries.len() >= self.capacity {
            let idle = idle_limit(policy);
            entries.retain(|_, e| {
                e.locked_until.is_some_and(|until| until > now)
                    || now.saturating_duration_since(e.last_failure) < idle
            });
            if entries.len() >= self.capacity {
                let oldest_unlocked = entries
                    .iter()
                    .filter(|(_, e)| !e.locked_until.is_some_and(|until| until > now))
                    .min_by_key(|(_, e)| e.last_failure)
                    .map(|(k, _)| k.clone());
                match oldest_unlocked {
                    Some(victim) => {
                        entries.remove(&victim);
                    }
                    None => return,
                }
            }
        }
        let entry = entries.entry(k).or_insert(Entry {
            failures: 0,
            locked_until: None,
            last_failure: now,
        });
        if now.saturating_duration_since(entry.last_failure) >= idle_limit(policy)
            && !entry.locked_until.is_some_and(|until| until > now)
        {
            entry.failures = 0;
        }
        entry.failures = entry.failures.saturating_add(1);
        entry.last_failure = now;
        if let Some(lock) = lock_for(policy, entry.failures) {
            entry.locked_until = Some(now + lock);
        }
    }

    /// Forget `login_name` in `tenant_id`: it signed in.
    pub fn clear(&self, tenant_id: Uuid, login_name: &str) {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries.remove(&key(tenant_id, login_name));
    }

    /// How many names are tracked (for tests and diagnostics).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Whether no name is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> LockoutPolicy {
        LockoutPolicy {
            max_failed_login_attempts: 3,
            lockout_duration_secs: 60,
            lockout_backoff_multiplier: 2.0,
            max_lockout_duration_secs: 300,
        }
    }

    #[test]
    fn the_threshold_locks_the_name_in_any_case_and_only_in_its_tenant() {
        let lockout = UnknownNameLockout::default();
        let (tenant, other_tenant, now) = (Uuid::new_v4(), Uuid::new_v4(), Instant::now());
        for spelled in ["alice", "Alice", " ALICE "] {
            assert!(!lockout.is_locked(tenant, "alice", now));
            lockout.record_failure(tenant, spelled, &policy(), now);
        }
        assert!(lockout.is_locked(tenant, "aLiCe", now));
        assert!(!lockout.is_locked(other_tenant, "alice", now));
        assert!(!lockout.is_locked(tenant, "bob", now));
        // Served, then a further failure locks again, for longer.
        let later = now + Duration::from_secs(61);
        assert!(!lockout.is_locked(tenant, "alice", later));
        lockout.record_failure(tenant, "alice", &policy(), later);
        assert!(lockout.is_locked(tenant, "alice", later + Duration::from_secs(100)));
        assert!(!lockout.is_locked(tenant, "alice", later + Duration::from_secs(121)));
    }

    #[test]
    fn success_clears_and_a_zero_threshold_never_locks() {
        let lockout = UnknownNameLockout::default();
        let (tenant, now) = (Uuid::new_v4(), Instant::now());
        lockout.record_failure(tenant, "alice", &policy(), now);
        lockout.record_failure(tenant, "alice", &policy(), now);
        lockout.clear(tenant, "ALICE");
        lockout.record_failure(tenant, "alice", &policy(), now);
        assert!(
            !lockout.is_locked(tenant, "alice", now),
            "the count restarted"
        );

        let off = LockoutPolicy {
            max_failed_login_attempts: 0,
            ..policy()
        };
        for _ in 0..10 {
            lockout.record_failure(tenant, "carol", &off, now);
        }
        assert!(!lockout.is_locked(tenant, "carol", now));
    }

    #[test]
    fn backoff_is_capped() {
        assert_eq!(lock_for(&policy(), 2), None);
        assert_eq!(lock_for(&policy(), 3), Some(Duration::from_secs(60)));
        assert_eq!(lock_for(&policy(), 4), Some(Duration::from_secs(120)));
        assert_eq!(lock_for(&policy(), 40), Some(Duration::from_secs(300)));
    }

    #[test]
    fn memory_is_bounded_and_a_locked_name_survives_a_flood() {
        let lockout = UnknownNameLockout::with_capacity(4);
        let (tenant, now) = (Uuid::new_v4(), Instant::now());
        for _ in 0..3 {
            lockout.record_failure(tenant, "target", &policy(), now);
        }
        for i in 0..100 {
            lockout.record_failure(tenant, &format!("spray-{i}"), &policy(), now);
        }
        assert!(lockout.len() <= 4);
        assert!(
            lockout.is_locked(tenant, "target", now),
            "spraying other names cannot evict a locked one"
        );
    }
}
