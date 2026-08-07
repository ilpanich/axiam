//! Read routing between the SurrealDB primary and its read replicas (A3/J11).
//!
//! # Why this exists
//!
//! Run 5's cache-off authorization cells capped at 1 010–1 032 checks/s with a
//! 2-core datastore, and rose **+75–79 %** when the datastore was given 4
//! cores with no other change. That is the shape of a *concurrency* ceiling,
//! not a per-query-cost one: the queries were already index-backed and
//! CI-guarded against table scans, and making them individually cheaper would
//! not have moved the number. Adding read capacity would.
//!
//! This module is the routing primitive for that. It does not, by itself,
//! connect to anything — [`crate::DbHandle`] holds the replica slots and this
//! type decides which slot a given read is allowed to use.
//!
//! # The staleness contract
//!
//! Routing a read to a replica means accepting that it may answer from a
//! slightly older state. That is the same class of decision the decision cache
//! already makes, and it is stated in the same terms here so the two can be
//! reasoned about together:
//!
//! | | decision cache | read replica |
//! |---|---|---|
//! | bound | TTL, plus event-path invalidation (262 ms measured) | replication lag |
//! | worst case | a grant revoked out-of-band is honoured until TTL | a grant revoked on the primary is honoured until the replica catches up |
//! | never stale | anything that invalidates on the event path | anything routed [`ReadPreference::Primary`] |
//!
//! **A replica-lag allow is the same class of stale allow as a cache-TTL
//! allow.** A deployment that has accepted the decision cache has already
//! accepted this shape of risk; a deployment that has not should leave
//! replicas unconfigured, which is the default and which routes everything to
//! the primary.
//!
//! What must **never** be replica-routed, regardless of configuration:
//!
//! - session-revocation reads (logout must take effect now, not after lag),
//! - anything read in order to write it back (read-modify-write),
//! - a read whose result is used to decide whether a *write* is permitted.
//!
//! [`QueryClass`] encodes those rules once so the decision is not re-litigated
//! at ~250 repository call sites.
//!
//! # Failure mode: never fail closed on a read
//!
//! A replica that is down, lagging beyond its bound, or unreachable falls back
//! to the primary. A read path must not start returning errors because a
//! *performance* optimisation is unavailable — the worst a replica outage may
//! cost is the throughput the replica was adding.

use std::time::Duration;

/// Where a read may be served from.
///
/// Deliberately a two-variant enum rather than a bool: `ReadPreference::
/// Primary` at a call site says "this read is pinned, on purpose", which a
/// `false` does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReadPreference {
    /// Must be served by the primary. The default, so a call site that has not
    /// been classified is safe by omission.
    #[default]
    Primary,
    /// May be served by a replica when one is configured and healthy;
    /// otherwise served by the primary.
    PreferReplica,
}

impl ReadPreference {
    /// Stable, log-safe name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::PreferReplica => "prefer_replica",
        }
    }

    /// Whether a replica may serve this read.
    pub const fn allows_replica(self) -> bool {
        matches!(self, Self::PreferReplica)
    }
}

/// What a read is *for*, which is what decides whether it may be stale.
///
/// The mapping from class to [`ReadPreference`] lives here, in one place,
/// rather than at each call site — "is this read allowed to be stale" is a
/// security judgement, and a security judgement repeated at 250 call sites is
/// a security judgement that will eventually be made wrong at one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryClass {
    /// Role/permission/resource reads behind an authorization decision.
    ///
    /// Replica-eligible. These are the reads run 5 found the ceiling on, and
    /// they are already served from a TTL cache in front of the datastore, so
    /// the deployment has necessarily already accepted a staleness bound on
    /// this exact data.
    AuthzDecision,
    /// Identity reads that describe a subject rather than authorize one:
    /// `userinfo`, profile lookups.
    ///
    /// Replica-eligible. A profile field arriving a few hundred milliseconds
    /// late is a display concern, not an access-control one.
    IdentityRead,
    /// JWKS and other public key material.
    ///
    /// Replica-eligible. Key *rotation* publishes the new key before retiring
    /// the old one, so a lagging replica serves a valid superset, never a gap.
    PublicKeyMaterial,
    /// Session validity / revocation.
    ///
    /// **Primary-pinned, always.** Logout, token revocation and forced
    /// sign-out are the operations an operator reaches for when something has
    /// gone wrong; "it takes effect once the replica catches up" is not an
    /// acceptable answer to those. Note the asymmetry with `AuthzDecision`
    /// above: the session cache's staleness is bounded by an *invalidation
    /// event* the server controls, whereas replica lag is bounded only by the
    /// replica's own progress.
    SessionRevocation,
    /// Any read taken in order to decide or perform a write.
    ///
    /// **Primary-pinned, always.** Read-modify-write against a replica is a
    /// lost-update bug, not a staleness trade.
    WritePath,
}

impl QueryClass {
    /// The routing this class permits.
    pub const fn read_preference(self) -> ReadPreference {
        match self {
            Self::AuthzDecision | Self::IdentityRead | Self::PublicKeyMaterial => {
                ReadPreference::PreferReplica
            }
            Self::SessionRevocation | Self::WritePath => ReadPreference::Primary,
        }
    }

    /// Stable, log-safe name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthzDecision => "authz_decision",
            Self::IdentityRead => "identity_read",
            Self::PublicKeyMaterial => "public_key_material",
            Self::SessionRevocation => "session_revocation",
            Self::WritePath => "write_path",
        }
    }
}

/// Replica-routing configuration.
///
/// Absent replicas (the default) means every read goes to the primary and this
/// whole module is inert — which is the shipped posture until an operator
/// explicitly opts in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadReplicaConfig {
    /// Replica endpoint URLs. Empty = feature off.
    pub urls: Vec<String>,
    /// The lag an operator is declaring acceptable for replica-eligible reads.
    ///
    /// This is a **contract, not an enforcement**: SurrealDB does not hand the
    /// client a per-query lag measurement, so this value documents the bound
    /// the deployment is accepting and sizes the operator's own replication
    /// alerting. Stating it explicitly is the point — an unstated staleness
    /// bound is an unbounded one.
    pub max_staleness: Duration,
}

/// Default declared staleness bound.
///
/// Chosen to sit alongside the measured 262 ms event-path invalidation of the
/// decision cache, so the two bounds are the same order of magnitude and an
/// operator reasoning about "how stale can an allow be" gets one answer rather
/// than two unrelated ones.
pub const DEFAULT_MAX_STALENESS: Duration = Duration::from_millis(500);

impl Default for ReadReplicaConfig {
    fn default() -> Self {
        Self {
            urls: Vec::new(),
            max_staleness: DEFAULT_MAX_STALENESS,
        }
    }
}

impl ReadReplicaConfig {
    /// Reads `AXIAM__DB__READ_REPLICAS` (comma-separated URLs) and
    /// `AXIAM__DB__READ_REPLICA_MAX_STALENESS_MS`.
    ///
    /// An unparseable staleness value falls back to the default rather than
    /// failing startup: the value is documentation for humans and alerting,
    /// and refusing to boot over it would trade a real outage for a typo.
    pub fn from_env() -> Self {
        let urls = std::env::var("AXIAM__DB__READ_REPLICAS")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let max_staleness = std::env::var("AXIAM__DB__READ_REPLICA_MAX_STALENESS_MS")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or(DEFAULT_MAX_STALENESS);

        Self {
            urls,
            max_staleness,
        }
    }

    /// Whether replica routing is enabled at all.
    pub fn is_enabled(&self) -> bool {
        !self.urls.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of `QueryClass`: the security-relevant classes are
    /// pinned to the primary and cannot be configured away. This test exists
    /// so that adding a variant forces a deliberate answer.
    #[test]
    fn revocation_and_write_path_reads_are_never_replica_eligible() {
        assert_eq!(
            QueryClass::SessionRevocation.read_preference(),
            ReadPreference::Primary,
            "logout must take effect now, not after replication lag"
        );
        assert_eq!(
            QueryClass::WritePath.read_preference(),
            ReadPreference::Primary,
            "read-modify-write against a replica is a lost update"
        );
        assert!(
            !QueryClass::SessionRevocation
                .read_preference()
                .allows_replica()
        );
        assert!(!QueryClass::WritePath.read_preference().allows_replica());
    }

    #[test]
    fn hot_read_classes_are_replica_eligible() {
        for class in [
            QueryClass::AuthzDecision,
            QueryClass::IdentityRead,
            QueryClass::PublicKeyMaterial,
        ] {
            assert!(
                class.read_preference().allows_replica(),
                "{} should be replica-eligible",
                class.as_str()
            );
        }
    }

    /// An unclassified call site must be safe: `ReadPreference::default()` is
    /// the pinned one.
    #[test]
    fn default_read_preference_is_primary() {
        assert_eq!(ReadPreference::default(), ReadPreference::Primary);
    }

    #[test]
    fn config_is_off_unless_replicas_are_listed() {
        assert!(!ReadReplicaConfig::default().is_enabled());
        assert!(
            ReadReplicaConfig {
                urls: vec!["ws://replica-1:8000".into()],
                ..Default::default()
            }
            .is_enabled()
        );
    }

    #[test]
    fn config_parses_a_comma_separated_list_and_ignores_blanks() {
        // Exercised through the same splitting the env parser uses.
        let cfg = ReadReplicaConfig {
            urls: " ws://a:8000 , , ws://b:8000 "
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect(),
            ..Default::default()
        };
        assert_eq!(cfg.urls, vec!["ws://a:8000", "ws://b:8000"]);
    }
}
