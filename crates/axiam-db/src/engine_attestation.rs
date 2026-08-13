//! Startup attestation of the SurrealDB storage engine (X6, ilpanich/axiam#302).
//!
//! # What this is for
//!
//! The three single-use consume paths — `permission_ticket.consume`,
//! `device_grant.redeem`, `pushed_auth_request.consume` — are single-use
//! *conditional on running a persistent storage engine*. That condition is
//! measured, not assumed: `tools/surreal-race-probe` records 0 double
//! redemptions in 40 000 contended attempts on `surrealkv` and 0 in 9 600 on
//! `rocksdb`, against 23 in 1 200 on `kv-mem`, which arbitrates at the same
//! 54% rate as the persistent engines and then silently misses.
//!
//! Before X6 that condition was enforced nowhere. `docker-compose*.yml` and the
//! k8s StatefulSet pin `surrealkv:`, but nothing stopped an operator pointing
//! `AXIAM__DB__URL` at a `surreal start memory` instance and getting a server
//! that boots cleanly and mints two RPTs from one authorization decision at
//! roughly 1 in 640. This module is where "never run `memory` in a real
//! deployment" stops being a code comment and becomes a control.
//!
//! # Finding: the engine is NOT detectable over the wire (SurrealDB 3.2.4)
//!
//! `axiam-server` reaches SurrealDB over HTTP, so the question X6 had to settle
//! first was whether a client can even see which datastore it is talking to.
//! It cannot. Every wire-reachable surface of `surrealdb-core` 3.2.4 was
//! enumerated:
//!
//!   * `/version` and the RPC `version` method — a semver string
//!     (`surrealdb-3.2.4`), no datastore identity.
//!   * `INFO FOR ROOT` — `accesses`, `defaults`, `namespaces`, `nodes`,
//!     `system`, `users`, `config`. `system` is CPU/memory/core utilisation
//!     (`expr/statements/info.rs::system()`); `nodes` is node ids and
//!     heartbeats; `config` is the query timeout. None name the datastore.
//!   * `INFO FOR NS` / `DB` / `TABLE` — schema only.
//!   * The `session::*` function namespace — `ac`, `db`, `id`, `ip`, `ns`,
//!     `origin`, `rd`, `token`. There is no `sys::` namespace.
//!   * `/health` — a bare liveness answer.
//!
//! The engine name *exists* in the process: `Transactable::kind()` returns
//! `"memory"` / `"surrealkv"` / `"rocksdb"`, and `Display for DatastoreFlavor`
//! renders the same strings. Both are `pub(super)`/internal and are never
//! serialised into a response — the only in-crate use of the `Display` impl is
//! one assertion in `kvs/ds/builder.rs`.
//!
//! Behavioural fingerprinting was considered and rejected. The one differential
//! that looked promising — versioned/temporal queries being unsupported on
//! `kv-mem` — turns out to be a per-datastore *config* flag
//! (`kvs/mem/mod.rs`'s `versioned`, set from `?versioned=true`), so it
//! identifies a configuration option rather than an engine, and would
//! misclassify a rocksdb deployment. A guess that reads like evidence is worse
//! than an honest "unknown".
//!
//! # So what this module actually does
//!
//! It asks anyway, and it is honest about the answer.
//!
//! [`probe_reported_engine`] runs a total, defensive query that yields the
//! engine name if any future SurrealDB release starts publishing one under a
//! plausible key, and `None` otherwise. On 3.2.4 it always returns `None`, and
//! `probe_reports_nothing_on_this_surrealdb` pins that as an executable fact —
//! if a bump starts exposing the engine, that test fails and the hard guard
//! below becomes live without a code change.
//!
//! [`classify`] and [`decide`] are pure functions over that answer, so the
//! whole policy is unit-testable without a datastore:
//!
//! | reported            | `allow_memory` | outcome                                     |
//! |---------------------|----------------|---------------------------------------------|
//! | `surrealkv`, …      | either         | attested, `INFO`                            |
//! | `memory`            | `false`        | **refused** — startup fails, naming #302    |
//! | `memory`            | `true`         | `WARN`, dev-only override acknowledged      |
//! | an unknown name     | either         | `WARN` — cannot attest                      |
//! | nothing (today)     | either         | `WARN` — cannot attest                      |
//!
//! Because today's answer is always the last row, enforcement for a real
//! deployment rests on the deployment layer, where compose and the k8s
//! StatefulSet already pin `surrealkv:` — plus the MUST-level operator
//! requirement in `docs/deployment/README.md`. The WARN exists so that
//! requirement is visible in the boot log of every server, not only in a
//! document nobody reads twice.
//!
//! Attestation never fails startup by itself. A datastore that refuses
//! `INFO FOR ROOT`, or a future one that renames it, produces the same
//! "cannot attest" WARN as today's silence — a monitoring gap is not a reason
//! to take a working deployment down. The only hard failure is a *positive*
//! identification of a memory datastore without the override.

use surrealdb::{Connection, Surreal};
use tracing::{info, warn};

/// Environment variable that lets a developer run against a `memory` datastore
/// on purpose. Deliberately not a config-file key: it exists for `just dev-up`
/// and for someone reproducing #302, and a value that only lives in one
/// operator's shell is harder to leave switched on in production than a line in
/// a checked-in TOML file.
pub const ALLOW_MEMORY_ENGINE_ENV: &str = "AXIAM__DB__ALLOW_MEMORY_ENGINE";

/// Whether [`ALLOW_MEMORY_ENGINE_ENV`] is set to an affirmative value.
///
/// Read from the environment directly rather than through [`crate::DbConfig`],
/// which is deserialized by the `config` crate without `try_parsing` — a `bool`
/// field there would silently fail to load from an `AXIAM__*` string, which is
/// the worst possible failure mode for a safety override (the same reason
/// `allow_missing_aud_as_user` is read by hand in `axiam-server`). Anything
/// other than the affirmatives below — including an unset variable — is
/// `false`, so the guard fails closed on a typo.
pub fn memory_engine_override_enabled() -> bool {
    matches!(
        std::env::var(ALLOW_MEMORY_ENGINE_ENV)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "true" | "1" | "yes"
    )
}

/// Engine names that give the single-use guarantee its precondition. Measured
/// for `surrealkv` and `rocksdb` (`tools/surreal-race-probe/RESULTS.md`); the
/// remaining three are persistent by construction but have never been probed,
/// which is why [`decide`] logs the name it accepted rather than just "ok".
const PERSISTENT_ENGINES: &[&str] = &["surrealkv", "rocksdb", "tikv", "foundationdb", "indxdb"];

/// Engine names that do not survive a restart and — per the probe — do not
/// reliably arbitrate a contended single-use `UPDATE`.
const MEMORY_ENGINES: &[&str] = &["memory", "mem", "kv-mem"];

/// Query used by [`probe_reported_engine`].
///
/// Written to be **total**: every field access on an absent key yields `NONE`
/// rather than erroring, `??` walks the candidate keys in order, and the
/// `type::is_string` guard means a future release publishing an object (rather
/// than a string) under one of these names degrades to "cannot attest" instead
/// of failing to deserialize.
///
/// The candidate keys are speculative by definition — none of them exists in
/// 3.2.4. They are the names a future release would plausibly choose, and
/// probing for them costs one query per boot.
const ENGINE_PROBE_SQL: &str = "\
LET $root = (INFO FOR ROOT); \
LET $named = $root.datastore ?? $root.engine ?? $root.storage \
    ?? $root.system.datastore ?? $root.system.engine ?? $root.system.storage; \
RETURN IF type::is_string($named) { $named } ELSE { NONE }";

/// What the datastore said about itself, classified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineIdentity {
    /// A reported name recognised as non-persistent.
    Memory(String),
    /// A reported name recognised as persistent.
    Persistent(String),
    /// A name was reported but is not one this build knows about.
    Unrecognised(String),
    /// No engine name was reported. The only outcome on SurrealDB 3.2.4.
    Unreported,
}

/// The startup decision, for the caller to log-and-continue on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attestation {
    /// The datastore positively identified itself as a persistent engine.
    Attested(String),
    /// It identified itself as a memory datastore and the operator set
    /// [`ALLOW_MEMORY_ENGINE_ENV`]. Single-use is **not** guaranteed here.
    MemoryOverridden(String),
    /// No usable identification. Enforcement rests on the deployment layer.
    NotAttestable(NotAttestable),
}

/// Why attestation could not reach a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotAttestable {
    /// The datastore published no engine name — SurrealDB 3.2.4 and earlier.
    NotExposed,
    /// It published a name this build does not recognise.
    UnknownEngine(String),
    /// The probe query itself failed (permissions, or a renamed `INFO`).
    ProbeFailed(String),
}

/// A positively-identified memory datastore with no override — startup must
/// stop. Its `Display` is the refusal message, and it names #302 so the reason
/// is one search away from the operator reading the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryEngineRefused {
    /// The engine name the datastore reported.
    pub reported: String,
}

impl std::fmt::Display for MemoryEngineRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "refusing to start against the `{}` storage engine: single-use redemption of \
             UMA permission tickets, RFC 8628 device grants and RFC 9126 PAR request_uris \
             is guaranteed only on a persistent engine (ilpanich/axiam#302). A memory \
             datastore admits two redemptions of one credential at roughly 1 in 640 — two \
             RPTs from one authorization decision, two token sets from one user approval, \
             or a replayable request_uri. Run `surrealkv:` (what docker-compose and the k8s \
             StatefulSet pin) or `rocksdb:`. To override for development only, set {}=true",
            self.reported, ALLOW_MEMORY_ENGINE_ENV
        )
    }
}

impl std::error::Error for MemoryEngineRefused {}

/// Classify a reported engine name. Pure — no datastore needed.
///
/// Matching is case-insensitive and tolerates a `kv-` prefix or a
/// `surrealkv://…` style path, because the name a future release publishes is
/// not something this code gets to choose.
pub fn classify(reported: Option<&str>) -> EngineIdentity {
    let Some(raw) = reported else {
        return EngineIdentity::Unreported;
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return EngineIdentity::Unreported;
    }

    // Reduce `SurrealKV://data/axiam.db` to `surrealkv` before matching.
    let normalised = trimmed
        .split("://")
        .next()
        .unwrap_or(trimmed)
        .trim_end_matches(':')
        .to_ascii_lowercase();

    if MEMORY_ENGINES.contains(&normalised.as_str()) {
        EngineIdentity::Memory(trimmed.to_string())
    } else if PERSISTENT_ENGINES.contains(&normalised.as_str()) {
        EngineIdentity::Persistent(trimmed.to_string())
    } else {
        EngineIdentity::Unrecognised(trimmed.to_string())
    }
}

/// Apply the startup policy to a classification. Pure — no datastore needed.
pub fn decide(
    identity: EngineIdentity,
    allow_memory: bool,
) -> Result<Attestation, MemoryEngineRefused> {
    match identity {
        EngineIdentity::Persistent(name) => Ok(Attestation::Attested(name)),
        EngineIdentity::Memory(name) if allow_memory => Ok(Attestation::MemoryOverridden(name)),
        EngineIdentity::Memory(name) => Err(MemoryEngineRefused { reported: name }),
        EngineIdentity::Unrecognised(name) => Ok(Attestation::NotAttestable(
            NotAttestable::UnknownEngine(name),
        )),
        EngineIdentity::Unreported => Ok(Attestation::NotAttestable(NotAttestable::NotExposed)),
    }
}

/// Ask the datastore which storage engine it runs.
///
/// Returns `Ok(None)` when it does not say — which, per the module docs, is
/// every SurrealDB release up to and including 3.2.4. `Err` means the probe
/// query itself failed; the caller downgrades that to "cannot attest" rather
/// than to a startup failure.
pub async fn probe_reported_engine<C: Connection>(
    db: &Surreal<C>,
) -> Result<Option<String>, String> {
    let mut response = db
        .query(ENGINE_PROBE_SQL)
        .await
        .map_err(|e| e.to_string())?
        .check()
        .map_err(|e| e.to_string())?;

    // LET $root = 0, LET $named = 1, RETURN = 2.
    response
        .take::<Option<String>>(2)
        .map_err(|e| e.to_string())
}

/// Attest the storage engine at startup and log the outcome.
///
/// `Err` is a hard refusal: the caller must fail startup rather than continue.
/// Every other outcome — including a probe that failed outright — returns `Ok`
/// with the reason logged, because a server that cannot identify its datastore
/// is in exactly the position every AXIAM release before X6 was in, and taking
/// it down would trade a documented gap for an outage.
pub async fn attest_storage_engine<C: Connection>(
    db: &Surreal<C>,
    allow_memory: bool,
) -> Result<Attestation, MemoryEngineRefused> {
    let identity = match probe_reported_engine(db).await {
        Ok(reported) => classify(reported.as_deref()),
        Err(error) => {
            let attestation = Attestation::NotAttestable(NotAttestable::ProbeFailed(error.clone()));
            log_attestation(&attestation);
            return Ok(attestation);
        }
    };

    let attestation = decide(identity, allow_memory)?;
    log_attestation(&attestation);
    Ok(attestation)
}

/// The boot-log half of the control. Split out so the policy functions stay
/// pure and the wording is asserted in one place.
fn log_attestation(attestation: &Attestation) {
    match attestation {
        Attestation::Attested(engine) => info!(
            engine = %engine,
            "Storage engine attested as persistent — single-use redemption is guaranteed \
             on this datastore (ilpanich/axiam#302)"
        ),
        Attestation::MemoryOverridden(engine) => warn!(
            engine = %engine,
            override_env = ALLOW_MEMORY_ENGINE_ENV,
            "Running against a MEMORY datastore because the dev-only override is set. \
             Single-use redemption is NOT guaranteed here: permission tickets, device \
             grants and PAR request_uris can each be redeemed twice under concurrency \
             (ilpanich/axiam#302). Never do this in a deployment"
        ),
        Attestation::NotAttestable(reason) => warn!(
            reason = %not_attestable_reason(reason),
            "Storage engine could NOT be attested — SurrealDB exposes no datastore \
             identity over the wire, so this server cannot verify it is running a \
             persistent engine. Single-use redemption of permission tickets, device \
             grants and PAR request_uris is guaranteed ONLY on a persistent engine \
             (ilpanich/axiam#302); operators MUST run `surrealkv:` or `rocksdb:` and \
             MUST NOT run `memory`. See docs/deployment/README.md"
        ),
    }
}

/// One-line rendering of a [`NotAttestable`] for the WARN's `reason` field.
fn not_attestable_reason(reason: &NotAttestable) -> String {
    match reason {
        NotAttestable::NotExposed => {
            "the datastore reports no engine name (SurrealDB 3.2.4 and earlier)".to_string()
        }
        NotAttestable::UnknownEngine(name) => {
            format!("the datastore reported an unrecognised engine `{name}`")
        }
        NotAttestable::ProbeFailed(error) => format!("the attestation probe failed: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_engines_are_attested() {
        for name in PERSISTENT_ENGINES {
            assert_eq!(
                decide(classify(Some(name)), false),
                Ok(Attestation::Attested((*name).to_string())),
                "{name} must attest"
            );
        }
    }

    #[test]
    fn a_memory_engine_is_refused_without_the_override() {
        let refusal = decide(classify(Some("memory")), false)
            .expect_err("a memory datastore must refuse startup");
        assert_eq!(refusal.reported, "memory");
    }

    /// The refusal has to be actionable by whoever finds it in a crash log, so
    /// it names the issue, the safe engines and the escape hatch.
    #[test]
    fn the_refusal_names_302_and_the_way_out() {
        let message = MemoryEngineRefused {
            reported: "memory".into(),
        }
        .to_string();
        assert!(message.contains("ilpanich/axiam#302"), "{message}");
        assert!(message.contains("surrealkv"), "{message}");
        assert!(message.contains(ALLOW_MEMORY_ENGINE_ENV), "{message}");
    }

    #[test]
    fn the_override_is_honored() {
        assert_eq!(
            decide(classify(Some("memory")), true),
            Ok(Attestation::MemoryOverridden("memory".to_string()))
        );
    }

    /// The override must not quietly widen into "accept anything unknown" —
    /// it is a memory-datastore escape hatch and nothing else.
    #[test]
    fn the_override_does_not_change_any_other_verdict() {
        assert_eq!(
            decide(classify(Some("surrealkv")), true),
            Ok(Attestation::Attested("surrealkv".to_string()))
        );
        assert_eq!(
            decide(classify(Some("hypothetical-kv")), true),
            Ok(Attestation::NotAttestable(NotAttestable::UnknownEngine(
                "hypothetical-kv".to_string()
            )))
        );
    }

    #[test]
    fn engine_names_are_matched_case_insensitively_and_through_a_path() {
        assert_eq!(
            classify(Some("SurrealKV://data/axiam.db")),
            EngineIdentity::Persistent("SurrealKV://data/axiam.db".to_string())
        );
        assert_eq!(
            classify(Some("Memory")),
            EngineIdentity::Memory("Memory".to_string())
        );
        assert_eq!(
            classify(Some("kv-mem")),
            EngineIdentity::Memory("kv-mem".to_string())
        );
    }

    /// Silence and whitespace are the same answer: we learned nothing.
    #[test]
    fn nothing_reported_is_not_attestable() {
        assert_eq!(classify(None), EngineIdentity::Unreported);
        assert_eq!(classify(Some("   ")), EngineIdentity::Unreported);
        assert_eq!(
            decide(EngineIdentity::Unreported, false),
            Ok(Attestation::NotAttestable(NotAttestable::NotExposed))
        );
    }

    /// A failed probe must never be the thing that stops a server booting.
    #[test]
    fn a_failed_probe_is_a_warning_not_a_refusal() {
        let attestation =
            Attestation::NotAttestable(NotAttestable::ProbeFailed("permission denied".into()));
        assert!(
            not_attestable_reason(match &attestation {
                Attestation::NotAttestable(r) => r,
                _ => unreachable!(),
            })
            .contains("permission denied")
        );
    }

    /// The finding in the module docs, as an executable fact rather than a
    /// claim: on this SurrealDB, the probe query parses, runs, and reports no
    /// engine. If a bump starts publishing one, this fails — and that is the
    /// signal that the hard guard above has become live.
    #[tokio::test]
    async fn probe_reports_nothing_on_this_surrealdb() {
        use surrealdb::engine::local::Mem;

        let db = Surreal::new::<Mem>(()).await.expect("in-memory connect");
        db.use_ns("attest")
            .use_db("attest")
            .await
            .expect("use ns/db");

        let reported = probe_reported_engine(&db)
            .await
            .expect("the probe query must parse and run");
        assert_eq!(
            reported, None,
            "SurrealDB started reporting a storage engine ({reported:?}). That is good news: \
             wire the hard guard in — `attest_storage_engine` already refuses `memory` — and \
             update the module docs, which currently record that no such surface exists."
        );
    }

    /// End-to-end on the only engine available to a unit test: an unattestable
    /// datastore boots, with a warning, and does not refuse — which is exactly
    /// the behaviour every real deployment gets today.
    #[tokio::test]
    async fn an_unattestable_datastore_warns_and_boots() {
        use surrealdb::engine::local::Mem;

        let db = Surreal::new::<Mem>(()).await.expect("in-memory connect");
        db.use_ns("attest")
            .use_db("attest")
            .await
            .expect("use ns/db");

        assert_eq!(
            attest_storage_engine(&db, false).await,
            Ok(Attestation::NotAttestable(NotAttestable::NotExposed))
        );
    }
}
