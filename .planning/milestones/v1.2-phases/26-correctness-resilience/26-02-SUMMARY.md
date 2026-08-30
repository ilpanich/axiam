---
phase: 26-correctness-resilience
plan: 02
subsystem: database
tags: [surrealdb, resilience, auth, token-renewal, health-check, rust]

# Dependency graph
requires:
  - phase: 13-surrealdb-connection-resilience
    provides: DbManager (HTTP-engine SurrealDB client), health_check baseline
provides:
  - Proactive periodic root-token re-signin (D-03/D-04), interval derived from the token TTL
  - AXIAM__DB__TOKEN_REFRESH_FRACTION config knob (D-20)
  - Reactive reconnect seam (DbManager::reconnect) for a fully-missed re-signin window
  - Auth-aware health_check returning DbError::Unhealthy on auth expiry/revocation (D-05)
  - connection_resilience_test.rs (pure-logic interval/health-classification tests + #[ignore]d live recovery test)
affects: [27-performance (PERF-04 poisoned-connection eviction extends DbManager::reconnect)]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Arc-shared Surreal<Client> handle so a background task and DbManager's own field observe/refresh the SAME session id (plain .clone() mints an independent session per the SDK's HTTP-engine session model)"
    - "Reactive reconnect via a brand-new Surreal::new::<Http> connection, never invalidate()+signin() on an already-401ing handle"
    - "DbError::Unhealthy as a distinct auth-classified variant, derived from surrealdb::Error::not_allowed_details() -> NotAllowedError::Auth(_)"

key-files:
  created:
    - crates/axiam-db/tests/connection_resilience_test.rs
  modified:
    - crates/axiam-db/src/connection.rs
    - crates/axiam-db/src/error.rs

key-decisions:
  - "ROOT_TOKEN_DURATION changed from a &str SurrealQL literal to a real Duration constant; the DEFINE USER ... DURATION FOR TOKEN literal is derived FROM it (root_token_duration_surql_literal) so the DB-side TTL and the re-signin cadence can never drift apart"
  - "DbManager.db changed from Surreal<Client> to Arc<Surreal<Client>> so the proactive re-signin task and DbManager's own client() field share the identical session id -- a .clone()'d handle would mint an independent session per the SDK's HTTP-engine model and would not be refreshed by the background task's signin() calls"
  - "Reactive reconnect (DbManager::reconnect) is a thin, single-attempt seam: builds a brand-new connection rather than invalidate()+signin() on the stale handle, and is documented as the extension point for PERF-04's future jittered-backoff/poisoned-connection-eviction loop (Phase 27) -- that full loop is explicitly NOT built here"
  - "health_check classification (classify_query_error) maps ANY NotAllowed(Auth(..)) failure to DbError::Unhealthy, not just AuthError::TokenExpired -- a genuinely revoked/invalid root credential must also alarm rather than being silently treated as recoverable expiry (T-26-02-02)"
  - "connect() is now a thin wrapper over connect_with_ttl(config, ROOT_TOKEN_DURATION); connect_with_ttl is a test-only entry point that lets the live-gated recovery test use a short TTL instead of waiting 4 weeks -- production behavior via connect() is unchanged"
  - "The ~30 other repository Surreal<Client> clones taken via db.client().clone() at server startup are explicitly out of this plan's scope (documented in module docs) -- each holds an independently-expiring session snapshot; only DbManager's own session (used by health_check) is kept alive by this fix. This is the same residual gap Phase 27's PERF-04 is slated to address."

requirements-completed: [CORR-02]

coverage:
  - id: D1
    description: "ROOT_TOKEN_DURATION represented as a Duration; DEFINE USER ... DURATION FOR TOKEN literal derived from it (no hardcoded \"4w\")"
    requirement: "CORR-02"
    verification:
      - kind: unit
        ref: "cargo build -p axiam-db --lib (grep confirms no \"4w\" literal remains)"
        status: pass
    human_judgment: false
  - id: D2
    description: "DbConfig.token_refresh_fraction sourced from AXIAM__DB__TOKEN_REFRESH_FRACTION (default ~0.6); re_signin_interval clamps to 0.05..=0.95"
    requirement: "CORR-02"
    verification:
      - kind: unit
        ref: "crates/axiam-db/tests/connection_resilience_test.rs#re_signin_interval_derives_from_ttl_and_fraction"
        status: pass
      - kind: unit
        ref: "crates/axiam-db/tests/connection_resilience_test.rs#re_signin_interval_clamps_fraction_below_band"
        status: pass
      - kind: unit
        ref: "crates/axiam-db/tests/connection_resilience_test.rs#re_signin_interval_clamps_fraction_above_band"
        status: pass
    human_judgment: false
  - id: D3
    description: "Proactive re-signin task keeps DbManager's own SurrealDB session alive on the SAME Arc-shared handle, without invalidate()"
    requirement: "CORR-02"
    verification:
      - kind: unit
        ref: "cargo build -p axiam-db --lib (grep confirms no invalidate() call on the proactive path)"
        status: pass
      - kind: integration
        ref: "crates/axiam-db/tests/connection_resilience_test.rs#recovers_from_token_expiry_without_restart (#[ignore], requires just dev-up)"
        status: unknown
    human_judgment: true
    rationale: "No live SurrealDB instance was available in this execution sandbox, so the #[ignore]d live-recovery test could not be run this session. It requires `just dev-up` + `cargo test -p axiam-db --test connection_resilience_test -- --ignored` to prove end-to-end recovery against a real server."
  - id: D4
    description: "Reactive reconnect seam (DbManager::reconnect) builds a brand-new connection rather than invalidate()+signin() on a stale handle"
    requirement: "CORR-02"
    verification:
      - kind: unit
        ref: "cargo build -p axiam-db --lib (grep confirms a second Surreal::new::<Http> construction beyond extend_root_token_duration)"
        status: pass
    human_judgment: false
  - id: D5
    description: "health_check returns DbError::Unhealthy (distinct from DbError::Surreal) on any auth failure -- expiry AND revoked/invalid credentials"
    requirement: "CORR-02"
    verification:
      - kind: unit
        ref: "crates/axiam-db/tests/connection_resilience_test.rs#health_classification_maps_token_expiry_to_unhealthy"
        status: pass
      - kind: unit
        ref: "crates/axiam-db/tests/connection_resilience_test.rs#health_classification_maps_revoked_credentials_to_unhealthy_too"
        status: pass
      - kind: unit
        ref: "crates/axiam-db/tests/connection_resilience_test.rs#health_classification_leaves_non_auth_errors_as_ordinary_surreal_errors"
        status: pass
    human_judgment: false

duration: 20min
completed: 2026-07-05
status: complete
---

# Phase 26 Plan 02: SurrealDB Root-Token Renewal & Resilience Summary

**DbManager now proactively re-signs its root SurrealDB session at a config-overridable fraction of the token TTL, has a reactive reconnect seam for a fully-missed window, and health_check reports a distinct `Unhealthy` on any auth failure (expiry or revoked credentials) instead of a generic query error.**

## Performance

- **Duration:** 20 min
- **Started:** 2026-07-05T08:08:00Z (approx.)
- **Completed:** 2026-07-05T08:28:47Z
- **Tasks:** 3
- **Files modified:** 3 (2 modified, 1 created)

## Accomplishments

- `ROOT_TOKEN_DURATION` is now a real `Duration` (4 weeks); the SurrealQL `DEFINE USER ... DURATION FOR TOKEN` literal is derived from it — single source of truth, no drift between the DB-side TTL and the renewal cadence.
- `DbConfig.token_refresh_fraction` (default ~0.6, overridable via `AXIAM__DB__TOKEN_REFRESH_FRACTION`) drives `re_signin_interval`, clamped to `0.05..=0.95`.
- `connect()` spawns a background task that re-signs the SAME `Arc`-shared SurrealDB session at that interval — well inside the TTL, so the cached token is still valid when the proactive request runs (no `invalidate()` needed).
- `DbManager::reconnect(config)` is a reactive, single-attempt safety net: builds a brand-new `Surreal::new::<Http>` connection rather than attempting `invalidate()`+`signin()` on an already-401ing handle (which the HTTP transport rejects before the RPC dispatcher runs). Documented as the PERF-04 (Phase 27) extension seam.
- `health_check` classifies any `NotAllowed(Auth(..))` failure — token expiry OR a genuinely revoked/invalid credential — as `DbError::Unhealthy`, distinct from an ordinary `DbError::Surreal` query error, so a readiness probe can alarm correctly.
- `crates/axiam-db/tests/connection_resilience_test.rs`: 6 passing pure-logic assertions (interval derivation/clamping, health classification for both expiry and revocation, non-auth errors unaffected) plus one `#[ignore]`d live-broker recovery test.

## Task Commits

Each task was committed atomically:

1. **Task 1: TTL-as-Duration + config fraction + proactive re-signin task (D-03/D-04/D-20)** - `18bbc25` (feat)
2. **Task 2: Reactive reconnect-on-auth-error + auth-aware health_check (D-03/D-05)** - `6c1a336` (feat)
3. **Task 3: Resilience test (interval derivation + health classification; live-gated recovery)** - `aded8b3` (test)

**Plan metadata:** (this commit, docs: complete plan)

## Files Created/Modified

- `crates/axiam-db/src/connection.rs` - `ROOT_TOKEN_DURATION` as `Duration`; `DbConfig.token_refresh_fraction`; `Arc<Surreal<Client>>`-backed `DbManager` with a proactive re-signin background task; `DbManager::reconnect` reactive seam; `classify_query_error`; auth-aware `health_check`; `connect_with_ttl` test-only override
- `crates/axiam-db/src/error.rs` - Added `DbError::Unhealthy(String)` variant
- `crates/axiam-db/tests/connection_resilience_test.rs` - New: pure-logic interval/health-classification tests + `#[ignore]`d live recovery test

## Decisions Made

- `DbManager.db` changed from `Surreal<Client>` to `Arc<Surreal<Client>>` — the proactive re-signin task and `DbManager`'s own `client()`/`health_check` must operate on the IDENTICAL session id for the periodic re-signin to actually keep that session alive; a plain `.clone()` (as used everywhere else in the codebase for repository construction) mints an independent session per the SDK's own `Clone` impl (`clone_session` snapshots current auth into a NEW session id), which would NOT be refreshed by re-signin traffic on a different clone. `client()`'s public signature (`&Surreal<Client>`) is unchanged — deref coercion from `&Arc<Surreal<Client>>` keeps all ~30 existing call sites in `axiam-server` unaffected (confirmed via a full `cargo build -p axiam-server` after the change).
- `classify_query_error` treats every `NotAllowedError::Auth(_)` variant as `Unhealthy`, not only `AuthError::TokenExpired` — per T-26-02-02, a genuinely revoked/invalid root credential must also alarm the readiness probe rather than being silently retried as if it were ordinary expiry.
- `connect()` is now a thin wrapper over a new `connect_with_ttl(config, ttl)`, which threads the TTL through `extend_root_token_duration` and `spawn_proactive_resignin`. This exists solely so the live-gated test can prove recovery against a short (seconds-scale) token TTL instead of the real 4-week constant; production `connect()` always passes the fixed `ROOT_TOKEN_DURATION` and behavior is unchanged.
- The residual gap already flagged by `26-RESEARCH.md` (Pitfall 2) — that ~30 other repository `Surreal<Client>` clones taken via `db.client().clone()` at server startup each hold an independently-expiring session, not touched by this fix — is explicitly documented in `connection.rs`'s module doc comment rather than silently left unaddressed. It is the same shape of problem Phase 27's PERF-04 ("poisoned-connection eviction") is already slated to resolve.

## Deviations from Plan

None — plan executed as written. Two small implementation choices not explicitly spelled out in the plan text were needed to make the design internally consistent, both already captured above as "Decisions Made": (1) wrapping the client handle in `Arc` so proactive re-signin actually reaches the session `health_check` reads, and (2) adding `connect_with_ttl` as the test-only override path the plan asked for ("introduce a test-only override path — e.g. a `#[cfg(test)]` setter or a `DbConfig` field the test can set"), implemented as a dedicated associated function rather than a new `DbConfig` field so production config surface is untouched.

## Issues Encountered

- No live SurrealDB instance was available in this execution sandbox, so the `#[ignore]`d live-recovery test (`recovers_from_token_expiry_without_restart`) could not be executed this session — it is correctly gated so the default `cargo test` run stays green (confirmed: 6 passed, 1 ignored, 0 failed). Running it requires `just dev-up` then `cargo test -p axiam-db --test connection_resilience_test -- --ignored`.
- Disk hygiene: ran `cargo clean` after all builds/tests completed (per CLAUDE.md), reclaiming ~12.7 GiB before finishing.

## User Setup Required

None - no external service configuration required. The new `AXIAM__DB__TOKEN_REFRESH_FRACTION` env var is optional (defaults to 0.6) and needs no action for existing deployments.

## Next Phase Readiness

- `DbManager::reconnect` is documented and positioned as the extension seam for Phase 27's PERF-04 (poisoned-connection eviction / jittered-backoff reconnect loop) — no design changes should be needed there, only wrapping this seam in retry/backoff/eviction logic.
- The residual gap (repository clones' independently-expiring sessions) remains open and is explicitly flagged in `connection.rs`'s module docs for PERF-04 to pick up.
- Recommend running the `#[ignore]`d live-recovery test against a real `just dev-up` SurrealDB instance before the phase-gate regression check, to get end-to-end proof (not just unit-level) that recovery-without-restart actually works.

---
*Phase: 26-correctness-resilience*
*Completed: 2026-07-05*

## Self-Check: PASSED

All created/modified files verified present on disk; all three task commit hashes (`18bbc25`, `6c1a336`, `aded8b3`) verified present in git history.
