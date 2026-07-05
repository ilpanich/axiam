---
phase: 27-performance-load-hardening
plan: 05
subsystem: api
tags: [rust, tonic, actix-web, futures, buffer_unordered, authz, grpc, rest, batch]

# Dependency graph
requires:
  - phase: 27-performance-load-hardening
    provides: 27-01's HibpBreaker/AuthConfig knobs and the phase's threat model / research on batch concurrency (D-06/D-07)
provides:
  - New AuthzConfig { batch_max_concurrency } (default 16) config section wired into AppConfig
  - Concurrent, bounded, order-preserving BatchCheckAccess for both gRPC and REST
  - Correctness tests proving batch results == sequential per-item results, same order
affects: [27-06, 27-07, any future phase touching authz batch endpoints or the AuthorizationServiceImpl constructor]

# Tech tracking
tech-stack:
  added: ["futures 0.3.32 (default-features=false, features=[\"std\"]) as a direct dependency of axiam-api-grpc and axiam-api-rest"]
  patterns: ["stream::iter(enumerate).map(...).buffer_unordered(n).collect() then sort_by_key(index) to restore order for bounded-concurrency batch evaluation over &self-borrowing futures (no Clone/'static bound needed)"]

key-files:
  created:
    - crates/axiam-authz/src/config.rs
  modified:
    - crates/axiam-authz/src/lib.rs
    - crates/axiam-server/src/main.rs
    - crates/axiam-api-grpc/src/server.rs
    - crates/axiam-api-grpc/src/services/authorization.rs
    - crates/axiam-api-grpc/Cargo.toml
    - crates/axiam-api-rest/src/handlers/authz_check.rs
    - crates/axiam-api-rest/Cargo.toml
    - crates/axiam-api-grpc/tests/grpc_auth_test.rs
    - crates/axiam-api-grpc/tests/grpc_authz_test.rs
    - crates/axiam-api-rest/src/tests/authz_check_test.rs

key-decisions:
  - "AuthzConfig mirrors GrpcConfig's exact structural precedent (container-level #[serde(default)] + custom impl Default) — AXIAM__AUTHZ__BATCH_MAX_CONCURRENCY maps automatically, no new env-parsing code"
  - "futures added as a direct, minimal-feature (std only) dependency in both axiam-api-grpc and axiam-api-rest — confirmed via cargo add --dry-run to resolve to the already-locked 0.3.32 (zero new download)"
  - "Both batch handlers validate ALL cross-request identity/permission checks synchronously up front, before the concurrent stream starts, preserving the pre-existing 'reject the whole batch on one bad item' semantics exactly"
  - "REST's append_check_as_audit fire-and-forget call runs inside the same mapped future as the decision, so the audit trail is still written per item regardless of concurrency"

patterns-established:
  - "Bounded concurrent batch evaluation: stream::iter(enumerate).map(|(i,req)| async move { ... }).buffer_unordered(n).collect() -> sort_by_key(|&(i,_)| i) — reusable wherever an ordered batch of independent async DB-bound checks needs overlap without unbounded fan-out"

requirements-completed: [PERF-02]

coverage:
  - id: D1
    description: "gRPC BatchCheckAccess evaluates items concurrently via buffer_unordered, bounded by AuthzConfig.batch_max_concurrency (default 16), preserving input order"
    requirement: "PERF-02"
    verification:
      - kind: unit
        ref: "crates/axiam-api-grpc/src/services/authorization.rs#tests::batch_check_access_matches_sequential_per_item_check_access"
        status: pass
    human_judgment: false
  - id: D2
    description: "REST batch_check_access evaluates items concurrently via buffer_unordered, bounded by AuthzConfig.batch_max_concurrency, preserving input order and per-item audit logging"
    requirement: "PERF-02"
    verification:
      - kind: unit
        ref: "crates/axiam-api-rest/src/tests/authz_check_test.rs#batch_check_access_matches_sequential_per_item_check_access"
        status: pass
    human_judgment: false
  - id: D3
    description: "AuthzConfig.batch_max_concurrency (default 16, env AXIAM__AUTHZ__BATCH_MAX_CONCURRENCY) wired into AppConfig and both transports"
    requirement: "PERF-02"
    verification:
      - kind: unit
        ref: "crates/axiam-authz/src/config.rs#tests"
        status: pass
    human_judgment: false

duration: 44min
completed: 2026-07-05
status: complete
---

# Phase 27 Plan 05: Concurrent BatchCheckAccess (gRPC + REST) Summary

**Parallelized BatchCheckAccess (gRPC and REST) with `futures::stream::buffer_unordered`, bounded by a new `AXIAM__AUTHZ__BATCH_MAX_CONCURRENCY` config knob (default 16), preserving result order and per-item semantics.**

## Performance

- **Duration:** ~44 min
- **Started:** 2026-07-05T14:13:54Z
- **Completed:** 2026-07-05T14:57:19Z
- **Tasks:** 3
- **Files modified:** 11 (1 created, 10 modified) + Cargo.lock

## Accomplishments
- New `AuthzConfig` (`crates/axiam-authz/src/config.rs`) with `batch_max_concurrency` (default 16), wired into `AppConfig` and threaded through both `start_grpc_server` and the REST app-data registration
- gRPC `BatchCheckAccess` rewritten to validate all cross-request identities up front (whole-batch reject on any single mismatch), then evaluate concurrently via `buffer_unordered(16)`, then `sort_by_key` to restore order
- REST `batch_check_access` rewritten the same way, additionally preserving the per-item `append_check_as_audit` fire-and-forget call inside each concurrent future
- Correctness tests for both transports assert batch results are byte-identical, same order, to sequential per-item `check_access` calls — the D-06/T-27-10 security gate for this plan

## Task Commits

Each task was committed atomically:

1. **Task 1: Create AuthzConfig + wire the concurrency bound through main.rs** - `db98174` (feat)
2. **Task 2: gRPC BatchCheckAccess concurrent + order-preserving + correctness test** - `96d9fae` (feat)
3. **Task 3: REST batch_check_access concurrent + audit-preserving + correctness test** - `99b289f` (feat)

**Plan metadata:** (this commit, following)

## Files Created/Modified
- `crates/axiam-authz/src/config.rs` - New `AuthzConfig { batch_max_concurrency: usize }`, default 16, with unit tests
- `crates/axiam-authz/src/lib.rs` - Exports `config` module and `AuthzConfig`
- `crates/axiam-authz/Cargo.toml` - Added `serde_json` dev-dependency for `AuthzConfig` deserialization tests
- `crates/axiam-server/src/main.rs` - `AppConfig.authz: AuthzConfig` field; `start_grpc_server` call passes `config.authz.batch_max_concurrency`; REST app-data registers `web::Data::new(config.authz.clone())`
- `crates/axiam-api-grpc/src/server.rs` - `start_grpc_server` gained a `batch_max_concurrency: usize` param, passed to `AuthorizationServiceImpl::new`
- `crates/axiam-api-grpc/src/services/authorization.rs` - `AuthorizationServiceImpl` gains `batch_max_concurrency` field; `batch_check_access` rewritten with up-front validation + `buffer_unordered` + `sort_by_key`; correctness test added
- `crates/axiam-api-grpc/Cargo.toml` - Added `futures` (std-only) direct dependency
- `crates/axiam-api-grpc/tests/grpc_auth_test.rs`, `tests/grpc_authz_test.rs` - Updated `AuthorizationServiceImpl::new(engine)` call sites to the new 2-arg signature
- `crates/axiam-api-rest/src/handlers/authz_check.rs` - `batch_check_access` extracts `web::Data<AuthzConfig>`; rewritten with up-front `authz:check_as` gate + `buffer_unordered` + `sort_by_key`, preserving per-item audit
- `crates/axiam-api-rest/Cargo.toml` - Added `futures` (std-only) direct dependency
- `crates/axiam-api-rest/src/tests/authz_check_test.rs` - Updated existing `batch_check_access` call sites for the new `authz_config` param; added the D-06 correctness test with a per-resource-variable test checker
- `Cargo.lock` - Updated for the two `futures` additions (already-resolved transitive 0.3.32, zero new download)

## Decisions Made
- `AuthzConfig` follows the exact `GrpcConfig` structural precedent (container `#[serde(default)]` + custom `impl Default`) rather than the `WebhookRetryConfig::from_env()` manual-parse anti-pattern
- `futures` added with `default-features = false, features = ["std"]` — minimal surface, confirmed via `cargo add --dry-run` to be a zero-network resolution against the already-locked 0.3.32
- Both batch handlers keep their up-front, synchronous, whole-batch-reject validation exactly where it was (before any `check_access` call), only parallelizing the actual per-item DB-bound evaluation step
- Correctness tests drive the real production handler/trait method (not a re-implementation of the `buffer_unordered` logic) to genuinely prove the refactor, using small concurrency bounds (2) to force interleaving and mixed allow/deny fixtures to make `sort_by_key` failures observable

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Updated two pre-existing gRPC test call sites for the new `AuthorizationServiceImpl::new` signature**
- **Found during:** Task 2
- **Issue:** `crates/axiam-api-grpc/tests/grpc_auth_test.rs` and `tests/grpc_authz_test.rs` both called `AuthorizationServiceImpl::new(engine)` (1-arg) inside their own local `start_test_server` harnesses — a compile break once the constructor's signature changed to take `batch_max_concurrency`.
- **Fix:** Updated both call sites to `AuthorizationServiceImpl::new(engine, 16)`.
- **Files modified:** `crates/axiam-api-grpc/tests/grpc_auth_test.rs`, `crates/axiam-api-grpc/tests/grpc_authz_test.rs`
- **Verification:** Confirmed via `git diff` these are the only two additional call sites in the repo (besides `server.rs`, updated in Task 1).
- **Committed in:** `96d9fae` (Task 2 commit)

**2. [Rule 3 - Blocking] Updated two pre-existing REST test call sites for the new `authz_config` param**
- **Found during:** Task 3
- **Issue:** `crates/axiam-api-rest/src/tests/authz_check_test.rs` had two existing tests (`batch_check_returns_results_in_input_order`, `batch_override_without_check_as_returns_403`) calling `batch_check_access(user, authz, audit_repo, body)` — a compile break once the handler gained a `web::Data<AuthzConfig>` param.
- **Fix:** Added a `make_authz_config()` test helper (`web::Data::new(AuthzConfig::default())`) and updated both call sites.
- **Files modified:** `crates/axiam-api-rest/src/tests/authz_check_test.rs`
- **Verification:** `cargo test -p axiam-api-rest --lib authz_check_test` — all 6 tests in the file pass.
- **Committed in:** `99b289f` (Task 3 commit)

---

**Total deviations:** 2 auto-fixed (both Rule 3 — blocking compile breaks from the intentional constructor/handler-signature changes this plan makes)
**Impact on plan:** Both fixes are mechanical call-site updates required by the plan's own intended API changes. No scope creep.

## Issues Encountered
- Hit the sandbox's ~38 GB disk quota mid-execution (linker `Bus error` during an extra, non-required `--features client` gRPC integration test run). Recovered via `cargo clean` (CLAUDE.md-sanctioned) and re-verified all of this plan's required `<verify>` commands cleanly afterward — no code was lost or altered by the clean.
- While investigating the `Bus error`, discovered `crates/axiam-api-grpc/tests/grpc_auth_test.rs` has a pre-existing (predates this plan, introduced by 27-01) compile gap: its local `test_auth_config()` is missing the `hibp_breaker_threshold`/`hibp_breaker_cooldown_secs` fields added to `AuthConfig` by 27-01. This is unrelated to PERF-02 and out of this plan's scope per the scope-boundary rule — logged to `deferred-items.md`, not fixed.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- PERF-02's success criterion #2 (bounded, order-preserving, correctness-proven concurrent BatchCheckAccess for both transports) is met.
- 27-06/27-07 (remaining phase plans, including the authz bench) can proceed; the bench should now be able to demonstrate the concurrent path outperforming the prior sequential baseline once artificial per-call latency is injected (kv-mem SurrealDB is near-zero-latency, per 27-PATTERNS.md's bench caveat).
- Follow-up recommended (logged in `deferred-items.md`): fix `grpc_auth_test.rs::test_auth_config()`'s missing `hibp_breaker_*` fields so `cargo test -p axiam-api-grpc --features client` compiles end-to-end again.

---
*Phase: 27-performance-load-hardening*
*Completed: 2026-07-05*
