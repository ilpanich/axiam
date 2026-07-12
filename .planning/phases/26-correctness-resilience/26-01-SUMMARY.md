---
phase: 26-correctness-resilience
plan: 01
subsystem: api
tags: [grpc, rate-limiting, governor, tower_governor, tokio]

# Dependency graph
requires:
  - phase: 25-security-hardening-ii
    provides: GrpcSharedRateLimitLayer/GrpcSharedRateLimitService shared-store pre-check wired into start_grpc_server (SECHRD-03) — left untouched by this plan
provides:
  - Corrected governor::Quota-based construction in build_grpc_governor_layer (crates/axiam-api-grpc/src/middleware/rate_limit.rs)
  - Sustained-throughput + monotonicity regression tests guarding against re-inverting the quota
affects: [27-performance, 30-compliance-docs]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Construct governor::Quota directly (Quota::per_second(NonZeroU32)) and feed const_period()/const_burst_size() into GovernorConfigBuilder, rather than trusting tower_governor's own .per_second()/.per_millisecond() builder convenience methods, which set the replenish PERIOD not the rate"
    - "FakeRelativeClock-driven sustained-load simulation as the reliable regression guard for token-bucket rate math (a naive first-burst smoke test cannot distinguish a correct rate limiter from an inverted one)"

key-files:
  created: []
  modified:
    - crates/axiam-api-grpc/src/middleware/rate_limit.rs

key-decisions:
  - "Burst size set to authz_per_sec (one second's worth of tokens), not authz_per_sec * 2 as the prior (still-buggy) remediation had it, per D-01"
  - "Reused governor::clock::FakeRelativeClock + RateLimiter::direct_with_clock directly against the same Quota construction the production function uses, rather than exercising the full GovernorLayer/tower stack, to keep the test fast (<1s wall) and deterministic"

patterns-established:
  - "Sustained-throughput + monotonicity assertions (not first-burst-only checks) are the required test shape for any token-bucket/rate-limit construction in this codebase"

requirements-completed: [CORR-01]

coverage:
  - id: D1
    description: "build_grpc_governor_layer constructs the governor quota via governor::Quota::per_second (burst == authz_per_sec), replacing the inverted tower_governor builder .per_second()/.burst_size(*2) construction"
    requirement: "CORR-01"
    verification:
      - kind: unit
        ref: "crates/axiam-api-grpc/src/middleware/rate_limit.rs#tests::governor_sustained_throughput_matches_configured_rate"
        status: pass
      - kind: unit
        ref: "crates/axiam-api-grpc/src/middleware/rate_limit.rs#tests::governor_higher_configured_rate_permits_strictly_more_requests"
        status: pass
    human_judgment: false

duration: 15min
completed: 2026-07-05
status: complete
---

# Phase 26 Plan 01: Correct gRPC Governor Quota Construction Summary

**Fixed the still-inverted CORR-01/CQ-B44 gRPC rate-limiter bug by constructing `governor::Quota::per_second` directly instead of trusting `tower_governor`'s period-setting `.per_second()` builder method, and added a `FakeRelativeClock`-driven sustained-throughput + monotonicity regression test.**

## Performance

- **Duration:** 15 min
- **Started:** 2026-07-05T07:39:49Z
- **Completed:** 2026-07-05T07:54:26Z
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments
- `build_grpc_governor_layer(authz_per_sec)` now builds `governor::Quota::per_second(NonZeroU32)` directly and feeds `.const_period(quota.replenish_interval())` / `.const_burst_size(quota.burst_size().get())` into `GovernorConfigBuilder`, instead of calling `tower_governor`'s own `.per_second(n).burst_size(n * 2)` (which sets the replenish PERIOD to `n` seconds, not the rate — the exact CQ-B44 inversion, still present after the prior "fix").
- Burst size corrected to `authz_per_sec` (one second's worth of tokens), not `authz_per_sec * 2`.
- Added `governor_sustained_throughput_matches_configured_rate`: drives a `FakeRelativeClock`-backed `RateLimiter` built from the same `Quota::per_second` construction over a simulated 1s window and asserts the post-burst permitted count is within a 0.7x-1.3x band of the configured rate (and > 1, ruling out the ~1-token/100s inversion).
- Added `governor_higher_configured_rate_permits_strictly_more_requests`: asserts a 100/s configured rate permits strictly more sustained requests than a 10/s rate over the same simulated window — the monotonicity property an inverted construction would violate.
- `GrpcSharedRateLimitLayer`/`GrpcSharedRateLimitService` (SECHRD-03 shared-store code) confirmed byte-for-byte unchanged (diff scope limited to the import block and `build_grpc_governor_layer`/test module only).

## Task Commits

Each task was committed atomically:

1. **Task 1: Correct the gRPC governor quota construction (D-01)** - `78b1196` (fix)
2. **Task 2: Add a sustained-throughput regression test (D-02)** - `bb4c859` (test)

**Plan metadata:** (this commit)

## Files Created/Modified
- `crates/axiam-api-grpc/src/middleware/rate_limit.rs` - Corrected `build_grpc_governor_layer` quota construction (D-01); added the two new regression tests (D-02)

## Decisions Made
- Burst size = `authz_per_sec` (not `* 2`), matching D-01's explicit acceptance criterion and the underlying `governor::Quota::per_second`'s own semantics (burst == the rate argument).
- Test drives the underlying `governor::RateLimiter`/`Quota` directly (not the full `GovernorLayer`/tower stack) via `FakeRelativeClock`, per the plan's explicit recommendation — keeps the test scoped, deterministic, and fast (0.00s wall per the test run).
- Merged the `std::num::NonZeroU32` import into the existing `std::` import group during `cargo fmt` cleanup (cosmetic only, no behavior change).

## Deviations from Plan

None - plan executed exactly as written. `cargo fmt -p axiam-api-grpc` reformatted the new test module's line-wrapping and consolidated an import group; no logic changed as a result (`cargo build`/`cargo test`/`cargo clippy -D warnings` all still pass after formatting).

## Issues Encountered
None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- CORR-01 is fully closed: raising `grpc_authz_per_sec` now strictly increases sustained gRPC authz throughput, and the regression test guards against reintroducing the inversion.
- `GrpcSharedRateLimitLayer`/`GrpcSharedRateLimitService` (SECHRD-03) remain untouched and continue to sit in front of the now-corrected in-memory governor per the existing Phase 24/25 wiring.
- No blockers for subsequent Phase 26 plans (CORR-02 through CORR-06) — this plan's scope was isolated to `rate_limit.rs`.

---
*Phase: 26-correctness-resilience*
*Completed: 2026-07-05*

## Self-Check: PASSED

- FOUND: crates/axiam-api-grpc/src/middleware/rate_limit.rs
- FOUND: 78b1196 (fix commit)
- FOUND: bb4c859 (test commit)
