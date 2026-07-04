---
phase: 24-security-hardening-i-authentication-access-control-surfaces
plan: 03
subsystem: auth
tags: [rate-limiting, x-forwarded-for, actix-governor, spoofing, rust]

# Dependency graph
requires:
  - phase: 24-security-hardening-i-authentication-access-control-surfaces (plan 02)
    provides: Public-path allowlist hardening (prior plan in this phase; no functional dependency, same crate)
provides:
  - "XForwardedForKeyExtractor keys off peer_addr() (never hops[0]) when trusted_hops >= hops.len()"
  - "Corrected nginx proxy_add_x_forwarded_for doc comment (rightmost = real client)"
  - "rate_limit_keying_test.rs — negative test proving rotating XFF no longer yields fresh buckets"
affects: [phase-24-security-hardening-i-authentication-access-control-surfaces (plan 04, shared cross-replica rate-limit store), phase-24 (plan 07, gRPC keying parity)]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Direct-call unit tests against a KeyExtractor via TestRequest::to_srv_request() + extractor.extract(&req) — no live server/DB needed to prove rate-limit key-derivation properties"

key-files:
  created:
    - crates/axiam-api-rest/tests/rate_limit_keying_test.rs
  modified:
    - crates/axiam-api-rest/src/extractors/rate_limit.rs

key-decisions:
  - "When trusted_hops >= hops.len(), skip the XFF path entirely (no indexing into hops at all) and fall through to the existing peer_addr() extraction, rather than returning an error — preserves prior behavior of always resolving a key when a peer address exists"
  - "Test exercises XForwardedForKeyExtractor::extract() directly via actix_web::test::TestRequest::to_srv_request(), avoiding a full App/DB/Governor server stack — the key-derivation property is provable at the extractor level alone"

patterns-established: []

requirements-completed: [SECHRD-03]

coverage:
  - id: D1
    description: "When trusted_hops >= hops.len(), the limiter keys off peer_addr(), never the client-controlled leftmost XFF hop"
    requirement: "SECHRD-03"
    verification:
      - kind: unit
        ref: "crates/axiam-api-rest/tests/rate_limit_keying_test.rs#insufficient_hops_falls_through_to_peer_addr_not_leftmost_hop"
        status: pass
    human_judgment: false
  - id: D2
    description: "Rotating X-Forwarded-For per request no longer yields a fresh rate-limit bucket (same peer_addr resolves to the same key across N rotated XFF values)"
    requirement: "SECHRD-03"
    verification:
      - kind: unit
        ref: "crates/axiam-api-rest/tests/rate_limit_keying_test.rs#rate_limit_xff_rotation_rejected"
        status: pass
    human_judgment: false
  - id: D3
    description: "Sufficient-hops right-indexed selection path (trusted_hops < hops.len()) is unchanged"
    requirement: "SECHRD-03"
    verification:
      - kind: unit
        ref: "crates/axiam-api-rest/tests/rate_limit_keying_test.rs#sufficient_hops_still_selects_right_indexed_hop"
        status: pass
    human_judgment: false

duration: 12min
completed: 2026-07-04
status: complete
---

# Phase 24 Plan 03: Rate-Limit XFF Keying Fix Summary

**`XForwardedForKeyExtractor` no longer falls back to the client-controlled leftmost `X-Forwarded-For` hop when there aren't enough trusted hops — it now keys off `peer_addr()`, closing the rotating-XFF rate-limit-evasion bypass, proven by a negative test.**

## Performance

- **Duration:** ~12 min
- **Started:** 2026-07-04T09:00:49Z (docs commit preceding this plan)
- **Completed:** 2026-07-04T09:09:57Z
- **Tasks:** 1
- **Files modified:** 2 (1 created, 1 modified)

## Accomplishments

- Fixed the `trusted_hops >= hops.len()` branch in `XForwardedForKeyExtractor::extract` (`crates/axiam-api-rest/src/extractors/rate_limit.rs`): it no longer indexes `hops[0]` (the attacker-controlled leftmost XFF entry) — it now skips the XFF path entirely and falls through to the existing `req.peer_addr().map(|a| a.ip())` extraction.
- Corrected the module-level and struct-level doc comments describing nginx `proxy_add_x_forwarded_for`: the proxy appends the real client to the RIGHT of the header, so the real client is the RIGHTMOST trusted entry, not the leftmost.
- Added `crates/axiam-api-rest/tests/rate_limit_keying_test.rs` with 3 tests: the plan's required `rate_limit_xff_rotation_rejected` (N requests rotating XFF with a fixed peer_addr all resolve to the same key), `insufficient_hops_falls_through_to_peer_addr_not_leftmost_hop` (direct assertion the buggy `hops[0]` fallback is gone), and `sufficient_hops_still_selects_right_indexed_hop` (regression guard proving the `trusted_hops < hops.len()` path is byte-for-byte unchanged).
- Followed the plan's `tdd="true"` RED→GREEN gate literally: committed the test file first against the still-buggy extractor (2/3 tests failed, confirming the negative test actually exercises the bug — the third, path-unchanged test correctly still passed), then restored the fix and confirmed all 3 tests pass.

## Task Commits

Each task was committed atomically, following the plan's `tdd="true"` RED→GREEN gate:

1. **Task 1 RED:** `2a791bc` (test) — added `rate_limit_keying_test.rs`; confirmed 2/3 tests fail against the pre-fix extractor
2. **Task 1 GREEN:** `2a64a84` (fix) — restored the `XForwardedForKeyExtractor` fix; confirmed all 3 tests pass

**Plan metadata:** committed alongside this SUMMARY per the state-update workflow.

## Files Created/Modified

- `crates/axiam-api-rest/src/extractors/rate_limit.rs` — Changed the `trusted_hops >= hops.len()` branch from `idx = 0` (indexing `hops[0]`) to skipping the XFF-index step entirely and letting control fall through to the existing `peer_addr()` return; corrected the nginx doc comments to state the real client is the rightmost trusted hop.
- `crates/axiam-api-rest/tests/rate_limit_keying_test.rs` (new) — 3 tests exercising `XForwardedForKeyExtractor::extract()` directly via `actix_web::test::TestRequest::to_srv_request()`.

## Decisions Made

- When `trusted_hops >= hops.len()`, the extractor does not return an error — it falls through to `peer_addr()` exactly as it already did for a missing/unparseable header, keeping the function's existing error contract (`SimpleKeyExtractionError` only when no peer address is available at all) unchanged.
- The negative test drives the `KeyExtractor::extract` trait method directly against a `ServiceRequest` built via `TestRequest::to_srv_request()`, rather than standing up a full `App` + `Governor` + DB-backed endpoint. This proves the key-derivation property in isolation, matching the plan's `<verify>` command shape (`cargo test -p axiam-api-rest --test rate_limit_keying_test rate_limit_xff_rotation_rejected`) without pulling in unrelated DB/handler setup.

## Deviations from Plan

None — plan executed exactly as written. TDD RED/GREEN gates were both satisfied with real commits (not reconstructed after the fact): the test commit was made while the extractor was still buggy (verified via `git stash` on the single modified source file, confirming 2/3 new tests failed), then the fix was restored and re-verified before the GREEN commit.

## Issues Encountered

None. `SWAGGER_UI_DOWNLOAD_URL` workaround from `CLAUDE.md`'s Build & Disk Hygiene policy was exported before every `cargo` invocation as required; all commands were scoped to `-p axiam-api-rest` per the build-environment guidance (no full-workspace build/test run).

## TDD Gate Compliance

Both gates present in git history for this plan's single task:
- RED: `2a791bc` `test(24-03): add failing test proving rotating XFF yields fresh rate-limit buckets` — committed while the extractor still had the `hops[0]` bug; `cargo test -p axiam-api-rest --test rate_limit_keying_test` showed 2 failed / 1 passed at this commit.
- GREEN: `2a64a84` `fix(24-03): key off peer_addr() when XFF hops are insufficient (SECHRD-03)` — all 3 tests pass at this commit.
- No REFACTOR commit was needed (no cleanup required after GREEN).

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- SECHRD-03 keying half closed (ROADMAP SC #2, keying portion): rotating `X-Forwarded-For` per request no longer yields a fresh rate-limit bucket; `trusted_hops >= hops.len()` now keys off `peer_addr()`, proven by `rate_limit_xff_rotation_rejected`.
- Remaining SECHRD-03 scope explicitly deferred per this plan's objective: the shared cross-replica rate-limit store is Plan 24-04; gRPC `SmartIpKeyExtractor` keying parity is Plan 24-07. Neither is blocked by this plan.
- No blockers for the remaining Phase 24 plans or the parallel Phase 25 track.

---
*Phase: 24-security-hardening-i-authentication-access-control-surfaces*
*Completed: 2026-07-04*

## Self-Check: PASSED

- FOUND: crates/axiam-api-rest/src/extractors/rate_limit.rs
- FOUND: crates/axiam-api-rest/tests/rate_limit_keying_test.rs
- FOUND: commit 2a791bc
- FOUND: commit 2a64a84
