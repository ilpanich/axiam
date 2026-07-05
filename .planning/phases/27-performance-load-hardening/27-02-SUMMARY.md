---
phase: 27-performance-load-hardening
plan: 02
subsystem: sdk
tags: [jwks, single-flight, tokio, threading, rust-sdk, python-sdk, perf]

# Dependency graph
requires:
  - phase: 16-rust-sdk
    provides: JwksVerifier (Rust SDK's JWKS fetch/cache/verify implementation)
  - phase: 19-python-sdk
    provides: JwksVerifier (Python SDK's JWKS fetch/cache/verify wrapper over PyJWKClient)
provides:
  - Rust SDK JwksVerifier.fetch_lock (tokio::sync::Mutex<()>) coalescing concurrent JWKS fetches to exactly one
  - Python SDK JwksVerifier._refetch_lock widened to span the entire lookup-and-fetch sequence
  - sdks/rust/tests/jwks_single_flight_test.rs counting-mock burst test
  - sdks/python/tests/test_jwks.py concurrent-burst test (threading.Barrier-synchronized)
affects: [27-03, 27-04, 27-05, 27-06, 27-07]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Double-checked-lock JWKS fetch coalescing: cheap freshness check, then acquire a dedicated fetch_lock/_refetch_lock, re-check under the lock, only then perform the actual network fetch"

key-files:
  created:
    - sdks/rust/tests/jwks_single_flight_test.rs
  modified:
    - sdks/rust/src/token/jwks.rs
    - sdks/python/src/axiam_sdk/_jwks.py
    - sdks/python/tests/test_jwks.py
    - .gitignore

key-decisions:
  - "Rust: fetch_lock: tokio::sync::Mutex<()> added to JwksVerifier; both get_or_fetch (normal cache-miss) and force_refetch_if_allowed (unknown-kid path) acquire the same lock and double-check the cache before fetching, so both paths serialize on one guard"
  - "Python: widened _refetch_lock to wrap the ENTIRE _get_signing_key lookup-and-fetch sequence (not just the invalidation decision) — this was necessary (not just the except-block retry) because PyJWKClient's own get_signing_key() has no cheap lock-free peek API, so guaranteeing exactly-one-fetch under concurrency requires serializing the whole call, not only the forced-refetch fallback"
  - "Fixed a latent bug in the Python test double _FakeJwksEndpoint: its fetch mock never populated PyJWKClient's own jwk_set_cache, so the client's TTL cache never actually warmed up under test — making single-flight coalescing structurally unobservable regardless of any production-code locking. Corrected to mirror PyJWKClient.fetch_data's real cache-populating side effect"
  - "sdks/python/.venv and uv.lock (this sandbox's ephemeral `uv run --with-editable` test environment) added to .gitignore — this SDK has no committed venv/lockfile convention"

requirements-completed: [PERF-03]

coverage:
  - id: D1
    description: "Rust SDK: 8 concurrent verify() calls against a cold JWKS cache collapse to exactly one network fetch; a subsequent call reuses the fresh cache with zero additional fetches"
    requirement: "PERF-03"
    verification:
      - kind: integration
        ref: "sdks/rust/tests/jwks_single_flight_test.rs#concurrent_cache_miss_burst_triggers_exactly_one_fetch"
        status: pass
      - kind: integration
        ref: "sdks/rust/tests/jwks_single_flight_test.rs#second_call_after_fetch_completes_uses_cache_with_no_additional_fetch"
        status: pass
    human_judgment: false
  - id: D2
    description: "Python SDK: 8 concurrent verify() calls (threading.Barrier-synchronized) against a cold JWKS cache collapse to exactly one network fetch; every caller still verifies successfully"
    requirement: "PERF-03"
    verification:
      - kind: unit
        ref: "sdks/python/tests/test_jwks.py#test_concurrent_cache_miss_burst_triggers_exactly_one_fetch"
        status: pass
    human_judgment: false
  - id: D3
    description: "Both SDKs' cryptographic verification path (jsonwebtoken / PyJWT decode+verify), JWKS TTL freshness, and forced-refetch cooldown are unchanged — single-flight is a coalescing wrapper only"
    requirement: "PERF-03"
    verification:
      - kind: integration
        ref: "cd sdks/rust && cargo test (full suite, 0 regressions)"
        status: pass
      - kind: unit
        ref: "cd sdks/python && pytest (full suite, 141 passed)"
        status: pass
    human_judgment: false

duration: 13min
completed: 2026-07-05
status: complete
---

# Phase 27 Plan 02: Rust + Python SDK JWKS Single-Flight Summary

**Hand-rolled fetch-guard (tokio::sync::Mutex in Rust, widened threading.Lock in Python) collapses a concurrent JWKS cache-miss burst to exactly one network fetch in both SDKs, closing PERF-03 for 2 of 7 SDKs.**

## Performance

- **Duration:** 13 min
- **Started:** 2026-07-05T13:22:19Z
- **Completed:** 2026-07-05T13:34:57Z
- **Tasks:** 2
- **Files modified:** 5 (2 created, 3 modified)

## Accomplishments
- Rust SDK's `JwksVerifier` gained a `fetch_lock: tokio::sync::Mutex<()>`; both the normal cache-miss path (`get_or_fetch`) and the unknown-kid forced-refetch path (`force_refetch_if_allowed`) now acquire this same lock and double-check the cache before fetching, closing the pre-existing TOCTOU race
- Python SDK's `JwksVerifier._refetch_lock` widened to span the entire lookup-and-fetch sequence via a new `_get_signing_key` helper, rather than guarding only the invalidation decision
- New counting-mock burst tests in both SDKs prove exactly 1 fetch across 8 concurrent cold-cache callers, and that a subsequent call reuses the warm cache with 0 additional fetches
- Full regression suites green in both SDKs: `cargo test` (Rust, all existing tests unaffected) and `pytest` (Python, 141 passed across the whole SDK including fastapi/django optional extras)

## Task Commits

Each task followed the RED → GREEN TDD cycle with atomic commits:

1. **Task 1: Rust SDK JWKS single-flight**
   - `369a323` - test(27-02): add failing test for Rust SDK JWKS single-flight (RED — confirmed 8 fetches without the guard)
   - `f21ac51` - feat(27-02): Rust SDK JWKS single-flight fetch guard (GREEN)
2. **Task 2: Python SDK JWKS single-flight**
   - `6800fa6` - test(27-02): add failing test for Python SDK JWKS single-flight (RED — confirmed 8 fetches without the guard)
   - `7d06361` - feat(27-02): Python SDK JWKS single-flight fetch guard (GREEN)

**Plan metadata:** (this commit, docs: complete plan)

## Files Created/Modified
- `sdks/rust/src/token/jwks.rs` - Added `fetch_lock: tokio::sync::Mutex<()>`; `get_or_fetch` and `force_refetch_if_allowed` both acquire it and double-check the cache before the actual fetch
- `sdks/rust/tests/jwks_single_flight_test.rs` (new) - Counting-mock burst test (8 concurrent `verify()` calls, wiremock responder incrementing an `AtomicUsize`) + a cache-reuse follow-up test
- `sdks/python/src/axiam_sdk/_jwks.py` - `verify()` now delegates to `_get_signing_key`, which holds `_refetch_lock` around the entire `get_signing_key_from_jwt` lookup-and-fetch sequence (both the normal attempt and the forced-refetch fallback)
- `sdks/python/tests/test_jwks.py` - Added `threading.Barrier`-synchronized 8-thread burst test; corrected `_FakeJwksEndpoint._fetch_data` to populate `jwk_set_cache` on a successful fetch (mirroring the real `PyJWKClient.fetch_data`), without which the mock could never demonstrate cache reuse
- `.gitignore` - Ignored `sdks/python/.venv/` and `sdks/python/uv.lock`, the ephemeral `uv run --with-editable` test environment used to run this SDK's suite in this sandbox

## Decisions Made
- Rust: single `fetch_lock` shared by both `get_or_fetch` and `force_refetch_if_allowed`, so a burst that starts via either entry point still serializes on the same guard (matches 27-PATTERNS.md's documented shape)
- Python: the fix necessarily extends beyond "just widen the lock around the except-block retry" (the literal plan action wording) to wrapping the *entire* `get_signing_key_from_jwt` call (including the first, non-exceptional attempt). Rationale: `PyJWKClient` exposes no cheap, side-effect-free way to peek "is the cache already warm with the kid I need" — its own `get_signing_key()` unconditionally performs a real second fetch (`refresh=True`) on any mismatch. Guarding only the except-block leaves the initial attempt racing unprotected, which cannot reach "exactly 1 fetch" for a genuinely concurrent cold-cache burst. This is the same double-checked-lock *shape* the plan specifies for Rust (must_haves.truths is the graded acceptance target and explicitly requires "exactly ONE network fetch" under concurrency) — applied to the one call PyJWKClient exposes.
- Fixed the Python test double's cache-populate gap (a pre-existing bug in `_FakeJwksEndpoint`, not in production code) rather than working around it, since no production-code fix could make the coalescing observable through a test mock that silently disabled the underlying TTL cache.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Widened the Python single-flight guard to cover the initial lookup attempt, not only the forced-refetch fallback**
- **Found during:** Task 2 (Python SDK JWKS single-flight)
- **Issue:** The plan's literal action text describes widening `_refetch_lock` around "the forced-refetch-and-refetch sequence" (i.e., only the except-block retry after an unknown-kid failure). Tracing `PyJWKClient.get_signing_key()`'s actual internals showed it performs its own unconditional second fetch (`refresh=True`) on any kid mismatch, entirely inside the *unprotected* first (`try`) attempt — before our except-block/lock code ever runs. Guarding only the except-block therefore cannot guarantee "exactly one fetch" for a genuinely concurrent burst (the required, graded acceptance criterion in `must_haves.truths`), since every racing thread would independently execute the unprotected first attempt.
- **Fix:** Introduced `_get_signing_key`, which holds `_refetch_lock` around the entire `get_signing_key_from_jwt` call — both the normal attempt and the forced-refetch fallback — so only one thread at a time ever enters `PyJWKClient` internals; every other waiter, once it acquires the lock, reuses the now-warm cache from a prior holder.
- **Files modified:** `sdks/python/src/axiam_sdk/_jwks.py`
- **Verification:** New burst test (`test_concurrent_cache_miss_burst_triggers_exactly_one_fetch`) asserts exactly 1 fetch across 8 threads, run 5x with no flakes; full existing `test_jwks.py` suite (8 tests) and full SDK suite (141 tests) pass unchanged
- **Committed in:** `7d06361` (Task 2 GREEN commit)

**2. [Rule 1 - Bug] Fixed `_FakeJwksEndpoint` test double to populate `jwk_set_cache` on fetch**
- **Found during:** Task 2 (Python SDK JWKS single-flight), while diagnosing why the burst test still showed 8 fetches after the production-code fix
- **Issue:** The pre-existing test mock replaced `PyJWKClient.fetch_data` entirely, without replicating its cache-populating side effect (`self.jwk_set_cache.put(jwk_set)`). This meant `PyJWKClient`'s own TTL cache never actually warmed up under test, so every lookup — even a same-kid repeat call from a thread that acquired the lock *after* a peer already fetched — appeared to require a fresh fetch, regardless of any locking in the code under test.
- **Fix:** `_FakeJwksEndpoint._fetch_data` now calls `self._client.jwk_set_cache.put(data)` on success, mirroring the real `PyJWKClient.fetch_data`.
- **Files modified:** `sdks/python/tests/test_jwks.py`
- **Verification:** Retraced all 4 pre-existing `test_jwks.py` tests by hand against the corrected mock to confirm no regression (all still pass; call-count assertions unaffected since the affected code paths either never hit the invalidate-cache branch or the mock-fix is a no-op after that branch wipes `jwk_set_cache` to `None`)
- **Committed in:** `7d06361` (Task 2 GREEN commit)

---

**Total deviations:** 2 auto-fixed (both Rule 1 — bugs blocking the stated "exactly one fetch" acceptance criterion from being achievable/observable)
**Impact on plan:** Both fixes were necessary for the plan's own acceptance criteria to hold; no scope creep beyond the JWKS single-flight coalescing this plan targets. Cryptographic verification, TTL freshness, and the forced-refetch cooldown value are untouched in both SDKs, matching D-08's "coalescing wrapper only" constraint.

## Issues Encountered
- Ran the Python SDK test suite via `uv run --with-editable ".[dev,fastapi,django]" pytest` since no committed venv/lockfile exists for this SDK in the sandbox; this created an ephemeral `.venv/` and `uv.lock` at `sdks/python/`, now gitignored (see Decisions).
- PyJWKClient's `get_signing_key()` internally performs its own second (`refresh=True`) fetch on any kid mismatch, independent of any locking this SDK adds — this is upstream library behavior, unrelated to and unaffected by this plan's fix, and does not block the "exactly one fetch" guarantee for the cold-cache-with-matching-kid scenario this plan's test proves.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- PERF-03 closed for the Rust and Python SDKs (2 of 7). Go, Java, C#, TypeScript, and PHP SDKs remain — 27-PATTERNS.md already documents the per-language shape for each (Go: explicit `sync.Mutex` around `jwk.Cache.Refresh`; Java: `ReentrantLock`/`synchronized` around Nimbus's refetch; C#: `SemaphoreSlim(1,1)`; TypeScript: verify whether `jose`'s `createRemoteJWKSet` already coalesces, wrap with a lazy-promise singleton if not; PHP: Guzzle-promise-based guard, with the documented FPM-vacuous-guarantee caveat).
- No blockers for subsequent 27-* plans.

---
*Phase: 27-performance-load-hardening*
*Completed: 2026-07-05*
