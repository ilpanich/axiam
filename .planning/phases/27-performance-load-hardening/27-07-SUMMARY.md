---
phase: 27-performance-load-hardening
plan: 07
subsystem: performance
tags: [criterion, benchmarking, argon2id, eddsa, x509, rbac, tokio, futures, performance-report]

# Dependency graph
requires:
  - phase: 27-performance-load-hardening
    provides: "27-05's concurrent buffer_unordered(16) BatchCheckAccess implementation (PERF-02), which this plan's authz_bench evidences with real numbers"
provides:
  - "Greenfield criterion micro-benches for auth (Argon2id hash/verify + EdDSA mint), authz (single check_access + sequential-vs-concurrent batch), and cert-validation (X.509 chain verify_signature)"
  - "claude_dev/performance-report.md with real baseline-vs-optimized numbers, closing PERF-05"
affects: [30-docs-compliance]

# Tech tracking
tech-stack:
  added: ["criterion 0.8.2 (html_reports, async_tokio features)", "futures 0.3.32 (axiam-authz dev-dependency, buffer_unordered for the bench)"]
  patterns: ["[[bench]] harness = false greenfield criterion setup, no benches/ dir existed anywhere in the workspace before this plan"]

key-files:
  created:
    - crates/axiam-auth/benches/auth_bench.rs
    - crates/axiam-authz/benches/authz_bench.rs
    - crates/axiam-pki/benches/cert_bench.rs
    - claude_dev/performance-report.md
  modified:
    - crates/axiam-auth/Cargo.toml
    - crates/axiam-authz/Cargo.toml
    - crates/axiam-pki/Cargo.toml
    - Cargo.lock

key-decisions:
  - "criterion resolved to 0.8.2 (not the RESEARCH-assumed 0.5.x) — confirmed via cargo add --dry-run at execution time, per A1"
  - "criterion::black_box is deprecated in 0.8.2 in favor of std::hint::black_box — used std::hint::black_box directly in all three bench files to keep cargo clippy -D warnings clean"
  - "authz_bench injects a bench-only tokio::time::sleep(2ms) per check_access call (not touching engine.rs) to make the sequential-vs-concurrent batch comparison meaningful, since kv-mem SurrealDB is near-zero-latency"

patterns-established:
  - "Criterion bench module layout: [[bench]] name = \"<x>_bench\" harness = false in Cargo.toml + benches/<x>_bench.rs using criterion_group!/criterion_main!, fixtures built once outside the timed closure"

requirements-completed: [PERF-05]

coverage:
  - id: D1
    description: "criterion micro-bench for auth (Argon2id verify + EdDSA token mint) exists and compiles"
    requirement: "PERF-05"
    verification:
      - kind: unit
        ref: "cargo bench -p axiam-auth --no-run"
        status: pass
    human_judgment: false
  - id: D2
    description: "criterion micro-bench for authz (single check_access + sequential-vs-concurrent BatchCheckAccess comparison with injected latency) exists and compiles"
    requirement: "PERF-05"
    verification:
      - kind: unit
        ref: "cargo bench -p axiam-authz --no-run"
        status: pass
    human_judgment: false
  - id: D3
    description: "criterion micro-bench for cert-validation (X.509 chain verify_signature) exists and compiles"
    requirement: "PERF-05"
    verification:
      - kind: unit
        ref: "cargo bench -p axiam-pki --no-run"
        status: pass
    human_judgment: false
  - id: D4
    description: "claude_dev/performance-report.md records baseline-vs-optimized numbers for auth, authz-check, and cert validation, manual/local framing, flamegraph invocation documented"
    requirement: "PERF-05"
    verification:
      - kind: other
        ref: "test -f claude_dev/performance-report.md && grep -qi baseline && grep -qi optimized (REPORT_OK)"
        status: pass
    human_judgment: false

duration: 40min
completed: 2026-07-05
status: complete
---

# Phase 27 Plan 07: Criterion Micro-Benchmarks + Performance Report Summary

**Greenfield criterion benches for auth/authz/cert-validation hot paths, with a real ~8.4x sequential-vs-concurrent speedup recorded for PERF-02's batch authz optimization**

## Performance

- **Duration:** ~40 min
- **Started:** 2026-07-05T15:22:00Z
- **Completed:** 2026-07-05T15:49:00Z
- **Tasks:** 3 completed
- **Files modified:** 8 (4 Cargo.toml/lock, 3 new bench files, 1 new report doc)

## Accomplishments

- Added criterion 0.8.2 (`html_reports`) as a dev-dependency to `axiam-auth`, `axiam-authz` (+ `async_tokio` + `futures` for the async batch comparison), and `axiam-pki`, with `[[bench]] harness = false` stanzas — no `benches/` directory existed anywhere in the workspace before this plan
- Wrote `auth_bench.rs` (Argon2id `hash_password`/`verify_password` + EdDSA `issue_access_token` with `resolve_keys()` called once outside the timed closure), `cert_bench.rs` (isolated X.509 `verify_signature` step using `rcgen` self-signed CA + leaf fixtures built once), and `authz_bench.rs` (single seeded-kv-mem `check_access` + a sequential-vs-concurrent 20-item `BatchCheckAccess` comparison with injected 2ms per-call latency)
- Ran all three benches for real and recorded the numbers in `claude_dev/performance-report.md`: the authz batch group shows sequential ~95.9ms vs. `buffer_unordered(16)` ~11.4ms (≈8.4x speedup) — concrete evidence for PERF-02's "concurrent batch faster than sequential" acceptance criterion
- Documented the `cargo-flamegraph` invocation as a manual, deferred step (confirmed neither `perf` nor `cargo-flamegraph` is installed in this sandbox) and stated explicitly that all three benches are manual/local, not a CI gate (D-15/D-16)

## Task Commits

Each task was committed atomically:

1. **Task 1: auth_bench + cert_bench (criterion greenfield)** - `41fec69` (feat)
2. **Task 2: authz_bench — single CheckAccess + sequential-vs-concurrent batch** - `c871ae9` (feat)
3. **Task 3: Run benches + author performance-report.md** - `097311e` (docs)

**Plan metadata:** (this commit, immediately following)

## Files Created/Modified

- `crates/axiam-auth/Cargo.toml` - added `criterion` dev-dependency + `[[bench]] auth_bench`
- `crates/axiam-auth/benches/auth_bench.rs` - Argon2id hash/verify + EdDSA mint benches
- `crates/axiam-authz/Cargo.toml` - added `criterion` (async_tokio) + `futures` dev-dependencies + `[[bench]] authz_bench`
- `crates/axiam-authz/benches/authz_bench.rs` - single check_access + sequential-vs-concurrent batch benches
- `crates/axiam-pki/Cargo.toml` - added `criterion` dev-dependency + `[[bench]] cert_bench`
- `crates/axiam-pki/benches/cert_bench.rs` - X.509 chain verify_signature bench
- `claude_dev/performance-report.md` - baseline-vs-optimized numbers for all three paths
- `Cargo.lock` - resolved criterion 0.8.2 + transitive deps (futures/futures-util already resolved)

## Decisions Made

- Used the real `cargo add --dry-run`-resolved criterion version (0.8.2) rather than RESEARCH's assumed 0.5.x, per the plan's own instruction to re-resolve at execution time (A1 in RESEARCH)
- Switched all three benches to `std::hint::black_box` instead of the criterion-re-exported `black_box`, since criterion 0.8.2 deprecates its own re-export — kept `cargo clippy -D warnings` clean per CLAUDE.md
- Injected a bench-only `tokio::time::sleep(2ms)` wrapper around `check_access` calls in the batch group (not touching `engine.rs`) so the sequential-vs-concurrent comparison is meaningful against near-zero-latency kv-mem, per RESEARCH Open Question 2's recommendation

## Deviations from Plan

None — plan executed exactly as written. The only adjustments were the criterion version (0.8.2 vs. assumed 0.5.x) and the `black_box` deprecation fix, both explicitly anticipated/sanctioned by the plan and RESEARCH's assumption log (re-resolve at execution time).

## Issues Encountered

None. `cargo bench -p axiam-auth --no-run` took ~7m15s on first compile (surrealdb-core release build, a heavy dev-dependency shared across the workspace's existing test suite) — expected per the plan's build-environment notes, not a build failure. Disk stayed well within budget throughout (peaked ~21GB used / 17GB free).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

PERF-05 is closed — all five PERF-* requirements (PERF-01 through PERF-05) in the v1.2 milestone's Performance feature group are now addressed across phase 27's plans. Phase 27 (performance-load-hardening) is complete; ready to advance to Phase 28 (FUNC completeness) per the roadmap.

## Self-Check: PASSED

All 4 created files verified present on disk; all 4 commit hashes (`41fec69`, `c871ae9`, `097311e`, `fe053c7`) verified present in `git log --oneline --all`.

---
*Phase: 27-performance-load-hardening*
*Completed: 2026-07-05*
