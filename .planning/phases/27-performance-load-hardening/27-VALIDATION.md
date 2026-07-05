---
phase: 27
slug: performance-load-hardening
status: approved
nyquist_compliant: true
wave_0_complete: false
created: 2026-07-05
approved: 2026-07-05
---

# Phase 27 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Derived from 27-RESEARCH.md § Validation Architecture.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` (workspace-standard, per-crate `-p <crate>`) for PERF-01/02/04; `criterion` (separate `harness = false` bench, NOT `cargo test`) for PERF-05; per-SDK native runners (`cargo test`, `vitest`, `go test`, `pytest`, `mvn test`, `dotnet test`, `phpunit`) for PERF-03 |
| **Config file** | None new for Rust unit tests; `Cargo.toml` `[[bench]]` stanzas with `harness = false` added per crate for criterion benches |
| **Quick run command** | `cargo test -p <touched-crate> --lib` (scoped — never unscoped, per CLAUDE.md build hygiene) |
| **Full suite command** | Per-crate `cargo test -p <crate>`; PERF-04 live-server proof: `cargo test -p axiam-db --test connection_resilience_test -- --ignored` (needs `just dev-up`) |
| **Estimated runtime** | ~30–90 s per scoped crate suite; criterion benches minutes (manual, phase-gate only) |

> **Build-hygiene reminder (CLAUDE.md):** scope every cargo invocation to the touched crate; `cargo clean` between plans, never during an executor run. For `axiam-api-rest` builds export `SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip`.

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p <touched-crate> --lib` scoped to the touched crate only.
- **After every plan wave:** Run the crate's full scoped suite (`cargo test -p <crate>`); for PERF-04 also run the `--ignored` live-server test when `just dev-up` is available.
- **Before `/gsd-verify-work`:** All scoped Rust + SDK suites green.
- **Phase gate (NON-blocking):** `criterion` benches run once manually to populate `claude_dev/performance-report.md` — explicitly NOT part of the automated green-gate (D-15/D-16).
- **Max feedback latency:** ~90 seconds (scoped crate test).

---

## Per-Requirement Verification Map

> Task IDs (`27-PP-TT`) are assigned by the planner once PLAN.md waves exist; this draft maps by requirement.

| Requirement | Behavior | Test Type | Automated Command | File Exists |
|-------------|----------|-----------|-------------------|-------------|
| PERF-01 | Breaker trips after N failures, fails open (`Ok(None)`), cools down, resumes | unit | `cargo test -p axiam-auth --lib hibp_breaker` | ❌ W0 — new `hibp_breaker.rs` + tests |
| PERF-01 | `check_complexity` violations identical after `Vec::with_capacity(5)` | unit | `cargo test -p axiam-auth --lib check_complexity` | ✅ extend existing `policy.rs` tests |
| PERF-02 | Batch results match per-item `CheckAccess`, input order preserved | integration | `cargo test -p axiam-api-grpc --lib` / `-p axiam-api-rest --lib batch_check_access` | ❌ W0 — new correctness test |
| PERF-02 | Concurrent batch faster than sequential baseline | criterion bench | `cargo bench -p axiam-authz` (or `-p axiam-api-grpc`) | ❌ W0 — new `benches/authz_bench.rs` |
| PERF-03 | Exactly one JWKS fetch under concurrent invalid-`kid` burst (×7 SDKs) | integration, per SDK | `cargo test -p axiam-rust-sdk` · `npx vitest run jwks` · `go test ./internal/jwks/...` · `pytest sdks/python/tests/test_jwks.py` · `mvn test -Dtest=JwksVerifierTest` · `dotnet test --filter JwksVerifier` · `vendor/bin/phpunit tests/JwksVerifierTest.php` | ❌ W0 — new test per SDK (counting/mock HTTP layer; PHP uses Guzzle async promises) |
| PERF-04 | Full-jitter backoff delay ∈ `[0, capped]`; capped follows exponential-to-ceiling shape | unit | `cargo test -p axiam-db --lib reconnect_backoff_delay` | ❌ W0 — new unit tests, no live server |
| PERF-04 | Reconnect exhaustion → stays Unhealthy, keeps probing at ceiling, never exits | integration (live, `#[ignore]`) | `cargo test -p axiam-db --test connection_resilience_test -- --ignored` | 🟡 file exists, add cases |
| PERF-04 | Poisoned handle never recycled/returned post-swap | unit | `cargo test -p axiam-db --lib` | ❌ W0 |
| PERF-05 | Baseline-vs-optimized numbers recorded | manual/doc-only | `cargo bench -p axiam-auth && cargo bench -p axiam-authz && cargo bench -p axiam-pki` → paste into report | ❌ W0 — greenfield, no `benches/` today |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `crates/axiam-auth/src/hibp_breaker.rs` + unit tests — new file, no existing coverage
- [ ] `crates/axiam-authz/src/config.rs` (`AuthzConfig`) — new config section (none existed)
- [ ] `crates/axiam-auth/benches/auth_bench.rs`, `crates/axiam-authz/benches/authz_bench.rs` (or `axiam-api-grpc`), `crates/axiam-pki/benches/cert_bench.rs` — greenfield benches
- [ ] `criterion` dev-dependency added to `axiam-auth`, `axiam-authz`/`axiam-api-grpc`, `axiam-pki` `Cargo.toml` (`[[bench]] harness = false`)
- [ ] `futures`/`futures-util` 0.3.32 direct dependency added to `axiam-api-grpc` and `axiam-api-rest` (already in `Cargo.lock` — no new network fetch)
- [ ] Per-SDK JWKS single-flight test files (7 new/extended)
- [ ] `claude_dev/performance-report.md` — created as PERF-05's deliverable

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Baseline-vs-optimized perf numbers | PERF-05 | Perf-in-CI is flaky (D-15); documentation-only, no regression gate (D-16) | Run `cargo bench` for auth/authz/pki locally, capture criterion output + `cargo-flamegraph` hotspots, paste baseline & optimized numbers into `claude_dev/performance-report.md` |
| Reconnect exhaustion under real network fault | PERF-04 | No live network-fault injector in sandbox (Open Question 3) | Prefer unit-level proof of the swap/eviction logic; run `--ignored` live-server test manually with `just dev-up` if available |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies — plan-checker confirmed every task carries a checkable `<acceptance_criteria>`; greenfield Wave-0 items (hibp_breaker.rs, AuthzConfig, benches, criterion/futures deps, per-SDK JWKS tests, performance-report.md) are folded into the plans' own creation-with-test tasks
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 90s
- [x] `nyquist_compliant: true` set in frontmatter

*`wave_0_complete` remains false until the Wave-0 creation tasks are executed.*

**Approval:** approved 2026-07-05 (via gsd-plan-checker PASS)
