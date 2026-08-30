---
phase: 24
slug: security-hardening-i-authentication-access-control-surfaces
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-03
---

# Phase 24 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution. Every SECHRD fix
> ships a **negative or concurrency test** proving the attack/race is now rejected — this is
> the phase's defining success signal, not optional. Seeded from `24-RESEARCH.md` §Validation
> Architecture; the per-task map is finalized by the planner/executor.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` (built-in Rust harness) + `#[tokio::test]` for async + `actix_web::test` for REST integration |
| **Config file** | none — per-crate `Cargo.toml` `[dev-dependencies]`; `tokio-test` available workspace-wide |
| **Quick run command** | `cargo test -p <crate> <test_name>` (e.g. `cargo test -p axiam-auth totp_replay`) |
| **Full suite command** | `cargo test --workspace` (CI-only per CLAUDE.md — local dev uses per-crate `-p`) |
| **Estimated runtime** | ~per-crate: seconds to low-minutes; timing tests are `#[ignore]`d and run explicitly |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p <crate> <specific_test>` for the crate(s) touched by that task
- **After every plan wave:** Run `cargo test -p axiam-db -p axiam-auth -p axiam-api-rest -p axiam-api-grpc` (the four crates every SECHRD surface lives in)
- **Before `/gsd-verify-work`:** `cargo clippy --workspace --all-targets -- -D warnings` + `cargo fmt --all -- --check` + full per-touched-crate test run must be green
- **Max feedback latency:** < 120 seconds (per-crate quick run)

---

## Per-Task Verification Map

> Requirement-level seed from research. The planner assigns Task IDs / Plan / Wave and links each
> row to a `<threat_model>` ref; the executor sets Status. `is_public_path` is the only surface
> where the segment-boundary bug is currently latent (single wildcard entry) — still tested.

| Requirement | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|-------------|-----------------|-----------|-------------------|-------------|--------|
| SECHRD-01 | N parallel submissions of one valid TOTP code succeed at most once (DB CAS) | concurrency (`tokio::spawn`×N, `join_all`, assert exactly 1 success) | `cargo test -p axiam-db totp_step_cas_concurrent` | ❌ W0 | ⬜ pending |
| SECHRD-01 | −1-skew-accepted code cannot be replayed in a later wall-clock step | unit (explicit step params) | `cargo test -p axiam-auth totp_skew_step_recorded` | ❌ W0 | ⬜ pending |
| SECHRD-03 | Rotating XFF per request no longer yields a fresh bucket | integration (`test::call_service`, N XFF values, assert 429) | `cargo test -p axiam-api-rest rate_limit_xff_rotation_rejected` | ❌ W0 | ⬜ pending |
| SECHRD-03 | Shared store enforces limit across replicas (2 governors, 1 SurrealDB) | integration | `cargo test -p axiam-api-rest rate_limit_shared_store_cross_instance` | ❌ W0 | ⬜ pending |
| SECHRD-03 | gRPC limiter shares store + keys off verified peer (not leftmost XFF) | integration | `cargo test -p axiam-api-grpc rate_limit_shared_store` | ❌ W0 | ⬜ pending |
| SECHRD-04 | Two concurrent first-run bootstraps create at most one super-admin | concurrency (`tokio::spawn`×2, same DB, assert 1 Created + 1 error) | `cargo test -p axiam-api-rest bootstrap_concurrent_race_single_admin` | ❌ W0 | ⬜ pending |
| SECHRD-04 | Bootstrap refused when gate (env var / setup token) unset | integration (reuse `env_lock()`/`env_guard()`) | `cargo test -p axiam-api-rest bootstrap_refused_when_gate_unset` | ❌ W0 | ⬜ pending |
| SECHRD-11 | Non-canonical/wrong-segment path cannot slip past the allowlist | unit (direct `is_public_path`) | `cargo test -p axiam-api-rest is_public_path` | ❌ W0 (extend inline `mod tests`) | ⬜ pending |
| SECHRD-12 | Ineligible/unknown/federated reset is time-indistinguishable | timing (statistical, `#[ignore]`d, run explicit) | `cargo test -p axiam-auth reset_timing_indistinguishable -- --ignored` | ❌ W0 | ⬜ pending |
| SECHRD-12 | Peppered buffer zeroized (`Zeroizing` at call site) | structural / grep-gate (memory wipe not runtime-assertable) | `cargo test -p axiam-auth` + grep-gate for `Zeroizing` wrap | N/A structural | ⬜ pending |
| SECHRD-12 | Current-password reuse blocked on the unauthenticated reset path | unit/integration | `cargo test -p axiam-auth confirm_reset_rejects_current_password` | ❌ W0 | ⬜ pending |
| SECHRD-12 | GDPR audit-write dead-letters to file + syslog on DB-write failure | integration (inject failing audit repo, assert both sinks) | `cargo test -p axiam-api-rest gdpr_audit_dlq_on_db_failure` | ❌ W0 (needs injectable audit-write seam) | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `crates/axiam-db/tests/totp_step_cas_test.rs` — new file, SECHRD-01 concurrency AC
- [ ] `crates/axiam-api-rest/tests/rate_limit_shared_store_test.rs` — new file, SECHRD-03 keying + shared-store ACs
- [ ] `crates/axiam-api-grpc/tests/rate_limit_shared_store_test.rs` — new file, SECHRD-03 gRPC coverage (D-01c)
- [ ] Extend `crates/axiam-api-rest/tests/bootstrap_test.rs` — SECHRD-04 concurrency + mandatory-gate cases (reuse `env_lock()`/`env_guard()` at `:56-67`)
- [ ] Extend `crates/axiam-api-rest/src/middleware/authz.rs` inline `mod tests` — SECHRD-11 normalization + segment-boundary cases
- [ ] Extend `crates/axiam-auth/src/password_reset.rs` inline `mod tests` — SECHRD-12 current-password-reuse + timing cases
- [ ] `crates/axiam-api-rest/tests/gdpr_audit_dlq_test.rs` — new file (or extend `gdpr_test.rs`), SECHRD-12 DLQ AC; requires deciding the audit-repo injectability seam first
- [ ] No new test-framework install needed — `cargo test`/`tokio::test`/`actix_web::test` already wired workspace-wide

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Peppered-buffer memory wipe | SECHRD-12 / T19.24 | Memory-wipe cannot be asserted at `cargo test` level without `unsafe`/process inspection | Grep-gate that the peppered buffer is wrapped in `Zeroizing`/pepper in `secrecy` at the call site (mirrors existing gate-script pattern); optional `miri` test if tooling available |
| Setup-token single-line first-boot log | SECHRD-04 / D-03b | The deliberate one-time operator log line is an operational check | Boot with both gates unset ⇒ refuse; boot fresh ⇒ token logged exactly once and consumed-once thereafter |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
