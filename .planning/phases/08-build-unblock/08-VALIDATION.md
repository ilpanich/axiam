---
phase: 8
slug: build-unblock
status: draft
nyquist_compliant: true
wave_0_complete: false
created: 2026-06-10
---

# Phase 8 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Source signal for this phase is the Rust build/lint toolchain — the success
> criteria ARE the test, so every criterion maps to a deterministic command.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in test harness + tokio-test (no separate framework install) |
| **Config file** | none — Cargo workspace |
| **Quick run command** | `cargo build -p axiam-server --no-default-features` |
| **Full suite command** | `cargo clippy -p axiam-server --all-targets --no-default-features -- -D warnings` |
| **Estimated runtime** | ~60–120 seconds (cold), ~10–20s incremental |

> Build-scope rule (project convention): build/check ONLY `-p axiam-server`,
> never the whole workspace. On Arch, `--no-default-features` is required
> (SAML/libxmlsec1 unavailable locally). Verify results from actual cargo
> output text, not exit codes (rtk masks them) and not IDE diagnostics.

---

## Sampling Rate

- **After every task commit:** Run `cargo build -p axiam-server --no-default-features`
- **After every plan wave:** Run `cargo clippy -p axiam-server --all-targets --no-default-features -- -D warnings`
- **Before `/gsd:verify-work`:** Full clippy `-D warnings` gate must be green AND `grep -n 'rsa::sha2' crates/axiam-server/src/cleanup.rs` returns 0 matches
- **Max feedback latency:** ~120 seconds

---

## Per-Task Verification Map

> Task IDs are assigned by the planner (next step). Each task below maps to a
> success criterion (SC) from ROADMAP REQ-12; the planner should attach these
> automated commands to the corresponding tasks' `<acceptance_criteria>`.

| SC | Requirement | Secure Behavior | Test Type | Automated Command | Status |
|----|-------------|-----------------|-----------|-------------------|--------|
| SC1 | REQ-12 | `axiam-server` binary compiles (uuid/chrono/serde_json/sha2 in `[dependencies]`) | build | `RUSTFLAGS="-Dwarnings" cargo build -p axiam-server --no-default-features` | ⬜ pending |
| SC2 | REQ-12 | `cleanup.rs` imports `sha2::{Digest, Sha256}`, not `rsa::sha2::{...}` | static | `grep -n 'rsa::sha2' crates/axiam-server/src/cleanup.rs` (expect 0 matches) | ⬜ pending |
| SC3 | REQ-12 | CI `build` / `build-no-saml` / `test` jobs go green | CI | `RUSTFLAGS="-Dwarnings" cargo build -p axiam-server --no-default-features --tests` | ⬜ pending |
| SC4 | REQ-12 | 9 test warnings cleared, `-D warnings` passes | build+lint | `cargo clippy -p axiam-server --all-targets --no-default-features -- -D warnings` | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [x] No new test files needed — phase is build-unblock only; existing test modules cover behavior
- [ ] `rsa` MUST remain in `[dev-dependencies]` (used by `req5_oidc_e2e.rs`, `req5_clock_skew.rs`) — do NOT drop it despite the ROADMAP's stale "drop rsa" note
- [ ] `cargo fmt -p axiam-server` run after edits (project convention)
- [ ] Final gate: `cargo clippy -p axiam-server --all-targets --no-default-features -- -D warnings`

*Existing infrastructure covers all phase requirements — this phase repairs the build so the existing tests can compile and run.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| CI `build` job transitions red → green | REQ-12 SC3 | True CI run requires push to branch; locally simulated only | After fix, push branch and confirm GitHub Actions `build` + `build-no-saml` + `test` jobs pass; or run `cargo build --workspace` on a SAML-capable env |

*All other phase behaviors have automated verification.*

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies (deterministic cargo commands)
- [x] Sampling continuity: every change is verified by the build/lint cycle (no 3 consecutive unverified tasks)
- [x] Wave 0 covers all MISSING references (no new test infra required)
- [x] No watch-mode flags
- [x] Feedback latency < 120s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
