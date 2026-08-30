---
phase: 8
slug: build-unblock
status: passed
verified: 2026-06-10
verifier: inline (orchestrator) — deterministic build/lint commands, no behavioral surface
requirements: [REQ-12]
plans_verified: 1
must_haves_met: 5/5
---

# Phase 8 — Verification (Build Unblock, Wave 0)

> Goal-backward verification. Phase goal: **`axiam-server` compiles and the CI
> build job passes under `-D warnings`, unblocking every subsequent remediation
> wave.** The goal is a build/lint property, so every check below is a
> deterministic command whose actual output was read (per project convention:
> `-p axiam-server` only, `--no-default-features` on Arch, trust output text not
> exit codes/IDE diagnostics).

## Success Criteria (from ROADMAP)

| SC | Criterion | Command | Result |
|----|-----------|---------|--------|
| SC1 | `cargo build -p axiam-server` succeeds (uuid/chrono/serde_json/sha2 in `[dependencies]`) | `RUSTFLAGS="-Dwarnings" cargo build -p axiam-server --no-default-features` | ✅ `Finished dev profile in 5m07s`, 0 errors/warnings |
| SC2 | `cleanup.rs` imports `sha2::{Digest, Sha256}`, not `rsa::sha2::{...}` | `grep -n 'rsa::sha2' …/cleanup.rs` → 0; `grep -c 'use sha2::{Digest, Sha256}'` → 2 | ✅ |
| SC3 | CI `build`/`build-no-saml`/`test` go green (local proxy: test build) | `RUSTFLAGS="-Dwarnings" cargo build -p axiam-server --no-default-features --tests` | ✅ `Finished in 4m17s`, clean. True-CI run is the manual item below. |
| SC4 | 12→(actually 9) test warnings cleared; `-D warnings` passes | `cargo clippy -p axiam-server --all-targets --no-default-features -- -D warnings` | ✅ `Finished` clean, 0 warnings |

## must_haves (plan 08-01)

| Truth | Evidence | Met |
|-------|----------|-----|
| build succeeds, 0 errors/warnings | SC1/SC3 green under `-Dwarnings` | ✅ |
| cleanup.rs imports sha2 directly (no rsa::sha2) | `grep rsa::sha2` → 0 | ✅ |
| uuid/chrono/serde_json/sha2 in `[dependencies]` | Cargo.toml `[dependencies]` has all four `{ workspace = true }` | ✅ |
| rsa remains in `[dev-dependencies]` | Cargo.toml:60 under `[dev-dependencies]`; not in `[dependencies]` | ✅ |
| clippy `--all-targets -- -D warnings` passes | SC4 green | ✅ |

## Requirement traceability

- **REQ-12** (Build Integrity, Wave 0) — covered by plan 08-01, SC1–SC4 all green. ✅

## Deviations vs ROADMAP text (research-corrected, intentional)

- `rsa` **retained** in `[dev-dependencies]` (ROADMAP said "dropped if unused"; it
  is still used by `req5_oidc_e2e.rs`/`req5_clock_skew.rs`).
- Warning count was **9**, not the ROADMAP's "12" (research-verified). Gate asserts
  a clean `-D warnings` run, not a hard count, so no discrepancy.

## Not verifiable locally (manual / CI)

- **SC3 true-CI:** push `feature/full-review` → confirm GitHub Actions `build`,
  `build-no-saml`, and `test` jobs transition red→green. Local `--no-default-features`
  build is the closest proxy; the SAML-on path (xmlsec) compiles only in CI/Docker
  per the known Arch limitation, and is unaffected by this phase's changes.

## Verdict

**PASSED.** All 4 success criteria and all 5 must_haves verified by deterministic
command output. Phases 9–12 are unblocked.
