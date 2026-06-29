---
phase: 15
slug: sdk-foundation
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-29
---

# Phase 15 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` (Rust workspace) + shell/CI assertions (buf, OpenAPI drift, scaffold) |
| **Config file** | none — Cargo workspace; CI gates under `.github/workflows/` |
| **Quick run command** | `cargo test -p axiam-api-rest --no-default-features authz_check` |
| **Full suite command** | `cargo test -p axiam-api-rest --no-default-features` (targeted; see constraint below) |
| **Estimated runtime** | ~60–120 seconds (single crate) |

> **Disk/build constraint (project memory):** /home is near-full and the workspace `target/` is large — NEVER run a full-workspace `cargo test` / `just test`; link steps hit `os error 28` and surface as false code defects. Always scope with `-p <crate>` and targeted `--test`. Verify cargo by reading actual output text, not exit code (rtk masks it). Add `--no-default-features` so SAML/xmlsec off-path crates compile locally on Arch.

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p axiam-api-rest --no-default-features authz_check`
- **After every plan wave:** Run the relevant targeted suite (`-p` scoped) for crates touched in the wave
- **Before `/gsd:verify-work`:** Targeted suites green + CI gates (drift, buf lint/breaking, scaffold) pass
- **Max feedback latency:** ~120 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 15-XX-XX | XX | N | FND-0X | T-15-XX / — | {expected secure behavior or "N/A"} | unit/integration/ci | `{command}` | ✅ / ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

*Planner/`gsd-nyquist-auditor` populates one row per task. FND-01 (OpenAPI drift), FND-02 (buf lint/breaking + codegen reproducibility), FND-05 (scaffold + path-filtered CI) verify via shell/CI assertions, not `cargo test`. FND-04 (authz-check endpoint) verifies via `cargo test -p axiam-api-rest` + the extended route↔OpenAPI parity test. FND-03 (CONTRACT.md) verifies via presence/section assertions and README cross-reference grep.*

---

## Wave 0 Requirements

- [ ] Extend `crates/axiam-api-rest/src/tests/route_openapi_parity_test.rs` to cover `/api/v1/authz/check` + `/check/batch` (FND-04)
- [ ] `cargo test -p axiam-api-rest` framework already present — no install needed

*Existing Rust + CI infrastructure covers all phase requirements; no new test framework install required.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| GitHub org `axiam` + 7 registry package-name availability (crates/npm/PyPI/Maven/NuGet/Packagist) | FND-05 / D-11–D-12 | External registries; cannot assume availability, no API auto-reserve in CI | Manually query each registry for `axiam-sdk` / `io.axiam:axiam-sdk` / `Axiam.Sdk` / `axiam/axiam-sdk`; record reserved/squatted status; reserve before first publish |
| buf remote plugin names for Rust (`neoeinstein-prost`/`neoeinstein-tonic`) resolve on buf.build BSR | FND-02 | Plugin names [ASSUMED] in research — need live BSR check before committing `buf.gen.yaml` | Install buf, run `buf generate` from clean checkout; confirm stubs emit for all 5 buf-managed languages |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
