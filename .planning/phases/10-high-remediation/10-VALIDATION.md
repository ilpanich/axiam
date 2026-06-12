---
phase: 10
slug: high-remediation
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-12
---

# Phase 10 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust: `cargo test` (per-crate integration tests under `crates/*/tests/`); Frontend: vitest + Playwright (`frontend/`) |
| **Config file** | Per-crate `Cargo.toml`; `frontend/vitest.config.ts`, `frontend/playwright.config.ts` |
| **Quick run command** | `cargo test -p <crate> --no-default-features --test <file>` (single test file) |
| **Full suite command** | `cargo test -p <crate> --no-default-features` per touched crate; `npm test --prefix frontend` |
| **Estimated runtime** | ~30–90s per crate; frontend unit ~10s |

> **Baseline caveat:** under `--no-default-features`, `axiam-api-rest` `federation_test.rs` has exactly 3 pre-existing SAML failures (`saml_acs`/`saml_authn`/`saml_metadata`) — NOT regressions. SAML protocol-hardening (REQ-14 item 5) is feature-gated and verified on the CI/Docker SAML-ON path.

---

## Sampling Rate

- **After every task commit:** Run the quick command for the touched crate/file
- **After every plan wave:** Run the full suite for all touched crates + frontend
- **Before `/gsd:verify-work`:** Full suite green (modulo the 3 known SAML baseline failures)
- **Max feedback latency:** 90 seconds

---

## Per-Task Verification Map

> Filled by gsd-planner during planning and audited by gsd-nyquist-auditor.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 10-01-01 | 01 | A | REQ-14 | T-10-01 / — | single hashing path + pepper; REST-created user logs in | integration | `cargo test -p axiam-api-rest --no-default-features` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] Test stubs authored per plan as part of each plan's test task (no separate framework install — `cargo test` + vitest/playwright already present)

*Existing infrastructure covers all phase requirements; per-plan test tasks add the new cases.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| SAML protocol checks (InResponseTo/Destination/Conditions/XSW) | REQ-14 | xmlsec feature-gated off on local Arch build | Run the SAML-ON path in CI/Docker; assert rejection of replayed/forged assertions |

*Remaining phase behaviors have automated verification.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 90s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
