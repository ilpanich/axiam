---
phase: 12
slug: low-remediation
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-19
---

# Phase 12 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Backend: `cargo test` (per-crate, targeted `--test`) · Frontend: `vitest` + `tsc -b` + ESLint · E2E: Playwright |
| **Config file** | `Cargo.toml` (workspace) · `frontend/vitest.config.ts` · `frontend/playwright.config.ts` |
| **Quick run command** | `cargo check -p <crate> --tests --no-default-features` · `cd frontend && npm run lint && npx tsc -b` |
| **Full suite command** | Final gate only: `cargo build/clippy -D warnings/test --workspace` + `cargo audit`/`cargo-deny` + `npm audit` + frontend `lint && tsc -b && vitest` + Playwright e2e |
| **Estimated runtime** | Quick: ~30–90s per crate · Full gate: several minutes (CI-preferred) |

> ⚠️ Disk near-full: do NOT run whole-workspace `cargo test`/`just test` locally (linking → ENOSPC). Use `cargo check` + targeted `--test`; reserve `--workspace` for the CI-run final gate. SAML behind `saml` feature — local builds use `--no-default-features`; 3 SAML federation_test failures are a known baseline, not regressions.

---

## Sampling Rate

- **After every task commit:** Run the quick command for the touched crate/package
- **After every plan wave:** Run the affected crate's targeted tests + frontend lint/tsc
- **Before `/gsd:verify-work`:** Final whole-effort gate must be green (CI)
- **Max feedback latency:** ~90 seconds (quick) / CI for full gate

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| _to be filled by planner per task_ | | | REQ-16 | | | | | | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

*To be filled by planner. Likely: "Existing infrastructure covers all phase requirements" — this is a remediation phase over existing code with established cargo/vitest/Playwright suites.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Final manual smoke: login→MFA→reset/verify/change-pw→GDPR→federation-after-restart→cross-org 403→gRPC-no-creds rejected | REQ-16 | End-to-end multi-protocol flow requiring live services (REST + gRPC + federation IdP + email) | Run the full smoke sequence against a `just dev-up` environment after the automated gate passes |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 90s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
