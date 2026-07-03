---
phase: 23
slug: security-regressions-high-findings
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-03
---

# Phase 23 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Seeded from `23-RESEARCH.md` § Validation Architecture. Every SECFIX ships a NEGATIVE
> test proving the attack is now rejected — that is the phase's defining success signal.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Backend framework** | `cargo test` (per-crate, `#[tokio::test]` / `#[actix_rt::test]`) — no new framework |
| **Frontend unit/contract framework** | `vitest` (`npm run test`) |
| **Frontend e2e framework** | `playwright` (`npm run test:e2e`) — specs under `frontend/e2e/`; CI *execution* wiring is CORR-04/Phase 26, specs run locally today |
| **Config files** | `crates/*/Cargo.toml`, `frontend/playwright.config.ts`, `frontend/vitest.config.ts` (not modified by this phase) |
| **Quick run command** | `cargo test -p <crate>` (backend, NEVER `--workspace` per CLAUDE.md) · `npm run test` (frontend unit) |
| **Full suite command** | per-crate suites for every touched crate + `npx playwright test <touched specs>` |
| **Estimated runtime** | ~30–120 s per touched crate |

---

## Sampling Rate

- **After every task commit:** `cargo test -p <touched crate>` (backend); `npm run test` (frontend unit) for any touched frontend file
- **After every plan wave:** full per-crate suites for every crate touched in the wave, plus `npx playwright test <touched specs>` for SECFIX-05/06 frontend changes
- **Before `/gsd-verify-work`:** all six SECFIX negative tests green; `cargo fmt` + `cargo clippy -D warnings` clean per touched crate; `eslint .` + `tsc -b` clean for touched frontend files
- **Max feedback latency:** ~120 seconds (single touched crate)

---

## Per-Task Verification Map

> Task IDs are assigned by the planner (`{23-PP-TT}`). The authoritative attack→signal
> mapping lives in `23-RESEARCH.md` § "Phase Requirements → Test Map"; the nyquist auditor
> fills the concrete task rows below once PLAN.md task IDs exist.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior (negative test) | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|---------------------------------|-----------|-------------------|-------------|--------|
| {23-01-01} | 01 | 1 | SECFIX-01 | T-23-01 | gRPC call with no bearer → `UNAUTHENTICATED`; cross-tenant `GetUser` → `PERMISSION_DENIED` | integration | `cargo test -p axiam-api-grpc --test grpc_auth_test` | ✅ file / ❌ new fns | ⬜ pending |
| {23-02-01} | 02 | 1 | SECFIX-02 | T-23-02 | tenant-A grant cannot attach tenant-B permission/scope via `grant_to_role_with_scopes` | integration | `cargo test -p axiam-db --test req14_tenant_isolation_test` | ✅ file / ❌ repoint | ⬜ pending |
| {23-03-01} | 03 | 1 | SECFIX-03 | T-23-03 | webhook register fails closed when key unset; stored secret ciphertext ≠ plaintext, decrypts at delivery | integration | `cargo test -p axiam-api-rest --test webhook_test` | ✅ file / ❌ new fns | ⬜ pending |
| {23-04-01} | 04 | 1 | SECFIX-04 | T-23-04 | wrapped/duplicated assertion, wrong `Destination`, missing `InResponseTo` on ACS path all rejected | integration | `cargo test -p axiam-server --test req5_saml_e2e` | ✅ file / ❌ new fns | ⬜ pending |
| {23-05-01} | 05 | 1 | SECFIX-05 | T-23-05 | replay of old cookies after logout → 401; frontend logout no longer 400s | integration + e2e | `cargo test -p axiam-api-rest --test auth_test` · `npx playwright test <logout spec>` | ✅ file / ❌ new fns | ⬜ pending |
| {23-06-01} | 06 | 1 | SECFIX-06 | T-23-06 | reset/confirm/resend carry `tenant_id`/`email`, succeed, stay enumeration-safe for unresolvable slug | integration + e2e | `cargo test -p axiam-api-rest` · `npx playwright test auth-contract.spec.ts` | ✅ file / ❌ body asserts | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Both backend test harnesses already exist and only need new test functions added — not new infrastructure:

- [ ] `crates/axiam-api-rest/tests/webhook_test.rs` — add a fail-closed-on-missing-key test and a stored-ciphertext-≠-plaintext test (working app harness already present)
- [ ] `crates/axiam-server/tests/req5_saml_e2e.rs` — add XSW wrapped-assertion, wrong-`Destination`, and missing-`InResponseTo` negative tests (`insert_saml_config` / `make_saml_svc` / `fixture()` helpers already built)
- [ ] New Playwright spec (or extension of `frontend/e2e/login.spec.ts`) for logout replay-after-cookie-clear behavior (no existing logout spec found)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Frontend logout / reset-body e2e assertions running **in CI** | SECFIX-05, SECFIX-06 | Playwright CI execution wiring is CORR-04 (Phase 26); specs run locally this phase | Run `npx playwright test` locally against a dev server; assert no 400 on logout and `tenant_id`/`email` present in reset/resend request bodies |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references (3 gaps above)
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
