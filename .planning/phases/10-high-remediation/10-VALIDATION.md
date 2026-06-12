---
phase: 10
slug: high-remediation
status: planned
nyquist_compliant: true
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

## Wave Structure

| Wave | Plans | Notes |
|------|-------|-------|
| 1 | 10-01, 10-06 | Foundational hashing+pepper (gate); frontend (independent) |
| 2 | 10-02 | load_key_from_env + PKI fail-fast (shares main.rs with 10-01) |
| 3 | 10-03, 10-04 | async-safety + tenant isolation; data-correctness. Both depend on 10-01+10-02 (Wave A green gate); no file overlap with each other → parallel within wave 3 |
| 4 | 10-05 | protocol hardening (shares schema.rs w/10-04, service.rs w/10-03) |

---

## Per-Task Verification Map

> Filled by gsd-planner during planning and audited by gsd-nyquist-auditor.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 10-01-01 | 01 | 1 | REQ-14 AC-1 | T-10-01 | Repo-layer hasher deleted; all hashing via axiam-auth::password | check | `cargo check -p axiam-db --no-default-features` | ❌ W0 | ⬜ pending |
| 10-01-02 | 01 | 1 | REQ-14 AC-1 | T-10-01b | AXIAM__AUTH__PEPPER loaded + with_pepper wired | check | `cargo check -p axiam-server --no-default-features` | ❌ W0 | ⬜ pending |
| 10-01-03 | 01 | 1 | REQ-14 AC-1 | T-10-01 | REST-created user logs in with pepper; mismatch fails | integration | `cargo test -p axiam-api-rest --no-default-features --test req14_pepper_test` | ❌ W0 | ⬜ pending |
| 10-02-01 | 02 | 2 | REQ-14 AC-5 | T-10-03 | Single load_key_from_env helper; 4 blocks deduped | check | `cargo check -p axiam-server --no-default-features` | ❌ W0 | ⬜ pending |
| 10-02-02 | 02 | 2 | REQ-14 AC-5 | T-10-02 | PkiConfig.encryption_key Option; CA fails fast on None | check | `cargo check -p axiam-pki --no-default-features` | ❌ W0 | ⬜ pending |
| 10-02-03 | 02 | 2 | REQ-14 AC-5 | T-10-02 | CA generation without key errors (no zero-key encrypt) | integration | `cargo test -p axiam-pki --no-default-features --test req14_pki_failfast_test` | ❌ W0 | ⬜ pending |
| 10-03-01 | 03 | 3 | REQ-14 AC-2 | T-10-04 | Argon2/PKI run in spawn_blocking behind a bounded semaphore | unit | `cargo test -p axiam-auth --no-default-features --test req14_async_safety_test` | ❌ W0 | ⬜ pending |
| 10-03-02 | 03 | 3 | REQ-14 AC-4 | T-10-05 | Cross-tenant role/permission edge mutation rejected | integration | `cargo test -p axiam-db --no-default-features --test req14_tenant_isolation_test` | ❌ W0 | ⬜ pending |
| 10-03-03 | 03 | 3 | REQ-14 AC-4 | T-10-06 | Resource cycle/orphan rejected; depth overflow errors | integration | `cargo test -p axiam-db --no-default-features --test req14_tenant_isolation_test` | ❌ W0 | ⬜ pending |
| 10-04-01 | 04 | 3 | REQ-14 AC-3,AC-5 | T-10-07, T-10-10 | Sparse settings propagate baseline; migrations idempotent | integration | `cargo test -p axiam-db --no-default-features --test req14_settings_migration_test` | ❌ W0 | ⬜ pending |
| 10-04-02 | 04 | 3 | REQ-14 AC-5 | T-10-08 | Audit+authz queues dead-letter; no drop/hot-loop | check | `cargo check -p axiam-amqp --no-default-features` | ❌ W0 | ⬜ pending |
| 10-04-03 | 04 | 3 | REQ-14 AC-5 | T-10-09 | GDPR purge re-selectable; export complete+paginated; Failed status | integration | `cargo test -p axiam-server --no-default-features --test req14_gdpr_test` | ❌ W0 | ⬜ pending |
| 10-05-01 | 05 | 4 | REQ-14 AC-5 | T-10-11, T-10-12 | Pagination clamped [1,200]; 5xx body generic | unit | `cargo test -p axiam-core --no-default-features --test req14_pagination_test` ; `cargo test -p axiam-api-rest --no-default-features --test req14_error_body_test` | ❌ W0 | ⬜ pending |
| 10-05-02 | 05 | 4 | REQ-14 AC-5 | T-10-13 | TOTP code replay within a step rejected | unit | `cargo test -p axiam-auth --no-default-features --test req14_totp_replay_test` | ❌ W0 | ⬜ pending |
| 10-05-03 | 05 | 4 | REQ-14 AC-5 | T-10-14, T-10-15 | SAML InResponseTo/Destination/Conditions/XSW; federation cert PEM API | manual (CI SAML-ON) + check | `cargo check -p axiam-federation --no-default-features` ; CI SAML-ON Docker job | ❌ W0 | ⬜ pending |
| 10-06-01 | 06 | 1 | REQ-14 AC-6 | T-10-16, T-10-17, T-10-18 | Real user.id; logout revokes session + clears cache; no fabricated status | lint+types | `cd frontend && npm run lint && npx tsc -b` | ❌ W0 | ⬜ pending |
| 10-06-02 | 06 | 1 | REQ-14 AC-6 | — | ConfirmDialog label; debounce cleanup; useQuery search; org settings init | lint+types | `cd frontend && npm run lint && npx tsc -b` | ❌ W0 | ⬜ pending |
| 10-06-03 | 06 | 1 | REQ-14 AC-6 | — | CI runs eslint + tsc -b for frontend | lint+types | `cd frontend && npm run lint && npx tsc -b` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] Test stubs authored per plan as part of each plan's test task (no separate framework install — `cargo test` + vitest/playwright already present)

*Existing infrastructure covers all phase requirements; per-plan test tasks add the new cases.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| SAML protocol checks (InResponseTo/Destination/Conditions/XSW) — task 10-05-03 | REQ-14 AC-5 | xmlsec feature-gated off on local Arch build; new SAML tests are `#[cfg(feature = "saml")]` | Run the SAML-ON path in CI/Docker (`build-saml` job); assert rejection of mismatched-InResponseTo, wrong-Destination, missing-Conditions, and XSW-forged assertions |

*Remaining phase behaviors have automated verification. The non-SAML portion of 10-05-03 (federation cert PEM API) is verified by `cargo check -p axiam-federation --no-default-features` + the federation integration test.*

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (test files authored within each plan's test task)
- [x] No watch-mode flags
- [x] Feedback latency < 90s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** planner-complete (pending nyquist-auditor review)
