---
phase: 29
slug: structural-quality
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-06
---

# Phase 29 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Derived from `29-RESEARCH.md` § Validation Architecture. Per-task rows are
> populated by the planner/executor once PLAN.md tasks exist.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework (backend)** | Rust built-in `#[tokio::test]` / `#[actix_web::test]` via `cargo test`; per-crate `tests/*.rs` integration + inline `#[cfg(test)] mod tests` unit tests |
| **Framework (frontend)** | Vitest (`frontend/src/**/*.test.ts`, 3 files today) + Playwright (`frontend/e2e/*.spec.ts`, 13 specs, CI-gated) |
| **Config file** | Cargo workspace (no separate test-framework config); `frontend/vitest.config.*` + `frontend/playwright.config.*` |
| **Quick run command** | `cargo test -p <crate> --lib` / `-p <crate> --test <name>`; for `axiam-api-rest`/`axiam-server` first `export SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip` |
| **Full suite command** | `export SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip && cargo test --workspace` (default features, `saml` on) + `cd frontend && npx playwright test` |
| **Estimated runtime** | per-crate ~30–120s; full workspace several minutes (build-heavy — run once as the phase-end regression gate, D-06) |

---

## Sampling Rate

- **After every task commit:** Run the narrowly-scoped `cargo test -p <crate> --lib` / `--test <name>` for the touched crate (per D-06 + CLAUDE.md build-hygiene: `cargo clean` between plans, never mid-build).
- **After every plan wave:** Run the relevant crate's full `--test` suite (e.g. all of `axiam-db/tests/`, all of `axiam-api-rest/tests/`).
- **Before `/gsd-verify-work`:** Full workspace suite must be green — this is the **primary proof** that QUAL-01/02/05/06/07's "no behavior change" holds. QUAL-03/04's intentionally-changed tests must be updated in the SAME commit that changes the behavior (D-04), never left red.
- **Max feedback latency:** ~120s (per-crate scoped run)

---

## Per-Task Verification Map

> Populated by the planner/executor once PLAN.md tasks exist. Requirement→behavior→test mapping below is lifted from `29-RESEARCH.md` § Phase Requirements → Test Map.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| TBD | 03/04 | 1 | QUAL-03 (409) | — | dup username/email/edge → `AlreadyExists` → HTTP 409 | integration | `cargo test -p axiam-api-rest --test <user_create_409>` | ❌ W0 | ⬜ pending |
| TBD | 03/04 | 1 | QUAL-03 (5xx) | — | non-uniqueness DB error still → 5xx, never a false 409 | unit | `cargo test -p axiam-db --lib` | ❌ W0 | ⬜ pending |
| TBD | 03/04 | 1 | QUAL-04 (cross-tenant) | T-cross-tenant-edge-strip | tenant B's edge survives a tenant-A delete with spoofed ID | integration | `cargo test -p axiam-db --test role_permission_test` | ❌ W0 | ⬜ pending |
| TBD | 03/04 | 1 | QUAL-04 (TOCTOU) | T-child-guard-toctou | concurrent child-create during resource delete keeps the invariant | integration | `cargo test -p axiam-db --test resource_scope_test` | ❌ W0 | ⬜ pending |
| TBD | 03/04 | 1 | QUAL-04 (D-14 GDPR) | T-gdpr-strand | `account_deletion` create failure rolls back `deletion_pending` | integration | `cargo test -p axiam-api-rest --test gdpr_test` | ❌ W0 | ⬜ pending |
| TBD | 01/07 | 2 | QUAL-01 | — | `AppState<C>` composition; 35 test-harness files compile + pass unchanged | integration | `cargo test --workspace` | ✅ | ⬜ pending |
| TBD | 02/05 | 3 | QUAL-02 | — | `paginate<T>`/`CountRow`/`take_first_or_not_found` adoption behavior-preserving | unit + integration | `cargo test -p axiam-db --lib` | ❌ W0 (paginate) | ⬜ pending |
| TBD | 02/05 | 3 | QUAL-05 | T-ca-dn-drift | leaf cert via `from_ca_cert_pem` carries identical issuer DN + verifies | unit | `cargo test -p axiam-pki` | ❌ W0 | ⬜ pending |
| TBD | 06 | 4 | QUAL-06 | — | pages render/function identically after shared-component/service adoption | e2e + manual | `cd frontend && npx playwright test` | ✅ (+ manual smoke) | ⬜ pending |
| TBD | 01/07 | 2 | QUAL-07 | — | deleted pepper-less `verify_password` — no live caller broken | unit | `cargo test -p axiam-db --test user_repository_test` | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

New tests that lock the QUAL-03/04/05 behavior changes and the `paginate<T>` helper (from `29-RESEARCH.md` § Wave 0 Gaps):

- [ ] `crates/axiam-db/src/helpers.rs` — `paginate<T>` unit tests (mirror existing `parse_uuid`/`take_first_or_not_found` test style)
- [ ] `crates/axiam-db/src/helpers.rs` (or new module) — `classify_write_error` unit tests: genuine-duplicate → `AlreadyExists`; non-marker error → falls through unchanged (5xx)
- [ ] `crates/axiam-api-rest/tests/` — user-create 409 path + edge-uniqueness 409 path integration tests
- [ ] `crates/axiam-oauth2/` or `axiam-api-rest/tests/oauth2_*` — DB-outage-vs-`invalid_client` test (needs a mockable repo error-injection seam — verify one exists or add a test-only seam)
- [ ] `crates/axiam-db/tests/role_permission_test.rs` — cross-tenant edge-strip test
- [ ] `crates/axiam-db/tests/resource_scope_test.rs` — concurrent-child TOCTOU test
- [ ] `crates/axiam-api-rest/tests/gdpr_test.rs` — GDPR deletion-setup atomicity test
- [ ] `crates/axiam-pki/src/cert.rs` (or new `crates/axiam-pki/tests/`) — identical-issuer-DN signing-equivalence test

*The existing 35 axiam-api-rest/axiam-server test-harness files + 13 Playwright specs ARE the no-behavior-change gate for QUAL-01/06/07 — no new tests required there.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Migrated pages without direct e2e coverage render + function identically | QUAL-06 | Not every one of the 11 shared-component/service-adoption pages has a Playwright spec | Smoke-check each migrated page (users/roles/permissions/federation/settings/notifications + profile/MFA) against pre-refactor behavior; confirm `ActionBadge` color parity (research flagged a case-sensitivity + fallback-class divergence between `shared.tsx` and `RoleDetailPage.tsx`'s local copy) |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
