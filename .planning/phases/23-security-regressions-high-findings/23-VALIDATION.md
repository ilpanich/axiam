---
phase: 23
slug: security-regressions-high-findings
status: complete
nyquist_compliant: true
wave_0_complete: true
created: 2026-07-03
validated: 2026-07-03
---

# Phase 23 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Seeded from `23-RESEARCH.md` § Validation Architecture. Every SECFIX ships a NEGATIVE
> test proving the attack is now rejected — that is the phase's defining success signal.
>
> **Audited 2026-07-03 against the live codebase** (see § Validation Audit): all six SECFIX
> negative suites were re-run and are green. Phase is Nyquist-compliant.

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

> **Sandbox build note (from execution SUMMARYs, confirmed during audit):** `axiam-api-rest` and
> `axiam-server` builds require `SWAGGER_UI_DOWNLOAD_URL` pointed at a local zip (the
> `utoipa-swagger-ui` build script cannot fetch from GitHub in the sandbox). `axiam-api-grpc`
> requires `protoc`; `axiam-federation`/`axiam-server` SAML builds require `libxml2-dev` +
> `libxmlsec1-dev`. All present in this environment during the audit.

---

## Sampling Rate

- **After every task commit:** `cargo test -p <touched crate>` (backend); `npm run test` (frontend unit) for any touched frontend file
- **After every plan wave:** full per-crate suites for every crate touched in the wave, plus `npx playwright test <touched specs>` for SECFIX-05/06 frontend changes
- **Before `/gsd-verify-work`:** all six SECFIX negative tests green; `cargo fmt` + `cargo clippy -D warnings` clean per touched crate; `eslint .` + `tsc -b` clean for touched frontend files
- **Max feedback latency:** ~120 seconds (single touched crate)

---

## Per-Task Verification Map

> Rows reconciled to the executed plans (23-01 … 23-06) and their SUMMARY `coverage` blocks.
> Every row's `Automated Command` was re-run during the 2026-07-03 audit; results in § Validation Audit.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior (negative test) | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|---------------------------------|-----------|-------------------|-------------|--------|
| 23-01-03 | 01 | 1 | SECFIX-01 | T-23-01 | gRPC `GetUser`/`ValidateCredentials`/`IntrospectToken` with no bearer → `UNAUTHENTICATED`; cross-tenant `GetUser` → `PERMISSION_DENIED`; wrong-password `ValidateCredentials` accrues lockout via shared helper | integration | `cargo test -p axiam-api-grpc --test grpc_auth_test --features client` | ✅ 5 new fns | ✅ green (8/8) |
| 23-02-01/02 | 02 | 1 | SECFIX-02 | T-23-02 | tenant-A grant cannot attach tenant-B permission (wildcard branch) or tenant-B scope (scoped branch) via `grant_to_role_with_scopes` | integration | `cargo test -p axiam-db --test req14_tenant_isolation_test` | ✅ 2 new fns | ✅ green (7/7) |
| 23-03-03 | 03 | 1 | SECFIX-03 | T-23-03 | webhook register fails closed (503) when key unset; stored secret ciphertext ≠ plaintext, decrypts round-trip | integration + unit | `cargo test -p axiam-api-rest --test webhook_test` · `cargo test -p axiam-api-rest --lib webhook::tests::webhook_secret_encrypt_decrypt_round_trip` | ✅ 2 + 1 new fns | ✅ green (18/18 + 1) |
| 23-04-03 | 04 | 1 | SECFIX-04 | T-23-04 | XSW wrapped/duplicated assertion, wrong `Destination`, and missing `InResponseTo` on authenticated ACS path all rejected | integration | `cargo test -p axiam-server --test req5_saml_e2e --features saml` | ✅ 3 new fns | ✅ green (9/9) |
| 23-05-01 | 05 | 1 | SECFIX-05 | T-23-05 | replay of old access cookie after body-less logout → 401 on `/auth/me`; all three cookies cleared | integration | `cargo test -p axiam-api-rest --test auth_test` | ✅ replay assert added | ✅ green (19/19) |
| 23-06-01 | 06 | 1 | SECFIX-06 | T-23-06-A…E | rendered reset/verify email link is fully substituted (`action_url` with token + tenant_id present, `{{action_url}}` placeholder gone) via the real render pipeline; unresolvable/missing tenant slug funnels into the uniform enumeration-safe `{"sent":true}` response | unit | `cargo test -p axiam-api-rest --lib handlers::password_reset` · `cargo test -p axiam-api-rest --lib handlers::email_verification` | ✅ 4 new fns | ✅ green (5/5 + 3/3) |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

All three seed gaps are now satisfied (verified on disk + green during the audit):

- [x] `crates/axiam-api-rest/tests/webhook_test.rs` — `create_webhook_fails_closed_without_encryption_key` (503) and `create_webhook_stores_ciphertext_not_plaintext` present and green
- [x] `crates/axiam-server/tests/req5_saml_e2e.rs` — `saml_rejects_xsw_wrapped_assertion`, `saml_rejects_wrong_destination_on_authenticated_path`, `saml_rejects_missing_in_response_to_on_authenticated_path` present and green (fail-before/pass-after documented in 23-04-SUMMARY)
- [x] `frontend/e2e/logout.spec.ts` — logout replay-after-cookie-clear Playwright spec created (local-run only; CI execution is CORR-04/Phase 26)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Frontend logout e2e (`frontend/e2e/logout.spec.ts`) running **in CI** | SECFIX-05 | Playwright CI execution wiring is CORR-04 (Phase 26); Chromium download is proxy-blocked in the sandbox | `docker compose -f docker/docker-compose.e2e.yml up -d --wait && ./scripts/e2e-bootstrap.sh && cd frontend && npx playwright test e2e/logout.spec.ts` — assert no 400 on logout and unauthenticated after reload |
| Frontend reset/verify/resend body assertions (`frontend/e2e/auth-contract.spec.ts`) running **in CI** | SECFIX-06 | Same — Playwright CI execution is CORR-04 (Phase 26); specs type/lint-checked but not executed in sandbox | `cd frontend && npx playwright test e2e/auth-contract.spec.ts` — assert `tenant_id`/`email` present in reset/confirm/verify/resend request bodies |

> Both frontend behaviors additionally carry a **backend** automated proof (SECFIX-05 replay-after-logout
> integration test; SECFIX-06 `action_url` substitution + enumeration-safety unit tests), so the
> security-defining signal for each is automated today — only the browser-level contract assertion is deferred.

---

## Validation Audit 2026-07-03

| Metric | Count |
|--------|-------|
| Requirements audited | 6 (SECFIX-01 … 06) |
| Gaps found | 0 |
| Resolved (auditor) | 0 |
| Escalated | 0 |
| Backend suites re-run green | 6 / 6 |
| Frontend specs deferred to CI (CORR-04 / Phase 26) | 2 |

**Method:** Every test function referenced in the six SUMMARY `coverage` blocks was confirmed present on
disk, then each owning suite was compiled and executed in this environment (`protoc`, `libxml2-dev`,
`libxmlsec1-dev` present; `SWAGGER_UI_DOWNLOAD_URL` pointed at a local placeholder zip for the
`axiam-api-rest`/`axiam-server` builds). All six SECFIX negative suites passed; no test was missing,
red, or flaky. No `gsd-nyquist-auditor` spawn was required.

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (3 gaps — all satisfied)
- [x] No watch-mode flags
- [x] Feedback latency < 120s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved — Phase 23 is Nyquist-compliant (2026-07-03)
