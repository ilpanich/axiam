---
phase: 12
slug: low-remediation
status: draft
nyquist_compliant: true
wave_0_complete: true
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
| 12-01-01 | 12-01 | 1 | REQ-16 | — | Single shared capped client_ip/user_agent extractor (no input length abuse, no dup defs) | Compilation | `cargo check -p axiam-api-rest --tests --no-default-features` | ✅ | ⬜ pending |
| 12-01-02 | 12-01 | 1 | REQ-16 | T-12-01/T-12-03 | Logged errors (no silent GDPR audit drop); audit-drop alertable; dispatcher resolved; deps pruned | Compilation + source assertion | `cargo check -p axiam-server -p axiam-api-rest -p axiam-oauth2 -p axiam-audit -p axiam-auth --no-default-features` | ✅ | ⬜ pending |
| 12-01-03 | 12-01 | 1 | REQ-16 | CQ-B35 / T-12-02 | HIBP runs on sync change-password; seeder skips UPSERT when registry hash unchanged | Unit test | `cargo test -p axiam-db --test seeder_skip_test --no-default-features` | ✅ | ⬜ pending |
| 12-02-01 | 12-02 | 1 | REQ-16 | SEC-043 / T-12-05/06 | mfa_secret redacted in Debug + excluded from list projection | Unit test + source assertion | `cargo test -p axiam-db --lib --no-default-features` | ✅ | ⬜ pending |
| 12-02-02 | 12-02 | 1 | REQ-16 | SEC-040 / T-12-08 | Docs describe additive-only RBAC engine (no false deny-override claim); engine.rs unchanged | Source assertion | `grep -n "additive-only" claude_dev/design-document.md /home/emanuele/git/priv/axiam/CLAUDE.md` | ✅ | ⬜ pending |
| 12-02-03 | 12-02 | 1 | REQ-16 | SEC-057 / T-12-07 | Every GitHub Actions `uses:` pinned to a 40-char commit SHA | Source assertion | `grep -nE 'uses:' .github/workflows/ci.yml .github/workflows/release.yml \| grep -vE '@[0-9a-f]{40}' \| grep -vE '^\s*#'` | ✅ | ⬜ pending |
| 12-03-01 | 12-03 | 1 | REQ-16 | CQ-F22 / T-12-11 | Dead Placeholder.tsx removed, unused radix deps pruned, safe DataTable key, i18n locale, CSS.escape | Compilation + source assertion | `cd frontend && npx tsc -b --noEmit` | ✅ | ⬜ pending |
| 12-03-02 | 12-03 | 1 | REQ-16 | CQ-F23 / T-12-09 | Password-policy checker gates admin-create + bootstrap; backend-404 already-initialized mapping pinned | Compilation + source assertion | `cd frontend && npx tsc -b --noEmit && grep -l PasswordPolicyChecker src/pages/users/UsersPage.tsx src/pages/BootstrapPage.tsx` | ✅ | ⬜ pending |
| 12-03-03 | 12-03 | 1 | REQ-16 | CQ-F32 / T-12-10 | Refresh `_retry` guarded; stable empty permissions; single StrictMode boot fetch; no tenants flash | Compilation + source assertion | `cd frontend && npx tsc -b --noEmit && grep -n 'EMPTY_PERMISSIONS' src/hooks/usePermissions.ts && grep -n 'useRef' src/hooks/useAuthInit.ts` | ✅ | ⬜ pending |
| 12-04-01 | 12-04 | 1 | REQ-16 | SEC-036 / T-12-13 | Revealed secret cleared from React state on modal close (5 pages) | Compilation + source assertion | `cd frontend && npx tsc -b --noEmit && grep -lE 'setRevealed(Secret\|Key)\(null\)' src/pages/certificates/CertificatesPage.tsx src/pages/oauth2/OAuth2ClientsPage.tsx src/pages/service-accounts/ServiceAccountsPage.tsx src/pages/webhooks/WebhooksPage.tsx src/pages/pgp/PgpKeysPage.tsx` | ✅ | ⬜ pending |
| 12-04-02 | 12-04 | 1 | REQ-16 | SEC-037 / T-12-14 | Reset/verify tokens stripped from URL via history.replaceState after use | Compilation + source assertion | `cd frontend && npx tsc -b --noEmit && grep -c replaceState src/pages/auth/ResetPasswordPage.tsx src/pages/auth/VerifyEmailPage.tsx` | ✅ | ⬜ pending |
| 12-04-03 | 12-04 | 1 | REQ-16 | SEC-041 / T-12-15 | ForgotPasswordPage no longer logs the AxiosError (which carries the submitted email) | Compilation + source assertion | `cd frontend && npx tsc -b --noEmit && grep -n 'console.warn' src/pages/auth/ForgotPasswordPage.tsx` | ✅ | ⬜ pending |
| 12-05-01 | 12-05 | 2 | REQ-16 | T-12-16 | Disk-safe local sweep (per-crate check/clippy/targeted-test + frontend lint/tsc/vitest) green | Compilation + targeted test | `cargo check -p axiam-db -p axiam-api-rest -p axiam-auth -p axiam-audit -p axiam-server --tests --no-default-features` | ✅ | ⬜ pending |
| 12-05-02 | 12-05 | 2 | REQ-16 | T-12-SC | CI gates present: workspace build/clippy/test, cargo audit/deny, npm audit, frontend, Playwright e2e | Source assertion | `grep -niE 'cargo (build\|clippy\|test)\|cargo-audit\|cargo audit\|cargo-deny\|npm audit\|playwright\|vitest\|tsc' .github/workflows/ci.yml` | ✅ | ⬜ pending |
| 12-05-03 | 12-05 | 2 | REQ-16 | T-12-16/T-12-17 | Manual multi-protocol smoke (login→MFA→reset/verify/change-pw→GDPR→federation-after-restart→cross-org 403→gRPC-no-creds) passes | Manual (checkpoint:human-verify) | Manual — see Manual-Only Verifications below | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. This is a remediation phase over existing code with established cargo (per-crate `--test`), frontend (`vitest` + `tsc -b` + ESLint), and Playwright e2e suites. The only NEW test file (`crates/axiam-db/tests/seeder_skip_test.rs`, created within plan 12-01 Task 3) is a targeted addition co-located with its behavior, not a Wave-0 infrastructure gap. No Wave 0 scaffolding plan is required.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Final manual smoke: login→MFA→reset/verify/change-pw→GDPR→federation-after-restart→cross-org 403→gRPC-no-creds rejected (+ token-strip, secret-clear, bootstrap-404, HIBP, password-policy checks) | REQ-16 | End-to-end multi-protocol flow requiring live services (REST + gRPC + federation IdP + email) | Run the full 11-item smoke sequence (Plan 12-05 Task 3 `<how-to-verify>`) against a `just dev-up` + `just run` environment after the automated gate passes |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 90s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-06-19
