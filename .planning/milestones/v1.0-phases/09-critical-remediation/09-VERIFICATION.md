---
phase: 09-critical-remediation
verified: 2026-06-12T00:00:00Z
status: human_needed
score: 13/13 must-haves verified
overrides_applied: 0
human_verification:
  - test: "Manual smoke: expire/delete access cookie, keep refresh cookie, reload the app"
    expected: "One POST /api/v1/auth/refresh fires, session restores, no redirect to /login"
    why_human: "Requires live browser session with real cookies; cannot be deterministically reproduced without a running backend"
  - test: "Run Playwright auth-contract suite against a live frontend dev server"
    expected: "npm test --prefix frontend passes all 8 tests (7 endpoint-URL checks + 1 CSRF header check) showing 'passed' in output"
    why_human: "Playwright tests require a running dev server (baseURL); no backend needed but Vite must be running"
---

# Phase 9: Critical Remediation Verification Report

**Phase Goal:** Close 5 critical security defects (SEC-002, SEC-003, SEC-044, SEC-045, CQ-F27, CQ-F28) identified in REQ-13 across REST handlers, gRPC, frontend auth flows, and federation secrets.
**Verified:** 2026-06-12
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Cross-org GET /organizations/{other_org_id} returns 403 | VERIFIED | `organizations.rs:116` — `if org_id != user.org_id` guard present; `organization_test.rs:341` test `cross_org_get_organization_returns_403` exists |
| 2 | Cross-org GET /organizations/{org_id}/tenants returns 403 | VERIFIED | `tenants.rs:64,124,164,211,257` — guard on all 5 handlers; `tenant_test.rs` has cross-org tests |
| 3 | Cross-org GET /organizations/{org_id}/ca-certificates returns 403 | VERIFIED | `ca_certificates.rs:41,83,121,159` — guard on all 4 handlers; `ca_certificate_test.rs` has cross-org tests |
| 4 | organizations create/list restricted to system-admin (super-admin) | VERIFIED | `organizations.rs:37-44,76-83` — `role_repo.get_user_roles` check, `is_super_admin` flag, `AuthorizationDenied` on non-super-admin |
| 5 | gRPC call without bearer token returns UNAUTHENTICATED | VERIFIED | `middleware/auth.rs:33` — `impl Interceptor for AuthInterceptor`; `grpc_auth_test.rs:211` test; 3 tests pass |
| 6 | gRPC call with valid bearer token succeeds | VERIFIED | `grpc_auth_test.rs:243` — `grpc_accepts_call_with_valid_bearer_token` test passes |
| 7 | tenant_id/subject_id derived from verified claims, not request body | VERIFIED | `middleware/auth.rs:42` — `validate_access_token` called, claims inserted into extensions; service reads from extensions |
| 8 | Public gRPC ingress removed from k8s/ingress.yml | VERIFIED | `grep -c 'axiam-grpc-ingress' k8s/ingress.yml` = 0; file non-empty (37 lines, HTTP ingress intact) |
| 9 | All six auth flows call correct /api/v1/auth/* endpoints via typed auth.ts | VERIFIED | All 6 pages call `authService.*`; no stale wrong-URL strings in src/pages (only a router `<Link>` to `/auth/forgot-password` which is a UI route, not an API call) |
| 10 | ForgotPassword submits to /api/v1/auth/reset | VERIFIED | `auth.ts:39` — `api.post("/api/v1/auth/reset", ...)` |
| 11 | MFA enroll submits to /api/v1/auth/mfa/setup/enroll | VERIFIED | `auth.ts:84` — `api.post("/api/v1/auth/mfa/setup/enroll")` |
| 12 | Silent refresh POST includes X-CSRF-Token (via api instance) | VERIFIED | `api.ts:102` — `await api.post("/api/v1/auth/refresh", {})` (not bare axios); `SKIP_REFRESH` list at line 63; CSRF contract test in `auth-contract.spec.ts:349` |
| 13 | Federation client_secret decrypted at use, encrypted on write, never serialized | VERIFIED | `oidc.rs:293-294` decrypt-at-use; `federation.rs:252` encrypt-on-write; `FederationConfigResponse` DTO (lines 82-109) has no secret fields |

**Score:** 13/13 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/axiam-api-rest/src/handlers/organizations.rs` | org guard + super-admin gate | VERIFIED | Guards at lines 116/154/190; super-admin check at 37-44/76-83 |
| `crates/axiam-api-rest/src/handlers/tenants.rs` | org guard on all 5 handlers | VERIFIED | 5 guard sites confirmed |
| `crates/axiam-api-rest/src/handlers/ca_certificates.rs` | org guard on 4 handlers | VERIFIED | 4 guard sites confirmed |
| `crates/axiam-api-rest/tests/organization_test.rs` | cross-org 403 + system-admin tests | VERIFIED | 18 test fns; cross-org tests at line 341+ |
| `crates/axiam-api-rest/tests/tenant_test.rs` | cross-org 403 tests | VERIFIED | 12 test fns |
| `crates/axiam-api-rest/tests/ca_certificate_test.rs` | cross-org 403 tests | VERIFIED | 14 test fns |
| `crates/axiam-api-grpc/src/middleware/auth.rs` | AuthInterceptor with validate_access_token | VERIFIED | `impl Interceptor for AuthInterceptor` at line 33 |
| `crates/axiam-api-grpc/src/server.rs` | with_interceptor wiring | VERIFIED | Line 48 confirmed |
| `crates/axiam-api-grpc/tests/grpc_auth_test.rs` | accept/reject interceptor tests | VERIFIED | 3 tests pass |
| `k8s/ingress.yml` | no axiam-grpc-ingress | VERIFIED | 0 matches; 1 HTTP ingress remains |
| `frontend/src/services/auth.ts` | typed authService, 7 methods, api instance | VERIFIED | All 7 endpoints present; `import api from "@/lib/api"` at line 1 |
| `frontend/e2e/auth-contract.spec.ts` | Playwright contract spec, 8 tests | VERIFIED | File exists (14.3KB); 8 test() calls confirmed |
| `frontend/src/lib/api.ts` | api.post refresh + narrowed SKIP_REFRESH | VERIFIED | `api.post("/api/v1/auth/refresh")` at line 102; `SKIP_REFRESH` at line 63 |
| `frontend/src/hooks/useAuthInit.ts` | boot refresh-once before clearAuth | VERIFIED | Single `api.post(".../auth/refresh")` at line 32 in try/catch |
| `crates/axiam-federation/src/oidc.rs` | decrypt-at-use + encryption_key field | VERIFIED | `encryption_key: [u8; 32]` at line 95; `decrypt_client_secret_or_legacy` call at line 293 |
| `crates/axiam-core/src/models/federation.rs` | secret fields on domain model | PRESENT | Fields exist; secret exclusion via DTO (`FederationConfigResponse`) in handler, not via `#[serde(skip)]` on the model — acceptable per plan pitfall note |
| `crates/axiam-api-rest/tests/federation_test.rs` | encrypt/decrypt round-trip + post-restart test | VERIFIED | `oidc_secret_stored_encrypted_and_round_trips` and `oidc_secret_decrypt_survives_simulated_restart` tests confirmed; 4 SEC-045 tests pass |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `organizations.rs` get/update/delete | `AuthenticatedUser.org_id` | `org_id != user.org_id -> AuthorizationDenied` | WIRED | Pattern confirmed at 3 sites |
| `ca_certificates.rs` handlers | `AuthenticatedUser.org_id` | `user.org_id` comparison | WIRED | Pattern at 4 sites |
| `AuthInterceptor::call` | `axiam_auth::token::validate_access_token` | bearer metadata validation | WIRED | `auth.rs:12,42` — import + call confirmed |
| `server.rs` | `AuthInterceptor` | `AuthorizationServiceServer::with_interceptor` | WIRED | Line 48 confirmed |
| `auth pages` | `auth.ts authService` | `import { authService }` | WIRED | 7 call sites in 6 pages confirmed |
| `auth.ts` | `api` axios instance | `import api from "@/lib/api"` | WIRED | Line 1 confirmed; no bare axios calls |
| `api.ts` refresh call | CSRF interceptor | `api.post` not bare `axios.post` | WIRED | Line 102: `await api.post(...)` |
| `useAuthInit.ts` init | `/api/v1/auth/refresh` | single boot refresh before clearAuth | WIRED | Line 32 in try/catch |
| `OidcFederationService::handle_callback` | `decrypt_client_secret_or_legacy` | `self.encryption_key + config secret columns` | WIRED | `oidc.rs:24` import + `oidc.rs:293` call |
| `federation REST create handler` | `encrypt_client_secret + set_encrypted_secret` | encrypt before store | WIRED | `federation.rs:252` encrypt; `federation.rs:272` set_encrypted_secret |

### Build Verification

| Crate | Command | Result |
|-------|---------|--------|
| axiam-api-rest | `cargo check -p axiam-api-rest --tests --no-default-features` | PASS — no errors |
| axiam-api-grpc | `cargo check -p axiam-api-grpc --tests --no-default-features` | PASS — no errors |
| axiam-federation | `cargo check -p axiam-federation --no-default-features` | PASS — no errors |
| frontend | `npx tsc -b` | PASS — only pre-existing TS5101 deprecation warning (baseUrl in tsconfig, untouched since initial React scaffold); no actual type errors |

### Test Execution

| Suite | Command | Result |
|-------|---------|--------|
| 09-01 cross-org | `cargo test -p axiam-api-rest --no-default-features --test organization_test --test tenant_test --test ca_certificate_test` | 29 passed, 0 failed |
| 09-02 gRPC auth | `cargo test -p axiam-api-grpc --features client --test grpc_auth_test` | 3 passed, 0 failed |
| 09-05 federation | `cargo test -p axiam-api-rest --no-default-features --test federation_test -- oidc_secret` | 4 passed (SEC-045 tests) |
| 09-05 federation full | `cargo test -p axiam-api-rest --no-default-features --test federation_test` | 17 passed, **3 failed** (saml_acs, saml_authn, saml_metadata) — **KNOWN BASELINE**, pre-existing under `--no-default-features` |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `crates/axiam-api-rest/src/handlers/federation.rs` | 483, 1023, 1262, 1491 | TODO markers | INFO | All reference formal Phase 19 task IDs (T19.9, T19.14, T19.15) — satisfy debt-marker gate |
| `crates/axiam-federation/src/oidc.rs` | 328 | TODO marker | INFO | References `plan 04-05` — formal follow-up reference, satisfies gate |

No TBD, FIXME, or XXX markers found in any modified file. All TODOs carry formal follow-up references.

### Human Verification Required

#### 1. Boot Refresh Smoke Test

**Test:** In a browser session against a running AXIAM dev stack: authenticate normally, then manually delete/expire the access token cookie while keeping the refresh cookie, then reload the page.
**Expected:** Exactly one POST to `/api/v1/auth/refresh` fires (visible in network tab), the session is restored without redirecting to `/login`.
**Why human:** Requires live browser session with real cookies and a running backend. Cookie manipulation and session restoration behavior cannot be tested with static analysis or a running frontend alone.

#### 2. Playwright Auth-Contract Suite

**Test:** Start the Vite dev server (`npm run dev --prefix frontend`), then run `npm test --prefix frontend -- --grep "Auth endpoint contract"` and `npm test --prefix frontend -- --grep "X-CSRF-Token"`.
**Expected:** All 8 tests pass — `test result: ok` in output. The CSRF test should show `x-csrf-token` is non-empty.
**Why human:** Playwright requires a running dev server (Vite on baseURL). Backend is not required (all routes are intercepted), but the test runner must be invoked manually with Vite serving.

---

## Summary

All 13 must-have truths are VERIFIED against the codebase:

- **SEC-002 (09-01):** Org-ownership 403 guards confirmed in all 3 handler files at 12 code sites; super-admin gate on org create/list confirmed; 29 negative tests pass.
- **SEC-003 (09-02):** Tonic `AuthInterceptor` with `validate_access_token` wired via `with_interceptor`; 3 accept/reject tests pass; `axiam-grpc-ingress` removed from k8s.
- **SEC-044/CQ-F27 (09-03):** `auth.ts` service with 7 correct `/api/v1/auth/*` endpoints; all 6 pages call `authService.*`; no stale wrong-URL API calls remain; Playwright spec (8 tests) exists.
- **CQ-F28 (09-04):** `api.post` (not bare axios) for refresh; `SKIP_REFRESH` list narrowed; `useAuthInit.ts` single boot refresh in try/catch; CSRF contract test in spec.
- **SEC-045/SEC-017 (09-05):** `decrypt_client_secret_or_legacy` called at use in `oidc.rs`; `encrypt_client_secret` + `set_encrypted_secret` in create/update handlers; `FederationConfigResponse` DTO excludes all secret fields; 4 round-trip/restart tests pass.

Two items require human execution: boot-refresh smoke test and Playwright suite (need a running frontend server).

---

_Verified: 2026-06-12_
_Verifier: Claude (gsd-verifier)_
