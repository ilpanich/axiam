---
phase: 23-security-regressions-high-findings
plan: 06
subsystem: auth
tags: [password-reset, email-verification, tenant-context, action-url, enumeration-safety, frontend, security]

# Dependency graph
requires: []
provides:
  - "request_reset and resend_verification build a fully-substituted action_url (token + tenant_id) into their mail template_context, mirroring gdpr.rs's cancel_url — the emailed reset/verify link is a working link, not an unsubstituted {{action_url}} placeholder"
  - "RequestResetBody.tenant_id is Option<Uuid> with optional org_slug/tenant_slug, resolved via resolve_reset_tenant_id() (mirrors auth.rs login's (Option<Uuid>, Option<&str>) pattern); slug-resolution failure funnels into the same uniform {\"sent\": true}/200 enumeration-safe response as an unknown account"
  - "LoginUserInfo.tenant_id (login + /auth/me responses) exposes the caller's raw tenant_id UUID so the frontend can carry it into tenant-scoped unauthenticated calls (resendVerification)"
  - "Frontend requestPasswordReset/confirmPasswordReset/resendVerification send bodies matching the backend DTOs; ForgotPasswordPage/ResetPasswordPage read tenant context from their own URL; LoginPage's Forgot-password link carries orgSlug/tenantSlug"
  - "auth-contract.spec.ts asserts request bodies (tenant_id/email), not just URL paths, for all four reset/verify/resend flows"
affects: [26-webhook-delivery-and-ci-hardening]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "action_url construction mirrors gdpr.rs's cancel_url precedent: a relative-path frontend route with the raw token + resolved tenant_id, added to template_context under the action_url key — no new frontend-base-URL config"
    - "Enumeration-safe slug resolution: an async helper (resolve_reset_tenant_id) returns Option<Uuid> instead of a Result, so a NotFound org/tenant slug is structurally incapable of being `?`-propagated into a distinct error response"

key-files:
  created: []
  modified:
    - crates/axiam-api-rest/src/handlers/password_reset.rs
    - crates/axiam-api-rest/src/handlers/email_verification.rs
    - crates/axiam-api-rest/src/handlers/auth.rs
    - crates/axiam-api-rest/Cargo.toml
    - frontend/src/services/auth.ts
    - frontend/src/pages/auth/ForgotPasswordPage.tsx
    - frontend/src/pages/auth/ResetPasswordPage.tsx
    - frontend/src/pages/LoginPage.tsx
    - frontend/src/pages/profile/ProfilePage.tsx
    - frontend/src/stores/auth.ts
    - frontend/e2e/auth-contract.spec.ts

key-decisions:
  - "Added axiam-email as a dev-dependency of axiam-api-rest so the action_url substitution test exercises the REAL render_email/resolve_template pipeline (not a source-file grep) — the phase-defining proof that the emailed link is fully substituted."
  - "Factored tenant resolution into a standalone async resolve_reset_tenant_id(org_repo, tenant_repo, ...) -> Option<Uuid> helper (generic over OrganizationRepository/TenantRepository) so the enumeration-safety funnel is independently unit-testable with fake repos, without a live DB."
  - "Missing tenant context entirely (no tenant_id, no tenant_slug) is treated identically to an unresolvable slug — both fall into the same uniform {\"sent\": true} response — rather than a distinct 400 for the missing-field case, to avoid any observable difference an attacker could use to distinguish 'field omitted' from 'slug doesn't exist'."
  - "Exposed tenant_id on LoginUserInfo (login + /auth/me) — a deviation beyond the plan's literal file list, but required to fulfill the plan's own explicit instruction that resendVerification's ProfilePage call site source the current user's raw tenant_id from the auth store, which was not exposed anywhere in the frontend before this plan."

requirements-completed: [SECFIX-06]

coverage:
  - id: D1
    description: "request_reset and resend_verification build a fully-substituted action_url (token + tenant_id) into template_context — the phase-defining backend fix (23-RESEARCH Pattern 6 / Pitfall 3)"
    requirement: SECFIX-06
    verification:
      - kind: unit
        ref: "crates/axiam-api-rest/src/handlers/password_reset.rs#action_url_is_substituted_in_rendered_password_reset_email — cargo test -p axiam-api-rest --lib handlers::password_reset"
        status: pass
      - kind: unit
        ref: "crates/axiam-api-rest/src/handlers/email_verification.rs#action_url_is_substituted_in_rendered_verification_email — cargo test -p axiam-api-rest --lib handlers::email_verification"
        status: pass
    human_judgment: false
  - id: D2
    description: "RequestResetBody.tenant_id is Option<Uuid> with optional org_slug/tenant_slug; an unresolvable/missing slug funnels into the SAME uniform {\"sent\": true}/200 response as an unknown account (D-05), never a distinct 400/404"
    requirement: SECFIX-06
    verification:
      - kind: unit
        ref: "crates/axiam-api-rest/src/handlers/password_reset.rs#unresolvable_tenant_slug_resolves_to_none_enumeration_safe, #missing_tenant_context_resolves_to_none_enumeration_safe"
        status: pass
      - kind: other
        ref: "grep -n '?' around resolve_reset_tenant_id call site — no `?`-propagation of the slug-resolution Result; failures are caught via .ok()"
        status: pass
    human_judgment: false
  - id: D3
    description: "ConfirmResetBody/VerifyEmailRequest/ResendVerificationRequest keep their required tenant_id: Uuid (Open Question 2 — raw tenant_id from the emailed link/authenticated page)"
    requirement: SECFIX-06
    verification:
      - kind: other
        ref: "crates/axiam-api-rest/src/handlers/password_reset.rs (ConfirmResetBody), crates/axiam-api-rest/src/handlers/email_verification.rs (VerifyEmailRequest, ResendVerificationRequest) — unchanged, tenant_id: Uuid required"
        status: pass
    human_judgment: false
  - id: D4
    description: "requestPasswordReset/confirmPasswordReset/resendVerification send bodies matching the backend DTOs; forgot-password resolves tenant via URL slug, confirm/verify carry the raw tenant_id"
    requirement: SECFIX-06
    verification:
      - kind: unit
        ref: "cd frontend && npx tsc -b && npx eslint . — both clean"
        status: pass
      - kind: e2e
        ref: "frontend/e2e/auth-contract.spec.ts (body assertions authored; not executed in-sandbox — see Issues Encountered)"
        status: unknown
    human_judgment: false
  - id: D5
    description: "The contract spec asserts request bodies (tenant_id/email), not just URL paths, for all four reset/verify/resend flows"
    requirement: SECFIX-06
    verification:
      - kind: e2e
        ref: "frontend/e2e/auth-contract.spec.ts — ForgotPasswordPage (2 tests), ResetPasswordPage, VerifyEmailPage, ProfilePage resend-verification body assertions (authored; local Playwright execution blocked — see Issues Encountered)"
        status: unknown
    human_judgment: false

duration: ~90min
completed: 2026-07-03
status: complete
---

# Phase 23 Plan 06: Reset/Verify Flows Thread tenant_id AND Build action_url (SECFIX-06) Summary

**Both `request_reset` and `resend_verification` now build a fully-substituted `action_url` (token + tenant_id) into their mail `template_context` — mirroring `gdpr.rs`'s `cancel_url` precedent — closing the phase-defining gap where emailed reset/verify links shipped as the raw unsubstituted `{{action_url}}` placeholder; `RequestResetBody` now resolves an optional tenant slug enumeration-safely, and the frontend threads tenant context/email through all three flows.**

## Performance

- **Duration:** ~90 min
- **Completed:** 2026-07-03
- **Tasks:** 3 completed
- **Files modified:** 11 (across 4 commits)

## Accomplishments

- **Backend action_url (the phase-defining fix):** `request_reset` (`password_reset.rs`) builds `/auth/reset-password?token={raw_token}&tenant_id={tenant_id}` and `resend_verification` (`email_verification.rs`) builds `/auth/verify-email?token={raw_token}&tenant_id={tenant_id}`, both added to `template_context` under the `action_url` key. Proven via a runtime substitution test that renders the email through the REAL `axiam-email::template::{resolve_template, render_email}` pipeline (added `axiam-email` as a dev-dependency) and asserts the rendered HTML/text body contains the token + tenant_id and does NOT contain the literal `{{action_url}}` placeholder.
- **Enumeration-safe tenant resolution:** `RequestResetBody.tenant_id` is now `Option<Uuid>` with optional `org_slug`/`tenant_slug`. A new `resolve_reset_tenant_id()` async helper (generic over `OrganizationRepository`/`TenantRepository`) mirrors `auth.rs`'s login `(Option<Uuid>, Option<&str>)` resolution, but returns `Option<Uuid>` instead of a `Result` — structurally preventing `?`-propagation of a slug-resolution failure. An unresolvable OR entirely-missing tenant context funnels into the same uniform `{"sent": true}`/200 response as an unknown account (D-05).
- **`ConfirmResetBody`/`VerifyEmailRequest`/`ResendVerificationRequest`** keep their required `tenant_id: Uuid` unchanged (Open Question 2 — the raw tenant_id from the emailed link or authenticated page).
- **Frontend threading:** `requestPasswordReset(email, orgSlug?, tenantSlug?)`, `confirmPasswordReset(tenantId, token, new_password)`, `resendVerification(tenantId, email)` now send bodies matching the backend DTOs. `ForgotPasswordPage` reads `?org=`/`?tenant=` from its own URL (D-04, no user-typed tenant field, no email-domain inference); `ResetPasswordPage` reads `?token=&tenant_id=` mirroring the already-shipped `VerifyEmailPage`; `LoginPage`'s "Forgot password?" link carries `orgSlug`/`tenantSlug` from component state.
- **Contract test hardening:** `auth-contract.spec.ts` now asserts request BODIES (not just URL paths) for all four flows — forgot-password (email + org/tenant slug), reset-confirm (tenant_id/token/new_password), verify-email (tenant_id/token), resend-verification (tenant_id/email).

## Task Commits

Each task was committed atomically (plus two deviation-driven commits):

1. **Task 1: Backend — build action_url + enumeration-safe tenant resolution** - `35ecb52` (feat)
2. **Deviation — expose tenant_id on LoginUserInfo** - `b18f017` (feat)
3. **Task 2: Frontend — thread tenant context/email through auth.ts/pages/router/LoginPage** - `edcc661` (feat)
4. **Task 3: Contract test asserts request bodies** - `fb0f24c` (test)

**Plan metadata:** (this commit, docs)

## Files Created/Modified

- `crates/axiam-api-rest/src/handlers/password_reset.rs` - `RequestResetBody.tenant_id` → `Option<Uuid>` + `org_slug`/`tenant_slug`; new `resolve_reset_tenant_id()` helper; `request_reset` builds `action_url` into `template_context`; 4 new tests (substitution + 2 enumeration-safety + existing tests unchanged)
- `crates/axiam-api-rest/src/handlers/email_verification.rs` - `resend_verification` builds `action_url` into `template_context`; new substitution test
- `crates/axiam-api-rest/src/handlers/auth.rs` - `LoginUserInfo` gains `tenant_id: Uuid` (deviation, see below)
- `crates/axiam-api-rest/Cargo.toml` - `axiam-email` added as a dev-dependency (real template rendering in tests)
- `frontend/src/services/auth.ts` - `requestPasswordReset`/`confirmPasswordReset`/`resendVerification` now send full DTO-matching bodies
- `frontend/src/pages/auth/ForgotPasswordPage.tsx` - reads `?org=`/`?tenant=` and forwards to `requestPasswordReset`
- `frontend/src/pages/auth/ResetPasswordPage.tsx` - reads `?token=&tenant_id=` (mirrors `VerifyEmailPage`), forwards `tenantId` to `confirmPasswordReset`
- `frontend/src/pages/LoginPage.tsx` - "Forgot password?" link carries `orgSlug`/`tenantSlug`; `LoginResponse.user` type gains `tenant_id`
- `frontend/src/pages/profile/ProfilePage.tsx` - `resendMutation` now sources `tenant_id`/`email` from the auth store
- `frontend/src/stores/auth.ts` - `AuthUser` gains `tenant_id: string`
- `frontend/e2e/auth-contract.spec.ts` - body assertions for all four flows; fixed pre-existing mock/method bugs blocking those assertions (see Deviations)

## Decisions Made

- **`axiam-email` as a test-only dependency**, not a runtime one — keeps the production dependency graph unchanged while giving the substitution test access to the real rendering pipeline instead of duplicating/faking it.
- **`resolve_reset_tenant_id` returns `Option<Uuid>`, never a `Result`** — this makes the enumeration-safety property structurally enforced at the type level (there is no `Err` variant to accidentally `?`-propagate) rather than relying on discipline alone.
- **Missing tenant context (no tenant_id, no tenant_slug at all) is enumeration-safe too**, not a distinct 400 — chose the more conservative option so "field omitted" and "slug doesn't exist" are indistinguishable at the response layer.
- **VerifyEmailPage.tsx and router.tsx were left unmodified** — VerifyEmailPage already implements the exact `?token=&tenant_id=` pattern Open Question 2 asks `ResetPasswordPage` to mirror; the router needs no path changes since tenant context is carried via query params on the existing routes.

## Deviations from Plan

### Auto-fixed / auto-added

**1. [Rule 2 - missing critical functionality] Exposed `tenant_id` on `LoginUserInfo` (login + `/auth/me` responses)**
- **Found during:** Task 2 (frontend threading)
- **Issue:** The plan's own action text requires `resendVerification`'s `ProfilePage` call site to pass "the current user's `tenant_id` ... from the auth store," but neither the login response nor `/auth/me` exposed a raw tenant_id UUID anywhere — only an (effectively always-unpopulated) `tenant_slug` existed. Without this field the plan's explicit instruction was literally impossible to satisfy.
- **Fix:** Added `tenant_id: Uuid` to `LoginUserInfo` (already known server-side at both construction sites — the validated JWT's `tenant_id` claim in `cookie_response_from_output`, and `AuthenticatedUser.tenant_id` in the `/auth/me` handler). Purely additive; does not widen trust.
- **Files modified:** `crates/axiam-api-rest/src/handlers/auth.rs`
- **Commit:** `b18f017`

**2. [Rule 3 - blocking issue] `stores/auth.ts` and `pages/profile/ProfilePage.tsx` touched (not in the plan's `files_modified` list)**
- **Found during:** Task 2
- **Issue:** `resendVerification`'s new required parameters (`tenantId`, `email`) need a source; `AuthUser` didn't carry `tenant_id` and `ProfilePage`'s mutation called `resendVerification` with no arguments.
- **Fix:** Added `tenant_id: string` to `AuthUser`; `ProfilePage`'s `resendMutation` now reads `tenant_id`/`email` from the auth store and rejects locally (no network call) if either is missing.
- **Files modified:** `frontend/src/stores/auth.ts`, `frontend/src/pages/profile/ProfilePage.tsx`
- **Commit:** `edcc661`

**3. [Rule 1 - bugs blocking the current task] Fixed three pre-existing bugs in `auth-contract.spec.ts` discovered while adding body assertions**
- **Found during:** Task 3
- **Issues:**
  - `VerifyEmailPage`'s existing test intercepted **GET** requests, but `authService.verifyEmail` has always sent a **POST** — `capturedUrl` could never have been populated by a real run, and the test's `goto()` URL was also missing `tenant_id`, which `VerifyEmailPage`'s `hasRequiredParams` gate requires before it will even attempt verification.
  - `mockAuthMe`'s mocked response body was a flat object, but `fetchCurrentUser()` reads `res.data.user` — the mock could never satisfy that check, meaning every "authenticated" test in the file was silently running unauthenticated (`clearAuth()` would have fired).
  - `mockUserProfile` intercepted the literal path `.../users/me`, but `ProfilePage.getCurrentUser()` addresses the user by their real id (there is no `/users/me` alias) — the mock could never match the actual request.
- **Fix:** Changed the VerifyEmailPage route interception to POST and added `tenant_id` to its `goto()` URL; nested `mockAuthMe`'s body under `user` and added `tenant_id` (23-06); broadened `mockUserProfile`'s route glob to a single-segment wildcard (`**/api/v1/users/*`).
- **Files modified:** `frontend/e2e/auth-contract.spec.ts`
- **Commit:** `fb0f24c`
- **Note:** These were genuinely pre-existing defects, not introduced by this plan — but fixing them was required for my newly-added body assertions to be reachable at all (Rule 1's "directly blocking the current task" criterion), so they are fixed rather than deferred.

None of these deviations touch enumeration-safety, weaken any security control, or ship a placeholder link.

## Issues Encountered

- **Sandbox environment build prerequisite (pre-existing, same as 23-03/04/05):** `utoipa-swagger-ui`'s build script needs to download a Swagger UI zip from GitHub, unreachable in this sandbox. Worked around with a placeholder zip built in the scratchpad directory and pointed at via `SWAGGER_UI_DOWNLOAD_URL=file://...` for every `axiam-api-rest` build/test/clippy invocation. Local build-only, no code/config change.
- **Playwright browser download blocked:** `npx playwright install chromium` fails with `403 request rejected: host not permitted` against `cdn.playwright.dev` — the sandbox's outbound proxy does not allowlist that host. `frontend/e2e/auth-contract.spec.ts` was authored, type-checked (`npx tsc -b`), and lint-checked (`npx eslint .`) — both clean — but could not be executed end-to-end in this session. Per the plan's explicit allowance (writing/adjusting the spec is sufficient; CI execution is CORR-04/Phase 26), this is a documented skip, not a gap in the deliverable.
- **Disk space:** the sandbox started with ~23 GB free and ran out mid-session during a whole-crate `cargo test -p axiam-api-rest` (no `--lib` filter) after several incremental compiles. Freed space by removing `target/debug/incremental` (safe — only affects incremental-compilation cache, not source or committed artifacts) and re-ran the specific touched-module test targets (`cargo test -p axiam-api-rest --lib handlers::`), which passed (9/9). All per-crate verification in this plan was scoped correctly (`-p axiam-api-rest`, never `--workspace`) per CLAUDE.md discipline; the disk exhaustion was from an out-of-scope broader command, not from this plan's required verification.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- SECFIX-06 is closed: both reset and verify emails carry a fully-substituted, tenant-aware action_url; tenant resolution is enumeration-safe for both a bad slug and missing tenant context; the frontend no longer 400s on any of the three flows; the contract spec would catch a re-omission regression in request bodies.
- **Phase 23 is now complete** — all six SECFIX findings (SECFIX-01 through SECFIX-06) have shipped, each with atomic commits, a threat-model-mapped mitigation, and a proving test (negative test for the security-specific findings, substitution + enumeration-safety tests for this one).
- Deferred/tracked elsewhere (unchanged by this plan): webhook delivery wiring (CORR-03), Playwright-in-CI with body assertions now enabled by this plan's spec changes (CORR-04) — both Phase 26.

---
*Phase: 23-security-regressions-high-findings*
*Completed: 2026-07-03*

## Self-Check: PASSED

- All 11 modified files verified present on disk (`crates/axiam-api-rest/src/handlers/{password_reset,email_verification,auth}.rs`, `crates/axiam-api-rest/Cargo.toml`, `frontend/src/services/auth.ts`, `frontend/src/pages/auth/{ForgotPasswordPage,ResetPasswordPage}.tsx`, `frontend/src/pages/LoginPage.tsx`, `frontend/src/pages/profile/ProfilePage.tsx`, `frontend/src/stores/auth.ts`, `frontend/e2e/auth-contract.spec.ts`).
- All 4 commits (`35ecb52`, `b18f017`, `edcc661`, `fb0f24c`) verified present in `git log`.
- Backend tests verified green: `cargo test -p axiam-api-rest --lib handlers::` — 9/9 pass, including the two new action_url substitution tests and the two new enumeration-safety tests.
