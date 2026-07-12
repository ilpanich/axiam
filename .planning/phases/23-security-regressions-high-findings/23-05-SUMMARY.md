---
phase: 23-security-regressions-high-findings
plan: 05
subsystem: auth
tags: [logout, session-revocation, cookies, frontend, security]

# Dependency graph
requires: []
provides:
  - "Body-less POST /api/v1/auth/logout — revokes the caller's own session from AuthenticatedUser.session_id (== JWT jti, D-15), no client-supplied session_id"
  - "logout_clears_cookies replay-after-logout assertion — proves a revoked session's old access cookie is rejected on the next request"
  - "SessionValidator wired into axiam-api-rest/tests/auth_test.rs's test_app! macro (was previously only wired in password_change.rs/mfa_reset_still_revokes.rs/password_reset_revokes_sessions.rs)"
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Revoke-from-verified-JWT-jti, not from a client-supplied identifier — the session to invalidate is derived entirely server-side from AuthenticatedUser.session_id; there is no request body to trust or reject"

key-files:
  created:
    - frontend/e2e/logout.spec.ts
  modified:
    - crates/axiam-api-rest/src/handlers/auth.rs
    - crates/axiam-api-rest/src/openapi.rs
    - crates/axiam-api-rest/tests/auth_test.rs
    - frontend/src/components/layout/Topbar.tsx

key-decisions:
  - "No new plumbing needed for the backend fix — AuthenticatedUser.session_id already equals the JWT jti (extractors/auth.rs, D-15), and AuthService::logout / SessionValidator were already correct. The only defect was the handler requiring a LogoutRequest{session_id} body that the frontend didn't send, causing a 400 before revocation ever ran (logout was a client-side-only no-op)."
  - "Added SessionValidator (Arc<dyn axiam_api_rest::SessionValidator>) to auth_test.rs's test_app! macro, mirroring the existing wiring pattern in password_change.rs/mfa_reset_still_revokes.rs/password_reset_revokes_sessions.rs. Without it the per-request liveness check silently no-ops (by design, for non-session test harnesses) and the new replay-after-logout assertion could not have been proven meaningful."
  - "sdks/rust/src/rest/auth.rs's local LogoutRequestBody struct (used by the Rust client SDK) was left untouched — it is a distinct, locally-scoped SDK type, not a reference to the removed handler DTO, and is out of this plan's file scope. A client sending an unused body to the now-body-less endpoint is harmless (Actix has no Json extractor to reject it)."

requirements-completed: [SECFIX-05]

coverage:
  - id: D1
    description: "After POST /api/v1/auth/logout, a request replaying the old access cookie is unauthenticated (401 on /api/v1/auth/me) — the defining SECFIX-05 negative signal (ROADMAP SC#5)"
    requirement: SECFIX-05
    verification:
      - kind: integration
        ref: "crates/axiam-api-rest/tests/auth_test.rs#logout_clears_cookies (replay assertion) — cargo test -p axiam-api-rest --test auth_test"
        status: pass
    human_judgment: false
  - id: D2
    description: "logout handler takes no request body and calls svc.logout(user.tenant_id, user.session_id); LogoutRequest DTO and its OpenAPI references are fully removed"
    requirement: SECFIX-05
    verification:
      - kind: other
        ref: "grep -rn LogoutRequest crates/axiam-api-rest/ — no matches"
        status: pass
    human_judgment: false
  - id: D3
    description: "All three cookies (access/refresh/csrf) are still cleared on logout"
    requirement: SECFIX-05
    verification:
      - kind: integration
        ref: "crates/axiam-api-rest/tests/auth_test.rs#logout_clears_cookies (cookie-clearing loop, unchanged assertions)"
        status: pass
    human_judgment: false
  - id: D4
    description: "Frontend handleLogout posts no body and no longer risks a 400; Playwright logout spec exists and asserts success + unauthenticated-afterward"
    requirement: SECFIX-05
    verification:
      - kind: other
        ref: "grep -n 'logout\", {}' frontend/src — no matches; frontend/e2e/logout.spec.ts authored (local execution only, CI wiring is CORR-04/Phase 26)"
        status: pass
      - kind: unit
        ref: "cd frontend && npx tsc -b && npx eslint . — both clean"
        status: pass
    human_judgment: false
  - id: D5
    description: "Existing auth_test.rs suite stays green after the handler/body change and SessionValidator wiring"
    requirement: SECFIX-05
    verification:
      - kind: integration
        ref: "cargo test -p axiam-api-rest --test auth_test — 19/19 pass"
        status: pass
      - kind: other
        ref: "cargo clippy -p axiam-api-rest --tests -- -D warnings; cargo fmt -p axiam-api-rest --check — both clean"
        status: pass

duration: ~35min
completed: 2026-07-03
status: complete
---

# Phase 23 Plan 05: Logout Revokes the Caller's Session (SECFIX-05) Summary

**Removed the client-supplied `LogoutRequest{session_id}` body that was causing logout to 400 before revocation ever ran; the handler now revokes solely from the verified JWT `jti`, and a new replay-after-logout test proves the old cookie is rejected once the session row is gone.**

## Performance

- **Duration:** ~35 min
- **Completed:** 2026-07-03
- **Tasks:** 2 completed
- **Files modified:** 4 (+ 1 created: `frontend/e2e/logout.spec.ts`)

## Accomplishments

- **Backend (`crates/axiam-api-rest/src/handlers/auth.rs`):** `logout` no longer takes `body: web::Json<LogoutRequest>`. It now derives the session to revoke entirely from `user.session_id` (`AuthenticatedUser.session_id`, which already equals the JWT `jti` per D-15) and calls `svc.logout(user.tenant_id, user.session_id)`. The dead cross-session comparison (`body.session_id != user.session_id`) is gone along with the body — there is no client-supplied identifier left to compare or reject. All three cookies (`clear_access_cookie`/`clear_refresh_cookie`/`clear_csrf_cookie`) are still cleared on the `204` response, unchanged.
- **DTO removal:** `LogoutRequest` struct and its `request_body = LogoutRequest` OpenAPI annotation are deleted from `auth.rs`; the matching `handlers::auth::LogoutRequest` schema registration is removed from `openapi.rs`. `grep -rn LogoutRequest crates/axiam-api-rest/` returns no matches.
- **Negative test (the defining SECFIX-05 signal):** `logout_clears_cookies` now sends no body on the logout request (matching the new handler signature) and, after the existing cookie-clearing assertions, replays the pre-logout `axiam_access` cookie against `GET /api/v1/auth/me` and asserts `401`. This is the proof that revocation is real, not just a 204 response — the session row behind the JWT is hard-deleted (`AuthService::logout` → `session_repo.invalidate`), and `SessionValidator::is_session_active` rejects the stale JWT on the very next request even though the JWT itself hasn't expired.
- **Test harness fix (Rule 3 — blocking):** `auth_test.rs`'s `test_app!` macro did not register `Arc<dyn SessionValidator>` as app data, so the per-request liveness check would have silently no-op'd (by design, for non-session harnesses) and the new replay assertion would have passed for the wrong reason (or not proven anything). Added the same `SurrealSessionRepository` → `Arc<dyn axiam_api_rest::SessionValidator>` wiring already used in `password_change.rs`, `mfa_reset_still_revokes.rs`, and `password_reset_revokes_sessions.rs`. All 19 tests in the file (including the other 18 that now also go through the liveness check) stay green — every one of them operates on a freshly-created, still-active session.
- **Frontend (`frontend/src/components/layout/Topbar.tsx`):** `handleLogout` now calls `api.post("/api/v1/auth/logout")` with no second argument (dropped the `{}`), matching the body-less backend. Client-side cleanup (query cache clear, auth store clear, redirect to `/login`) is unchanged.
- **New Playwright spec (`frontend/e2e/logout.spec.ts`):** logs in via the existing `loginAsAdmin` helper, opens the Topbar user menu, clicks "Sign out", and asserts (a) the `/api/v1/auth/logout` network response is not a 400 and is `ok()`, (b) the app redirects to `/login`, and (c) a reload does not silently re-authenticate (confirms client auth state was actually cleared, not just navigated away transiently).

## Fail-Before / Pass-After Proof (replay-after-logout)

Verified the negative test actually exercises the fix, not just passes vacuously:

- **Before** (handler reverted to the original `body: web::Json<LogoutRequest>` signature via `git stash`, test file kept at the new no-body-request form): `cargo test -p axiam-api-rest --test auth_test logout_clears_cookies` **fails** — the logout request itself errors out (no body sent against a handler that requires one), so the test never reaches the replay assertion. This demonstrates the pre-fix state genuinely could not complete a successful logout from a real client that sends no body.
- **After** (`git stash pop` restoring the fix): all 19 tests in `auth_test.rs` pass, including `logout_clears_cookies` with its replay-after-logout 401 assertion.

## Task Commits

Each task was committed atomically:

1. **Task 1: Body-less server-side logout from jti + remove the redundant DTO; replay-after-logout negative test** - `9a34553` (feat)
2. **Task 2: Frontend handleLogout sends no body + Playwright logout spec** - `29e0a4d` (feat)

**Plan metadata:** (this commit, docs)

## Files Created/Modified

- `crates/axiam-api-rest/src/handlers/auth.rs` - `logout` handler drops the `LogoutRequest` body parameter and cross-session comparison; revokes via `user.session_id`; `LogoutRequest` struct and its `request_body` OpenAPI annotation removed
- `crates/axiam-api-rest/src/openapi.rs` - `handlers::auth::LogoutRequest` schema registration removed
- `crates/axiam-api-rest/tests/auth_test.rs` - `logout_clears_cookies` sends no body and gains the replay-after-logout 401 assertion; `test_app!` macro gains `Arc<dyn SessionValidator>` app_data wiring
- `frontend/src/components/layout/Topbar.tsx` - `handleLogout` posts to `/api/v1/auth/logout` with no body
- `frontend/e2e/logout.spec.ts` (new) - Playwright spec: sign-out via the Topbar control succeeds with no 400 and returns to the unauthenticated state

## Decisions Made

- No new session-tracking, blocklist, or JWT versioning was added (per 23-RESEARCH.md Pitfall 3 and the plan's explicit "deliberately a SMALL fix" framing) — the existing per-request `SessionValidator.is_session_active` liveness check already handles replay once the session row is hard-deleted.
- `sdks/rust/src/rest/auth.rs`'s `LogoutRequestBody` (a distinct, SDK-local struct with a different name, used by the Rust client SDK to send a `{session_id}` body) was intentionally left untouched. It does not reference the removed `axiam_api_rest::handlers::auth::LogoutRequest` type and is outside this plan's declared file scope (`crates/axiam-api-rest/src/handlers/auth.rs`, `crates/axiam-api-rest/tests/auth_test.rs`, `frontend/src/components/layout/Topbar.tsx`, `frontend/e2e/logout.spec.ts`). Because the new handler has no `Json` extractor, an SDK client that still sends a body is harmless — Actix simply never parses it. Updating the SDK to stop sending the now-unnecessary body is a candidate follow-up but not required for SECFIX-05 closure.
- Wired `SessionValidator` into `auth_test.rs`'s `test_app!` macro (previously absent) rather than building a separate, narrower test harness for just the replay assertion — this matches the established pattern in three sibling test files and means all of `auth_test.rs`'s pre-existing tests now also exercise the real liveness-check path (all continue to pass, since they all operate on freshly-created active sessions).

## Deviations from Plan

None — plan executed as written. The only additive change beyond the plan's literal `<action>` text was wiring `SessionValidator` into the test harness, which the plan's own acceptance criteria implicitly required (the replay assertion is meaningless without it) and which is documented above as a Rule 3 (blocking-issue) auto-fix.

## Issues Encountered

- **Sandbox environment build prerequisite (pre-existing, unrelated to this plan's code):** `utoipa-swagger-ui`'s build script needs to download a Swagger UI zip from GitHub, which this sandbox's session cannot reach — the same documented limitation noted in `23-03-SUMMARY.md` and `23-04-SUMMARY.md`. Worked around locally by pointing `SWAGGER_UI_DOWNLOAD_URL` at a minimal placeholder zip built in the scratchpad directory (`file://` protocol) for every `axiam-api-rest` build/test/clippy invocation in this session. This is a local build-only environment variable, not a code or config change, and does not affect the committed diff.
- **`frontend/node_modules` was empty** at session start (fresh checkout/environment) — ran `npm install` before `tsc -b`/`eslint` would work. This regenerated `frontend/package-lock.json` with cosmetic `libc` metadata differences from a different npm version; those lockfile changes were discarded (`git checkout -- frontend/package-lock.json`) before committing, since they are unrelated environment noise, not a dependency change.
- **Playwright execution (`npx playwright test e2e/logout.spec.ts`) was not run in-sandbox.** Running it requires the full stack (SurrealDB + RabbitMQ via `docker compose -f docker/docker-compose.e2e.yml up -d --wait`, `scripts/e2e-bootstrap.sh` seeding, the AXIAM server binary built and running, and the Vite dev server) — `docker` is installed but the daemon is not reachable in this sandbox (`dial unix /var/run/docker.sock: connect: no such file or directory`), and disk headroom is tight (16 GB free after the backend test/clippy builds). Per the plan's explicit allowance ("if a dev server is unavailable in the sandbox, the SUMMARY records the spec authored + the local-run instruction, deferring CI to CORR-04"), the spec was authored and type/lint-checked but not executed here. **To run locally:** `docker compose -f docker/docker-compose.e2e.yml up -d --wait && ./scripts/e2e-bootstrap.sh && cd frontend && npx playwright test e2e/logout.spec.ts`. CI wiring for the full Playwright suite remains CORR-04 (Phase 26), unchanged by this plan.

## User Setup Required

None — no external service configuration required. This is a pure bug fix to an existing, already-deployed endpoint shape (logout was previously reachable but always 400'd from the real frontend).

## Next Phase Readiness

- SECFIX-05 is closed: logout revokes the caller's own session from the verified JWT `jti`, no client-supplied session identifier exists anywhere in the request, all three cookies are cleared, and the replay-after-logout negative test is green (fail-before/pass-after demonstrated).
- No blockers for the remaining Phase 23 plan (SECFIX-06 reset/resend tenant resolution).
- Recommended (not blocking) follow-up: update `sdks/rust/src/rest/auth.rs`'s `LogoutRequestBody` to stop sending an unnecessary body, for SDK hygiene — tracked here as a note, not a new backlog item, since it has zero functional impact on the server.

---
*Phase: 23-security-regressions-high-findings*
*Completed: 2026-07-03*

## Self-Check: PASSED

- All 4 modified files and 1 created file verified present on disk (`crates/axiam-api-rest/src/handlers/auth.rs`, `crates/axiam-api-rest/src/openapi.rs`, `crates/axiam-api-rest/tests/auth_test.rs`, `frontend/src/components/layout/Topbar.tsx`, `frontend/e2e/logout.spec.ts`).
- Both task commits (`9a34553`, `29e0a4d`) verified present in `git log`.
