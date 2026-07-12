---
phase: 26-correctness-resilience
plan: 05
subsystem: auth
tags: [rust, actix-web, serde, rest-api, tenant-slug, jwt-auth]

# Dependency graph
requires:
  - phase: 26-correctness-resilience
    provides: prior CORR plans in this phase (unrelated files)
provides:
  - "LoginUserInfo.tenant_slug/org_slug optional fields (D-14)"
  - "/auth/me and the fresh-login response path (login, verify_mfa, setup_confirm_mfa) resolve and emit both slugs with graceful degradation (D-15)"
affects: [26-08-frontend-tenant-restore]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Optional response-DTO field with skip_serializing_if=Option::is_none populated via .ok()-guarded repo lookup, so a downstream lookup failure degrades the field to absent rather than failing the whole response"

key-files:
  created: []
  modified:
    - crates/axiam-api-rest/src/handlers/auth.rs

key-decisions:
  - "tenant_slug/org_slug resolved strictly from the authenticated user's own tenant_id/organization_id, never from request input (T-26-05-01, no cross-tenant enumeration surface)"
  - "cookie_response_from_output gained tenant_repo/org_repo params (shared by login, verify_mfa, setup_confirm_mfa) so the fresh-login response and a later /me call always agree on slugs"

patterns-established:
  - "Graceful-degrade optional DTO field pattern: .ok()-guarded repo lookup -> Option -> skip_serializing_if, applied uniformly at two call families (me handler, shared cookie_response_from_output)"

requirements-completed: [CORR-05]

coverage:
  - id: D1
    description: "LoginUserInfo/MeResponse gains optional tenant_slug/org_slug fields, omitted from JSON when None"
    requirement: "CORR-05"
    verification:
      - kind: unit
        ref: "crates/axiam-api-rest/src/handlers/auth.rs#tests::login_user_info_serializes_slugs_when_present"
        status: pass
      - kind: unit
        ref: "crates/axiam-api-rest/src/handlers/auth.rs#tests::login_user_info_omits_slugs_when_absent"
        status: pass
    human_judgment: false
  - id: D2
    description: "/auth/me handler resolves tenant_slug/org_slug via .ok()-guarded tenant_repo/org_repo lookups scoped to the caller's own tenant_id, degrading to None on failure without failing the call"
    requirement: "CORR-05"
    verification:
      - kind: unit
        ref: "cargo build -p axiam-api-rest --lib (compiles; grep confirms .ok()-guarded lookups at handlers/auth.rs:208-215 and :701-708)"
        status: pass
    human_judgment: true
    rationale: "No live-DB integration test exercises a real repo failure path in this plan (out of scope per plan's <verify> — build+grep only); a full end-to-end reload-restore check is deferred to plan 26-08 (frontend half) per the plan's own dependency note"
  - id: D3
    description: "cookie_response_from_output (shared by login, verify_mfa, setup_confirm_mfa) populates the same two slugs so a fresh login and a post-reload /me agree"
    requirement: "CORR-05"
    verification:
      - kind: unit
        ref: "cargo build -p axiam-api-rest --lib (compiles all three call sites with the new tenant_repo/org_repo args)"
        status: pass
    human_judgment: true
    rationale: "Verified by compilation and code inspection only; no integration test asserts fresh-login vs. post-reload /me parity live against a database in this plan's scope"

duration: 22min
completed: 2026-07-05
status: complete
---

# Phase 26 Plan 05: Emit tenant_slug/org_slug from /auth/me and fresh-login (CORR-05 backend half) Summary

**LoginUserInfo now emits optional tenant_slug/org_slug (omitted when unresolvable), resolved via `.ok()`-guarded tenant/org repo lookups in both `/auth/me` and the shared `cookie_response_from_output` fresh-login path.**

## Performance

- **Duration:** 22 min
- **Started:** 2026-07-05T09:00:37Z
- **Completed:** 2026-07-05T09:22:48Z
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments
- `LoginUserInfo` gained `tenant_slug: Option<String>` / `org_slug: Option<String>` with `skip_serializing_if = "Option::is_none"` (D-14)
- The `me` handler resolves both slugs from the authenticated user's own `tenant_id` via `.ok()`-guarded `tenant_repo`/`org_repo` lookups — a lookup failure degrades to `None` and never fails `/me` (D-15)
- `cookie_response_from_output` — shared by `login`, `verify_mfa`, and `setup_confirm_mfa` — now resolves and populates the same two slugs, so a fresh login and a subsequent post-reload `/me` call agree
- Added a pure serialization unit test proving both slugs appear when present and are omitted (not `null`) when absent

## Task Commits

Each task was committed atomically:

1. **Task 1: Emit tenant_slug/org_slug from /auth/me and the fresh-login path (D-14/D-15)** - `5379e5e` (feat)
2. **Task 2: Backend test — MeResponse serializes tenant_slug/org_slug and degrades on absence** - `e467b1f` (test)

**Plan metadata:** (this commit)

## Files Created/Modified
- `crates/axiam-api-rest/src/handlers/auth.rs` - `LoginUserInfo` gains `tenant_slug`/`org_slug`; `cookie_response_from_output` gains `tenant_repo`/`org_repo` params and slug resolution; `me`, `verify_mfa`, and `setup_confirm_mfa` handler signatures updated to supply them; added `#[cfg(test)] mod tests` with two serialization assertions

## Decisions Made
- Resolved slugs strictly from the authenticated user's own `tenant_id`/`organization_id` — never from request input — closing off any cross-tenant slug-enumeration surface (T-26-05-01)
- Threaded `tenant_repo`/`org_repo` into `cookie_response_from_output`'s signature (rather than duplicating slug-resolution logic per call site) so `login`, `verify_mfa`, and `setup_confirm_mfa` share one implementation and can never drift out of sync with the `me` handler's degrade contract
- Added `#[allow(clippy::too_many_arguments)]` to `verify_mfa`, `setup_confirm_mfa`, and `me` (each now has 5-6 Actix DI extractor parameters), consistent with the existing precedent already applied to `login` and `change_password` in this file

## Deviations from Plan

None — plan executed exactly as written. Both new handler params (`tenant_repo`, `org_repo`) were already registered as `app_data` in `crates/axiam-server/src/main.rs` (confirmed per the plan's read_first note), so no `main.rs` changes were required.

## Issues Encountered
None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Backend precedent for CORR-05 (D-14/D-15) is in place: `/auth/me`, fresh login, MFA-verify login, and MFA-setup-confirm login all emit `tenant_slug`/`org_slug` with graceful degradation.
- Plan 26-08 (Wave 2, frontend restore + MFA-setup) can now consume these fields to restore the selected tenant on a hard reload — no backend blockers remain for that plan.
- `cargo build -p axiam-api-rest --lib` and `cargo test -p axiam-api-rest --lib handlers::auth` both green with `SWAGGER_UI_DOWNLOAD_URL` exported per CLAUDE.md's build workaround; `cargo clippy -p axiam-api-rest --lib --tests -- -D warnings` clean.

---
*Phase: 26-correctness-resilience*
*Completed: 2026-07-05*

## Self-Check: PASSED
- FOUND: crates/axiam-api-rest/src/handlers/auth.rs
- FOUND: .planning/phases/26-correctness-resilience/26-05-SUMMARY.md
- FOUND commit: 5379e5e
- FOUND commit: e467b1f
