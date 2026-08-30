---
phase: 29-structural-quality
plan: 07
subsystem: ui
tags: [react, typescript, vite, playwright, tanstack-query, dedup]

# Dependency graph
requires:
  - phase: 29-structural-quality
    provides: shared.tsx / lib/utils.ts / services/users.ts / hooks/useCrudMutations.ts canonical modules (pre-existing, zero/partial adoption before this plan)
provides:
  - shared.tsx ActionBadge fixed to lowercase the action before the color-map lookup, with a single reconciled fallback class and wrapper className matching real production usage
  - 9 pages (FederationPage, GroupDetailPage, NotificationRulesPage, PermissionsPage, RoleDetailPage, ServiceAccountsPage, UsersPage, WebhooksPage, RolesPage) with local ToggleField/SectionCard/InfoRow/ActionBadge duplicates now import the canonical components/shared.tsx versions
  - UserDetailPage migrated for SectionCard + ToggleField only (local InfoRow intentionally kept — see Deviations)
  - OrganizationsPage/OrganizationDetailPage use lib/utils.ts's slugify instead of local copies
  - ProfilePage/MfaManagementPage route data calls through the typed userService (get/update/listMfaMethods/deleteMfaMethod) instead of inline api.get/api.put/api.delete
  - RolesPage adopts useCrudMutations for its create/edit/delete mutations
affects: [frontend-ui, structural-quality-followups]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "components/shared.tsx as the single source of truth for ToggleField/SectionCard/InfoRow/ActionBadge — page-local copies should be diffed byte-for-byte against it before being deleted (this plan found 2 of 13 local copies were NOT actually identical)"
    - "userService typed methods (get/update/listMfaMethods/deleteMfaMethod) as the canonical data-access layer for user/profile/MFA pages, replacing inline api.get/api.put/api.delete"
    - "useCrudMutations as the canonical create/edit/delete mutation factory for simple CRUD admin pages"

key-files:
  created: []
  modified:
    - frontend/src/components/shared.tsx
    - frontend/src/pages/federation/FederationPage.tsx
    - frontend/src/pages/groups/GroupDetailPage.tsx
    - frontend/src/pages/notifications/NotificationRulesPage.tsx
    - frontend/src/pages/organizations/OrganizationDetailPage.tsx
    - frontend/src/pages/organizations/OrganizationsPage.tsx
    - frontend/src/pages/permissions/PermissionsPage.tsx
    - frontend/src/pages/roles/RoleDetailPage.tsx
    - frontend/src/pages/roles/RolesPage.tsx
    - frontend/src/pages/service-accounts/ServiceAccountsPage.tsx
    - frontend/src/pages/users/UserDetailPage.tsx
    - frontend/src/pages/users/UsersPage.tsx
    - frontend/src/pages/webhooks/WebhooksPage.tsx
    - frontend/src/pages/profile/ProfilePage.tsx
    - frontend/src/pages/profile/MfaManagementPage.tsx

key-decisions:
  - "Reconciled shared.tsx ActionBadge's wrapper className (px-2 py-0.5 text-xs, no uppercase/tracking-wider) to match the real production usage in RoleDetailPage/PermissionsPage, not shared.tsx's own prior (unused) className — the plan's read_first note only called out the color-map lookup/fallback divergence, but the wrapper className also diverged and would have visibly shrunk/uppercased real badges on adoption"
  - "UserDetailPage's local InfoRow and SettingsPage's local ToggleField were NOT migrated — both diverge from shared.tsx's implementation in ways that change rendered output (InfoRow: sm:items-center/w-40/no-pt-0.5 vs shared's sm:items-start/w-36/pt-0.5; SettingsPage's ToggleField: supports description/disabled props and uses a completely different label-wrapping DOM structure). Migrating either would violate D-03 behavior preservation."
  - "ProfilePage's edit-profile flow now uses userService.update with the `display_name: trimmed || undefined` convention already established by UserDetailPage/UsersPage, rather than ProfilePage's previous merge-and-delete-key approach that guaranteed a full metadata clear. This matches the app-wide userService.update contract/behavior consistently (no other code path writes any user.metadata key besides display_name)."
  - "GroupsPage/PermissionsPage/WebhooksPage/ServiceAccountsPage/NotificationRulesPage were evaluated for useCrudMutations adoption (all would fit as cleanly as RolesPage) but left unmigrated, since they are not in this plan's frontmatter files_modified list — keeping the diff scoped to the declared file set per D-19 review separability."

requirements-completed: [QUAL-06]

coverage:
  - id: D1
    description: "shared.tsx ActionBadge lowercases the action before the color-map lookup and uses a single reconciled fallback/wrapper class matching real production usage"
    requirement: "QUAL-06"
    verification:
      - kind: unit
        ref: "npx tsc -b (type-checks the updated component)"
        status: pass
      - kind: other
        ref: "grep -rn 'function ActionBadge|const ActionBadge' frontend/src/pages/ returns 0 matches"
        status: pass
    human_judgment: true
    rationale: "Visual color/sizing parity on Permissions and Role detail pages needs eyeballing in a real browser — covered by the Task 3 manual smoke checklist, PENDING."
  - id: D2
    description: "9 pages (FederationPage, GroupDetailPage, NotificationRulesPage, PermissionsPage, RoleDetailPage, ServiceAccountsPage, UsersPage, WebhooksPage, RolesPage) + UserDetailPage (partial) import shared ToggleField/SectionCard/InfoRow instead of local duplicates"
    requirement: "QUAL-06"
    verification:
      - kind: unit
        ref: "npx tsc -b"
        status: pass
      - kind: unit
        ref: "npx eslint ."
        status: pass
    human_judgment: true
    rationale: "No direct e2e coverage for the visual rendering of toggles/section cards/info rows on all 9+1 pages — Task 3 manual smoke, PENDING."
  - id: D3
    description: "OrganizationsPage/OrganizationDetailPage use lib/utils.ts's slugify instead of local copies"
    requirement: "QUAL-06"
    verification:
      - kind: unit
        ref: "npx tsc -b"
        status: pass
      - kind: other
        ref: "grep -rn 'function slugify|const slugify' frontend/src/pages/organizations/OrganizationsPage.tsx frontend/src/pages/organizations/OrganizationDetailPage.tsx returns 0 matches"
        status: pass
    human_judgment: false
  - id: D4
    description: "ProfilePage/MfaManagementPage route data calls through userService (get/update/listMfaMethods/deleteMfaMethod) instead of inline api.get/api.put/api.delete"
    requirement: "QUAL-06"
    verification:
      - kind: unit
        ref: "npx tsc -b"
        status: pass
      - kind: other
        ref: 'grep -n "from \"@/lib/api\"" frontend/src/pages/profile/ProfilePage.tsx frontend/src/pages/profile/MfaManagementPage.tsx returns 0 matches'
        status: pass
      - kind: e2e
        ref: "e2e/identity.spec.ts (Playwright — profile/MFA pages), suite could not execute in this sandbox — see Issues Encountered"
        status: unknown
    human_judgment: true
    rationale: "Playwright e2e suite (the plan's designated no-behavior-change gate for this deliverable) could not execute in this sandbox due to a browser-binary version mismatch unrelated to the code change. Needs a real run + Task 3 manual smoke to close out."
  - id: D5
    description: "RolesPage adopts useCrudMutations for create/edit/delete mutations, with the toast-on-error UX delta explicitly flagged"
    requirement: "QUAL-06"
    verification:
      - kind: unit
        ref: "npx tsc -b"
        status: pass
      - kind: e2e
        ref: "e2e/roles.spec.ts (Playwright), suite could not execute in this sandbox — see Issues Encountered"
        status: unknown
    human_judgment: true
    rationale: "Same Playwright-suite environment limitation as D4; the toast-on-error behavior change on delete failure also needs a human read (per plan's explicit call-out) rather than silent auto-pass."

# Metrics
duration: 55min
completed: 2026-07-06
status: complete
---

# Phase 29 Plan 07: Frontend Shared Components & Services Adoption Summary

**Fixed shared.tsx's ActionBadge divergence (case-insensitive lookup + reconciled fallback/wrapper class) then wired 9 pages (+UserDetailPage partial) to the canonical shared.tsx components, 2 pages to shared slugify, ProfilePage/MfaManagementPage to userService, and RolesPage to useCrudMutations — Playwright suite could not execute in this sandbox (browser-binary version mismatch), Task 3 manual smoke PENDING HUMAN VERIFICATION.**

## Performance

- **Duration:** ~55 min
- **Started:** 2026-07-06 (session start)
- **Completed:** 2026-07-06T14:34:40Z
- **Tasks:** 2 of 3 executed (Task 3 is a `checkpoint:human-verify` — see below)
- **Files modified:** 15

## Accomplishments

- Fixed `shared.tsx`'s `ActionBadge` to lowercase the action before the `ACTION_COLOR_MAP` lookup, and reconciled both the fallback class and the wrapper `className` (padding/font-size/uppercase) to match the real production behavior already in `RoleDetailPage`/`PermissionsPage` (the only two real usage sites; `shared.tsx`'s prior version had zero external adopters).
- Migrated 9 pages' local `ToggleField`/`SectionCard`/`InfoRow`/`ActionBadge` duplicates to import from `components/shared.tsx`: `FederationPage`, `GroupDetailPage`, `NotificationRulesPage`, `PermissionsPage`, `RoleDetailPage`, `ServiceAccountsPage`, `UsersPage`, `WebhooksPage`, `RolesPage`. `UserDetailPage` migrated for `SectionCard`/`ToggleField` only (its local `InfoRow` differs from shared's and was intentionally kept — see Deviations).
- Removed `RoleDetailPage.tsx`'s dead exported local `ActionBadge` (zero external importers).
- `OrganizationsPage`/`OrganizationDetailPage` now import `slugify` from `lib/utils.ts` instead of maintaining local copies (functionally identical regex).
- `ProfilePage`/`MfaManagementPage` now call `userService.get`/`userService.update`/`userService.listMfaMethods`/`userService.deleteMfaMethod` instead of inline `api.get`/`api.put`/`api.delete`; the raw `@/lib/api` import is gone from both files.
- `RolesPage` adopts `useCrudMutations` for its create/edit/delete mutations, explicitly flagging the accepted toast-on-error UX delta on delete failure (previously silent).
- `tsc -b` and `eslint .` are both clean after all changes.

## Task Commits

1. **Task 1: Fix shared.tsx ActionBadge, then migrate 11 pages to shared components + shared slugify** - `b0c63c9` (feat)
2. **Task 2: Profile/MFA → userService (D-16); adopt useCrudMutations where it cleanly fits** - `daecb6f` (feat)

**Task 3 (`checkpoint:human-verify`): NOT executed by this run.** This plan was executed by an automated sequential executor with no human available to perform a browser smoke test. Per explicit run instructions, Task 3 is recorded below as **PENDING HUMAN VERIFICATION** rather than fabricated, and the plan's manual smoke checklist is reproduced verbatim so the orchestrator/human can pick it up.

**Plan metadata:** committed separately (this SUMMARY + STATE.md + ROADMAP.md + REQUIREMENTS.md).

## Files Created/Modified

- `frontend/src/components/shared.tsx` - `ActionBadge` case-insensitive lookup + reconciled fallback/wrapper class
- `frontend/src/pages/federation/FederationPage.tsx` - `ToggleField` → shared import
- `frontend/src/pages/groups/GroupDetailPage.tsx` - `SectionCard`/`InfoRow` → shared import
- `frontend/src/pages/notifications/NotificationRulesPage.tsx` - `ToggleField` → shared import
- `frontend/src/pages/organizations/OrganizationDetailPage.tsx` - local `slugify` → `lib/utils.ts` import
- `frontend/src/pages/organizations/OrganizationsPage.tsx` - local `slugify` → `lib/utils.ts` import
- `frontend/src/pages/permissions/PermissionsPage.tsx` - `ActionBadge` → shared import
- `frontend/src/pages/roles/RoleDetailPage.tsx` - `SectionCard`/`InfoRow`/`ActionBadge` → shared import; dead local `ActionBadge` export removed
- `frontend/src/pages/roles/RolesPage.tsx` - `ToggleField` → shared import; create/edit/delete mutations → `useCrudMutations`
- `frontend/src/pages/service-accounts/ServiceAccountsPage.tsx` - `ToggleField` → shared import
- `frontend/src/pages/users/UserDetailPage.tsx` - `SectionCard`/`ToggleField` → shared import (local `InfoRow` kept — see Deviations)
- `frontend/src/pages/users/UsersPage.tsx` - `ToggleField` → shared import
- `frontend/src/pages/webhooks/WebhooksPage.tsx` - `ToggleField` → shared import
- `frontend/src/pages/profile/ProfilePage.tsx` - `getCurrentUser`/`updateProfile`/`getMfaMethods` inline helpers removed; routes through `userService`
- `frontend/src/pages/profile/MfaManagementPage.tsx` - `getMfaMethods`/`deleteMfaMethod` inline helpers removed; routes through `userService`

## Decisions Made

- Reconciled `shared.tsx`'s `ActionBadge` wrapper `className` (not just the color-map lookup/fallback) to match `RoleDetailPage`/`PermissionsPage`'s real production styling (`px-2 py-0.5 text-xs`, no `uppercase tracking-wider`) — the plan's `read_first` note only called out the lookup/fallback divergence, but the wrapper `className` was also divergent (`px-1.5`, `text-[10px]`, `uppercase tracking-wider`) and would have visibly shrunk and uppercased the two real-usage badges on adoption. See Deviations for full rationale.
- Left `UserDetailPage`'s local `InfoRow` and `SettingsPage`'s local `ToggleField` unmigrated — both genuinely diverge from `components/shared.tsx`'s implementation (not "byte-identical" as the plan's must_haves assumed). See Deviations.
- `ProfilePage`'s clear-display-name behavior now follows the same `display_name: trimmed || undefined` convention as `UserDetailPage`/`UsersPage` (via `userService.update`), rather than its own previous full-metadata-object-replace approach. No functional user metadata key besides `display_name` exists anywhere in the app, so this is behavior-neutral in practice.
- `GroupsPage`/`PermissionsPage`/`WebhooksPage`/`ServiceAccountsPage`/`NotificationRulesPage` were evaluated for `useCrudMutations` fit (all match `RolesPage`'s shape cleanly) but deliberately left unmigrated since they are outside this plan's declared `files_modified` scope (D-19 review separability) — flagged as a natural follow-up plan.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] shared.tsx ActionBadge wrapper className also diverged from real usage (beyond the plan's documented lookup/fallback divergence)**
- **Found during:** Task 1
- **Issue:** The plan's `read_first` note and `must_haves` only called out `ACTION_COLOR_MAP` case-sensitivity and the fallback class as needing reconciliation. On inspection, `shared.tsx`'s `ActionBadge` wrapper `className` (`px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider border`) also diverged from the className actually rendered at both real usage sites in `RoleDetailPage`/`PermissionsPage` (`px-2 py-0.5 text-xs font-medium border`, no uppercase/tracking). Migrating `PermissionsPage`/`RoleDetailPage` onto `shared.tsx`'s unreconciled className would have visibly shrunk and uppercased every action badge on those two real pages — a behavior regression this plan's D-03 constraint explicitly prohibits.
- **Fix:** Reconciled `shared.tsx`'s wrapper `className` to the real-usage value (`px-2 py-0.5 rounded text-xs font-medium border`) in the same edit that fixed the color-map lookup/fallback.
- **Files modified:** `frontend/src/components/shared.tsx`
- **Verification:** `npx tsc -b` clean; visual parity is now byte-identical to the pre-migration `RoleDetailPage`/`PermissionsPage` local `ActionBadge` rendering (confirmed by diff, not yet by browser screenshot — folded into Task 3's manual smoke).
- **Committed in:** `b0c63c9` (Task 1 commit)

**2. [Rule 4 - Architectural/behavior-preservation] Plan's "byte-identical" premise did not hold for 2 of 13 local component copies**
- **Found during:** Task 1
- **Issue:** The plan's `must_haves.truths` asserted `SectionCard/InfoRow/ToggleField are byte-identical to their local copies — direct swaps`. Diffing every local copy against `components/shared.tsx` found two genuine exceptions: (a) `UserDetailPage.tsx`'s local `InfoRow` uses `sm:items-center`/`sm:w-40`/no `pt-0.5` vs shared's `sm:items-start`/`sm:w-36`/`pt-0.5` (alignment/width visibly different); (b) `SettingsPage.tsx`'s local `ToggleField` supports `description`/`disabled` props and a completely different label-wrapping DOM/class structure, actively used in 3 real toggles (`hibp_check_enabled`, `mfa_enforced`, `email_verification_required`, `admin_notifications_enabled`).
- **Fix:** Did NOT migrate these two components — kept both local, with an inline comment on `UserDetailPage.tsx`'s `InfoRow` explaining why. `SettingsPage.tsx` was left entirely untouched (no changes at all in this plan, despite being listed in the plan's `files_modified`).
- **Files modified:** `frontend/src/pages/users/UserDetailPage.tsx` (comment added, `InfoRow` kept local; `SectionCard`/`ToggleField` still migrated)
- **Verification:** `npx tsc -b`/`npx eslint .` clean; no visual regression risk since nothing changed for these two components.
- **Committed in:** `b0c63c9` (Task 1 commit)

---

**Total deviations:** 2 auto-fixed (1 bug/parity fix in shared.tsx beyond the plan's documented scope, 1 conservative non-migration to preserve D-03 behavior-preservation where the plan's premise was inaccurate)
**Impact on plan:** Both deviations exist specifically to uphold the plan's own D-03 behavior-preservation constraint more strictly than the plan's own `read_first`/`must_haves` text anticipated. No scope creep beyond what's necessary for correctness; `SettingsPage.tsx` (listed in `files_modified`) ends up with zero diff, which is intentional and documented here rather than silent.

## Issues Encountered

- **Playwright e2e suite could not execute in this sandbox.** Running `cd frontend && npx playwright test` (108 tests) failed uniformly with `Error: browserType.launch: Executable doesn't exist at /opt/pw-browsers/chromium_headless_shell-1208/...` (and, under `--headed`, `chromium-1208`). The pre-installed browser cache at `/opt/pw-browsers` only has revision `1194` variants (`chromium-1194`, `chromium_headless_shell-1194`), but the project's pinned `@playwright/test@1.58.2` expects revision `1208`. This is a pure environment/browser-cache version mismatch, unrelated to any code change in this plan — every one of the 107 failures (1 skipped) is the identical launch error, occurring before any test body executes (2-6ms per test). Per the run's explicit instructions, `playwright install` was NOT run to try to resolve this. `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/opt/pw-browsers/chromium` was tried as a workaround and did not change the outcome (Playwright's default headless mode still requires the separate `chrome-headless-shell` binary at the pinned revision). This needs to be resolved in the CI/dev environment (matching the pre-installed browser cache to the pinned `@playwright/test` version, or vice versa) before the suite can actually gate this plan's changes.
- Also required a Docker daemon (unavailable — `docker ps` fails with "no such file or directory" on the daemon socket) plus a live `axiam-server` + SurrealDB + RabbitMQ backend (`just dev-up` + `just run-local` + `just bootstrap-local`) for any of the 108 e2e specs to pass even with a working browser — none of that infrastructure is reachable in this sandbox, and building/running the Rust backend is explicitly out of scope for this frontend-only plan (per the plan's own verification section: "No cargo build in this plan").
- **`tsc -b` and `npx eslint .` both ran cleanly** (deterministic, environment-independent gates) after every edit in this plan, giving source-level confidence in the migration independent of the Playwright/backend limitation above.

## Task 3: PENDING HUMAN VERIFICATION

Task 3 (`checkpoint:human-verify`, gate="blocking") requires a human to manually smoke-test the migrated pages in a real browser. This could not be performed by this automated run. The manual smoke checklist below is reproduced verbatim from the plan for the human/orchestrator to execute:

> Manual smoke of the migrated pages that lack direct Playwright coverage (per 29-VALIDATION Manual-Only table):
> 1. `cd frontend && npm run dev` (or the project's dev command) and log in.
> 2. Visit Users, User detail, Roles, Role detail, Permissions, Federation, Settings, Notification rules,
>    Service accounts, Webhooks, Groups/Group detail, Organizations/Organization detail, Profile, MFA management.
> 3. Confirm each page renders and functions identically to before (toggles, section cards, info rows, badges,
>    slug fields, profile/MFA read+update flows).
> 4. Specifically confirm ActionBadge colors are correct/unchanged on Permissions and Role detail (the
>    case-sensitivity + fallback-class divergence that was reconciled in shared.tsx).
> 5. Confirm the accepted toast-on-error behavior on create/update/delete failures is acceptable.
>
> **Resume signal:** Type "approved" or describe any page whose rendering/behavior regressed.

**Additionally recommend the human/CI also run** `cd frontend && npx playwright test` in an environment with a matching browser cache + live backend, since that suite could not be exercised in this sandbox (see Issues Encountered).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- QUAL-06's automated code changes (Task 1 + Task 2) are complete, committed, and pass `tsc -b`/`eslint` cleanly.
- **Blocker for full plan closure:** Task 3's manual browser smoke test has not been performed, and the Playwright e2e suite has not been run to completion in any environment for this plan's diff (sandbox limitation documented above). Both should be completed before this plan/phase is considered fully verified.
- This was the last plan in phase 29 (structural-quality) per the plan's own D-19 review-separability note.

## Self-Check: PASSED

- FOUND: `.planning/phases/29-structural-quality/29-07-SUMMARY.md`
- FOUND: commit `b0c63c9` (Task 1)
- FOUND: commit `daecb6f` (Task 2)
