---
phase: 26-correctness-resilience
plan: 06
subsystem: ui
tags: [react, typescript, tanstack-query, react-router, vitest]

# Dependency graph
requires:
  - phase: 26-correctness-resilience
    provides: prior CORR plans in this phase (unrelated files)
provides:
  - "VerifyEmailPage useRef once-guard replacing the cancelled-closure de-dup (D-17)"
  - "Dashboard user-count query key structurally distinct from UsersPage's [users, page, search] key (D-18)"
  - "Org-settings SettingsTab init-once guard + dirty-tracking + navigate-away guard (D-19)"
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "useRef(false) once-guard set synchronously before the async call, mirroring useAuthInit.ts's proven StrictMode de-dup idiom"
    - "Shared query-infrastructure constants (query keys) live in lib/queryClient.ts rather than inline in a page component, so they can be exported for a regression test without tripping react-refresh/only-export-components (array literals are not a 'constant export' under that rule)"
    - "Pure logic extracted to a colocated plain .ts module (not .tsx) when it needs unit-test coverage but the project has no DOM-rendering test harness"
    - "Frozen-snapshot dirty tracking: form compared against the last-loaded server snapshot (not live query data), so a background refetch never overwrites or silently re-cleans an in-progress edit"
    - "Dual navigate-away guard: react-router v7 useBlocker for actual route changes, plus a lifted dirty flag + pending-tab intercept for a component's own in-page tab switch (which is local state, not a router navigation)"

key-files:
  created:
    - frontend/src/pages/DashboardPage.test.ts
    - frontend/src/pages/organizations/settingsForm.ts
    - frontend/src/pages/organizations/OrganizationDetailPage.test.tsx
  modified:
    - frontend/src/pages/auth/VerifyEmailPage.tsx
    - frontend/src/pages/DashboardPage.tsx
    - frontend/src/lib/queryClient.ts
    - frontend/src/pages/organizations/OrganizationDetailPage.tsx
    - frontend/src/components/ConfirmDialog.tsx

key-decisions:
  - "Extracted DASHBOARD_USER_COUNT_QUERY_KEY into lib/queryClient.ts (not inline in DashboardPage.tsx) so it could be exported for a regression test without tripping react-refresh/only-export-components"
  - "Extracted shouldSeedForm/computeIsDirty into settingsForm.ts (plain .ts, not .tsx) for unit-testability — no testing-library/jsdom installed in this project"
  - "Org-settings navigate-away guard uses two complementary mechanisms: useBlocker for route-level navigation, and a lifted isDirty flag + pending-tab intercept in the parent for the Settings tab's own in-page tab switch"
  - "Added an optional cancelLabel prop to ConfirmDialog (defaults to 'Cancel') so the org-settings guard can show 'Keep editing' while all other existing callers are unaffected"

patterns-established:
  - "useRef once-guard idiom for single-use side effects under StrictMode (now used in both useAuthInit.ts and VerifyEmailPage.tsx)"
  - "Colocated *.test.ts/*.test.tsx pure-logic tests as the default test strategy for this project (no component-render harness available)"

requirements-completed: [CORR-06]

coverage:
  - id: D1
    description: "VerifyEmailPage's verify effect fires exactly once per real mount via a useRef guard, eliminating StrictMode's false 'failed' double-fire of the single-use token"
    requirement: "CORR-06"
    verification:
      - kind: unit
        ref: "npx tsc -b --noEmit (compiles clean); npx eslint src/pages/auth/VerifyEmailPage.tsx (clean); grep confirms verifiedRef guard replaces the cancelled closure"
        status: pass
    human_judgment: true
    rationale: "No render harness (testing-library/jsdom) is installed in this project to simulate a StrictMode double-mount and assert the network call fires exactly once; verified by code inspection, tsc, and lint only, mirroring the proven useAuthInit.ts idiom this task copies verbatim"
  - id: D2
    description: "Dashboard's user-count query key is structurally distinct from UsersPage's [users, page, search] key and can never collide"
    requirement: "CORR-06"
    verification:
      - kind: unit
        ref: "frontend/src/pages/DashboardPage.test.ts#DASHBOARD_USER_COUNT_QUERY_KEY"
        status: pass
    human_judgment: false
  - id: D3
    description: "Org-settings SettingsTab seeds form state only on first load per mount, tracks dirtiness against a frozen snapshot, and does not overwrite in-progress edits on a later settings refetch"
    requirement: "CORR-06"
    verification:
      - kind: unit
        ref: "frontend/src/pages/organizations/OrganizationDetailPage.test.tsx#shouldSeedForm and #computeIsDirty"
        status: pass
    human_judgment: false
  - id: D4
    description: "Org-settings navigate-away guard: amber 'Unsaved changes' indicator, beforeunload prompt, and a ConfirmDialog-based guard for both in-app route navigation (useBlocker) and the Settings tab's own tab switch"
    requirement: "CORR-06"
    verification:
      - kind: unit
        ref: "npx tsc -b --noEmit (compiles clean, including useBlocker's BlockerFunction typing); npx eslint (clean); grep confirms initializedRef/isDirty/beforeunload"
        status: pass
    human_judgment: true
    rationale: "No render harness is installed to exercise the actual dialog open/confirm/cancel interaction or a live router blocker transition; verified by code inspection, tsc, and lint only. The pure decision logic feeding isDirty is separately unit-tested (D3)"

duration: 20min
completed: 2026-07-05
status: complete
---

# Phase 26 Plan 06: Frontend residual correctness fixes (VerifyEmail/Dashboard/Org-settings) Summary

**Three residual frontend correctness bugs closed: VerifyEmailPage's StrictMode double-fire (useRef guard), Dashboard's colliding user-count query key (distinct key), and org-settings silently discarding in-progress edits on refocus (init-guard + dirty-tracking + navigate-away guard).**

## Performance

- **Duration:** 20 min
- **Started:** 2026-07-05T09:31:44Z
- **Completed:** 2026-07-05T09:52:00Z
- **Tasks:** 3
- **Files modified:** 8 (5 modified, 3 created)

## Accomplishments
- `VerifyEmailPage.tsx`'s verify `useEffect` now uses a `verifiedRef = useRef(false)` guard set synchronously before the async verify call — mirrors `useAuthInit.ts`'s proven StrictMode de-dup idiom exactly, replacing the `cancelled` closure flag that let StrictMode's dev double-mount consume the single-use verification token twice and surface a false "failed" (D-17)
- Dashboard's user-count probe query key changed from `["users", 1, ""]` (byte-identical to UsersPage's page-1/no-filter key) to `DASHBOARD_USER_COUNT_QUERY_KEY` (`["users", "dashboard-count"]`), which can never structurally collide — a `DashboardPage.test.ts` regression test guards the shape against reintroducing the collision (D-18)
- `OrganizationDetailPage.tsx`'s `SettingsTab` now seeds `form` from `settings` only on the first successful load per mount (`initializedRef` guard) instead of unconditionally re-seeding on every `settings` change; a background refetch/refocus no longer silently discards in-progress edits (D-19)
- Added `isDirty` tracking computed against a frozen server snapshot, an amber "Unsaved changes" indicator next to Save, a `beforeunload` handler for browser refresh/close, and a `ConfirmDialog`-based navigate-away guard covering both actual route navigation (`useBlocker`) and the Settings tab's own in-page tab switch (lifted dirty flag + pending-tab intercept in the parent)
- Extracted the pure init-once/dirty decision logic (`shouldSeedForm`, `computeIsDirty`) into `settingsForm.ts` and unit-tested it directly, including the exact D-19 regression scenario (a post-seed settings change must not overwrite an edited field)

## Task Commits

Each task was committed atomically:

1. **Task 1: VerifyEmailPage StrictMode once-guard (D-17)** - `9e53213` (fix)
2. **Task 2: Dashboard distinct query key (D-18)** - `feee596` (fix)
3. **Task 3: Org-settings init-guard + dirty-tracking + navigate-away guard (D-19)** - `c287026` (fix)

**Plan metadata:** (this commit)

## Files Created/Modified
- `frontend/src/pages/auth/VerifyEmailPage.tsx` - `verifiedRef` useRef once-guard replaces the `cancelled` closure flag in the verify effect
- `frontend/src/pages/DashboardPage.tsx` - user-count query now imports and uses `DASHBOARD_USER_COUNT_QUERY_KEY`
- `frontend/src/pages/DashboardPage.test.ts` - regression test asserting the count-query key can never structurally equal any `[users, page, search]` tuple
- `frontend/src/lib/queryClient.ts` - exports `DASHBOARD_USER_COUNT_QUERY_KEY` (extracted here, not inline in the page, to satisfy the react-refresh ESLint rule)
- `frontend/src/pages/organizations/OrganizationDetailPage.tsx` - `SettingsTab` gains `initializedRef`, `isDirty`/`computeIsDirty`, `beforeunload` handler, `useBlocker`-based route guard, amber unsaved-changes indicator; parent `OrganizationDetailPage` lifts `isDirty` to guard its own in-page tab switch with a `ConfirmDialog`
- `frontend/src/pages/organizations/settingsForm.ts` - pure `shouldSeedForm`/`computeIsDirty` helpers extracted for unit-testability
- `frontend/src/pages/organizations/OrganizationDetailPage.test.tsx` - unit tests for the init-once decision and dirty computation, including the D-19 regression scenario
- `frontend/src/components/ConfirmDialog.tsx` - added optional `cancelLabel` prop (defaults to `"Cancel"`) so the org-settings guard can render "Keep editing"

## Decisions Made
- Extracted `DASHBOARD_USER_COUNT_QUERY_KEY` into `lib/queryClient.ts` rather than inline in `DashboardPage.tsx` — an inline exported array const trips `react-refresh/only-export-components` (array literals aren't in that rule's `allowConstantExport` set), and `queryClient.ts` is already this project's home for shared react-query infrastructure
- Extracted `shouldSeedForm`/`computeIsDirty` into a plain `.ts` module (`settingsForm.ts`, not `.tsx`) rather than exporting them from `OrganizationDetailPage.tsx` — exporting a lowercase-named function from a `.tsx` page file trips the same ESLint rule (functions are never in the "constant export" allowlist regardless of the name), and this project has no `testing-library`/`jsdom` installed to render the full component anyway
- Implemented the org-settings navigate-away guard with two independent mechanisms rather than one: `useBlocker` (react-router v7, works because this app already uses the data router via `createBrowserRouter`) for genuine route changes, and a lifted `isDirty` flag + `pendingTab` intercept in the parent for the Settings tab's own in-page tab bar switch — the UI-SPEC's contract explicitly covers both "a different tab" and "a sidebar link", and only the latter is an actual router navigation
- Added `ConfirmDialog`'s `cancelLabel` prop (optional, default `"Cancel"`) instead of building a new dialog primitive — satisfies the UI-SPEC's "Keep editing" copy while every other existing `ConfirmDialog` caller in the codebase is unaffected (they simply don't pass the new prop)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Extracted query-key/dirty-logic constants to non-page modules to satisfy the react-refresh ESLint rule**
- **Found during:** Task 2 and Task 3
- **Issue:** The plan's action text said to "extract the key to a named exported const" (Task 2) and "prefer extracting the pure init-once/dirty computation into a small testable function" (Task 3) directly implying export from the page file itself. Exporting a non-component array const or a lowercase-named function from a `.tsx` page file trips `react-refresh/only-export-components` (`npm run lint` failed with `error Fast refresh only works when a file only exports components`), since neither array literals nor function declarations are in that rule's `allowConstantExport` allowlist.
- **Fix:** Moved `DASHBOARD_USER_COUNT_QUERY_KEY` to the existing `frontend/src/lib/queryClient.ts` (already the shared react-query infrastructure home); moved `shouldSeedForm`/`computeIsDirty` to a new plain `frontend/src/pages/organizations/settingsForm.ts` (`.ts`, not `.tsx` — this ESLint rule only scans `.jsx`/`.tsx` files, so a `.ts` module is never subject to it). Both page files import from their respective extracted module; the vitest test files import directly from the extracted module.
- **Files modified:** `frontend/src/lib/queryClient.ts`, `frontend/src/pages/organizations/settingsForm.ts` (new)
- **Verification:** `npx tsc -b --noEmit` and `npm run lint` both exit 0 project-wide; `npm run test` passes all 17 tests across 3 files
- **Committed in:** `feee596` (Task 2), `c287026` (Task 3)

---

**Total deviations:** 1 auto-fixed (1 blocking — ESLint rule constraint required a module-extraction adjustment to the plan's literal wording, with no change to the functional behavior or test coverage intent)
**Impact on plan:** No scope creep — the extracted modules contain exactly the same logic the plan specified, relocated to satisfy a pre-existing project-wide lint gate. All three tasks' acceptance criteria are otherwise met exactly as written.

## Issues Encountered
None beyond the deviation above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All three CORR-06 defects (D-17/D-18/D-19) are closed with `npx tsc -b --noEmit`, `npm run lint`, and `npm run test` (17 tests, 3 files) all green in `frontend/`.
- The org-settings navigate-away guard's dialog-interaction paths (open/confirm/cancel, `useBlocker` transition) and VerifyEmailPage's actual double-mount de-dup are verified by code inspection + tsc/lint only — this project has no DOM-rendering test harness (`testing-library`/`jsdom` not installed) to drive a full component render or a live router transition. If a future phase adds that harness, these are natural candidates for upgrading to `automated_ui`/`integration` coverage.
- No blockers for Phase 26's remaining plans (26-07, 26-08).

---
*Phase: 26-correctness-resilience*
*Completed: 2026-07-05*

## Self-Check: PASSED
- FOUND: frontend/src/pages/auth/VerifyEmailPage.tsx
- FOUND: frontend/src/pages/DashboardPage.tsx
- FOUND: frontend/src/pages/DashboardPage.test.ts
- FOUND: frontend/src/lib/queryClient.ts
- FOUND: frontend/src/pages/organizations/OrganizationDetailPage.tsx
- FOUND: frontend/src/pages/organizations/settingsForm.ts
- FOUND: frontend/src/pages/organizations/OrganizationDetailPage.test.tsx
- FOUND: frontend/src/components/ConfirmDialog.tsx
- FOUND commit: 9e53213
- FOUND commit: feee596
- FOUND commit: c287026
