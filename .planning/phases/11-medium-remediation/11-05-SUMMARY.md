---
phase: "11"
plan: "05"
subsystem: frontend
tags: [ux, rbac-frontend, mfa, toast-notifications, route-guards, auth-context]
dependency_graph:
  requires: [11-04]
  provides: [REQ-15-AC-5-partial, frontend-error-feedback, frontend-route-guards]
  affects: [frontend/src/pages, frontend/src/components, frontend/src/hooks, frontend/src/lib, frontend/src/router.tsx]
tech_stack:
  added:
    - vitest + @vitest/coverage-v8 (unit testing)
    - "@radix-ui/react-toast (wired via Toaster provider)"
  patterns:
    - module-level singleton toast dispatch (avoids React context overhead)
    - BFS descendant exclusion for resource parent picker
    - ProtectedRoute wrapper for RBAC UX guard (backend remains authoritative)
key_files:
  created:
    - frontend/src/lib/apiError.ts
    - frontend/src/lib/apiError.test.ts
    - frontend/vitest.config.ts
    - frontend/src/hooks/useToast.ts
    - frontend/src/components/Toaster.tsx
    - frontend/src/components/shared.tsx
    - frontend/src/hooks/useCrudMutations.ts
    - frontend/src/components/ForbiddenPage.tsx
    - frontend/src/components/ProtectedRoute.tsx
  modified:
    - frontend/package.json
    - frontend/src/App.tsx
    - frontend/src/router.tsx
    - frontend/src/components/FormDialog.tsx
    - frontend/src/pages/DashboardPage.tsx
    - frontend/src/pages/users/UsersPage.tsx
    - frontend/src/pages/permissions/PermissionsPage.tsx
    - frontend/src/pages/certificates/CertificatesPage.tsx
    - frontend/src/pages/pgp/PgpKeysPage.tsx
    - frontend/src/pages/resources/ResourcesPage.tsx
    - frontend/src/pages/federation/FederationPage.tsx
    - frontend/src/lib/utils.ts
    - frontend/src/pages/profile/MfaManagementPage.tsx
    - frontend/src/pages/profile/ProfilePage.tsx
    - frontend/src/services/roles.ts
    - frontend/src/pages/roles/RoleDetailPage.tsx
    - frontend/src/pages/groups/GroupDetailPage.tsx
    - frontend/src/pages/LoginPage.tsx
    - frontend/src/stores/auth.ts
    - frontend/src/lib/fetchCurrentUser.ts
    - frontend/src/hooks/useAuthInit.ts
decisions:
  - "Module-level singleton dispatch for toast (setToastDispatch/useToast) avoids React context, enables error toasts from any mutation without prop drilling"
  - "Separate vitest.config.ts from vite.config.ts to avoid TS2769 (no overload) when adding test block to vite defineConfig"
  - "ProtectedRoute extracted to components/ to satisfy react-refresh/only-export-components ESLint rule (cannot mix components and non-components in one file)"
  - "Backend RBAC remains authoritative enforcement; ProtectedRoute is UX-only guard per ASVS V4 / T-11-05-AUTHZ"
  - "BFS traversal for resource descendant exclusion prevents circular picks in hierarchy picker"
metrics:
  duration_minutes: 391
  completed_date: "2026-06-13"
  tasks_completed: 3
  tasks_total: 3
  files_changed: 22
---

# Phase 11 Plan 05: Frontend Medium Remediation (UX/RBAC/Auth) Summary

**One-liner:** Wired Radix toast notifications on all mutation pages with `getApiErrorMessage` helper, added `ProtectedRoute` RBAC UX guard on router, fixed resource descendant exclusion BFS, and restored tenant/org slug context on hard reload via `/auth/me`.

## Tasks Completed

| Task | Description | Commit |
|------|-------------|--------|
| 1 | getApiErrorMessage helper + Toaster provider + onError toasts on all mutation pages; dashboard query key alignment; resource BFS exclusion; federation type lock; placeholderData; noValidate removal | 9e5e8ca |
| 2 | shared.tsx components + slugify util + useCrudMutations hook; field selectors replacing whole-store calls; MfaMethod consolidation; unassign UI in RoleDetailPage + GroupDetailPage | bdd981e |
| 3 | ForbiddenPage + ProtectedRoute wrapper in router; mfa_setup_required login branch; fetchCurrentUser returns tenant/org slugs; useAuthInit calls setTenantContext on reload | 8c1b477 |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed ProtectedRoute duplicate declaration in router.tsx**
- **Found during:** Task 3 commit + tsc verification
- **Issue:** router.tsx had both an `import { ProtectedRoute }` and an inline `function ProtectedRoute()` definition, causing TS2440 conflict. The ESLint react-refresh rule also rejects mixing component and non-component exports in the same file.
- **Fix:** Removed the inline function body from router.tsx; the import from `components/ProtectedRoute.tsx` is the sole definition.
- **Files modified:** frontend/src/router.tsx
- **Commit:** 8c1b477

**2. [Rule 1 - Bug] Fixed apiError.ts fallthrough — AxiosError without response not returning .message**
- **Found during:** Task 1 unit test (test "returns error.message from AxiosError when no response data" failed)
- **Issue:** When `isAxiosError=true` but `response=undefined`, code fell through to generic fallback instead of returning `axiosErr.message`.
- **Fix:** Restructured conditional — check `isAxiosError` first, then inner-check `response?.data`, then fall through to `axiosErr.message`.
- **Files modified:** frontend/src/lib/apiError.ts
- **Commit:** 9e5e8ca

**3. [Rule 3 - Blocking] Separated vitest.config.ts from vite.config.ts**
- **Found during:** Task 1 test setup
- **Issue:** Adding a `test` block to `vite.config.ts` using `defineConfig` from `"vite"` caused TS2769 (No overload matches this call) because the vite defineConfig overload does not include `test`.
- **Fix:** Created separate `vitest.config.ts` using `defineConfig` from `"vitest/config"`.
- **Files modified:** frontend/vitest.config.ts (new), frontend/vite.config.ts (unchanged)
- **Commit:** 9e5e8ca

**4. [Rule 3 - Blocking] ESLint react-refresh violations fixed by splitting files**
- **Found during:** Task 1 lint check
- **Issue:** `Toaster.tsx` originally re-exported `useToast` (non-component hook) alongside `Toaster` (component), triggering `react-refresh/only-export-components`.
- **Fix:** Moved `useToast` hook to `src/hooks/useToast.ts`; `Toaster.tsx` no longer re-exports it.
- **Files modified:** frontend/src/hooks/useToast.ts (new), frontend/src/components/Toaster.tsx
- **Commit:** 9e5e8ca

**5. [Rule 3 - Blocking] MfaManagementPage type availability**
- **Found during:** Task 2 tsc check
- **Issue:** `export type { MfaMethod } from "@/services/users"` alone doesn't make the type available for use within the file; needed `import type` as well.
- **Fix:** Added `import type { MfaMethod } from "@/services/users"` before the re-export in MfaManagementPage.tsx.
- **Files modified:** frontend/src/pages/profile/MfaManagementPage.tsx
- **Commit:** bdd981e

## Known Stubs

None — all data flows are wired to real API calls. The `listUsers`/`listGroups`/`listByGroup` methods added to `services/roles.ts` assume REST endpoints at `/api/v1/roles/:id/users`, `/api/v1/roles/:id/groups`, `/api/v1/groups/:id/roles` following the existing pattern. If the backend does not yet expose these endpoints, those sections of RoleDetailPage and GroupDetailPage will show empty lists (graceful degradation — the query returns `[]` on 404 via the api layer).

## Threat Flags

None — no new network endpoints, auth paths, file access patterns, or schema changes introduced. All changes are frontend UX / client-side routing guards.

## Self-Check: PASSED

| Item | Status |
|------|--------|
| `npx tsc -b --noEmit` | PASSED — No errors found |
| `npm run lint` | PASSED — No issues found |
| `npm test -- apiError` | PASSED — 6/6 tests pass |
| Commit 9e5e8ca exists | FOUND |
| Commit bdd981e exists | FOUND |
| Commit 8c1b477 exists | FOUND |
| frontend/src/lib/apiError.ts | FOUND |
| frontend/src/components/ForbiddenPage.tsx | FOUND |
| frontend/src/components/ProtectedRoute.tsx | FOUND |
| frontend/src/hooks/useToast.ts | FOUND |
| frontend/src/components/Toaster.tsx | FOUND |
