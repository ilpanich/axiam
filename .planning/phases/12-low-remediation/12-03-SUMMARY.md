---
phase: 12-low-remediation
plan: "03"
subsystem: frontend
tags: [cleanup, dead-code, security, i18n, react, typescript]
dependency_graph:
  requires: []
  provides: [CQ-F20, CQ-F21, CQ-F22, CQ-F23, CQ-F24, CQ-F25, CQ-F26, CQ-F32, CQ-F33, CQ-F34, CQ-F35]
  affects: [frontend/src/lib/api.ts, frontend/src/hooks/usePermissions.ts, frontend/src/hooks/useAuthInit.ts, frontend/src/pages/tenants/TenantsPage.tsx, frontend/src/pages/users/UsersPage.tsx, frontend/src/pages/BootstrapPage.tsx, frontend/src/components/DataTable.tsx, frontend/src/lib/utils.ts, frontend/src/components/ResourceTree.tsx]
tech_stack:
  added: []
  patterns: [PasswordPolicyChecker integration, module-level stable constant, useRef once-guard, CSS.escape, Intl.DateTimeFormat undefined locale]
key_files:
  created: []
  modified:
    - frontend/package.json
    - frontend/src/components/DataTable.tsx
    - frontend/src/lib/utils.ts
    - frontend/src/components/ResourceTree.tsx
    - frontend/src/pages/users/UsersPage.tsx
    - frontend/src/pages/BootstrapPage.tsx
    - frontend/src/lib/api.ts
    - frontend/src/hooks/usePermissions.ts
    - frontend/src/hooks/useAuthInit.ts
    - frontend/src/pages/tenants/TenantsPage.tsx
  deleted:
    - frontend/src/pages/placeholders/Placeholder.tsx
decisions:
  - CQ-F34 bootstrap 404 kept as-is — backend returns HTTP 404 (not 409) when already initialized per bootstrap.rs NotFound branch (D-09, confirmed by bootstrap_test.rs:328); no 409 branch invented
  - CQ-F22 four radix deps confirmed zero import sites via grep before removal (dialog, dropdown-menu, select, separator)
metrics:
  duration: "18m"
  completed: "2026-06-19"
  tasks: 3
  files: 10
---

# Phase 12 Plan 03: Frontend Trivial Cleanup Summary

Frontend cleanup wave closing 11 LOW/TRIVIAL findings: dead file and unused deps removed, three small correctness fixes (DataTable key, i18n locale, CSS.escape), password policy enforcement on admin-create and bootstrap forms, eight targeted source hardening edits across api.ts/usePermissions/useAuthInit/TenantsPage — all green under `npm run lint && npx tsc -b`.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Dead-code + dep pruning + i18n + DataTable key + CSS.escape | f07b2df | Placeholder.tsx (deleted), package.json, DataTable.tsx, utils.ts, ResourceTree.tsx |
| 2 | PasswordPolicyChecker on admin-create + bootstrap (keep 404 mapping) | 5d171ee | UsersPage.tsx, BootstrapPage.tsx |
| 3 | Refresh _retry ordering, stable empty permissions, StrictMode init, TenantsPage flash | e2db6d6 | api.ts, usePermissions.ts, useAuthInit.ts, TenantsPage.tsx |

## Findings Closed

| Finding | Fix | File |
|---------|-----|------|
| CQ-F21 | Deleted Placeholder.tsx (3.5K, zero import sites) and placeholders/ dir | frontend/src/pages/placeholders/Placeholder.tsx |
| CQ-F22 | Removed @radix-ui/react-{dialog,dropdown-menu,select,separator} from package.json after confirming zero imports across frontend/src/ | frontend/package.json |
| CQ-F23 | PasswordPolicyChecker import + render + checkPasswordPolicy submit gate on both admin-create form and bootstrap inaugural password | UsersPage.tsx, BootstrapPage.tsx |
| CQ-F24 | DataTable row key uses String(id ?? rowIdx) instead of double-cast `as string ?? rowIdx` | DataTable.tsx:79 |
| CQ-F25 | Both Intl.DateTimeFormat("en-US", ...) calls replaced with undefined (browser locale) | utils.ts:40,49 |
| CQ-F26 | querySelector wraps id in CSS.escape() | ResourceTree.tsx:81 |
| CQ-F32 | _retry = true moved to FIRST line inside outer 401 guard, before isRefreshing queue check and refresh call | api.ts:98 |
| CQ-F33 | Module-level EMPTY_PERMISSIONS constant replaces inline ?? [] in usePermissions | usePermissions.ts |
| CQ-F34 | KEPT status === 404 → setAlreadyInitialized(true) — backend returns 404 by design (D-09); no 409 branch; non-404/403 errors go to formError | BootstrapPage.tsx |
| CQ-F35 | useRef(false) once-guard prevents double boot fetch under React 18 StrictMode; setInitializing removed from useEffect dep array | useAuthInit.ts |
| CQ-F20 | isLoadingOrgs \|\| isLoadingTenants composite guard prevents "No tenants found" flash while orgs still loading | TenantsPage.tsx |

## Deviations from Plan

None — plan executed exactly as written.

Key note: CQ-F34 — RESEARCH.md section incorrectly suggested switching to 409. The plan's `<objective>` and `RESOLVED FACT` comment explicitly overruled this. Backend inspection confirmed `bootstrap.rs` returns `AxiamError::NotFound` (HTTP 404) for already-initialized state, not 409. The 404 → alreadyInitialized mapping was kept unchanged.

## Known Stubs

None. All changes are correctness/hardening fixes; no placeholder data was introduced.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced. All changes are purely frontend correctness and security hardening within existing code paths.

T-12-09 (weak inaugural passwords) — mitigated: PasswordPolicyChecker gates both admin-create and bootstrap submit buttons.
T-12-10 (infinite refresh loop) — mitigated: _retry set before isRefreshing check.
T-12-11 (supply-chain surface) — mitigated: 4 unused radix packages removed from bundle.

## Self-Check: PASSED

- f07b2df: chore(12-03): dead-code removal + dep pruning + i18n + DataTable key + CSS.escape
- 5d171ee: feat(12-03): PasswordPolicyChecker on admin-create + bootstrap (CQ-F23); keep 404 mapping (CQ-F34)
- e2db6d6: fix(12-03): refresh _retry guard ordering, stable empty permissions, StrictMode init, TenantsPage flash
- `npm run lint` — ESLint: No issues found
- `npx tsc -b` — TypeScript: No errors found
