---
phase: 14-frontend-list-contract
plan: "01"
subsystem: frontend/services
tags: [frontend, typescript, pagination, contract-alignment]
dependency_graph:
  requires: []
  provides: [REQ-18, unwrapList-helper]
  affects: [CertificatesPage, RolesPage, GroupsPage, ResourcesPage, PermissionsPage, WebhooksPage, PgpKeysPage, OAuth2ClientsPage, ServiceAccountsPage, NotificationRulesPage, OrganizationDetailPage, DashboardPage]
tech_stack:
  added: [frontend/src/services/_pagination.ts]
  patterns: [defensive-unwrap, paginated-result-contract]
key_files:
  created:
    - frontend/src/services/_pagination.ts
  modified:
    - frontend/src/services/certificates.ts
    - frontend/src/services/roles.ts
    - frontend/src/services/users.ts
    - frontend/src/services/organizations.ts
    - frontend/src/services/resources.ts
    - frontend/src/services/permissions.ts
    - frontend/src/services/webhooks.ts
    - frontend/src/services/pgp.ts
    - frontend/src/services/oauth2clients.ts
    - frontend/src/services/serviceAccounts.ts
    - frontend/src/services/notificationRules.ts
    - frontend/src/services/federation.ts
decisions:
  - "unwrapList applied uniformly to all T[] list methods — safe on bare-array endpoints too"
  - "userService.list and auditService.list intentionally excluded (return PaginatedXxx, consumers use .items/.total)"
  - "Inline .items ?? [] patterns in certificates/roles/groupService refactored to the shared helper"
metrics:
  duration: "~8 minutes"
  completed: "2026-06-19"
  tasks_completed: 2
  files_changed: 13
---

# Phase 14 Plan 01: Frontend List Contract Alignment Summary

Defensive `unwrapList<T>` helper added to align all frontend list services to the backend
`PaginatedResult<T>` = `{ items, total, offset, limit }` contract without breaking
bare-array endpoints.

## Tasks Completed

### Task 1: Add shared unwrapList helper + apply across all list services

Created `frontend/src/services/_pagination.ts`:

```ts
export function unwrapList<T>(data: T[] | { items?: T[] } | null | undefined): T[] {
  if (Array.isArray(data)) return data;
  return data?.items ?? [];
}
```

Applied to every service method returning `Promise<T[]>`:

| Service | Methods changed |
|---------|-----------------|
| certificates | `list` (refactored inline fix) |
| roles | `list`, `listPermissions`, `listUsers`, `listGroups`, `listByGroup` |
| users (groupService) | `list`, `listMembers` |
| users (userService) | `listMfaMethods` |
| organizations | `orgService.list`, `tenantService.list`, `caCertService.list` |
| resources | `list`, `listChildren` |
| permissions | `list` |
| webhooks | `list` |
| pgp | `list` |
| oauth2clients | `list` |
| serviceAccounts | `getAll` |
| notificationRules | `list` |
| federation | `getAll` |

Intentionally excluded:
- `userService.list` — returns `PaginatedUsers`, consumed via `.items`/`.total` in UsersPage
- `auditService.list` — returns `PaginatedAuditLogs`, consumed via `.data` in audit pages

### Task 2: Spot-verify consuming pages expect arrays

Grep result: `grep -rnE "\.data\.items|\?\.items" src/pages | grep -viE "UsersPage|audit"` — empty output. No consuming page (except UsersPage/audit) relies on the wrapper shape. No reconciliation needed.

## Verification

```
npm run lint  → ESLint: No issues found
npx tsc -b   → TypeScript: No errors found
```

## Deviations from Plan

None — plan executed exactly as written.

## Threat Flags

None — no new network endpoints, auth paths, or schema changes introduced.

## Self-Check: PASSED

- `frontend/src/services/_pagination.ts` — FOUND
- `Array.isArray` in _pagination.ts — PRESENT
- All 13 service files modified and staged
- Commit 36bc6ea — FOUND
- `userService.list` / `auditService.list` untouched — VERIFIED
- `npm run lint` clean — VERIFIED
- `npx tsc -b` no errors — VERIFIED
