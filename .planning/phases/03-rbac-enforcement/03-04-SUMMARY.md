---
phase: 03-rbac-enforcement
plan: 04
subsystem: axiam-api-rest, frontend
tags: [rbac, frontend, permissions, sidebar, auth-me]
dependency_graph:
  requires: [03-02]
  provides: [me-returns-permissions, usePermissions-hook, sidebar-gating]
  affects: [03-05]
tech_stack:
  added: []
  patterns: [effective-permissions-union, wildcard-superadmin, visible-but-disabled-nav]
key_files:
  created:
    - frontend/src/hooks/usePermissions.ts
    - frontend/src/lib/fetchCurrentUser.ts
  modified:
    - crates/axiam-api-rest/src/handlers/auth.rs
    - crates/axiam-api-rest/tests/auth_test.rs
    - frontend/src/stores/auth.ts
    - frontend/src/hooks/useAuthInit.ts
    - frontend/src/pages/LoginPage.tsx
    - frontend/src/components/layout/Sidebar.tsx
decisions:
  - "/auth/me computes effective permissions as the union of action strings across all roles assigned directly or via groups (RoleRepository::get_user_roles already handles both sources)"
  - "super-admin role holders get a leading '*' entry in the permissions array so the client can short-circuit fine-grained can() checks"
  - "BTreeSet deduplicates and sorts permissions deterministically — stable response bodies aid caching and test assertions"
  - "Login response does not carry permissions; LoginPage now calls /auth/me after successful login to hydrate the store, with graceful fallback to empty permission set if /me fails"
  - "Shared fetchCurrentUser() helper in lib/ consolidates /me → AuthUser mapping for useAuthInit and LoginPage — single source of truth"
  - "Sidebar items without a required permission (Dashboard, Audit Logs, Profile) are self-service surfaces — always visible"
  - "Disabled nav items are rendered visible-but-disabled (opacity-40, pointer-events-none, aria-disabled, tabIndex=-1) per UI-SPEC — not hidden — so users understand what the system offers"
  - "Defensive onClick preventDefault covers keyboard activation edge cases that pointer-events-none does not block"
  - "Active-path ChevronRight indicator is suppressed on disabled items to avoid visually claiming 'here' on an unclickable target"
metrics:
  duration: ~20m (resumed after rate-limit interruption)
  completed_date: "2026-04-12"
  tasks_completed: 2
  files_changed: 8
---

# Phase 03 Plan 04: Frontend Permission Gating Summary

Extended `/auth/me` with an effective permissions array and wired RBAC-gated sidebar navigation. Users now see which sections they have access to — items they cannot use remain visible but are visually disabled (opacity-40 + aria-disabled) rather than hidden, preserving discoverability of the system's surface area.

## Tasks Completed

| # | Task | Commit | Files |
|---|------|--------|-------|
| 1 | Extend /auth/me to return permissions and update auth store | `e562667` | 6 |
| 2 | Create usePermissions hook and wire sidebar gating | `a11f146` | 2 |

## Artifact Matrix

| Artifact | Path | Provides |
|---|---|---|
| /auth/me permissions | `crates/axiam-api-rest/src/handlers/auth.rs` | effective-permission-array on me response |
| usePermissions hook | `frontend/src/hooks/usePermissions.ts` | `can(permission)` predicate with wildcard support |
| Auth store permissions | `frontend/src/stores/auth.ts` | `AuthUser.permissions: string[]` |
| fetchCurrentUser helper | `frontend/src/lib/fetchCurrentUser.ts` | shared /me → AuthUser mapping |
| Sidebar gating | `frontend/src/components/layout/Sidebar.tsx` | visible-but-disabled nav items keyed by requiredPermission |

## Verification

- `cargo check -p axiam-api-rest` — exit 0
- `cargo clippy -p axiam-api-rest --tests -- -D warnings` — exit 0
- `cargo fmt -p axiam-api-rest` — applied
- `tsc --noEmit` frontend — exit 0
- auth_test.rs macro registers `SurrealRoleRepository` + `SurrealPermissionRepository` so existing /me tests continue to work

## Deferred

- Runtime UAT: verifying the sidebar gating in a browser with a real backend is **deferred to 03-05** (where integration tests and bootstrap UI are also built). Full phase sign-off requires `just dev-up && cargo test -p axiam-api-rest` per the 03-05 `<done>` clause.
