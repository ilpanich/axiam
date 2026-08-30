---
phase: 03-rbac-enforcement
plan: "02"
subsystem: axiam-api-rest
tags: [rbac, authorization, handlers, permissions, self-service, tenant-seeding]
dependency_graph:
  requires: ["03-01-SUMMARY.md"]
  provides: ["per-handler-authz", "tenant-permission-seeding"]
  affects: ["all REST handlers", "axiam-api-rest/src/handlers/"]
tech_stack:
  added: []
  patterns: ["RequirePermission::new(perm, Uuid::nil()).check(&user, authz).await?", "self-service ownership via is_own_resource", "audit self-service via actor_id filter"]
key_files:
  created: []
  modified:
    - crates/axiam-api-rest/src/handlers/groups.rs
    - crates/axiam-api-rest/src/handlers/roles.rs
    - crates/axiam-api-rest/src/handlers/permissions.rs
    - crates/axiam-api-rest/src/handlers/resources.rs
    - crates/axiam-api-rest/src/handlers/scopes.rs
    - crates/axiam-api-rest/src/handlers/certificates.rs
    - crates/axiam-api-rest/src/handlers/ca_certificates.rs
    - crates/axiam-api-rest/src/handlers/audit.rs
    - crates/axiam-api-rest/src/handlers/service_accounts.rs
    - crates/axiam-api-rest/src/handlers/pgp_keys.rs
    - crates/axiam-api-rest/src/handlers/webhooks.rs
    - crates/axiam-api-rest/src/handlers/oauth2_clients.rs
    - crates/axiam-api-rest/src/handlers/federation.rs
    - crates/axiam-api-rest/src/handlers/notification_rules.rs
    - crates/axiam-api-rest/src/handlers/settings.rs
    - crates/axiam-api-rest/src/handlers/tenants.rs
    - crates/axiam-api-rest/src/handlers/organizations.rs
    - crates/axiam-api-rest/src/handlers/users.rs (fmt only)
decisions:
  - "Audit list self-service: restrict to actor_id filter when caller lacks audit_logs:list; AuditLogFilter uses actor_id not user_id"
  - "OIDC callback, SAML ACS, SAML metadata left public (already in PUBLIC_PATHS, no authz added)"
  - "AxiamError::Internal is a tuple variant, not struct variant"
  - "ca_certificates and organizations handlers used _user pattern; changed to user with authz"
metrics:
  duration: "~45 minutes"
  completed_date: "2026-04-12"
  tasks_completed: 3
  files_changed: 18
---

# Phase 03 Plan 02: Wire RequirePermission to All Handlers Summary

Per-handler RBAC enforcement wired to all 17 non-public handler files using RequirePermission checks with Uuid::nil() resource scope. Self-service ownership checks applied to audit logs handler. New tenants get permissions auto-seeded via seed_permissions on creation.

## Tasks Completed

### Task 1 (prior run, commit c526d69)
- Added `is_own_resource` helper to `authz.rs`
- Wired authz to users.rs (self-service for get/update, full admin for list/create/delete/unlock)
- Wired authz to auth.rs and mfa_methods.rs

### Task 2a (commit 9ba1483)
Wired RequirePermission to core entity handlers:
- **groups.rs**: 8 handlers — list, get, create, update, delete, add_member, remove_member, list_members
- **roles.rs**: 9 handlers — list, get, create, update, delete, assign_to_user, unassign_from_user, assign_to_group, unassign_from_group
- **permissions.rs**: 8 handlers — list, get, create, update, delete, grant_to_role, revoke_from_role, list_role_permissions
- **resources.rs**: 7 handlers — list, get, create, update, delete, list_children, list_ancestors
- **scopes.rs**: 5 handlers — list, get, create, update, delete

### Task 2b (commit 69b1718)
Wired RequirePermission to specialized handlers:
- **certificates.rs**: 5 handlers (generate, list, get, revoke, bind)
- **ca_certificates.rs**: 4 handlers (generate, list, get, revoke) — changed `_user` to `user`
- **audit.rs**: `list` — self-service pattern: if caller lacks `audit_logs:list`, restrict results to `actor_id = caller.user_id`; `list_system` — requires `audit_logs:list_system`
- **service_accounts.rs**: 6 handlers (list, get, create, update, delete, rotate_secret)
- **pgp_keys.rs**: 6 handlers (list, get, generate, revoke, encrypt, sign_audit_batch)
- **webhooks.rs**: 5 handlers (list, get, create, update, delete)
- **oauth2_clients.rs**: 5 handlers (list, get, create, update, delete)
- **federation.rs**: 7 handlers (list, get, create, update, delete, list_user_links, delete_link); OIDC callback/SAML ACS/metadata NOT touched (in PUBLIC_PATHS)
- **notification_rules.rs**: 5 handlers (list, get, create, update, delete)
- **settings.rs**: 4 handlers (get_org_settings, set_org_settings, get_tenant_settings, set_tenant_settings)
- **tenants.rs**: 5 handlers (list, get, create, update, delete) + seed_permissions in create for auto-seeding new tenant permissions
- **organizations.rs**: 5 handlers (list, get, create, update, delete) — changed `_user` to `user`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] AuditLogFilter has no user_id field — used actor_id instead**
- **Found during:** Task 2b (audit.rs)
- **Issue:** Plan referenced `f.user_id` but `AuditLogFilter` only has `actor_id` (the actor who performed the action)
- **Fix:** Used `f.actor_id = Some(user.user_id)` for self-service audit filter
- **Files modified:** crates/axiam-api-rest/src/handlers/audit.rs

**2. [Rule 1 - Bug] AxiamError::Internal is a tuple variant, not struct variant**
- **Found during:** Task 2b (tenants.rs seed_permissions error handling)
- **Issue:** Plan showed `AxiamError::Internal { message: "..." }` but the actual enum is `Internal(String)`
- **Fix:** Used `AxiamError::Internal("...".into())` syntax
- **Files modified:** crates/axiam-api-rest/src/handlers/tenants.rs

## Known Stubs

None — all handlers are fully wired with real permission checks.

## Self-Check: PASSED

Files created/modified verified:
- All 17+ handler files confirmed modified with `RequirePermission` calls
- Commits 9ba1483 and 69b1718 confirmed via `git log`
- `cargo check -p axiam-api-rest` exits 0
- `cargo clippy -p axiam-api-rest -- -D warnings` exits 0
