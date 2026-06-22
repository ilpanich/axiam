---
slug: frontend-contract-fixes
status: complete
completed: 2026-06-21
---

# Summary — Frontend ↔ Backend contract remediation (UAT)

Section-by-section Playwright review of the admin UI. Root cause of the
UAT issues: the frontend service layer was written against a drifted/fictional
contract. Serde silently drops unknown fields → `200 OK` saves that persist
nothing; wrong enum casing / missing required fields → 400s.

## Commits (all signed)

1. `fix(api): expose email_verified on UserResponse; persist metadata on org update`
2. `fix(frontend): align users/groups/service-accounts to backend contract`
3. `fix(frontend): rewrite certificate, CA, and PGP forms to backend contract`
4. `fix(frontend): align settings, profile, and audit-log filters to backend`
5. `fix(rbac): back-fill default-role grants for registry permissions on startup`
6. `fix(frontend): align webhooks/oauth2/permissions/resources/roles/tenants/orgs`
7. `feat(api): add GET endpoints to list a role's assigned users and groups`
8. `fix(api): register users::unlock in OpenAPI spec`

## Verified live via Playwright (login admin@axiam.dev)

- Users: status toggle persists (was no-op); display_name via metadata; email_verified.
- Settings: reads real nested SecuritySettings; save persists (min length 12→14).
- Profile: display_name persists; email_verified.
- Audit: date filter sends RFC3339 (200, was 400).
- Certificates: CA generate (201) → cert generate (201) end-to-end + private key reveal. **(reported 400 fixed)**
- Webhooks: create 201 (events/enabled rename).
- OAuth2: create 201 (was 403 — RBAC back-fill fix).
- Permissions: render off action (name/resource_id removed).
- Resources: description via metadata persists.
- Roles: permissions render (PermissionGrant[]); members panel 200 (was 405).

## Beyond contract drift (discovered during review)

- **RBAC seeding bug**: permissions added to the registry after the initial
  `/bootstrap` were granted to no role (bootstrap self-disables) → 403 on
  e.g. `oauth2_clients:create`. Fixed with a startup reconciliation.
- **Role members 405**: no GET to list a role's users/groups; added endpoints.
- **OpenAPI parity**: `users::unlock` was unregistered (latent test failure).

## Decisions applied

- Frontend aligns to backend (source of truth).
- Soft text fields (`display_name`, org/tenant/resource `description`) routed
  through the existing `metadata` JSON.
- Pure-invention fields dropped from UI: permission name/resource_id, webhook
  description, oauth2 is_public, service-account roles/description.

## Follow-ups

- ~~CA-cert generation private key not surfaced~~ — DONE (commit 17a1c0d):
  reveals `private_key_pem` in `SecretRevealModal`, verified live.
- PGP section aligned to contract but not exercised live this pass.
