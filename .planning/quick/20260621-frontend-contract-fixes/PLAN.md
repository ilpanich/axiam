---
slug: frontend-contract-fixes
created: 2026-06-21
status: in-progress
---

# Frontend ↔ Backend contract fixes (UAT remediation)

## Problem

UAT surfaced widespread frontend bugs: form values not persisting (e.g. user "active"
flag), certificate generation 400, etc. Parallel static audit confirmed the **frontend
service layer was written against a drifted/fictional contract**. Serde silently drops
unknown fields → `200 OK` saves that persist nothing. Wrong enum casing / missing required
fields → 400s.

## Root-cause patterns

- **A. Enum casing**: backend enums serialize PascalCase (`UserStatus` Active/Inactive,
  `KeyAlgorithm` Rsa4096/Ed25519, `CertificateStatus` Active/Revoked/Expired,
  federation `OidcConnect`/`Saml`). Frontend sends/compares lowercase. → fix frontend.
- **B. Field-name drift**: `is_active`↔`status`, `event_types`↔`events`, `is_active`↔`enabled`,
  `org_id`↔`organization_id`, `common_name`↔`subject`, `key_type`↔`key_algorithm`,
  `public_key_armor`↔`public_key_armored`, `data`↔`data_base64`, `encrypted`↔`ciphertext_armored`,
  `expires_at`↔`not_after`, etc.
- **C. Pure-invention fields** (no backend home): permission `name`/`resource_id`,
  webhook `description`, oauth2 `is_public`, service-account `roles`/`description`.
- **D. Shape mismatch**: SA create response flat (not nested), role permissions return
  `PermissionGrant[]` not `Permission[]`, settings nested-read vs flat-write, missing
  required cert fields (`issuer_ca_id`, `cert_type`).

## Decisions

- **Align frontend to backend** (Rust domain layer is source of truth) — default.
- **Route soft text via `metadata`**: user `display_name`, org/tenant/resource `description`.
- **Drop pure-invention fields** from UI: permission `name`/`resource_id`, webhook
  `description`, oauth2 `is_public`, SA `roles`/`description`.
- **Minimal backend changes** (data already exists / metadata plumbing only):
  1. `UserResponse`: add `email_verified: bool` (= `email_verified_at.is_some()`).
  2. `UpdateOrganizationRequest` + handler: accept & persist `metadata`.
  3. `UpdateTenantRequest` + handler: accept & persist `metadata`.

## Section checklist

- [ ] users (status mapping, email_verified, display_name via metadata)
- [ ] groups (create description required → send "")
- [ ] service-accounts (flat create resp, status casing, guard roles, drop roles/desc)
- [ ] roles (PermissionGrant[] shape, create description "")
- [ ] permissions (drop name/resource_id, key off action)
- [ ] resources (description via metadata, parent null-clear)
- [ ] certificates (rewrite: subject/key_algorithm/cert_type/issuer_ca_id + CA selector; list fields) ← user-reported 400
- [ ] pgp (rewrite generate/list/encrypt/sign field names + enum)
- [ ] webhooks (events, enabled rename; drop description)
- [ ] oauth2 (drop is_public)
- [ ] organizations (description via metadata; backend metadata persist)
- [ ] tenants (organization_id rename; description via metadata; backend metadata persist)
- [ ] settings (rewrite: nested read, flat override write, minutes↔seconds) — system + org tab
- [ ] profile (display_name via metadata, email_verified)
- [ ] audit (date → RFC3339)
- [ ] federation, notification-rules, dashboard — verified clean by audit
