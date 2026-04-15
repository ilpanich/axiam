---
type: audit
status: open
created: 2026-04-15
source: /gsd-progress follow-ups after phase 02 UAT
---

# Pagination contract audit — admin list endpoints

## Problem

Every backend list handler returns `PaginatedResult<T>`:

```rust
// crates/axiam-api-rest/src/handlers/*.rs
Ok(HttpResponse::Ok().json(result))   // result is PaginatedResult<T>
```

where `PaginatedResult` is defined as:

```rust
pub struct PaginatedResult<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub offset: u64,
    pub limit: u64,
}
```

Almost every frontend service expects a bare array:

```ts
// frontend/src/services/*.ts
api.get<X[]>("/api/v1/…").then((r) => r.data)
```

The mismatch means `r.data` is an *object*, not an array. TypeScript's lack of
runtime type checking plus tanstack-query's passthrough lets this render as
"no records" everywhere silently. This was only discovered during Phase 02
UAT because the users page was the one page that used a typed wrapper
(`PaginatedUsers`) — the other pages haven't been UAT'd.

## Backend list endpoints (16)

All return `PaginatedResult<T>` today:

| Endpoint | Handler returns | Repo method |
|---|---|---|
| GET /api/v1/organizations | `PaginatedResult<Organization>` | repo.list |
| GET /api/v1/organizations/{org_id}/tenants | `PaginatedResult<Tenant>` | repo.list_by_organization |
| GET /api/v1/organizations/{org_id}/ca-certificates | `PaginatedResult<CaCertificate>` | service.list |
| GET /api/v1/users | `PaginatedResult<User>` | repo.list |
| GET /api/v1/groups | `PaginatedResult<Group>` | repo.list |
| GET /api/v1/roles | `PaginatedResult<Role>` | repo.list |
| GET /api/v1/permissions | `PaginatedResult<Permission>` | repo.list |
| GET /api/v1/resources | `PaginatedResult<Resource>` | repo.list |
| GET /api/v1/resources/{id}/scopes | `Vec<Scope>` (bare) | repo.list_by_resource |
| GET /api/v1/certificates | `PaginatedResult<Certificate>` | service.list |
| GET /api/v1/service-accounts | `PaginatedResult<ServiceAccount>` | inlined |
| GET /api/v1/pgp-keys | `PaginatedResult<PgpKey>` | service.list |
| GET /api/v1/webhooks | `PaginatedResult<Webhook>` | inlined |
| GET /api/v1/oauth2-clients | `PaginatedResult<OAuth2Client>` | inlined |
| GET /api/v1/federation-configs | `PaginatedResult<FederationConfig>` | inlined |
| GET /api/v1/notification-rules | `PaginatedResult<NotificationRule>` | inlined |
| GET /api/v1/audit-logs | `PaginatedResult<AuditLog>` | repo.list |

Scopes is the one exception that returns a bare `Vec`.

## Frontend expectations (11 services)

| Service | Call | Expected shape |
|---|---|---|
| `services/users.ts` (users) | `api.get<PaginatedUsers>` | `{items, total, offset, limit}` — **aligned** (fixed in commit 8a8589a) |
| `services/users.ts` (groups) | `api.get<Group[]>` | bare array — drift |
| `services/audit.ts` | `api.get<PaginatedAuditLogs>` | `{data, total, page, per_page}` — drift (field-name drift) |
| `services/organizations.ts` (orgs) | `api.get<Organization[]>` | bare array — drift |
| `services/organizations.ts` (tenants) | `api.get<Tenant[]>` | bare array — drift |
| `services/organizations.ts` (CA certs) | `api.get<CaCertificate[]>` | bare array — drift |
| `services/roles.ts` (roles) | `api.get<Role[]>` | bare array — drift |
| `services/roles.ts` (role perms) | `api.get<Permission[]>` | bare array — ambiguous (this is a nested sub-resource) |
| `services/permissions.ts` | `api.get<Permission[]>` | bare array — drift |
| `services/resources.ts` | `api.get<Resource[]>` | bare array — drift |
| `services/certificates.ts` | `api.get<Certificate[]>` | bare array — drift |
| `services/serviceAccounts.ts` | `api.get<ServiceAccount[]>` | bare array — drift |
| `services/pgp.ts` | `api.get<PgpKey[]>` | bare array — drift |
| `services/webhooks.ts` | `api.get<Webhook[]>` | bare array — drift |
| `services/oauth2Clients.ts` | `api.get<OAuth2Client[]>` | bare array — drift |
| `services/federation.ts` | `api.get<FederationProvider[]>` | bare array — drift |
| `services/notificationRules.ts` | `api.get<NotificationRule[]>` | bare array — drift |

## Options

### Option A — align frontend to backend (recommended)

Change each service's `api.get<X[]>` to `api.get<PaginatedResult<X>>` and
propagate through consumer pages. Standardise on `{items, total, offset, limit}`
as the canonical shape.

**Pros:**
- Single-point fix in each service function + a typed wrapper type shared
  across all services (`PaginatedResult<T>`).
- Uses the shape already present in axiam-core; no backend change.
- Enables proper pagination UI across all admin pages.

**Cons:**
- Every consumer page needs destructuring updates (likely `data?.items ?? []`).
- Need to preserve existing page / per_page URL params expected by each page
  OR switch to offset/limit.

**Estimated effort:** 1–2 days of focused work to cover 16 services + maybe
20 consumer pages with spot-check UAT per page.

### Option B — align backend to frontend

Change backend handlers to return bare `Vec<T>` for list endpoints, losing
pagination metadata on the wire. Move total/offset/limit into response
headers (`X-Total-Count`, `X-Pagination-Offset`, etc.).

**Pros:**
- Minimal frontend change (keep `api.get<X[]>`).
- Headers are a REST-idiomatic pagination carrier.

**Cons:**
- Throws away strong typing for pagination metadata.
- Breaks every existing Rust integration test that asserts on the
  `PaginatedResult` JSON body (20+ tests).
- Tests and OpenAPI schemas need regeneration.

**Estimated effort:** 3–5 days + test migration.

### Option C — dual-shape with a compatibility helper (hybrid)

Add a `unwrapList<T>(response: PaginatedResult<T> | T[]): T[]` helper and
route every service through it. Backend stays on `PaginatedResult`; consumer
pages that just need the items get them. Pagination metadata becomes
opt-in per page.

**Pros:**
- Smallest blast radius; pages render correctly without destructuring work.
- Can migrate page-by-page to a fully typed flow as needs arise.

**Cons:**
- Introduces a compatibility helper that lives forever.
- Loses pagination UI on pages that don't opt in.

**Estimated effort:** half a day for the helper + services; per-page updates
only when pagination is needed.

## Recommendation

**Option A** with phased delivery:

1. Define `PaginatedResult<T>` once in `frontend/src/types/pagination.ts`
   or similar.
2. For each service, change the return type and consumer destructuring in
   one atomic commit + in-browser spot-check.
3. Order by UAT criticality — start with what's visible in admin flows:
   roles → permissions → groups → resources → orgs/tenants, then the less
   frequently touched endpoints.
4. For `services/audit.ts`, also fix the field-name drift
   (`data/page/per_page` → `items/offset/limit`) — currently it has both
   layers of drift.

## Non-drift cases

- **Scopes** backend returns a bare `Vec<Scope>`. Either promote it to
  `PaginatedResult` for consistency, or keep bare and explicitly type the
  frontend `api.get<Scope[]>`.
- **Users MFA methods, role permissions** are nested sub-resources that
  return bare arrays. Those are legitimately non-paginated — leave as-is
  but mark each clearly.

## Preconditions for fixing this

- Surrealdb persistence landed (commit 7758f1a) — browser UAT needs to
  survive stack reboots to be useful across the audit.
- Test fixtures register `AuthzData` (commit 74a1d7b) — a follow-up test
  sweep will catch regressions introduced by the frontend changes.
