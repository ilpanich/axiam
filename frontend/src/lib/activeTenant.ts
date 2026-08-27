/**
 * The tenant an organization-level principal is currently acting on.
 *
 * Module state rather than React state, because the axios request interceptor
 * that sends it runs outside React and cannot read a store.
 *
 * # Why this is not inside `lib/api`
 *
 * It was, and that made `@/lib/api` a module with a default export *and* named
 * ones. Fifty-four test files mock it as `{ default: apiMock }`, so every one
 * of them broke the moment anything imported a named export — with
 * `No "setActiveTenant" export is defined on the "@/lib/api" mock`, which
 * points at the mock rather than at the design decision that invalidated it.
 *
 * Separating them is also the more honest arrangement: which tenant is being
 * acted on is not a fact about the HTTP client. `lib/api` reads it; the auth
 * store writes it; neither has to know about the other.
 *
 * `null` means "act on my own tenant" — every ordinary principal, and an
 * organization-level one that has not switched. The header is then omitted
 * rather than sent with the caller's own tenant id: the server treats a header
 * naming the principal's own tenant as a no-op anyway, and omitting it keeps
 * ordinary requests byte-identical to what they were.
 */
let activeTenantId: string | null = null;

/** Header the server reads to decide which tenant a request acts on. */
export const ACTIVE_TENANT_HEADER = "X-Axiam-Tenant";

/**
 * Set (or clear) the tenant subsequent requests act on.
 *
 * Honoured by the server only for an organization-level principal, and only for
 * a tenant in that principal's own organization — anything else is a 403 rather
 * than a silent fallback. So sending it wrongly fails loudly instead of
 * returning another tenant's data.
 */
export function setActiveTenant(tenantId: string | null): void {
  activeTenantId = tenantId;
}

/** The tenant currently being acted on, or `null` for the caller's own. */
export function getActiveTenant(): string | null {
  return activeTenantId;
}
