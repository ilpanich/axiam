import api from "@/lib/api";
import { getActiveTenant, setActiveTenant } from "@/lib/activeTenant";
import type { AuthUser } from "@/stores/auth";

/**
 * Fetch the authenticated user from GET /api/v1/auth/me.
 *
 * Used by both the initial app boot (useAuthInit) and the login flow
 * (LoginPage) so the permissions array is always populated from the
 * single authoritative source — avoids divergence between the two
 * surfaces.
 *
 * Also extracts tenantSlug/orgSlug from the /auth/me response so the
 * auth store context can be restored after a hard reload (CQ-F29 / T-11-05-CTX).
 * Slugs are sourced from the backend response, never fabricated client-side.
 *
 * Returns `null` on 401 or network error so callers can clear auth state.
 */
export async function fetchCurrentUser(): Promise<AuthUser | null> {
  try {
    const res = await api.get("/api/v1/auth/me");
    if (!res.data?.user) {
      return null;
    }
    return {
      ...res.data.user,
      permissions: Array.isArray(res.data.permissions)
        ? res.data.permissions
        : [],
      // Restore slugs from /auth/me for setTenantContext after hard reload.
      tenantSlug: res.data.tenant_slug ?? res.data.user?.tenant_slug ?? undefined,
      orgSlug: res.data.org_slug ?? res.data.user?.org_slug ?? undefined,
      // Effective OPAQUE policy for this user's tenant — needed to build a
      // verifier when they change their password.
      opaque: res.data.opaque ?? undefined,
    };
  } catch {
    return null;
  }
}

/**
 * Put a tenant-restricted organization principal into a tenant it can work in,
 * and return the caller as seen from there.
 *
 * An organization-level account whose roles name particular tenants holds
 * nothing in the organization's own scope — by design: a restriction that still
 * applied organization-wide would not be one. So signing in with no tenant
 * selected lands it on an empty dashboard with every list forbidden and a
 * switcher it has to discover before anything works.
 *
 * Selecting a tenant changes what `/auth/me` answers — the permission array is
 * computed for the tenant being acted on — so the caller is re-read afterwards.
 * Returning the *first* snapshot would leave the UI gating on the empty
 * organization-scope permission set while every request went to the tenant.
 *
 * Does nothing for anyone else, and nothing when a tenant is already selected:
 * that value is the operator's own choice, restored per tab from
 * `sessionStorage`.
 *
 * Best-effort. If the re-read fails the selection still stands and the caller
 * gets the snapshot it came in with — every request is authorized server-side
 * regardless, and an error here would block a sign-in that succeeded.
 */
export async function withReachableTenantSelected(
  user: AuthUser,
): Promise<AuthUser> {
  const reachable = user.reachable_tenant_ids;
  if (
    user.organization_level !== true ||
    !Array.isArray(reachable) ||
    reachable.length === 0 ||
    getActiveTenant() !== null
  ) {
    return user;
  }

  // The name is unknown here — `/auth/me` reports ids — and the topbar resolves
  // it from the tenant list it already fetches.
  setActiveTenant(reachable[0], null);
  return (await fetchCurrentUser()) ?? user;
}
