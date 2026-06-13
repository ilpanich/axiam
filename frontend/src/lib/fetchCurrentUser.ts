import api from "@/lib/api";
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
    };
  } catch {
    return null;
  }
}
