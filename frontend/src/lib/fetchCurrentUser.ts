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
    };
  } catch {
    return null;
  }
}
