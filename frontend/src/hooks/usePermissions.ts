import { useAuthStore } from "@/stores/auth";

/**
 * RBAC permission gate hook — exposes a `can(permission)` predicate
 * backed by the authenticated user's effective permissions array.
 *
 * Contract (per UI-SPEC):
 * - `"*"` in the permissions array is a wildcard and satisfies every
 *   check. Backend sets this for super-admin role holders.
 * - Unauthenticated or not-yet-hydrated state returns `false` for
 *   every check — consumers should combine with `isLoading` to avoid
 *   flashing disabled UI during boot.
 */

// CQ-F33: module-level stable empty array — avoids a new array reference on
// every render when the user has no permissions, preserving React.memo equality.
const EMPTY_PERMISSIONS: string[] = [];

export function usePermissions() {
  const permissions = useAuthStore((s) => s.user?.permissions ?? EMPTY_PERMISSIONS);
  const isLoading = useAuthStore((s) => s.isInitializing);

  const can = (permission: string): boolean => {
    return permissions.includes(permission) || permissions.includes("*");
  };

  return { can, permissions, isLoading };
}
