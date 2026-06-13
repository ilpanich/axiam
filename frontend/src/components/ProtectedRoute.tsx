import { Navigate, Outlet } from "react-router-dom";
import { useAuthStore } from "@/stores/auth";
import { usePermissions } from "@/hooks/usePermissions";
import { ForbiddenPage } from "@/components/ForbiddenPage";

/**
 * ProtectedRoute — wraps routes that require a specific permission (CQ-F30).
 *
 * Checks:
 *  1. isAuthenticated — redirects to /login if not authenticated (defense in depth
 *     alongside AppLayout's own guard).
 *  2. can(requiredPermission) — renders ForbiddenPage if the user lacks the permission.
 *
 * Backend RBAC remains the authoritative enforcement layer; this is a UX guard that
 * prevents confusing blank views for users navigating to gated sections (ASVS V4 / T-11-05-AUTHZ).
 */
export function ProtectedRoute({ permission }: { permission: string }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const { can, isLoading } = usePermissions();

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (isLoading) {
    return null;
  }

  if (!can(permission)) {
    return <ForbiddenPage />;
  }

  return <Outlet />;
}
