import { Link } from "react-router-dom";
import { ShieldX } from "lucide-react";
import { Button } from "@/components/ui/button";

/**
 * ForbiddenPage — friendly 403 rendered by ProtectedRoute when the
 * authenticated user lacks the required permission (CQ-F30 / T-11-05-AUTHZ).
 *
 * Note: this is a client-side UX guard. The backend RBAC check remains the
 * authoritative enforcement layer — this page prevents confusing blank views.
 */
export function ForbiddenPage() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] text-center px-4">
      <div className="h-16 w-16 rounded-full bg-destructive/10 border border-destructive/30 flex items-center justify-center mb-6">
        <ShieldX size={32} className="text-destructive" />
      </div>

      <h1 className="text-2xl font-bold text-foreground mb-2">
        Access Denied
      </h1>
      <p className="text-muted-foreground max-w-sm mb-2">
        You don't have permission to view this page.
      </p>
      <p className="text-xs text-muted-foreground/60 mb-8">
        If you believe this is a mistake, contact your administrator.
      </p>

      <Button asChild variant="outline">
        <Link to="/dashboard">Back to Dashboard</Link>
      </Button>
    </div>
  );
}
