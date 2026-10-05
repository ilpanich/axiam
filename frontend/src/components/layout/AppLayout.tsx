import { useState, useEffect } from "react";
import { Outlet, Navigate, useLocation } from "react-router";
import { Loader2 } from "lucide-react";
import { useAuthStore } from "@/stores/auth";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";
import { cn } from "@/lib/utils";
import { OWN_SCOPE_CACHE_SLOT } from "@/lib/queryClient";
import { sanitizeReturnTo } from "@/lib/returnTo";

export function AppLayout() {
  const { isAuthenticated, activeTenantId, isSwitchingTenant } = useAuthStore();
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  // Close sidebar on escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setSidebarOpen(false);
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, []);

  if (!isAuthenticated) {
    // A visitor arriving on a page that is meant to be reached from a link in a
    // mail (the CIBA approval page, T23.7.2) is brought back to it after
    // signing in. Only a destination `sanitizeReturnTo` accepts is carried --
    // for every other page the answer is the plain login it always was.
    const resume = sanitizeReturnTo(location.pathname + location.search);
    return (
      <Navigate
        to={resume ? `/login?return_to=${encodeURIComponent(resume)}` : "/login"}
        replace
      />
    );
  }

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      {/* Desktop sidebar */}
      <div className="hidden lg:flex">
        <Sidebar />
      </div>

      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 z-40 bg-black/60 backdrop-blur-xs lg:hidden"
            onClick={() => setSidebarOpen(false)}
            aria-hidden="true"
          />
          {/* Drawer */}
          <div
            className={cn(
              "fixed inset-y-0 left-0 z-50 lg:hidden",
              "transform transition-transform duration-300 ease-in-out"
            )}
            role="dialog"
            aria-modal="true"
            aria-label="Navigation menu"
          >
            <Sidebar
              mobile
              onClose={() => setSidebarOpen(false)}
            />
          </div>
        </>
      )}

      {/* Main content area */}
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <Topbar onMenuClick={() => setSidebarOpen(true)} />
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8">
          {isSwitchingTenant ? (
            <div
              className="flex h-full items-center justify-center gap-3 text-muted-foreground"
              aria-live="polite"
            >
              <Loader2 className="h-5 w-5 animate-spin text-primary" />
              <span className="text-sm">Switching tenant…</span>
            </div>
          ) : (
            /* Keyed by the tenant being acted on, so a switch REMOUNTS the
               routed page rather than re-rendering it.

               A remount is what makes the data correct. Every query key in this
               app is namespaced by the acting tenant
               (`tenantScopedQueryKeyHash`), but a mounted observer keeps the
               key — and therefore the cache entry — it was created with; only a
               fresh mount computes the namespace again and misses. It also
               discards page-local state, which after a switch refers to rows,
               ids and half-filled forms belonging to a tenant nobody is looking
               at any more. */
            <div key={activeTenantId ?? OWN_SCOPE_CACHE_SLOT} className="h-full">
              <Outlet />
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
