import { useNavigate, useMatches } from "react-router-dom";
import { Menu, LogOut, ChevronDown, Building2 } from "lucide-react";
import { useAuthStore } from "@/stores/auth";
import { cn } from "@/lib/utils";
import { useState, useEffect, useRef, useCallback } from "react";

interface TopbarProps {
  onMenuClick: () => void;
}

export function Topbar({ onMenuClick }: TopbarProps) {
  const navigate = useNavigate();
  const matches = useMatches();
  const { user, tenantSlug, orgSlug, clearAuth } = useAuthStore();
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [tenantMenuOpen, setTenantMenuOpen] = useState(false);
  const tenantPanelRef = useRef<HTMLDivElement>(null);
  const userPanelRef = useRef<HTMLDivElement>(null);

  const closeAll = useCallback(() => {
    setUserMenuOpen(false);
    setTenantMenuOpen(false);
  }, []);

  useEffect(() => {
    if (!userMenuOpen && !tenantMenuOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeAll();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [userMenuOpen, tenantMenuOpen, closeAll]);

  useEffect(() => {
    if (tenantMenuOpen && tenantPanelRef.current) {
      const first = tenantPanelRef.current.querySelector<HTMLElement>(
        "button, a, [tabindex]",
      );
      first?.focus();
    }
  }, [tenantMenuOpen]);

  useEffect(() => {
    if (userMenuOpen && userPanelRef.current) {
      const first = userPanelRef.current.querySelector<HTMLElement>(
        "button, a, [tabindex]",
      );
      first?.focus();
    }
  }, [userMenuOpen]);

  const handleLogout = () => {
    clearAuth();
    navigate("/login");
  };

  // Build breadcrumb from current route matches
  const breadcrumbs = matches
    .filter(
      (m) =>
        m.handle && typeof (m.handle as { crumb?: string }).crumb === "string",
    )
    .map((m) => (m.handle as { crumb: string }).crumb);

  return (
    <header className="h-14 flex items-center justify-between px-4 border-b border-primary/10 bg-[#0d0d2b]/60 backdrop-blur-sm shrink-0">
      {/* Left: hamburger + breadcrumb */}
      <div className="flex items-center gap-3">
        <button
          onClick={onMenuClick}
          className="lg:hidden p-2 rounded-md text-muted-foreground hover:text-foreground hover:bg-white/5 transition-colors"
          aria-label="Open navigation menu"
        >
          <Menu size={20} />
        </button>
        <nav aria-label="Breadcrumb">
          <ol className="flex items-center gap-1 text-sm text-muted-foreground">
            <li>
              <span className="text-primary font-semibold">AXIAM</span>
            </li>
            {breadcrumbs.map((crumb, i) => (
              <li key={i} className="flex items-center gap-1">
                <ChevronDown
                  size={14}
                  className="rotate-[-90deg] opacity-50"
                  aria-hidden="true"
                />
                <span
                  className={
                    i === breadcrumbs.length - 1
                      ? "text-foreground"
                      : "text-muted-foreground"
                  }
                >
                  {crumb}
                </span>
              </li>
            ))}
          </ol>
        </nav>
      </div>

      {/* Right: tenant selector + user menu */}
      <div className="flex items-center gap-2">
        {/* Tenant selector */}
        <div className="relative">
          <button
            onClick={() => {
              setTenantMenuOpen((v) => !v);
              setUserMenuOpen(false);
            }}
            className={cn(
              "flex items-center gap-2 px-3 py-1.5 rounded-md text-sm",
              "border border-primary/20 bg-white/5",
              "text-muted-foreground hover:text-foreground hover:border-primary/40",
              "transition-all duration-200",
            )}
            aria-expanded={tenantMenuOpen}
            aria-haspopup="true"
          >
            <Building2 size={14} aria-hidden="true" />
            <span className="hidden sm:inline">
              {tenantSlug
                ? `${orgSlug ?? "org"} / ${tenantSlug}`
                : "Select tenant"}
            </span>
            <ChevronDown size={14} aria-hidden="true" />
          </button>
          {tenantMenuOpen && (
            <div
              ref={tenantPanelRef}
              className={cn(
                "absolute right-0 top-full mt-1 z-50 min-w-48",
                "glass-card py-1 shadow-glass",
              )}
              role="dialog"
              aria-label="Tenant selector"
            >
              <p className="px-3 py-2 text-xs text-muted-foreground">
                Tenant switching coming soon
              </p>
            </div>
          )}
        </div>

        {/* User menu */}
        <div className="relative">
          <button
            onClick={() => {
              setUserMenuOpen((v) => !v);
              setTenantMenuOpen(false);
            }}
            className={cn(
              "flex items-center gap-2 px-3 py-1.5 rounded-md text-sm",
              "border border-primary/20 bg-white/5",
              "text-muted-foreground hover:text-foreground hover:border-primary/40",
              "transition-all duration-200",
            )}
            aria-expanded={userMenuOpen}
            aria-haspopup="true"
            aria-label="User menu"
          >
            <div
              className="h-6 w-6 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center text-primary text-xs font-semibold"
              aria-hidden="true"
            >
              {user?.username?.[0]?.toUpperCase() ?? "U"}
            </div>
            <span className="hidden sm:inline truncate max-w-24">
              {user?.username ?? "User"}
            </span>
            <ChevronDown size={14} aria-hidden="true" />
          </button>

          {userMenuOpen && (
            <div
              ref={userPanelRef}
              className={cn(
                "absolute right-0 top-full mt-1 z-50 min-w-40",
                "glass-card py-1 shadow-glass",
              )}
              role="dialog"
              aria-label="User menu"
            >
              <div className="px-3 py-2 border-b border-primary/10">
                <p className="text-sm text-foreground font-medium">
                  {user?.username}
                </p>
                <p className="text-xs text-muted-foreground">{user?.email}</p>
              </div>
              <button
                onClick={handleLogout}
                className="w-full flex items-center gap-2 px-3 py-2 text-sm text-destructive hover:bg-destructive/10 transition-colors"
              >
                <LogOut size={14} aria-hidden="true" />
                Sign out
              </button>
            </div>
          )}
        </div>
      </div>

      {(userMenuOpen || tenantMenuOpen) && (
        <div
          className="fixed inset-0 z-40"
          onClick={closeAll}
          aria-hidden="true"
        />
      )}
    </header>
  );
}
