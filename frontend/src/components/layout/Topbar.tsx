import { useNavigate, useMatches } from "react-router";
import { Menu, LogOut, ChevronDown, Building2, Check } from "lucide-react";
import { useAuthStore } from "@/stores/auth";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { cn } from "@/lib/utils";
import api from "@/lib/api";
import { fetchCurrentUser } from "@/lib/fetchCurrentUser";
import { orgService, tenantService } from "@/services/organizations";
import { usePermissions } from "@/hooks/usePermissions";
import {
  useState,
  useEffect,
  useRef,
  useCallback,
  type KeyboardEvent as ReactKeyboardEvent,
} from "react";

interface TopbarProps {
  onMenuClick: () => void;
}

export function Topbar({ onMenuClick }: TopbarProps) {
  const navigate = useNavigate();
  const matches = useMatches();
  const {
    user,
    tenantSlug,
    orgSlug,
    activeTenantId,
    activeTenantName,
    clearAuth,
    selectTenant,
    setUser,
  } = useAuthStore();
  // Whether this principal lives in the organization's own scope. Only such a
  // principal can act on another tenant, because only its grants apply there.
  const isOrgLevel = user?.organization_level === true;
  const queryClientInstance = useQueryClient();
  const { can } = usePermissions();
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

  const handleMenuKeyDown = useCallback(
    (e: ReactKeyboardEvent<HTMLDivElement>) => {
      const container = e.currentTarget;
      const items = Array.from(
        container.querySelectorAll<HTMLElement>('[role="menuitem"]'),
      );
      if (items.length === 0) return;

      const current = document.activeElement as HTMLElement;
      const idx = items.indexOf(current);

      if (e.key === "ArrowDown") {
        e.preventDefault();
        items[idx < items.length - 1 ? idx + 1 : 0]?.focus();
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        items[idx > 0 ? idx - 1 : items.length - 1]?.focus();
      } else if (e.key === "Home") {
        e.preventDefault();
        items[0]?.focus();
      } else if (e.key === "End") {
        e.preventDefault();
        items[items.length - 1]?.focus();
      }
    },
    [],
  );

  // The tenants of the caller's own organization.
  //
  // `orgService.list()` returns only that organization — the endpoint refuses
  // any other — so resolving the id from the slug the auth store carries costs
  // one request and needs no extra permission beyond the two checked here.
  // Fetched only while the menu is open: an operator who never switches tenants
  // should not pay for this on every page.
  const { data: tenants = [], isLoading: tenantsLoading } = useQuery({
    queryKey: ["topbar-tenants", orgSlug],
    enabled: tenantMenuOpen && can("organizations:list") && can("tenants:list"),
    queryFn: async () => {
      const orgs = await orgService.list();
      const org = orgSlug ? orgs.find((o) => o.slug === orgSlug) : orgs[0];
      if (!org) return [];
      return tenantService.list(org.id);
    },
  });

  /**
   * Act on a different tenant, for an organization-level principal.
   *
   * No re-authentication: this principal's grants live in the organization
   * tenant and apply to every tenant in the organization, so it already *is* a
   * principal there. Selecting one sets `X-Axiam-Tenant` on subsequent
   * requests; the server verifies the tenant is in the caller's own
   * organization and refuses otherwise.
   *
   * The query cache is cleared because every list in the app is tenant-scoped.
   * Leaving one tenant's rows on screen under another tenant's name is worse
   * than a moment of loading.
   */
  const selectActiveTenant = async (
    tenantId: string | null,
    tenantName: string | null,
  ) => {
    selectTenant(tenantId, tenantName);
    queryClientInstance.clear();
    closeAll();

    // Re-read the caller in the scope it has just switched into.
    //
    // Several fields of `/auth/me` describe the tenant being ACTED ON rather
    // than the principal — the effective OPAQUE policy, the tenant slug, and
    // the permission array, which across a tenant boundary carries only the
    // caller's *global* grants. Keeping the copy taken at login meant the UI
    // offered controls the server would refuse, and hid ones it would allow.
    //
    // Failure is not fatal and deliberately silent: the previous snapshot stays,
    // every request is authorized server-side regardless, and an error toast for
    // a background refresh is noise on an action that visibly succeeded.
    const refreshed = await fetchCurrentUser();
    if (refreshed) setUser(refreshed);
  };

  /**
   * Switch to another tenant, for a **tenant-level** principal.
   *
   * A session is bound to one tenant and such a user record belongs to one
   * tenant: the JWT carries `tenant_id`, every repository call is scoped by it,
   * and a principal of one tenant is simply not a principal of another. So
   * switching cannot re-scope the current session — there is no server-side
   * operation that would make that safe, and inventing one would be a
   * cross-tenant privilege path in a product whose central promise is tenant
   * isolation.
   *
   * What it does instead is honest and does the job: revoke the current session
   * and hand the login page the target org and tenant pre-filled. The operator
   * authenticates as a principal of that tenant, which is the only way to
   * become one.
   *
   * Organization-level principals do not come through here — they use
   * `selectActiveTenant`, because for them the premise above is false.
   */
  const switchTenant = async (targetSlug: string) => {
    if (targetSlug === tenantSlug) {
      closeAll();
      return;
    }
    try {
      await api.post("/api/v1/auth/logout");
    } catch {
      // Ignore: the local state is cleared either way, and a session left
      // alive server-side expires on its own.
    }
    queryClientInstance.clear();
    clearAuth();
    const params = new URLSearchParams({
      tenant: targetSlug,
      ...(orgSlug ? { org: orgSlug } : {}),
    });
    navigate(`/login?${params.toString()}`);
  };

  const handleLogout = async () => {
    try {
      // D-03 (SECFIX-05): logout revokes the caller's own session from the
      // authenticated JWT — no request body, no client-supplied session_id.
      await api.post("/api/v1/auth/logout");
    } catch {
      // Ignore errors — still clear local state
    }
    queryClientInstance.clear();
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
    <header className="h-14 flex items-center justify-between px-4 border-b border-primary/10 bg-[#0d0d2b]/60 backdrop-blur-xs shrink-0">
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
            aria-haspopup="menu"
          >
            <Building2 size={14} aria-hidden="true" />
            <span className="hidden sm:inline">
              {isOrgLevel
                ? `${orgSlug ?? "org"} / ${activeTenantName ?? "Organization"}`
                : tenantSlug
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
                "glass-menu px-0 py-1 shadow-glass",
              )}
              role="menu"
              aria-label="Tenant selector"
              onKeyDown={handleMenuKeyDown}
            >
              <p className="px-3 pt-2 pb-1 text-xs text-muted-foreground">
                {orgSlug ? `Tenants in ${orgSlug}` : "Tenants"}
              </p>
              {tenantsLoading && (
                <p className="px-3 py-2 text-xs text-muted-foreground">
                  Loading…
                </p>
              )}
              {!tenantsLoading && tenants.length === 0 && (
                <p className="px-3 py-2 text-xs text-muted-foreground">
                  No other tenant is visible to you.
                </p>
              )}
              {/* Organization scope: only an organization-level principal has
                  one to return to, and it is where its own record lives. */}
              {isOrgLevel && (
                <button
                  role="menuitem"
                  onClick={() => selectActiveTenant(null, null)}
                  aria-current={activeTenantId === null ? "true" : undefined}
                  className={cn(
                    "w-full flex items-center justify-between gap-2 px-3 py-2 text-sm text-left",
                    "hover:bg-white/5 transition-colors border-b border-primary/10",
                    activeTenantId === null
                      ? "text-foreground"
                      : "text-muted-foreground",
                  )}
                >
                  <span className="truncate font-medium">Organization</span>
                  {activeTenantId === null && (
                    <Check
                      size={14}
                      className="shrink-0 text-primary"
                      aria-hidden="true"
                    />
                  )}
                </button>
              )}
              {tenants
                // The organization scope is offered above, by name, and is not
                // a tenant an operator picks from a list of tenants.
                .filter((t) => t.kind !== "organization")
                .map((t) => {
                  const current = isOrgLevel
                    ? activeTenantId === t.id
                    : t.slug === tenantSlug;
                  return (
                    <button
                      key={t.id}
                      role="menuitem"
                      onClick={() =>
                        isOrgLevel
                          ? selectActiveTenant(t.id, t.name)
                          : void switchTenant(t.slug)
                      }
                      aria-current={current ? "true" : undefined}
                      className={cn(
                        "w-full flex items-center justify-between gap-2 px-3 py-2 text-sm text-left",
                        "hover:bg-white/5 transition-colors",
                        current ? "text-foreground" : "text-muted-foreground",
                      )}
                    >
                      <span className="truncate">{t.name}</span>
                      {current && (
                        <Check
                          size={14}
                          className="shrink-0 text-primary"
                          aria-hidden="true"
                        />
                      )}
                    </button>
                  );
                })}
              <p className="px-3 pt-2 pb-1 border-t border-primary/10 text-xs text-muted-foreground">
                {isOrgLevel
                  ? "Your roles are held at organization level, so switching " +
                    "tenant takes effect immediately — no sign-in needed."
                  : "A session belongs to one tenant, so switching signs you " +
                    "out and asks you to sign in to the tenant you picked."}
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
            aria-haspopup="menu"
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
                "glass-menu px-0 py-1 shadow-glass",
              )}
              role="menu"
              aria-label="User menu"
              onKeyDown={handleMenuKeyDown}
            >
              <div className="px-3 py-2 border-b border-primary/10">
                <p className="text-sm text-foreground font-medium">
                  {user?.username}
                </p>
                <p className="text-xs text-muted-foreground">{user?.email}</p>
              </div>
              <button
                role="menuitem"
                onClick={() => void handleLogout()}
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
