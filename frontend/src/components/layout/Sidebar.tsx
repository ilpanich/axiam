// `Link`, not `NavLink`, on purpose. `NavLink` sets `aria-current="page"`
// itself from its own internal prefix match, which cannot be told about
// `alsoMatches` and silently overrode the value computed here — a tenant detail
// page lit Organizations however `activeNavPath` answered. With `Link` the
// active state has exactly one source.
import { Link, useLocation } from "react-router";
import { cn } from "@/lib/utils";
import { usePermissions } from "@/hooks/usePermissions";
import {
  LayoutDashboard,
  Users,
  UsersRound,
  Shield,
  Lock,
  Database,
  Building2,
  Network,
  Award,
  Key,
  Webhook,
  Code2,
  ScrollText,
  UserCircle,
  Settings,
  X,
  ChevronRight,
  KeyRound,
  Globe,
  BellRing,
  Zap,
  MonitorSmartphone,
  ShieldCheck,
} from "lucide-react";

interface NavItem {
  to: string;
  label: string;
  icon: React.ReactNode;
  /**
   * Permission required to access this nav target. `null` means the
   * item is always visible (self-service surfaces: Dashboard, Audit
   * Logs, Profile).
   */
  requiredPermission: string | null;
  /**
   * Extra path prefixes this item owns, for detail pages that do not live
   * under `to`.
   *
   * Tenant detail is the case that forced this: it is routed as
   * `/organizations/:orgId/tenants/:tenantId` (a tenant is only meaningful
   * inside its organization), so opening one from the Tenants list highlighted
   * **Organizations** and the sidebar disagreed with the page the user was
   * looking at.
   */
  alsoMatches?: string[];
}

/**
 * Whether `pathname` is inside `base`, comparing path **segments**.
 *
 * Two things a `pathname.startsWith(base)` test gets wrong, both of which this
 * replaces:
 *
 * 1. A raw string prefix does not know where a segment ends, so `/tenants`
 *    would claim `/tenants-archive`. Comparing segment by segment cannot.
 * 2. It has no notion of a route parameter. `alsoMatches` entries carry them —
 *    tenant detail is `/organizations/:orgId/tenants/:tenantId` — and a
 *    literal `:orgId` matches no real URL. A segment beginning with `:` is
 *    treated as a wildcard that matches exactly one non-empty segment.
 *
 * `base` matches when it is a segment-wise prefix of `pathname`, so
 * `/organizations/:orgId/tenants` matches `/organizations/abc/tenants/xyz`
 * (and `/organizations/abc/tenants`) but not `/organizations/abc`.
 */
function isUnder(pathname: string, base: string): boolean {
  const path = pathname.split("/").filter(Boolean);
  const pattern = base.split("/").filter(Boolean);
  if (pattern.length > path.length) return false;
  return pattern.every(
    (seg, i) => (seg.startsWith(":") ? path[i].length > 0 : seg === path[i]),
  );
}

/**
 * How specific a `base` is, for picking a winner among several matches.
 *
 * Segment count rather than string length: `/organizations/:orgId/tenants` is
 * three segments and must beat `/organizations`'s one, even though a literal
 * `:orgId` makes the two strings a similar length and a real URL's id would make
 * the comparison depend on how long that particular UUID happens to be.
 */
function specificity(base: string): number {
  return base.split("/").filter(Boolean).length;
}

/**
 * The nav item, if any, that owns `pathname`.
 *
 * The **longest** matching prefix wins, so a more specific item beats a more
 * general one regardless of the order they are declared in. Without that,
 * `/organizations` and `/organizations/:orgId/tenants/:id` would both match a
 * tenant detail page and the answer would depend on which section happened to
 * be listed first.
 *
 * Exported for the test that walks every route in the router and asserts each
 * one lights exactly one sidebar entry.
 */
export function activeNavPath(pathname: string): string | null {
  let best: string | null = null;
  let bestSpecificity = -1;
  for (const section of navSections) {
    for (const item of section.items) {
      for (const base of [item.to, ...(item.alsoMatches ?? [])]) {
        // Dashboard is the fallback route ("/" redirects to it) and owns
        // nothing below itself, so it matches exactly and never by prefix.
        const matches =
          item.to === "/dashboard"
            ? pathname === base
            : isUnder(pathname, base);
        if (matches && specificity(base) > bestSpecificity) {
          best = item.to;
          bestSpecificity = specificity(base);
        }
      }
    }
  }
  return best;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

const navSections: NavSection[] = [
  {
    title: "Overview",
    items: [
      {
        to: "/dashboard",
        label: "Dashboard",
        icon: <LayoutDashboard size={18} />,
        requiredPermission: null,
      },
    ],
  },
  {
    title: "Identity",
    items: [
      {
        to: "/users",
        label: "Users",
        icon: <Users size={18} />,
        requiredPermission: "users:list",
      },
      {
        to: "/groups",
        label: "Groups",
        icon: <UsersRound size={18} />,
        requiredPermission: "groups:list",
      },
      {
        to: "/roles",
        label: "Roles",
        icon: <Shield size={18} />,
        requiredPermission: "roles:list",
      },
      {
        to: "/permissions",
        label: "Permissions",
        icon: <Lock size={18} />,
        requiredPermission: "permissions:list",
      },
      {
        to: "/resources",
        label: "Resources",
        icon: <Database size={18} />,
        requiredPermission: "resources:list",
      },
      {
        to: "/scim-tokens",
        label: "SCIM Provisioning",
        icon: <KeyRound size={18} />,
        requiredPermission: "scim_tokens:list",
      },
      {
        to: "/service-accounts",
        label: "Service Accounts",
        icon: <KeyRound size={18} />,
        requiredPermission: "service_accounts:list",
      },
      {
        to: "/federation",
        label: "Federation",
        icon: <Globe size={18} />,
        requiredPermission: "federation:list",
      },
    ],
  },
  {
    title: "Infrastructure",
    items: [
      {
        to: "/organizations",
        label: "Organizations",
        icon: <Building2 size={18} />,
        requiredPermission: "organizations:list",
      },
      {
        to: "/tenants",
        label: "Tenants",
        icon: <Network size={18} />,
        requiredPermission: "tenants:list",
        // Tenant detail is routed under its organization — see `alsoMatches`.
        alsoMatches: ["/organizations/:orgId/tenants"],
      },
      {
        to: "/certificates",
        label: "Certificates",
        icon: <Award size={18} />,
        requiredPermission: "certificates:list",
      },
      {
        to: "/pgp-keys",
        label: "PGP Keys",
        icon: <Key size={18} />,
        requiredPermission: "pgp_keys:list",
      },
      {
        to: "/webhooks",
        label: "Webhooks",
        icon: <Webhook size={18} />,
        requiredPermission: "webhooks:list",
      },
      {
        to: "/reactors",
        label: "Reactors",
        icon: <Zap size={18} />,
        requiredPermission: "reactors:list",
      },
    ],
  },
  {
    title: "Developers",
    items: [
      {
        to: "/oauth2-clients",
        label: "OAuth2 Clients",
        icon: <Code2 size={18} />,
        requiredPermission: "oauth2_clients:list",
      },
      {
        to: "/audit-logs",
        label: "Audit Logs",
        icon: <ScrollText size={18} />,
        requiredPermission: null,
      },
      {
        to: "/notification-rules",
        label: "Notification Rules",
        icon: <BellRing size={18} />,
        requiredPermission: "notification_rules:list",
      },
      {
        // B2/R4.1: self-service (any authenticated user can approve a device
        // they're holding), so no permission gate -- matches Dashboard/Profile.
        to: "/device",
        label: "Connect a Device",
        icon: <MonitorSmartphone size={18} />,
        requiredPermission: null,
      },
    ],
  },
  {
    title: "Account",
    items: [
      {
        to: "/profile",
        label: "Profile",
        icon: <UserCircle size={18} />,
        requiredPermission: null,
      },
      {
        // GDPR Art. 15/17 self-service console -- every authenticated user
        // manages their own export/erasure requests here.
        to: "/privacy",
        label: "Privacy & Data",
        icon: <ShieldCheck size={18} />,
        requiredPermission: null,
      },
      {
        to: "/settings",
        label: "Settings",
        icon: <Settings size={18} />,
        requiredPermission: "settings:get",
      },
    ],
  },
];

interface SidebarProps {
  onClose?: () => void;
  mobile?: boolean;
}

export function Sidebar({ onClose, mobile = false }: SidebarProps) {
  const location = useLocation();
  const { can } = usePermissions();

  // Exactly one entry is active, chosen by longest matching prefix — see
  // `activeNavPath`. Computing it once per render also means two entries can
  // never both light up, which the old per-item `startsWith` allowed.
  const activePath = activeNavPath(location.pathname);

  return (
    <aside
      className={cn(
        "flex flex-col h-full bg-[#0d0d2b]/90 backdrop-blur-xl border-r border-primary/10",
        "w-60 shrink-0"
      )}
      aria-label="Main navigation"
    >
      {/* Logo area */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-primary/10">
        <div className="flex items-center gap-3">
          <img
            src="/axiam_logo_mark.png"
            alt="AXIAM logo"
            className="h-8 w-8 rounded-full object-cover"
          />
          <span className="text-foreground font-bold text-lg tracking-tight">
            AXIAM
          </span>
        </div>
        {mobile && (
          <button
            onClick={onClose}
            className="text-muted-foreground hover:text-foreground transition-colors p-1 rounded"
            aria-label="Close navigation"
          >
            <X size={20} />
          </button>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-6">
        {navSections.map((section) => (
          <div key={section.title}>
            <p className="px-2 mb-2 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60">
              {section.title}
            </p>
            <ul className="space-y-0.5" role="list">
              {section.items.map((item) => {
                const isActive = activePath === item.to;
                const isDisabled =
                  item.requiredPermission !== null &&
                  !can(item.requiredPermission);
                return (
                  <li key={item.to}>
                    <Link
                      to={item.to}
                      onClick={
                        isDisabled
                          ? (e) => e.preventDefault()
                          : mobile
                            ? onClose
                            : undefined
                      }
                      className={cn(
                        "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-all duration-200 group",
                        isActive
                          ? "sidebar-item-active font-medium"
                          : "text-muted-foreground hover:text-foreground hover:bg-white/5 pl-3",
                        isDisabled &&
                          "opacity-40 cursor-not-allowed pointer-events-none"
                      )}
                      aria-current={isActive ? "page" : undefined}
                      aria-disabled={isDisabled ? "true" : undefined}
                      tabIndex={isDisabled ? -1 : undefined}
                    >
                      <span
                        className={cn(
                          "shrink-0 transition-colors",
                          isActive
                            ? "text-primary"
                            : "text-muted-foreground group-hover:text-foreground"
                        )}
                        aria-hidden="true"
                      >
                        {item.icon}
                      </span>
                      <span className="truncate">{item.label}</span>
                      {isActive && !isDisabled && (
                        <ChevronRight
                          size={14}
                          className="ml-auto text-primary"
                          aria-hidden="true"
                        />
                      )}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-5 py-3 border-t border-primary/10">
        <p className="text-[10px] text-muted-foreground/50">
          AXIAM v1.0.0-alpha44
        </p>
      </div>
    </aside>
  );
}
