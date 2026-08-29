/**
 * The sidebar's navigation model, and the rule for which entry a route lights.
 *
 * Separate from `Sidebar.tsx` because `activeNavPath` is exported for tests and
 * a module that exports both a component and a plain function breaks React Fast
 * Refresh (oxlint `react(only-export-components)`). Splitting the data and the
 * matching rule out of the view is the better shape regardless: what the nav
 * contains and which entry a URL belongs to are facts about the router, and are
 * worth testing without rendering anything.
 */
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

export const navSections: NavSection[] = [
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
        // The route is wrapped in `<ProtectedRoute permission="audit_logs:list">`.
        // Declaring `null` here left the entry enabled for a principal the
        // route would refuse — a live link into an Access Denied page, which is
        // the "renders a control the server would refuse" class. Every other
        // entry already agreed with its route; this one did not.
        requiredPermission: "audit_logs:list",
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
