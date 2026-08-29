import { Page } from "@playwright/test";
import { existsSync, readFileSync } from "node:fs";
import {
  FIXTURE_STATE,
  MatrixFixture,
  TENANT_A_SLUG,
  TENANT_B_SLUG,
  storageStateFor,
} from "./matrix-fixture";

/**
 * The data the permission matrix is driven from: who the principals are, where
 * the frontend can go, and what each destination declares it requires.
 */

// ---------------------------------------------------------------------------
// Destinations
// ---------------------------------------------------------------------------

/**
 * One navigable area of the admin UI.
 *
 * `navPermission` is what `frontend/src/components/layout/navSections.tsx`
 * declares for the sidebar entry; `routePermission` is what
 * `frontend/src/router.tsx` wraps the route in. **They are recorded separately
 * on purpose.** Where they disagree the UI offers a live link into a page that
 * refuses — exactly the "renders a control the server would refuse" class — and
 * a single field would have hidden that by construction.
 *
 * `null` means "no gate declared at that layer".
 */
export interface NavDestination {
  path: string;
  label: string;
  navPermission: string | null;
  routePermission: string | null;
  /**
   * Whether the sidebar offers this destination at all. Defaults to `true`.
   *
   * A page reachable only from inside another page has no sidebar entry, so
   * there is no nav gate for the route gate to agree with — and recording it as
   * `navPermission: null` would claim there *is* one, declared ungated, which
   * is the exact shape of the `/audit-logs` finding. `false` says "not offered",
   * which is a different statement from "offered to everyone".
   *
   * The route gate is still asserted in both directions: a page nobody links to
   * is still reachable by typing its URL.
   */
  inNav?: boolean;
  /**
   * Whether the sidebar entry is gated on organization **standing** rather than
   * on a permission alone (`navSections.tsx`'s `organizationOnly`).
   *
   * No permission expresses this. `organizations:list` is seeded into every
   * tenant's own `super-admin` role, so a tenant administrator holds it and is
   * still refused every organization-level action by
   * `handlers::org_scope::require_organization_principal`, which keys on where
   * the caller's record lives. Gating the entry on the permission alone is what
   * produced a live link into a page whose every button answered 403.
   *
   * Recorded here so this matrix asserts the gate the UI actually applies. A
   * model that knew only about permissions would read the fix as a regression —
   * "holds `organizations:list` but the entry is disabled" — and demand the bug
   * back.
   */
  organizationOnly?: boolean;
}

export const NAV_DESTINATIONS: NavDestination[] = [
  {
    path: "/dashboard",
    label: "Dashboard",
    navPermission: null,
    routePermission: null,
  },
  {
    path: "/users",
    label: "Users",
    navPermission: "users:list",
    routePermission: "users:list",
  },
  {
    path: "/groups",
    label: "Groups",
    navPermission: "groups:list",
    routePermission: "groups:list",
  },
  {
    path: "/roles",
    label: "Roles",
    navPermission: "roles:list",
    routePermission: "roles:list",
  },
  {
    path: "/permissions",
    label: "Permissions",
    navPermission: "permissions:list",
    routePermission: "permissions:list",
  },
  {
    path: "/resources",
    label: "Resources",
    navPermission: "resources:list",
    routePermission: "resources:list",
  },
  {
    path: "/scim-tokens",
    label: "SCIM Provisioning",
    navPermission: "scim_tokens:list",
    routePermission: "scim_tokens:list",
  },
  {
    path: "/service-accounts",
    label: "Service Accounts",
    navPermission: "service_accounts:list",
    routePermission: "service_accounts:list",
  },
  {
    path: "/federation",
    label: "Federation",
    navPermission: "federation:list",
    routePermission: "federation:list",
  },
  {
    path: "/organizations",
    label: "Organizations",
    navPermission: "organizations:list",
    routePermission: "organizations:list",
    organizationOnly: true,
  },
  {
    path: "/tenants",
    label: "Tenants",
    navPermission: "tenants:list",
    routePermission: "tenants:list",
  },
  {
    path: "/certificates",
    label: "Certificates",
    navPermission: "certificates:list",
    routePermission: "certificates:list",
  },
  {
    path: "/pgp-keys",
    label: "PGP Keys",
    navPermission: "pgp_keys:list",
    routePermission: "pgp_keys:list",
  },
  {
    path: "/webhooks",
    label: "Webhooks",
    navPermission: "webhooks:list",
    routePermission: "webhooks:list",
  },
  {
    path: "/reactors",
    label: "Reactors",
    navPermission: "reactors:list",
    routePermission: "reactors:list",
  },
  {
    path: "/oauth2-clients",
    label: "OAuth2 Clients",
    navPermission: "oauth2_clients:list",
    routePermission: "oauth2_clients:list",
  },
  // This one was the finding: the sidebar declared no permission while the route
  // required `audit_logs:list`, so the entry stayed enabled for a principal the
  // route would refuse. Both sides now declare it, and the pair is recorded here
  // so the "nav gate and route gate agree" assertion has something to compare.
  {
    path: "/audit-logs",
    label: "Audit Logs",
    navPermission: "audit_logs:list",
    routePermission: "audit_logs:list",
  },
  {
    path: "/notification-rules",
    label: "Notification Rules",
    navPermission: "notification_rules:list",
    routePermission: "notification_rules:list",
  },
  {
    path: "/device",
    label: "Connect a Device",
    navPermission: null,
    routePermission: null,
  },
  {
    path: "/profile",
    label: "Profile",
    navPermission: null,
    routePermission: null,
  },
  {
    path: "/privacy",
    label: "Privacy & Data",
    navPermission: null,
    routePermission: null,
  },
  {
    path: "/settings",
    label: "Settings",
    navPermission: "settings:get",
    routePermission: "settings:get",
  },
  // Reached from the Settings page, not the sidebar — and gated by a permission
  // no other destination uses, so before this entry existed the whole
  // `webauthn_policy:read` boundary went unmeasured in both directions.
  // Self-service, reachable from the profile page rather than the sidebar, and
  // gated by nothing but a session — the same class as `/profile` itself. Listed
  // rather than exempted so the matrix actually opens them: a regression that
  // accidentally put a permission in front of "change your own password" would
  // otherwise be invisible here.
  {
    path: "/profile/change-password",
    label: "Change Password",
    navPermission: null,
    routePermission: null,
    inNav: false,
  },
  {
    path: "/profile/mfa",
    label: "Multi-factor Authentication",
    navPermission: null,
    routePermission: null,
    inNav: false,
  },
  {
    path: "/settings/webauthn-attestation-policy",
    label: "WebAuthn Attestation Policy",
    navPermission: null,
    routePermission: "webauthn_policy:read",
    inNav: false,
  },
];

// ---------------------------------------------------------------------------
// Principals
// ---------------------------------------------------------------------------

export interface MatrixPrincipal {
  key: string;
  username: string;
  /** `null` = signs in at organization level, naming no tenant. */
  tenantSlug: string | null;
  storageState: string;
  /** One line on what this principal exists to prove. */
  purpose: string;
}

export const MATRIX_PRINCIPALS: MatrixPrincipal[] = [
  {
    key: "org-admin",
    username: "admin",
    tenantSlug: null,
    storageState: storageStateFor("org-admin"),
    purpose: "organization super-admin — must reach every tenant",
  },
  {
    key: "org-a-admin",
    username: "mx-org-a-admin",
    tenantSlug: null,
    purpose:
      "organization-level but restricted to tenant A — reaches A, not B, not the organization",
    storageState: storageStateFor("org-a-admin"),
  },
  {
    key: "tenant-admin",
    username: "tenant-admin",
    tenantSlug: TENANT_A_SLUG,
    storageState: storageStateFor("tenant-admin"),
    purpose: "super-admin within tenant A only",
  },
  {
    key: "viewer",
    username: "mx-viewer",
    tenantSlug: TENANT_A_SLUG,
    storageState: storageStateFor("viewer"),
    purpose: "read-only across tenant A — the 'cannot do' half of the matrix",
  },
  {
    key: "editor",
    username: "mx-editor",
    tenantSlug: TENANT_A_SLUG,
    storageState: storageStateFor("editor"),
    purpose:
      "write, but only beneath resource mx-b — inheritance and its limit",
  },
  {
    key: "denied",
    username: "mx-denied",
    tenantSlug: TENANT_A_SLUG,
    storageState: storageStateFor("denied"),
    purpose: "an allow deep in the tree masked by a deny on an ancestor",
  },
  {
    key: "grouped",
    username: "mx-grouped",
    tenantSlug: TENANT_A_SLUG,
    storageState: storageStateFor("grouped"),
    purpose: "holds nothing directly — everything arrives through a group",
  },
  {
    key: "nobody",
    username: "mx-nobody",
    tenantSlug: TENANT_A_SLUG,
    storageState: storageStateFor("nobody"),
    purpose: "no roles at all — the floor the default-deny engine must hold",
  },
  {
    key: "b-admin",
    username: "mx-b-admin",
    tenantSlug: TENANT_B_SLUG,
    storageState: storageStateFor("b-admin"),
    purpose: "super-admin in tenant B — must see nothing of tenant A",
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * The fixture the setup project built, or an empty one with a single problem
 * recorded. Returning an empty fixture rather than throwing is deliberate: the
 * structural assertions in the matrix do not need it, and losing them too
 * because the fixture failed would cost the wave breadth it did not have to
 * lose.
 */
export function readFixture(): MatrixFixture {
  if (!existsSync(FIXTURE_STATE)) {
    return {
      orgId: "",
      tenantA: "",
      tenantB: "",
      resources: {},
      scopes: {},
      roles: {},
      groups: {},
      users: {},
      serviceAccounts: {},
      caCertificates: {},
      certificates: {},
      problems: [
        `${FIXTURE_STATE} does not exist — the matrix setup project did not run`,
      ],
    };
  }
  return JSON.parse(readFileSync(FIXTURE_STATE, "utf8")) as MatrixFixture;
}

/**
 * `true` if the permission array satisfies `permission`.
 *
 * `"*"` is the wildcard the backend sets for super-admin role holders, and the
 * UI's own `usePermissions().can` honours it — so the matrix must too, or every
 * super-admin assertion would invert.
 */
export function holds(permissions: string[], permission: string): boolean {
  return permissions.includes("*") || permissions.includes(permission);
}

/**
 * Puts the page on the app's own origin, if it is not there already.
 *
 * Every helper below reaches the API through `page.evaluate` + `fetch`, which
 * is what makes the session cookie and the app's own origin apply. A fresh
 * Playwright page starts on `about:blank`, where `document.cookie` throws
 * `SecurityError` and a relative `fetch` has no origin to be relative to — so a
 * spec that asks the engine a question before navigating anywhere fails for a
 * reason that has nothing to do with the answer.
 */
export async function ensureOnApp(page: Page): Promise<void> {
  if (new URL(page.url()).protocol === "about:") {
    await page.goto("/dashboard", { waitUntil: "networkidle" });
  }
}

/**
 * The signed-in principal's effective permissions, read from the server.
 *
 * Taken from `GET /api/v1/auth/me` inside the page's own origin so the session
 * cookie and any acting-tenant state the app has set both apply — the same
 * answer the UI gates on, rather than a second opinion computed differently.
 */
export async function canActOnOrganization(page: Page): Promise<boolean> {
  await page.goto("/dashboard", { waitUntil: "networkidle" });
  return page.evaluate(async () => {
    const res = await fetch("/api/v1/auth/me", { credentials: "include" });
    if (!res.ok) return false;
    const body = (await res.json()) as {
      organization_level?: boolean;
      reachable_tenant_ids?: unknown;
    };
    // Deliberately the same two fields, in the same order, as
    // `useCanActOnOrganization` in `src/lib/grantReach.ts`: organization-level,
    // and not narrowed to particular tenants. An organization-level account
    // restricted to some of the organization's tenants was created precisely so
    // it would administer those and not the organization, and the server
    // refuses it organization-level actions for that reason.
    if (body.organization_level !== true) return false;
    return !Array.isArray(body.reachable_tenant_ids);
  });
}

export async function effectivePermissions(
  page: Page,
): Promise<string[] | null> {
  await page.goto("/dashboard", { waitUntil: "networkidle" });
  return page.evaluate(async () => {
    const res = await fetch("/api/v1/auth/me", { credentials: "include" });
    if (!res.ok) return null;
    const body = (await res.json()) as { permissions?: string[] };
    return body.permissions ?? null;
  });
}

/**
 * Asks the authorization engine directly.
 *
 * The UI can only show what it was told; `POST /api/v1/authz/check` is the
 * engine's own answer, and it is the only way to assert deny-override and
 * resource inheritance at the depth the fixture builds — no page renders
 * "may mx-denied update mx-d?".
 */
export async function authzCheck(
  page: Page,
  body: Record<string, unknown>,
): Promise<{ status: number; allowed: boolean | null }> {
  await ensureOnApp(page);
  return page.evaluate(async (payload) => {
    const csrf = document.cookie
      .split("; ")
      .find((c) => c.startsWith("axiam_csrf="))
      ?.split("=")[1];
    const res = await fetch("/api/v1/authz/check", {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...(csrf ? { "X-CSRF-Token": decodeURIComponent(csrf) } : {}),
      },
      body: JSON.stringify(payload),
    });
    let allowed: boolean | null = null;
    try {
      const json = (await res.json()) as { allowed?: boolean };
      allowed = typeof json.allowed === "boolean" ? json.allowed : null;
    } catch {
      allowed = null;
    }
    return { status: res.status, allowed };
  }, body);
}
