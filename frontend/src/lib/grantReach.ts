import { useAuthStore } from "@/stores/auth";

/**
 * How far a grant reaches, in words an operator can act on.
 *
 * `is_global` on a role means "every resource in scope" and always has. What
 * organization scope changed is *what the scope is*: a global role in the
 * organization's own tenant reaches every tenant in the organization, and the
 * same flag in an ordinary tenant reaches only that tenant. One word cannot
 * honestly cover both, and "Global" was quietly claiming the stronger one
 * everywhere.
 *
 * The flag itself is deliberately not renamed. `is_global` appears throughout
 * the REST API, `sdks/CONTRACT.md` and eleven vendored SDK repositories, and
 * its meaning did not change — only the reach it implies, which depends on
 * where the role lives. Renaming the wire field would be a breaking change
 * across every SDK in exchange for a label, so the label is what changes.
 */
export type GrantReach = "organization" | "tenant" | "resource";

export function reachLabel(reach: GrantReach): string {
  switch (reach) {
    case "organization":
      return "Organization-wide";
    case "tenant":
      return "Tenant-wide";
    case "resource":
      return "Resource-scoped";
  }
}

export function reachTitle(reach: GrantReach): string {
  switch (reach) {
    case "organization":
      return "Applies to every resource in every tenant of this organization";
    case "tenant":
      return "Applies to every resource in this tenant";
    case "resource":
      return "Applies only under the chosen resource and its descendants";
  }
}

/**
 * Whether the scope currently being administered is the organization's own.
 *
 * True when the caller is organization-level *and* has not switched to a
 * particular tenant. Both halves matter: an organization-level administrator
 * looking at `tenant-a` is editing roles that live in `tenant-a`, and those
 * reach exactly that tenant however privileged the person editing them is.
 */
export function useIsOrganizationScope(): boolean {
  const user = useAuthStore((s) => s.user);
  const activeTenantId = useAuthStore((s) => s.activeTenantId);
  return user?.organization_level === true && activeTenantId === null;
}

/** The reach of a role, given where it lives. */
export function roleReach(
  isGlobal: boolean,
  isOrganizationScope: boolean,
): GrantReach {
  if (!isGlobal) return "resource";
  return isOrganizationScope ? "organization" : "tenant";
}

/**
 * Whether this principal may perform **organization-level** actions —
 * creating an organization or a tenant, minting the organization's CA, flagging
 * an mTLS trust anchor.
 *
 * Two conditions, both from `/auth/me`, and both mirroring exactly what
 * `handlers::org_scope::require_organization_principal` checks on the server:
 *
 * 1. the principal's own record lives in the organization's reserved tenant
 *    (`organization_level`), and
 * 2. its roles are not confined to particular tenants of it
 *    (`reachable_tenant_ids` absent).
 *
 * # Why this is not `useIsOrganizationScope`
 *
 * That one answers "which scope am I *editing* right now", and goes false the
 * moment an organization administrator switches to a child tenant — correct
 * for labelling a role's reach, wrong here. The server does not care which
 * tenant is selected when it is asked to create another organization; it cares
 * where the caller lives. A gate built on the other predicate would hide the
 * organization's own controls from its own administrator for as long as they
 * had a tenant selected.
 *
 * # Why a UI gate at all
 *
 * The server refuses these actions regardless, so this changes no security
 * boundary. What it changes is that a tenant administrator no longer sees "New
 * Organization", a tenant lifecycle menu and the CA controls, click one, and
 * get a 403 — a control offered to somebody the server refuses is a defect in
 * its own right, and the one this closes.
 */
export function useCanActOnOrganization(): boolean {
  const user = useAuthStore((s) => s.user);
  if (user?.organization_level !== true) return false;
  return !Array.isArray(user.reachable_tenant_ids);
}

/**
 * Whether this principal's roles are confined to particular tenants.
 *
 * Only ever true for an organization-level principal: an ordinary one has a
 * single tenant and no restriction to express.
 */
export function useIsTenantRestricted(): boolean {
  const user = useAuthStore((s) => s.user);
  return Array.isArray(user?.reachable_tenant_ids);
}
