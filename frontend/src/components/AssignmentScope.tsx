import { useQuery } from "@tanstack/react-query";
import { Globe, Layers, Target } from "lucide-react";
import { useCanActOnOrganization, useIsOrganizationScope } from "@/lib/grantReach";
import { useResourceNames } from "@/hooks/useResourceNames";
import { useAuthStore } from "@/stores/auth";
import { tenantService, type Tenant } from "@/services/organizations";
import { cn } from "@/lib/utils";

/**
 * The resource scope of a role assignment, and the picker that sets it.
 *
 * A role assignment is either **global** (applies everywhere) or scoped to one
 * resource, and until the server exposed `resource_id` on its assignment reads
 * the admin UI could show neither — every assignment rendered as if it were
 * global. Two consequences made that worse than a cosmetic gap: an admin could
 * not tell what a grant actually covered, and the revoke button did not work on
 * a scoped grant at all, because `DELETE …?resource_id=` matches the null-scope
 * edge when the parameter is omitted.
 */

export interface AssignmentScopeBadgeProps {
  resourceId: string | null;
  nameFor: (id: string) => string;
  /**
   * The tenants the assignment reaches, when it names any.
   *
   * A second axis, so it gets its own badge rather than changing this one's
   * wording: an assignment can be resource-scoped *and* tenant-scoped, and a
   * single label that tried to say both would say neither clearly.
   */
  tenantScope?: string[] | null;
}

/** Says whether an assignment is global or scoped, and to what. */
export function AssignmentScopeBadge({
  resourceId,
  nameFor,
  tenantScope,
}: AssignmentScopeBadgeProps) {
  const organizationScope = useIsOrganizationScope();
  const restricted = Array.isArray(tenantScope) && tenantScope.length > 0;
  if (restricted) {
    // The reach badge replaces "Organization-wide" outright when the
    // assignment is confined, because that label would be exactly wrong: the
    // whole point of the scope is that this grant does NOT apply
    // organization-wide. A resource scope, if any, still shows beside it.
    return (
      <span className="inline-flex items-center gap-1">
        <TenantScopeBadge tenantIds={tenantScope} />
        {resourceId && (
          <span
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wide bg-cyan-500/10 text-cyan-400 border border-cyan-500/25"
            title={`Applies only under the resource "${nameFor(resourceId)}" and its descendants`}
          >
            <Target size={9} aria-hidden="true" />
            {nameFor(resourceId)}
          </span>
        )}
      </span>
    );
  }
  if (!resourceId) {
    return (
      <span
        className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wide bg-white/5 text-muted-foreground border border-white/15"
        title={
          organizationScope
            ? "Applies to every resource in every tenant of this organization — this assignment is not scoped to a resource"
            : "Applies to every resource in this tenant — this assignment is not scoped to a resource"
        }
      >
        <Globe size={9} aria-hidden="true" />
        {organizationScope ? "Organization-wide" : "Tenant-wide"}
      </span>
    );
  }
  const name = nameFor(resourceId);
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wide bg-cyan-500/10 text-cyan-400 border border-cyan-500/25"
      title={`Applies only under the resource "${name}" and its descendants`}
    >
      <Target size={9} aria-hidden="true" />
      {name}
    </span>
  );
}

export interface ResourceScopePickerProps {
  id: string;
  value: string;
  onChange: (resourceId: string) => void;
  /** What the empty option means for this dialog. */
  subject: "user" | "group" | "service account";
  disabled?: boolean;
}

/**
 * Picks the resource an assignment is scoped to. The empty value — the default
 * — is a global assignment, which is what every assignment made from this UI
 * used to be, so an admin who ignores this field gets exactly the old
 * behaviour.
 */
export function ResourceScopePicker({
  id,
  value,
  onChange,
  subject,
  disabled,
}: ResourceScopePickerProps) {
  const organizationScope = useIsOrganizationScope();
  const { resources } = useResourceNames();

  return (
    <div className="flex flex-col gap-1.5">
      <label
        htmlFor={id}
        className="text-xs font-medium uppercase tracking-wide text-muted-foreground"
      >
        Scope
      </label>
      <select
        id={id}
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
        className={cn(
          "focus-ring flex h-9 w-full rounded-md px-3 py-1 text-sm",
          "bg-white/5 border border-primary/20 text-foreground",
          "focus:border-primary transition-colors duration-200",
          disabled && "opacity-50"
        )}
      >
        <option value="">
          {organizationScope
            ? "Organization-wide — every resource in every tenant"
            : "Tenant-wide — every resource in this tenant"}
        </option>
        {resources.map((r) => (
          <option key={r.id} value={r.id}>
            {r.name}
          </option>
        ))}
      </select>
      <p className="text-xs text-muted-foreground">
        {value
          ? `The ${subject} gets this role only under the selected resource and its descendants.`
          : `The ${subject} gets this role everywhere in the tenant.`}
      </p>
    </div>
  );
}

/**
 * The tenants a restricted assignment reaches, named rather than counted where
 * there is room.
 *
 * Names are resolved from the tenant list the caller can already see, which is
 * the list the server filtered to this principal's own reach — so an id that
 * does not resolve is one this operator cannot see, and it is shown as a
 * shortened id rather than hidden. "3 tenants" that turns out to be 2 you can
 * see and 1 you cannot is the sort of quiet arithmetic that makes an access
 * review wrong.
 */
export function TenantScopeBadge({ tenantIds }: { tenantIds: string[] }) {
  const { nameFor } = useReachableTenants();
  const names = tenantIds.map(nameFor);
  const label =
    names.length <= 2 ? names.join(", ") : `${names.length} tenants`;
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wide bg-amber-500/10 text-amber-400 border border-amber-500/25"
      title={`Applies only in: ${names.join(", ")}`}
    >
      <Layers size={9} aria-hidden="true" />
      {label}
    </span>
  );
}

/**
 * The tenants of the caller's organization, for naming and for choosing.
 *
 * `GET /organizations/{org}/tenants` returns only the tenants the caller may
 * act on, so this list is already the right set to offer: an operator cannot
 * scope a grant to a tenant they cannot themselves reach, and the server would
 * refuse it anyway.
 *
 * Local to this module: both consumers are the badge and the picker below, and
 * a non-component export here would break Fast Refresh for the whole file.
 */
function useReachableTenants() {
  const orgId = useAuthStore((s) => s.user?.org_id);
  const { data: tenants = [], isLoading } = useQuery({
    queryKey: ["assignment-scope-tenants", orgId],
    enabled: Boolean(orgId),
    queryFn: () => tenantService.list(orgId as string),
  });

  const selectable = tenants.filter((t: Tenant) => t.kind !== "organization");
  const nameFor = (id: string) =>
    selectable.find((t: Tenant) => t.id === id)?.name ?? `${id.slice(0, 8)}…`;

  return { tenants: selectable, nameFor, isLoading };
}

export interface TenantScopePickerProps {
  value: string[];
  onChange: (tenantIds: string[]) => void;
  /** What the empty selection means for this dialog. */
  subject: "user" | "group" | "service account";
  disabled?: boolean;
}

/**
 * Picks the tenants an organization-level assignment reaches.
 *
 * # Why this is a separate control from the resource scope
 *
 * A resource scope narrows *what inside a tenant* a grant covers. This narrows
 * *which tenants* it covers at all, and the two compose: "auditor, on the
 * billing service, in tenants A and B" is a sentence with both. Folding them
 * into one picker would force a choice between them.
 *
 * # What it shows outside an organization scope
 *
 * In an ordinary tenant the only tenant an assignment could name is that tenant
 * itself, so the control would offer a single option that changes nothing —
 * and the server refuses the field there outright. A picker that can only be
 * wrong is worse than no picker.
 *
 * But "worse than no picker" is not the same as "worse than no words". An
 * organization administrator who has switched into a tenant is in exactly the
 * standing this feature was built for, and saw the control disappear with
 * nothing said — leaving the scope selector in the top right as an unmarked
 * prerequisite. So that one case gets a note naming it, and only that case:
 * a principal that cannot reach the organization scope at all (an ordinary
 * tenant administrator, or an organization account already confined to
 * particular tenants, which the switcher never offers the organization scope)
 * still gets nothing, because for them the note would describe a door that is
 * not there.
 *
 * The empty selection is the default and means "every tenant of the
 * organization", which is what every assignment made here meant before this
 * control existed.
 */
export function TenantScopePicker({
  value,
  onChange,
  subject,
  disabled,
}: TenantScopePickerProps) {
  const organizationScope = useIsOrganizationScope();
  const canActOnOrganization = useCanActOnOrganization();
  const { tenants, isLoading } = useReachableTenants();

  if (!organizationScope) {
    if (!canActOnOrganization) return null;
    return (
      <div className="flex flex-col gap-1.5">
        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          Tenants
        </p>
        <p className="text-xs text-muted-foreground rounded-md border border-primary/20 bg-white/5 px-3 py-2">
          Switch to{" "}
          <span className="text-foreground/80 font-medium">Organization</span>{" "}
          scope, with the selector at the top right, to confine this assignment
          to particular tenants. A role assigned from inside a tenant lives in
          that tenant and reaches it alone.
        </p>
      </div>
    );
  }

  const toggle = (id: string) => {
    onChange(
      value.includes(id) ? value.filter((t) => t !== id) : [...value, id],
    );
  };

  return (
    <fieldset className="flex flex-col gap-1.5" disabled={disabled}>
      <legend className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
        Tenants
      </legend>
      {isLoading && (
        <p className="text-xs text-muted-foreground">Loading tenants…</p>
      )}
      {!isLoading && tenants.length === 0 && (
        <p className="text-xs text-muted-foreground">
          This organization has no tenants yet.
        </p>
      )}
      {tenants.length > 0 && (
        <div className="max-h-40 overflow-y-auto rounded-md border border-primary/20 bg-white/5 divide-y divide-primary/10">
          {tenants.map((t: Tenant) => (
            <label
              key={t.id}
              className="flex items-center gap-2 px-3 py-2 text-sm cursor-pointer hover:bg-white/5"
            >
              <input
                type="checkbox"
                checked={value.includes(t.id)}
                onChange={() => toggle(t.id)}
                className="focus-ring"
              />
              <span className="truncate">{t.name}</span>
            </label>
          ))}
        </div>
      )}
      <p className="text-xs text-muted-foreground">
        {value.length === 0
          ? `The ${subject} gets this role in every tenant of the organization.`
          : `The ${subject} gets this role only in the selected tenant${
              value.length === 1 ? "" : "s"
            } — not in the organization scope itself.`}
      </p>
    </fieldset>
  );
}
