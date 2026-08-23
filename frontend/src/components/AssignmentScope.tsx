import { Globe, Target } from "lucide-react";
import { useResourceNames } from "@/hooks/useResourceNames";
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
}

/** Says whether an assignment is global or scoped, and to what. */
export function AssignmentScopeBadge({
  resourceId,
  nameFor,
}: AssignmentScopeBadgeProps) {
  if (!resourceId) {
    return (
      <span
        className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wide bg-white/5 text-muted-foreground border border-white/15"
        title="Applies everywhere — this assignment is not scoped to a resource"
      >
        <Globe size={9} aria-hidden="true" />
        Global
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
  subject: "user" | "group";
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
        <option value="">Global — applies everywhere</option>
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
