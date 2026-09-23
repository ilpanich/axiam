import { ConfirmDialog } from "@/components/ConfirmDialog";
import { useResourceNames } from "@/hooks/useResourceNames";
import type { PendingMakeGlobal } from "@/hooks/useMakeRoleGlobalGuard";

/** How many assignments the confirmation names before it counts the rest. */
const NAMED = 3;

/**
 * The confirmation `useMakeRoleGlobalGuard` asks for. Mounted only while a
 * question is pending, so the resource names it resolves cost no request on a
 * page that never asks.
 */
export function MakeRoleGlobalConfirm({
  pending,
  onConfirm,
  onCancel,
}: {
  pending: PendingMakeGlobal | null;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  if (pending === null) return null;
  return <Question pending={pending} onConfirm={onConfirm} onCancel={onCancel} />;
}

function Question({
  pending,
  onConfirm,
  onCancel,
}: {
  pending: PendingMakeGlobal;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const { nameFor } = useResourceNames();
  const { roleName, assignments } = pending;

  let description: string;
  if (assignments === null) {
    description =
      `Could not check whether "${roleName}" has assignments made to stop at their resource (inherit: false). ` +
      `If it has, making the role global applies each of them everywhere — including the descendants they were made ` +
      `to stop short of — because a global role ignores where it is assigned. Make it global anyway?`;
  } else {
    const named = assignments
      .slice(0, NAMED)
      .map((a) => `${a.kind} "${a.name}" at "${nameFor(a.resource_id)}"`)
      .join(", ");
    const rest = assignments.length - NAMED;
    const count = assignments.length;
    description =
      `"${roleName}" has ${count} assignment${count === 1 ? "" : "s"} made to stop at ${count === 1 ? "its" : "their"} resource ` +
      `(inherit: false): ${named}${rest > 0 ? ` and ${rest} more` : ""}. ` +
      `Making the role global applies ${count === 1 ? "it" : "each of them"} everywhere — at every resource, including the ` +
      `descendants ${count === 1 ? "it was" : "they were"} made to stop short of — because a global role ignores where it ` +
      `is assigned. A deny among its grants would then deny everywhere too. Make it global anyway?`;
  }

  return (
    <ConfirmDialog
      open
      onClose={onCancel}
      onConfirm={onConfirm}
      title="Make this role global?"
      description={description}
      confirmLabel="Make global"
      cancelLabel="Keep it scoped"
    />
  );
}
