import { useState } from "react";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import {
  AssignmentToggleError,
  assignmentInherits,
  roleService,
  type AssignmentScopeState,
  type AssignmentSubjectKind,
} from "@/services/roles";
import { getApiErrorMessage } from "@/lib/apiError";

/**
 * S-10b — changing an existing assignment's `inherit` flag from a listing.
 *
 * There is no update: `has_role` is `UNIQUE(in, out)`, so a second assign is a
 * 409 by design, and the change is `roleService.setAssignmentInherit` —
 * unassign, then assign again. The confirmation says so, says which way the
 * change moves access (a non-inheritable *deny* re-opens the subtree it used
 * to close), and keeps the dialog open with the outcome when the second call
 * fails, because "restored" and "the role is gone" are different states and
 * the operator must learn which one they are in.
 */

/** Everything needed to name, and to redo, one assignment. */
export interface InheritChangeTarget {
  kind: AssignmentSubjectKind;
  roleId: string;
  roleName: string;
  subjectId: string;
  subjectName: string;
  assignment: AssignmentScopeState & { resource_id: string };
}

/** The small row action that opens the confirmation. */
export function InheritChangeButton({
  target,
  resourceName,
  onRequest,
}: {
  target: InheritChangeTarget;
  resourceName: string;
  onRequest: (target: InheritChangeTarget) => void;
}) {
  const inherits = assignmentInherits(target.assignment);
  return (
    <button
      type="button"
      onClick={() => onRequest(target)}
      aria-label={
        inherits
          ? `Stop ${target.subjectName}'s ${target.roleName} assignment at ${resourceName}`
          : `Extend ${target.subjectName}'s ${target.roleName} assignment to the descendants of ${resourceName}`
      }
      title={
        inherits
          ? "Make this assignment apply at its resource only (inherit: false)"
          : "Make this assignment reach the resource's descendants too (inherit: true)"
      }
      className="px-2.5 py-1 rounded text-xs font-medium border border-white/10 text-muted-foreground transition-colors hover:text-foreground focus:outline-hidden focus:ring-2 focus:ring-primary/40"
    >
      {/* Worded as the action, never as the state: "This resource only" is
          the badge a non-inheritable row carries. */}
      {inherits ? "Stop here" : "Include descendants"}
    </button>
  );
}

/** The confirmation, and the two calls behind it. */
export function InheritChangeDialog({
  target,
  resourceName,
  onClose,
  onSettled,
}: {
  target: InheritChangeTarget | null;
  resourceName: string;
  onClose: () => void;
  /**
   * Called after every attempt, successful or not: a failure between the two
   * calls can still have changed what the subject holds, so the listing must
   * be re-read either way.
   */
  onSettled: () => void;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (target === null) return null;
  const next = !assignmentInherits(target.assignment);

  function close() {
    setError(null);
    onClose();
  }

  async function confirm() {
    if (target === null) return;
    setPending(true);
    setError(null);
    try {
      await roleService.setAssignmentInherit(
        target.kind,
        target.roleId,
        target.subjectId,
        target.assignment,
        next
      );
      onSettled();
      close();
    } catch (err) {
      onSettled();
      setError(
        err instanceof AssignmentToggleError
          ? err.message
          : `Nothing was changed: ${getApiErrorMessage(err, "the unassign was refused")}`
      );
    } finally {
      setPending(false);
    }
  }

  const who = `${target.kind} "${target.subjectName}"`;
  const description = next
    ? `Make the assignment of "${target.roleName}" to ${who} under "${resourceName}" and all its descendants again? ` +
      `The role is unassigned and assigned again with inherit: true; between the two calls the ${target.kind} does not hold it. ` +
      `An allow now reaches the whole subtree, and so does a deny.`
    : `Make the assignment of "${target.roleName}" to ${who} apply at "${resourceName}" only, and at none of its descendants? ` +
      `The role is unassigned and assigned again with inherit: false; between the two calls the ${target.kind} does not hold it. ` +
      `On an allow this narrows access; on a deny it re-opens the descendants the deny used to close.`;

  return (
    <ConfirmDialog
      open
      onClose={close}
      onConfirm={() => void confirm()}
      title={next ? "Include descendants" : "Apply at this resource only"}
      description={description}
      confirmLabel={next ? "Include descendants" : "Apply here only"}
      isLoading={pending}
      error={error}
    />
  );
}
