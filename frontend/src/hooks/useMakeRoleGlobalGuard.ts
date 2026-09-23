import { useState } from "react";
import {
  roleService,
  type NonInheritableAssignment,
  type Role,
} from "@/services/roles";

/**
 * S-10b — ask before a role with non-inheritable assignments is made global.
 *
 * Making a role global widens every assignment of it to every resource, and a
 * non-inheritable one most visibly: it was made to stop at its resource, and
 * afterwards it stops nowhere. That is what `is_global` means, so the server
 * accepts the change (S-10 item 6, T-285's residual); this is the confirmation
 * that names the effect, not a refusal.
 *
 * `guard` runs `proceed` straight away — no read, no dialog, exactly today's
 * save — unless the change moves `is_global` from false to true. Then it reads
 * the role's assignments from the server and asks only if one of them is
 * non-inheritable, or if the read failed (an unanswered question is not a
 * "no").
 */
export interface PendingMakeGlobal {
  roleName: string;
  /** `null` when the listings could not be read. */
  assignments: NonInheritableAssignment[] | null;
  proceed: () => void;
}

export function useMakeRoleGlobalGuard() {
  const [pending, setPending] = useState<PendingMakeGlobal | null>(null);
  const [checking, setChecking] = useState(false);

  async function guard(
    role: Pick<Role, "id" | "name" | "is_global">,
    willBeGlobal: boolean,
    proceed: () => void
  ): Promise<void> {
    if (role.is_global || !willBeGlobal) {
      proceed();
      return;
    }
    setChecking(true);
    let assignments: NonInheritableAssignment[] | null;
    try {
      assignments = await roleService.nonInheritableAssignments(role.id);
    } catch {
      assignments = null;
    } finally {
      setChecking(false);
    }
    if (assignments !== null && assignments.length === 0) {
      proceed();
      return;
    }
    setPending({ roleName: role.name, assignments, proceed });
  }

  function confirm() {
    const p = pending;
    setPending(null);
    p?.proceed();
  }

  return { guard, checking, pending, confirm, cancel: () => setPending(null) };
}
