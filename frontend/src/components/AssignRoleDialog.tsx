import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { FormDialog } from "@/components/FormDialog";
import { Label } from "@/components/ui/label";
import {
  ResourceScopePicker,
  TenantScopePicker,
} from "@/components/AssignmentScope";
import { roleService, type Role } from "@/services/roles";
import { getApiErrorMessage } from "@/lib/apiError";
import { cn } from "@/lib/utils";

/**
 * Grants one role to one principal, with the scopes that grant is allowed to
 * carry.
 *
 * # Why this is shared rather than written twice
 *
 * The role detail page has always asked the question the other way round —
 * pick a *subject* for this role — and grew both scope pickers when the scopes
 * were added. The subject pages ask it as "pick a role for this user", and
 * that dialog was left behind: it posted a bare `{ user_id }` and quietly
 * produced an unrestricted grant, which at organization scope means every
 * tenant in the organization. Somebody administering a user, on the user's own
 * page, had no way to see that a scope existed, let alone set one.
 *
 * The group page had the opposite gap — it listed and revoked assignments but
 * could not make one at all, so the only route to a group's roles was through
 * whichever role you happened to guess.
 *
 * Both pages want the identical control, so it lives here rather than in two
 * places that would drift the next time a scope axis is added.
 *
 * # What it does not do
 *
 * Change an existing assignment. `has_role` is created and deleted, never
 * updated (`POST`/`DELETE` on `/roles/{role}/{subject}s`), so re-scoping a
 * grant is a revoke followed by a fresh assignment — which is what the revoke
 * control beside each assignment is for.
 */
export interface AssignRoleDialogProps {
  open: boolean;
  onClose: () => void;
  /** What kind of principal is being granted the role. Wording only. */
  subject: "user" | "group" | "service account";
  /**
   * Performs the assignment. Given the role and the two scopes the operator
   * chose — an empty `resourceId` and an empty `tenantScope` are the defaults,
   * and mean "unscoped" on both axes.
   *
   * Rejections are caught and rendered in the dialog, so this may throw.
   */
  onAssign: (
    roleId: string,
    resourceId: string,
    tenantScope: string[],
  ) => Promise<unknown>;
  /** Called after a successful assignment, to refresh whatever it changed. */
  onAssigned?: () => void;
  /** Distinguishes this dialog's error node when a page renders more than one. */
  errorId?: string;
}

export function AssignRoleDialog({
  open,
  onClose,
  subject,
  onAssign,
  onAssigned,
  errorId = "assign-role-error",
}: AssignRoleDialogProps) {
  const [selectedRoleId, setSelectedRoleId] = useState("");
  const [resourceScope, setResourceScope] = useState("");
  const [tenantScope, setTenantScope] = useState<string[]>([]);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // Only while the dialog is open: the roles list is needed to answer this
  // dialog's one question and nothing else on the page reads it.
  const { data: roles = [], isLoading } = useQuery({
    queryKey: ["roles"],
    queryFn: roleService.list,
    enabled: open,
  });

  function reset() {
    setSelectedRoleId("");
    setResourceScope("");
    setTenantScope([]);
    setError("");
  }

  function handleClose() {
    reset();
    onClose();
  }

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");
    if (!selectedRoleId) {
      setError("Please select a role.");
      return;
    }
    setSubmitting(true);
    try {
      await onAssign(selectedRoleId, resourceScope, tenantScope);
      onAssigned?.();
      reset();
      onClose();
    } catch (err: unknown) {
      // Verbatim from the server where it wrote a sentence: a 409 means the
      // principal already holds this role, which is a different thing from a
      // failure and worth saying so. `has_role` is unique on (subject, role),
      // so that answer comes back whichever scope was asked for.
      setError(getApiErrorMessage(err, "Failed to assign role."));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <FormDialog
      open={open}
      onClose={handleClose}
      title="Assign Role"
      onSubmit={handleSubmit}
      isLoading={submitting}
      submitLabel="Assign"
      error={error}
      errorId={errorId}
    >
      <div className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="assign-role-select">Role</Label>
          {isLoading ? (
            <div className="flex items-center gap-2 py-1">
              <Loader2 size={16} className="animate-spin text-primary/60" />
              <span className="text-sm text-muted-foreground">
                Loading roles…
              </span>
            </div>
          ) : roles.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No roles available. Create roles in the Roles page first.
            </p>
          ) : (
            <select
              id="assign-role-select"
              value={selectedRoleId}
              disabled={submitting}
              onChange={(e) => setSelectedRoleId(e.target.value)}
              className={cn(
                "flex h-9 w-full rounded-md px-3 py-1 text-sm",
                "bg-white/5 border border-primary/20 text-foreground",
                "focus:outline-hidden focus:ring-2 focus:ring-primary/40 focus:border-primary",
                "transition-colors duration-200",
                submitting && "opacity-50",
              )}
            >
              <option value="" disabled>
                Select a role…
              </option>
              {roles.map((role: Role) => (
                <option key={role.id} value={role.id}>
                  {role.name}
                </option>
              ))}
            </select>
          )}
        </div>

        {/* Both scopes, in the order the role detail page shows them. Each
            renders its own "unscoped" default, so an operator who ignores them
            gets exactly the grant this dialog used to make silently. */}
        <ResourceScopePicker
          id="assign-role-resource-scope"
          value={resourceScope}
          onChange={setResourceScope}
          subject={subject}
          disabled={submitting}
        />
        <TenantScopePicker
          value={tenantScope}
          onChange={setTenantScope}
          subject={subject}
          disabled={submitting}
        />
      </div>
    </FormDialog>
  );
}
