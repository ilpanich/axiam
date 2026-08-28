import { useState } from "react";
import { useParams } from "react-router";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  roleService,
  type RoleGroupAssignment,
  type RoleServiceAccountAssignment,
  type RoleUserAssignment,
  type UpdateRolePayload,
} from "@/services/roles";
import {
  permissionService,
  isElevatedPermission,
  type GrantedScope,
  type Permission,
  type PermissionEffect,
} from "@/services/permissions";
import { groupService, type Group } from "@/services/users";
import {
  serviceAccountService,
  type ServiceAccount,
} from "@/services/serviceAccounts";
import { resourceService } from "@/services/resources";
import { scopeService } from "@/services/scopes";
import { useToast } from "@/hooks/useToast";
import { getApiErrorMessage } from "@/lib/apiError";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { UserSearchDialog } from "@/components/UserSearchDialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Loader2,
  Plus,
  Unlink,
  Search,
  Pencil,
  Trash2,
  Ban,
  Filter,
  AlertTriangle,
} from "lucide-react";
import { cn, formatDate } from "@/lib/utils";
import { Textarea } from "@/components/ui/textarea";
import { SectionCard, InfoRow, ActionBadge } from "@/components/shared";
import {
  AssignmentScopeBadge,
  ResourceScopePicker,
} from "@/components/AssignmentScope";
import { useResourceNames } from "@/hooks/useResourceNames";
import { invalidateEntity } from "@/lib/queryInvalidation";

// ─── Scope chips ──────────────────────────────────────────────────────────────

/**
 * The scopes a grant is narrowed to, named.
 *
 * This was a single chip reading "3 scopes" beside a filter icon. It told an
 * operator their grant was constrained and gave them no way to learn to what:
 * the only route to the answer was opening the resource, listing its scopes and
 * matching UUIDs by eye — for a fact the row itself is about.
 *
 * Names are shown up to `MAX_VISIBLE`, then a "+N more" chip carrying the rest
 * in its tooltip. A grant narrowed to a dozen scopes is unusual and rendering
 * all of them inline would push the description column off the row, but the
 * information stays reachable without leaving the page.
 *
 * When the server resolved nothing — an older API, or every named scope since
 * deleted — this falls back to the original count chip rather than rendering an
 * empty row: the grant IS still scoped, and saying nothing would make it look
 * like a wildcard, which overstates what it allows (or, for a deny, what it
 * masks).
 */
const MAX_VISIBLE_SCOPES = 3;

function ScopeChips({
  count,
  scopes,
}: {
  count: number;
  scopes: GrantedScope[];
}) {
  const chipClass =
    "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium tracking-wide bg-white/5 text-muted-foreground border border-white/15";

  if (scopes.length === 0) {
    return (
      <span
        className={cn(chipClass, "uppercase")}
        title="Constrained to specific scopes of a resource"
      >
        <Filter size={9} aria-hidden="true" />
        {count} scope{count === 1 ? "" : "s"}
      </span>
    );
  }

  const visible = scopes.slice(0, MAX_VISIBLE_SCOPES);
  const hidden = scopes.slice(MAX_VISIBLE_SCOPES);

  return (
    <span className="inline-flex items-center gap-1 flex-wrap">
      <Filter
        size={9}
        className="text-muted-foreground"
        aria-hidden="true"
      />
      <span className="sr-only">
        Constrained to {count} scope{count === 1 ? "" : "s"}:
      </span>
      {visible.map((scope) => (
        <span key={scope.id} className={chipClass} title={`Scope: ${scope.name}`}>
          <code className="font-mono">{scope.name}</code>
        </span>
      ))}
      {hidden.length > 0 && (
        <span
          className={chipClass}
          title={hidden.map((s) => s.name).join(", ")}
        >
          +{hidden.length} more
        </span>
      )}
    </span>
  );
}

// ─── Grant Permission dialog ──────────────────────────────────────────────────

interface GrantPermissionDialogProps {
  open: boolean;
  onClose: () => void;
  roleId: string;
  grantedPermissionIds: Set<string>;
  onGranted: () => void;
}

function GrantPermissionDialog({
  open,
  onClose,
  roleId,
  grantedPermissionIds,
  onGranted,
}: GrantPermissionDialogProps) {
  const [search, setSearch] = useState("");
  const [grantingId, setGrantingId] = useState<string | null>(null);
  // B1/C4: which kind of rule the next grant writes. Defaults to allow, which
  // is what every grant meant before deny-override existed.
  const [effect, setEffect] = useState<PermissionEffect>("allow");
  // C4 scope constraint. Scopes live under a resource, and there is no
  // tenant-wide scope listing, so narrowing a grant means picking the resource
  // first. Empty selection = the wildcard the server defaults to.
  const [scopeResourceId, setScopeResourceId] = useState("");
  const [scopeIds, setScopeIds] = useState<string[]>([]);

  const { data: allPermissions = [], isLoading } = useQuery({
    queryKey: ["permissions"],
    queryFn: () => permissionService.list(),
    enabled: open,
  });

  const { data: resources = [] } = useQuery({
    queryKey: ["resources"],
    queryFn: () => resourceService.list(),
    enabled: open,
  });

  const { data: scopes = [], isLoading: scopesLoading } = useQuery({
    queryKey: ["scopes", scopeResourceId],
    queryFn: () => scopeService.list(scopeResourceId),
    enabled: open && scopeResourceId !== "",
  });

  const filtered = allPermissions.filter(
    (p) =>
      p.action.toLowerCase().includes(search.toLowerCase()) ||
      (p.description ?? "").toLowerCase().includes(search.toLowerCase())
  );

  async function handleGrant(permission: Permission) {
    setGrantingId(permission.id);
    try {
      await roleService.grantPermission(roleId, permission.id, effect, scopeIds);
      onGranted();
    } catch {
      // parent will refetch
    } finally {
      setGrantingId(null);
    }
  }

  function handleClose() {
    setSearch("");
    setScopeResourceId("");
    setScopeIds([]);
    onClose();
  }

  function toggleScope(id: string) {
    setScopeIds((prev) =>
      prev.includes(id) ? prev.filter((s) => s !== id) : [...prev, id]
    );
  }

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      aria-modal="true"
      role="dialog"
      aria-labelledby="grant-permission-title"
    >
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-xs"
        onClick={handleClose}
        aria-hidden="true"
      />
      <div className="relative z-10 glass-card w-full max-w-md flex flex-col max-h-[80vh]">
        <div className="flex items-center justify-between pb-4 border-b border-primary/10">
          <h2
            id="grant-permission-title"
            className="text-lg font-semibold text-foreground"
          >
            Grant Permission
          </h2>
          <button
            onClick={handleClose}
            className="text-muted-foreground hover:text-foreground transition-colors rounded p-1 focus:outline-hidden focus:ring-2 focus:ring-primary/40"
            aria-label="Close dialog"
          >
            ✕
          </button>
        </div>

        <div className="py-4 flex flex-col gap-3 overflow-hidden">
          <div className="relative">
            <Search
              size={15}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none"
              aria-hidden="true"
            />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter permissions…"
              aria-label="Filter permissions"
              className={cn(
                "h-9 w-full rounded-md pl-9 pr-3 text-sm",
                "bg-white/5 border border-primary/20 text-foreground",
                "placeholder:text-muted-foreground",
                "focus:outline-hidden focus:ring-2 focus:ring-primary/40 focus:border-primary",
                "transition-colors duration-200"
              )}
            />
          </div>

          <div className="overflow-y-auto flex-1 min-h-[120px] max-h-60 rounded-md border border-white/5">
            {/* B1: effect selector. Deny is NOT styled as "a red allow" -- it
                is the rule that beats every allow, at any depth, so the
                control states that outright rather than leaving an admin to
                infer precedence from a colour. */}
            <fieldset className="px-3 py-3 border-b border-white/5">
              <legend className="sr-only">Grant effect</legend>
              <div className="flex gap-2" role="radiogroup" aria-label="Grant effect">
                {(["allow", "deny"] as const).map((value) => (
                  <button
                    key={value}
                    type="button"
                    role="radio"
                    aria-checked={effect === value}
                    onClick={() => setEffect(value)}
                    className={
                      effect === value
                        ? value === "deny"
                          ? "focus-ring px-3 py-1.5 text-xs font-semibold rounded border bg-destructive/20 text-destructive border-destructive/40"
                          : "focus-ring px-3 py-1.5 text-xs font-semibold rounded border bg-primary/20 text-primary border-primary/40"
                        : "focus-ring px-3 py-1.5 text-xs rounded border border-white/10 text-muted-foreground hover:bg-white/5"
                    }
                  >
                    {value === "deny" ? "Deny" : "Allow"}
                  </button>
                ))}
              </div>
              {effect === "deny" && (
                <p role="note" className="mt-2 text-xs text-destructive/90">
                  A deny rule overrides <strong>every</strong> allow for this
                  action — including allows granted lower in the resource tree.
                  It cannot be undone by adding another allow; remove the deny
                  instead.
                </p>
              )}
            </fieldset>

            {/* C4: optional scope constraint. Left alone the grant keeps the
                wildcard it has always had. */}
            <fieldset className="px-3 py-3 border-b border-white/5 space-y-2">
              <legend className="sr-only">Scope constraint</legend>
              <Label htmlFor="grant-scope-resource" className="text-xs">
                Limit to scopes (optional)
              </Label>
              <select
                id="grant-scope-resource"
                value={scopeResourceId}
                onChange={(e) => {
                  setScopeResourceId(e.target.value);
                  setScopeIds([]);
                }}
                className="focus-ring w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground"
              >
                <option value="">Every scope (unscoped grant)</option>
                {resources.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name}
                  </option>
                ))}
              </select>

              {scopeResourceId !== "" &&
                (scopesLoading ? (
                  <p className="text-xs text-muted-foreground">Loading scopes…</p>
                ) : scopes.length === 0 ? (
                  <p className="text-xs text-muted-foreground">
                    This resource defines no scopes. The grant will cover every
                    scope.
                  </p>
                ) : (
                  <div className="space-y-1">
                    {scopes.map((scope) => (
                      <label
                        key={scope.id}
                        className="flex items-center gap-2 text-xs text-foreground cursor-pointer"
                      >
                        <input
                          type="checkbox"
                          checked={scopeIds.includes(scope.id)}
                          onChange={() => toggleScope(scope.id)}
                          className="h-3.5 w-3.5 rounded border-primary/40 bg-white/5 text-primary focus:ring-primary/40"
                        />
                        <span className="font-mono">{scope.name}</span>
                      </label>
                    ))}
                    {effect === "deny" && scopeIds.length > 0 && (
                      <p role="note" className="text-xs text-destructive/90">
                        A scoped deny masks only the scopes you name. Leave the
                        selection empty to mask the action entirely.
                      </p>
                    )}
                  </div>
                ))}
            </fieldset>

            {isLoading ? (
              <div className="flex items-center justify-center py-6">
                <Loader2 size={20} className="animate-spin text-primary/60" />
              </div>
            ) : filtered.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-6">
                No permissions found.
              </p>
            ) : (
              <ul>
                {filtered.map((perm) => {
                  const alreadyGranted = grantedPermissionIds.has(perm.id);
                  const elevated = isElevatedPermission(perm);
                  return (
                    <li
                      key={perm.id}
                      className="flex items-center justify-between px-3 py-2.5 hover:bg-white/5 border-b border-white/5 last:border-0"
                    >
                      <div>
                        <div className="flex items-center gap-2">
                          <ActionBadge action={perm.action} />
                          {elevated && (
                            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] font-medium bg-amber-500/15 text-amber-400 border border-amber-500/30">
                              <AlertTriangle size={11} aria-hidden="true" />
                              Elevated
                            </span>
                          )}
                        </div>
                        {perm.description && (
                          <p
                            className={cn(
                              "text-xs mt-0.5",
                              // An elevated grant reads as ordinary help text
                              // otherwise — see isElevatedPermission.
                              elevated
                                ? "text-amber-400/90"
                                : "text-muted-foreground"
                            )}
                          >
                            {perm.description}
                          </p>
                        )}
                      </div>
                      {alreadyGranted ? (
                        <span className="text-xs text-muted-foreground">
                          Granted
                        </span>
                      ) : (
                        <button
                          onClick={() => handleGrant(perm)}
                          disabled={grantingId === perm.id}
                          className="flex items-center gap-1 text-xs px-2.5 py-1 rounded bg-primary/20 text-primary hover:bg-primary/30 transition-colors disabled:opacity-50"
                        >
                          {grantingId === perm.id ? (
                            <Loader2 size={12} className="animate-spin" />
                          ) : (
                            <Plus size={12} />
                          )}
                          {effect === "deny" ? "Deny" : "Grant"}
                        </button>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </div>

        <div className="flex justify-end pt-4 border-t border-primary/10">
          <Button variant="ghost" onClick={handleClose}>
            Done
          </Button>
        </div>
      </div>
    </div>
  );
}

// ─── Assign Group dialog ──────────────────────────────────────────────────────

interface AssignGroupDialogProps {
  open: boolean;
  onClose: () => void;
  roleId: string;
  onAssigned: () => void;
}

function AssignGroupDialog({
  open,
  onClose,
  roleId,
  onAssigned,
}: AssignGroupDialogProps) {
  const [selectedGroupId, setSelectedGroupId] = useState("");
  // "" is a global assignment — the only kind this dialog could make before.
  const [scopeResourceId, setScopeResourceId] = useState("");
  const [assigning, setAssigning] = useState(false);
  const [error, setError] = useState("");

  const { data: groups = [], isLoading } = useQuery({
    queryKey: ["groups"],
    queryFn: () => groupService.list(),
    enabled: open,
  });

  async function handleAssign(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!selectedGroupId) {
      setError("Please select a group.");
      return;
    }
    setAssigning(true);
    setError("");
    try {
      await roleService.assignToGroup(roleId, selectedGroupId, scopeResourceId);
      onAssigned();
      setSelectedGroupId("");
      setScopeResourceId("");
      onClose();
    } catch (err) {
      // Surfaced verbatim: the server refuses a second assignment of the same
      // role to the same group with 409 whatever scope is asked for, and
      // "Failed to assign group" would hide which of the two it was.
      setError(getApiErrorMessage(err));
    } finally {
      setAssigning(false);
    }
  }

  function handleClose() {
    setSelectedGroupId("");
    setScopeResourceId("");
    setError("");
    onClose();
  }

  return (
    <FormDialog
      open={open}
      onClose={handleClose}
      title="Assign Group"
      onSubmit={handleAssign}
      isLoading={assigning}
      submitLabel="Assign"
      error={error}
      errorId="assign-group-error"
    >
      <div className="space-y-2">
        <Label htmlFor="assign-group-select">Group</Label>
        {isLoading ? (
          <div className="flex items-center gap-2 py-2 text-sm text-muted-foreground">
            <Loader2 size={14} className="animate-spin" />
            Loading groups…
          </div>
        ) : (
          <select
            id="assign-group-select"
            value={selectedGroupId}
            onChange={(e) => setSelectedGroupId(e.target.value)}
            className={cn(
              "flex h-9 w-full rounded-md px-3 py-1 text-sm",
              "bg-white/5 border border-primary/20 text-foreground",
              "focus:outline-hidden focus:ring-2 focus:ring-primary/40 focus:border-primary",
              "transition-colors duration-200"
            )}
          >
            <option value="">Select a group…</option>
            {groups.map((g: Group) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </select>
        )}
      </div>
      <div className="mt-4">
        <ResourceScopePicker
          id="assign-group-scope"
          value={scopeResourceId}
          onChange={setScopeResourceId}
          subject="group"
        />
      </div>
    </FormDialog>
  );
}

interface AssignServiceAccountDialogProps {
  open: boolean;
  onClose: () => void;
  roleId: string;
  onAssigned: () => void;
}

/**
 * Grant this role to a machine identity.
 *
 * The engine has always applied RBAC to a service account exactly as it does to
 * a person — it takes no flag to branch on — but nothing could create the grant,
 * so the only way to give a machine permissions was to hand it a human's
 * account. This dialog is the missing half.
 */
function AssignServiceAccountDialog({
  open,
  onClose,
  roleId,
  onAssigned,
}: AssignServiceAccountDialogProps) {
  const [selectedId, setSelectedId] = useState("");
  // "" is a global assignment, the same default the user and group dialogs use.
  const [scopeResourceId, setScopeResourceId] = useState("");
  const [assigning, setAssigning] = useState(false);
  const [error, setError] = useState("");

  const { data: serviceAccounts = [], isLoading } = useQuery({
    queryKey: ["service-accounts"],
    queryFn: () => serviceAccountService.getAll(),
    enabled: open,
  });

  async function handleAssign(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!selectedId) {
      setError("Please select a service account.");
      return;
    }
    setAssigning(true);
    setError("");
    try {
      await roleService.assignToServiceAccount(roleId, selectedId, scopeResourceId);
      onAssigned();
      setSelectedId("");
      setScopeResourceId("");
      onClose();
    } catch (err) {
      // Verbatim, for the same reason the group dialog is: a 409 means this
      // account already holds the role, whichever scope was asked for, and a
      // generic message would hide which of the two failures it was.
      setError(getApiErrorMessage(err));
    } finally {
      setAssigning(false);
    }
  }

  function handleClose() {
    setSelectedId("");
    setScopeResourceId("");
    setError("");
    onClose();
  }

  return (
    <FormDialog
      open={open}
      onClose={handleClose}
      title="Assign Service Account"
      onSubmit={handleAssign}
      isLoading={assigning}
      submitLabel="Assign"
      error={error}
      errorId="assign-service-account-error"
    >
      <div className="space-y-2">
        <Label htmlFor="assign-service-account-select">Service account</Label>
        {isLoading ? (
          <div className="flex items-center gap-2 py-2 text-sm text-muted-foreground">
            <Loader2 size={14} className="animate-spin" />
            Loading service accounts…
          </div>
        ) : (
          <select
            id="assign-service-account-select"
            value={selectedId}
            onChange={(e) => setSelectedId(e.target.value)}
            className={cn(
              "flex h-9 w-full rounded-md px-3 py-1 text-sm",
              "bg-white/5 border border-primary/20 text-foreground",
              "focus:outline-hidden focus:ring-2 focus:ring-primary/40 focus:border-primary",
              "transition-colors duration-200"
            )}
          >
            <option value="">Select a service account…</option>
            {serviceAccounts.map((sa: ServiceAccount) => (
              <option key={sa.id} value={sa.id}>
                {sa.name}
              </option>
            ))}
          </select>
        )}
      </div>
      <div className="mt-4">
        <ResourceScopePicker
          id="assign-service-account-scope"
          value={scopeResourceId}
          onChange={setScopeResourceId}
          subject="service account"
        />
      </div>
    </FormDialog>
  );
}

// ─── Edit Role form ───────────────────────────────────────────────────────────

interface EditRoleFormProps {
  name: string;
  description: string;
  isGlobal: boolean;
  onNameChange: (v: string) => void;
  onDescriptionChange: (v: string) => void;
  onIsGlobalChange: (v: boolean) => void;
}

function EditRoleForm({
  name,
  description,
  isGlobal,
  onNameChange,
  onDescriptionChange,
  onIsGlobalChange,
}: EditRoleFormProps) {
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor="detail-edit-name">Name *</Label>
        <Input
          id="detail-edit-name"
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          required
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="detail-edit-desc">Description</Label>
        <Textarea
          id="detail-edit-desc"
          value={description}
          onChange={(e) => onDescriptionChange(e.target.value)}
          rows={3}
        />
      </div>
      <div className="flex items-center gap-3">
        <input
          type="checkbox"
          id="detail-edit-is-global"
          checked={isGlobal}
          onChange={(e) => onIsGlobalChange(e.target.checked)}
          className="w-4 h-4 accent-cyan-400 cursor-pointer"
        />
        <Label htmlFor="detail-edit-is-global" className="cursor-pointer">
          Global role
        </Label>
      </div>
    </>
  );
}

// ─── Assignments tabs ─────────────────────────────────────────────────────────

type AssignmentTab = "users" | "groups" | "service accounts";

// ─── Main page ─────────────────────────────────────────────────────────────────

export function RoleDetailPage() {
  const { roleId } = useParams<{ roleId: string }>();
  const queryClient = useQueryClient();
  const { toast } = useToast();

  // ─── Role query ────────────────────────────────────────────────────────────
  const {
    data: role,
    isLoading: roleLoading,
    error: roleError,
  } = useQuery({
    queryKey: ["role", roleId],
    queryFn: () => roleService.get(roleId!),
    enabled: !!roleId,
  });

  // ─── Permissions query ─────────────────────────────────────────────────────
  const { data: grantedPermissions = [], isLoading: permissionsLoading } =
    useQuery({
      queryKey: ["role-permissions", roleId],
      queryFn: () => roleService.listPermissions(roleId!),
      enabled: !!roleId,
    });

  const grantedPermissionIds = new Set(
    grantedPermissions.map((g) => g.permission.id)
  );

  // B1: permission id -> effect, so the table can mark deny rules. Grants
  // written before deny-override carry no `effect` and mean allow.
  // C4: how many scopes each grant is constrained to. Zero is the wildcard, so
  // only a non-zero count is worth a badge.
  const grantScopeCounts = new Map<string, number>(
    grantedPermissions.map((g) => [g.permission.id, g.scope_ids?.length ?? 0])
  );

  // The scopes themselves, so a scoped grant can say WHICH scopes it covers.
  // A bare "3 scopes" chip told an operator their grant was narrowed and gave
  // them no way to find out to what — they had to go to the resource, list its
  // scopes, and match ids by eye. The API resolves the names now; this renders
  // them.
  const grantScopes = new Map<string, GrantedScope[]>(
    grantedPermissions.map((g) => [g.permission.id, g.scopes ?? []])
  );

  const grantEffects = new Map<string, PermissionEffect>(
    grantedPermissions.map((g) => [g.permission.id, g.effect ?? "allow"])
  );

  // Flatten grants to the underlying permissions for the table.
  const grantedPermissionList: Permission[] = grantedPermissions.map(
    (g) => g.permission
  );

  // ─── Edit state ────────────────────────────────────────────────────────────
  const [editOpen, setEditOpen] = useState(false);
  const [editName, setEditName] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editIsGlobal, setEditIsGlobal] = useState(false);
  const [editError, setEditError] = useState("");

  const editMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: UpdateRolePayload }) =>
      roleService.update(id, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["role", roleId] });
      void queryClient.invalidateQueries({ queryKey: ["roles"] });
      setEditOpen(false);
    },
    onError: (err: unknown) => {
      setEditError(
        err instanceof Error ? err.message : "Failed to update role."
      );
    },
  });

  function openEdit() {
    if (!role) return;
    setEditName(role.name);
    setEditDescription(role.description ?? "");
    setEditIsGlobal(role.is_global);
    setEditError("");
    setEditOpen(true);
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setEditError("");
    if (!editName.trim()) {
      setEditError("Name is required.");
      return;
    }
    editMutation.mutate({
      id: roleId!,
      payload: {
        name: editName.trim(),
        description: editDescription.trim() || undefined,
        is_global: editIsGlobal,
      },
    });
  }

  // ─── Revoke permission ─────────────────────────────────────────────────────
  const [revokePermission, setRevokePermission] = useState<Permission | null>(
    null
  );

  const revokeMutation = useMutation({
    mutationFn: (permissionId: string) =>
      roleService.revokePermission(roleId!, permissionId),
    onSuccess: () => {
      invalidateEntity(queryClient, "role-permissions");
      setRevokePermission(null);
    },
  });

  // ─── Grant permission dialog ───────────────────────────────────────────────
  const [grantOpen, setGrantOpen] = useState(false);

  function handlePermissionGranted() {
    invalidateEntity(queryClient, "role-permissions");
  }

  // ─── Assignments state ─────────────────────────────────────────────────────
  const [assignmentTab, setAssignmentTab] = useState<AssignmentTab>("users");
  const [assignUserOpen, setAssignUserOpen] = useState(false);
  const [assignGroupOpen, setAssignGroupOpen] = useState(false);
  const [assignServiceAccountOpen, setAssignServiceAccountOpen] = useState(false);

  // ─── Assigned users/groups ─────────────────────────────────────────────────
  const { data: assignedUsers = [], isLoading: usersLoading } = useQuery({
    queryKey: ["role-users", roleId],
    queryFn: () => roleService.listUsers(roleId!),
    enabled: !!roleId,
  });

  const { data: assignedGroups = [], isLoading: groupsLoading } = useQuery({
    queryKey: ["role-groups", roleId],
    queryFn: () => roleService.listGroups(roleId!),
    enabled: !!roleId,
  });

  // A service account is a principal like any other, and the engine has always
  // treated it as one — there was simply no way to create the grant, so a
  // machine identity could authenticate and then do nothing.
  const {
    data: assignedServiceAccounts = [],
    isLoading: serviceAccountsLoading,
  } = useQuery({
    queryKey: ["role-service-accounts", roleId],
    queryFn: () => roleService.listServiceAccounts(roleId!),
    enabled: !!roleId,
  });

  // The unassign targets are *assignments*, not subjects: the scope has to
  // travel with the confirm dialog, because an unassign that drops it removes
  // the global grant instead — and against a scoped assignment removes nothing
  // while still answering 204.
  const [unassignUser, setUnassignUser] =
    useState<RoleUserAssignment | null>(null);
  const [unassignGroup, setUnassignGroup] =
    useState<RoleGroupAssignment | null>(null);
  const [unassignServiceAccount, setUnassignServiceAccount] =
    useState<RoleServiceAccountAssignment | null>(null);

  // Resource names for the scope badges on both member lists.
  const { nameFor } = useResourceNames();

  const unassignUserMutation = useMutation({
    mutationFn: (a: RoleUserAssignment) =>
      roleService.unassignFromUser(roleId!, a.user.id, a.resource_id),
    onSuccess: () => {
      invalidateEntity(queryClient, "role-users");
      setUnassignUser(null);
    },
    onError: (err: unknown) => {
      toast({ description: getApiErrorMessage(err), variant: "destructive" });
    },
  });

  const unassignGroupMutation = useMutation({
    mutationFn: (a: RoleGroupAssignment) =>
      roleService.unassignFromGroup(roleId!, a.group.id, a.resource_id),
    onSuccess: () => {
      invalidateEntity(queryClient, "role-groups");
      setUnassignGroup(null);
    },
    onError: (err: unknown) => {
      toast({ description: getApiErrorMessage(err), variant: "destructive" });
    },
  });

  const unassignServiceAccountMutation = useMutation({
    mutationFn: (a: RoleServiceAccountAssignment) =>
      roleService.unassignFromServiceAccount(
        roleId!,
        a.service_account.id,
        a.resource_id
      ),
    onSuccess: () => {
      invalidateEntity(queryClient, "role-service-accounts");
      setUnassignServiceAccount(null);
    },
    onError: (err: unknown) => {
      toast({ description: getApiErrorMessage(err), variant: "destructive" });
    },
  });

  // Scope of the next user assignment. "" is global — the old behaviour.
  const [assignUserScope, setAssignUserScope] = useState("");

  // ─── Permissions table columns ─────────────────────────────────────────────
  const permissionColumns: Column<Permission>[] = [
    {
      key: "action",
      header: "Permission",
      render: (row) => (
        <div className="flex items-center gap-2">
          <ActionBadge action={row.action} />
          {/* B1: a deny rule that looked like every other row would be the
              worst outcome of shipping deny-override -- it is the one rule
              that changes what all the others mean. */}
          {grantEffects.get(row.id) === "deny" && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wide bg-destructive/20 text-destructive border border-destructive/40">
              <Ban size={9} aria-hidden="true" />
              Deny
            </span>
          )}
          {/* C4: a scoped grant covers only the scopes it names, so a row that
              looked identical to a wildcard grant would overstate what it
              allows (or, for a deny, what it masks). */}
          {(grantScopeCounts.get(row.id) ?? 0) > 0 && (
            <ScopeChips
              count={grantScopeCounts.get(row.id) ?? 0}
              scopes={grantScopes.get(row.id) ?? []}
            />
          )}
        </div>
      ),
    },
    {
      key: "description",
      header: "Description",
      render: (row) => (
        <span className="text-muted-foreground text-sm">
          {row.description ?? <span className="opacity-40">—</span>}
        </span>
      ),
    },
    {
      key: "created_at",
      header: "Granted",
      render: (row) => (
        <span className="text-muted-foreground text-sm">
          {formatDate(row.created_at)}
        </span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      width: "w-16",
      render: (row) => (
        <button
          aria-label={`Revoke ${row.action}`}
          onClick={() => setRevokePermission(row)}
          className="p-1.5 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors"
          title="Revoke permission"
        >
          <Unlink size={14} />
        </button>
      ),
    },
  ];

  // ─── Loading / error states ────────────────────────────────────────────────
  if (roleLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 size={28} className="animate-spin text-primary/60" />
      </div>
    );
  }

  if (roleError || !role) {
    return (
      <div className="glass-card text-center py-12 text-muted-foreground">
        Role not found or failed to load.
      </div>
    );
  }

  return (
    <div className="max-w-4xl">
      {/* ── Section 1: Role Info ── */}
      <SectionCard
        title="Role Info"
        action={
          <Button size="sm" variant="ghost" onClick={openEdit}>
            <Pencil size={14} className="mr-1" />
            Edit
          </Button>
        }
      >
        <InfoRow label="Name">{role.name}</InfoRow>
        <InfoRow label="Description">
          {role.description ?? <span className="opacity-40">—</span>}
        </InfoRow>
        <InfoRow label="Scope">
          <span
            className={cn(
              "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border",
              role.is_global
                ? "bg-purple-500/15 text-purple-400 border-purple-500/30"
                : "bg-cyan-500/10 text-cyan-400 border-cyan-500/20"
            )}
          >
            {role.is_global ? "Global" : "Tenant"}
          </span>
        </InfoRow>
        <InfoRow label="Created">{formatDate(role.created_at)}</InfoRow>
      </SectionCard>

      {/* ── Section 2: Permissions ── */}
      <SectionCard
        title="Permissions"
        action={
          <Button size="sm" onClick={() => setGrantOpen(true)}>
            <Plus size={14} className="mr-1" />
            Grant Permission
          </Button>
        }
      >
        <DataTable
          columns={permissionColumns}
          data={grantedPermissionList}
          isLoading={permissionsLoading}
          emptyMessage="No permissions granted to this role."
        />
      </SectionCard>

      {/* ── Section 3: Assignments ── */}
      <SectionCard
        title="Assignments"
        action={
          assignmentTab === "users" ? (
            <Button size="sm" onClick={() => setAssignUserOpen(true)}>
              <Plus size={14} className="mr-1" />
              Assign User
            </Button>
          ) : assignmentTab === "groups" ? (
            <Button size="sm" onClick={() => setAssignGroupOpen(true)}>
              <Plus size={14} className="mr-1" />
              Assign Group
            </Button>
          ) : (
            <Button size="sm" onClick={() => setAssignServiceAccountOpen(true)}>
              <Plus size={14} className="mr-1" />
              Assign Service Account
            </Button>
          )
        }
      >
        {/* Tabs */}
        <div className="flex gap-1 mb-4 border-b border-white/10">
          {(["users", "groups", "service accounts"] as AssignmentTab[]).map((tab) => (
            <button
              key={tab}
              onClick={() => setAssignmentTab(tab)}
              className={cn(
                "px-4 py-2 text-sm font-medium capitalize transition-colors",
                assignmentTab === tab
                  ? "text-primary border-b-2 border-primary -mb-px"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              {tab}
            </button>
          ))}
        </div>

        {assignmentTab === "users" && (
          usersLoading ? (
            <div className="flex items-center justify-center py-6">
              <Loader2 size={20} className="animate-spin text-primary/60" />
            </div>
          ) : assignedUsers.length === 0 ? (
            <div className="py-4 text-sm text-muted-foreground text-center">
              <p>No users assigned. Use "Assign User" to grant this role.</p>
            </div>
          ) : (
            <ul className="divide-y divide-white/5">
              {assignedUsers.map((a) => (
                <li
                  key={`${a.user.id}:${a.resource_id ?? "global"}`}
                  className="flex items-center justify-between py-2.5 px-1"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-medium text-foreground/90">{a.user.display_name ?? a.user.username}</p>
                      <AssignmentScopeBadge
                        resourceId={a.resource_id}
                        nameFor={nameFor}
                      />
                    </div>
                    <p className="text-xs text-muted-foreground">{a.user.email}</p>
                  </div>
                  <button
                    aria-label={`Unassign ${a.user.username}`}
                    onClick={() => setUnassignUser(a)}
                    className="p-1.5 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors"
                  >
                    <Unlink size={14} />
                  </button>
                </li>
              ))}
            </ul>
          )
        )}

        {assignmentTab === "groups" && (
          groupsLoading ? (
            <div className="flex items-center justify-center py-6">
              <Loader2 size={20} className="animate-spin text-primary/60" />
            </div>
          ) : assignedGroups.length === 0 ? (
            <div className="py-4 text-sm text-muted-foreground text-center">
              <p>No groups assigned. Use "Assign Group" to grant this role.</p>
            </div>
          ) : (
            <ul className="divide-y divide-white/5">
              {assignedGroups.map((a) => (
                <li
                  key={`${a.group.id}:${a.resource_id ?? "global"}`}
                  className="flex items-center justify-between py-2.5 px-1"
                >
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-medium text-foreground/90">{a.group.name}</p>
                    <AssignmentScopeBadge
                      resourceId={a.resource_id}
                      nameFor={nameFor}
                    />
                  </div>
                  <button
                    aria-label={`Unassign group ${a.group.name}`}
                    onClick={() => setUnassignGroup(a)}
                    className="p-1.5 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors"
                  >
                    <Unlink size={14} />
                  </button>
                </li>
              ))}
            </ul>
          )
        )}

        {assignmentTab === "service accounts" && (
          serviceAccountsLoading ? (
            <div className="flex items-center justify-center py-6">
              <Loader2 size={20} className="animate-spin text-primary/60" />
            </div>
          ) : assignedServiceAccounts.length === 0 ? (
            <div className="py-4 text-sm text-muted-foreground text-center">
              <p>
                No service accounts assigned. Use &quot;Assign Service
                Account&quot; to grant this role to a machine identity.
              </p>
            </div>
          ) : (
            <ul className="divide-y divide-white/5">
              {assignedServiceAccounts.map((a) => (
                <li
                  key={`${a.service_account.id}:${a.resource_id ?? "global"}`}
                  className="flex items-center justify-between py-2.5 px-1"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-medium text-foreground/90">
                        {a.service_account.name}
                      </p>
                      <AssignmentScopeBadge
                        resourceId={a.resource_id}
                        nameFor={nameFor}
                      />
                    </div>
                    <p className="text-xs text-muted-foreground font-mono">
                      {a.service_account.client_id}
                    </p>
                  </div>
                  <button
                    aria-label={`Unassign service account ${a.service_account.name}`}
                    onClick={() => setUnassignServiceAccount(a)}
                    className="p-1.5 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors"
                  >
                    <Unlink size={14} />
                  </button>
                </li>
              ))}
            </ul>
          )
        )}
      </SectionCard>

      {/* Edit dialog */}
      <FormDialog
        open={editOpen}
        onClose={() => setEditOpen(false)}
        title="Edit Role"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
        error={editError}
        errorId="role-detail-edit-error"
      >
        <EditRoleForm
          name={editName}
          description={editDescription}
          isGlobal={editIsGlobal}
          onNameChange={setEditName}
          onDescriptionChange={setEditDescription}
          onIsGlobalChange={setEditIsGlobal}
        />
      </FormDialog>

      {/* Revoke permission confirm */}
      <ConfirmDialog
        open={revokePermission !== null}
        onClose={() => setRevokePermission(null)}
        onConfirm={() =>
          revokePermission && revokeMutation.mutate(revokePermission.id)
        }
        title="Revoke Permission"
        description={`Remove permission "${revokePermission?.action}" from this role?`}
        isLoading={revokeMutation.isPending}
      />

      {/* Grant permission dialog */}
      <GrantPermissionDialog
        open={grantOpen}
        onClose={() => setGrantOpen(false)}
        roleId={roleId!}
        grantedPermissionIds={grantedPermissionIds}
        onGranted={handlePermissionGranted}
      />

      {/* Assign user dialog */}
      <UserSearchDialog
        open={assignUserOpen}
        onClose={() => {
          setAssignUserOpen(false);
          setAssignUserScope("");
        }}
        title="Assign User"
        actionLabel="Assign"
        header={
          <ResourceScopePicker
            id="assign-user-scope"
            value={assignUserScope}
            onChange={setAssignUserScope}
            subject="user"
          />
        }
        onAction={async (user) => {
          try {
            await roleService.assignToUser(roleId!, user.id, assignUserScope);
            invalidateEntity(queryClient, "role-users");
          } catch (err) {
            // The dialog swallows the rejection, so the 409 an already-assigned
            // user produces would otherwise look like a click that did nothing.
            toast({ description: getApiErrorMessage(err), variant: "destructive" });
            throw err;
          }
        }}
      />

      {/* Assign group dialog */}
      <AssignGroupDialog
        open={assignGroupOpen}
        onClose={() => setAssignGroupOpen(false)}
        roleId={roleId!}
        onAssigned={() => {
          invalidateEntity(queryClient, "role-groups");
          setAssignGroupOpen(false);
        }}
      />

      {/* Unassign user confirm */}
      <ConfirmDialog
        open={unassignUser !== null}
        onClose={() => setUnassignUser(null)}
        onConfirm={() => unassignUser && unassignUserMutation.mutate(unassignUser)}
        title="Unassign User"
        description={
          unassignUser?.resource_id
            ? `Remove this role from "${unassignUser.user.display_name ?? unassignUser.user.username}" under "${nameFor(unassignUser.resource_id)}"? Any global assignment of the same role is left alone.`
            : `Remove this role from "${unassignUser?.user.display_name ?? unassignUser?.user.username}"?`
        }
        isLoading={unassignUserMutation.isPending}
      />

      {/* Unassign group confirm */}
      <ConfirmDialog
        open={unassignGroup !== null}
        onClose={() => setUnassignGroup(null)}
        onConfirm={() => unassignGroup && unassignGroupMutation.mutate(unassignGroup)}
        title="Unassign Group"
        description={
          unassignGroup?.resource_id
            ? `Remove this role from group "${unassignGroup.group.name}" under "${nameFor(unassignGroup.resource_id)}"? Any global assignment of the same role is left alone.`
            : `Remove this role from group "${unassignGroup?.group.name}"?`
        }
        isLoading={unassignGroupMutation.isPending}
      />

      {/* Assign service account dialog */}
      <AssignServiceAccountDialog
        open={assignServiceAccountOpen}
        onClose={() => setAssignServiceAccountOpen(false)}
        roleId={roleId!}
        onAssigned={() => {
          invalidateEntity(queryClient, "role-service-accounts");
          setAssignServiceAccountOpen(false);
        }}
      />

      {/* Unassign service account confirm */}
      <ConfirmDialog
        open={unassignServiceAccount !== null}
        onClose={() => setUnassignServiceAccount(null)}
        onConfirm={() =>
          unassignServiceAccount &&
          unassignServiceAccountMutation.mutate(unassignServiceAccount)
        }
        title="Unassign Service Account"
        description={
          unassignServiceAccount?.resource_id
            ? `Remove this role from service account "${unassignServiceAccount.service_account.name}" under "${nameFor(unassignServiceAccount.resource_id)}"? Any global assignment of the same role is left alone.`
            : `Remove this role from service account "${unassignServiceAccount?.service_account.name}"?`
        }
        isLoading={unassignServiceAccountMutation.isPending}
      />
    </div>
  );
}

// Re-export for convenience
export { Pencil as PencilIcon, Trash2 as Trash2Icon };
