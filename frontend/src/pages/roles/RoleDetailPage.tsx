import { useState, useRef } from "react";
import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  roleService,
  type UpdateRolePayload,
} from "@/services/roles";
import {
  permissionService,
  type Permission,
} from "@/services/permissions";
import { userService, groupService, type User, type Group } from "@/services/users";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
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
} from "lucide-react";
import { cn } from "@/lib/utils";

const formatDate = (iso: string) =>
  new Intl.DateTimeFormat("en-US", { dateStyle: "medium" }).format(
    new Date(iso)
  );

// ─── Section card ─────────────────────────────────────────────────────────────

function SectionCard({
  title,
  action,
  children,
}: {
  title: string;
  action?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="glass-card mb-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-base font-semibold text-foreground">{title}</h2>
        {action}
      </div>
      {children}
    </div>
  );
}

// ─── Info row ─────────────────────────────────────────────────────────────────

function InfoRow({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-start gap-1 sm:gap-4 py-2 border-b border-white/5 last:border-0">
      <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground sm:w-36 shrink-0 pt-0.5">
        {label}
      </span>
      <span className="text-sm text-foreground/90">{children}</span>
    </div>
  );
}

// ─── Action badge ─────────────────────────────────────────────────────────────

export function ActionBadge({ action }: { action: string }) {
  const colorMap: Record<string, string> = {
    read: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    write: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    delete: "bg-rose-500/15 text-rose-400 border-rose-500/30",
    admin: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  };

  const classes =
    colorMap[action.toLowerCase()] ??
    "bg-white/10 text-foreground/70 border-white/20";

  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border",
        classes
      )}
    >
      {action}
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

  const { data: allPermissions = [], isLoading } = useQuery({
    queryKey: ["permissions"],
    queryFn: () => permissionService.list(),
    enabled: open,
  });

  const filtered = allPermissions.filter((p) =>
    p.name.toLowerCase().includes(search.toLowerCase()) ||
    p.action.toLowerCase().includes(search.toLowerCase())
  );

  async function handleGrant(permission: Permission) {
    setGrantingId(permission.id);
    try {
      await roleService.grantPermission(roleId, permission.id);
      onGranted();
    } catch {
      // parent will refetch
    } finally {
      setGrantingId(null);
    }
  }

  function handleClose() {
    setSearch("");
    onClose();
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
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
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
            className="text-muted-foreground hover:text-foreground transition-colors rounded p-1 focus:outline-none focus:ring-2 focus:ring-primary/40"
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
                "focus:outline-none focus:ring-2 focus:ring-primary/40 focus:border-primary",
                "transition-colors duration-200"
              )}
            />
          </div>

          <div className="overflow-y-auto flex-1 min-h-[120px] max-h-60 rounded-md border border-white/5">
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
                  return (
                    <li
                      key={perm.id}
                      className="flex items-center justify-between px-3 py-2.5 hover:bg-white/5 border-b border-white/5 last:border-0"
                    >
                      <div>
                        <p className="text-sm font-medium text-foreground/90">
                          {perm.name}
                        </p>
                        <div className="flex items-center gap-2 mt-0.5">
                          <ActionBadge action={perm.action} />
                          {perm.resource_id && (
                            <span className="text-xs text-muted-foreground">
                              {perm.resource_id}
                            </span>
                          )}
                        </div>
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
                          Grant
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

// ─── Assign User dialog ───────────────────────────────────────────────────────

interface AssignUserDialogProps {
  open: boolean;
  onClose: () => void;
  roleId: string;
  onAssigned: () => void;
}

function AssignUserDialog({
  open,
  onClose,
  roleId,
  onAssigned,
}: AssignUserDialogProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [results, setResults] = useState<User[]>([]);
  const [searching, setSearching] = useState(false);
  const [assigningId, setAssigningId] = useState<string | null>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  function handleSearchChange(e: React.ChangeEvent<HTMLInputElement>) {
    const term = e.target.value;
    setSearchTerm(term);

    if (debounceRef.current !== null) clearTimeout(debounceRef.current);
    if (!term.trim()) {
      setResults([]);
      return;
    }
    debounceRef.current = setTimeout(async () => {
      setSearching(true);
      try {
        const data = await userService.list(1, 20, term.trim());
        setResults(data.data);
      } catch {
        setResults([]);
      } finally {
        setSearching(false);
      }
    }, 300);
  }

  async function handleAssign(user: User) {
    setAssigningId(user.id);
    try {
      await roleService.assignToUser(roleId, user.id);
      onAssigned();
      setResults((prev) => prev.filter((u) => u.id !== user.id));
    } catch {
      // silently ignore
    } finally {
      setAssigningId(null);
    }
  }

  function handleClose() {
    setSearchTerm("");
    setResults([]);
    onClose();
  }

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      aria-modal="true"
      role="dialog"
      aria-labelledby="assign-user-title"
    >
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={handleClose}
        aria-hidden="true"
      />
      <div className="relative z-10 glass-card w-full max-w-md flex flex-col max-h-[80vh]">
        <div className="flex items-center justify-between pb-4 border-b border-primary/10">
          <h2
            id="assign-user-title"
            className="text-lg font-semibold text-foreground"
          >
            Assign User
          </h2>
          <button
            onClick={handleClose}
            className="text-muted-foreground hover:text-foreground transition-colors rounded p-1 focus:outline-none focus:ring-2 focus:ring-primary/40"
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
              value={searchTerm}
              onChange={handleSearchChange}
              placeholder="Search users…"
              aria-label="Search users"
              className={cn(
                "h-9 w-full rounded-md pl-9 pr-3 text-sm",
                "bg-white/5 border border-primary/20 text-foreground",
                "placeholder:text-muted-foreground",
                "focus:outline-none focus:ring-2 focus:ring-primary/40 focus:border-primary",
                "transition-colors duration-200"
              )}
            />
          </div>

          <div className="overflow-y-auto flex-1 min-h-[120px] max-h-60 rounded-md border border-white/5">
            {searching ? (
              <div className="flex items-center justify-center py-6">
                <Loader2 size={20} className="animate-spin text-primary/60" />
              </div>
            ) : !searchTerm ? (
              <p className="text-sm text-muted-foreground text-center py-6">
                Type to search for users.
              </p>
            ) : results.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-6">
                No users found.
              </p>
            ) : (
              <ul>
                {results.map((user) => (
                  <li
                    key={user.id}
                    className="flex items-center justify-between px-3 py-2.5 hover:bg-white/5 border-b border-white/5 last:border-0"
                  >
                    <div>
                      <p className="text-sm font-medium text-foreground/90">
                        {user.display_name ?? user.username}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {user.email}
                      </p>
                    </div>
                    <button
                      onClick={() => handleAssign(user)}
                      disabled={assigningId === user.id}
                      className="flex items-center gap-1 text-xs px-2.5 py-1 rounded bg-primary/20 text-primary hover:bg-primary/30 transition-colors disabled:opacity-50"
                    >
                      {assigningId === user.id ? (
                        <Loader2 size={12} className="animate-spin" />
                      ) : (
                        <Plus size={12} />
                      )}
                      Assign
                    </button>
                  </li>
                ))}
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
      await roleService.assignToGroup(roleId, selectedGroupId);
      onAssigned();
      setSelectedGroupId("");
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to assign group.");
    } finally {
      setAssigning(false);
    }
  }

  function handleClose() {
    setSelectedGroupId("");
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
    >
      <div className="space-y-1.5">
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
              "focus:outline-none focus:ring-2 focus:ring-primary/40 focus:border-primary",
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
      {error && <p className="text-sm text-destructive">{error}</p>}
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
  error?: string;
}

function EditRoleForm({
  name,
  description,
  isGlobal,
  onNameChange,
  onDescriptionChange,
  onIsGlobalChange,
  error,
}: EditRoleFormProps) {
  return (
    <>
      <div className="space-y-1.5">
        <Label htmlFor="detail-edit-name">Name *</Label>
        <Input
          id="detail-edit-name"
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          required
        />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="detail-edit-desc">Description</Label>
        <textarea
          id="detail-edit-desc"
          value={description}
          onChange={(e) => onDescriptionChange(e.target.value)}
          rows={3}
          className={cn(
            "flex w-full rounded-md px-3 py-2 text-sm resize-none",
            "bg-white/5 border border-primary/20 text-foreground",
            "placeholder:text-muted-foreground",
            "focus:outline-none focus:ring-2 focus:ring-primary/40 focus:border-primary",
            "transition-colors duration-200"
          )}
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
      {error && <p className="text-sm text-destructive">{error}</p>}
    </>
  );
}

// ─── Assignments tabs ─────────────────────────────────────────────────────────

type AssignmentTab = "users" | "groups";

// ─── Main page ─────────────────────────────────────────────────────────────────

export function RoleDetailPage() {
  const { roleId } = useParams<{ roleId: string }>();
  const queryClient = useQueryClient();

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

  const grantedPermissionIds = new Set(grantedPermissions.map((p) => p.id));

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
      void queryClient.invalidateQueries({
        queryKey: ["role-permissions", roleId],
      });
      setRevokePermission(null);
    },
  });

  // ─── Grant permission dialog ───────────────────────────────────────────────
  const [grantOpen, setGrantOpen] = useState(false);

  function handlePermissionGranted() {
    void queryClient.invalidateQueries({
      queryKey: ["role-permissions", roleId],
    });
  }

  // ─── Assignments state ─────────────────────────────────────────────────────
  const [assignmentTab, setAssignmentTab] = useState<AssignmentTab>("users");
  const [assignUserOpen, setAssignUserOpen] = useState(false);
  const [assignGroupOpen, setAssignGroupOpen] = useState(false);

  // ─── Permissions table columns ─────────────────────────────────────────────
  const permissionColumns: Column<Permission>[] = [
    {
      key: "name",
      header: "Permission",
      render: (row) => (
        <span className="font-medium text-foreground/90">{row.name}</span>
      ),
    },
    {
      key: "action",
      header: "Action",
      render: (row) => <ActionBadge action={row.action} />,
    },
    {
      key: "resource_id",
      header: "Resource",
      render: (row) => (
        <span className="text-muted-foreground text-sm">
          {row.resource_id ?? (
            <span className="text-cyan-400/70 text-xs italic">Global</span>
          )}
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
          aria-label={`Revoke ${row.name}`}
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
          data={grantedPermissions}
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
          ) : (
            <Button size="sm" onClick={() => setAssignGroupOpen(true)}>
              <Plus size={14} className="mr-1" />
              Assign Group
            </Button>
          )
        }
      >
        {/* Tabs */}
        <div className="flex gap-1 mb-4 border-b border-white/10">
          {(["users", "groups"] as AssignmentTab[]).map((tab) => (
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
          <div className="py-4 text-sm text-muted-foreground text-center">
            <p>
              Use "Assign User" to grant this role to a user directly.
            </p>
            <p className="mt-1 text-xs opacity-60">
              Assigned users are visible on each user's detail page.
            </p>
          </div>
        )}

        {assignmentTab === "groups" && (
          <div className="py-4 text-sm text-muted-foreground text-center">
            <p>
              Use "Assign Group" to grant this role to all members of a group.
            </p>
            <p className="mt-1 text-xs opacity-60">
              Assigned groups are visible on each group's detail page.
            </p>
          </div>
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
      >
        <EditRoleForm
          name={editName}
          description={editDescription}
          isGlobal={editIsGlobal}
          onNameChange={setEditName}
          onDescriptionChange={setEditDescription}
          onIsGlobalChange={setEditIsGlobal}
          error={editError}
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
        description={`Remove permission "${revokePermission?.name}" from this role?`}
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
      <AssignUserDialog
        open={assignUserOpen}
        onClose={() => setAssignUserOpen(false)}
        roleId={roleId!}
        onAssigned={() => {}}
      />

      {/* Assign group dialog */}
      <AssignGroupDialog
        open={assignGroupOpen}
        onClose={() => setAssignGroupOpen(false)}
        roleId={roleId!}
        onAssigned={() => {
          setAssignGroupOpen(false);
        }}
      />
    </div>
  );
}

// Re-export for convenience
export { Pencil as PencilIcon, Trash2 as Trash2Icon };
