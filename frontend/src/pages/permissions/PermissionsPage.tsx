import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  permissionService,
  type Permission,
  type CreatePermissionPayload,
  type UpdatePermissionPayload,
} from "@/services/permissions";
import { resourceService } from "@/services/resources";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { Textarea } from "@/components/ui/textarea";

const formatDate = (iso: string) =>
  new Intl.DateTimeFormat("en-US", { dateStyle: "medium" }).format(
    new Date(iso)
  );

// ─── Action badge ─────────────────────────────────────────────────────────────

function ActionBadge({ action }: { action: string }) {
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

// ─── Standard actions ─────────────────────────────────────────────────────────

const STANDARD_ACTIONS = ["read", "write", "delete", "admin"] as const;

// ─── Permission form fields ───────────────────────────────────────────────────

interface PermissionFormFieldsProps {
  name: string;
  action: string;
  customAction: string;
  resourceId: string;
  description: string;
  onNameChange: (v: string) => void;
  onActionChange: (v: string) => void;
  onCustomActionChange: (v: string) => void;
  onResourceIdChange: (v: string) => void;
  onDescriptionChange: (v: string) => void;
  error?: string;
  idPrefix: string;
}

function PermissionFormFields({
  name,
  action,
  customAction,
  resourceId,
  description,
  onNameChange,
  onActionChange,
  onCustomActionChange,
  onResourceIdChange,
  onDescriptionChange,
  error,
  idPrefix,
}: PermissionFormFieldsProps) {
  const { data: resources = [] } = useQuery({
    queryKey: ["resources"],
    queryFn: () => resourceService.list(),
  });

  return (
    <>
      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-name`}>Name *</Label>
        <Input
          id={`${idPrefix}-name`}
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          placeholder="e.g. users:read"
          required
          autoComplete="off"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-action`}>Action *</Label>
        <select
          id={`${idPrefix}-action`}
          value={action}
          onChange={(e) => onActionChange(e.target.value)}
          className={cn(
            "flex h-9 w-full rounded-md px-3 py-1 text-sm",
            "bg-white/5 border border-primary/20 text-foreground",
            "focus:outline-none focus:ring-2 focus:ring-primary/40 focus:border-primary",
            "transition-colors duration-200"
          )}
        >
          {STANDARD_ACTIONS.map((a) => (
            <option key={a} value={a}>
              {a}
            </option>
          ))}
          <option value="custom">custom…</option>
        </select>
        {action === "custom" && (
          <Input
            id={`${idPrefix}-custom-action`}
            value={customAction}
            onChange={(e) => onCustomActionChange(e.target.value)}
            placeholder="Enter custom action"
            autoComplete="off"
            className="mt-1.5"
          />
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-resource`}>Resource</Label>
        <select
          id={`${idPrefix}-resource`}
          value={resourceId}
          onChange={(e) => onResourceIdChange(e.target.value)}
          className={cn(
            "flex h-9 w-full rounded-md px-3 py-1 text-sm",
            "bg-white/5 border border-primary/20 text-foreground",
            "focus:outline-none focus:ring-2 focus:ring-primary/40 focus:border-primary",
            "transition-colors duration-200"
          )}
        >
          <option value="">Global (no resource)</option>
          {resources.map((r) => (
            <option key={r.id} value={r.id}>
              {r.name} ({r.resource_type})
            </option>
          ))}
        </select>
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-description`}>Description</Label>
        <Textarea
          id={`${idPrefix}-description`}
          value={description}
          onChange={(e) => onDescriptionChange(e.target.value)}
          rows={2}
          placeholder="Optional description…"
        />
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}
    </>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────────

export function PermissionsPage() {
  const queryClient = useQueryClient();

  const { data: permissions = [], isLoading } = useQuery({
    queryKey: ["permissions"],
    queryFn: () => permissionService.list(),
  });

  const { data: resources = [] } = useQuery({
    queryKey: ["resources"],
    queryFn: () => resourceService.list(),
  });

  // Helper: resolve resource name from id
  function resourceName(id?: string): string {
    if (!id) return "";
    return resources.find((r) => r.id === id)?.name ?? id;
  }

  // ─── Create state ──────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false);
  const [createName, setCreateName] = useState("");
  const [createAction, setCreateAction] = useState<string>("read");
  const [createCustomAction, setCreateCustomAction] = useState("");
  const [createResourceId, setCreateResourceId] = useState("");
  const [createDescription, setCreateDescription] = useState("");
  const [createError, setCreateError] = useState("");

  const createMutation = useMutation({
    mutationFn: (payload: CreatePermissionPayload) =>
      permissionService.create(payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["permissions"] });
      setCreateOpen(false);
      resetCreateForm();
    },
    onError: (err: unknown) => {
      setCreateError(
        err instanceof Error ? err.message : "Failed to create permission."
      );
    },
  });

  function resetCreateForm() {
    setCreateName("");
    setCreateAction("read");
    setCreateCustomAction("");
    setCreateResourceId("");
    setCreateDescription("");
    setCreateError("");
  }

  function resolvedAction(action: string, custom: string): string {
    return action === "custom" ? custom.trim() : action;
  }

  function handleCreateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setCreateError("");
    if (!createName.trim()) {
      setCreateError("Name is required.");
      return;
    }
    const finalAction = resolvedAction(createAction, createCustomAction);
    if (!finalAction) {
      setCreateError("Action is required.");
      return;
    }
    createMutation.mutate({
      name: createName.trim(),
      action: finalAction,
      resource_id: createResourceId || undefined,
      description: createDescription.trim() || undefined,
    });
  }

  // ─── Edit state ────────────────────────────────────────────────────────────
  const [editPermission, setEditPermission] = useState<Permission | null>(null);
  const [editName, setEditName] = useState("");
  const [editAction, setEditAction] = useState<string>("read");
  const [editCustomAction, setEditCustomAction] = useState("");
  const [editResourceId, setEditResourceId] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editError, setEditError] = useState("");

  const editMutation = useMutation({
    mutationFn: ({
      id,
      payload,
    }: {
      id: string;
      payload: UpdatePermissionPayload;
    }) => permissionService.update(id, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["permissions"] });
      setEditPermission(null);
    },
    onError: (err: unknown) => {
      setEditError(
        err instanceof Error ? err.message : "Failed to update permission."
      );
    },
  });

  function openEdit(perm: Permission) {
    setEditPermission(perm);
    setEditName(perm.name);
    const isStandard = (STANDARD_ACTIONS as readonly string[]).includes(
      perm.action
    );
    setEditAction(isStandard ? perm.action : "custom");
    setEditCustomAction(isStandard ? "" : perm.action);
    setEditResourceId(perm.resource_id ?? "");
    setEditDescription(perm.description ?? "");
    setEditError("");
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setEditError("");
    if (!editPermission || !editName.trim()) {
      setEditError("Name is required.");
      return;
    }
    const finalAction = resolvedAction(editAction, editCustomAction);
    if (!finalAction) {
      setEditError("Action is required.");
      return;
    }
    editMutation.mutate({
      id: editPermission.id,
      payload: {
        name: editName.trim(),
        action: finalAction,
        resource_id: editResourceId || undefined,
        description: editDescription.trim() || undefined,
      },
    });
  }

  // ─── Delete state ──────────────────────────────────────────────────────────
  const [deletePermission, setDeletePermission] = useState<Permission | null>(
    null
  );

  const deleteMutation = useMutation({
    mutationFn: (id: string) => permissionService.remove(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["permissions"] });
      setDeletePermission(null);
    },
  });

  // ─── Table columns ─────────────────────────────────────────────────────────
  const columns: Column<Permission>[] = [
    {
      key: "name",
      header: "Name",
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
          {row.resource_id ? (
            resourceName(row.resource_id)
          ) : (
            <span className="text-cyan-400/70 text-xs italic">Global</span>
          )}
        </span>
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
      header: "Created",
      render: (row) => (
        <span className="text-muted-foreground text-sm">
          {formatDate(row.created_at)}
        </span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      width: "w-20",
      render: (row) => (
        <div className="flex items-center gap-1">
          <button
            aria-label={`Edit ${row.name}`}
            onClick={() => openEdit(row)}
            className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
          >
            <Pencil size={14} />
          </button>
          <button
            aria-label={`Delete ${row.name}`}
            onClick={() => setDeletePermission(row)}
            className="p-1.5 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors"
          >
            <Trash2 size={14} />
          </button>
        </div>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="Permissions"
        description="Define actions that can be granted to roles."
        action={
          <Button
            onClick={() => {
              resetCreateForm();
              setCreateOpen(true);
            }}
          >
            <Plus size={16} />
            New Permission
          </Button>
        }
      />

      <DataTable
        columns={columns}
        data={permissions}
        isLoading={isLoading}
        emptyMessage="No permissions defined yet."
      />

      {/* Create dialog */}
      <FormDialog
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          resetCreateForm();
        }}
        title="New Permission"
        onSubmit={handleCreateSubmit}
        isLoading={createMutation.isPending}
        submitLabel="Create"
      >
        <PermissionFormFields
          name={createName}
          action={createAction}
          customAction={createCustomAction}
          resourceId={createResourceId}
          description={createDescription}
          onNameChange={setCreateName}
          onActionChange={setCreateAction}
          onCustomActionChange={setCreateCustomAction}
          onResourceIdChange={setCreateResourceId}
          onDescriptionChange={setCreateDescription}
          error={createError}
          idPrefix="create-perm"
        />
      </FormDialog>

      {/* Edit dialog */}
      <FormDialog
        open={editPermission !== null}
        onClose={() => setEditPermission(null)}
        title="Edit Permission"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
      >
        <PermissionFormFields
          name={editName}
          action={editAction}
          customAction={editCustomAction}
          resourceId={editResourceId}
          description={editDescription}
          onNameChange={setEditName}
          onActionChange={setEditAction}
          onCustomActionChange={setEditCustomAction}
          onResourceIdChange={setEditResourceId}
          onDescriptionChange={setEditDescription}
          error={editError}
          idPrefix="edit-perm"
        />
      </FormDialog>

      {/* Delete confirm */}
      <ConfirmDialog
        open={deletePermission !== null}
        onClose={() => setDeletePermission(null)}
        onConfirm={() =>
          deletePermission && deleteMutation.mutate(deletePermission.id)
        }
        title="Delete Permission"
        description={`Are you sure you want to delete "${deletePermission?.name}"? This action cannot be undone.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}
