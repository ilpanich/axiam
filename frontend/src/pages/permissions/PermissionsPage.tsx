import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  permissionService,
  type Permission,
  type CreatePermissionPayload,
  type UpdatePermissionPayload,
} from "@/services/permissions";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { cn, formatDate } from "@/lib/utils";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/useToast";
import { getApiErrorMessage } from "@/lib/apiError";
import { ActionBadge } from "@/components/shared";

// ─── Standard actions ─────────────────────────────────────────────────────────

const STANDARD_ACTIONS = ["read", "write", "delete", "admin"] as const;

// ─── Permission form fields ───────────────────────────────────────────────────

interface PermissionFormFieldsProps {
  action: string;
  customAction: string;
  description: string;
  onActionChange: (v: string) => void;
  onCustomActionChange: (v: string) => void;
  onDescriptionChange: (v: string) => void;
  error?: string;
  idPrefix: string;
}

function PermissionFormFields({
  action,
  customAction,
  description,
  onActionChange,
  onCustomActionChange,
  onDescriptionChange,
  error,
  idPrefix,
}: PermissionFormFieldsProps) {
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-action`}>Action *</Label>
        <select
          id={`${idPrefix}-action`}
          value={action}
          onChange={(e) => onActionChange(e.target.value)}
          className={cn(
            "flex h-9 w-full rounded-md px-3 py-1 text-sm",
            "bg-white/5 border border-primary/20 text-foreground",
            "focus:outline-hidden focus:ring-2 focus:ring-primary/40 focus:border-primary",
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
  const { toast } = useToast();

  const { data: permissions = [], isLoading } = useQuery({
    queryKey: ["permissions"],
    queryFn: () => permissionService.list(),
  });

  // ─── Create state ──────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false);
  const [createAction, setCreateAction] = useState<string>("read");
  const [createCustomAction, setCreateCustomAction] = useState("");
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
      const msg = getApiErrorMessage(err);
      setCreateError(msg);
      toast({ description: msg, variant: "destructive" });
    },
  });

  function resetCreateForm() {
    setCreateAction("read");
    setCreateCustomAction("");
    setCreateDescription("");
    setCreateError("");
  }

  function resolvedAction(action: string, custom: string): string {
    return action === "custom" ? custom.trim() : action;
  }

  function handleCreateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setCreateError("");
    const finalAction = resolvedAction(createAction, createCustomAction);
    if (!finalAction) {
      setCreateError("Action is required.");
      return;
    }
    createMutation.mutate({
      action: finalAction,
      description: createDescription.trim(),
    });
  }

  // ─── Edit state ────────────────────────────────────────────────────────────
  const [editPermission, setEditPermission] = useState<Permission | null>(null);
  const [editAction, setEditAction] = useState<string>("read");
  const [editCustomAction, setEditCustomAction] = useState("");
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
      const msg = getApiErrorMessage(err);
      setEditError(msg);
      toast({ description: msg, variant: "destructive" });
    },
  });

  function openEdit(perm: Permission) {
    setEditPermission(perm);
    const isStandard = (STANDARD_ACTIONS as readonly string[]).includes(
      perm.action
    );
    setEditAction(isStandard ? perm.action : "custom");
    setEditCustomAction(isStandard ? "" : perm.action);
    setEditDescription(perm.description ?? "");
    setEditError("");
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setEditError("");
    if (!editPermission) {
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
        action: finalAction,
        description: editDescription.trim(),
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
    onError: (err: unknown) => {
      toast({ description: getApiErrorMessage(err), variant: "destructive" });
    },
  });

  // ─── Table columns ─────────────────────────────────────────────────────────
  const columns: Column<Permission>[] = [
    {
      key: "action",
      header: "Action",
      render: (row) => <ActionBadge action={row.action} />,
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
            aria-label={`Edit ${row.action}`}
            onClick={() => openEdit(row)}
            className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
          >
            <Pencil size={14} />
          </button>
          <button
            aria-label={`Delete ${row.action}`}
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
          action={createAction}
          customAction={createCustomAction}
          description={createDescription}
          onActionChange={setCreateAction}
          onCustomActionChange={setCreateCustomAction}
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
          action={editAction}
          customAction={editCustomAction}
          description={editDescription}
          onActionChange={setEditAction}
          onCustomActionChange={setEditCustomAction}
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
        description={`Are you sure you want to delete "${deletePermission?.action}"? This action cannot be undone.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}
