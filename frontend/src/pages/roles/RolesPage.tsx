import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  roleService,
  type Role,
  type CreateRolePayload,
  type UpdateRolePayload,
} from "@/services/roles";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Eye, Pencil, Plus, Trash2 } from "lucide-react";
import { cn, formatDate } from "@/lib/utils";
import { Textarea } from "@/components/ui/textarea";

// ─── Global badge ─────────────────────────────────────────────────────────────

function GlobalBadge({ isGlobal }: { isGlobal: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border",
        isGlobal
          ? "bg-purple-500/15 text-purple-400 border-purple-500/30"
          : "bg-cyan-500/10 text-cyan-400 border-cyan-500/20"
      )}
    >
      {isGlobal ? "Global" : "Tenant"}
    </span>
  );
}

// ─── Toggle field ─────────────────────────────────────────────────────────────

function ToggleField({
  id,
  label,
  checked,
  onChange,
}: {
  id: string;
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center gap-3">
      <input
        type="checkbox"
        id={id}
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="w-4 h-4 accent-cyan-400 cursor-pointer"
      />
      <Label htmlFor={id} className="cursor-pointer">
        {label}
      </Label>
    </div>
  );
}

// ─── Role form fields ─────────────────────────────────────────────────────────

interface RoleFormFieldsProps {
  name: string;
  description: string;
  isGlobal: boolean;
  onNameChange: (v: string) => void;
  onDescriptionChange: (v: string) => void;
  onIsGlobalChange: (v: boolean) => void;
  error?: string;
  nameId: string;
  descriptionId: string;
  toggleId: string;
}

function RoleFormFields({
  name,
  description,
  isGlobal,
  onNameChange,
  onDescriptionChange,
  onIsGlobalChange,
  error,
  nameId,
  descriptionId,
  toggleId,
}: RoleFormFieldsProps) {
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor={nameId}>Name *</Label>
        <Input
          id={nameId}
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          placeholder="e.g. Admin"
          required
          autoComplete="off"
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor={descriptionId}>Description</Label>
        <Textarea
          id={descriptionId}
          value={description}
          onChange={(e) => onDescriptionChange(e.target.value)}
          rows={3}
          placeholder="Optional description…"
        />
      </div>
      <ToggleField
        id={toggleId}
        label="Global role (applies across all tenants)"
        checked={isGlobal}
        onChange={onIsGlobalChange}
      />
      {error && <p className="text-sm text-destructive">{error}</p>}
    </>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────────

export function RolesPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const { data: roles = [], isLoading } = useQuery({
    queryKey: ["roles"],
    queryFn: () => roleService.list(),
  });

  // ─── Create state ──────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false);
  const [createName, setCreateName] = useState("");
  const [createDescription, setCreateDescription] = useState("");
  const [createIsGlobal, setCreateIsGlobal] = useState(false);
  const [createError, setCreateError] = useState("");

  const createMutation = useMutation({
    mutationFn: (payload: CreateRolePayload) => roleService.create(payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["roles"] });
      setCreateOpen(false);
      resetCreateForm();
    },
    onError: (err: unknown) => {
      setCreateError(
        err instanceof Error ? err.message : "Failed to create role."
      );
    },
  });

  function resetCreateForm() {
    setCreateName("");
    setCreateDescription("");
    setCreateIsGlobal(false);
    setCreateError("");
  }

  function handleCreateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setCreateError("");
    if (!createName.trim()) {
      setCreateError("Name is required.");
      return;
    }
    createMutation.mutate({
      name: createName.trim(),
      description: createDescription.trim() || undefined,
      is_global: createIsGlobal,
    });
  }

  // ─── Edit state ────────────────────────────────────────────────────────────
  const [editRole, setEditRole] = useState<Role | null>(null);
  const [editName, setEditName] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editIsGlobal, setEditIsGlobal] = useState(false);
  const [editError, setEditError] = useState("");

  const editMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: UpdateRolePayload }) =>
      roleService.update(id, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["roles"] });
      setEditRole(null);
    },
    onError: (err: unknown) => {
      setEditError(
        err instanceof Error ? err.message : "Failed to update role."
      );
    },
  });

  function openEdit(role: Role) {
    setEditRole(role);
    setEditName(role.name);
    setEditDescription(role.description ?? "");
    setEditIsGlobal(role.is_global);
    setEditError("");
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setEditError("");
    if (!editRole || !editName.trim()) {
      setEditError("Name is required.");
      return;
    }
    editMutation.mutate({
      id: editRole.id,
      payload: {
        name: editName.trim(),
        description: editDescription.trim() || undefined,
        is_global: editIsGlobal,
      },
    });
  }

  // ─── Delete state ──────────────────────────────────────────────────────────
  const [deleteRole, setDeleteRole] = useState<Role | null>(null);

  const deleteMutation = useMutation({
    mutationFn: (id: string) => roleService.remove(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["roles"] });
      setDeleteRole(null);
    },
  });

  // ─── Table columns ─────────────────────────────────────────────────────────
  const columns: Column<Role>[] = [
    {
      key: "name",
      header: "Name",
      render: (row) => (
        <span className="font-medium text-foreground/90">{row.name}</span>
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
      key: "is_global",
      header: "Scope",
      render: (row) => <GlobalBadge isGlobal={row.is_global} />,
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
      width: "w-28",
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
            aria-label={`View ${row.name}`}
            onClick={() => navigate(`/roles/${row.id}`)}
            className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
          >
            <Eye size={14} />
          </button>
          <button
            aria-label={`Delete ${row.name}`}
            onClick={() => setDeleteRole(row)}
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
        title="Roles"
        description="Manage roles and their permission assignments."
        action={
          <Button
            onClick={() => {
              resetCreateForm();
              setCreateOpen(true);
            }}
          >
            <Plus size={16} />
            New Role
          </Button>
        }
      />

      <DataTable
        columns={columns}
        data={roles}
        isLoading={isLoading}
        emptyMessage="No roles found."
      />

      {/* Create dialog */}
      <FormDialog
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          resetCreateForm();
        }}
        title="New Role"
        onSubmit={handleCreateSubmit}
        isLoading={createMutation.isPending}
        submitLabel="Create"
      >
        <RoleFormFields
          name={createName}
          description={createDescription}
          isGlobal={createIsGlobal}
          onNameChange={setCreateName}
          onDescriptionChange={setCreateDescription}
          onIsGlobalChange={setCreateIsGlobal}
          error={createError}
          nameId="create-role-name"
          descriptionId="create-role-description"
          toggleId="create-role-is-global"
        />
      </FormDialog>

      {/* Edit dialog */}
      <FormDialog
        open={editRole !== null}
        onClose={() => setEditRole(null)}
        title="Edit Role"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
      >
        <RoleFormFields
          name={editName}
          description={editDescription}
          isGlobal={editIsGlobal}
          onNameChange={setEditName}
          onDescriptionChange={setEditDescription}
          onIsGlobalChange={setEditIsGlobal}
          error={editError}
          nameId="edit-role-name"
          descriptionId="edit-role-description"
          toggleId="edit-role-is-global"
        />
      </FormDialog>

      {/* Delete confirm */}
      <ConfirmDialog
        open={deleteRole !== null}
        onClose={() => setDeleteRole(null)}
        onConfirm={() => deleteRole && deleteMutation.mutate(deleteRole.id)}
        title="Delete Role"
        description={`Are you sure you want to delete "${deleteRole?.name}"? This action cannot be undone.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}
