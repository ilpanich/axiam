import { useState } from "react";
import { useNavigate } from "react-router";
import { useQuery } from "@tanstack/react-query";
import {
  roleService,
  type Role,
  type CreateRolePayload,
  type UpdateRolePayload,
} from "@/services/roles";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { PaginationControls, SearchBox } from "@/components/ListToolbar";
import { usePaginatedList } from "@/hooks/usePaginatedList";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Eye, Pencil, Plus, Trash2 } from "lucide-react";
import { cn, formatDate } from "@/lib/utils";
import { Textarea } from "@/components/ui/textarea";
import { ToggleField } from "@/components/shared";
import { useCrudMutations } from "@/hooks/useCrudMutations";
import {
  reachLabel,
  reachTitle,
  roleReach,
  useIsOrganizationScope,
} from "@/lib/grantReach";

// ─── Reach badge ──────────────────────────────────────────────────────────────

/**
 * How far this role's grants reach.
 *
 * The previous labels were `is_global ? "Global" : "Tenant"`, which was
 * backwards in one case and ambiguous in the other: a *resource-scoped* role —
 * the narrowest kind there is — was labelled "Tenant", and a global role was
 * labelled "Global" whether it reached one tenant or every tenant in the
 * organization. See `@/lib/grantReach` for why the underlying `is_global` field
 * keeps its name.
 */
function ReachBadge({ isGlobal }: { isGlobal: boolean }) {
  const organizationScope = useIsOrganizationScope();
  const reach = roleReach(isGlobal, organizationScope);
  return (
    <span
      title={reachTitle(reach)}
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border",
        reach === "organization" &&
          "bg-amber-500/15 text-amber-400 border-amber-500/30",
        reach === "tenant" &&
          "bg-purple-500/15 text-purple-400 border-purple-500/30",
        reach === "resource" &&
          "bg-cyan-500/10 text-cyan-400 border-cyan-500/20"
      )}
    >
      {reachLabel(reach)}
    </span>
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
  nameId,
  descriptionId,
  toggleId,
}: RoleFormFieldsProps) {
  const organizationScope = useIsOrganizationScope();
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
      {/* The old label read "applies across all tenants", which was untrue for
          every tenant-level role ever created: a global role applies to every
          *resource* in the scope it lives in. It is true only for a role in the
          organization's own tenant — so the label now says which case you are
          in rather than asserting the stronger one always. */}
      <ToggleField
        id={toggleId}
        label={
          organizationScope
            ? "Organization-wide role (applies to every tenant)"
            : "Tenant-wide role (applies to every resource in this tenant)"
        }
        checked={isGlobal}
        onChange={onIsGlobalChange}
      />
    </>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────────

export function RolesPage() {
  const navigate = useNavigate();

  // Server-paged and server-searched. The page used to fetch every role in the
  // tenant in one request and render all of them; that is fine at ten roles and
  // a wall of rows at two hundred, with no way to find one by name.
  const {
    items: roles,
    isLoading,
    search,
    setSearch,
    page,
    totalPages,
    total,
    setPage,
    isFiltered,
  } = usePaginatedList<Role>(["roles"], "/api/v1/roles");

  // ─── Create state ──────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false);
  const [createName, setCreateName] = useState("");
  const [createDescription, setCreateDescription] = useState("");
  const [createIsGlobal, setCreateIsGlobal] = useState(false);
  const [createError, setCreateError] = useState("");

  // ─── Edit state ────────────────────────────────────────────────────────────
  const [editRole, setEditRole] = useState<Role | null>(null);
  const [editName, setEditName] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editIsGlobal, setEditIsGlobal] = useState(false);
  const [editError, setEditError] = useState("");

  // ─── Delete state ──────────────────────────────────────────────────────────
  const [deleteRole, setDeleteRole] = useState<Role | null>(null);

  // QUAL-06/D-16: adopted useCrudMutations (CQ-F15) — note the accepted UX
  // delta: the hook's deleteMutation always toasts on error, whereas the
  // previous inline deleteMutation had no onError (silent failure). This is
  // an explicitly accepted improvement per D-15/RESEARCH A2.
  const { createMutation, updateMutation: editMutation, deleteMutation } =
    useCrudMutations<CreateRolePayload, UpdateRolePayload>({
      queryKey: ["roles"],
      createFn: (payload) => roleService.create(payload),
      updateFn: (id, payload) => roleService.update(id, payload),
      deleteFn: (id) => roleService.remove(id),
      onCreateSuccess: () => {
        setCreateOpen(false);
        resetCreateForm();
      },
      onCreateError: (msg) => setCreateError(msg),
      onUpdateSuccess: () => setEditRole(null),
      onUpdateError: (msg) => setEditError(msg),
      onDeleteSuccess: () => setDeleteRole(null),
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
      description: createDescription.trim(),
      is_global: createIsGlobal,
    });
  }

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
        description: editDescription.trim(),
        is_global: editIsGlobal,
      },
    });
  }

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
      header: "Reach",
      render: (row) => <ReachBadge isGlobal={row.is_global} />,
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

      <SearchBox
        value={search}
        onChange={setSearch}
        noun="roles"
        className="mb-4 max-w-sm"
      />

      <DataTable
        columns={columns}
        data={roles}
        isLoading={isLoading}
        emptyMessage={
          isFiltered ? "No roles match your search." : "No roles found."
        }
      />

      <PaginationControls
        page={page}
        totalPages={totalPages}
        total={total}
        onPageChange={setPage}
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
        error={createError}
        errorId="role-create-error"
      >
        <RoleFormFields
          name={createName}
          description={createDescription}
          isGlobal={createIsGlobal}
          onNameChange={setCreateName}
          onDescriptionChange={setCreateDescription}
          onIsGlobalChange={setCreateIsGlobal}
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
        error={editError}
        errorId="role-edit-error"
      >
        <RoleFormFields
          name={editName}
          description={editDescription}
          isGlobal={editIsGlobal}
          onNameChange={setEditName}
          onDescriptionChange={setEditDescription}
          onIsGlobalChange={setEditIsGlobal}
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
