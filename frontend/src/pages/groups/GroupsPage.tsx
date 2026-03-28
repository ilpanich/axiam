import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  groupService,
  type Group,
  type CreateGroupPayload,
  type UpdateGroupPayload,
} from "@/services/users";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Eye, Pencil, Plus, Trash2 } from "lucide-react";
import { Textarea } from "@/components/ui/textarea";
import { formatDate } from "@/lib/utils";

// ─── Group form fields ────────────────────────────────────────────────────────

interface GroupFormFieldsProps {
  name: string;
  description: string;
  onNameChange: (v: string) => void;
  onDescriptionChange: (v: string) => void;
  error?: string;
}

function GroupFormFields({
  name,
  description,
  onNameChange,
  onDescriptionChange,
  error,
}: GroupFormFieldsProps) {
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor="group-name">Name *</Label>
        <Input
          id="group-name"
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          placeholder="Engineering"
          required
          autoComplete="off"
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="group-description">Description</Label>
        <Textarea
          id="group-description"
          value={description}
          onChange={(e) => onDescriptionChange(e.target.value)}
          placeholder="Optional description"
          rows={3}
        />
      </div>
      {error && <p className="text-sm text-destructive">{error}</p>}
    </>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────────

export function GroupsPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const { data: groups = [], isLoading } = useQuery({
    queryKey: ["groups"],
    queryFn: groupService.list,
  });

  // ─── Create state ─────────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false);
  const [createName, setCreateName] = useState("");
  const [createDescription, setCreateDescription] = useState("");
  const [createError, setCreateError] = useState("");

  const createMutation = useMutation({
    mutationFn: (payload: CreateGroupPayload) => groupService.create(payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["groups"] });
      setCreateOpen(false);
      resetCreateForm();
    },
    onError: (err: unknown) => {
      setCreateError(
        err instanceof Error ? err.message : "Failed to create group.",
      );
    },
  });

  function resetCreateForm() {
    setCreateName("");
    setCreateDescription("");
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
    });
  }

  // ─── Edit state ───────────────────────────────────────────────────────────────
  const [editGroup, setEditGroup] = useState<Group | null>(null);
  const [editName, setEditName] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editError, setEditError] = useState("");

  const editMutation = useMutation({
    mutationFn: ({
      id,
      payload,
    }: {
      id: string;
      payload: UpdateGroupPayload;
    }) => groupService.update(id, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["groups"] });
      setEditGroup(null);
    },
    onError: (err: unknown) => {
      setEditError(
        err instanceof Error ? err.message : "Failed to update group.",
      );
    },
  });

  function openEdit(group: Group) {
    setEditGroup(group);
    setEditName(group.name);
    setEditDescription(group.description ?? "");
    setEditError("");
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setEditError("");
    if (!editGroup || !editName.trim()) {
      setEditError("Name is required.");
      return;
    }
    editMutation.mutate({
      id: editGroup.id,
      payload: {
        name: editName.trim(),
        description: editDescription.trim() || undefined,
      },
    });
  }

  // ─── Delete state ─────────────────────────────────────────────────────────────
  const [deleteGroup, setDeleteGroup] = useState<Group | null>(null);

  const deleteMutation = useMutation({
    mutationFn: (id: string) => groupService.remove(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["groups"] });
      setDeleteGroup(null);
    },
  });

  // ─── Table columns ─────────────────────────────────────────────────────────────
  const columns: Column<Group>[] = [
    {
      key: "name",
      header: "Name",
      render: (row) => (
        <button
          className="font-medium text-primary hover:underline focus:outline-none focus:underline"
          onClick={() => navigate(`/groups/${row.id}`)}
        >
          {row.name}
        </button>
      ),
    },
    {
      key: "description",
      header: "Description",
      render: (row) => (
        <span className="text-muted-foreground text-sm truncate max-w-xs block">
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
            onClick={() => navigate(`/groups/${row.id}`)}
            className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
          >
            <Eye size={14} />
          </button>
          <button
            aria-label={`Delete ${row.name}`}
            onClick={() => setDeleteGroup(row)}
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
        title="Groups"
        description="Organize users into groups. Roles assigned to a group are inherited by all members."
        action={
          <Button
            onClick={() => {
              resetCreateForm();
              setCreateOpen(true);
            }}
          >
            <Plus size={16} />
            New Group
          </Button>
        }
      />

      <DataTable
        columns={columns}
        data={groups}
        isLoading={isLoading}
        emptyMessage="No groups yet. Create your first one."
      />

      {/* Create dialog */}
      <FormDialog
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          resetCreateForm();
        }}
        title="New Group"
        onSubmit={handleCreateSubmit}
        isLoading={createMutation.isPending}
        submitLabel="Create"
      >
        <GroupFormFields
          name={createName}
          description={createDescription}
          onNameChange={setCreateName}
          onDescriptionChange={setCreateDescription}
          error={createError}
        />
      </FormDialog>

      {/* Edit dialog */}
      <FormDialog
        open={editGroup !== null}
        onClose={() => setEditGroup(null)}
        title="Edit Group"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
      >
        <GroupFormFields
          name={editName}
          description={editDescription}
          onNameChange={setEditName}
          onDescriptionChange={setEditDescription}
          error={editError}
        />
      </FormDialog>

      {/* Delete confirm */}
      <ConfirmDialog
        open={deleteGroup !== null}
        onClose={() => setDeleteGroup(null)}
        onConfirm={() => deleteGroup && deleteMutation.mutate(deleteGroup.id)}
        title="Delete Group"
        description={`Are you sure you want to delete "${deleteGroup?.name}"? This action cannot be undone.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}
