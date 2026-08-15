import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, Trash2 } from "lucide-react";
import {
  scopeService,
  type Scope,
  type CreateScopePayload,
  type UpdateScopePayload,
} from "@/services/scopes";
import { usePermissions } from "@/hooks/usePermissions";
import { useToast } from "@/hooks/useToast";
import { getApiErrorMessage } from "@/lib/apiError";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { SectionCard } from "@/components/shared";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

// ─── Scopes CRUD (C4) ──────────────────────────────────────────────────────────
//
// Standalone completion of the scopes surface: scopes were previously only
// selectable while granting a permission (PermissionsPage), with no way to
// create, rename, or delete one directly. Scopes are nested under a resource
// (`/api/v1/resources/{resource_id}/scopes`), so this panel takes the
// currently-selected resource from ResourcesPage rather than being its own
// route.

interface ScopeFormFieldsProps {
  name: string;
  description: string;
  onNameChange: (v: string) => void;
  onDescriptionChange: (v: string) => void;
  idPrefix: string;
}

function ScopeFormFields({
  name,
  description,
  onNameChange,
  onDescriptionChange,
  idPrefix,
}: ScopeFormFieldsProps) {
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-name`}>Name *</Label>
        <Input
          id={`${idPrefix}-name`}
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          placeholder="e.g. invoices"
          autoComplete="off"
        />
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
    </>
  );
}

export interface ScopesPanelProps {
  resourceId: string;
  resourceName: string;
}

export function ScopesPanel({ resourceId, resourceName }: ScopesPanelProps) {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const { can } = usePermissions();

  const { data: scopes = [], isLoading } = useQuery({
    queryKey: ["scopes", resourceId],
    queryFn: () => scopeService.list(resourceId),
  });

  // ─── Create ────────────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false);
  const [createName, setCreateName] = useState("");
  const [createDescription, setCreateDescription] = useState("");
  const [createError, setCreateError] = useState("");

  const createMutation = useMutation({
    mutationFn: (payload: CreateScopePayload) => scopeService.create(resourceId, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["scopes", resourceId] });
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
      description: createDescription.trim(),
    });
  }

  // ─── Edit ──────────────────────────────────────────────────────────────────
  const [editScope, setEditScope] = useState<Scope | null>(null);
  const [editName, setEditName] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editError, setEditError] = useState("");

  const editMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: UpdateScopePayload }) =>
      scopeService.update(resourceId, id, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["scopes", resourceId] });
      setEditScope(null);
    },
    onError: (err: unknown) => {
      const msg = getApiErrorMessage(err);
      setEditError(msg);
      toast({ description: msg, variant: "destructive" });
    },
  });

  function openEdit(scope: Scope) {
    setEditScope(scope);
    setEditName(scope.name);
    setEditDescription(scope.description);
    setEditError("");
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setEditError("");
    if (!editScope || !editName.trim()) {
      setEditError("Name is required.");
      return;
    }
    editMutation.mutate({
      id: editScope.id,
      payload: { name: editName.trim(), description: editDescription.trim() },
    });
  }

  // ─── Delete ────────────────────────────────────────────────────────────────
  const [deleteScope, setDeleteScope] = useState<Scope | null>(null);
  const deleteMutation = useMutation({
    mutationFn: (id: string) => scopeService.remove(resourceId, id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["scopes", resourceId] });
      setDeleteScope(null);
    },
    onError: (err: unknown) => {
      toast({ description: getApiErrorMessage(err), variant: "destructive" });
    },
  });

  const columns: Column<Scope>[] = [
    {
      key: "name",
      header: "Name",
      render: (row) => (
        <span className="font-mono text-sm text-foreground/90">{row.name}</span>
      ),
    },
    {
      key: "description",
      header: "Description",
      render: (row) => (
        <span className="text-sm text-muted-foreground">
          {row.description || <span className="opacity-40">—</span>}
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
            aria-label={`Edit scope ${row.name}`}
            onClick={() => openEdit(row)}
            className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
          >
            <Pencil size={14} />
          </button>
          <button
            aria-label={`Delete scope ${row.name}`}
            onClick={() => setDeleteScope(row)}
            className="p-1.5 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors"
          >
            <Trash2 size={14} />
          </button>
        </div>
      ),
    },
  ];

  return (
    <SectionCard
      title={`Scopes — ${resourceName}`}
      action={
        can("scopes:create") ? (
          <Button
            size="sm"
            onClick={() => {
              resetCreateForm();
              setCreateOpen(true);
            }}
          >
            <Plus size={14} />
            New Scope
          </Button>
        ) : undefined
      }
    >
      <DataTable
        columns={columns}
        data={scopes}
        isLoading={isLoading}
        emptyMessage="No scopes defined for this resource."
      />

      <FormDialog
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          resetCreateForm();
        }}
        title={`New Scope on ${resourceName}`}
        onSubmit={handleCreateSubmit}
        isLoading={createMutation.isPending}
        submitLabel="Create"
        error={createError}
        errorId="scope-create-error"
      >
        <ScopeFormFields
          name={createName}
          description={createDescription}
          onNameChange={setCreateName}
          onDescriptionChange={setCreateDescription}
          idPrefix="create-scope"
        />
      </FormDialog>

      <FormDialog
        open={editScope !== null}
        onClose={() => setEditScope(null)}
        title="Edit Scope"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
        error={editError}
        errorId="scope-edit-error"
      >
        <ScopeFormFields
          name={editName}
          description={editDescription}
          onNameChange={setEditName}
          onDescriptionChange={setEditDescription}
          idPrefix="edit-scope"
        />
      </FormDialog>

      <ConfirmDialog
        open={deleteScope !== null}
        onClose={() => setDeleteScope(null)}
        onConfirm={() => deleteScope && deleteMutation.mutate(deleteScope.id)}
        title="Delete Scope"
        description={`Are you sure you want to delete the scope "${deleteScope?.name}"? Grants referencing it will lose that scope constraint.`}
        isLoading={deleteMutation.isPending}
      />
    </SectionCard>
  );
}
