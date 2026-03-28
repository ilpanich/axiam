import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  orgService,
  type Organization,
  type CreateOrganizationPayload,
} from "@/services/organizations";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Pencil, Trash2, Plus } from "lucide-react";
import { Textarea } from "@/components/ui/textarea";
import { formatDate } from "@/lib/utils";

function slugify(value: string): string {
  return value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

// ─── Org form (shared between create/edit) ────────────────────────────────────

interface OrgFormFieldsProps {
  name: string;
  slug: string;
  description: string;
  onNameChange: (v: string) => void;
  onSlugChange: (v: string) => void;
  onDescriptionChange: (v: string) => void;
  error?: string;
}

function OrgFormFields({
  name,
  slug,
  description,
  onNameChange,
  onSlugChange,
  onDescriptionChange,
  error,
}: OrgFormFieldsProps) {
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor="org-name">Name *</Label>
        <Input
          id="org-name"
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          placeholder="Acme Corp"
          required
          autoComplete="off"
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="org-slug">Slug *</Label>
        <Input
          id="org-slug"
          value={slug}
          onChange={(e) => onSlugChange(e.target.value)}
          placeholder="acme-corp"
          required
          autoComplete="off"
        />
        <p className="text-xs text-muted-foreground">
          URL-safe identifier, auto-generated from name.
        </p>
      </div>
      <div className="space-y-2">
        <Label htmlFor="org-description">Description</Label>
        <Textarea
          id="org-description"
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

export function OrganizationsPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  // ─── Query ───────────────────────────────────────────────────────────────────
  const { data: orgs = [], isLoading } = useQuery({
    queryKey: ["organizations"],
    queryFn: orgService.list,
  });

  // ─── Create state ─────────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false);
  const [createName, setCreateName] = useState("");
  const [createSlug, setCreateSlug] = useState("");
  const [createDescription, setCreateDescription] = useState("");
  const [createError, setCreateError] = useState("");

  const createMutation = useMutation({
    mutationFn: (payload: CreateOrganizationPayload) =>
      orgService.create(payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["organizations"] });
      setCreateOpen(false);
      resetCreateForm();
    },
    onError: (err: unknown) => {
      setCreateError(
        err instanceof Error ? err.message : "Failed to create organization."
      );
    },
  });

  function resetCreateForm() {
    setCreateName("");
    setCreateSlug("");
    setCreateDescription("");
    setCreateError("");
  }

  function handleCreateNameChange(v: string) {
    setCreateName(v);
    setCreateSlug(slugify(v));
  }

  function handleCreateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setCreateError("");
    if (!createName.trim() || !createSlug.trim()) {
      setCreateError("Name and slug are required.");
      return;
    }
    createMutation.mutate({
      name: createName.trim(),
      slug: createSlug.trim(),
      description: createDescription.trim() || undefined,
    });
  }

  // ─── Edit state ───────────────────────────────────────────────────────────────
  const [editOrg, setEditOrg] = useState<Organization | null>(null);
  const [editName, setEditName] = useState("");
  const [editSlug, setEditSlug] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editError, setEditError] = useState("");

  const editMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: CreateOrganizationPayload }) =>
      orgService.update(id, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["organizations"] });
      setEditOrg(null);
    },
    onError: (err: unknown) => {
      setEditError(
        err instanceof Error ? err.message : "Failed to update organization."
      );
    },
  });

  function openEdit(org: Organization) {
    setEditOrg(org);
    setEditName(org.name);
    setEditSlug(org.slug);
    setEditDescription(org.description ?? "");
    setEditError("");
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setEditError("");
    if (!editOrg) return;
    if (!editName.trim() || !editSlug.trim()) {
      setEditError("Name and slug are required.");
      return;
    }
    editMutation.mutate({
      id: editOrg.id,
      payload: {
        name: editName.trim(),
        slug: editSlug.trim(),
        description: editDescription.trim() || undefined,
      },
    });
  }

  // ─── Delete state ─────────────────────────────────────────────────────────────
  const [deleteOrg, setDeleteOrg] = useState<Organization | null>(null);

  const deleteMutation = useMutation({
    mutationFn: (id: string) => orgService.remove(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["organizations"] });
      setDeleteOrg(null);
    },
  });

  // ─── Table columns ─────────────────────────────────────────────────────────────
  const columns: Column<Organization>[] = [
    {
      key: "name",
      header: "Name",
      render: (row) => (
        <button
          className="font-medium text-primary hover:underline focus:outline-none focus:underline"
          onClick={() => navigate(`/organizations/${row.id}`)}
        >
          {row.name}
        </button>
      ),
    },
    {
      key: "slug",
      header: "Slug",
      render: (row) => (
        <code className="text-xs bg-white/5 px-1.5 py-0.5 rounded text-muted-foreground">
          {row.slug}
        </code>
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
      width: "w-24",
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
            onClick={() => setDeleteOrg(row)}
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
        title="Organizations"
        description="Manage top-level organizations and their CA certificates."
        action={
          <Button
            onClick={() => {
              resetCreateForm();
              setCreateOpen(true);
            }}
          >
            <Plus size={16} />
            New Organization
          </Button>
        }
      />

      <DataTable
        columns={columns}
        data={orgs}
        isLoading={isLoading}
        emptyMessage="No organizations yet. Create your first one."
      />

      {/* Create dialog */}
      <FormDialog
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          resetCreateForm();
        }}
        title="New Organization"
        onSubmit={handleCreateSubmit}
        isLoading={createMutation.isPending}
        submitLabel="Create"
      >
        <OrgFormFields
          name={createName}
          slug={createSlug}
          description={createDescription}
          onNameChange={handleCreateNameChange}
          onSlugChange={setCreateSlug}
          onDescriptionChange={setCreateDescription}
          error={createError}
        />
      </FormDialog>

      {/* Edit dialog */}
      <FormDialog
        open={editOrg !== null}
        onClose={() => setEditOrg(null)}
        title="Edit Organization"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
      >
        <OrgFormFields
          name={editName}
          slug={editSlug}
          description={editDescription}
          onNameChange={(v) => {
            setEditName(v);
            setEditSlug(slugify(v));
          }}
          onSlugChange={setEditSlug}
          onDescriptionChange={setEditDescription}
          error={editError}
        />
      </FormDialog>

      {/* Delete confirm */}
      <ConfirmDialog
        open={deleteOrg !== null}
        onClose={() => setDeleteOrg(null)}
        onConfirm={() => deleteOrg && deleteMutation.mutate(deleteOrg.id)}
        title="Delete Organization"
        description={`Are you sure you want to delete "${deleteOrg?.name}"? This action cannot be undone.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}
