import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  orgService,
  tenantService,
  type Organization,
  type Tenant,
  type CreateTenantPayload,
  type UpdateTenantPayload,
} from "@/services/organizations";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { StatusBadge } from "@/components/StatusBadge";
import { SearchInput } from "@/components/SearchInput";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Eye, Pencil, Plus, Trash2 } from "lucide-react";
import { formatDate } from "@/lib/utils";

// ─── Enriched tenant type (includes org name for display) ─────────────────────

interface TenantWithOrg extends Tenant {
  org_name: string;
}

// ─── Create form fields ───────────────────────────────────────────────────────

interface CreateTenantFieldsProps {
  name: string;
  slug: string;
  description: string;
  orgId: string;
  organizations: Organization[];
  onNameChange: (v: string) => void;
  onSlugChange: (v: string) => void;
  onDescriptionChange: (v: string) => void;
  onOrgIdChange: (v: string) => void;
  error?: string;
}

function CreateTenantFields({
  name,
  slug,
  description,
  orgId,
  organizations,
  onNameChange,
  onSlugChange,
  onDescriptionChange,
  onOrgIdChange,
  error,
}: CreateTenantFieldsProps) {
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor="tenant-org">Organization *</Label>
        <select
          id="tenant-org"
          value={orgId}
          onChange={(e) => onOrgIdChange(e.target.value)}
          required
          className="flex w-full rounded-md px-3 py-2 text-sm bg-white/5 border border-primary/20 text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/40 focus:border-primary transition-colors duration-200"
        >
          <option value="" className="bg-background text-foreground">
            Select organization...
          </option>
          {organizations.map((org) => (
            <option
              key={org.id}
              value={org.id}
              className="bg-background text-foreground"
            >
              {org.name}
            </option>
          ))}
        </select>
      </div>
      <div className="space-y-2">
        <Label htmlFor="tenant-name">Name *</Label>
        <Input
          id="tenant-name"
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          placeholder="Production"
          required
          autoComplete="off"
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="tenant-slug">Slug *</Label>
        <Input
          id="tenant-slug"
          value={slug}
          onChange={(e) => onSlugChange(e.target.value)}
          placeholder="production"
          required
          autoComplete="off"
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="tenant-description">Description</Label>
        <Textarea
          id="tenant-description"
          value={description}
          onChange={(e) => onDescriptionChange(e.target.value)}
          placeholder="Optional description for this tenant"
          rows={3}
        />
      </div>
      {error && <p className="text-sm text-destructive">{error}</p>}
    </>
  );
}

// ─── Edit form fields ─────────────────────────────────────────────────────────

interface EditTenantFieldsProps {
  name: string;
  slug: string;
  description: string;
  onNameChange: (v: string) => void;
  onSlugChange: (v: string) => void;
  onDescriptionChange: (v: string) => void;
  error?: string;
}

function EditTenantFields({
  name,
  slug,
  description,
  onNameChange,
  onSlugChange,
  onDescriptionChange,
  error,
}: EditTenantFieldsProps) {
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor="edit-tenant-name">Name *</Label>
        <Input
          id="edit-tenant-name"
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          placeholder="Production"
          required
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="edit-tenant-slug">Slug *</Label>
        <Input
          id="edit-tenant-slug"
          value={slug}
          onChange={(e) => onSlugChange(e.target.value)}
          placeholder="production"
          required
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="edit-tenant-description">Description</Label>
        <Textarea
          id="edit-tenant-description"
          value={description}
          onChange={(e) => onDescriptionChange(e.target.value)}
          placeholder="Optional description for this tenant"
          rows={3}
        />
      </div>
      {error && <p className="text-sm text-destructive">{error}</p>}
    </>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────────

export function TenantsPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  // ─── Search state ──────────────────────────────────────────────────────────
  const [search, setSearch] = useState("");

  // ─── Fetch organizations (for select & name mapping) ───────────────────────
  const { data: organizations = [] } = useQuery({
    queryKey: ["organizations"],
    queryFn: () => orgService.list(),
  });

  // ─── Fetch tenants across all organizations ────────────────────────────────
  const { data: tenants = [], isLoading } = useQuery({
    queryKey: ["tenants", organizations.map((o) => o.id)],
    queryFn: async () => {
      if (organizations.length === 0) return [];
      const results = await Promise.all(
        organizations.map((org) =>
          tenantService.list(org.id).then((list) =>
            list.map((t) => ({
              ...t,
              org_name: org.name,
            }))
          )
        )
      );
      return results.flat();
    },
    enabled: organizations.length > 0,
  });

  // ─── Filter tenants by search ──────────────────────────────────────────────
  const filteredTenants = search
    ? tenants.filter(
        (t) =>
          t.name.toLowerCase().includes(search.toLowerCase()) ||
          t.slug.toLowerCase().includes(search.toLowerCase()) ||
          t.org_name.toLowerCase().includes(search.toLowerCase())
      )
    : tenants;

  function handleSearchChange(value: string) {
    setSearch(value);
  }

  // ─── Create state ──────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false);
  const [createName, setCreateName] = useState("");
  const [createSlug, setCreateSlug] = useState("");
  const [createDescription, setCreateDescription] = useState("");
  const [createOrgId, setCreateOrgId] = useState("");
  const [createError, setCreateError] = useState("");

  const createMutation = useMutation({
    mutationFn: ({
      orgId,
      payload,
    }: {
      orgId: string;
      payload: CreateTenantPayload;
    }) => tenantService.create(orgId, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["tenants"] });
      setCreateOpen(false);
      resetCreateForm();
    },
    onError: (err: unknown) => {
      setCreateError(
        err instanceof Error ? err.message : "Failed to create tenant."
      );
    },
  });

  function resetCreateForm() {
    setCreateName("");
    setCreateSlug("");
    setCreateDescription("");
    setCreateOrgId("");
    setCreateError("");
  }

  function handleCreateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setCreateError("");
    if (!createOrgId) {
      setCreateError("Please select an organization.");
      return;
    }
    if (!createName.trim() || !createSlug.trim()) {
      setCreateError("Name and slug are required.");
      return;
    }
    createMutation.mutate({
      orgId: createOrgId,
      payload: {
        name: createName.trim(),
        slug: createSlug.trim(),
        description: createDescription.trim() || undefined,
      },
    });
  }

  // ─── Edit state ────────────────────────────────────────────────────────────
  const [editTenant, setEditTenant] = useState<TenantWithOrg | null>(null);
  const [editName, setEditName] = useState("");
  const [editSlug, setEditSlug] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editError, setEditError] = useState("");

  const editMutation = useMutation({
    mutationFn: ({
      orgId,
      tenantId,
      payload,
    }: {
      orgId: string;
      tenantId: string;
      payload: UpdateTenantPayload;
    }) => tenantService.update(orgId, tenantId, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["tenants"] });
      setEditTenant(null);
    },
    onError: (err: unknown) => {
      setEditError(
        err instanceof Error ? err.message : "Failed to update tenant."
      );
    },
  });

  function openEdit(tenant: TenantWithOrg) {
    setEditTenant(tenant);
    setEditName(tenant.name);
    setEditSlug(tenant.slug);
    setEditDescription(tenant.description ?? "");
    setEditError("");
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setEditError("");
    if (!editTenant || !editName.trim() || !editSlug.trim()) {
      setEditError("Name and slug are required.");
      return;
    }
    editMutation.mutate({
      orgId: editTenant.org_id,
      tenantId: editTenant.id,
      payload: {
        name: editName.trim(),
        slug: editSlug.trim(),
        description: editDescription.trim() || undefined,
      },
    });
  }

  // ─── Delete state ──────────────────────────────────────────────────────────
  const [deleteTenant, setDeleteTenant] = useState<TenantWithOrg | null>(null);

  const deleteMutation = useMutation({
    mutationFn: ({ orgId, tenantId }: { orgId: string; tenantId: string }) =>
      tenantService.remove(orgId, tenantId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["tenants"] });
      setDeleteTenant(null);
    },
  });

  // ─── Table columns ────────────────────────────────────────────────────────
  const columns: Column<TenantWithOrg>[] = [
    {
      key: "name",
      header: "Name",
      render: (row) => (
        <span className="font-medium text-foreground/90">{row.name}</span>
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
      key: "org_name",
      header: "Organization",
      render: (row) => (
        <span className="text-muted-foreground text-sm">
          {row.org_name}
        </span>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: () => <StatusBadge status="active" />,
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
            onClick={() =>
              navigate(`/organizations/${row.org_id}/tenants/${row.id}`)
            }
            className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
          >
            <Eye size={14} />
          </button>
          <button
            aria-label={`Delete ${row.name}`}
            onClick={() => setDeleteTenant(row)}
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
        title="Tenants"
        description="Manage tenants across all organizations. Tenants provide full data isolation."
        action={
          <Button
            onClick={() => {
              resetCreateForm();
              setCreateOpen(true);
            }}
          >
            <Plus size={16} />
            New Tenant
          </Button>
        }
      />

      {/* Search + count */}
      <div className="flex items-center justify-between gap-4 mb-4">
        <SearchInput
          value={search}
          onChange={handleSearchChange}
          placeholder="Search tenants..."
          className="max-w-sm"
        />
        <span className="text-sm text-muted-foreground shrink-0">
          {filteredTenants.length} tenant{filteredTenants.length !== 1 ? "s" : ""}
        </span>
      </div>

      <DataTable
        columns={columns}
        data={filteredTenants}
        isLoading={isLoading}
        emptyMessage="No tenants found."
      />

      {/* Create dialog */}
      <FormDialog
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          resetCreateForm();
        }}
        title="New Tenant"
        onSubmit={handleCreateSubmit}
        isLoading={createMutation.isPending}
        submitLabel="Create"
      >
        <CreateTenantFields
          name={createName}
          slug={createSlug}
          description={createDescription}
          orgId={createOrgId}
          organizations={organizations}
          onNameChange={setCreateName}
          onSlugChange={setCreateSlug}
          onDescriptionChange={setCreateDescription}
          onOrgIdChange={setCreateOrgId}
          error={createError}
        />
      </FormDialog>

      {/* Edit dialog */}
      <FormDialog
        open={editTenant !== null}
        onClose={() => setEditTenant(null)}
        title="Edit Tenant"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
      >
        <EditTenantFields
          name={editName}
          slug={editSlug}
          description={editDescription}
          onNameChange={setEditName}
          onSlugChange={setEditSlug}
          onDescriptionChange={setEditDescription}
          error={editError}
        />
      </FormDialog>

      {/* Delete confirm */}
      <ConfirmDialog
        open={deleteTenant !== null}
        onClose={() => setDeleteTenant(null)}
        onConfirm={() =>
          deleteTenant &&
          deleteMutation.mutate({
            orgId: deleteTenant.org_id,
            tenantId: deleteTenant.id,
          })
        }
        title="Delete Tenant"
        description={`Are you sure you want to delete "${deleteTenant?.name}"? This will remove all data within this tenant. This action cannot be undone.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}
