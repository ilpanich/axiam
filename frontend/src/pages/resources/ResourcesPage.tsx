import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  resourceService,
  type Resource,
  type CreateResourcePayload,
  type UpdateResourcePayload,
} from "@/services/resources";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { ResourceTree } from "@/components/ResourceTree";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { List, Network, Pencil, Plus, Trash2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { Textarea } from "@/components/ui/textarea";

const formatDate = (iso: string) =>
  new Intl.DateTimeFormat("en-US", { dateStyle: "medium" }).format(
    new Date(iso)
  );

// ─── Resource type badge ──────────────────────────────────────────────────────

function ResourceTypeBadge({ type }: { type: string }) {
  return (
    <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider bg-white/5 text-muted-foreground border border-white/10">
      {type}
    </span>
  );
}

// ─── Standard resource types ──────────────────────────────────────────────────

const STANDARD_TYPES = ["api", "service", "dataset", "endpoint"] as const;

// ─── Resource form fields ─────────────────────────────────────────────────────

interface ResourceFormFieldsProps {
  name: string;
  resourceType: string;
  customType: string;
  parentId: string;
  description: string;
  onNameChange: (v: string) => void;
  onResourceTypeChange: (v: string) => void;
  onCustomTypeChange: (v: string) => void;
  onParentIdChange: (v: string) => void;
  onDescriptionChange: (v: string) => void;
  error?: string;
  idPrefix: string;
  allResources: Resource[];
  excludeId?: string;
}

function ResourceFormFields({
  name,
  resourceType,
  customType,
  parentId,
  description,
  onNameChange,
  onResourceTypeChange,
  onCustomTypeChange,
  onParentIdChange,
  onDescriptionChange,
  error,
  idPrefix,
  allResources,
  excludeId,
}: ResourceFormFieldsProps) {
  const availableParents = allResources.filter((r) => r.id !== excludeId);

  return (
    <>
      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-name`}>Name *</Label>
        <Input
          id={`${idPrefix}-name`}
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          placeholder="e.g. API Gateway"
          required
          autoComplete="off"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-type`}>Resource Type *</Label>
        <select
          id={`${idPrefix}-type`}
          value={resourceType}
          onChange={(e) => onResourceTypeChange(e.target.value)}
          className={cn(
            "flex h-9 w-full rounded-md px-3 py-1 text-sm",
            "bg-white/5 border border-primary/20 text-foreground",
            "focus:outline-none focus:ring-2 focus:ring-primary/40 focus:border-primary",
            "transition-colors duration-200"
          )}
        >
          {STANDARD_TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
          <option value="custom">custom…</option>
        </select>
        {resourceType === "custom" && (
          <Input
            id={`${idPrefix}-custom-type`}
            value={customType}
            onChange={(e) => onCustomTypeChange(e.target.value)}
            placeholder="Enter custom type"
            autoComplete="off"
            className="mt-1.5"
          />
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-parent`}>Parent Resource</Label>
        <select
          id={`${idPrefix}-parent`}
          value={parentId}
          onChange={(e) => onParentIdChange(e.target.value)}
          className={cn(
            "flex h-9 w-full rounded-md px-3 py-1 text-sm",
            "bg-white/5 border border-primary/20 text-foreground",
            "focus:outline-none focus:ring-2 focus:ring-primary/40 focus:border-primary",
            "transition-colors duration-200"
          )}
        >
          <option value="">None (root)</option>
          {availableParents.map((r) => (
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

// ─── View toggle ──────────────────────────────────────────────────────────────

type ViewMode = "tree" | "list";

// ─── Main page ─────────────────────────────────────────────────────────────────

export function ResourcesPage() {
  const queryClient = useQueryClient();
  const [viewMode, setViewMode] = useState<ViewMode>("tree");
  const [selectedId, setSelectedId] = useState<string | undefined>(undefined);

  const { data: resources = [], isLoading } = useQuery({
    queryKey: ["resources"],
    queryFn: () => resourceService.list(),
  });

  // Helper: resolve parent resource name
  function parentName(parentId?: string): string {
    if (!parentId) return "Root";
    return resources.find((r) => r.id === parentId)?.name ?? parentId;
  }

  // ─── Create state ──────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false);
  const [createName, setCreateName] = useState("");
  const [createType, setCreateType] = useState<string>("api");
  const [createCustomType, setCreateCustomType] = useState("");
  const [createParentId, setCreateParentId] = useState("");
  const [createDescription, setCreateDescription] = useState("");
  const [createError, setCreateError] = useState("");

  const createMutation = useMutation({
    mutationFn: (payload: CreateResourcePayload) =>
      resourceService.create(payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["resources"] });
      setCreateOpen(false);
      resetCreateForm();
    },
    onError: (err: unknown) => {
      setCreateError(
        err instanceof Error ? err.message : "Failed to create resource."
      );
    },
  });

  function resetCreateForm() {
    setCreateName("");
    setCreateType("api");
    setCreateCustomType("");
    setCreateParentId("");
    setCreateDescription("");
    setCreateError("");
  }

  function resolvedType(type: string, custom: string): string {
    return type === "custom" ? custom.trim() : type;
  }

  function handleCreateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setCreateError("");
    if (!createName.trim()) {
      setCreateError("Name is required.");
      return;
    }
    const finalType = resolvedType(createType, createCustomType);
    if (!finalType) {
      setCreateError("Resource type is required.");
      return;
    }
    createMutation.mutate({
      name: createName.trim(),
      resource_type: finalType,
      parent_id: createParentId || undefined,
      description: createDescription.trim() || undefined,
    });
  }

  // ─── Edit state ────────────────────────────────────────────────────────────
  const [editResource, setEditResource] = useState<Resource | null>(null);
  const [editName, setEditName] = useState("");
  const [editType, setEditType] = useState<string>("api");
  const [editCustomType, setEditCustomType] = useState("");
  const [editParentId, setEditParentId] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editError, setEditError] = useState("");

  const editMutation = useMutation({
    mutationFn: ({
      id,
      payload,
    }: {
      id: string;
      payload: UpdateResourcePayload;
    }) => resourceService.update(id, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["resources"] });
      setEditResource(null);
    },
    onError: (err: unknown) => {
      setEditError(
        err instanceof Error ? err.message : "Failed to update resource."
      );
    },
  });

  function openEdit(resource: Resource) {
    setEditResource(resource);
    setEditName(resource.name);
    const isStandard = (STANDARD_TYPES as readonly string[]).includes(
      resource.resource_type
    );
    setEditType(isStandard ? resource.resource_type : "custom");
    setEditCustomType(isStandard ? "" : resource.resource_type);
    setEditParentId(resource.parent_id ?? "");
    setEditDescription(resource.description ?? "");
    setEditError("");
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setEditError("");
    if (!editResource || !editName.trim()) {
      setEditError("Name is required.");
      return;
    }
    const finalType = resolvedType(editType, editCustomType);
    if (!finalType) {
      setEditError("Resource type is required.");
      return;
    }
    editMutation.mutate({
      id: editResource.id,
      payload: {
        name: editName.trim(),
        resource_type: finalType,
        parent_id: editParentId || undefined,
        description: editDescription.trim() || undefined,
      },
    });
  }

  // ─── Delete state ──────────────────────────────────────────────────────────
  const [deleteResource, setDeleteResource] = useState<Resource | null>(null);

  const deleteMutation = useMutation({
    mutationFn: (id: string) => resourceService.remove(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["resources"] });
      setDeleteResource(null);
    },
  });

  // ─── Tree action buttons ───────────────────────────────────────────────────
  function treeActions(resource: Resource) {
    return (
      <>
        <button
          aria-label={`Edit ${resource.name}`}
          onClick={() => openEdit(resource)}
          className="p-1 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
        >
          <Pencil size={13} />
        </button>
        <button
          aria-label={`Delete ${resource.name}`}
          onClick={() => setDeleteResource(resource)}
          className="p-1 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors"
        >
          <Trash2 size={13} />
        </button>
      </>
    );
  }

  // ─── List table columns ────────────────────────────────────────────────────
  const columns: Column<Resource>[] = [
    {
      key: "name",
      header: "Name",
      render: (row) => (
        <span className="font-medium text-foreground/90">{row.name}</span>
      ),
    },
    {
      key: "resource_type",
      header: "Type",
      render: (row) => <ResourceTypeBadge type={row.resource_type} />,
    },
    {
      key: "parent_id",
      header: "Parent",
      render: (row) => (
        <span className="text-muted-foreground text-sm">
          {row.parent_id ? (
            parentName(row.parent_id)
          ) : (
            <span className="text-cyan-400/70 text-xs italic">Root</span>
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
            onClick={() => setDeleteResource(row)}
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
        title="Resources"
        description="Define the resource hierarchy for role-based access control."
        action={
          <div className="flex items-center gap-2">
            {/* View toggle */}
            <div className="flex items-center rounded-md border border-primary/20 overflow-hidden">
              <button
                aria-label="Tree view"
                aria-pressed={viewMode === "tree"}
                onClick={() => setViewMode("tree")}
                className={cn(
                  "px-2.5 py-1.5 transition-colors",
                  viewMode === "tree"
                    ? "bg-primary/20 text-primary"
                    : "text-muted-foreground hover:text-foreground hover:bg-white/5"
                )}
              >
                <Network size={15} />
              </button>
              <button
                aria-label="List view"
                aria-pressed={viewMode === "list"}
                onClick={() => setViewMode("list")}
                className={cn(
                  "px-2.5 py-1.5 transition-colors",
                  viewMode === "list"
                    ? "bg-primary/20 text-primary"
                    : "text-muted-foreground hover:text-foreground hover:bg-white/5"
                )}
              >
                <List size={15} />
              </button>
            </div>

            <Button
              onClick={() => {
                resetCreateForm();
                setCreateOpen(true);
              }}
            >
              <Plus size={16} />
              New Resource
            </Button>
          </div>
        }
      />

      {/* Views */}
      {viewMode === "tree" ? (
        <div className="glass-card">
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <div className="h-6 w-6 border-2 border-primary/40 border-t-primary rounded-full animate-spin" />
            </div>
          ) : (
            <ResourceTree
              resources={resources}
              onSelect={(r) => setSelectedId(r.id)}
              selectedId={selectedId}
              actions={treeActions}
            />
          )}
        </div>
      ) : (
        <DataTable
          columns={columns}
          data={resources}
          isLoading={isLoading}
          emptyMessage="No resources defined yet."
        />
      )}

      {/* Create dialog */}
      <FormDialog
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          resetCreateForm();
        }}
        title="New Resource"
        onSubmit={handleCreateSubmit}
        isLoading={createMutation.isPending}
        submitLabel="Create"
      >
        <ResourceFormFields
          name={createName}
          resourceType={createType}
          customType={createCustomType}
          parentId={createParentId}
          description={createDescription}
          onNameChange={setCreateName}
          onResourceTypeChange={setCreateType}
          onCustomTypeChange={setCreateCustomType}
          onParentIdChange={setCreateParentId}
          onDescriptionChange={setCreateDescription}
          error={createError}
          idPrefix="create-res"
          allResources={resources}
        />
      </FormDialog>

      {/* Edit dialog */}
      <FormDialog
        open={editResource !== null}
        onClose={() => setEditResource(null)}
        title="Edit Resource"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
      >
        <ResourceFormFields
          name={editName}
          resourceType={editType}
          customType={editCustomType}
          parentId={editParentId}
          description={editDescription}
          onNameChange={setEditName}
          onResourceTypeChange={setEditType}
          onCustomTypeChange={setEditCustomType}
          onParentIdChange={setEditParentId}
          onDescriptionChange={setEditDescription}
          error={editError}
          idPrefix="edit-res"
          allResources={resources}
          excludeId={editResource?.id}
        />
      </FormDialog>

      {/* Delete confirm */}
      <ConfirmDialog
        open={deleteResource !== null}
        onClose={() => setDeleteResource(null)}
        onConfirm={() =>
          deleteResource && deleteMutation.mutate(deleteResource.id)
        }
        title="Delete Resource"
        description={`Are you sure you want to delete "${deleteResource?.name}"? Child resources may be affected.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}
