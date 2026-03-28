import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Pencil, Trash2, RotateCw } from "lucide-react";
import {
  serviceAccountService,
  type ServiceAccount,
  type CreateServiceAccountRequest,
  type UpdateServiceAccountRequest,
} from "@/services/serviceAccounts";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { SecretRevealModal } from "@/components/SecretRevealModal";
import { StatusBadge } from "@/components/StatusBadge";
import { SearchInput } from "@/components/SearchInput";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { formatDate } from "@/lib/utils";

// ─── Toggle field ─────────────────────────────────────────────────────────────

interface ToggleFieldProps {
  id: string;
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}

function ToggleField({ id, label, checked, onChange }: ToggleFieldProps) {
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

// ─── Create form fields ───────────────────────────────────────────────────────

interface CreateFieldsProps {
  name: string;
  description: string;
  roles: string;
  onNameChange: (v: string) => void;
  onDescriptionChange: (v: string) => void;
  onRolesChange: (v: string) => void;
  error?: string;
}

function CreateFields({
  name,
  description,
  roles,
  onNameChange,
  onDescriptionChange,
  onRolesChange,
  error,
}: CreateFieldsProps) {
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor="sa-name">Name *</Label>
        <Input
          id="sa-name"
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          placeholder="my-service-account"
          required
          autoComplete="off"
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="sa-description">Description</Label>
        <Textarea
          id="sa-description"
          value={description}
          onChange={(e) => onDescriptionChange(e.target.value)}
          placeholder="What this service account is used for..."
          rows={3}
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="sa-roles">Roles</Label>
        <Textarea
          id="sa-roles"
          value={roles}
          onChange={(e) => onRolesChange(e.target.value)}
          placeholder={"admin\nreader\nwriter"}
          rows={3}
        />
        <p className="text-xs text-muted-foreground">One role per line.</p>
      </div>
      {error && <p className="text-sm text-destructive">{error}</p>}
    </>
  );
}

// ─── Edit form fields ─────────────────────────────────────────────────────────

interface EditFieldsProps {
  name: string;
  description: string;
  isActive: boolean;
  onNameChange: (v: string) => void;
  onDescriptionChange: (v: string) => void;
  onIsActiveChange: (v: boolean) => void;
  error?: string;
}

function EditFields({
  name,
  description,
  isActive,
  onNameChange,
  onDescriptionChange,
  onIsActiveChange,
  error,
}: EditFieldsProps) {
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor="edit-sa-name">Name *</Label>
        <Input
          id="edit-sa-name"
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          placeholder="my-service-account"
          required
          autoComplete="off"
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="edit-sa-description">Description</Label>
        <Textarea
          id="edit-sa-description"
          value={description}
          onChange={(e) => onDescriptionChange(e.target.value)}
          placeholder="What this service account is used for..."
          rows={3}
        />
      </div>
      <ToggleField
        id="edit-sa-active"
        label="Active"
        checked={isActive}
        onChange={onIsActiveChange}
      />
      {error && <p className="text-sm text-destructive">{error}</p>}
    </>
  );
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function parseRoles(raw: string): string[] {
  return raw
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function ServiceAccountsPage() {
  const queryClient = useQueryClient();

  const { data: accounts = [], isLoading } = useQuery({
    queryKey: ["service-accounts"],
    queryFn: () => serviceAccountService.getAll(),
  });

  // ─── Search ─────────────────────────────────────────────────────────────────
  const [search, setSearch] = useState("");

  const filtered = search
    ? accounts.filter(
        (sa) =>
          sa.name.toLowerCase().includes(search.toLowerCase()) ||
          sa.client_id.toLowerCase().includes(search.toLowerCase()),
      )
    : accounts;

  // ─── Create state ──────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false);
  const [createName, setCreateName] = useState("");
  const [createDesc, setCreateDesc] = useState("");
  const [createRoles, setCreateRoles] = useState("");
  const [createError, setCreateError] = useState("");

  // ─── Secret reveal ─────────────────────────────────────────────────────────
  const [secretModalOpen, setSecretModalOpen] = useState(false);
  const [revealedClientId, setRevealedClientId] = useState("");
  const [revealedSecret, setRevealedSecret] = useState("");
  const [secretModalTitle, setSecretModalTitle] = useState("");
  const [secretModalDesc, setSecretModalDesc] = useState("");

  const createMutation = useMutation({
    mutationFn: (payload: CreateServiceAccountRequest) =>
      serviceAccountService.create(payload),
    onSuccess: (resp) => {
      void queryClient.invalidateQueries({
        queryKey: ["service-accounts"],
      });
      setCreateOpen(false);
      resetCreateForm();
      setRevealedClientId(resp.service_account.client_id);
      setRevealedSecret(resp.client_secret);
      setSecretModalTitle("Service Account Created");
      setSecretModalDesc(
        "Your service account has been created. Save the credentials now — the secret will not be shown again.",
      );
      setSecretModalOpen(true);
    },
    onError: (err: unknown) => {
      setCreateError(
        err instanceof Error
          ? err.message
          : "Failed to create service account.",
      );
    },
  });

  function resetCreateForm() {
    setCreateName("");
    setCreateDesc("");
    setCreateRoles("");
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
      description: createDesc.trim() || undefined,
      roles:
        parseRoles(createRoles).length > 0
          ? parseRoles(createRoles)
          : undefined,
    });
  }

  // ─── Edit state ────────────────────────────────────────────────────────────
  const [editAccount, setEditAccount] = useState<ServiceAccount | null>(null);
  const [editName, setEditName] = useState("");
  const [editDesc, setEditDesc] = useState("");
  const [editIsActive, setEditIsActive] = useState(true);
  const [editError, setEditError] = useState("");

  const editMutation = useMutation({
    mutationFn: ({
      id,
      payload,
    }: {
      id: string;
      payload: UpdateServiceAccountRequest;
    }) => serviceAccountService.update(id, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["service-accounts"],
      });
      setEditAccount(null);
    },
    onError: (err: unknown) => {
      setEditError(
        err instanceof Error
          ? err.message
          : "Failed to update service account.",
      );
    },
  });

  function openEdit(sa: ServiceAccount) {
    setEditAccount(sa);
    setEditName(sa.name);
    setEditDesc(sa.description ?? "");
    setEditIsActive(sa.status === "active");
    setEditError("");
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setEditError("");
    if (!editAccount || !editName.trim()) {
      setEditError("Name is required.");
      return;
    }
    editMutation.mutate({
      id: editAccount.id,
      payload: {
        name: editName.trim(),
        description: editDesc.trim() || undefined,
        status: editIsActive ? "active" : "disabled",
      },
    });
  }

  // ─── Delete state ──────────────────────────────────────────────────────────
  const [deleteAccount, setDeleteAccount] = useState<ServiceAccount | null>(
    null,
  );

  const deleteMutation = useMutation({
    mutationFn: (id: string) => serviceAccountService.remove(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["service-accounts"],
      });
      setDeleteAccount(null);
    },
  });

  // ─── Rotate secret state ───────────────────────────────────────────────────
  const [rotateAccount, setRotateAccount] = useState<ServiceAccount | null>(
    null,
  );

  const rotateMutation = useMutation({
    mutationFn: (id: string) => serviceAccountService.rotateSecret(id),
    onSuccess: (resp) => {
      void queryClient.invalidateQueries({
        queryKey: ["service-accounts"],
      });
      setRotateAccount(null);
      setRevealedClientId(resp.client_id);
      setRevealedSecret(resp.client_secret);
      setSecretModalTitle("Secret Rotated");
      setSecretModalDesc(
        "The client secret has been rotated. Save the new credentials — the old secret is now invalid.",
      );
      setSecretModalOpen(true);
    },
  });

  // ─── Table columns ─────────────────────────────────────────────────────────
  const columns: Column<ServiceAccount>[] = [
    {
      key: "name",
      header: "Name",
      render: (row) => (
        <span className="font-medium text-foreground/90">{row.name}</span>
      ),
    },
    {
      key: "client_id",
      header: "Client ID",
      render: (row) => (
        <span
          className="font-mono text-xs text-foreground/70 max-w-[180px] truncate block"
          title={row.client_id}
        >
          {row.client_id}
        </span>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (row) => (
        <StatusBadge status={row.status === "active" ? "active" : "inactive"} />
      ),
    },
    {
      key: "roles",
      header: "Roles",
      render: (row) => (
        <span className="text-sm text-muted-foreground">
          {row.roles.length} {row.roles.length === 1 ? "role" : "roles"}
        </span>
      ),
    },
    {
      key: "last_used_at",
      header: "Last Used",
      render: (row) => (
        <span className="text-sm text-muted-foreground">
          {row.last_used_at ? formatDate(row.last_used_at) : "Never"}
        </span>
      ),
    },
    {
      key: "created_at",
      header: "Created",
      render: (row) => (
        <span className="text-sm text-muted-foreground">
          {formatDate(row.created_at)}
        </span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      width: "w-32",
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
            aria-label={`Rotate secret for ${row.name}`}
            onClick={() => setRotateAccount(row)}
            className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
            title="Rotate secret"
          >
            <RotateCw size={14} />
          </button>
          <button
            aria-label={`Delete ${row.name}`}
            onClick={() => setDeleteAccount(row)}
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
        title="Service Accounts"
        description="Manage machine-to-machine service accounts with client credentials for automated authentication."
        action={
          <Button
            onClick={() => {
              resetCreateForm();
              setCreateOpen(true);
            }}
          >
            <Plus size={16} />
            New Service Account
          </Button>
        }
      />

      {/* Search */}
      <div className="mb-4">
        <SearchInput
          value={search}
          onChange={setSearch}
          placeholder="Search service accounts..."
          className="max-w-sm"
        />
      </div>

      <DataTable
        columns={columns}
        data={filtered}
        isLoading={isLoading}
        emptyMessage="No service accounts found."
      />

      {/* Create dialog */}
      <FormDialog
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          resetCreateForm();
        }}
        title="New Service Account"
        onSubmit={handleCreateSubmit}
        isLoading={createMutation.isPending}
        submitLabel="Create"
      >
        <CreateFields
          name={createName}
          description={createDesc}
          roles={createRoles}
          onNameChange={setCreateName}
          onDescriptionChange={setCreateDesc}
          onRolesChange={setCreateRoles}
          error={createError}
        />
      </FormDialog>

      {/* Edit dialog */}
      <FormDialog
        open={editAccount !== null}
        onClose={() => setEditAccount(null)}
        title="Edit Service Account"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
      >
        <EditFields
          name={editName}
          description={editDesc}
          isActive={editIsActive}
          onNameChange={setEditName}
          onDescriptionChange={setEditDesc}
          onIsActiveChange={setEditIsActive}
          error={editError}
        />
      </FormDialog>

      {/* Secret reveal */}
      <SecretRevealModal
        open={secretModalOpen}
        onClose={() => setSecretModalOpen(false)}
        title={secretModalTitle}
        description={secretModalDesc}
        secrets={[
          { label: "Client ID", value: revealedClientId },
          { label: "Client Secret", value: revealedSecret },
        ]}
      />

      {/* Rotate secret confirm */}
      <ConfirmDialog
        open={rotateAccount !== null}
        onClose={() => setRotateAccount(null)}
        onConfirm={() =>
          rotateAccount && rotateMutation.mutate(rotateAccount.id)
        }
        title="Rotate Client Secret"
        description={`Are you sure you want to rotate the secret for "${rotateAccount?.name}"? The current secret will be immediately invalidated.`}
        isLoading={rotateMutation.isPending}
      />

      {/* Delete confirm */}
      <ConfirmDialog
        open={deleteAccount !== null}
        onClose={() => setDeleteAccount(null)}
        onConfirm={() =>
          deleteAccount && deleteMutation.mutate(deleteAccount.id)
        }
        title="Delete Service Account"
        description={`Are you sure you want to delete "${deleteAccount?.name}"? All associated credentials will be revoked.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}
