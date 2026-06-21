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
  onNameChange: (v: string) => void;
  error?: string;
}

function CreateFields({ name, onNameChange, error }: CreateFieldsProps) {
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
      {error && <p className="text-sm text-destructive">{error}</p>}
    </>
  );
}

// ─── Edit form fields ─────────────────────────────────────────────────────────

interface EditFieldsProps {
  name: string;
  isActive: boolean;
  onNameChange: (v: string) => void;
  onIsActiveChange: (v: boolean) => void;
  error?: string;
}

function EditFields({
  name,
  isActive,
  onNameChange,
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
      setRevealedClientId(resp.client_id);
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
    });
  }

  // ─── Edit state ────────────────────────────────────────────────────────────
  const [editAccount, setEditAccount] = useState<ServiceAccount | null>(null);
  const [editName, setEditName] = useState("");
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
    setEditIsActive(sa.status === "Active");
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
        status: editIsActive ? "Active" : "Inactive",
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
      // Rotation returns only the new secret; the client_id is unchanged,
      // so show the rotated account's existing client_id.
      setRevealedClientId(rotateAccount?.client_id ?? "");
      setRotateAccount(null);
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
        <StatusBadge status={row.status === "Active" ? "active" : "inactive"} />
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
          onNameChange={setCreateName}
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
          isActive={editIsActive}
          onNameChange={setEditName}
          onIsActiveChange={setEditIsActive}
          error={editError}
        />
      </FormDialog>

      {/* Secret reveal */}
      <SecretRevealModal
        open={secretModalOpen}
        onClose={() => { setSecretModalOpen(false); setRevealedClientId(""); setRevealedSecret(""); setSecretModalTitle(""); setSecretModalDesc(""); }}
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
        confirmLabel="Rotate"
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
