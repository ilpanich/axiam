import { useMemo, useState } from "react";
import { Link } from "react-router";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Plus,
  Pencil,
  Trash2,
  RotateCw,
  FileKey,
  ShieldCheck,
  ShieldOff,
} from "lucide-react";
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
import { cn, formatDate } from "@/lib/utils";
import { ToggleField } from "@/components/shared";
import {
  certificateService,
  type Certificate,
  type CertificateType,
} from "@/services/certificates";
import { usePermissions } from "@/hooks/usePermissions";
import { invalidateEntity } from "@/lib/queryInvalidation";

// ─── Create form fields ───────────────────────────────────────────────────────

interface CreateFieldsProps {
  name: string;
  description: string;
  onNameChange: (v: string) => void;
  onDescriptionChange: (v: string) => void;
}

function CreateFields({
  name,
  description,
  onNameChange,
  onDescriptionChange,
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
          placeholder="Optional description of this account's purpose"
          rows={3}
        />
      </div>
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
}

function EditFields({
  name,
  description,
  isActive,
  onNameChange,
  onDescriptionChange,
  onIsActiveChange,
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
          placeholder="Optional description of this account's purpose"
          rows={3}
        />
      </div>
      <ToggleField
        id="edit-sa-active"
        label="Active"
        checked={isActive}
        onChange={onIsActiveChange}
      />
    </>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function ServiceAccountsPage() {
  const queryClient = useQueryClient();
  const { can } = usePermissions();

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
  const [createDescription, setCreateDescription] = useState("");
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
      invalidateEntity(queryClient, "service-accounts");
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
    const description = createDescription.trim();
    createMutation.mutate({
      name: createName.trim(),
      description: description || undefined,
    });
  }

  // ─── Edit state ────────────────────────────────────────────────────────────
  const [editAccount, setEditAccount] = useState<ServiceAccount | null>(null);
  const [editName, setEditName] = useState("");
  const [editDescription, setEditDescription] = useState("");
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
      invalidateEntity(queryClient, "service-accounts");
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
    setEditDescription(sa.description ?? "");
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
        description: editDescription.trim(),
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
      invalidateEntity(queryClient, "service-accounts");
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
      invalidateEntity(queryClient, "service-accounts");
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
  // ─── Certificate binding ───────────────────────────────────────────────────
  // Lets a service account authenticate by mTLS rather than by its client
  // secret — the credential shape IoT and service-mesh deployments actually
  // use, and until now reachable only by calling the API directly.
  const canBindCertificate = can("certificates:bind");

  const [bindAccount, setBindAccount] = useState<ServiceAccount | null>(null);
  const [bindCertId, setBindCertId] = useState("");
  const [bindError, setBindError] = useState("");

  // A revoked or expired certificate would bind and then fail every handshake,
  // so only Active ones are offered.
  const { data: allCertificates = [] } = useQuery({
    queryKey: ["certificates"],
    queryFn: () => certificateService.list(),
    // Not gated on the bind dialog any more. The "Certificate" column below
    // needs this on every render — gating it meant the page could only learn
    // about bindings *while* someone was creating one, which is the moment they
    // least need telling.
    enabled: canBindCertificate,
  });

  // Which service account each certificate authenticates, keyed the way the
  // table reads it. Built once per render rather than scanned per row.
  const certificateBySaId = useMemo(() => {
    const map = new Map<string, Certificate>();
    for (const cert of allCertificates) {
      if (cert.bound_service_account_id) {
        map.set(cert.bound_service_account_id, cert);
      }
    }
    return map;
  }, [allCertificates]);

  // Device certificates belong here as much as Service ones. An IoT device
  // authenticating by mTLS *is* a machine principal, and binding its
  // certificate to a service account is how it gets an identity to carry —
  // it is the deployment shape this feature was built for. Filtering to
  // `cert_type === "Service"` left the picker empty for exactly those
  // deployments, with no explanation and nothing to select.
  //
  // The backend never had this restriction: `POST /service-accounts/{id}
  // /bind-certificate` checks tenant ownership and nothing about the type. This
  // was a client-side filter with no server-side counterpart, which is the
  // shape a restriction takes when it was assumed rather than decided.
  //
  // `User` certificates stay out: those identify a person, and binding one to a
  // machine account would let a service authenticate as its holder.
  const BINDABLE_CERT_TYPES: CertificateType[] = ["Service", "Device"];

  const bindableCertificates = allCertificates.filter(
    (c) => c.status === "Active" && BINDABLE_CERT_TYPES.includes(c.cert_type)
  );

  function openBind(account: ServiceAccount) {
    setBindAccount(account);
    setBindCertId("");
    setBindError("");
  }

  const bindMutation = useMutation({
    mutationFn: ({ saId, certId }: { saId: string; certId: string }) =>
      certificateService.bindToServiceAccount(saId, certId),
    onSuccess: () => {
      invalidateEntity(queryClient, "service-accounts");
      setBindAccount(null);
      setBindCertId("");
    },
    onError: (err: unknown) =>
      setBindError(
        err instanceof Error ? err.message : "Failed to bind the certificate."
      ),
  });

  function handleBindSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBindError("");
    if (!bindAccount) return;
    if (!bindCertId) {
      setBindError("Select a certificate to bind.");
      return;
    }
    bindMutation.mutate({ saId: bindAccount.id, certId: bindCertId });
  }

  const columns: Column<ServiceAccount>[] = [
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
      render: (row) =>
        row.description ? (
          <span
            className="text-sm text-muted-foreground max-w-[220px] truncate block"
            title={row.description}
          >
            {row.description}
          </span>
        ) : (
          <span className="text-sm text-muted-foreground/40">—</span>
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
      key: "certificate",
      header: "Certificate",
      render: (row) => {
        const cert = certificateBySaId.get(row.id);
        if (!cert) {
          return (
            <span
              className="inline-flex items-center gap-1 text-xs text-muted-foreground/60"
              title="No certificate is bound — this account authenticates by client secret only"
            >
              <ShieldOff size={12} aria-hidden="true" />
              None
            </span>
          );
        }
        const expired = new Date(cert.not_after) < new Date();
        return (
          <span
            className={cn(
              "inline-flex items-center gap-1 text-xs font-mono max-w-[200px] truncate",
              expired ? "text-amber-400" : "text-emerald-400"
            )}
            title={`${cert.subject}\nFingerprint ${cert.fingerprint}\nExpires ${formatDate(cert.not_after)}`}
          >
            <ShieldCheck size={12} aria-hidden="true" className="shrink-0" />
            {cert.fingerprint.slice(0, 12)}…
          </span>
        );
      },
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
          {canBindCertificate && (
            <button
              aria-label={`Bind certificate to ${row.name}`}
              onClick={() => openBind(row)}
              className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
              title="Bind certificate"
            >
              <FileKey size={14} />
            </button>
          )}
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

      {/* A service account cannot hold RBAC permissions at all: the has_role
          edge is scoped to the `user` table (RoleRepository::assign_to_user),
          so one created for SCIM silently authenticates and then 403s on every
          call. Operators reach for this page first because machine-to-machine
          is what it is for, so the dead end is named here rather than
          discovered. */}
      <div
        role="note"
        className="mb-4 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2.5 text-xs text-amber-300/90"
      >
        <strong className="font-medium">Setting up SCIM provisioning?</strong>{" "}
        Service accounts cannot hold roles or permissions, so one created for an
        Okta or Entra integration will authenticate and then be refused. Use{" "}
        <Link
          to="/scim-tokens"
          className="underline underline-offset-2 hover:text-amber-200"
        >
          SCIM Provisioning
        </Link>{" "}
        instead, which issues a long-lived token bound to a provisioner user.
      </div>

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
        error={createError}
        errorId="service-account-create-error"
      >
        <CreateFields
          name={createName}
          description={createDescription}
          onNameChange={setCreateName}
          onDescriptionChange={setCreateDescription}
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
        error={editError}
        errorId="service-account-edit-error"
      >
        <EditFields
          name={editName}
          description={editDescription}
          isActive={editIsActive}
          onNameChange={setEditName}
          onDescriptionChange={setEditDescription}
          onIsActiveChange={setEditIsActive}
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

      {/* Bind certificate */}
      <FormDialog
        open={bindAccount !== null}
        onClose={() => setBindAccount(null)}
        title={`Bind Certificate to ${bindAccount?.name ?? ""}`}
        onSubmit={handleBindSubmit}
        isLoading={bindMutation.isPending}
        submitLabel="Bind"
        error={bindError}
        errorId="service-account-bind-error"
      >
        <div className="space-y-2">
          <Label htmlFor="bind-certificate">Certificate *</Label>
          <select
            id="bind-certificate"
            value={bindCertId}
            onChange={(e) => setBindCertId(e.target.value)}
            className="w-full rounded-md border border-input bg-background/50 px-3 py-2 text-sm"
          >
            <option value="">Select a certificate…</option>
            {bindableCertificates.map((c) => (
              <option key={c.id} value={c.id}>
                {c.subject} — {c.cert_type} — {c.fingerprint.slice(0, 16)}…
              </option>
            ))}
          </select>
          {bindableCertificates.length === 0 && (
            <p className="text-xs text-muted-foreground">
              No active Service or IoT Device certificates exist yet. Issue one
              from the <span className="text-primary">Certificates</span> page
              first.
            </p>
          )}
          <p className="text-xs text-muted-foreground">
            The service account will be able to authenticate with this
            certificate over mTLS. Active <code>Service</code> and{" "}
            <code>Device</code> (IoT) certificates are listed; <code>User</code>{" "}
            certificates are not, because those identify a person.
          </p>
        </div>
      </FormDialog>

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
