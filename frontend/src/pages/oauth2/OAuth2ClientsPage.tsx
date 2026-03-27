import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Pencil, Trash2 } from "lucide-react";
import {
  oauth2ClientService,
  GRANT_TYPES,
  OAUTH2_SCOPES,
  type OAuth2Client,
  type CreateOAuth2ClientPayload,
  type UpdateOAuth2ClientPayload,
} from "@/services/oauth2clients";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { SecretRevealModal } from "@/components/SecretRevealModal";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn, formatDate } from "@/lib/utils";

// ─── Helpers ──────────────────────────────────────────────────────────────────

const GRANT_TYPE_LABELS: Record<string, string> = {
  authorization_code: "Auth Code",
  client_credentials: "Client Creds",
  refresh_token: "Refresh Token",
};

function GrantTypeBadge({ type }: { type: string }) {
  return (
    <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-blue-500/15 text-blue-400 border border-blue-500/30">
      {GRANT_TYPE_LABELS[type] ?? type}
    </span>
  );
}

// ─── Checkbox group ───────────────────────────────────────────────────────────

interface CheckboxGroupProps {
  id: string;
  label: string;
  options: readonly string[];
  selected: string[];
  onChange: (v: string[]) => void;
  labelMap?: Record<string, string>;
}

function CheckboxGroup({
  id,
  label,
  options,
  selected,
  onChange,
  labelMap,
}: CheckboxGroupProps) {
  function toggle(opt: string) {
    if (selected.includes(opt)) {
      onChange(selected.filter((v) => v !== opt));
    } else {
      onChange([...selected, opt]);
    }
  }

  return (
    <div className="space-y-1.5">
      <Label>{label}</Label>
      <div
        className="rounded-md border border-input bg-background/50 p-3 space-y-2"
        role="group"
        aria-label={label}
        id={id}
      >
        {options.map((opt) => (
          <label
            key={opt}
            className="flex items-center gap-2.5 cursor-pointer hover:text-foreground transition-colors"
          >
            <input
              type="checkbox"
              checked={selected.includes(opt)}
              onChange={() => toggle(opt)}
              className="w-3.5 h-3.5 accent-cyan-400 cursor-pointer"
              aria-label={labelMap?.[opt] ?? opt}
            />
            <span className="text-sm font-mono text-foreground/80">
              {opt}
            </span>
          </label>
        ))}
      </div>
    </div>
  );
}

// ─── Toggle field ─────────────────────────────────────────────────────────────

interface ToggleFieldProps {
  id: string;
  label: string;
  description?: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}

function ToggleField({ id, label, description, checked, onChange }: ToggleFieldProps) {
  return (
    <div className="flex items-start gap-3">
      <input
        type="checkbox"
        id={id}
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="w-4 h-4 mt-0.5 accent-cyan-400 cursor-pointer shrink-0"
      />
      <div>
        <Label htmlFor={id} className="cursor-pointer">
          {label}
        </Label>
        {description && (
          <p className="text-xs text-muted-foreground mt-0.5">{description}</p>
        )}
      </div>
    </div>
  );
}

// ─── Shared form fields ───────────────────────────────────────────────────────

interface ClientFormFieldsProps {
  name: string;
  isPublic: boolean;
  grantTypes: string[];
  redirectUris: string;
  scopes: string[];
  onNameChange: (v: string) => void;
  onIsPublicChange: (v: boolean) => void;
  onGrantTypesChange: (v: string[]) => void;
  onRedirectUrisChange: (v: string) => void;
  onScopesChange: (v: string[]) => void;
  error?: string;
  idPrefix: string;
}

function ClientFormFields({
  name,
  isPublic,
  grantTypes,
  redirectUris,
  scopes,
  onNameChange,
  onIsPublicChange,
  onGrantTypesChange,
  onRedirectUrisChange,
  onScopesChange,
  error,
  idPrefix,
}: ClientFormFieldsProps) {
  return (
    <>
      <div className="space-y-1.5">
        <Label htmlFor={`${idPrefix}-name`}>Name *</Label>
        <Input
          id={`${idPrefix}-name`}
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          placeholder="My OAuth2 App"
          required
          autoComplete="off"
        />
      </div>

      <ToggleField
        id={`${idPrefix}-public`}
        label="Public Client"
        description="Public clients (e.g. SPAs, mobile apps) do not have a client secret."
        checked={isPublic}
        onChange={onIsPublicChange}
      />

      <CheckboxGroup
        id={`${idPrefix}-grant-types`}
        label="Grant Types *"
        options={GRANT_TYPES}
        selected={grantTypes}
        onChange={onGrantTypesChange}
      />

      <div className="space-y-1.5">
        <Label htmlFor={`${idPrefix}-redirect-uris`}>Redirect URIs</Label>
        <textarea
          id={`${idPrefix}-redirect-uris`}
          value={redirectUris}
          onChange={(e) => onRedirectUrisChange(e.target.value)}
          placeholder={"https://app.example.com/callback\nhttps://app.example.com/silent-renew"}
          rows={3}
          className={cn(
            "w-full rounded-md border border-input bg-background/50 px-3 py-2 text-sm text-foreground",
            "placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/40 resize-none font-mono"
          )}
          aria-label="Redirect URIs (one per line)"
        />
        <p className="text-xs text-muted-foreground">One URI per line.</p>
      </div>

      <CheckboxGroup
        id={`${idPrefix}-scopes`}
        label="Scopes"
        options={OAUTH2_SCOPES}
        selected={scopes}
        onChange={onScopesChange}
      />

      {error && <p className="text-sm text-destructive">{error}</p>}
    </>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────────

function useClientFormState() {
  const [name, setName] = useState("");
  const [isPublic, setIsPublic] = useState(false);
  const [grantTypes, setGrantTypes] = useState<string[]>(["authorization_code"]);
  const [redirectUris, setRedirectUris] = useState("");
  const [scopes, setScopes] = useState<string[]>(["openid", "profile"]);
  const [error, setError] = useState("");

  function reset() {
    setName("");
    setIsPublic(false);
    setGrantTypes(["authorization_code"]);
    setRedirectUris("");
    setScopes(["openid", "profile"]);
    setError("");
  }

  function load(client: OAuth2Client) {
    setName(client.name);
    setIsPublic(client.is_public);
    setGrantTypes(client.grant_types);
    setRedirectUris(client.redirect_uris.join("\n"));
    setScopes(client.scopes);
    setError("");
  }

  return {
    name,
    setName,
    isPublic,
    setIsPublic,
    grantTypes,
    setGrantTypes,
    redirectUris,
    setRedirectUris,
    scopes,
    setScopes,
    error,
    setError,
    reset,
    load,
  };
}

function parseUris(raw: string): string[] {
  return raw
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export function OAuth2ClientsPage() {
  const queryClient = useQueryClient();

  const { data: clients = [], isLoading } = useQuery({
    queryKey: ["oauth2-clients"],
    queryFn: () => oauth2ClientService.list(),
  });

  // ─── Create state ──────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false);
  const createForm = useClientFormState();

  // ─── Secret reveal ─────────────────────────────────────────────────────────
  const [secretModalOpen, setSecretModalOpen] = useState(false);
  const [revealedClientId, setRevealedClientId] = useState("");
  const [revealedSecret, setRevealedSecret] = useState("");

  const createMutation = useMutation({
    mutationFn: (payload: CreateOAuth2ClientPayload) =>
      oauth2ClientService.create(payload),
    onSuccess: (resp) => {
      void queryClient.invalidateQueries({ queryKey: ["oauth2-clients"] });
      setCreateOpen(false);
      createForm.reset();
      if (!resp.client.is_public && resp.client_secret) {
        setRevealedClientId(resp.client.client_id);
        setRevealedSecret(resp.client_secret);
        setSecretModalOpen(true);
      }
    },
    onError: (err: unknown) => {
      createForm.setError(
        err instanceof Error ? err.message : "Failed to create OAuth2 client."
      );
    },
  });

  function handleCreateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    createForm.setError("");
    if (!createForm.name.trim()) {
      createForm.setError("Name is required.");
      return;
    }
    if (createForm.grantTypes.length === 0) {
      createForm.setError("Select at least one grant type.");
      return;
    }
    const payload: CreateOAuth2ClientPayload = {
      name: createForm.name.trim(),
      redirect_uris: parseUris(createForm.redirectUris),
      grant_types: createForm.grantTypes,
      scopes: createForm.scopes.length > 0 ? createForm.scopes : undefined,
      is_public: createForm.isPublic,
    };
    createMutation.mutate(payload);
  }

  // ─── Edit state ────────────────────────────────────────────────────────────
  const [editClient, setEditClient] = useState<OAuth2Client | null>(null);
  const editForm = useClientFormState();

  const editMutation = useMutation({
    mutationFn: ({
      id,
      payload,
    }: {
      id: string;
      payload: UpdateOAuth2ClientPayload;
    }) => oauth2ClientService.update(id, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["oauth2-clients"] });
      setEditClient(null);
    },
    onError: (err: unknown) => {
      editForm.setError(
        err instanceof Error ? err.message : "Failed to update OAuth2 client."
      );
    },
  });

  function openEdit(client: OAuth2Client) {
    setEditClient(client);
    editForm.load(client);
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    editForm.setError("");
    if (!editClient || !editForm.name.trim()) {
      editForm.setError("Name is required.");
      return;
    }
    if (editForm.grantTypes.length === 0) {
      editForm.setError("Select at least one grant type.");
      return;
    }
    editMutation.mutate({
      id: editClient.id,
      payload: {
        name: editForm.name.trim(),
        redirect_uris: parseUris(editForm.redirectUris),
        grant_types: editForm.grantTypes,
        scopes: editForm.scopes,
        is_public: editForm.isPublic,
      },
    });
  }

  // ─── Delete state ──────────────────────────────────────────────────────────
  const [deleteClient, setDeleteClient] = useState<OAuth2Client | null>(null);

  const deleteMutation = useMutation({
    mutationFn: (id: string) => oauth2ClientService.remove(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["oauth2-clients"] });
      setDeleteClient(null);
    },
  });

  // ─── Table columns ─────────────────────────────────────────────────────────

  const columns: Column<OAuth2Client>[] = [
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
      key: "grant_types",
      header: "Grant Types",
      render: (row) => (
        <div className="flex flex-wrap gap-1">
          {row.grant_types.map((gt) => (
            <GrantTypeBadge key={gt} type={gt} />
          ))}
        </div>
      ),
    },
    {
      key: "is_public",
      header: "Type",
      render: (row) => (
        <span
          className={cn(
            "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border",
            row.is_public
              ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
              : "bg-purple-500/15 text-purple-400 border-purple-500/30"
          )}
        >
          {row.is_public ? "Public" : "Confidential"}
        </span>
      ),
    },
    {
      key: "redirect_uris",
      header: "Redirect URIs",
      render: (row) => (
        <span className="text-sm text-muted-foreground">
          {row.redirect_uris.length}{" "}
          {row.redirect_uris.length === 1 ? "URI" : "URIs"}
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
      width: "w-24",
      render: (row) => (
        <div className="flex items-center gap-1">
          <button
            aria-label={`Edit OAuth2 client ${row.name}`}
            onClick={() => openEdit(row)}
            className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
          >
            <Pencil size={14} />
          </button>
          <button
            aria-label={`Delete OAuth2 client ${row.name}`}
            onClick={() => setDeleteClient(row)}
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
        title="OAuth2 Clients"
        description="Manage OAuth2 client applications for Authorization Code, Client Credentials, and Refresh Token flows."
        action={
          <Button
            onClick={() => {
              createForm.reset();
              setCreateOpen(true);
            }}
          >
            <Plus size={16} />
            New Client
          </Button>
        }
      />

      <DataTable
        columns={columns}
        data={clients}
        isLoading={isLoading}
        emptyMessage="No OAuth2 clients registered."
      />

      {/* Create dialog */}
      <FormDialog
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          createForm.reset();
        }}
        title="New OAuth2 Client"
        onSubmit={handleCreateSubmit}
        isLoading={createMutation.isPending}
        submitLabel="Create"
      >
        <ClientFormFields
          name={createForm.name}
          isPublic={createForm.isPublic}
          grantTypes={createForm.grantTypes}
          redirectUris={createForm.redirectUris}
          scopes={createForm.scopes}
          onNameChange={createForm.setName}
          onIsPublicChange={createForm.setIsPublic}
          onGrantTypesChange={createForm.setGrantTypes}
          onRedirectUrisChange={createForm.setRedirectUris}
          onScopesChange={createForm.setScopes}
          error={createForm.error}
          idPrefix="create"
        />
      </FormDialog>

      {/* Edit dialog */}
      <FormDialog
        open={editClient !== null}
        onClose={() => setEditClient(null)}
        title="Edit OAuth2 Client"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
      >
        <ClientFormFields
          name={editForm.name}
          isPublic={editForm.isPublic}
          grantTypes={editForm.grantTypes}
          redirectUris={editForm.redirectUris}
          scopes={editForm.scopes}
          onNameChange={editForm.setName}
          onIsPublicChange={editForm.setIsPublic}
          onGrantTypesChange={editForm.setGrantTypes}
          onRedirectUrisChange={editForm.setRedirectUris}
          onScopesChange={editForm.setScopes}
          error={editForm.error}
          idPrefix="edit"
        />
      </FormDialog>

      {/* Client secret reveal */}
      <SecretRevealModal
        open={secretModalOpen}
        onClose={() => setSecretModalOpen(false)}
        title="OAuth2 Client Created"
        description="Your confidential OAuth2 client has been created. Save the secret now — it will not be shown again."
        secrets={[
          {
            label: "Client ID",
            value: revealedClientId,
          },
          {
            label: "Client Secret",
            value: revealedSecret,
          },
        ]}
      />

      {/* Delete confirm */}
      <ConfirmDialog
        open={deleteClient !== null}
        onClose={() => setDeleteClient(null)}
        onConfirm={() =>
          deleteClient && deleteMutation.mutate(deleteClient.id)
        }
        title="Delete OAuth2 Client"
        description={`Are you sure you want to delete "${deleteClient?.name}"? This will invalidate all tokens issued to this client.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}
