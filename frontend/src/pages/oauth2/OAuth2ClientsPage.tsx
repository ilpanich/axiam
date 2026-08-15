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
import { formatDate } from "@/lib/utils";
import { Textarea } from "@/components/ui/textarea";

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
    <div className="space-y-2">
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

// ─── Shared form fields ───────────────────────────────────────────────────────

interface ClientFormFieldsProps {
  name: string;
  grantTypes: string[];
  redirectUris: string;
  scopes: string[];
  postLogoutRedirectUris: string;
  backchannelLogoutUri: string;
  onNameChange: (v: string) => void;
  onGrantTypesChange: (v: string[]) => void;
  onRedirectUrisChange: (v: string) => void;
  onScopesChange: (v: string[]) => void;
  onPostLogoutRedirectUrisChange: (v: string) => void;
  onBackchannelLogoutUriChange: (v: string) => void;
  idPrefix: string;
}

function ClientFormFields({
  name,
  grantTypes,
  redirectUris,
  scopes,
  postLogoutRedirectUris,
  backchannelLogoutUri,
  onNameChange,
  onGrantTypesChange,
  onRedirectUrisChange,
  onScopesChange,
  onPostLogoutRedirectUrisChange,
  onBackchannelLogoutUriChange,
  idPrefix,
}: ClientFormFieldsProps) {
  return (
    <>
      <div className="space-y-2">
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

      <CheckboxGroup
        id={`${idPrefix}-grant-types`}
        label="Grant Types *"
        options={GRANT_TYPES}
        selected={grantTypes}
        onChange={onGrantTypesChange}
      />

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-redirect-uris`}>Redirect URIs</Label>
        <Textarea
          id={`${idPrefix}-redirect-uris`}
          value={redirectUris}
          onChange={(e) => onRedirectUrisChange(e.target.value)}
          placeholder={"https://app.example.com/callback\nhttps://app.example.com/silent-renew"}
          rows={3}
          className="font-mono"
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

      {/* B5 — session/logout settings */}
      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-post-logout-uris`}>
          Post-Logout Redirect URIs
        </Label>
        <Textarea
          id={`${idPrefix}-post-logout-uris`}
          value={postLogoutRedirectUris}
          onChange={(e) => onPostLogoutRedirectUrisChange(e.target.value)}
          placeholder={"https://app.example.com/logged-out"}
          rows={2}
          className="font-mono"
          aria-label="Post-Logout Redirect URIs (one per line)"
        />
        <p className="text-xs text-muted-foreground">
          Allow-list for RP-initiated logout's <code>post_logout_redirect_uri</code>{" "}
          — separate from Redirect URIs, since this one receives a browser
          after logout rather than an authorization code. One URI per line.
        </p>
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-backchannel-logout-uri`}>
          Back-Channel Logout URI
        </Label>
        <Input
          id={`${idPrefix}-backchannel-logout-uri`}
          value={backchannelLogoutUri}
          onChange={(e) => onBackchannelLogoutUriChange(e.target.value)}
          placeholder="https://app.example.com/backchannel-logout"
          autoComplete="off"
          className="font-mono"
        />
        <p className="text-xs text-muted-foreground">
          Where OIDC back-channel logout tokens are delivered. Leave blank for
          a client that does not participate.
        </p>
      </div>
    </>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────────

function useClientFormState() {
  const [name, setName] = useState("");
  const [grantTypes, setGrantTypes] = useState<string[]>(["authorization_code"]);
  const [redirectUris, setRedirectUris] = useState("");
  const [scopes, setScopes] = useState<string[]>(["openid", "profile"]);
  const [postLogoutRedirectUris, setPostLogoutRedirectUris] = useState("");
  const [backchannelLogoutUri, setBackchannelLogoutUri] = useState("");
  const [error, setError] = useState("");

  function reset() {
    setName("");
    setGrantTypes(["authorization_code"]);
    setRedirectUris("");
    setScopes(["openid", "profile"]);
    setPostLogoutRedirectUris("");
    setBackchannelLogoutUri("");
    setError("");
  }

  function load(client: OAuth2Client) {
    setName(client.name);
    setGrantTypes(client.grant_types);
    setRedirectUris(client.redirect_uris.join("\n"));
    setScopes(client.scopes);
    // See the OAuth2Client.post_logout_redirect_uris doc: the backend
    // response DTO doesn't echo these back today, so this will populate the
    // field once that gap is fixed and is a harmless no-op (empty string)
    // until then.
    setPostLogoutRedirectUris((client.post_logout_redirect_uris ?? []).join("\n"));
    setBackchannelLogoutUri(client.backchannel_logout_uri ?? "");
    setError("");
  }

  return {
    name,
    setName,
    grantTypes,
    setGrantTypes,
    redirectUris,
    setRedirectUris,
    scopes,
    setScopes,
    postLogoutRedirectUris,
    setPostLogoutRedirectUris,
    backchannelLogoutUri,
    setBackchannelLogoutUri,
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
      setRevealedClientId(resp.client_id);
      setRevealedSecret(resp.client_secret);
      setSecretModalOpen(true);
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
      post_logout_redirect_uris: parseUris(createForm.postLogoutRedirectUris),
      backchannel_logout_uri: createForm.backchannelLogoutUri.trim() || undefined,
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
        post_logout_redirect_uris: parseUris(editForm.postLogoutRedirectUris),
        // "" clears a previously registered URI, matching the backend's
        // Some("") semantics — trimming to empty is deliberate, not a bug.
        backchannel_logout_uri: editForm.backchannelLogoutUri.trim(),
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
        error={createForm.error}
        errorId="oauth2-client-create-error"
      >
        <ClientFormFields
          name={createForm.name}
          grantTypes={createForm.grantTypes}
          redirectUris={createForm.redirectUris}
          scopes={createForm.scopes}
          postLogoutRedirectUris={createForm.postLogoutRedirectUris}
          backchannelLogoutUri={createForm.backchannelLogoutUri}
          onNameChange={createForm.setName}
          onGrantTypesChange={createForm.setGrantTypes}
          onRedirectUrisChange={createForm.setRedirectUris}
          onScopesChange={createForm.setScopes}
          onPostLogoutRedirectUrisChange={createForm.setPostLogoutRedirectUris}
          onBackchannelLogoutUriChange={createForm.setBackchannelLogoutUri}
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
        error={editForm.error}
        errorId="oauth2-client-edit-error"
      >
        <ClientFormFields
          name={editForm.name}
          grantTypes={editForm.grantTypes}
          redirectUris={editForm.redirectUris}
          scopes={editForm.scopes}
          postLogoutRedirectUris={editForm.postLogoutRedirectUris}
          backchannelLogoutUri={editForm.backchannelLogoutUri}
          onNameChange={editForm.setName}
          onGrantTypesChange={editForm.setGrantTypes}
          onRedirectUrisChange={editForm.setRedirectUris}
          onScopesChange={editForm.setScopes}
          onPostLogoutRedirectUrisChange={editForm.setPostLogoutRedirectUris}
          onBackchannelLogoutUriChange={editForm.setBackchannelLogoutUri}
          idPrefix="edit"
        />
      </FormDialog>

      {/* Client secret reveal */}
      <SecretRevealModal
        open={secretModalOpen}
        onClose={() => { setSecretModalOpen(false); setRevealedClientId(""); setRevealedSecret(""); }}
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
