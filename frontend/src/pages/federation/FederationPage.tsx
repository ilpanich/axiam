import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Pencil, Trash2, Zap } from "lucide-react";
import {
  federationService,
  type FederationProvider,
  type CreateProviderRequest,
  type UpdateProviderRequest,
} from "@/services/federation";
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
import { cn, formatDate } from "@/lib/utils";

// ─── Type badge ───────────────────────────────────────────────────────────────

function ProviderTypeBadge({ type }: { type: "saml" | "oidc" }) {
  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border",
        type === "saml"
          ? "bg-purple-500/15 text-purple-400 border-purple-500/30"
          : "bg-blue-500/15 text-blue-400 border-blue-500/30"
      )}
    >
      {type === "saml" ? "SAML" : "OIDC"}
    </span>
  );
}

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
  type: "saml" | "oidc";
  domain: string;
  // SAML
  metadataUrl: string;
  entityId: string;
  ssoUrl: string;
  certificate: string;
  // OIDC
  issuerUrl: string;
  clientId: string;
  clientSecret: string;
  scopes: string;
  // Handlers
  onNameChange: (v: string) => void;
  onTypeChange: (v: "saml" | "oidc") => void;
  onDomainChange: (v: string) => void;
  onMetadataUrlChange: (v: string) => void;
  onEntityIdChange: (v: string) => void;
  onSsoUrlChange: (v: string) => void;
  onCertificateChange: (v: string) => void;
  onIssuerUrlChange: (v: string) => void;
  onClientIdChange: (v: string) => void;
  onClientSecretChange: (v: string) => void;
  onScopesChange: (v: string) => void;
  error?: string;
  idPrefix: string;
}

function CreateFields({
  name,
  type,
  domain,
  metadataUrl,
  entityId,
  ssoUrl,
  certificate,
  issuerUrl,
  clientId,
  clientSecret,
  scopes,
  onNameChange,
  onTypeChange,
  onDomainChange,
  onMetadataUrlChange,
  onEntityIdChange,
  onSsoUrlChange,
  onCertificateChange,
  onIssuerUrlChange,
  onClientIdChange,
  onClientSecretChange,
  onScopesChange,
  error,
  idPrefix,
}: CreateFieldsProps) {
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-name`}>Name *</Label>
        <Input
          id={`${idPrefix}-name`}
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          placeholder="Corporate SSO"
          required
          autoComplete="off"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-type`}>Type *</Label>
        <select
          id={`${idPrefix}-type`}
          value={type}
          onChange={(e) =>
            onTypeChange(e.target.value as "saml" | "oidc")
          }
          className={cn(
            "w-full rounded-md px-3 py-2 text-sm",
            "bg-white/5 border border-primary/20 text-foreground",
            "focus:outline-none focus:ring-2 focus:ring-primary/40 focus:border-primary",
            "transition-colors duration-200"
          )}
          aria-label="Provider type"
        >
          <option value="saml" className="bg-[#0d0d2b] text-foreground">
            SAML
          </option>
          <option value="oidc" className="bg-[#0d0d2b] text-foreground">
            OIDC (OpenID Connect)
          </option>
        </select>
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-domain`}>Domain *</Label>
        <Input
          id={`${idPrefix}-domain`}
          value={domain}
          onChange={(e) => onDomainChange(e.target.value)}
          placeholder="example.com"
          required
          autoComplete="off"
        />
      </div>

      {/* SAML config fields */}
      {type === "saml" && (
        <>
          <div className="pt-2 border-t border-primary/10">
            <p className="text-xs font-semibold uppercase tracking-wider text-primary/70 mb-3">
              SAML Configuration
            </p>
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-metadata-url`}>
              Metadata URL
            </Label>
            <Input
              id={`${idPrefix}-metadata-url`}
              value={metadataUrl}
              onChange={(e) => onMetadataUrlChange(e.target.value)}
              placeholder="https://idp.example.com/metadata.xml"
              autoComplete="off"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-entity-id`}>Entity ID *</Label>
            <Input
              id={`${idPrefix}-entity-id`}
              value={entityId}
              onChange={(e) => onEntityIdChange(e.target.value)}
              placeholder="https://idp.example.com"
              autoComplete="off"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-sso-url`}>SSO URL *</Label>
            <Input
              id={`${idPrefix}-sso-url`}
              value={ssoUrl}
              onChange={(e) => onSsoUrlChange(e.target.value)}
              placeholder="https://idp.example.com/sso"
              autoComplete="off"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-certificate`}>
              Certificate (PEM)
            </Label>
            <Textarea
              id={`${idPrefix}-certificate`}
              value={certificate}
              onChange={(e) => onCertificateChange(e.target.value)}
              placeholder="-----BEGIN CERTIFICATE-----"
              rows={4}
              className="font-mono text-xs"
            />
          </div>
        </>
      )}

      {/* OIDC config fields */}
      {type === "oidc" && (
        <>
          <div className="pt-2 border-t border-primary/10">
            <p className="text-xs font-semibold uppercase tracking-wider text-primary/70 mb-3">
              OIDC Configuration
            </p>
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-issuer-url`}>
              Issuer URL *
            </Label>
            <Input
              id={`${idPrefix}-issuer-url`}
              value={issuerUrl}
              onChange={(e) => onIssuerUrlChange(e.target.value)}
              placeholder="https://accounts.google.com"
              autoComplete="off"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-client-id`}>Client ID *</Label>
            <Input
              id={`${idPrefix}-client-id`}
              value={clientId}
              onChange={(e) => onClientIdChange(e.target.value)}
              placeholder="your-client-id"
              autoComplete="off"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-client-secret`}>
              Client Secret *
            </Label>
            <Input
              id={`${idPrefix}-client-secret`}
              type="password"
              value={clientSecret}
              onChange={(e) => onClientSecretChange(e.target.value)}
              placeholder="your-client-secret"
              autoComplete="new-password"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-scopes`}>Scopes</Label>
            <Input
              id={`${idPrefix}-scopes`}
              value={scopes}
              onChange={(e) => onScopesChange(e.target.value)}
              placeholder="openid profile email"
              autoComplete="off"
            />
            <p className="text-xs text-muted-foreground">
              Space-separated list of scopes.
            </p>
          </div>
        </>
      )}

      {error && <p className="text-sm text-destructive">{error}</p>}
    </>
  );
}

// ─── Form state hook ──────────────────────────────────────────────────────────

function useProviderFormState() {
  const [name, setName] = useState("");
  const [type, setType] = useState<"saml" | "oidc">("saml");
  const [domain, setDomain] = useState("");
  // SAML
  const [metadataUrl, setMetadataUrl] = useState("");
  const [entityId, setEntityId] = useState("");
  const [ssoUrl, setSsoUrl] = useState("");
  const [certificate, setCertificate] = useState("");
  // OIDC
  const [issuerUrl, setIssuerUrl] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [scopes, setScopes] = useState("openid profile email");
  // Status (edit only)
  const [isActive, setIsActive] = useState(true);
  const [error, setError] = useState("");

  function reset() {
    setName("");
    setType("saml");
    setDomain("");
    setMetadataUrl("");
    setEntityId("");
    setSsoUrl("");
    setCertificate("");
    setIssuerUrl("");
    setClientId("");
    setClientSecret("");
    setScopes("openid profile email");
    setIsActive(true);
    setError("");
  }

  function load(provider: FederationProvider) {
    setName(provider.name);
    setType(provider.type);
    setDomain(provider.domain);
    setIsActive(provider.status === "active");
    if (provider.saml_config) {
      setMetadataUrl(provider.saml_config.metadata_url);
      setEntityId(provider.saml_config.entity_id);
      setSsoUrl(provider.saml_config.sso_url);
      setCertificate(provider.saml_config.certificate);
    }
    if (provider.oidc_config) {
      setIssuerUrl(provider.oidc_config.issuer_url);
      setClientId(provider.oidc_config.client_id);
      setClientSecret(provider.oidc_config.client_secret);
      setScopes(provider.oidc_config.scopes.join(" "));
    }
    setError("");
  }

  return {
    name,
    setName,
    type,
    setType,
    domain,
    setDomain,
    metadataUrl,
    setMetadataUrl,
    entityId,
    setEntityId,
    ssoUrl,
    setSsoUrl,
    certificate,
    setCertificate,
    issuerUrl,
    setIssuerUrl,
    clientId,
    setClientId,
    clientSecret,
    setClientSecret,
    scopes,
    setScopes,
    isActive,
    setIsActive,
    error,
    setError,
    reset,
    load,
  };
}

function parseScopes(raw: string): string[] {
  return raw
    .split(/\s+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function FederationPage() {
  const queryClient = useQueryClient();

  const { data: providers = [], isLoading } = useQuery({
    queryKey: ["federation-providers"],
    queryFn: () => federationService.getAll(),
  });

  // ─── Search ─────────────────────────────────────────────────────────────────
  const [search, setSearch] = useState("");

  const filtered = search
    ? providers.filter(
        (p) =>
          p.name.toLowerCase().includes(search.toLowerCase()) ||
          p.domain.toLowerCase().includes(search.toLowerCase())
      )
    : providers;

  // ─── Create state ──────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false);
  const createForm = useProviderFormState();

  const createMutation = useMutation({
    mutationFn: (payload: CreateProviderRequest) =>
      federationService.create(payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["federation-providers"],
      });
      setCreateOpen(false);
      createForm.reset();
    },
    onError: (err: unknown) => {
      createForm.setError(
        err instanceof Error
          ? err.message
          : "Failed to create federation provider."
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
    if (!createForm.domain.trim()) {
      createForm.setError("Domain is required.");
      return;
    }

    const payload: CreateProviderRequest = {
      name: createForm.name.trim(),
      type: createForm.type,
      domain: createForm.domain.trim(),
    };

    if (createForm.type === "saml") {
      if (!createForm.entityId.trim() || !createForm.ssoUrl.trim()) {
        createForm.setError(
          "Entity ID and SSO URL are required for SAML."
        );
        return;
      }
      payload.saml_config = {
        metadata_url: createForm.metadataUrl.trim(),
        entity_id: createForm.entityId.trim(),
        sso_url: createForm.ssoUrl.trim(),
        certificate: createForm.certificate.trim(),
      };
    } else {
      if (
        !createForm.issuerUrl.trim() ||
        !createForm.clientId.trim() ||
        !createForm.clientSecret.trim()
      ) {
        createForm.setError(
          "Issuer URL, Client ID, and Client Secret are required for OIDC."
        );
        return;
      }
      payload.oidc_config = {
        issuer_url: createForm.issuerUrl.trim(),
        client_id: createForm.clientId.trim(),
        client_secret: createForm.clientSecret.trim(),
        scopes: parseScopes(createForm.scopes),
      };
    }

    createMutation.mutate(payload);
  }

  // ─── Edit state ────────────────────────────────────────────────────────────
  const [editProvider, setEditProvider] =
    useState<FederationProvider | null>(null);
  const editForm = useProviderFormState();

  const editMutation = useMutation({
    mutationFn: ({
      id,
      payload,
    }: {
      id: string;
      payload: UpdateProviderRequest;
    }) => federationService.update(id, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["federation-providers"],
      });
      setEditProvider(null);
    },
    onError: (err: unknown) => {
      editForm.setError(
        err instanceof Error
          ? err.message
          : "Failed to update federation provider."
      );
    },
  });

  function openEdit(provider: FederationProvider) {
    setEditProvider(provider);
    editForm.load(provider);
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    editForm.setError("");
    if (!editProvider || !editForm.name.trim()) {
      editForm.setError("Name is required.");
      return;
    }
    if (!editForm.domain.trim()) {
      editForm.setError("Domain is required.");
      return;
    }

    const payload: UpdateProviderRequest = {
      name: editForm.name.trim(),
      domain: editForm.domain.trim(),
      status: editForm.isActive ? "active" : "inactive",
    };

    if (editForm.type === "saml") {
      payload.saml_config = {
        metadata_url: editForm.metadataUrl.trim(),
        entity_id: editForm.entityId.trim(),
        sso_url: editForm.ssoUrl.trim(),
        certificate: editForm.certificate.trim(),
      };
    } else {
      payload.oidc_config = {
        issuer_url: editForm.issuerUrl.trim(),
        client_id: editForm.clientId.trim(),
        client_secret: editForm.clientSecret.trim(),
        scopes: parseScopes(editForm.scopes),
      };
    }

    editMutation.mutate({ id: editProvider.id, payload });
  }

  // ─── Delete state ──────────────────────────────────────────────────────────
  const [deleteProvider, setDeleteProvider] =
    useState<FederationProvider | null>(null);

  const deleteMutation = useMutation({
    mutationFn: (id: string) => federationService.delete(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["federation-providers"],
      });
      setDeleteProvider(null);
    },
  });

  // ─── Test connection state ─────────────────────────────────────────────────
  const [testingId, setTestingId] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{
    success: boolean;
    message: string;
  } | null>(null);

  const testMutation = useMutation({
    mutationFn: (id: string) => federationService.testConnection(id),
    onSuccess: (result) => {
      setTestResult(result);
      setTestingId(null);
    },
    onError: (err: unknown) => {
      setTestResult({
        success: false,
        message:
          err instanceof Error ? err.message : "Connection test failed.",
      });
      setTestingId(null);
    },
  });

  function handleTestConnection(provider: FederationProvider) {
    setTestingId(provider.id);
    setTestResult(null);
    testMutation.mutate(provider.id);
  }

  // ─── Table columns ─────────────────────────────────────────────────────────
  const columns: Column<FederationProvider>[] = [
    {
      key: "name",
      header: "Name",
      render: (row) => (
        <span className="font-medium text-foreground/90">{row.name}</span>
      ),
    },
    {
      key: "type",
      header: "Type",
      render: (row) => <ProviderTypeBadge type={row.type} />,
    },
    {
      key: "status",
      header: "Status",
      render: (row) => (
        <StatusBadge
          status={row.status === "active" ? "active" : "inactive"}
        />
      ),
    },
    {
      key: "domain",
      header: "Domain",
      render: (row) => (
        <span className="text-sm text-muted-foreground font-mono">
          {row.domain}
        </span>
      ),
    },
    {
      key: "last_sync_at",
      header: "Last Sync",
      render: (row) => (
        <span className="text-sm text-muted-foreground">
          {row.last_sync_at ? formatDate(row.last_sync_at) : "Never"}
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
            aria-label={`Test connection for ${row.name}`}
            onClick={() => handleTestConnection(row)}
            disabled={testingId === row.id}
            className={cn(
              "p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors",
              testingId === row.id && "animate-pulse"
            )}
            title="Test connection"
          >
            <Zap size={14} />
          </button>
          <button
            aria-label={`Edit ${row.name}`}
            onClick={() => openEdit(row)}
            className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
          >
            <Pencil size={14} />
          </button>
          <button
            aria-label={`Delete ${row.name}`}
            onClick={() => setDeleteProvider(row)}
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
        title="Federation"
        description="Configure cross-domain Single Sign-On via SAML and OpenID Connect identity providers."
        action={
          <Button
            onClick={() => {
              createForm.reset();
              setCreateOpen(true);
            }}
          >
            <Plus size={16} />
            New Provider
          </Button>
        }
      />

      {/* Test result banner */}
      {testResult && (
        <div
          className={cn(
            "mb-4 px-4 py-3 rounded-lg border text-sm flex items-center justify-between",
            testResult.success
              ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
              : "bg-red-500/10 border-red-500/30 text-red-400"
          )}
          role="alert"
        >
          <span>{testResult.message}</span>
          <button
            onClick={() => setTestResult(null)}
            className="text-xs underline opacity-70 hover:opacity-100"
            aria-label="Dismiss test result"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Search */}
      <div className="mb-4">
        <SearchInput
          value={search}
          onChange={setSearch}
          placeholder="Search providers..."
          className="max-w-sm"
        />
      </div>

      <DataTable
        columns={columns}
        data={filtered}
        isLoading={isLoading}
        emptyMessage="No federation providers configured."
      />

      {/* Create dialog */}
      <FormDialog
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          createForm.reset();
        }}
        title="New Federation Provider"
        onSubmit={handleCreateSubmit}
        isLoading={createMutation.isPending}
        submitLabel="Create"
      >
        <CreateFields
          name={createForm.name}
          type={createForm.type}
          domain={createForm.domain}
          metadataUrl={createForm.metadataUrl}
          entityId={createForm.entityId}
          ssoUrl={createForm.ssoUrl}
          certificate={createForm.certificate}
          issuerUrl={createForm.issuerUrl}
          clientId={createForm.clientId}
          clientSecret={createForm.clientSecret}
          scopes={createForm.scopes}
          onNameChange={createForm.setName}
          onTypeChange={createForm.setType}
          onDomainChange={createForm.setDomain}
          onMetadataUrlChange={createForm.setMetadataUrl}
          onEntityIdChange={createForm.setEntityId}
          onSsoUrlChange={createForm.setSsoUrl}
          onCertificateChange={createForm.setCertificate}
          onIssuerUrlChange={createForm.setIssuerUrl}
          onClientIdChange={createForm.setClientId}
          onClientSecretChange={createForm.setClientSecret}
          onScopesChange={createForm.setScopes}
          error={createForm.error}
          idPrefix="create"
        />
      </FormDialog>

      {/* Edit dialog */}
      <FormDialog
        open={editProvider !== null}
        onClose={() => setEditProvider(null)}
        title="Edit Federation Provider"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
      >
        <CreateFields
          name={editForm.name}
          type={editForm.type}
          domain={editForm.domain}
          metadataUrl={editForm.metadataUrl}
          entityId={editForm.entityId}
          ssoUrl={editForm.ssoUrl}
          certificate={editForm.certificate}
          issuerUrl={editForm.issuerUrl}
          clientId={editForm.clientId}
          clientSecret={editForm.clientSecret}
          scopes={editForm.scopes}
          onNameChange={editForm.setName}
          onTypeChange={editForm.setType}
          onDomainChange={editForm.setDomain}
          onMetadataUrlChange={editForm.setMetadataUrl}
          onEntityIdChange={editForm.setEntityId}
          onSsoUrlChange={editForm.setSsoUrl}
          onCertificateChange={editForm.setCertificate}
          onIssuerUrlChange={editForm.setIssuerUrl}
          onClientIdChange={editForm.setClientId}
          onClientSecretChange={editForm.setClientSecret}
          onScopesChange={editForm.setScopes}
          error={editForm.error}
          idPrefix="edit"
        />
        {/* Status toggle only in edit */}
        <ToggleField
          id="edit-fed-active"
          label="Active"
          checked={editForm.isActive}
          onChange={editForm.setIsActive}
        />
      </FormDialog>

      {/* Delete confirm */}
      <ConfirmDialog
        open={deleteProvider !== null}
        onClose={() => setDeleteProvider(null)}
        onConfirm={() =>
          deleteProvider && deleteMutation.mutate(deleteProvider.id)
        }
        title="Delete Federation Provider"
        description={`Are you sure you want to delete "${deleteProvider?.name}"? Users authenticating through this provider will lose SSO access.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}
