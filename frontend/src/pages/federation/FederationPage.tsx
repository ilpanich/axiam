import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Pencil, Trash2 } from "lucide-react";
import {
  federationService,
  type FederationConfig,
  type FederationProtocol,
  type CreateFederationConfigRequest,
  type UpdateFederationConfigRequest,
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
import { useToast } from "@/hooks/useToast";
import { getApiErrorMessage } from "@/lib/apiError";
import { ToggleField } from "@/components/shared";

// ─── Protocol badge ─────────────────────────────────────────────────────────

function ProtocolBadge({ protocol }: { protocol: string }) {
  const isOidc = protocol === "OidcConnect";
  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border",
        isOidc
          ? "bg-blue-500/15 text-blue-400 border-blue-500/30"
          : "bg-purple-500/15 text-purple-400 border-purple-500/30",
      )}
    >
      {isOidc ? "OIDC" : "SAML"}
    </span>
  );
}

// ─── attribute_map / allowed_algorithms helpers ───────────────────────────────

/** Parse an allowed-algorithms input (comma/space separated) into a string[]. */
function parseAlgorithms(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * Validate + parse the attribute_map textarea. Empty input maps to `{}`.
 * Returns the parsed object, or an `error` string if the JSON is invalid or
 * not a plain object.
 */
function parseAttributeMap(
  raw: string,
): { value: Record<string, unknown> } | { error: string } {
  const trimmed = raw.trim();
  if (!trimmed) return { value: {} };
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return { error: "Attribute map must be valid JSON." };
  }
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed)
  ) {
    return { error: "Attribute map must be a JSON object." };
  }
  return { value: parsed as Record<string, unknown> };
}

/** Stringify a server-returned attribute_map for display in the textarea. */
function stringifyAttributeMap(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "object" && Object.keys(value).length === 0) return "";
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return "";
  }
}

// ─── Config form fields ───────────────────────────────────────────────────────

interface ConfigFieldsProps {
  provider: string;
  protocol: FederationProtocol;
  clientId: string;
  clientSecret: string;
  metadataUrl: string;
  idpSigningCertPem: string;
  allowedAlgorithms: string;
  attributeMap: string;
  // Handlers
  onProviderChange: (v: string) => void;
  onProtocolChange: (v: FederationProtocol) => void;
  onClientIdChange: (v: string) => void;
  onClientSecretChange: (v: string) => void;
  onMetadataUrlChange: (v: string) => void;
  onIdpSigningCertPemChange: (v: string) => void;
  onAllowedAlgorithmsChange: (v: string) => void;
  onAttributeMapChange: (v: string) => void;
  error?: string;
  idPrefix: string;
  isEditMode?: boolean;
}

function ConfigFields({
  provider,
  protocol,
  clientId,
  clientSecret,
  metadataUrl,
  idpSigningCertPem,
  allowedAlgorithms,
  attributeMap,
  onProviderChange,
  onProtocolChange,
  onClientIdChange,
  onClientSecretChange,
  onMetadataUrlChange,
  onIdpSigningCertPemChange,
  onAllowedAlgorithmsChange,
  onAttributeMapChange,
  error,
  idPrefix,
  isEditMode = false,
}: ConfigFieldsProps) {
  const isSaml = protocol === "Saml";
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-provider`}>Provider *</Label>
        <Input
          id={`${idPrefix}-provider`}
          value={provider}
          onChange={(e) => onProviderChange(e.target.value)}
          placeholder="Okta"
          required
          autoComplete="off"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-protocol`}>Protocol *</Label>
        <select
          id={`${idPrefix}-protocol`}
          value={protocol}
          onChange={(e) =>
            onProtocolChange(e.target.value as FederationProtocol)
          }
          disabled={isEditMode}
          className={cn(
            "w-full rounded-md px-3 py-2 text-sm",
            "bg-white/5 border border-primary/20 text-foreground",
            "focus:outline-none focus:ring-2 focus:ring-primary/40 focus:border-primary",
            "transition-colors duration-200",
            isEditMode && "opacity-60 cursor-not-allowed",
          )}
          aria-label="Federation protocol"
          title={
            isEditMode
              ? "Protocol cannot be changed after creation"
              : undefined
          }
        >
          <option value="OidcConnect" className="bg-[#0d0d2b] text-foreground">
            OIDC (OpenID Connect)
          </option>
          <option value="Saml" className="bg-[#0d0d2b] text-foreground">
            SAML
          </option>
        </select>
        {isEditMode && (
          <p className="text-xs text-muted-foreground">
            Protocol cannot be changed after creation.
          </p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-client-id`}>Client ID *</Label>
        <Input
          id={`${idPrefix}-client-id`}
          value={clientId}
          onChange={(e) => onClientIdChange(e.target.value)}
          placeholder="your-client-id"
          required
          autoComplete="off"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-client-secret`}>
          Client Secret {isEditMode ? "" : "*"}
        </Label>
        <Input
          id={`${idPrefix}-client-secret`}
          type="password"
          value={clientSecret}
          onChange={(e) => onClientSecretChange(e.target.value)}
          placeholder={
            isEditMode ? "Leave blank to keep current secret" : "your-client-secret"
          }
          autoComplete="new-password"
        />
        {isEditMode && (
          <p className="text-xs text-muted-foreground">
            Leave blank to keep the existing secret unchanged.
          </p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-metadata-url`}>
          Metadata URL{isSaml ? " (IdP metadata)" : ""}
        </Label>
        <Input
          id={`${idPrefix}-metadata-url`}
          type="url"
          value={metadataUrl}
          onChange={(e) => onMetadataUrlChange(e.target.value)}
          placeholder={
            isSaml
              ? "https://idp.example.com/metadata.xml"
              : "https://idp.example.com/.well-known/openid-configuration"
          }
          autoComplete="off"
        />
      </div>

      {/* SAML-only fields */}
      {isSaml && (
        <>
          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-idp-cert`}>
              IdP Signing Certificate (PEM)
            </Label>
            <Textarea
              id={`${idPrefix}-idp-cert`}
              value={idpSigningCertPem}
              onChange={(e) => onIdpSigningCertPemChange(e.target.value)}
              placeholder="-----BEGIN CERTIFICATE-----"
              rows={4}
              className="font-mono text-xs"
            />
            <p className="text-xs text-muted-foreground">
              Required for SAML — used to verify signed assertions.
            </p>
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-allowed-algos`}>
              Allowed Algorithms
            </Label>
            <Input
              id={`${idPrefix}-allowed-algos`}
              value={allowedAlgorithms}
              onChange={(e) => onAllowedAlgorithmsChange(e.target.value)}
              placeholder="RS256 RS384"
              autoComplete="off"
            />
            <p className="text-xs text-muted-foreground">
              Comma- or space-separated. Defaults to RS256 when left blank.
            </p>
          </div>
        </>
      )}

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-attribute-map`}>
          Attribute Map (JSON)
        </Label>
        <Textarea
          id={`${idPrefix}-attribute-map`}
          value={attributeMap}
          onChange={(e) => onAttributeMapChange(e.target.value)}
          placeholder={'{\n  "email": "mail",\n  "name": "displayName"\n}'}
          rows={4}
          className="font-mono text-xs"
        />
        <p className="text-xs text-muted-foreground">
          Optional JSON object mapping IdP claims to AXIAM attributes.
        </p>
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}
    </>
  );
}

// ─── Form state hook ──────────────────────────────────────────────────────────

function useConfigFormState() {
  const [provider, setProvider] = useState("");
  const [protocol, setProtocol] = useState<FederationProtocol>("OidcConnect");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [metadataUrl, setMetadataUrl] = useState("");
  const [idpSigningCertPem, setIdpSigningCertPem] = useState("");
  const [allowedAlgorithms, setAllowedAlgorithms] = useState("");
  const [attributeMap, setAttributeMap] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [error, setError] = useState("");

  function reset() {
    setProvider("");
    setProtocol("OidcConnect");
    setClientId("");
    setClientSecret("");
    setMetadataUrl("");
    setIdpSigningCertPem("");
    setAllowedAlgorithms("");
    setAttributeMap("");
    setEnabled(true);
    setError("");
  }

  function load(config: FederationConfig) {
    setProvider(config.provider);
    setProtocol(config.protocol === "Saml" ? "Saml" : "OidcConnect");
    setClientId(config.client_id);
    // client_secret is write-only — never returned, so never prefilled.
    setClientSecret("");
    setMetadataUrl(config.metadata_url ?? "");
    setIdpSigningCertPem("");
    setAllowedAlgorithms("");
    setAttributeMap(stringifyAttributeMap(config.attribute_map));
    setEnabled(config.enabled);
    setError("");
  }

  return {
    provider,
    setProvider,
    protocol,
    setProtocol,
    clientId,
    setClientId,
    clientSecret,
    setClientSecret,
    metadataUrl,
    setMetadataUrl,
    idpSigningCertPem,
    setIdpSigningCertPem,
    allowedAlgorithms,
    setAllowedAlgorithms,
    attributeMap,
    setAttributeMap,
    enabled,
    setEnabled,
    error,
    setError,
    reset,
    load,
  };
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function FederationPage() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: configs = [], isLoading } = useQuery({
    queryKey: ["federation-configs"],
    queryFn: () => federationService.getAll(),
  });

  // ─── Search ─────────────────────────────────────────────────────────────────
  const [search, setSearch] = useState("");

  const filtered = search
    ? configs.filter(
        (c) =>
          c.provider.toLowerCase().includes(search.toLowerCase()) ||
          c.client_id.toLowerCase().includes(search.toLowerCase()),
      )
    : configs;

  // ─── Create state ──────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false);
  const createForm = useConfigFormState();

  const createMutation = useMutation({
    mutationFn: (payload: CreateFederationConfigRequest) =>
      federationService.create(payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["federation-configs"],
      });
      setCreateOpen(false);
      createForm.reset();
    },
    onError: (err: unknown) => {
      const msg = getApiErrorMessage(err);
      createForm.setError(msg);
      toast({ description: msg, variant: "destructive" });
    },
  });

  function handleCreateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    createForm.setError("");

    if (!createForm.provider.trim()) {
      createForm.setError("Provider is required.");
      return;
    }
    if (!createForm.clientId.trim()) {
      createForm.setError("Client ID is required.");
      return;
    }
    if (!createForm.clientSecret.trim()) {
      createForm.setError("Client Secret is required.");
      return;
    }
    if (createForm.protocol === "Saml" && !createForm.idpSigningCertPem.trim()) {
      createForm.setError("IdP signing certificate is required for SAML.");
      return;
    }

    const attrResult = parseAttributeMap(createForm.attributeMap);
    if ("error" in attrResult) {
      createForm.setError(attrResult.error);
      return;
    }

    const metadataUrl = createForm.metadataUrl.trim();
    const payload: CreateFederationConfigRequest = {
      provider: createForm.provider.trim(),
      protocol: createForm.protocol,
      client_id: createForm.clientId.trim(),
      client_secret: createForm.clientSecret,
      metadata_url: metadataUrl ? metadataUrl : null,
      attribute_map: attrResult.value,
    };

    if (createForm.protocol === "Saml") {
      payload.idp_signing_cert_pem = createForm.idpSigningCertPem.trim();
      const algos = parseAlgorithms(createForm.allowedAlgorithms);
      if (algos.length > 0) payload.allowed_algorithms = algos;
    }

    createMutation.mutate(payload);
  }

  // ─── Edit state ────────────────────────────────────────────────────────────
  const [editConfig, setEditConfig] = useState<FederationConfig | null>(null);
  const editForm = useConfigFormState();

  const editMutation = useMutation({
    mutationFn: ({
      id,
      payload,
    }: {
      id: string;
      payload: UpdateFederationConfigRequest;
    }) => federationService.update(id, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["federation-configs"],
      });
      setEditConfig(null);
    },
    onError: (err: unknown) => {
      const msg = getApiErrorMessage(err);
      editForm.setError(msg);
      toast({ description: msg, variant: "destructive" });
    },
  });

  function openEdit(config: FederationConfig) {
    setEditConfig(config);
    editForm.load(config);
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    editForm.setError("");

    if (!editConfig) return;
    if (!editForm.provider.trim()) {
      editForm.setError("Provider is required.");
      return;
    }
    if (!editForm.clientId.trim()) {
      editForm.setError("Client ID is required.");
      return;
    }

    const attrResult = parseAttributeMap(editForm.attributeMap);
    if ("error" in attrResult) {
      editForm.setError(attrResult.error);
      return;
    }

    const metadataUrl = editForm.metadataUrl.trim();
    const payload: UpdateFederationConfigRequest = {
      provider: editForm.provider.trim(),
      client_id: editForm.clientId.trim(),
      metadata_url: metadataUrl ? metadataUrl : null,
      attribute_map: attrResult.value,
      enabled: editForm.enabled,
    };

    // client_secret is write-only — only send when the admin entered a new one.
    if (editForm.clientSecret.trim()) {
      payload.client_secret = editForm.clientSecret;
    }

    if (editConfig.protocol === "Saml") {
      const cert = editForm.idpSigningCertPem.trim();
      if (cert) payload.idp_signing_cert_pem = cert;
      const algos = parseAlgorithms(editForm.allowedAlgorithms);
      if (algos.length > 0) payload.allowed_algorithms = algos;
    }

    editMutation.mutate({ id: editConfig.id, payload });
  }

  // ─── Delete state ──────────────────────────────────────────────────────────
  const [deleteConfig, setDeleteConfig] = useState<FederationConfig | null>(
    null,
  );

  const deleteMutation = useMutation({
    mutationFn: (id: string) => federationService.remove(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["federation-configs"],
      });
      setDeleteConfig(null);
    },
    onError: (err: unknown) => {
      toast({ description: getApiErrorMessage(err), variant: "destructive" });
    },
  });

  // ─── Table columns ─────────────────────────────────────────────────────────
  const columns: Column<FederationConfig>[] = [
    {
      key: "provider",
      header: "Provider",
      render: (row) => (
        <span className="font-medium text-foreground/90">{row.provider}</span>
      ),
    },
    {
      key: "protocol",
      header: "Protocol",
      render: (row) => <ProtocolBadge protocol={row.protocol} />,
    },
    {
      key: "enabled",
      header: "Status",
      render: (row) => (
        <StatusBadge status={row.enabled ? "active" : "inactive"} />
      ),
    },
    {
      key: "client_id",
      header: "Client ID",
      render: (row) => (
        <span className="text-sm text-muted-foreground font-mono">
          {row.client_id}
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
            aria-label={`Edit ${row.provider}`}
            onClick={() => openEdit(row)}
            className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
          >
            <Pencil size={14} />
          </button>
          <button
            aria-label={`Delete ${row.provider}`}
            onClick={() => setDeleteConfig(row)}
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
            New Config
          </Button>
        }
      />

      {/* Search */}
      <div className="mb-4">
        <SearchInput
          value={search}
          onChange={setSearch}
          placeholder="Search by provider or client ID..."
          className="max-w-sm"
        />
      </div>

      <DataTable
        columns={columns}
        data={filtered}
        isLoading={isLoading}
        emptyMessage="No federation configs defined."
      />

      {/* Create dialog */}
      <FormDialog
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          createForm.reset();
        }}
        title="New Federation Config"
        onSubmit={handleCreateSubmit}
        isLoading={createMutation.isPending}
        submitLabel="Create"
      >
        <ConfigFields
          provider={createForm.provider}
          protocol={createForm.protocol}
          clientId={createForm.clientId}
          clientSecret={createForm.clientSecret}
          metadataUrl={createForm.metadataUrl}
          idpSigningCertPem={createForm.idpSigningCertPem}
          allowedAlgorithms={createForm.allowedAlgorithms}
          attributeMap={createForm.attributeMap}
          onProviderChange={createForm.setProvider}
          onProtocolChange={createForm.setProtocol}
          onClientIdChange={createForm.setClientId}
          onClientSecretChange={createForm.setClientSecret}
          onMetadataUrlChange={createForm.setMetadataUrl}
          onIdpSigningCertPemChange={createForm.setIdpSigningCertPem}
          onAllowedAlgorithmsChange={createForm.setAllowedAlgorithms}
          onAttributeMapChange={createForm.setAttributeMap}
          error={createForm.error}
          idPrefix="create"
        />
      </FormDialog>

      {/* Edit dialog */}
      <FormDialog
        open={editConfig !== null}
        onClose={() => setEditConfig(null)}
        title="Edit Federation Config"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
      >
        <ConfigFields
          provider={editForm.provider}
          protocol={editForm.protocol}
          clientId={editForm.clientId}
          clientSecret={editForm.clientSecret}
          metadataUrl={editForm.metadataUrl}
          idpSigningCertPem={editForm.idpSigningCertPem}
          allowedAlgorithms={editForm.allowedAlgorithms}
          attributeMap={editForm.attributeMap}
          onProviderChange={editForm.setProvider}
          onProtocolChange={editForm.setProtocol}
          onClientIdChange={editForm.setClientId}
          onClientSecretChange={editForm.setClientSecret}
          onMetadataUrlChange={editForm.setMetadataUrl}
          onIdpSigningCertPemChange={editForm.setIdpSigningCertPem}
          onAllowedAlgorithmsChange={editForm.setAllowedAlgorithms}
          onAttributeMapChange={editForm.setAttributeMap}
          error={editForm.error}
          idPrefix="edit"
          isEditMode={true}
        />
        {/* Enabled toggle only in edit */}
        <ToggleField
          id="edit-fed-enabled"
          label="Enabled"
          checked={editForm.enabled}
          onChange={editForm.setEnabled}
        />
      </FormDialog>

      {/* Delete confirm */}
      <ConfirmDialog
        open={deleteConfig !== null}
        onClose={() => setDeleteConfig(null)}
        onConfirm={() =>
          deleteConfig && deleteMutation.mutate(deleteConfig.id)
        }
        title="Delete Federation Config"
        description={`Are you sure you want to delete the "${deleteConfig?.provider}" config? Users authenticating through this provider will lose SSO access.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}
