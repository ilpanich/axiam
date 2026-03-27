import { useState, useCallback } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  tenantService,
  caCertService,
  orgSettingsService,
  orgService,
  type Tenant,
  type CaCertificate,
  type SecuritySettings,
  type CreateTenantPayload,
  type GenerateCaCertPayload,
} from "@/services/organizations";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Pencil, Trash2, Plus, ChevronLeft, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { Textarea } from "@/components/ui/textarea";

const formatDate = (iso: string) =>
  new Intl.DateTimeFormat("en-US", { dateStyle: "medium" }).format(
    new Date(iso)
  );

function slugify(value: string): string {
  return value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

// ─── Tab bar ──────────────────────────────────────────────────────────────────

type Tab = "tenants" | "certificates" | "settings";

interface TabBarProps {
  active: Tab;
  onChange: (tab: Tab) => void;
}

function TabBar({ active, onChange }: TabBarProps) {
  const tabs: { id: Tab; label: string }[] = [
    { id: "tenants", label: "Tenants" },
    { id: "certificates", label: "CA Certificates" },
    { id: "settings", label: "Settings" },
  ];

  return (
    <div
      className="flex gap-1 border-b border-primary/10 mb-6"
      role="tablist"
      aria-label="Organization sections"
    >
      {tabs.map((tab) => (
        <button
          key={tab.id}
          role="tab"
          aria-selected={active === tab.id}
          aria-controls={`tabpanel-${tab.id}`}
          onClick={() => onChange(tab.id)}
          className={cn(
            "px-4 py-2.5 text-sm font-medium transition-all duration-200 border-b-2 -mb-px focus:outline-none focus:ring-2 focus:ring-primary/40 focus:ring-inset rounded-t",
            active === tab.id
              ? "border-primary text-primary"
              : "border-transparent text-muted-foreground hover:text-foreground hover:border-white/20"
          )}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}

// ─── Tenant form fields ───────────────────────────────────────────────────────

interface TenantFormFieldsProps {
  name: string;
  slug: string;
  description: string;
  onNameChange: (v: string) => void;
  onSlugChange: (v: string) => void;
  onDescriptionChange: (v: string) => void;
  error?: string;
}

function TenantFormFields({
  name,
  slug,
  description,
  onNameChange,
  onSlugChange,
  onDescriptionChange,
  error,
}: TenantFormFieldsProps) {
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor="tenant-name">Name *</Label>
        <Input
          id="tenant-name"
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          placeholder="Default"
          required
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="tenant-slug">Slug *</Label>
        <Input
          id="tenant-slug"
          value={slug}
          onChange={(e) => onSlugChange(e.target.value)}
          placeholder="default"
          required
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="tenant-description">Description</Label>
        <Textarea
          id="tenant-description"
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

// ─── Tenants tab ──────────────────────────────────────────────────────────────

function TenantsTab({ orgId }: { orgId: string }) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const { data: tenants = [], isLoading } = useQuery({
    queryKey: ["tenants", orgId],
    queryFn: () => tenantService.list(orgId),
  });

  // Create
  const [createOpen, setCreateOpen] = useState(false);
  const [createName, setCreateName] = useState("");
  const [createSlug, setCreateSlug] = useState("");
  const [createDescription, setCreateDescription] = useState("");
  const [createError, setCreateError] = useState("");

  const createMutation = useMutation({
    mutationFn: (payload: CreateTenantPayload) =>
      tenantService.create(orgId, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["tenants", orgId] });
      setCreateOpen(false);
      resetCreate();
    },
    onError: (err: unknown) => {
      setCreateError(
        err instanceof Error ? err.message : "Failed to create tenant."
      );
    },
  });

  function resetCreate() {
    setCreateName("");
    setCreateSlug("");
    setCreateDescription("");
    setCreateError("");
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

  // Edit
  const [editTenant, setEditTenant] = useState<Tenant | null>(null);
  const [editName, setEditName] = useState("");
  const [editSlug, setEditSlug] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editError, setEditError] = useState("");

  const editMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: CreateTenantPayload }) =>
      tenantService.update(orgId, id, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["tenants", orgId] });
      setEditTenant(null);
    },
    onError: (err: unknown) => {
      setEditError(
        err instanceof Error ? err.message : "Failed to update tenant."
      );
    },
  });

  function openEdit(t: Tenant) {
    setEditTenant(t);
    setEditName(t.name);
    setEditSlug(t.slug);
    setEditDescription(t.description ?? "");
    setEditError("");
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setEditError("");
    if (!editTenant) return;
    if (!editName.trim() || !editSlug.trim()) {
      setEditError("Name and slug are required.");
      return;
    }
    editMutation.mutate({
      id: editTenant.id,
      payload: {
        name: editName.trim(),
        slug: editSlug.trim(),
        description: editDescription.trim() || undefined,
      },
    });
  }

  // Delete
  const [deleteTenant, setDeleteTenant] = useState<Tenant | null>(null);
  const deleteMutation = useMutation({
    mutationFn: (id: string) => tenantService.remove(orgId, id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["tenants", orgId] });
      setDeleteTenant(null);
    },
  });

  const columns: Column<Tenant>[] = [
    {
      key: "name",
      header: "Name",
      render: (row) => (
        <button
          className="font-medium text-primary hover:underline focus:outline-none focus:underline"
          onClick={() => navigate(`/organizations/${orgId}/tenants/${row.id}`)}
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
    <div role="tabpanel" id="tabpanel-tenants" aria-labelledby="tab-tenants">
      <div className="flex justify-end mb-4">
        <Button
          onClick={() => {
            resetCreate();
            setCreateOpen(true);
          }}
          size="sm"
        >
          <Plus size={14} />
          New Tenant
        </Button>
      </div>

      <DataTable
        columns={columns}
        data={tenants}
        isLoading={isLoading}
        emptyMessage="No tenants yet."
      />

      <FormDialog
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          resetCreate();
        }}
        title="New Tenant"
        onSubmit={handleCreateSubmit}
        isLoading={createMutation.isPending}
        submitLabel="Create"
      >
        <TenantFormFields
          name={createName}
          slug={createSlug}
          description={createDescription}
          onNameChange={(v) => {
            setCreateName(v);
            setCreateSlug(slugify(v));
          }}
          onSlugChange={setCreateSlug}
          onDescriptionChange={setCreateDescription}
          error={createError}
        />
      </FormDialog>

      <FormDialog
        open={editTenant !== null}
        onClose={() => setEditTenant(null)}
        title="Edit Tenant"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
      >
        <TenantFormFields
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

      <ConfirmDialog
        open={deleteTenant !== null}
        onClose={() => setDeleteTenant(null)}
        onConfirm={() =>
          deleteTenant && deleteMutation.mutate(deleteTenant.id)
        }
        title="Delete Tenant"
        description={`Are you sure you want to delete "${deleteTenant?.name}"? All tenant data will be permanently removed.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}

// ─── CA Certificates tab ──────────────────────────────────────────────────────

function CaCertificatesTab({ orgId }: { orgId: string }) {
  const queryClient = useQueryClient();

  const { data: certs = [], isLoading } = useQuery({
    queryKey: ["ca-certificates", orgId],
    queryFn: () => caCertService.list(orgId),
  });

  // Generate
  const [generateOpen, setGenerateOpen] = useState(false);
  const [commonName, setCommonName] = useState("");
  const [keyType, setKeyType] = useState<"RSA4096" | "Ed25519">("RSA4096");
  const [validityDays, setValidityDays] = useState(365);
  const [generateError, setGenerateError] = useState("");

  const generateMutation = useMutation({
    mutationFn: (payload: GenerateCaCertPayload) =>
      caCertService.generate(orgId, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["ca-certificates", orgId] });
      setGenerateOpen(false);
      resetGenerate();
    },
    onError: (err: unknown) => {
      setGenerateError(
        err instanceof Error ? err.message : "Failed to generate certificate."
      );
    },
  });

  function resetGenerate() {
    setCommonName("");
    setKeyType("RSA4096");
    setValidityDays(365);
    setGenerateError("");
  }

  function handleGenerateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setGenerateError("");
    if (!commonName.trim()) {
      setGenerateError("Common name is required.");
      return;
    }
    if (validityDays < 1) {
      setGenerateError("Validity must be at least 1 day.");
      return;
    }
    generateMutation.mutate({
      common_name: commonName.trim(),
      key_type: keyType,
      validity_days: validityDays,
    });
  }

  // Revoke
  const [revokeCert, setRevokeCert] = useState<CaCertificate | null>(null);
  const revokeMutation = useMutation({
    mutationFn: (id: string) => caCertService.revoke(orgId, id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["ca-certificates", orgId] });
      setRevokeCert(null);
    },
  });

  const columns: Column<CaCertificate>[] = [
    {
      key: "common_name",
      header: "Common Name",
      render: (row) => (
        <span className="font-medium text-foreground">{row.common_name}</span>
      ),
    },
    {
      key: "key_type",
      header: "Key Type",
      render: (row) => (
        <code className="text-xs bg-white/5 px-1.5 py-0.5 rounded text-muted-foreground">
          {row.key_type}
        </code>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (row) => <StatusBadge status={row.status} />,
    },
    {
      key: "expires_at",
      header: "Expires",
      render: (row) => (
        <span className="text-muted-foreground text-sm">
          {formatDate(row.expires_at)}
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
        <button
          aria-label={`Revoke ${row.common_name}`}
          onClick={() => setRevokeCert(row)}
          disabled={row.status === "revoked"}
          className={cn(
            "px-2.5 py-1 rounded text-xs font-medium transition-colors",
            row.status === "revoked"
              ? "opacity-40 cursor-not-allowed text-muted-foreground"
              : "text-red-400 hover:bg-red-500/20 hover:text-red-300"
          )}
        >
          Revoke
        </button>
      ),
    },
  ];

  return (
    <div
      role="tabpanel"
      id="tabpanel-certificates"
      aria-labelledby="tab-certificates"
    >
      <div className="flex justify-end mb-4">
        <Button
          onClick={() => {
            resetGenerate();
            setGenerateOpen(true);
          }}
          size="sm"
        >
          <Plus size={14} />
          Generate Certificate
        </Button>
      </div>

      <DataTable
        columns={columns}
        data={certs}
        isLoading={isLoading}
        emptyMessage="No CA certificates yet."
      />

      <FormDialog
        open={generateOpen}
        onClose={() => {
          setGenerateOpen(false);
          resetGenerate();
        }}
        title="Generate CA Certificate"
        onSubmit={handleGenerateSubmit}
        isLoading={generateMutation.isPending}
        submitLabel="Generate"
      >
        <div className="space-y-2">
          <Label htmlFor="cert-cn">Common Name *</Label>
          <Input
            id="cert-cn"
            value={commonName}
            onChange={(e) => setCommonName(e.target.value)}
            placeholder="My Org Root CA"
            required
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="cert-key-type">Key Type</Label>
          <select
            id="cert-key-type"
            value={keyType}
            onChange={(e) =>
              setKeyType(e.target.value as "RSA4096" | "Ed25519")
            }
            className={cn(
              "flex h-10 w-full rounded-md px-3 py-2 text-sm",
              "bg-white/5 border border-primary/20 text-foreground",
              "focus:outline-none focus:ring-2 focus:ring-primary/40 focus:border-primary",
              "transition-colors duration-200"
            )}
          >
            <option value="RSA4096">RSA-4096</option>
            <option value="Ed25519">Ed25519</option>
          </select>
        </div>
        <div className="space-y-2">
          <Label htmlFor="cert-validity">Validity (days)</Label>
          <Input
            id="cert-validity"
            type="number"
            min={1}
            value={validityDays}
            onChange={(e) => setValidityDays(Number(e.target.value))}
          />
        </div>
        {generateError && (
          <p className="text-sm text-destructive">{generateError}</p>
        )}
      </FormDialog>

      <ConfirmDialog
        open={revokeCert !== null}
        onClose={() => setRevokeCert(null)}
        onConfirm={() => revokeCert && revokeMutation.mutate(revokeCert.id)}
        title="Revoke Certificate"
        description={`Are you sure you want to revoke "${revokeCert?.common_name}"? This cannot be undone.`}
        isLoading={revokeMutation.isPending}
      />
    </div>
  );
}

// ─── Settings tab ─────────────────────────────────────────────────────────────

function SettingsTab({ orgId }: { orgId: string }) {
  const queryClient = useQueryClient();
  const [saveError, setSaveError] = useState("");
  const [saveSuccess, setSaveSuccess] = useState(false);

  const { data: settings, isLoading } = useQuery({
    queryKey: ["org-settings", orgId],
    queryFn: () => orgSettingsService.get(orgId),
  });

  const [form, setForm] = useState<SecuritySettings>({});

  // Sync form with loaded settings
  const syncedRef = { current: false };
  if (settings && !syncedRef.current) {
    syncedRef.current = true;
  }

  const updateMutation = useMutation({
    mutationFn: (payload: SecuritySettings) =>
      orgSettingsService.update(orgId, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["org-settings", orgId] });
      setSaveError("");
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    },
    onError: (err: unknown) => {
      setSaveError(
        err instanceof Error ? err.message : "Failed to save settings."
      );
    },
  });

  const merged: SecuritySettings = { ...settings, ...form };

  function setField<K extends keyof SecuritySettings>(
    key: K,
    value: SecuritySettings[K]
  ) {
    setForm((prev) => ({ ...prev, [key]: value }));
  }

  function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setSaveError("");
    setSaveSuccess(false);
    updateMutation.mutate(merged);
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">
        <Loader2 size={20} className="animate-spin mr-2" />
        Loading settings...
      </div>
    );
  }

  return (
    <div role="tabpanel" id="tabpanel-settings" aria-labelledby="tab-settings">
      <form onSubmit={handleSubmit} className="max-w-lg space-y-6">
        {/* Password policy */}
        <div className="glass-card space-y-4">
          <h3 className="text-base font-semibold text-foreground">
            Password Policy
          </h3>

          <div className="space-y-2">
            <Label htmlFor="pwd-min-len">Minimum length</Label>
            <Input
              id="pwd-min-len"
              type="number"
              min={8}
              value={merged.password_min_length ?? 12}
              onChange={(e) =>
                setField("password_min_length", Number(e.target.value))
              }
            />
          </div>

          {(
            [
              ["password_require_uppercase", "Require uppercase letter"],
              ["password_require_lowercase", "Require lowercase letter"],
              ["password_require_digit", "Require digit"],
              ["password_require_symbol", "Require symbol"],
            ] as [keyof SecuritySettings, string][]
          ).map(([key, label]) => (
            <label key={key} className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={Boolean(merged[key])}
                onChange={(e) => setField(key, e.target.checked)}
                className="h-4 w-4 rounded border-primary/40 bg-white/5 text-primary focus:ring-primary/40"
              />
              <span className="text-sm text-foreground">{label}</span>
            </label>
          ))}

          <div className="space-y-2">
            <Label htmlFor="pwd-history">Password history count</Label>
            <Input
              id="pwd-history"
              type="number"
              min={0}
              value={merged.password_history_count ?? 5}
              onChange={(e) =>
                setField("password_history_count", Number(e.target.value))
              }
            />
          </div>
        </div>

        {/* MFA & Session */}
        <div className="glass-card space-y-4">
          <h3 className="text-base font-semibold text-foreground">
            MFA & Session
          </h3>

          <label
            htmlFor="mfa-enforced"
            className="flex items-center gap-3 cursor-pointer"
          >
            <input
              id="mfa-enforced"
              type="checkbox"
              checked={Boolean(merged.mfa_enforced)}
              onChange={(e) => setField("mfa_enforced", e.target.checked)}
              className="h-4 w-4 rounded border-primary/40 bg-white/5 text-primary focus:ring-primary/40"
            />
            <span className="text-sm text-foreground">Enforce MFA for all users</span>
          </label>

          <div className="space-y-2">
            <Label htmlFor="session-timeout">Session timeout (minutes)</Label>
            <Input
              id="session-timeout"
              type="number"
              min={1}
              value={merged.session_timeout_minutes ?? 60}
              onChange={(e) =>
                setField("session_timeout_minutes", Number(e.target.value))
              }
            />
          </div>
        </div>

        {/* Certificates */}
        <div className="glass-card space-y-4">
          <h3 className="text-base font-semibold text-foreground">
            Certificates
          </h3>
          <div className="space-y-2">
            <Label htmlFor="cert-validity-days">
              Default certificate validity (days)
            </Label>
            <Input
              id="cert-validity-days"
              type="number"
              min={1}
              value={merged.certificate_validity_days ?? 365}
              onChange={(e) =>
                setField("certificate_validity_days", Number(e.target.value))
              }
            />
          </div>
        </div>

        {saveError && <p className="text-sm text-destructive">{saveError}</p>}
        {saveSuccess && (
          <p className="text-sm text-cyan-400">Settings saved successfully.</p>
        )}

        <Button type="submit" disabled={updateMutation.isPending}>
          {updateMutation.isPending ? (
            <>
              <Loader2 size={14} className="animate-spin" />
              Saving...
            </>
          ) : (
            "Save Settings"
          )}
        </Button>
      </form>
    </div>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────────

export function OrganizationDetailPage() {
  const { orgId } = useParams<{ orgId: string }>();
  const [activeTab, setActiveTab] = useState<Tab>("tenants");

  const { data: org, isLoading: orgLoading } = useQuery({
    queryKey: ["organizations", orgId],
    queryFn: () => orgService.get(orgId!),
    enabled: !!orgId,
  });

  const handleTabChange = useCallback((tab: Tab) => {
    setActiveTab(tab);
  }, []);

  if (!orgId) return null;

  return (
    <div>
      {/* Breadcrumb */}
      <nav
        aria-label="Breadcrumb"
        className="flex items-center gap-2 text-sm text-muted-foreground mb-4"
      >
        <Link
          to="/organizations"
          className="hover:text-foreground transition-colors"
        >
          Organizations
        </Link>
        <span aria-hidden="true">/</span>
        <span className="text-foreground">
          {orgLoading ? "..." : org?.name ?? orgId}
        </span>
      </nav>

      <PageHeader
        title={orgLoading ? "Loading..." : (org?.name ?? "Organization")}
        description={org?.description}
        action={
          <Button variant="ghost" size="sm" asChild>
            <Link to="/organizations">
              <ChevronLeft size={14} />
              Back
            </Link>
          </Button>
        }
      />

      <TabBar active={activeTab} onChange={handleTabChange} />

      {activeTab === "tenants" && <TenantsTab orgId={orgId} />}
      {activeTab === "certificates" && <CaCertificatesTab orgId={orgId} />}
      {activeTab === "settings" && <SettingsTab orgId={orgId} />}
    </div>
  );
}
