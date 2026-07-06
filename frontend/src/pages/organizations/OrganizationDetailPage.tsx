import { useState, useCallback, useEffect, useRef } from "react";
import {
  useParams,
  useNavigate,
  Link,
  useBlocker,
  type BlockerFunction,
} from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  tenantService,
  caCertService,
  orgSettingsService,
  orgService,
  flattenOrgSettings,
  type Tenant,
  type CaCertificate,
  type SetOrgSettings,
  type CreateTenantPayload,
  type GenerateCaCertPayload,
} from "@/services/organizations";
import { shouldSeedForm, computeIsDirty } from "./settingsForm";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { StatusBadge } from "@/components/StatusBadge";
import { SecretRevealModal } from "@/components/SecretRevealModal";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Pencil, Trash2, Plus, ChevronLeft, Loader2 } from "lucide-react";
import { cn, formatDate, slugify } from "@/lib/utils";
import { Textarea } from "@/components/ui/textarea";

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
    const description = createDescription.trim();
    createMutation.mutate({
      name: createName.trim(),
      slug: createSlug.trim(),
      metadata: description ? { description } : undefined,
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
    setEditDescription((t.metadata?.description as string | undefined) ?? "");
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
    const description = editDescription.trim();
    editMutation.mutate({
      id: editTenant.id,
      payload: {
        name: editName.trim(),
        slug: editSlug.trim(),
        metadata: { ...editTenant.metadata, description },
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
          {(row.metadata?.description as string | undefined) ?? (
            <span className="opacity-40">—</span>
          )}
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

/**
 * Map the backend's PascalCase `CertificateStatus` (Active/Revoked/Expired)
 * onto the lowercase variants the shared `StatusBadge` accepts. `Expired`
 * has no badge variant of its own, so it renders with the neutral style.
 */
function caBadgeStatus(
  status: CaCertificate["status"]
): "active" | "revoked" | "inactive" {
  switch (status) {
    case "Active":
      return "active";
    case "Revoked":
      return "revoked";
    case "Expired":
      return "inactive";
  }
}

function CaCertificatesTab({ orgId }: { orgId: string }) {
  const queryClient = useQueryClient();

  const { data: certs = [], isLoading } = useQuery({
    queryKey: ["ca-certificates", orgId],
    queryFn: () => caCertService.list(orgId),
  });

  // Generate
  const [generateOpen, setGenerateOpen] = useState(false);
  const [subject, setSubject] = useState("");
  const [keyAlgorithm, setKeyAlgorithm] = useState<"Rsa4096" | "Ed25519">(
    "Rsa4096"
  );
  const [validityDays, setValidityDays] = useState(365);
  const [generateError, setGenerateError] = useState("");
  // The one-time PEM private key returned on generation (never retrievable again).
  const [revealedPrivateKey, setRevealedPrivateKey] = useState<string | null>(
    null
  );

  const generateMutation = useMutation({
    mutationFn: (payload: GenerateCaCertPayload) =>
      caCertService.generate(orgId, payload),
    onSuccess: (result) => {
      void queryClient.invalidateQueries({ queryKey: ["ca-certificates", orgId] });
      setGenerateOpen(false);
      resetGenerate();
      // Surface the one-time private key — it is never retrievable again.
      if (result.private_key_pem) {
        setRevealedPrivateKey(result.private_key_pem);
      }
    },
    onError: (err: unknown) => {
      setGenerateError(
        err instanceof Error ? err.message : "Failed to generate certificate."
      );
    },
  });

  function resetGenerate() {
    setSubject("");
    setKeyAlgorithm("Rsa4096");
    setValidityDays(365);
    setGenerateError("");
  }

  function handleGenerateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setGenerateError("");
    if (!subject.trim()) {
      setGenerateError("Subject is required.");
      return;
    }
    if (validityDays < 1) {
      setGenerateError("Validity must be at least 1 day.");
      return;
    }
    generateMutation.mutate({
      subject: subject.trim(),
      key_algorithm: keyAlgorithm,
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
      key: "subject",
      header: "Subject",
      render: (row) => (
        <span className="font-medium text-foreground">{row.subject}</span>
      ),
    },
    {
      key: "key_algorithm",
      header: "Key Algorithm",
      render: (row) => (
        <code className="text-xs bg-white/5 px-1.5 py-0.5 rounded text-muted-foreground">
          {row.key_algorithm}
        </code>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (row) => <StatusBadge status={caBadgeStatus(row.status)} />,
    },
    {
      key: "not_after",
      header: "Expires",
      render: (row) => (
        <span className="text-muted-foreground text-sm">
          {formatDate(row.not_after)}
        </span>
      ),
    },
    {
      key: "fingerprint",
      header: "Fingerprint",
      render: (row) => (
        <code className="text-xs text-muted-foreground">
          {row.fingerprint.slice(0, 16)}…
        </code>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      width: "w-24",
      render: (row) => (
        <button
          aria-label={`Revoke ${row.subject}`}
          onClick={() => setRevokeCert(row)}
          disabled={row.status === "Revoked"}
          className={cn(
            "px-2.5 py-1 rounded text-xs font-medium transition-colors",
            row.status === "Revoked"
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
          <Label htmlFor="cert-subject">Subject *</Label>
          <Input
            id="cert-subject"
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
            placeholder="CN=My Org Root CA"
            required
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="cert-key-algorithm">Key Algorithm</Label>
          <select
            id="cert-key-algorithm"
            value={keyAlgorithm}
            onChange={(e) =>
              setKeyAlgorithm(e.target.value as "Rsa4096" | "Ed25519")
            }
            className={cn(
              "flex h-10 w-full rounded-md px-3 py-2 text-sm",
              "bg-white/5 border border-primary/20 text-foreground",
              "focus:outline-none focus:ring-2 focus:ring-primary/40 focus:border-primary",
              "transition-colors duration-200"
            )}
          >
            <option value="Rsa4096">RSA-4096</option>
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
        description={`Are you sure you want to revoke "${revokeCert?.subject}"? This cannot be undone.`}
        isLoading={revokeMutation.isPending}
      />

      <SecretRevealModal
        open={revealedPrivateKey !== null}
        onClose={() => setRevealedPrivateKey(null)}
        title="CA Certificate Generated"
        description="Save the CA private key now — it is never shown again and cannot be recovered."
        secrets={
          revealedPrivateKey
            ? [{ label: "Private Key (PEM)", value: revealedPrivateKey }]
            : []
        }
      />
    </div>
  );
}

// ─── Settings tab ─────────────────────────────────────────────────────────────

function SettingsTab({
  orgId,
  onDirtyChange,
}: {
  orgId: string;
  onDirtyChange?: (dirty: boolean) => void;
}) {
  const queryClient = useQueryClient();
  const [saveError, setSaveError] = useState("");
  const [saveSuccess, setSaveSuccess] = useState(false);

  const { data: settings, isLoading } = useQuery({
    queryKey: ["org-settings", orgId],
    queryFn: () => orgSettingsService.get(orgId),
  });

  // The form holds the FULL flat SetOrgSettings — PUT requires every field.
  // `null` until the nested settings load, then pre-filled from them.
  const [form, setForm] = useState<SetOrgSettings | null>(null);
  // D-19: last-loaded server snapshot, frozen once seeded — the comparison
  // baseline for isDirty. NOT updated by a background refetch while the
  // form is dirty, so in-progress edits keep comparing against the value
  // the user actually started editing from.
  const snapshotRef = useRef<SetOrgSettings | null>(null);
  // D-19: init-once guard — seeds `form` from `settings` only on the FIRST
  // successful load per mount (SettingsTab remounts on orgId change, which
  // is the intended re-seed case). A later background refetch/refocus with
  // initializedRef.current already true must NOT overwrite in-progress
  // edits — that was the reported bug.
  const initializedRef = useRef(false);
  const [isDirty, setIsDirty] = useState(false);

  // Initialize form from loaded settings — once per mount/orgId only.
  useEffect(() => {
    if (shouldSeedForm(initializedRef.current, settings)) {
      const flattened = flattenOrgSettings(settings!);
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setForm(flattened);
      snapshotRef.current = flattened;
      initializedRef.current = true;
    }
  }, [settings]);

  // Propagate dirty state to the parent so it can guard the in-page
  // tab-switch (Settings -> Tenants/Certificates), which is local component
  // state in OrganizationDetailPage, not a router navigation.
  useEffect(() => {
    onDirtyChange?.(isDirty);
  }, [isDirty, onDirtyChange]);

  // D-19: native browser-level guard (refresh/close tab) — copy is
  // browser-controlled, only `event.returnValue` needs to be set.
  useEffect(() => {
    function handleBeforeUnload(e: BeforeUnloadEvent) {
      if (isDirty) {
        e.preventDefault();
        e.returnValue = "";
      }
    }
    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => window.removeEventListener("beforeunload", handleBeforeUnload);
  }, [isDirty]);

  // D-19: in-app navigate-away guard for actual route changes (e.g. the
  // "Back" link/breadcrumb, or a sidebar link to a different page) while
  // dirty. react-router v7's useBlocker requires the data router this app
  // already uses (createBrowserRouter in router.tsx).
  const blocker = useBlocker(
    useCallback<BlockerFunction>(
      ({ currentLocation, nextLocation }) =>
        isDirty && currentLocation.pathname !== nextLocation.pathname,
      [isDirty]
    )
  );

  const updateMutation = useMutation({
    mutationFn: (payload: SetOrgSettings) =>
      orgSettingsService.update(orgId, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["org-settings", orgId] });
      setSaveError("");
      setSaveSuccess(true);
      // Save resets the dirty baseline to the just-saved values and
      // deactivates the navigate-away guard (UI-SPEC: "Dirty state resets
      // to clean and the navigate-away guard deactivates").
      if (form) snapshotRef.current = form;
      setIsDirty(false);
      setTimeout(() => setSaveSuccess(false), 3000);
    },
    onError: (err: unknown) => {
      setSaveError(
        err instanceof Error ? err.message : "Failed to save settings."
      );
    },
  });

  function setField<K extends keyof SetOrgSettings>(
    key: K,
    value: SetOrgSettings[K]
  ) {
    setForm((prev) => (prev ? { ...prev, [key]: value } : prev));
  }

  // D-19: recompute dirtiness whenever the form changes, against the frozen
  // snapshot (not the live `settings` query data — a background refetch
  // must never flip a genuinely-edited field back to clean, or vice versa).
  useEffect(() => {
    if (form && snapshotRef.current) {
      setIsDirty(computeIsDirty(form, snapshotRef.current));
    }
  }, [form]);

  function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!form) return;
    setSaveError("");
    setSaveSuccess(false);
    updateMutation.mutate(form);
  }

  if (isLoading || !form) {
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">
        <Loader2 size={20} className="animate-spin mr-2" />
        Loading settings...
      </div>
    );
  }

  const merged = form;

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
              value={merged.min_length}
              onChange={(e) =>
                setField("min_length", Number(e.target.value))
              }
            />
          </div>

          {(
            [
              ["require_uppercase", "Require uppercase letter"],
              ["require_lowercase", "Require lowercase letter"],
              ["require_digits", "Require digit"],
              ["require_symbols", "Require symbol"],
              ["hibp_check_enabled", "Check against breach database (HIBP)"],
            ] as [keyof SetOrgSettings, string][]
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
              value={merged.password_history_count}
              onChange={(e) =>
                setField("password_history_count", Number(e.target.value))
              }
            />
          </div>
        </div>

        {/* MFA */}
        <div className="glass-card space-y-4">
          <h3 className="text-base font-semibold text-foreground">MFA</h3>

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
            <Label htmlFor="mfa-challenge">
              MFA challenge lifetime (seconds)
            </Label>
            <Input
              id="mfa-challenge"
              type="number"
              min={1}
              value={merged.mfa_challenge_lifetime_secs}
              onChange={(e) =>
                setField(
                  "mfa_challenge_lifetime_secs",
                  Number(e.target.value)
                )
              }
            />
          </div>
        </div>

        {/* Lockout */}
        <div className="glass-card space-y-4">
          <h3 className="text-base font-semibold text-foreground">
            Account Lockout
          </h3>

          <div className="space-y-2">
            <Label htmlFor="lockout-max-attempts">
              Max failed login attempts
            </Label>
            <Input
              id="lockout-max-attempts"
              type="number"
              min={1}
              value={merged.max_failed_login_attempts}
              onChange={(e) =>
                setField("max_failed_login_attempts", Number(e.target.value))
              }
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="lockout-duration">
              Lockout duration (seconds)
            </Label>
            <Input
              id="lockout-duration"
              type="number"
              min={1}
              value={merged.lockout_duration_secs}
              onChange={(e) =>
                setField("lockout_duration_secs", Number(e.target.value))
              }
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="lockout-backoff">Lockout backoff multiplier</Label>
            <Input
              id="lockout-backoff"
              type="number"
              min={1}
              step={0.1}
              value={merged.lockout_backoff_multiplier}
              onChange={(e) =>
                setField(
                  "lockout_backoff_multiplier",
                  Number(e.target.value)
                )
              }
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="lockout-max-duration">
              Max lockout duration (seconds)
            </Label>
            <Input
              id="lockout-max-duration"
              type="number"
              min={1}
              value={merged.max_lockout_duration_secs}
              onChange={(e) =>
                setField("max_lockout_duration_secs", Number(e.target.value))
              }
            />
          </div>
        </div>

        {/* Tokens */}
        <div className="glass-card space-y-4">
          <h3 className="text-base font-semibold text-foreground">Tokens</h3>

          <div className="space-y-2">
            <Label htmlFor="access-token-lifetime">
              Access token lifetime (seconds)
            </Label>
            <Input
              id="access-token-lifetime"
              type="number"
              min={1}
              value={merged.access_token_lifetime_secs}
              onChange={(e) =>
                setField("access_token_lifetime_secs", Number(e.target.value))
              }
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="refresh-token-lifetime">
              Refresh token lifetime (seconds)
            </Label>
            <Input
              id="refresh-token-lifetime"
              type="number"
              min={1}
              value={merged.refresh_token_lifetime_secs}
              onChange={(e) =>
                setField(
                  "refresh_token_lifetime_secs",
                  Number(e.target.value)
                )
              }
            />
          </div>
        </div>

        {/* Email */}
        <div className="glass-card space-y-4">
          <h3 className="text-base font-semibold text-foreground">
            Email Verification
          </h3>

          <label
            htmlFor="email-verif-required"
            className="flex items-center gap-3 cursor-pointer"
          >
            <input
              id="email-verif-required"
              type="checkbox"
              checked={Boolean(merged.email_verification_required)}
              onChange={(e) =>
                setField("email_verification_required", e.target.checked)
              }
              className="h-4 w-4 rounded border-primary/40 bg-white/5 text-primary focus:ring-primary/40"
            />
            <span className="text-sm text-foreground">
              Require email verification
            </span>
          </label>

          <div className="space-y-2">
            <Label htmlFor="email-grace">
              Verification grace period (hours)
            </Label>
            <Input
              id="email-grace"
              type="number"
              min={0}
              value={merged.email_verification_grace_period_hours}
              onChange={(e) =>
                setField(
                  "email_verification_grace_period_hours",
                  Number(e.target.value)
                )
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
              value={merged.default_cert_validity_days}
              onChange={(e) =>
                setField("default_cert_validity_days", Number(e.target.value))
              }
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="cert-max-validity-days">
              Max certificate validity (days)
            </Label>
            <Input
              id="cert-max-validity-days"
              type="number"
              min={1}
              value={merged.max_cert_validity_days}
              onChange={(e) =>
                setField("max_cert_validity_days", Number(e.target.value))
              }
            />
          </div>
        </div>

        {/* Notifications */}
        <div className="glass-card space-y-4">
          <h3 className="text-base font-semibold text-foreground">
            Notifications
          </h3>
          <label
            htmlFor="admin-notifications"
            className="flex items-center gap-3 cursor-pointer"
          >
            <input
              id="admin-notifications"
              type="checkbox"
              checked={Boolean(merged.admin_notifications_enabled)}
              onChange={(e) =>
                setField("admin_notifications_enabled", e.target.checked)
              }
              className="h-4 w-4 rounded border-primary/40 bg-white/5 text-primary focus:ring-primary/40"
            />
            <span className="text-sm text-foreground">
              Enable admin notifications
            </span>
          </label>
        </div>

        {saveError && <p className="text-sm text-destructive">{saveError}</p>}
        {saveSuccess && (
          <p className="text-sm text-cyan-400">Settings saved successfully.</p>
        )}

        <div className="flex items-center gap-3">
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
          {isDirty && (
            <span
              className="text-xs font-medium text-amber-400"
              role="status"
            >
              Unsaved changes
            </span>
          )}
        </div>
      </form>

      {/* D-19: in-app navigate-away guard (route-level, e.g. the breadcrumb
          "Organizations" link or a sidebar link to a different page) —
          reuses the existing ConfirmDialog for visual consistency. */}
      <ConfirmDialog
        open={blocker.state === "blocked"}
        onClose={() => blocker.reset?.()}
        onConfirm={() => blocker.proceed?.()}
        title="Discard unsaved changes?"
        description="You have unsaved changes to these settings. Leaving now will discard them."
        confirmLabel="Discard changes"
        cancelLabel="Keep editing"
      />
    </div>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────────

export function OrganizationDetailPage() {
  const { orgId } = useParams<{ orgId: string }>();
  const [activeTab, setActiveTab] = useState<Tab>("tenants");
  // D-19: SettingsTab's dirty state, lifted up so switching AWAY from the
  // Settings tab (a local component-state change, not a router navigation)
  // can also be guarded. Route-level navigation away from this page
  // entirely is separately guarded inside SettingsTab via useBlocker.
  const [settingsDirty, setSettingsDirty] = useState(false);
  const [pendingTab, setPendingTab] = useState<Tab | null>(null);
  // Bumped to force-remount SettingsTab (fresh init-once/dirty state) after
  // the user explicitly discards in-progress edits to switch tabs.
  const [settingsResetKey, setSettingsResetKey] = useState(0);

  const { data: org, isLoading: orgLoading } = useQuery({
    queryKey: ["organizations", orgId],
    queryFn: () => orgService.get(orgId!),
    enabled: !!orgId,
  });

  const handleTabChange = useCallback(
    (tab: Tab) => {
      if (activeTab === "settings" && settingsDirty && tab !== "settings") {
        setPendingTab(tab);
        return;
      }
      setActiveTab(tab);
    },
    [activeTab, settingsDirty]
  );

  function discardAndSwitchTab() {
    if (pendingTab) {
      setActiveTab(pendingTab);
      setSettingsDirty(false);
      setSettingsResetKey((k) => k + 1);
      setPendingTab(null);
    }
  }

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
        description={org?.metadata?.description as string | undefined}
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
      {activeTab === "settings" && (
        <SettingsTab
          key={settingsResetKey}
          orgId={orgId}
          onDirtyChange={setSettingsDirty}
        />
      )}

      {/* D-19: in-app navigate-away guard for the Settings tab's own
          in-page tab bar — reuses the existing ConfirmDialog. */}
      <ConfirmDialog
        open={pendingTab !== null}
        onClose={() => setPendingTab(null)}
        onConfirm={discardAndSwitchTab}
        title="Discard unsaved changes?"
        description="You have unsaved changes to these settings. Leaving now will discard them."
        confirmLabel="Discard changes"
        cancelLabel="Keep editing"
      />
    </div>
  );
}
