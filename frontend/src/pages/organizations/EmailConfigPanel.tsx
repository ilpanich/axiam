import { useEffect, useRef, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Loader2, Send, Trash2 } from "lucide-react";
import {
  emailConfigService,
  validateOrgEmailConfig,
  EMAIL_PROVIDER_KINDS,
  EMAIL_PROVIDER_LABELS,
  type EmailConfig,
  type EmailConfigOverride,
  type EmailProviderKind,
  type EmailTestResult,
  type ProviderConfig,
  type SetOrgEmailConfigPayload,
} from "@/services/emailConfig";
import { getApiErrorMessage } from "@/lib/apiError";
import { usePermissions } from "@/hooks/usePermissions";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

// ─── Shared form model ────────────────────────────────────────────────────────

/**
 * The panel's local form shape.
 *
 * Flat rather than the nested `ProviderConfig`, because the provider kind is a
 * dropdown and the fields under it change with it — keeping every provider's
 * fields side by side means switching the dropdown back and forth does not
 * discard what was already typed.
 *
 * Secrets live here as the empty string until the operator types one, which is
 * exactly the backend's "omit — preserve the stored value" sentinel (D-02), so
 * a save that does not touch the secret field leaves the stored secret alone.
 */
interface EmailFormState {
  enabled: boolean;
  fromName: string;
  fromEmail: string;
  replyTo: string;
  providerKind: EmailProviderKind;
  smtpHost: string;
  smtpPort: string;
  smtpUsername: string;
  smtpPassword: string;
  smtpStarttls: boolean;
  apiKey: string;
  apiUrl: string;
}

const EMPTY_FORM: EmailFormState = {
  enabled: true,
  fromName: "",
  fromEmail: "",
  replyTo: "",
  providerKind: "smtp",
  smtpHost: "",
  smtpPort: "587",
  smtpUsername: "",
  smtpPassword: "",
  smtpStarttls: true,
  apiKey: "",
  apiUrl: "",
};

function formFromProvider(
  base: EmailFormState,
  provider: ProviderConfig | undefined
): EmailFormState {
  if (!provider) return base;
  if (provider.kind === "smtp") {
    return {
      ...base,
      providerKind: "smtp",
      smtpHost: provider.host,
      smtpPort: String(provider.port),
      smtpUsername: provider.username,
      smtpStarttls: provider.starttls,
      // Deliberately not seeded: the backend never sends it back.
      smtpPassword: "",
    };
  }
  return {
    ...base,
    providerKind: provider.kind,
    apiUrl: provider.api_url ?? "",
    apiKey: "",
  };
}

function providerFromForm(f: EmailFormState): ProviderConfig {
  if (f.providerKind === "smtp") {
    return {
      kind: "smtp",
      host: f.smtpHost.trim(),
      // NaN would serialize as null and fail the backend's u16 parse with a
      // less useful message than the empty-port validation below.
      port: Number.parseInt(f.smtpPort, 10) || 0,
      username: f.smtpUsername.trim(),
      password: f.smtpPassword,
      starttls: f.smtpStarttls,
    };
  }
  return {
    kind: f.providerKind,
    api_key: f.apiKey,
    api_url: f.apiUrl.trim() || null,
  };
}

// ─── Shared field groups ──────────────────────────────────────────────────────

function ProviderFields({
  form,
  setField,
  idPrefix,
  hasStoredSecret,
}: {
  form: EmailFormState;
  setField: <K extends keyof EmailFormState>(
    k: K,
    v: EmailFormState[K]
  ) => void;
  idPrefix: string;
  hasStoredSecret: boolean;
}) {
  // "A secret is stored" is only true for the provider kind that was actually
  // saved. After switching SMTP → SendGrid there is no stored API key, so
  // promising that a blank field keeps one would store an empty secret behind
  // a message saying the opposite.
  const secretHint = hasStoredSecret
    ? "A secret is already stored. Leave blank to keep it; type a new one to replace it."
    : "Stored encrypted at rest and never returned by the API.";

  return (
    <>
      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-provider`}>Provider</Label>
        <select
          id={`${idPrefix}-provider`}
          value={form.providerKind}
          onChange={(e) =>
            setField("providerKind", e.target.value as EmailProviderKind)
          }
          className="w-full rounded-md border border-input bg-background/50 px-3 py-2 text-sm"
        >
          {EMAIL_PROVIDER_KINDS.map((k) => (
            <option key={k} value={k}>
              {EMAIL_PROVIDER_LABELS[k]}
            </option>
          ))}
        </select>
      </div>

      {form.providerKind === "smtp" ? (
        <>
          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-2 space-y-2">
              <Label htmlFor={`${idPrefix}-smtp-host`}>SMTP Host *</Label>
              <Input
                id={`${idPrefix}-smtp-host`}
                value={form.smtpHost}
                onChange={(e) => setField("smtpHost", e.target.value)}
                placeholder="smtp.example.com"
                className="font-mono"
                autoComplete="off"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${idPrefix}-smtp-port`}>Port *</Label>
              <Input
                id={`${idPrefix}-smtp-port`}
                type="number"
                min={1}
                max={65535}
                value={form.smtpPort}
                onChange={(e) => setField("smtpPort", e.target.value)}
                className="font-mono"
              />
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-smtp-username`}>Username</Label>
            <Input
              id={`${idPrefix}-smtp-username`}
              value={form.smtpUsername}
              onChange={(e) => setField("smtpUsername", e.target.value)}
              autoComplete="off"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-smtp-password`}>Password</Label>
            <Input
              id={`${idPrefix}-smtp-password`}
              type="password"
              value={form.smtpPassword}
              onChange={(e) => setField("smtpPassword", e.target.value)}
              autoComplete="new-password"
              placeholder={hasStoredSecret ? "••••••••" : ""}
            />
            <p className="text-xs text-muted-foreground">{secretHint}</p>
          </div>

          <label className="flex items-center gap-2.5 cursor-pointer">
            <input
              type="checkbox"
              checked={form.smtpStarttls}
              onChange={(e) => setField("smtpStarttls", e.target.checked)}
              className="w-3.5 h-3.5 accent-cyan-400 cursor-pointer"
            />
            <span className="text-sm text-foreground/80">
              Use STARTTLS (uncheck for implicit TLS)
            </span>
          </label>
        </>
      ) : (
        <>
          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-api-key`}>API Key</Label>
            <Input
              id={`${idPrefix}-api-key`}
              type="password"
              value={form.apiKey}
              onChange={(e) => setField("apiKey", e.target.value)}
              autoComplete="new-password"
              placeholder={hasStoredSecret ? "••••••••" : ""}
            />
            <p className="text-xs text-muted-foreground">{secretHint}</p>
          </div>

          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-api-url`}>API URL</Label>
            <Input
              id={`${idPrefix}-api-url`}
              value={form.apiUrl}
              onChange={(e) => setField("apiUrl", e.target.value)}
              placeholder="Leave blank for the provider default"
              className="font-mono"
              autoComplete="off"
            />
          </div>
        </>
      )}
    </>
  );
}

function SenderFields({
  form,
  setField,
  idPrefix,
  required,
  showReplyTo = true,
}: {
  form: EmailFormState;
  setField: <K extends keyof EmailFormState>(
    k: K,
    v: EmailFormState[K]
  ) => void;
  idPrefix: string;
  required: boolean;
  /**
   * The tenant override sets this false: the tenant email-config schema has
   * no `reply_to` column, so `get_tenant_override` hard-codes it to `None`
   * (`crates/axiam-db/src/repository/email_config.rs`). Offering the field
   * there would take a value, appear to save it, and silently drop it.
   */
  showReplyTo?: boolean;
}) {
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-from-name`}>
          From Name {required && "*"}
        </Label>
        <Input
          id={`${idPrefix}-from-name`}
          value={form.fromName}
          onChange={(e) => setField("fromName", e.target.value)}
          placeholder="Example Identity"
          autoComplete="off"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-from-email`}>
          From Address {required && "*"}
        </Label>
        <Input
          id={`${idPrefix}-from-email`}
          type="email"
          value={form.fromEmail}
          onChange={(e) => setField("fromEmail", e.target.value)}
          placeholder="no-reply@example.com"
          className="font-mono"
          autoComplete="off"
        />
      </div>

      {showReplyTo && (
        <div className="space-y-2">
          <Label htmlFor={`${idPrefix}-reply-to`}>Reply-To</Label>
          <Input
            id={`${idPrefix}-reply-to`}
            type="email"
            value={form.replyTo}
            onChange={(e) => setField("replyTo", e.target.value)}
            placeholder="support@example.com"
            className="font-mono"
            autoComplete="off"
          />
        </div>
      )}
    </>
  );
}

function StatusLine({
  error,
  success,
}: {
  error: string;
  success: boolean;
}) {
  if (error) {
    return (
      <p role="alert" className="text-sm text-destructive">
        {error}
      </p>
    );
  }
  if (success) {
    return (
      <p role="status" className="text-sm text-emerald-400">
        Saved.
      </p>
    );
  }
  return null;
}

/**
 * "Send test email" — the one control that tells an operator whether the
 * configuration they just saved actually delivers.
 *
 * Nothing else in the admin UI can answer that. `PUT` validates structure only
 * and never opens a connection (D-15), and real sends happen on an AMQP
 * consumer in another process, so a provider rejection — an unverified sender
 * domain, a revoked key — reaches an operator only as a dead-letter line in a
 * log they are not reading. This runs the same resolve → build → send path
 * inline and prints the provider's own words next to the button.
 *
 * The endpoint takes no recipient: the server reads the caller's own address
 * from their user record, so this cannot mail anyone else.
 */
function SelfTestButton({ send }: { send: () => Promise<EmailTestResult> }) {
  const [result, setResult] = useState<EmailTestResult | null>(null);
  const [failure, setFailure] = useState("");

  const testMutation = useMutation({
    mutationFn: send,
    onMutate: () => {
      setResult(null);
      setFailure("");
    },
    onSuccess: setResult,
    onError: (err: unknown) =>
      setFailure(
        getApiErrorMessage(err, "The provider rejected the test message.")
      ),
  });

  return (
    <div className="space-y-2">
      <Button
        type="button"
        variant="ghost"
        onClick={() => testMutation.mutate()}
        disabled={testMutation.isPending}
      >
        {testMutation.isPending ? (
          <Loader2 size={14} className="animate-spin" />
        ) : (
          <Send size={14} />
        )}
        Send test email
      </Button>
      {result && (
        <p role="status" className="text-sm text-emerald-400">
          {result.provider} accepted a message to {result.to}
          {result.message_id ? ` (id ${result.message_id})` : ""}.
        </p>
      )}
      {failure && (
        <p role="alert" className="text-sm text-destructive">
          {failure}
        </p>
      )}
    </div>
  );
}

// ─── Organization panel ───────────────────────────────────────────────────────

/**
 * The org-level baseline (FUNC-03 / D-13). Every field is required, because
 * PUT replaces the whole configuration — there is no partial org write.
 */
export function OrgEmailConfigPanel({ orgId }: { orgId: string }) {
  const queryClient = useQueryClient();
  const { can } = usePermissions();
  const canWrite = can("email_config:write");

  const {
    data: config,
    isLoading,
    isError,
    error: loadError,
  } = useQuery({
    queryKey: ["org-email-config", orgId],
    queryFn: () => emailConfigService.getOrgConfig(orgId),
  });

  const [form, setForm] = useState<EmailFormState>(EMPTY_FORM);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  // Seed once per mount, on the same reasoning as SettingsTab's init-once
  // guard: a background refetch must not overwrite in-progress edits.
  const seeded = useRef(false);

  useEffect(() => {
    if (seeded.current || isLoading) return;
    seeded.current = true;
    if (!config) return;
    // Seeding an editable form from server data is a one-shot copy, not a derived
    // value: the `seeded` guard is what stops a background refetch from
    // overwriting edits in progress, and it is re-armed by the delete handler so
    // the form re-seeds from whatever the server reports next. Deriving during
    // render instead would re-seed from the stale query result the moment the
    // guard is re-armed, before the refetch lands.
    // oxlint-disable-next-line react/set-state-in-effect
    setForm(
      formFromProvider(
        {
          ...EMPTY_FORM,
          enabled: config.enabled,
          fromName: config.from_name,
          fromEmail: config.from_email,
          replyTo: config.reply_to ?? "",
        },
        config.provider
      )
    );
  }, [config, isLoading]);

  function setField<K extends keyof EmailFormState>(
    k: K,
    v: EmailFormState[K]
  ) {
    setForm((prev) => ({ ...prev, [k]: v }));
    setSuccess(false);
  }

  const saveMutation = useMutation({
    mutationFn: (payload: SetOrgEmailConfigPayload) =>
      emailConfigService.setOrgConfig(orgId, payload),
    onSuccess: (saved: EmailConfig) => {
      void queryClient.invalidateQueries({
        queryKey: ["org-email-config", orgId],
      });
      setError("");
      setSuccess(true);
      // Clear the secret inputs so a second save does not resend what was
      // just stored — and so the placeholder flips to "already stored".
      setForm((prev) => ({ ...prev, smtpPassword: "", apiKey: "" }));
      void saved;
    },
    onError: (err: unknown) =>
      setError(
        err instanceof Error ? err.message : "Failed to save email configuration."
      ),
  });

  const deleteMutation = useMutation({
    mutationFn: () => emailConfigService.deleteOrgConfig(orgId),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["org-email-config", orgId],
      });
      setConfirmDelete(false);
      seeded.current = false;
      setForm(EMPTY_FORM);
      setError("");
    },
    onError: (err: unknown) => {
      setConfirmDelete(false);
      setError(
        err instanceof Error
          ? err.message
          : "Failed to delete email configuration."
      );
    },
  });

  function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");
    const payload: SetOrgEmailConfigPayload = {
      enabled: form.enabled,
      from_name: form.fromName.trim(),
      from_email: form.fromEmail.trim(),
      reply_to: form.replyTo.trim() || null,
      provider: providerFromForm(form),
    };
    const validationError = validateOrgEmailConfig(payload);
    if (validationError) {
      setError(validationError);
      return;
    }
    saveMutation.mutate(payload);
  }

  if (isLoading) {
    return (
      <div className="glass-card animate-pulse space-y-3" aria-busy="true">
        <div className="h-4 bg-white/10 rounded w-1/3" />
        <div className="h-4 bg-white/10 rounded w-1/2" />
      </div>
    );
  }

  // A failed load must not fall through to the blank form: that reads as "no
  // configuration set", and saving from it would replace a live configuration
  // the panel never managed to show. 404 is not an error here — the service
  // maps it to null, which is genuinely "not configured yet".
  if (isError) {
    return (
      <div className="glass-card max-w-2xl">
        <p role="alert" className="text-sm text-destructive">
          Could not load the email configuration
          {loadError instanceof Error ? `: ${loadError.message}` : "."} Reload
          before editing — saving from here would overwrite whatever is stored.
        </p>
      </div>
    );
  }

  // Scoped to the provider kind that was saved — see ProviderFields.
  const hasStoredSecret = config?.provider?.kind === form.providerKind;

  return (
    <div className="glass-card max-w-2xl">
      {/* noValidate: this form's validator mirrors the backend's rules exactly
          (see validateOrgEmailConfig), so native constraint validation would
          only add a second, browser-worded opinion that fires first and says
          something different. One authority, and it is the one that matches
          what the server will actually accept. */}
      <form onSubmit={handleSubmit} className="space-y-4" noValidate>
        <div>
          <h2 className="text-base font-medium text-foreground">
            Organization Email Baseline
          </h2>
          <p className="text-sm text-muted-foreground">
            The sender identity and provider used for verification and
            password-reset mail. Tenants may override parts of it.
          </p>
        </div>

        {!config && (
          <p className="text-sm text-muted-foreground">
            No email configuration is set for this organization yet — email
            delivery is disabled until one is saved.
          </p>
        )}

        <label className="flex items-center gap-2.5 cursor-pointer">
          <input
            type="checkbox"
            checked={form.enabled}
            onChange={(e) => setField("enabled", e.target.checked)}
            className="w-3.5 h-3.5 accent-cyan-400 cursor-pointer"
            disabled={!canWrite}
          />
          <span className="text-sm text-foreground/80">
            Email delivery enabled
          </span>
        </label>

        <fieldset disabled={!canWrite} className="space-y-4">
          <SenderFields
            form={form}
            setField={setField}
            idPrefix="org-email"
            required
          />
          <ProviderFields
            form={form}
            setField={setField}
            idPrefix="org-email"
            hasStoredSecret={hasStoredSecret}
          />
        </fieldset>

        <StatusLine error={error} success={success} />

        {canWrite && (
          <div className="flex items-center gap-2">
            <Button type="submit" disabled={saveMutation.isPending}>
              {saveMutation.isPending && (
                <Loader2 size={14} className="animate-spin" />
              )}
              Save Configuration
            </Button>
            {config && (
              <Button
                type="button"
                variant="ghost"
                onClick={() => setConfirmDelete(true)}
              >
                <Trash2 size={14} />
                Remove
              </Button>
            )}
          </div>
        )}
      </form>

      {canWrite && config && (
        <div className="mt-4 pt-4 border-t border-primary/10">
          <SelfTestButton send={() => emailConfigService.sendOrgTest(orgId)} />
        </div>
      )}

      <ConfirmDialog
        open={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        onConfirm={() => deleteMutation.mutate()}
        title="Remove email configuration?"
        description="Verification and password-reset mail will stop being delivered for this organization, and any tenant override will have no baseline to inherit from."
        confirmLabel="Remove"
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}

// ─── Tenant panel ─────────────────────────────────────────────────────────────

/** Which override fields the operator has explicitly turned on. */
type OverrideToggles = {
  sender: boolean;
  provider: boolean;
  enabled: boolean;
};

/**
 * The tenant-level override (FUNC-03 / D-13).
 *
 * Unlike the org baseline this is *partial*: an absent field inherits. That
 * distinction is the whole point of the endpoint, so it is made explicit in
 * the UI with per-group "override" switches rather than inferred from whether
 * a field happens to be blank — a blank From Name meaning "inherit" and a
 * blank one meaning "set it to empty" are different intentions, and guessing
 * between them silently changes what mail this tenant sends.
 */
export function TenantEmailConfigPanel({ tenantId }: { tenantId: string }) {
  const queryClient = useQueryClient();
  const { can } = usePermissions();
  const canWrite = can("email_config:write");

  const {
    data: override,
    isLoading,
    isError,
    error: loadError,
  } = useQuery({
    queryKey: ["tenant-email-config", tenantId],
    queryFn: () => emailConfigService.getTenantOverride(tenantId),
  });

  const [form, setForm] = useState<EmailFormState>(EMPTY_FORM);
  const [toggles, setToggles] = useState<OverrideToggles>({
    sender: false,
    provider: false,
    enabled: false,
  });
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const seeded = useRef(false);

  useEffect(() => {
    if (seeded.current || isLoading) return;
    seeded.current = true;
    if (!override) return;
    // Seeding an editable form from server data is a one-shot copy, not a derived
    // value: the `seeded` guard is what stops a background refetch from
    // overwriting edits in progress, and it is re-armed by the delete handler so
    // the form re-seeds from whatever the server reports next. Deriving during
    // render instead would re-seed from the stale query result the moment the
    // guard is re-armed, before the refetch lands.
    // oxlint-disable-next-line react/set-state-in-effect
    setToggles({
      sender:
        override.from_name !== undefined ||
        override.from_email !== undefined ||
        override.reply_to !== undefined,
      provider: override.provider !== undefined,
      enabled: override.enabled !== undefined,
    });
    setForm(
      formFromProvider(
        {
          ...EMPTY_FORM,
          enabled: override.enabled ?? EMPTY_FORM.enabled,
          fromName: override.from_name ?? "",
          fromEmail: override.from_email ?? "",
          // `null` is a deliberate "no reply-to", distinct from `undefined`
          // (inherit); both render as an empty input, and the sender-override
          // toggle is what tells them apart on save.
          replyTo: override.reply_to ?? "",
        },
        override.provider
      )
    );
  }, [override, isLoading]);

  function setField<K extends keyof EmailFormState>(
    k: K,
    v: EmailFormState[K]
  ) {
    setForm((prev) => ({ ...prev, [k]: v }));
    setSuccess(false);
  }

  const saveMutation = useMutation({
    mutationFn: (payload: EmailConfigOverride) =>
      emailConfigService.setTenantOverride(tenantId, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["tenant-email-config", tenantId],
      });
      setError("");
      setSuccess(true);
      setForm((prev) => ({ ...prev, smtpPassword: "", apiKey: "" }));
    },
    onError: (err: unknown) =>
      setError(
        err instanceof Error ? err.message : "Failed to save email override."
      ),
  });

  const deleteMutation = useMutation({
    mutationFn: () => emailConfigService.deleteTenantOverride(tenantId),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["tenant-email-config", tenantId],
      });
      setConfirmDelete(false);
      seeded.current = false;
      setForm(EMPTY_FORM);
      setToggles({ sender: false, provider: false, enabled: false });
      setError("");
    },
    onError: (err: unknown) => {
      setConfirmDelete(false);
      setError(
        err instanceof Error ? err.message : "Failed to remove email override."
      );
    },
  });

  function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");

    const payload: EmailConfigOverride = {};
    if (toggles.enabled) payload.enabled = form.enabled;
    if (toggles.sender) {
      if (!form.fromName.trim()) {
        setError("From name must not be empty when overriding the sender.");
        return;
      }
      if (!form.fromEmail.trim() || !form.fromEmail.includes("@")) {
        setError("From address must be a valid email address.");
        return;
      }
      const replyTo = form.replyTo.trim();
      if (replyTo && !replyTo.includes("@")) {
        setError("Reply-to must be a valid email address.");
        return;
      }
      payload.from_name = form.fromName.trim();
      payload.from_email = form.fromEmail.trim();
      // Schema v43 gave the tenant row a reply-to of its own, plus the flag
      // that separates "clear the organization's reply-to" (null) from
      // "inherit it" (field absent). An empty box under an active sender
      // override means the former.
      payload.reply_to = replyTo || null;
    }
    if (toggles.provider) {
      if (form.providerKind === "smtp") {
        if (!form.smtpHost.trim()) {
          setError("SMTP host must not be empty.");
          return;
        }
        if (!(Number.parseInt(form.smtpPort, 10) > 0)) {
          setError("SMTP port must be greater than 0.");
          return;
        }
      }
      payload.provider = providerFromForm(form);
    }

    saveMutation.mutate(payload);
  }

  if (isLoading) {
    return (
      <div className="glass-card animate-pulse space-y-3" aria-busy="true">
        <div className="h-4 bg-white/10 rounded w-1/3" />
        <div className="h-4 bg-white/10 rounded w-1/2" />
      </div>
    );
  }

  // As in the org panel: a failed load must not render as "nothing is
  // overridden". This is also what a cross-tenant view looks like — the
  // endpoint enforces `tenant_id == user.tenant_id` on top of the permission,
  // so viewing a sibling tenant 403s here rather than showing empty toggles.
  if (isError) {
    return (
      <div className="glass-card max-w-2xl">
        <p role="alert" className="text-sm text-destructive">
          Could not load this tenant's email overrides
          {loadError instanceof Error ? `: ${loadError.message}` : "."} Email
          configuration is readable only for your own tenant.
        </p>
      </div>
    );
  }

  return (
    <div className="glass-card max-w-2xl">
      {/* noValidate: this form's validator mirrors the backend's rules exactly
          (see validateOrgEmailConfig), so native constraint validation would
          only add a second, browser-worded opinion that fires first and says
          something different. One authority, and it is the one that matches
          what the server will actually accept. */}
      <form onSubmit={handleSubmit} className="space-y-4" noValidate>
        <div>
          <h2 className="text-base font-medium text-foreground">
            Email Overrides
          </h2>
          <p className="text-sm text-muted-foreground">
            Anything left un-overridden is inherited from the organization's
            email baseline.
          </p>
        </div>

        <fieldset disabled={!canWrite} className="space-y-4">
          <label className="flex items-center gap-2.5 cursor-pointer">
            <input
              type="checkbox"
              checked={toggles.enabled}
              onChange={(e) =>
                setToggles((t) => ({ ...t, enabled: e.target.checked }))
              }
              className="w-3.5 h-3.5 accent-cyan-400 cursor-pointer"
            />
            <span className="text-sm text-foreground/80">
              Override delivery on/off
            </span>
          </label>
          {toggles.enabled && (
            <label className="ml-6 flex items-center gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(e) => setField("enabled", e.target.checked)}
                className="w-3.5 h-3.5 accent-cyan-400 cursor-pointer"
              />
              <span className="text-sm text-foreground/80">
                Email delivery enabled for this tenant
              </span>
            </label>
          )}

          <label className="flex items-center gap-2.5 cursor-pointer">
            <input
              type="checkbox"
              checked={toggles.sender}
              onChange={(e) =>
                setToggles((t) => ({ ...t, sender: e.target.checked }))
              }
              className="w-3.5 h-3.5 accent-cyan-400 cursor-pointer"
            />
            <span className="text-sm text-foreground/80">
              Override sender identity
            </span>
          </label>
          {toggles.sender && (
            <div className="ml-6 space-y-4">
              <SenderFields
                form={form}
                setField={setField}
                idPrefix="tenant-email"
                required
                showReplyTo
              />
              <p className="text-xs text-muted-foreground">
                Leaving reply-to empty clears the organization's reply-to for
                this tenant rather than inheriting it. To inherit it again,
                turn off this sender override.
              </p>
            </div>
          )}

          <label className="flex items-center gap-2.5 cursor-pointer">
            <input
              type="checkbox"
              checked={toggles.provider}
              onChange={(e) =>
                setToggles((t) => ({ ...t, provider: e.target.checked }))
              }
              className="w-3.5 h-3.5 accent-cyan-400 cursor-pointer"
            />
            <span className="text-sm text-foreground/80">
              Override provider
            </span>
          </label>
          {toggles.provider && (
            <div className="ml-6 space-y-4">
              <p className="text-xs text-muted-foreground">
                A provider override replaces the organization's provider
                outright — there is no partial merge within a provider, so
                every field below must be filled in.
              </p>
              <ProviderFields
                form={form}
                setField={setField}
                idPrefix="tenant-email"
                hasStoredSecret={
                  override?.provider?.kind === form.providerKind
                }
              />
            </div>
          )}
        </fieldset>

        <StatusLine error={error} success={success} />

        {canWrite && (
          <div className="flex items-center gap-2">
            <Button type="submit" disabled={saveMutation.isPending}>
              {saveMutation.isPending && (
                <Loader2 size={14} className="animate-spin" />
              )}
              Save Overrides
            </Button>
            {override && (
              <Button
                type="button"
                variant="ghost"
                onClick={() => setConfirmDelete(true)}
              >
                <Trash2 size={14} />
                Clear All
              </Button>
            )}
          </div>
        )}
      </form>

      {canWrite && (
        <div className="mt-4 pt-4 border-t border-primary/10 space-y-1">
          <SelfTestButton
            send={() => emailConfigService.sendTenantTest(tenantId)}
          />
          <p className="text-xs text-muted-foreground">
            Sends through this tenant's effective configuration — its own
            overrides where set, the organization's baseline everywhere else.
          </p>
        </div>
      )}

      <ConfirmDialog
        open={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        onConfirm={() => deleteMutation.mutate()}
        title="Clear email overrides?"
        description="This tenant will fall back entirely to the organization's email baseline."
        confirmLabel="Clear overrides"
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}
