import { useState, useMemo } from "react";
import { Link } from "react-router";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Settings,
  Shield,
  Clock,
  Smartphone,
  Bell,
  Fingerprint,
  KeyRound,
  Pencil,
  X,
  Loader2,
  AlertCircle,
  CheckCircle2,
  ChevronRight,
  UserPlus,
} from "lucide-react";
import {
  settingsService,
  validateDcrPolicy,
  DEFAULT_DCR_MAX_CLIENTS,
  DEFAULT_DCR_UNUSED_CLIENT_TTL_DAYS,
  type SecuritySettings,
  type TenantSettingsOverride,
  type WebauthnUserVerification,
  type DynamicRegistrationMode,
} from "@/services/settings";
import {
  opaqueRelaxationWarning,
  readOpaquePolicy,
  type OpaqueKsf,
  type OpaqueMode,
  type OpaqueSuite,
} from "@/services/opaquePolicy";
import {
  OpaquePolicyFields,
  OpaquePolicySummary,
} from "@/components/OpaquePolicyFields";
import { getApiErrorMessage } from "@/lib/apiError";
import { PageHeader } from "@/components/PageHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";

// ─── Flat editable view-model (minutes where presented as minutes) ────────────
// The backend stores token/lockout/mfa durations in SECONDS. We present the
// long-lived ones in friendlier units (minutes/days) and convert on save.
// Every field here maps 1:1 to a backend SecuritySettings/TenantSettingsOverride
// field — no invented keys.

interface SettingsForm {
  // Password
  min_length: number;
  require_uppercase: boolean;
  require_lowercase: boolean;
  require_digits: boolean;
  require_symbols: boolean;
  password_history_count: number;
  hibp_check_enabled: boolean;
  // MFA
  mfa_enforced: boolean;
  mfa_challenge_lifetime_min: number; // backend: mfa_challenge_lifetime_secs
  // Lockout
  max_failed_login_attempts: number;
  lockout_duration_min: number; // backend: lockout_duration_secs
  // Token
  access_token_lifetime_min: number; // backend: access_token_lifetime_secs
  refresh_token_lifetime_days: number; // backend: refresh_token_lifetime_secs
  // Email
  email_verification_required: boolean;
  // Certificate
  default_cert_validity_days: number;
  // Notification
  admin_notifications_enabled: boolean;
  // OPAQUE
  opaque_mode: OpaqueMode;
  opaque_suite: OpaqueSuite;
  opaque_ksf: OpaqueKsf;
  // WebAuthn
  webauthn_user_verification: WebauthnUserVerification;
  // T21.4 — Dynamic client registration (RFC 7591)
  dynamic_registration: DynamicRegistrationMode;
  dcr_allowed_scopes: string[];
  dcr_allowed_redirect_hosts: string[];
  external_client_allowed_resources: string[];
  dcr_max_clients: number;
  dcr_unused_client_ttl_days: number;
}

/** `"a\nb\n  \nc"` → `["a", "b", "c"]` — one entry per non-blank line. */
function parseLines(raw: string): string[] {
  return raw
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * What each value actually does to a security key, in the terms an admin cares
 * about. Named rather than inlined so the edit and read-only views cannot drift.
 *
 * The passwordless caveat is stated on every value because it is the one thing
 * this control does *not* govern: usernameless sign-in always requires user
 * verification, since there the key is the only factor.
 */
const WEBAUTHN_UV_HELP: Record<WebauthnUserVerification, string> = {
  discouraged:
    "Security keys enrol without a PIN prompt. Appropriate only where the key is always a second factor behind a password.",
  preferred:
    "A PIN is requested when the key supports one and accepted either way, so a YubiKey with no PIN configured still enrols. Whether verification happened is recorded on the credential.",
  required:
    "A key that cannot verify its user is refused at enrolment — this excludes every security key with no PIN configured.",
};

const SECS_PER_MIN = 60;
const SECS_PER_DAY = 86_400;

function toForm(s: SecuritySettings): SettingsForm {
  return {
    min_length: s.password.min_length,
    require_uppercase: s.password.require_uppercase,
    require_lowercase: s.password.require_lowercase,
    require_digits: s.password.require_digits,
    require_symbols: s.password.require_symbols,
    password_history_count: s.password.password_history_count,
    hibp_check_enabled: s.password.hibp_check_enabled,
    mfa_enforced: s.mfa.mfa_enforced,
    mfa_challenge_lifetime_min: Math.round(
      s.mfa.mfa_challenge_lifetime_secs / SECS_PER_MIN
    ),
    max_failed_login_attempts: s.lockout.max_failed_login_attempts,
    lockout_duration_min: Math.round(
      s.lockout.lockout_duration_secs / SECS_PER_MIN
    ),
    access_token_lifetime_min: Math.round(
      s.token.access_token_lifetime_secs / SECS_PER_MIN
    ),
    refresh_token_lifetime_days: Math.round(
      s.token.refresh_token_lifetime_secs / SECS_PER_DAY
    ),
    email_verification_required: s.email.email_verification_required,
    default_cert_validity_days: s.certificate.default_cert_validity_days,
    admin_notifications_enabled: s.notification.admin_notifications_enabled,
    // Optional on the wire so a server older than the field still types: fall
    // back to the same `preferred` that server would apply anyway.
    webauthn_user_verification:
      s.webauthn?.webauthn_user_verification ?? "preferred",
    ...readOpaquePolicy(s),
    // T21.4 — optional on the wire for the same reason as `webauthn`; falls
    // back to the server's own defaults (I1).
    dynamic_registration: s.oidc?.dynamic_registration ?? "disabled",
    dcr_allowed_scopes: s.oidc?.dcr_allowed_scopes ?? [],
    dcr_allowed_redirect_hosts: s.oidc?.dcr_allowed_redirect_hosts ?? [],
    external_client_allowed_resources:
      s.oidc?.external_client_allowed_resources ?? [],
    dcr_max_clients: s.oidc?.dcr_max_clients ?? DEFAULT_DCR_MAX_CLIENTS,
    dcr_unused_client_ttl_days:
      s.oidc?.dcr_unused_client_ttl_days ?? DEFAULT_DCR_UNUSED_CLIENT_TTL_DAYS,
  };
}

/** Convert the full form into a flat TenantSettingsOverride (seconds). */
function toOverride(f: SettingsForm): TenantSettingsOverride {
  return {
    min_length: f.min_length,
    require_uppercase: f.require_uppercase,
    require_lowercase: f.require_lowercase,
    require_digits: f.require_digits,
    require_symbols: f.require_symbols,
    password_history_count: f.password_history_count,
    hibp_check_enabled: f.hibp_check_enabled,
    mfa_enforced: f.mfa_enforced,
    mfa_challenge_lifetime_secs: f.mfa_challenge_lifetime_min * SECS_PER_MIN,
    max_failed_login_attempts: f.max_failed_login_attempts,
    lockout_duration_secs: f.lockout_duration_min * SECS_PER_MIN,
    access_token_lifetime_secs: f.access_token_lifetime_min * SECS_PER_MIN,
    refresh_token_lifetime_secs: f.refresh_token_lifetime_days * SECS_PER_DAY,
    email_verification_required: f.email_verification_required,
    default_cert_validity_days: f.default_cert_validity_days,
    admin_notifications_enabled: f.admin_notifications_enabled,
    opaque_mode: f.opaque_mode,
    opaque_suite: f.opaque_suite,
    opaque_ksf: f.opaque_ksf,
    webauthn_user_verification: f.webauthn_user_verification,
    dynamic_registration: f.dynamic_registration,
    dcr_allowed_scopes: f.dcr_allowed_scopes,
    dcr_allowed_redirect_hosts: f.dcr_allowed_redirect_hosts,
    external_client_allowed_resources: f.external_client_allowed_resources,
    dcr_max_clients: f.dcr_max_clients,
    dcr_unused_client_ttl_days: f.dcr_unused_client_ttl_days,
  };
}

// ─── Toggle checkbox component ───────────────────────────────────────────────

interface ToggleFieldProps {
  id: string;
  label: string;
  description?: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (checked: boolean) => void;
}

function ToggleField({
  id,
  label,
  description,
  checked,
  disabled,
  onChange,
}: ToggleFieldProps) {
  return (
    <label
      htmlFor={id}
      className="flex items-start gap-3 cursor-pointer select-none"
    >
      <input
        id={id}
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-0.5 h-4 w-4 rounded border-primary/40 bg-white/5 text-primary focus:ring-primary/40 disabled:opacity-50 disabled:cursor-not-allowed"
      />
      <div className="min-w-0">
        <span className="text-sm text-foreground">{label}</span>
        {description && (
          <p className="text-xs text-muted-foreground mt-0.5">
            {description}
          </p>
        )}
      </div>
    </label>
  );
}

// ─── Display helpers ─────────────────────────────────────────────────────────

interface NumberDisplayProps {
  label: string;
  value: number;
  unit?: string;
}

function NumberDisplay({ label, value, unit }: NumberDisplayProps) {
  return (
    <div>
      <p className="text-xs text-muted-foreground uppercase tracking-wide mb-0.5">
        {label}
      </p>
      <p className="text-sm text-foreground font-medium">
        {value}
        {unit ? ` ${unit}` : ""}
      </p>
    </div>
  );
}

interface BooleanDisplayProps {
  label: string;
  enabled: boolean;
}

function BooleanDisplay({ label, enabled }: BooleanDisplayProps) {
  return (
    <div className="flex items-center gap-2">
      <p className="text-xs text-muted-foreground uppercase tracking-wide">
        {label}
      </p>
      <Badge variant={enabled ? "default" : "secondary"}>
        {enabled ? "Enabled" : "Disabled"}
      </Badge>
    </div>
  );
}

// ─── T21.4 — Dynamic Client Registration fields ────────────────────────────

interface DcrPolicyValue {
  dynamic_registration: DynamicRegistrationMode;
  dcr_allowed_scopes: string[];
  dcr_allowed_redirect_hosts: string[];
  external_client_allowed_resources: string[];
  dcr_max_clients: number;
  dcr_unused_client_ttl_days: number;
}

const DYNAMIC_REGISTRATION_LABELS: Record<DynamicRegistrationMode, string> = {
  disabled: "Disabled — no self-registered client may exist",
  initial_access_token: "Initial access token — requires an administrator-minted credential",
  anonymous: "Anonymous — open to anybody who can reach the endpoint",
};

const DYNAMIC_REGISTRATION_HELP: Record<DynamicRegistrationMode, string> = {
  disabled:
    "Every client is an administrator's decision. What every AXIAM deployment does today.",
  initial_access_token:
    "RFC 7591 §1.2's \"protected\" profile: the endpoint is open, the act is not. Mint a " +
    "single-use credential from the OAuth2 Clients page and hand it to the registering client.",
  anonymous:
    "RFC 7591 §1.2's \"open\" profile — the one MCP Inspector, Claude Code and VS Code use. " +
    "Refused while Allowed audiences is empty (D3, below).",
};

/**
 * Edit-mode fields for the T21.4 policy.
 *
 * `dcr_allowed_scopes`, `dcr_allowed_redirect_hosts` and
 * `external_client_allowed_resources` are free-text lists rather than
 * checkbox groups — unlike `OAUTH2_SCOPES` on the OAuth2 Clients page, this
 * policy is not bounded to a fixed catalog (a redirect host glob or a
 * resource URL is never one of a known few), so a textarea is the only
 * faithful editor, matching the "one per line" convention `redirect_uris` and
 * `allowed_resources` already use there.
 */
function DcrPolicyFields({
  value,
  onChange,
}: {
  value: DcrPolicyValue;
  onChange: (patch: Partial<DcrPolicyValue>) => void;
}) {
  const d3Empty =
    value.dynamic_registration === "anonymous" &&
    value.external_client_allowed_resources.length === 0;

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="dcr-mode">Self-registration mode</Label>
        <select
          id="dcr-mode"
          className="w-full rounded border border-white/20 bg-transparent px-3 py-2 text-sm"
          value={value.dynamic_registration}
          onChange={(e) =>
            onChange({
              dynamic_registration: e.target.value as DynamicRegistrationMode,
            })
          }
        >
          <option value="disabled">{DYNAMIC_REGISTRATION_LABELS.disabled}</option>
          <option value="initial_access_token">
            {DYNAMIC_REGISTRATION_LABELS.initial_access_token}
          </option>
          <option value="anonymous">{DYNAMIC_REGISTRATION_LABELS.anonymous}</option>
        </select>
        <p className="text-xs text-muted-foreground">
          {DYNAMIC_REGISTRATION_HELP[value.dynamic_registration]}
        </p>
      </div>

      <div className="space-y-2">
        <Label htmlFor="dcr-allowed-scopes">Allowed scopes</Label>
        <Textarea
          id="dcr-allowed-scopes"
          value={value.dcr_allowed_scopes.join("\n")}
          onChange={(e) =>
            onChange({ dcr_allowed_scopes: parseLines(e.target.value) })
          }
          placeholder={"openid\nprofile\nemail"}
          rows={3}
          className="font-mono"
          aria-label="Allowed scopes (one per line)"
        />
        <p className="text-xs text-muted-foreground">
          Scopes a self-registered client may ask for. One per line; empty
          means it gets none.{" "}
          <strong>
            <code>address</code> and <code>phone</code> may never appear
            here
          </strong>{" "}
          — both release personal data under a per-client consent record
          (W7), and a self-registered client already carries a forced consent
          record of its own (D4); two records in one namespace is a state
          this policy refuses to create. Register a client that needs them
          through <code>POST /oauth2-clients</code> instead.
        </p>
      </div>

      <div className="space-y-2">
        <Label htmlFor="dcr-allowed-redirect-hosts">
          Allowed redirect hosts
        </Label>
        <Textarea
          id="dcr-allowed-redirect-hosts"
          value={value.dcr_allowed_redirect_hosts.join("\n")}
          onChange={(e) =>
            onChange({
              dcr_allowed_redirect_hosts: parseLines(e.target.value),
            })
          }
          placeholder={"mcp.example.com\n*.example.com"}
          rows={2}
          className="font-mono"
          aria-label="Allowed redirect hosts (one per line)"
        />
        <p className="text-xs text-muted-foreground">
          Host globs a self-registered <code>redirect_uri</code> may point at
          (<code>*.example.com</code>, or <code>*</code> for any). Empty is
          fine: <code>127.0.0.1</code>, <code>localhost</code> and{" "}
          <code>[::1]</code> are always allowed regardless, since RFC 8252
          §7.3 loopback callbacks are how every desktop MCP client receives
          its callback.
        </p>
      </div>

      <div className="space-y-2">
        <Label htmlFor="dcr-allowed-resources">
          Allowed audiences (resource servers)
        </Label>
        <Textarea
          id="dcr-allowed-resources"
          value={value.external_client_allowed_resources.join("\n")}
          onChange={(e) =>
            onChange({
              external_client_allowed_resources: parseLines(e.target.value),
            })
          }
          placeholder="https://mcp.example.com/mcp"
          rows={2}
          className="font-mono"
          aria-label="Allowed audiences (one per line)"
        />
        <p className="text-xs text-muted-foreground">
          <strong>D3.</strong> The MCP servers (or other resource servers)
          this tenant fronts. A self-registered client cannot choose its own
          audiences — it inherits this list verbatim, so what a stranger can
          mint a token <em>for</em> is decided here, in advance, rather than
          by the registration request.
        </p>
        {d3Empty && (
          <p
            role="alert"
            className="flex items-center gap-2 p-2.5 rounded-md bg-destructive/10 border border-destructive/30 text-destructive text-xs"
          >
            <AlertCircle size={14} className="shrink-0" aria-hidden="true" />
            Anonymous registration cannot be saved while this list is empty:
            an empty list would leave a self-registered client able to obtain
            only the <code>axiam:user</code> tokens AXIAM's own APIs accept —
            an unauthenticated endpoint that mints clients able to ask for
            tokens against AXIAM itself. Name the MCP servers this tenant
            fronts first.
          </p>
        )}
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-2">
          <Label htmlFor="dcr-max-clients">Max self-registered clients</Label>
          <Input
            id="dcr-max-clients"
            type="number"
            min={1}
            value={value.dcr_max_clients}
            onChange={(e) =>
              onChange({ dcr_max_clients: Number(e.target.value) })
            }
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="dcr-unused-ttl">
            Unused-client sweep (days)
          </Label>
          <Input
            id="dcr-unused-ttl"
            type="number"
            min={0}
            value={value.dcr_unused_client_ttl_days}
            onChange={(e) =>
              onChange({ dcr_unused_client_ttl_days: Number(e.target.value) })
            }
          />
          <p className="text-xs text-muted-foreground">
            A self-registered client with no authorization for this many days
            is deleted. <code>0</code> disables the sweep for this tenant.
          </p>
        </div>
      </div>
    </div>
  );
}

/**
 * Read-mode summary. **I1** — while `dynamic_registration` is `disabled`
 * (the default), nothing beyond that fact is shown: an empty scopes/hosts
 * list and default counters would still be true, but rendering them invites
 * an operator to read significance into a policy that does nothing.
 */
function DcrPolicySummary({ value }: { value: DcrPolicyValue }) {
  if (value.dynamic_registration === "disabled") {
    return (
      <div className="flex items-center gap-2">
        <p className="text-xs text-muted-foreground uppercase tracking-wide">
          Self-registration
        </p>
        <Badge variant="secondary">Disabled</Badge>
      </div>
    );
  }

  const listOrNone = (items: string[]) =>
    items.length > 0 ? items.join(", ") : "none configured";

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <p className="text-xs text-muted-foreground uppercase tracking-wide">
          Self-registration
        </p>
        <Badge>{DYNAMIC_REGISTRATION_LABELS[value.dynamic_registration]}</Badge>
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <NumberDisplay
          label="Max self-registered clients"
          value={value.dcr_max_clients}
        />
        <NumberDisplay
          label="Unused-client sweep"
          value={value.dcr_unused_client_ttl_days}
          unit={value.dcr_unused_client_ttl_days === 0 ? "(disabled)" : "days"}
        />
      </div>
      <div className="space-y-2 text-sm">
        <p>
          <span className="text-muted-foreground">Allowed scopes: </span>
          {listOrNone(value.dcr_allowed_scopes)}
        </p>
        <p>
          <span className="text-muted-foreground">
            Allowed redirect hosts:{" "}
          </span>
          <span>{listOrNone(value.dcr_allowed_redirect_hosts)}</span>
          <span className="text-muted-foreground"> (loopback always allowed)</span>
        </p>
        <p>
          <span className="text-muted-foreground">
            Allowed audiences (D3):{" "}
          </span>
          {listOrNone(value.external_client_allowed_resources)}
        </p>
      </div>
    </div>
  );
}

// ─── SettingsPage ────────────────────────────────────────────────────────────

export function SettingsPage() {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [formOverrides, setFormOverrides] = useState<Partial<SettingsForm>>({});
  const [feedback, setFeedback] = useState<{
    type: "success" | "error";
    message: string;
  } | null>(null);

  const {
    data: settings,
    isLoading,
    error: loadError,
  } = useQuery({
    queryKey: ["system-settings"],
    queryFn: settingsService.getSettings,
  });

  // Derive form state from query data + local overrides (no useEffect needed).
  const form = useMemo<SettingsForm | null>(() => {
    if (!settings) return null;
    return { ...toForm(settings), ...formOverrides };
  }, [settings, formOverrides]);

  const updateMutation = useMutation({
    mutationFn: (payload: TenantSettingsOverride) =>
      settingsService.updateSettings(payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["system-settings"],
      });
      setFormOverrides({});
      setEditing(false);
      setFeedback({
        type: "success",
        message: "Settings saved successfully.",
      });
      setTimeout(() => setFeedback(null), 4000);
    },
    onError: (err: unknown) => {
      // The 400 from `validate_tenant_override` lists exactly which field was
      // below the org baseline; that text is the whole value of the response.
      setFeedback({
        type: "error",
        message: getApiErrorMessage(
          err,
          err instanceof Error
            ? err.message
            : "Failed to save settings. Please try again."
        ),
      });
    },
  });

  function setField<K extends keyof SettingsForm>(
    key: K,
    value: SettingsForm[K]
  ) {
    setFormOverrides((prev) => ({ ...prev, [key]: value }));
  }

  function handleSave() {
    if (!form) return;
    setFeedback(null);
    // T21.4 — both D3 and the sensitive-scope interlock are hard refusals on
    // the backend (400), not tighten-only advisories like OPAQUE/WebAuthn
    // above, so this blocks the save rather than merely warning.
    const dcrError = validateDcrPolicy(form);
    if (dcrError) {
      setFeedback({ type: "error", message: dcrError });
      return;
    }
    updateMutation.mutate(toOverride(form));
  }

  function handleCancel() {
    setFormOverrides({});
    setEditing(false);
    setFeedback(null);
  }

  function handleEdit() {
    setFeedback(null);
    setEditing(true);
  }

  // ── Loading state ────────────────────────────────────────────────────────

  if (isLoading || !form) {
    if (loadError) {
      // fall through to error block below
    } else {
      return (
        <div className="flex items-center justify-center py-24">
          <Loader2 className="animate-spin text-primary" size={32} />
        </div>
      );
    }
  }

  // ── Error state ──────────────────────────────────────────────────────────

  if (loadError || !form) {
    return (
      <div
        role="alert"
        className="flex items-center gap-2 p-4 rounded-md bg-destructive/10 border border-destructive/30 text-destructive text-sm"
      >
        <AlertCircle size={16} />
        <span>
          Failed to load system settings. Please refresh the page.
        </span>
      </div>
    );
  }

  const data = form;
  // The advisory compares against the *loaded effective* policy, which is the
  // only thing this endpoint exposes — the org baseline is not readable here.
  const effectiveOpaque = readOpaquePolicy(settings);

  // ── Render ───────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6 max-w-3xl">
      <PageHeader
        title="Settings"
        description="Configure tenant security policies. Values may only be made more restrictive than the organization baseline."
        action={
          !editing ? (
            <Button variant="outline" size="sm" onClick={handleEdit}>
              <Pencil size={14} aria-hidden="true" />
              Edit Settings
            </Button>
          ) : undefined
        }
      />

      {/* Feedback alert */}
      {feedback && (
        <div
          role="alert"
          className={
            feedback.type === "success"
              ? "flex items-center gap-2 p-3 rounded-md bg-emerald-400/10 border border-emerald-400/30 text-emerald-400 text-sm"
              : "flex items-center gap-2 p-3 rounded-md bg-destructive/10 border border-destructive/30 text-destructive text-sm"
          }
        >
          {feedback.type === "success" ? (
            <CheckCircle2 size={16} />
          ) : (
            <AlertCircle size={16} />
          )}
          <span>{feedback.message}</span>
        </div>
      )}

      {/* ── Password Policy ────────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <Shield size={18} className="text-primary" aria-hidden="true" />
            <CardTitle className="text-base">Password Policy</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          {editing ? (
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="min_length">Password minimum length</Label>
                <Input
                  id="min_length"
                  type="number"
                  min={8}
                  max={128}
                  value={data.min_length}
                  onChange={(e) =>
                    setField("min_length", Number(e.target.value))
                  }
                />
              </div>

              <ToggleField
                id="require_uppercase"
                label="Require uppercase letter"
                checked={data.require_uppercase}
                onChange={(v) => setField("require_uppercase", v)}
              />
              <ToggleField
                id="require_lowercase"
                label="Require lowercase letter"
                checked={data.require_lowercase}
                onChange={(v) => setField("require_lowercase", v)}
              />
              <ToggleField
                id="require_digits"
                label="Require digit"
                checked={data.require_digits}
                onChange={(v) => setField("require_digits", v)}
              />
              <ToggleField
                id="require_symbols"
                label="Require symbol"
                checked={data.require_symbols}
                onChange={(v) => setField("require_symbols", v)}
              />
              <ToggleField
                id="hibp_check_enabled"
                label="Check passwords against breach database (HIBP)"
                description="Reject passwords known to be compromised."
                checked={data.hibp_check_enabled}
                onChange={(v) => setField("hibp_check_enabled", v)}
              />

              <div className="space-y-2">
                <Label htmlFor="password_history_count">
                  Password history count
                </Label>
                <Input
                  id="password_history_count"
                  type="number"
                  min={0}
                  max={50}
                  value={data.password_history_count}
                  onChange={(e) =>
                    setField(
                      "password_history_count",
                      Number(e.target.value)
                    )
                  }
                />
              </div>
            </div>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2">
              <NumberDisplay
                label="Password minimum length"
                value={data.min_length}
                unit="characters"
              />
              <BooleanDisplay
                label="Require uppercase"
                enabled={data.require_uppercase}
              />
              <BooleanDisplay
                label="Require lowercase"
                enabled={data.require_lowercase}
              />
              <BooleanDisplay
                label="Require digit"
                enabled={data.require_digits}
              />
              <BooleanDisplay
                label="Require symbol"
                enabled={data.require_symbols}
              />
              <BooleanDisplay
                label="HIBP breach check"
                enabled={data.hibp_check_enabled}
              />
              <NumberDisplay
                label="Password history count"
                value={data.password_history_count}
                unit="passwords"
              />
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── Lockout & Tokens ───────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <Clock size={18} className="text-primary" aria-hidden="true" />
            <CardTitle className="text-base">Lockout & Tokens</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          {editing ? (
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="max_failed_login_attempts">
                  Max failed login attempts
                </Label>
                <Input
                  id="max_failed_login_attempts"
                  type="number"
                  min={1}
                  max={100}
                  value={data.max_failed_login_attempts}
                  onChange={(e) =>
                    setField(
                      "max_failed_login_attempts",
                      Number(e.target.value)
                    )
                  }
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="lockout_duration_min">
                  Account lockout duration (minutes)
                </Label>
                <Input
                  id="lockout_duration_min"
                  type="number"
                  min={1}
                  max={1440}
                  value={data.lockout_duration_min}
                  onChange={(e) =>
                    setField("lockout_duration_min", Number(e.target.value))
                  }
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="access_token_lifetime_min">
                  Access token lifetime (minutes)
                </Label>
                <Input
                  id="access_token_lifetime_min"
                  type="number"
                  min={1}
                  max={1440}
                  value={data.access_token_lifetime_min}
                  onChange={(e) =>
                    setField(
                      "access_token_lifetime_min",
                      Number(e.target.value)
                    )
                  }
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="refresh_token_lifetime_days">
                  Refresh token lifetime (days)
                </Label>
                <Input
                  id="refresh_token_lifetime_days"
                  type="number"
                  min={1}
                  max={365}
                  value={data.refresh_token_lifetime_days}
                  onChange={(e) =>
                    setField(
                      "refresh_token_lifetime_days",
                      Number(e.target.value)
                    )
                  }
                />
              </div>
            </div>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2">
              <NumberDisplay
                label="Max failed login attempts"
                value={data.max_failed_login_attempts}
                unit="attempts"
              />
              <NumberDisplay
                label="Account lockout duration"
                value={data.lockout_duration_min}
                unit="minutes"
              />
              <NumberDisplay
                label="Access token lifetime"
                value={data.access_token_lifetime_min}
                unit="minutes"
              />
              <NumberDisplay
                label="Refresh token lifetime"
                value={data.refresh_token_lifetime_days}
                unit="days"
              />
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── MFA Settings ───────────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <Smartphone size={18} className="text-primary" aria-hidden="true" />
            <CardTitle className="text-base">MFA Settings</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          {editing ? (
            <div className="space-y-4">
              <ToggleField
                id="mfa_enforced"
                label="Require MFA for all users"
                description="When enabled, users must configure at least one MFA method to access the system."
                checked={data.mfa_enforced}
                onChange={(v) => setField("mfa_enforced", v)}
              />
              <div className="space-y-2">
                <Label htmlFor="mfa_challenge_lifetime_min">
                  MFA challenge lifetime (minutes)
                </Label>
                <Input
                  id="mfa_challenge_lifetime_min"
                  type="number"
                  min={1}
                  max={60}
                  value={data.mfa_challenge_lifetime_min}
                  onChange={(e) =>
                    setField(
                      "mfa_challenge_lifetime_min",
                      Number(e.target.value)
                    )
                  }
                />
              </div>
            </div>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2">
              <BooleanDisplay label="MFA required" enabled={data.mfa_enforced} />
              <NumberDisplay
                label="MFA challenge lifetime"
                value={data.mfa_challenge_lifetime_min}
                unit="minutes"
              />
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── OPAQUE (RFC 9807) ──────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <KeyRound size={18} className="text-primary" aria-hidden="true" />
            <CardTitle className="text-base">OPAQUE (RFC 9807)</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground mb-4">
            An augmented PAKE: the password never leaves the browser, not even
            over TLS. This tenant inherits its organization's baseline and may
            only tighten it.
          </p>
          {editing ? (
            <OpaquePolicyFields
              idPrefix="tenant"
              value={{
                opaque_mode: data.opaque_mode,
                opaque_suite: data.opaque_suite,
                opaque_ksf: data.opaque_ksf,
              }}
              onChange={(next) =>
                setFormOverrides((prev) => ({ ...prev, ...next }))
              }
              warning={opaqueRelaxationWarning(
                {
                  opaque_mode: data.opaque_mode,
                  opaque_suite: data.opaque_suite,
                  opaque_ksf: data.opaque_ksf,
                },
                effectiveOpaque
              )}
            />
          ) : (
            <OpaquePolicySummary
              value={{
                opaque_mode: data.opaque_mode,
                opaque_suite: data.opaque_suite,
                opaque_ksf: data.opaque_ksf,
              }}
            />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <KeyRound size={18} className="text-primary" aria-hidden="true" />
            <CardTitle className="text-base">WebAuthn</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground mb-4">
            How hard an authenticator must prove <em>who</em> is present. This
            tenant inherits its organization's baseline and may only tighten it.
          </p>
          {editing ? (
            <div className="space-y-2">
              <Label htmlFor="tenant-webauthn-uv">User verification</Label>
              <select
                id="tenant-webauthn-uv"
                className="w-full rounded border border-white/20 bg-transparent px-3 py-2 text-sm"
                value={data.webauthn_user_verification}
                onChange={(e) =>
                  setFormOverrides((prev) => ({
                    ...prev,
                    webauthn_user_verification: e.target
                      .value as WebauthnUserVerification,
                  }))
                }
              >
                <option value="discouraged">
                  Discouraged — do not ask for a PIN
                </option>
                <option value="preferred">
                  Preferred — ask, accept either way (default)
                </option>
                <option value="required">
                  Required — refuse keys that cannot verify
                </option>
              </select>
              <p className="text-xs text-muted-foreground">
                {WEBAUTHN_UV_HELP[data.webauthn_user_verification]}
              </p>
            </div>
          ) : (
            <div className="space-y-1">
              <p className="text-sm">
                User verification:{" "}
                <span className="font-medium">
                  {data.webauthn_user_verification}
                </span>
              </p>
              <p className="text-xs text-muted-foreground">
                {WEBAUTHN_UV_HELP[data.webauthn_user_verification]}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── Email & Certificates & Notifications ───────────────────────── */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <Bell size={18} className="text-primary" aria-hidden="true" />
            <CardTitle className="text-base">
              Email, Certificates & Notifications
            </CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          {editing ? (
            <div className="space-y-4">
              <ToggleField
                id="email_verification_required"
                label="Require email verification"
                description="Users must verify their email address before full access."
                checked={data.email_verification_required}
                onChange={(v) => setField("email_verification_required", v)}
              />
              <div className="space-y-2">
                <Label htmlFor="default_cert_validity_days">
                  Default certificate validity (days)
                </Label>
                <Input
                  id="default_cert_validity_days"
                  type="number"
                  min={1}
                  max={3650}
                  value={data.default_cert_validity_days}
                  onChange={(e) =>
                    setField(
                      "default_cert_validity_days",
                      Number(e.target.value)
                    )
                  }
                />
              </div>
              <ToggleField
                id="admin_notifications_enabled"
                label="Admin notifications"
                description="Send security and system event notifications to admins."
                checked={data.admin_notifications_enabled}
                onChange={(v) => setField("admin_notifications_enabled", v)}
              />
            </div>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2">
              <BooleanDisplay
                label="Email verification required"
                enabled={data.email_verification_required}
              />
              <NumberDisplay
                label="Default certificate validity"
                value={data.default_cert_validity_days}
                unit="days"
              />
              <BooleanDisplay
                label="Admin notifications"
                enabled={data.admin_notifications_enabled}
              />
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── WebAuthn Attestation Policy (X3) ───────────────────────────── */}
      {/* This has its own admin-permission pair (webauthn_policy:read/write,
          deliberately not settings:get/update — see the handler module's
          docs) and its own page: mode, AAGUID allow/block lists, the
          compliance report, and MDS status don't fit this page's flat
          toggle-grid shape, and an admin with settings:update should not
          automatically be able to change which security keys a tenant
          accepts. */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <Fingerprint size={18} className="text-primary" aria-hidden="true" />
            <CardTitle className="text-base">
              WebAuthn Attestation Policy
            </CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground mb-4">
            Restrict which security key or passkey models may register,
            backed by the FIDO Metadata Service. Default is unchanged: every
            authenticator is accepted until this is opted into.
          </p>
          <Link
            to="/settings/webauthn-attestation-policy"
            className="inline-flex items-center gap-1 text-sm text-primary hover:underline"
          >
            Manage attestation policy
            <ChevronRight size={14} aria-hidden="true" />
          </Link>
        </CardContent>
      </Card>

      {/* ── Dynamic Client Registration (T21.4, RFC 7591) ──────────────── */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <UserPlus size={18} className="text-primary" aria-hidden="true" />
            <CardTitle className="text-base">
              Dynamic Client Registration
            </CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground mb-4">
            Let a client register itself at <code>POST /oauth2/register</code>{" "}
            (RFC 7591) instead of an administrator creating it. Off by
            default: this tenant registers no client it did not create, and
            the endpoint answers <code>403</code> on every request. This
            tenant inherits its organization's baseline and may only tighten
            it.
          </p>
          {editing ? (
            <DcrPolicyFields
              value={{
                dynamic_registration: data.dynamic_registration,
                dcr_allowed_scopes: data.dcr_allowed_scopes,
                dcr_allowed_redirect_hosts: data.dcr_allowed_redirect_hosts,
                external_client_allowed_resources:
                  data.external_client_allowed_resources,
                dcr_max_clients: data.dcr_max_clients,
                dcr_unused_client_ttl_days: data.dcr_unused_client_ttl_days,
              }}
              onChange={(next) =>
                setFormOverrides((prev) => ({ ...prev, ...next }))
              }
            />
          ) : (
            <DcrPolicySummary
              value={{
                dynamic_registration: data.dynamic_registration,
                dcr_allowed_scopes: data.dcr_allowed_scopes,
                dcr_allowed_redirect_hosts: data.dcr_allowed_redirect_hosts,
                external_client_allowed_resources:
                  data.external_client_allowed_resources,
                dcr_max_clients: data.dcr_max_clients,
                dcr_unused_client_ttl_days: data.dcr_unused_client_ttl_days,
              }}
            />
          )}
        </CardContent>
      </Card>

      {/* ── Action bar (edit mode) ─────────────────────────────────────── */}
      {editing && (
        <div className="flex gap-3 pt-2">
          <Button
            onClick={handleSave}
            disabled={updateMutation.isPending}
            size="sm"
          >
            {updateMutation.isPending ? (
              <>
                <Loader2
                  size={14}
                  className="animate-spin"
                  aria-hidden="true"
                />
                Saving...
              </>
            ) : (
              <>
                <Settings size={14} aria-hidden="true" />
                Save Settings
              </>
            )}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleCancel}
            disabled={updateMutation.isPending}
          >
            <X size={14} aria-hidden="true" />
            Cancel
          </Button>
        </div>
      )}
    </div>
  );
}
