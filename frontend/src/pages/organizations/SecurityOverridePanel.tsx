import { useEffect, useRef, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Loader2, Trash2 } from "lucide-react";

import {
  settingsService,
  type TenantSettingsOverride,
} from "@/services/settings";
import {
  MAX_DELETION_GRACE_PERIOD_DAYS,
  type SecuritySettings,
} from "@/services/organizations";
import { readOpaquePolicy, type OpaquePolicy } from "@/services/opaquePolicy";
import { OpaquePolicyFields } from "@/components/OpaquePolicyFields";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { usePermissions } from "@/hooks/usePermissions";
import { getApiErrorMessage } from "@/lib/apiError";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

// ─── Which groups a tenant can override ───────────────────────────────────────
//
// Grouped rather than per-field for the same reason the email panel is: a
// half-overridden password policy is not a thing an operator means. Checking
// "Password policy" takes over the whole block; leaving it unchecked inherits
// the whole block, and later changes to the organization's baseline keep
// cascading through.
//
// Every group here is tighten-only server-side (`validate_tenant_override` in
// `crates/axiam-core/src/models/settings.rs`) and the direction differs per
// field — a longer minimum length is more restrictive, a shorter token lifetime
// is. Rather than reimplement that table here and let the two drift, the panel
// states the direction next to each control and lets the server be the one that
// refuses; a rejection comes back as a message naming the offending field.

interface OverrideGroups {
  password: boolean;
  mfa: boolean;
  lockout: boolean;
  token: boolean;
  emailVerification: boolean;
  certificate: boolean;
  notification: boolean;
  opaque: boolean;
  privacy: boolean;
}

const NO_GROUPS: OverrideGroups = {
  password: false,
  mfa: false,
  lockout: false,
  token: false,
  emailVerification: false,
  certificate: false,
  notification: false,
  opaque: false,
  privacy: false,
};

/** The panel's editable state — flat, seconds where the backend uses seconds. */
interface FormState {
  min_length: number;
  require_uppercase: boolean;
  require_lowercase: boolean;
  require_digits: boolean;
  require_symbols: boolean;
  password_history_count: number;
  hibp_check_enabled: boolean;
  mfa_enforced: boolean;
  mfa_challenge_lifetime_secs: number;
  max_failed_login_attempts: number;
  lockout_duration_secs: number;
  lockout_backoff_multiplier: number;
  max_lockout_duration_secs: number;
  access_token_lifetime_secs: number;
  refresh_token_lifetime_secs: number;
  email_verification_required: boolean;
  email_verification_grace_period_hours: number;
  default_cert_validity_days: number;
  max_cert_validity_days: number;
  admin_notifications_enabled: boolean;
  opaque: OpaquePolicy;
  deletion_grace_period_days: number;
}

/** Seed the form from the effective settings, so an un-overridden group opens
 *  showing what the tenant currently gets rather than an arbitrary default. */
function formFromEffective(s: SecuritySettings): FormState {
  return {
    min_length: s.password.min_length,
    require_uppercase: s.password.require_uppercase,
    require_lowercase: s.password.require_lowercase,
    require_digits: s.password.require_digits,
    require_symbols: s.password.require_symbols,
    password_history_count: s.password.password_history_count,
    hibp_check_enabled: s.password.hibp_check_enabled,
    mfa_enforced: s.mfa.mfa_enforced,
    mfa_challenge_lifetime_secs: s.mfa.mfa_challenge_lifetime_secs,
    max_failed_login_attempts: s.lockout.max_failed_login_attempts,
    lockout_duration_secs: s.lockout.lockout_duration_secs,
    lockout_backoff_multiplier: s.lockout.lockout_backoff_multiplier,
    max_lockout_duration_secs: s.lockout.max_lockout_duration_secs,
    access_token_lifetime_secs: s.token.access_token_lifetime_secs,
    refresh_token_lifetime_secs: s.token.refresh_token_lifetime_secs,
    email_verification_required: s.email.email_verification_required,
    email_verification_grace_period_hours:
      s.email.email_verification_grace_period_hours,
    default_cert_validity_days: s.certificate.default_cert_validity_days,
    max_cert_validity_days: s.certificate.max_cert_validity_days,
    admin_notifications_enabled: s.notification.admin_notifications_enabled,
    opaque: readOpaquePolicy(s),
    deletion_grace_period_days:
      s.privacy?.deletion_grace_period_days ?? 30,
  };
}

/** Which groups the stored override actually touches. */
function groupsFromOverride(o: TenantSettingsOverride): OverrideGroups {
  return {
    password:
      o.min_length !== undefined ||
      o.require_uppercase !== undefined ||
      o.require_lowercase !== undefined ||
      o.require_digits !== undefined ||
      o.require_symbols !== undefined ||
      o.password_history_count !== undefined ||
      o.hibp_check_enabled !== undefined,
    mfa:
      o.mfa_enforced !== undefined ||
      o.mfa_challenge_lifetime_secs !== undefined,
    lockout:
      o.max_failed_login_attempts !== undefined ||
      o.lockout_duration_secs !== undefined ||
      o.lockout_backoff_multiplier !== undefined ||
      o.max_lockout_duration_secs !== undefined,
    token:
      o.access_token_lifetime_secs !== undefined ||
      o.refresh_token_lifetime_secs !== undefined,
    emailVerification:
      o.email_verification_required !== undefined ||
      o.email_verification_grace_period_hours !== undefined,
    certificate:
      o.default_cert_validity_days !== undefined ||
      o.max_cert_validity_days !== undefined,
    notification: o.admin_notifications_enabled !== undefined,
    opaque:
      o.opaque_mode !== undefined ||
      o.opaque_suite !== undefined ||
      o.opaque_ksf !== undefined,
    privacy: o.deletion_grace_period_days !== undefined,
  };
}

/** Build the sparse payload: only the checked groups' fields are sent. */
function overrideFromForm(
  form: FormState,
  groups: OverrideGroups
): TenantSettingsOverride {
  const out: TenantSettingsOverride = {};
  if (groups.password) {
    out.min_length = form.min_length;
    out.require_uppercase = form.require_uppercase;
    out.require_lowercase = form.require_lowercase;
    out.require_digits = form.require_digits;
    out.require_symbols = form.require_symbols;
    out.password_history_count = form.password_history_count;
    out.hibp_check_enabled = form.hibp_check_enabled;
  }
  if (groups.mfa) {
    out.mfa_enforced = form.mfa_enforced;
    out.mfa_challenge_lifetime_secs = form.mfa_challenge_lifetime_secs;
  }
  if (groups.lockout) {
    out.max_failed_login_attempts = form.max_failed_login_attempts;
    out.lockout_duration_secs = form.lockout_duration_secs;
    out.lockout_backoff_multiplier = form.lockout_backoff_multiplier;
    out.max_lockout_duration_secs = form.max_lockout_duration_secs;
  }
  if (groups.token) {
    out.access_token_lifetime_secs = form.access_token_lifetime_secs;
    out.refresh_token_lifetime_secs = form.refresh_token_lifetime_secs;
  }
  if (groups.emailVerification) {
    out.email_verification_required = form.email_verification_required;
    out.email_verification_grace_period_hours =
      form.email_verification_grace_period_hours;
  }
  if (groups.certificate) {
    out.default_cert_validity_days = form.default_cert_validity_days;
    out.max_cert_validity_days = form.max_cert_validity_days;
  }
  if (groups.notification) {
    out.admin_notifications_enabled = form.admin_notifications_enabled;
  }
  if (groups.opaque) {
    out.opaque_mode = form.opaque.opaque_mode;
    out.opaque_suite = form.opaque.opaque_suite;
    out.opaque_ksf = form.opaque.opaque_ksf;
  }
  if (groups.privacy) {
    out.deletion_grace_period_days = form.deletion_grace_period_days;
  }
  return out;
}

// ─── Small building blocks ────────────────────────────────────────────────────

function GroupToggle({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="flex items-center gap-2.5 cursor-pointer">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="w-3.5 h-3.5 accent-cyan-400 cursor-pointer"
      />
      <span className="text-sm text-foreground/80">{label}</span>
    </label>
  );
}

function NumField({
  id,
  label,
  hint,
  value,
  min,
  max,
  step,
  onChange,
}: {
  id: string;
  label: string;
  hint?: string;
  value: number;
  min?: number;
  max?: number;
  step?: number;
  onChange: (v: number) => void;
}) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        type="number"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
      />
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

function BoolField({
  id,
  label,
  checked,
  onChange,
}: {
  id: string;
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label htmlFor={id} className="flex items-center gap-2.5 cursor-pointer">
      <input
        id={id}
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="w-3.5 h-3.5 accent-cyan-400 cursor-pointer"
      />
      <span className="text-sm text-foreground/80">{label}</span>
    </label>
  );
}

// ─── The panel ────────────────────────────────────────────────────────────────

/**
 * The tenant's security overrides on the organization's baseline.
 *
 * The sibling of `TenantEmailConfigPanel`, and the answer to a tenant detail
 * page that offered email overrides and nothing else — so the password policy,
 * MFA, lockout, token, certificate and OPAQUE settings a tenant is entitled to
 * tighten were reachable only from `/settings`, which acts on whichever tenant
 * the caller happens to be signed in to and never names it.
 */
export function TenantSecurityOverridePanel({
  tenantId,
}: {
  tenantId: string;
}) {
  const queryClient = useQueryClient();
  const { can } = usePermissions();
  const canWrite = can("settings:update");

  const {
    data: override,
    isLoading: overrideLoading,
    isError,
    error: loadError,
  } = useQuery({
    queryKey: ["tenant-settings-override", tenantId],
    queryFn: () => settingsService.getTenantOverride(tenantId),
  });

  // The merged view, used only to seed a group the operator has just opened.
  const { data: effective, isLoading: effectiveLoading } = useQuery({
    queryKey: ["settings"],
    queryFn: () => settingsService.getSettings(),
  });

  const [form, setForm] = useState<FormState | null>(null);
  const [groups, setGroups] = useState<OverrideGroups>(NO_GROUPS);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);
  const [confirmClear, setConfirmClear] = useState(false);
  const seeded = useRef(false);

  useEffect(() => {
    if (seeded.current || overrideLoading || effectiveLoading) return;
    if (!effective) return;
    seeded.current = true;
    setForm(formFromEffective(effective));
    setGroups(override ? groupsFromOverride(override) : NO_GROUPS);
  }, [override, effective, overrideLoading, effectiveLoading]);

  function setField<K extends keyof FormState>(k: K, v: FormState[K]) {
    setForm((prev) => (prev ? { ...prev, [k]: v } : prev));
    setSuccess(false);
  }

  const saveMutation = useMutation({
    mutationFn: (payload: TenantSettingsOverride) =>
      settingsService.setTenantOverride(tenantId, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["tenant-settings-override", tenantId],
      });
      void queryClient.invalidateQueries({ queryKey: ["settings"] });
      setError("");
      setSuccess(true);
    },
    onError: (err: unknown) =>
      setError(getApiErrorMessage(err, "Failed to save security overrides.")),
  });

  const clearMutation = useMutation({
    mutationFn: () => settingsService.deleteTenantOverride(tenantId),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["tenant-settings-override", tenantId],
      });
      void queryClient.invalidateQueries({ queryKey: ["settings"] });
      setConfirmClear(false);
      setGroups(NO_GROUPS);
      setError("");
    },
    onError: (err: unknown) => {
      setConfirmClear(false);
      setError(getApiErrorMessage(err, "Failed to clear security overrides."));
    },
  });

  function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");
    if (!form) return;
    saveMutation.mutate(overrideFromForm(form, groups));
  }

  if (overrideLoading || effectiveLoading || !form) {
    return (
      <div className="glass-card animate-pulse space-y-3" aria-busy="true">
        <div className="h-4 bg-white/10 rounded w-1/3" />
        <div className="h-4 bg-white/10 rounded w-1/2" />
      </div>
    );
  }

  // As in the email panel: a failed load must not render as "nothing is
  // overridden". This is also what a cross-tenant view looks like — the
  // endpoint enforces `tenant_id == user.tenant_id` on top of the permission,
  // so a sibling tenant 403s here rather than showing empty toggles.
  if (isError) {
    return (
      <div className="glass-card max-w-2xl">
        <p role="alert" className="text-sm text-destructive">
          Could not load this tenant&rsquo;s security overrides
          {loadError instanceof Error ? `: ${loadError.message}` : "."} Security
          settings are editable only for your own tenant; sign in to a tenant to
          change its policy.
        </p>
      </div>
    );
  }

  return (
    <div className="glass-card max-w-2xl">
      <form onSubmit={handleSubmit} className="space-y-4" noValidate>
        <div>
          <h2 className="text-base font-medium text-foreground">
            Security Overrides
          </h2>
          <p className="text-sm text-muted-foreground">
            Anything left un-overridden is inherited from the organization&rsquo;s
            security baseline, and keeps following it as the baseline changes.
            An override may only be <strong>more</strong> restrictive — the
            server refuses one that loosens the baseline and names the field.
          </p>
        </div>

        <fieldset disabled={!canWrite} className="space-y-4">
          {/* Password */}
          <GroupToggle
            label="Override password policy"
            checked={groups.password}
            onChange={(v) => setGroups((g) => ({ ...g, password: v }))}
          />
          {groups.password && (
            <div className="ml-6 space-y-3">
              <NumField
                id="tso-min-length"
                label="Minimum length"
                hint="May be raised, not lowered."
                min={1}
                value={form.min_length}
                onChange={(v) => setField("min_length", v)}
              />
              <NumField
                id="tso-history"
                label="Password history"
                hint="Previous passwords refused on reuse. May be raised, not lowered."
                min={0}
                value={form.password_history_count}
                onChange={(v) => setField("password_history_count", v)}
              />
              <div className="space-y-2">
                <BoolField
                  id="tso-upper"
                  label="Require an uppercase letter"
                  checked={form.require_uppercase}
                  onChange={(v) => setField("require_uppercase", v)}
                />
                <BoolField
                  id="tso-lower"
                  label="Require a lowercase letter"
                  checked={form.require_lowercase}
                  onChange={(v) => setField("require_lowercase", v)}
                />
                <BoolField
                  id="tso-digits"
                  label="Require a digit"
                  checked={form.require_digits}
                  onChange={(v) => setField("require_digits", v)}
                />
                <BoolField
                  id="tso-symbols"
                  label="Require a symbol"
                  checked={form.require_symbols}
                  onChange={(v) => setField("require_symbols", v)}
                />
                <BoolField
                  id="tso-hibp"
                  label="Check against known breached passwords (HIBP)"
                  checked={form.hibp_check_enabled}
                  onChange={(v) => setField("hibp_check_enabled", v)}
                />
              </div>
              <p className="text-xs text-muted-foreground">
                A requirement the organization already enforces cannot be turned
                off here.
              </p>
            </div>
          )}

          {/* MFA */}
          <GroupToggle
            label="Override multi-factor authentication"
            checked={groups.mfa}
            onChange={(v) => setGroups((g) => ({ ...g, mfa: v }))}
          />
          {groups.mfa && (
            <div className="ml-6 space-y-3">
              <BoolField
                id="tso-mfa-enforced"
                label="Require MFA for every user in this tenant"
                checked={form.mfa_enforced}
                onChange={(v) => setField("mfa_enforced", v)}
              />
              <NumField
                id="tso-mfa-lifetime"
                label="Challenge lifetime (seconds)"
                hint="May be shortened, not lengthened."
                min={1}
                value={form.mfa_challenge_lifetime_secs}
                onChange={(v) => setField("mfa_challenge_lifetime_secs", v)}
              />
            </div>
          )}

          {/* Lockout */}
          <GroupToggle
            label="Override account lockout"
            checked={groups.lockout}
            onChange={(v) => setGroups((g) => ({ ...g, lockout: v }))}
          />
          {groups.lockout && (
            <div className="ml-6 space-y-3">
              <NumField
                id="tso-max-attempts"
                label="Failed attempts before lockout"
                hint="May be lowered, not raised."
                min={1}
                value={form.max_failed_login_attempts}
                onChange={(v) => setField("max_failed_login_attempts", v)}
              />
              <NumField
                id="tso-lockout-duration"
                label="Lockout duration (seconds)"
                hint="May be raised, not lowered."
                min={1}
                value={form.lockout_duration_secs}
                onChange={(v) => setField("lockout_duration_secs", v)}
              />
              <NumField
                id="tso-lockout-backoff"
                label="Backoff multiplier"
                hint="Applied per repeat lockout. May be raised, not lowered."
                min={1}
                step={0.1}
                value={form.lockout_backoff_multiplier}
                onChange={(v) => setField("lockout_backoff_multiplier", v)}
              />
              <NumField
                id="tso-lockout-max"
                label="Maximum lockout duration (seconds)"
                hint="May be raised, not lowered, and must be at least the lockout duration."
                min={1}
                value={form.max_lockout_duration_secs}
                onChange={(v) => setField("max_lockout_duration_secs", v)}
              />
            </div>
          )}

          {/* Tokens */}
          <GroupToggle
            label="Override token lifetimes"
            checked={groups.token}
            onChange={(v) => setGroups((g) => ({ ...g, token: v }))}
          />
          {groups.token && (
            <div className="ml-6 space-y-3">
              <NumField
                id="tso-access-lifetime"
                label="Access token lifetime (seconds)"
                hint="May be shortened, not lengthened."
                min={1}
                value={form.access_token_lifetime_secs}
                onChange={(v) => setField("access_token_lifetime_secs", v)}
              />
              <NumField
                id="tso-refresh-lifetime"
                label="Refresh token lifetime (seconds)"
                hint="May be shortened, not lengthened."
                min={1}
                value={form.refresh_token_lifetime_secs}
                onChange={(v) => setField("refresh_token_lifetime_secs", v)}
              />
            </div>
          )}

          {/* Email verification */}
          <GroupToggle
            label="Override email verification"
            checked={groups.emailVerification}
            onChange={(v) =>
              setGroups((g) => ({ ...g, emailVerification: v }))
            }
          />
          {groups.emailVerification && (
            <div className="ml-6 space-y-3">
              <BoolField
                id="tso-email-required"
                label="Require a verified email address"
                checked={form.email_verification_required}
                onChange={(v) => setField("email_verification_required", v)}
              />
              <NumField
                id="tso-email-grace"
                label="Verification grace period (hours)"
                hint="May be shortened, not lengthened."
                min={0}
                value={form.email_verification_grace_period_hours}
                onChange={(v) =>
                  setField("email_verification_grace_period_hours", v)
                }
              />
            </div>
          )}

          {/* Certificates */}
          <GroupToggle
            label="Override certificate validity"
            checked={groups.certificate}
            onChange={(v) => setGroups((g) => ({ ...g, certificate: v }))}
          />
          {groups.certificate && (
            <div className="ml-6 space-y-3">
              <NumField
                id="tso-cert-default"
                label="Default certificate validity (days)"
                hint="May be shortened, not lengthened."
                min={1}
                value={form.default_cert_validity_days}
                onChange={(v) => setField("default_cert_validity_days", v)}
              />
              <NumField
                id="tso-cert-max"
                label="Maximum certificate validity (days)"
                hint="May be shortened, not lengthened, and must be at least the default."
                min={1}
                value={form.max_cert_validity_days}
                onChange={(v) => setField("max_cert_validity_days", v)}
              />
            </div>
          )}

          {/* Notifications */}
          <GroupToggle
            label="Override admin notifications"
            checked={groups.notification}
            onChange={(v) => setGroups((g) => ({ ...g, notification: v }))}
          />
          {groups.notification && (
            <div className="ml-6">
              <BoolField
                id="tso-admin-notifications"
                label="Send admin notifications for this tenant"
                checked={form.admin_notifications_enabled}
                onChange={(v) => setField("admin_notifications_enabled", v)}
              />
            </div>
          )}

          {/* OPAQUE */}
          <GroupToggle
            label="Override OPAQUE policy"
            checked={groups.opaque}
            onChange={(v) => setGroups((g) => ({ ...g, opaque: v }))}
          />
          {groups.opaque && (
            <div className="ml-6">
              <OpaquePolicyFields
                idPrefix="tso"
                value={form.opaque}
                onChange={(next) => setField("opaque", next)}
                warning="Tighten-only: the mode may be raised above the organization's
                  (disabled → optional → required) and never lowered, and the
                  ciphersuite and key-stretching function may only be made
                  stronger."
              />
            </div>
          )}

          {/* Privacy */}
          <GroupToggle
            label="Override the pending-deletion window"
            checked={groups.privacy}
            onChange={(v) => setGroups((g) => ({ ...g, privacy: v }))}
          />
          {groups.privacy && (
            <div className="ml-6">
              <NumField
                id="tso-deletion-grace"
                label="Pending-deletion window (days)"
                hint="How long a requested erasure stays cancellable. May be shortened, not lengthened — it is time spent holding data the subject has already asked to have erased."
                min={1}
                max={MAX_DELETION_GRACE_PERIOD_DAYS}
                value={form.deletion_grace_period_days}
                onChange={(v) => setField("deletion_grace_period_days", v)}
              />
            </div>
          )}
        </fieldset>

        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
        {!error && success && (
          <p role="status" className="text-sm text-emerald-400">
            Saved.
          </p>
        )}

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
                onClick={() => setConfirmClear(true)}
              >
                <Trash2 size={14} />
                Clear All
              </Button>
            )}
          </div>
        )}
      </form>

      <ConfirmDialog
        open={confirmClear}
        onClose={() => setConfirmClear(false)}
        onConfirm={() => clearMutation.mutate()}
        title="Clear security overrides?"
        description="This tenant will fall back entirely to the organization's security baseline, including any setting it currently tightens."
        confirmLabel="Clear overrides"
        isLoading={clearMutation.isPending}
      />
    </div>
  );
}
