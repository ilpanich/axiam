import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Settings,
  Shield,
  Clock,
  Smartphone,
  Bell,
  Pencil,
  X,
  Loader2,
  AlertCircle,
  CheckCircle2,
} from "lucide-react";
import {
  settingsService,
  type SecuritySettings,
  type TenantSettingsOverride,
} from "@/services/settings";
import { PageHeader } from "@/components/PageHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";

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
}

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
      setFeedback({
        type: "error",
        message:
          err instanceof Error
            ? err.message
            : "Failed to save settings. Please try again.",
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
