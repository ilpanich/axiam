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
  type SystemSettings,
  type UpdateSettingsPayload,
} from "@/services/settings";
import { PageHeader } from "@/components/PageHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";

// ─── Defaults for when API returns partial data ──────────────────────────────

const DEFAULT_SETTINGS: SystemSettings = {
  password_min_length: 12,
  password_complexity_enabled: true,
  max_failed_login_attempts: 5,
  account_lockout_duration_minutes: 30,
  access_token_lifetime_minutes: 15,
  refresh_token_lifetime_days: 7,
  max_concurrent_sessions: 5,
  mfa_required: false,
  mfa_totp_enabled: true,
  mfa_webauthn_enabled: false,
  email_notifications_enabled: true,
  webhook_notifications_enabled: false,
};

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

// ─── Number field for view / edit mode ───────────────────────────────────────

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
  const [formOverrides, setFormOverrides] = useState<Partial<SystemSettings>>({});
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

  // Derive form state from query data + local overrides (no useEffect needed)
  const form = useMemo<SystemSettings>(
    () => ({ ...DEFAULT_SETTINGS, ...settings, ...formOverrides }),
    [settings, formOverrides]
  );

  const updateMutation = useMutation({
    mutationFn: (payload: UpdateSettingsPayload) =>
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

  function setField<K extends keyof SystemSettings>(
    key: K,
    value: SystemSettings[K]
  ) {
    setFormOverrides((prev) => ({ ...prev, [key]: value }));
  }

  function handleSave() {
    setFeedback(null);
    updateMutation.mutate(form);
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

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <Loader2 className="animate-spin text-primary" size={32} />
      </div>
    );
  }

  // ── Error state ──────────────────────────────────────────────────────────

  if (loadError) {
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
        description="Configure system-wide security policies, session management, and notification preferences."
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

      {/* ── Security Policies ──────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <Shield
              size={18}
              className="text-primary"
              aria-hidden="true"
            />
            <CardTitle className="text-base">
              Security Policies
            </CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          {editing ? (
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="password_min_length">
                  Password minimum length
                </Label>
                <Input
                  id="password_min_length"
                  type="number"
                  min={8}
                  max={128}
                  value={data.password_min_length}
                  onChange={(e) =>
                    setField(
                      "password_min_length",
                      Number(e.target.value)
                    )
                  }
                />
              </div>

              <ToggleField
                id="password_complexity_enabled"
                label="Require password complexity"
                description="Enforce uppercase, lowercase, digit, and symbol requirements."
                checked={data.password_complexity_enabled}
                onChange={(v) =>
                  setField("password_complexity_enabled", v)
                }
              />

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
                <Label htmlFor="account_lockout_duration_minutes">
                  Account lockout duration (minutes)
                </Label>
                <Input
                  id="account_lockout_duration_minutes"
                  type="number"
                  min={1}
                  max={1440}
                  value={data.account_lockout_duration_minutes}
                  onChange={(e) =>
                    setField(
                      "account_lockout_duration_minutes",
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
                value={data.password_min_length}
                unit="characters"
              />
              <BooleanDisplay
                label="Password complexity"
                enabled={data.password_complexity_enabled}
              />
              <NumberDisplay
                label="Max failed login attempts"
                value={data.max_failed_login_attempts}
                unit="attempts"
              />
              <NumberDisplay
                label="Account lockout duration"
                value={data.account_lockout_duration_minutes}
                unit="minutes"
              />
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── Session Management ─────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <Clock
              size={18}
              className="text-primary"
              aria-hidden="true"
            />
            <CardTitle className="text-base">
              Session Management
            </CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          {editing ? (
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="access_token_lifetime_minutes">
                  Access token lifetime (minutes)
                </Label>
                <Input
                  id="access_token_lifetime_minutes"
                  type="number"
                  min={1}
                  max={1440}
                  value={data.access_token_lifetime_minutes}
                  onChange={(e) =>
                    setField(
                      "access_token_lifetime_minutes",
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

              <div className="space-y-2">
                <Label htmlFor="max_concurrent_sessions">
                  Max concurrent sessions
                </Label>
                <Input
                  id="max_concurrent_sessions"
                  type="number"
                  min={1}
                  max={100}
                  value={data.max_concurrent_sessions}
                  onChange={(e) =>
                    setField(
                      "max_concurrent_sessions",
                      Number(e.target.value)
                    )
                  }
                />
              </div>
            </div>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2">
              <NumberDisplay
                label="Access token lifetime"
                value={data.access_token_lifetime_minutes}
                unit="minutes"
              />
              <NumberDisplay
                label="Refresh token lifetime"
                value={data.refresh_token_lifetime_days}
                unit="days"
              />
              <NumberDisplay
                label="Max concurrent sessions"
                value={data.max_concurrent_sessions}
                unit="sessions"
              />
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── MFA Settings ───────────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <Smartphone
              size={18}
              className="text-primary"
              aria-hidden="true"
            />
            <CardTitle className="text-base">MFA Settings</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          {editing ? (
            <div className="space-y-4">
              <ToggleField
                id="mfa_required"
                label="Require MFA for all users"
                description="When enabled, users must configure at least one MFA method to access the system."
                checked={data.mfa_required}
                onChange={(v) => setField("mfa_required", v)}
              />

              <div className="border-t border-white/5 pt-4">
                <p className="text-xs text-muted-foreground uppercase tracking-wide mb-3">
                  Allowed MFA methods
                </p>
                <div className="space-y-3">
                  <ToggleField
                    id="mfa_totp_enabled"
                    label="TOTP (Authenticator app)"
                    description="Time-based one-time passwords via apps like Google Authenticator."
                    checked={data.mfa_totp_enabled}
                    onChange={(v) =>
                      setField("mfa_totp_enabled", v)
                    }
                  />
                  <ToggleField
                    id="mfa_webauthn_enabled"
                    label="WebAuthn (Security keys)"
                    description="Hardware security keys and biometric authenticators."
                    checked={data.mfa_webauthn_enabled}
                    onChange={(v) =>
                      setField("mfa_webauthn_enabled", v)
                    }
                  />
                </div>
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              <BooleanDisplay
                label="MFA required"
                enabled={data.mfa_required}
              />
              <div className="border-t border-white/5 pt-3">
                <p className="text-xs text-muted-foreground uppercase tracking-wide mb-2">
                  Allowed MFA methods
                </p>
                <div className="flex flex-wrap gap-2">
                  <Badge
                    variant={
                      data.mfa_totp_enabled ? "default" : "secondary"
                    }
                  >
                    TOTP{" "}
                    {data.mfa_totp_enabled ? "(Active)" : "(Disabled)"}
                  </Badge>
                  <Badge
                    variant={
                      data.mfa_webauthn_enabled
                        ? "default"
                        : "secondary"
                    }
                  >
                    WebAuthn{" "}
                    {data.mfa_webauthn_enabled
                      ? "(Active)"
                      : "(Disabled)"}
                  </Badge>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── Notification Preferences ───────────────────────────────────── */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <Bell
              size={18}
              className="text-primary"
              aria-hidden="true"
            />
            <CardTitle className="text-base">
              Notification Preferences
            </CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          {editing ? (
            <div className="space-y-4">
              <ToggleField
                id="email_notifications_enabled"
                label="Email notifications"
                description="Send system alerts and security events via email."
                checked={data.email_notifications_enabled}
                onChange={(v) =>
                  setField("email_notifications_enabled", v)
                }
              />
              <ToggleField
                id="webhook_notifications_enabled"
                label="Webhook notifications"
                description="Deliver event payloads to configured webhook endpoints."
                checked={data.webhook_notifications_enabled}
                onChange={(v) =>
                  setField("webhook_notifications_enabled", v)
                }
              />
            </div>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2">
              <BooleanDisplay
                label="Email notifications"
                enabled={data.email_notifications_enabled}
              />
              <BooleanDisplay
                label="Webhook notifications"
                enabled={data.webhook_notifications_enabled}
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
