import api from "@/lib/api";

// ─── Backend-aligned nested READ shape ─────────────────────────────────────────
// GET /api/v1/settings returns the effective (merged) `SecuritySettings`.
// Source of truth: crates/axiam-core/src/models/settings.rs (SecuritySettings).

export interface PasswordPolicy {
  min_length: number;
  require_uppercase: boolean;
  require_lowercase: boolean;
  require_digits: boolean;
  require_symbols: boolean;
  password_history_count: number;
  hibp_check_enabled: boolean;
}

export interface MfaPolicy {
  mfa_enforced: boolean;
  mfa_challenge_lifetime_secs: number;
}

export interface LockoutPolicy {
  max_failed_login_attempts: number;
  lockout_duration_secs: number;
  lockout_backoff_multiplier: number;
  max_lockout_duration_secs: number;
}

export interface TokenPolicy {
  access_token_lifetime_secs: number;
  refresh_token_lifetime_secs: number;
}

export interface EmailVerificationPolicy {
  email_verification_required: boolean;
  email_verification_grace_period_hours: number;
}

export interface CertificatePolicy {
  default_cert_validity_days: number;
  max_cert_validity_days: number;
}

export interface NotificationPolicy {
  admin_notifications_enabled: boolean;
}

/** Fully-resolved security settings (nested) — GET /api/v1/settings. */
export interface SecuritySettings {
  id: string;
  scope: "Org" | "Tenant";
  scope_id: string;
  password: PasswordPolicy;
  mfa: MfaPolicy;
  lockout: LockoutPolicy;
  token: TokenPolicy;
  email: EmailVerificationPolicy;
  certificate: CertificatePolicy;
  notification: NotificationPolicy;
  created_at: string;
  updated_at: string;
}

// ─── Backend-aligned flat WRITE shape (all optional, SECONDS) ──────────────────
// PUT /api/v1/settings expects `TenantSettingsOverride` — flat, all fields
// optional. Omitted fields inherit the org baseline. All durations are in
// SECONDS. Source: crates/axiam-core/src/models/settings.rs.

export interface TenantSettingsOverride {
  // Password
  min_length?: number;
  require_uppercase?: boolean;
  require_lowercase?: boolean;
  require_digits?: boolean;
  require_symbols?: boolean;
  password_history_count?: number;
  hibp_check_enabled?: boolean;
  // MFA
  mfa_enforced?: boolean;
  mfa_challenge_lifetime_secs?: number;
  // Lockout
  max_failed_login_attempts?: number;
  lockout_duration_secs?: number;
  lockout_backoff_multiplier?: number;
  max_lockout_duration_secs?: number;
  // Token
  access_token_lifetime_secs?: number;
  refresh_token_lifetime_secs?: number;
  // Email
  email_verification_required?: boolean;
  email_verification_grace_period_hours?: number;
  // Certificate
  default_cert_validity_days?: number;
  max_cert_validity_days?: number;
  // Notification
  admin_notifications_enabled?: boolean;
}

// ─── Service ──────────────────────────────────────────────────────────────────

export const settingsService = {
  /** GET /api/v1/settings — effective (merged) tenant security settings. */
  async getSettings(): Promise<SecuritySettings> {
    const res = await api.get<SecuritySettings>("/api/v1/settings");
    return res.data;
  },

  /**
   * PUT /api/v1/settings — set tenant-level overrides. Only fields that are
   * MORE restrictive than the org baseline are accepted. All durations are in
   * seconds.
   */
  async updateSettings(
    data: TenantSettingsOverride
  ): Promise<SecuritySettings> {
    const res = await api.put<SecuritySettings>("/api/v1/settings", data);
    return res.data;
  },
};
