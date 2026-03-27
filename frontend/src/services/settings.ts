import api from "@/lib/api";

// ─── Domain Models ────────────────────────────────────────────────────────────

export interface SystemSettings {
  // Security policies
  password_min_length: number;
  password_complexity_enabled: boolean;
  max_failed_login_attempts: number;
  account_lockout_duration_minutes: number;

  // Session management
  access_token_lifetime_minutes: number;
  refresh_token_lifetime_days: number;
  max_concurrent_sessions: number;

  // MFA settings
  mfa_required: boolean;
  mfa_totp_enabled: boolean;
  mfa_webauthn_enabled: boolean;

  // Notification preferences
  email_notifications_enabled: boolean;
  webhook_notifications_enabled: boolean;
}

export type UpdateSettingsPayload = Partial<SystemSettings>;

// ─── Service ──────────────────────────────────────────────────────────────────

export const settingsService = {
  async getSettings(): Promise<SystemSettings> {
    const res = await api.get<SystemSettings>("/api/v1/settings");
    return res.data;
  },

  async updateSettings(
    data: UpdateSettingsPayload
  ): Promise<SystemSettings> {
    const res = await api.put<SystemSettings>("/api/v1/settings", data);
    return res.data;
  },
};
