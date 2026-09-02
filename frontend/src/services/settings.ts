import api from "@/lib/api";
import type {
  OpaqueKsf,
  OpaqueMode,
  OpaquePolicy,
  OpaqueSuite,
} from "@/services/opaquePolicy";

export type { OpaqueKsf, OpaqueMode, OpaquePolicy, OpaqueSuite };

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

export interface PrivacyPolicy {
  /** How long a requested account erasure stays cancellable, in days. */
  deletion_grace_period_days: number;
}

/**
 * How hard an authenticator must prove *who* is present during a WebAuthn
 * ceremony — the WebAuthn `userVerification`.
 *
 * `required` refuses any security key that cannot set the UV bit, which
 * includes every YubiKey with no PIN configured. `preferred` (the default)
 * asks, accepts either answer, and records which happened.
 *
 * Usernameless sign-in always requires user verification whatever this says:
 * there the credential is the only factor.
 */
export type WebauthnUserVerification = "discouraged" | "preferred" | "required";

export interface WebauthnPolicy {
  webauthn_user_verification: WebauthnUserVerification;
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
  /**
   * OPAQUE (RFC 9807) policy. Always present on a current server; see
   * `readOpaquePolicy` for why the write paths never read it directly.
   */
  opaque: OpaquePolicy;
  /**
   * Retention rules after an erasure request. Optional so a server older than
   * the field does not fail the type; callers fall back to the server's own
   * 30-day default.
   */
  privacy?: PrivacyPolicy;
  /**
   * WebAuthn ceremony policy. Optional for the same reason as `privacy`: a
   * server older than the field does not carry it, and callers fall back to
   * the server's own `preferred` default.
   */
  webauthn?: WebauthnPolicy;
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
  // OPAQUE — tighten-only, like every other field here: the server refuses a
  // mode below the org baseline, or a weaker suite/KSF.
  opaque_mode?: OpaqueMode;
  opaque_suite?: OpaqueSuite;
  opaque_ksf?: OpaqueKsf;
  // Privacy — tighten-only means *shorter*: it is time spent holding data the
  // subject has already asked to have erased.
  deletion_grace_period_days?: number;
  // WebAuthn — tighten-only on required > preferred > discouraged.
  webauthn_user_verification?: WebauthnUserVerification;
}

// ─── Service ──────────────────────────────────────────────────────────────────

export const settingsService = {
  /**
   * GET /api/v1/tenants/{id}/settings — the tenant's **own** overrides, sparse.
   *
   * Distinct from `getSettings`, which returns the merged view. The tenant
   * detail page needs to tell an overridden field from an inherited one, and a
   * merged view cannot express that. `404` (this tenant overrides nothing) maps
   * to `null` so "inherits everything" is a value the caller can render.
   */
  async getTenantOverride(
    tenantId: string
  ): Promise<TenantSettingsOverride | null> {
    try {
      const res = await api.get<TenantSettingsOverride>(
        `/api/v1/tenants/${tenantId}/settings`
      );
      return res.data;
    } catch (err) {
      const status = (err as { response?: { status?: number } })?.response
        ?.status;
      if (status === 404) return null;
      throw err;
    }
  },

  /** PUT /api/v1/tenants/{id}/settings — replace the sparse override set. */
  async setTenantOverride(
    tenantId: string,
    data: TenantSettingsOverride
  ): Promise<TenantSettingsOverride> {
    const res = await api.put<TenantSettingsOverride>(
      `/api/v1/tenants/${tenantId}/settings`,
      data
    );
    return res.data;
  },

  /** DELETE /api/v1/tenants/{id}/settings — inherit the org baseline entirely. */
  async deleteTenantOverride(tenantId: string): Promise<void> {
    await api.delete(`/api/v1/tenants/${tenantId}/settings`);
  },

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
