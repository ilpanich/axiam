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

/**
 * T21.4 — how a client may register itself (RFC 7591). `disabled` refuses
 * every request; `initial_access_token` requires a single-use credential an
 * administrator minted; `anonymous` accepts anybody who can reach the
 * endpoint. Mirrors `DynamicRegistrationMode` in
 * `crates/axiam-core/src/models/settings.rs`, on the same permissiveness
 * ladder (`disabled` < `initial_access_token` < `anonymous`): a tenant may
 * move down it and never up.
 */
export type DynamicRegistrationMode =
  | "disabled"
  | "initial_access_token"
  | "anonymous";

/**
 * T21.4 — the dynamic-client-registration fields of `OidcPolicy`. Only the
 * fields this task's admin surfaces read or write; `sensitive_scopes_enabled`
 * and `default_locale` predate T21.4 and have no admin UI yet, so they are
 * left out of this type rather than modelled and ignored.
 *
 * Source: `crates/axiam-core/src/models/settings.rs` (`OidcPolicy`).
 */
export interface OidcPolicy {
  dynamic_registration: DynamicRegistrationMode;
  /** May not contain `address` or `phone` — see `validateDcrPolicy`. */
  dcr_allowed_scopes: string[];
  dcr_allowed_redirect_hosts: string[];
  /** D3 — the audiences an externally registered client may address. */
  external_client_allowed_resources: string[];
  dcr_max_clients: number;
  dcr_unused_client_ttl_days: number;
}

/** T21.4 defaults, mirroring `DEFAULT_DCR_MAX_CLIENTS` / `DEFAULT_DCR_UNUSED_CLIENT_TTL_DAYS`. */
export const DEFAULT_DCR_MAX_CLIENTS = 20;
export const DEFAULT_DCR_UNUSED_CLIENT_TTL_DAYS = 30;

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
  /**
   * T21.4 — dynamic client registration policy. Optional for the same reason
   * as `privacy`/`webauthn`: a server older than the field does not carry it,
   * and callers fall back to the server's own `disabled` default (I1).
   */
  oidc?: OidcPolicy;
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
  // T21.4 — dynamic client registration. `dynamic_registration`,
  // `dcr_max_clients` and `dcr_unused_client_ttl_days` are tighten-only, like
  // every ordered field above; the three lists replace the org baseline whole
  // rather than being ordered against it (see `OidcPolicy` on the backend).
  dynamic_registration?: DynamicRegistrationMode;
  dcr_allowed_scopes?: string[];
  dcr_allowed_redirect_hosts?: string[];
  external_client_allowed_resources?: string[];
  dcr_max_clients?: number;
  dcr_unused_client_ttl_days?: number;
}

/**
 * The two GDPR-sensitive scopes a self-registered client may never ask for.
 * Mirrors `sensitive_scope_in_dcr_list` in
 * `crates/axiam-core/src/models/settings.rs` — trimmed, exact match, no
 * case-folding, because that is what the backend does.
 */
const DCR_SENSITIVE_SCOPES = ["address", "phone"];

/**
 * Client-side mirror of `validate_dcr_policy`
 * (`crates/axiam-core/src/models/settings.rs`), which the settings handler
 * runs on the *resolved* policy. Both interlocks recorded by the T21.4a
 * amendment:
 *
 * 1. **D3** — `anonymous` registration cannot be enabled while
 *    `external_client_allowed_resources` is empty: a client an unrelated
 *    party registered inherits that list verbatim, and an empty one leaves it
 *    able to obtain only the `axiam:user` tokens AXIAM's own APIs accept.
 * 2. **Amendment 1** — `dcr_allowed_scopes` may not contain `address` or
 *    `phone`: both release personal data under W7's per-client consent
 *    record, and a self-registered client already carries a forced consent
 *    record of its own (D4) — offering them here would need two records in
 *    one namespace.
 *
 * Returns `null` when the policy is valid. Messages match the backend's
 * wording so an operator who has read the docs recognises the refusal.
 */
export function validateDcrPolicy(policy: {
  dynamic_registration: DynamicRegistrationMode;
  dcr_allowed_scopes: string[];
  external_client_allowed_resources: string[];
}): string | null {
  if (
    policy.dynamic_registration === "anonymous" &&
    policy.external_client_allowed_resources.length === 0
  ) {
    return (
      "dynamic_registration: anonymous registration cannot be enabled while " +
      "external_client_allowed_resources is empty (D3). A client registered by an unrelated " +
      "party inherits that list as its allowed_resources, and an empty list leaves it able to " +
      "obtain only the axiam:user tokens AXIAM's own APIs accept. Name the MCP servers this " +
      "tenant fronts first."
    );
  }

  const sensitive = policy.dcr_allowed_scopes.find((s) =>
    DCR_SENSITIVE_SCOPES.includes(s.trim())
  );
  if (sensitive !== undefined) {
    return (
      `dcr_allowed_scopes: ${sensitive.trim()} releases personal data under W7's per-client ` +
      "consent record and cannot be offered to a self-registered client, which already " +
      "carries a forced consent record of its own (D4). Register a client for it through " +
      "POST /oauth2-clients instead."
    );
  }

  return null;
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
