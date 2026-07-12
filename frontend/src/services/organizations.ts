import api from "@/lib/api";
import { unwrapList } from "@/services/_pagination";

// ─── Domain Models ────────────────────────────────────────────────────────────

export interface Organization {
  id: string;
  name: string;
  slug: string;
  metadata?: Record<string, unknown>;
  created_at: string;
  updated_at?: string;
}

/** Backend `TenantStatus` enum, serialized PascalCase. */
export type TenantStatus = "Active" | "Suspended";

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  /** Lifecycle status; new tenants default to "Active". */
  status: TenantStatus;
  metadata?: Record<string, unknown>;
  organization_id: string;
  created_at: string;
  updated_at?: string;
}

export interface CaCertificate {
  id: string;
  organization_id: string;
  subject: string;
  fingerprint: string;
  public_cert_pem: string;
  key_algorithm: "Rsa4096" | "Ed25519";
  status: "Active" | "Revoked" | "Expired";
  not_before: string;
  not_after: string;
}

// ─── Security settings ─────────────────────────────────────────────────────────
// GET /organizations/{id}/settings returns the nested `SecuritySettings`.
// PUT /organizations/{id}/settings requires the flat `SetOrgSettings` where
// EVERY field is required and all durations are in SECONDS.
// Source of truth: crates/axiam-core/src/models/settings.rs.

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

/** Nested, fully-resolved org security settings (READ shape). */
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

/** Flat org settings input (WRITE shape) — ALL fields required, SECONDS. */
export interface SetOrgSettings {
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
  mfa_challenge_lifetime_secs: number;
  // Lockout
  max_failed_login_attempts: number;
  lockout_duration_secs: number;
  lockout_backoff_multiplier: number;
  max_lockout_duration_secs: number;
  // Token
  access_token_lifetime_secs: number;
  refresh_token_lifetime_secs: number;
  // Email
  email_verification_required: boolean;
  email_verification_grace_period_hours: number;
  // Certificate
  default_cert_validity_days: number;
  max_cert_validity_days: number;
  // Notification
  admin_notifications_enabled: boolean;
}

/** Flatten a nested SecuritySettings into the flat SetOrgSettings input. */
export function flattenOrgSettings(s: SecuritySettings): SetOrgSettings {
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
  };
}

// ─── Request payloads ─────────────────────────────────────────────────────────

export interface CreateOrganizationPayload {
  name: string;
  slug: string;
  metadata?: Record<string, unknown>;
}

export type UpdateOrganizationPayload = Partial<CreateOrganizationPayload>;

export interface CreateTenantPayload {
  name: string;
  slug: string;
  metadata?: Record<string, unknown>;
}

export type UpdateTenantPayload = Partial<CreateTenantPayload> & {
  status?: TenantStatus;
};

export interface GenerateCaCertPayload {
  subject: string;
  key_algorithm: "Rsa4096" | "Ed25519";
  validity_days: number;
}

/// Generation response flattens the CA certificate and adds the one-time
/// PEM-encoded private key (never retrievable again).
export interface GeneratedCaCertificate extends CaCertificate {
  private_key_pem: string;
}

// ─── Organizations service ────────────────────────────────────────────────────

export const orgService = {
  list: (): Promise<Organization[]> =>
    api
      .get<Organization[] | { items: Organization[] }>("/api/v1/organizations")
      .then((r) => unwrapList(r.data)),

  get: (orgId: string): Promise<Organization> =>
    api.get<Organization>(`/api/v1/organizations/${orgId}`).then((r) => r.data),

  create: (payload: CreateOrganizationPayload): Promise<Organization> =>
    api
      .post<Organization>("/api/v1/organizations", payload)
      .then((r) => r.data),

  update: (
    orgId: string,
    payload: UpdateOrganizationPayload
  ): Promise<Organization> =>
    api
      .put<Organization>(`/api/v1/organizations/${orgId}`, payload)
      .then((r) => r.data),

  remove: (orgId: string): Promise<void> =>
    api.delete(`/api/v1/organizations/${orgId}`).then(() => undefined),
};

// ─── Tenants service ──────────────────────────────────────────────────────────

export const tenantService = {
  list: (orgId: string): Promise<Tenant[]> =>
    api
      .get<Tenant[] | { items: Tenant[] }>(`/api/v1/organizations/${orgId}/tenants`)
      .then((r) => unwrapList(r.data)),

  get: (orgId: string, tenantId: string): Promise<Tenant> =>
    api
      .get<Tenant>(`/api/v1/organizations/${orgId}/tenants/${tenantId}`)
      .then((r) => r.data),

  create: (orgId: string, payload: CreateTenantPayload): Promise<Tenant> =>
    api
      .post<Tenant>(`/api/v1/organizations/${orgId}/tenants`, payload)
      .then((r) => r.data),

  update: (
    orgId: string,
    tenantId: string,
    payload: UpdateTenantPayload
  ): Promise<Tenant> =>
    api
      .put<Tenant>(
        `/api/v1/organizations/${orgId}/tenants/${tenantId}`,
        payload
      )
      .then((r) => r.data),

  remove: (orgId: string, tenantId: string): Promise<void> =>
    api
      .delete(`/api/v1/organizations/${orgId}/tenants/${tenantId}`)
      .then(() => undefined),
};

// ─── CA Certificates service ──────────────────────────────────────────────────

export const caCertService = {
  list: (orgId: string): Promise<CaCertificate[]> =>
    api
      .get<CaCertificate[] | { items: CaCertificate[] }>(
        `/api/v1/organizations/${orgId}/ca-certificates`
      )
      .then((r) => unwrapList(r.data)),

  generate: (
    orgId: string,
    payload: GenerateCaCertPayload
  ): Promise<GeneratedCaCertificate> =>
    api
      .post<GeneratedCaCertificate>(
        `/api/v1/organizations/${orgId}/ca-certificates`,
        payload
      )
      .then((r) => r.data),

  revoke: (orgId: string, certId: string): Promise<void> =>
    api
      .post(`/api/v1/organizations/${orgId}/ca-certificates/${certId}/revoke`)
      .then(() => undefined),
};

// ─── Organization settings service ───────────────────────────────────────────

export const orgSettingsService = {
  get: (orgId: string): Promise<SecuritySettings> =>
    api
      .get<SecuritySettings>(`/api/v1/organizations/${orgId}/settings`)
      .then((r) => r.data),

  update: (
    orgId: string,
    payload: SetOrgSettings
  ): Promise<SecuritySettings> =>
    api
      .put<SecuritySettings>(
        `/api/v1/organizations/${orgId}/settings`,
        payload
      )
      .then((r) => r.data),
};
