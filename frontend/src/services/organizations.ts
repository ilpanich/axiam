import api from "@/lib/api";
import { fetchAllPages } from "@/services/_pagination";
import {
  readOpaquePolicy,
  type OpaqueKsf,
  type OpaqueMode,
  type OpaquePolicy,
  type OpaqueSuite,
} from "@/services/opaquePolicy";

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

/**
 * Who holds a CA's signing key.
 *
 * Recorded per CA rather than read from configuration, so a deployment that
 * adopts Vault does not strand the CAs it already has.
 *
 * - `database` — AES-256-GCM ciphertext in the CA row, under the server's
 *   `pki_encryption_key`.
 * - `vault` — a HashiCorp Vault KV v2 secret; the row holds only a path.
 * - `external` — AXIAM holds no key. An imported trust anchor: certificates it
 *   signed are trusted, and AXIAM cannot issue new ones against it.
 */
export type CaKeyCustody = "database" | "vault" | "vault_pki" | "external";

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
  /** Optional so a server older than the field does not fail the type. */
  key_custody?: CaKeyCustody;
  /**
   * Whether this CA is offered as a trust anchor for mutual TLS.
   *
   * When set, the server exports this CA's **public** certificate to the
   * client-CA bundle at startup and enables client-certificate verification, so
   * an IoT device or service account holding a certificate this CA issued is
   * authenticated by the TLS layer itself. The signing key is not copied and
   * stays with its custodian.
   *
   * Takes effect at the next server start: rustls builds its client trust store
   * once, when the listener is constructed.
   */
  mtls_trust_anchor?: boolean;
  /**
   * The issuers above `public_cert_pem`, concatenated PEM, root last.
   *
   * Present for a `vault_pki` CA, where the certificate that signs is an
   * intermediate and its root exists only inside Vault. Absent for a CA that is
   * its own root.
   */
  chain_pem?: string;
  /**
   * Set when this CA signs for one tenant rather than the whole organization.
   *
   * A tenant signing CA is an intermediate created beneath an organization CA
   * and constrained to signing leaves. Absent on every organization-level CA,
   * and on every CA created before tenant signing CAs existed.
   */
  tenant_id?: string;
  /** The CA in this organization that signed this one, when there is one. */
  parent_ca_id?: string;
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

export interface PrivacyPolicy {
  /**
   * How long a requested account erasure stays cancellable, in days.
   *
   * The window the "Cancel pending deletion" control in Privacy & Data acts
   * within. It was fixed at 30 days server-side, so the control referred to a
   * duration nobody could see or change.
   */
  deletion_grace_period_days: number;
}

/** The longest erasure grace window the server accepts (GDPR Art. 12(3)). */
export const MAX_DELETION_GRACE_PERIOD_DAYS = 90;

/** The default the server applies, and what every deployment had before it was settable. */
export const DEFAULT_DELETION_GRACE_PERIOD_DAYS = 30;

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
  /** OPAQUE (RFC 9807) policy — the baseline every tenant inherits. */
  opaque: OpaquePolicy;
  /** Retention rules that apply after a subject asks to be erased. */
  privacy?: PrivacyPolicy;
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
  // OPAQUE. Required here like every other field, because this PUT replaces the
  // whole row: the backend defaults these to `disabled` when they are absent,
  // so omitting them from a save turns OPAQUE off org-wide.
  opaque_mode: OpaqueMode;
  opaque_suite: OpaqueSuite;
  opaque_ksf: OpaqueKsf;
  // Privacy. Required here for the same reason: the PUT replaces the whole
  // row, and the server's default for an absent value is 30 days.
  deletion_grace_period_days: number;
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
    // Read through the guard rather than `s.opaque.*`: a settings row written
    // before the OPAQUE migration carries no such block, and an `undefined`
    // here would be dropped from the JSON body and land back as `disabled`.
    ...readOpaquePolicy(s),
    // Same guard, same reason: a server older than the privacy block sends no
    // `privacy`, and an `undefined` would be dropped from the body and land
    // back as the server's own 30-day default anyway — but going through the
    // constant keeps the form control from rendering an empty number input.
    deletion_grace_period_days:
      s.privacy?.deletion_grace_period_days ?? DEFAULT_DELETION_GRACE_PERIOD_DAYS,
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

/**
 * Body of the import endpoint (BYOK).
 *
 * No subject, validity or algorithm: all three come from the certificate.
 */
export interface ImportCaCertPayload {
  public_cert_pem: string;
  /** Omit to register the certificate as a trust anchor only. Write-only. */
  private_key_pem?: string;
}

/// Generation response flattens the CA certificate and adds the one-time
/// PEM-encoded private key (never retrievable again).
///
/// `private_key_pem` is optional because under `vault_pki` custody there is no
/// key to return: Vault generated it and exposes no API that exports it. The
/// thing to save in that case is `chain_pem` — Vault hands over a generated
/// root's certificate exactly once.
export interface GeneratedCaCertificate extends CaCertificate {
  private_key_pem?: string;
}

// ─── Organizations service ────────────────────────────────────────────────────

export const orgService = {
  list: (): Promise<Organization[]> =>
    fetchAllPages<Organization>("/api/v1/organizations"),

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
    fetchAllPages<Tenant>(`/api/v1/organizations/${orgId}/tenants`),

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
    fetchAllPages<CaCertificate>(`/api/v1/organizations/${orgId}/ca-certificates`),

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

  /**
   * Register a CA the organization already has, instead of generating one.
   *
   * For an organization whose root lives offline, in an HSM, or in an existing
   * internal PKI and which wants AXIAM in the chain rather than at the top of
   * it. Subject, validity window and key algorithm are read from the
   * certificate server-side and are not part of the request — a caller that
   * could name them separately could name a subject the certificate does not
   * have.
   *
   * With `private_key_pem`, the server takes custody of the key (Vault when
   * configured, otherwise sealed into the row) and can issue against the CA.
   * Without it, the certificate is a trust anchor only.
   */
  import: (
    orgId: string,
    payload: ImportCaCertPayload
  ): Promise<CaCertificate> =>
    api
      .post<CaCertificate>(
        `/api/v1/organizations/${orgId}/ca-certificates/import`,
        payload
      )
      .then((r) => r.data),

  revoke: (orgId: string, certId: string): Promise<void> =>
    api
      .post(`/api/v1/organizations/${orgId}/ca-certificates/${certId}/revoke`)
      .then(() => undefined),

  /**
   * Offer this CA — or stop offering it — as an mTLS client trust anchor.
   *
   * The response's `restart_required` is always true and is the point of it:
   * there is no supported way to add a root to a rustls listener that is
   * already serving, so the change applies at the next server start. Surface
   * that to the operator rather than letting the toggle imply it took effect.
   */
  setMtlsTrustAnchor: (
    orgId: string,
    certId: string,
    enabled: boolean
  ): Promise<MtlsTrustAnchorResponse> =>
    api
      .put<MtlsTrustAnchorResponse>(
        `/api/v1/organizations/${orgId}/ca-certificates/${certId}/mtls-trust-anchor`,
        { enabled }
      )
      .then((r) => r.data),

  /**
   * Move this CA's signing key to the custodian the deployment is configured
   * for — in practice, out of the database and into Vault.
   *
   * Custody is recorded per CA rather than read from configuration, so adopting
   * Vault does not move the CAs that already exist. Without this the only route
   * out of database custody is to generate a new CA and re-issue every leaf
   * beneath it, which for a trust anchor means touching every relying party.
   *
   * Takes effect immediately — no restart. The row is the authority on where a
   * key lives and the signing path reads it per request.
   */
  migrateCustody: (
    orgId: string,
    certId: string
  ): Promise<MigrateCustodyResponse> =>
    api
      .post<MigrateCustodyResponse>(
        `/api/v1/organizations/${orgId}/ca-certificates/${certId}/migrate-custody`
      )
      .then((r) => r.data),
};

/** What a `migrateCustody` call moved. */
export interface MigrateCustodyResponse {
  ca_certificate_id: string;
  previous_custody: CaKeyCustody;
  key_custody: CaKeyCustody;
  key_locator: string | null;
}

/** Acknowledgement of a `setMtlsTrustAnchor` call. */
export interface MtlsTrustAnchorResponse {
  ca_certificate_id: string;
  mtls_trust_anchor: boolean;
  /** Always true — see `caCertService.setMtlsTrustAnchor`. */
  restart_required: boolean;
  message: string;
}

// ─── Tenant signing CAs ───────────────────────────────────────────────────────
//
// The intermediate between an organization's trust anchor and one tenant's
// certificates. Issuing every tenant's leaves straight from the anchor means
// one tenant's compromised issuance is the whole estate's problem, and rotating
// the anchor is a co-ordinated change at every relying party. A tenant signing
// CA is revoked and replaced on its own.

export interface GenerateSigningCaPayload {
  /** The organization CA that signs it — must be Active and hold a key. */
  parent_ca_id: string;
  subject: string;
  key_algorithm: "Rsa4096" | "Ed25519";
  /** Capped server-side to the parent CA's own expiry. */
  validity_days: number;
}

export interface SignSigningCaCsrPayload {
  parent_ca_id: string;
  /** PEM-encoded PKCS#10 certificate signing request. */
  csr_pem: string;
  validity_days: number;
}

export const signingCaService = {
  list: (orgId: string, tenantId: string): Promise<CaCertificate[]> =>
    fetchAllPages<CaCertificate>(
      `/api/v1/organizations/${orgId}/tenants/${tenantId}/signing-cas`
    ),

  /**
   * Create one with the key generated by whoever the server's custodian is.
   *
   * `private_key_pem` comes back exactly once and only when there is one:
   * under Vault's PKI engine the key is born inside Vault and no API exports
   * it, so the response omits the field rather than sending an empty one.
   */
  generate: (
    orgId: string,
    tenantId: string,
    payload: GenerateSigningCaPayload
  ): Promise<GeneratedCaCertificate> =>
    api
      .post<GeneratedCaCertificate>(
        `/api/v1/organizations/${orgId}/tenants/${tenantId}/signing-cas`,
        payload
      )
      .then((r) => r.data),

  /**
   * Sign a request the tenant produced elsewhere.
   *
   * Nothing is returned once, because nothing was generated here: the private
   * key is wherever the CSR was made and never reaches AXIAM. The subject comes
   * from the CSR; its requested extensions do not — the server decides that
   * this is a CA and constrains it to signing leaves.
   */
  signCsr: (
    orgId: string,
    tenantId: string,
    payload: SignSigningCaCsrPayload
  ): Promise<CaCertificate> =>
    api
      .post<CaCertificate>(
        `/api/v1/organizations/${orgId}/tenants/${tenantId}/signing-cas/sign-csr`,
        payload
      )
      .then((r) => r.data),

  /**
   * Revoke one. Routed through the organization CA endpoint because a tenant
   * signing CA *is* a CA certificate and is revoked as one.
   */
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
