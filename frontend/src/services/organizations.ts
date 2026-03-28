import api from "@/lib/api";

// ─── Domain Models ────────────────────────────────────────────────────────────

export interface Organization {
  id: string;
  name: string;
  slug: string;
  description?: string;
  created_at: string;
}

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  description?: string;
  org_id: string;
  created_at: string;
}

export interface CaCertificate {
  id: string;
  common_name: string;
  key_type: "RSA4096" | "Ed25519";
  status: "active" | "revoked" | "inactive";
  expires_at: string;
  created_at: string;
}

export interface SecuritySettings {
  password_min_length?: number;
  password_require_uppercase?: boolean;
  password_require_lowercase?: boolean;
  password_require_digit?: boolean;
  password_require_symbol?: boolean;
  password_history_count?: number;
  mfa_enforced?: boolean;
  session_timeout_minutes?: number;
  certificate_validity_days?: number;
}

// ─── Request payloads ─────────────────────────────────────────────────────────

export interface CreateOrganizationPayload {
  name: string;
  slug: string;
  description?: string;
}

export type UpdateOrganizationPayload = Partial<CreateOrganizationPayload>;

export interface CreateTenantPayload {
  name: string;
  slug: string;
  description?: string;
}

export type UpdateTenantPayload = Partial<CreateTenantPayload>;

export interface GenerateCaCertPayload {
  common_name: string;
  key_type: "RSA4096" | "Ed25519";
  validity_days: number;
}

// ─── Organizations service ────────────────────────────────────────────────────

export const orgService = {
  list: (): Promise<Organization[]> =>
    api.get<Organization[]>("/api/v1/organizations").then((r) => r.data),

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
      .get<Tenant[]>(`/api/v1/organizations/${orgId}/tenants`)
      .then((r) => r.data),

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
      .get<CaCertificate[]>(`/api/v1/organizations/${orgId}/ca-certificates`)
      .then((r) => r.data),

  generate: (
    orgId: string,
    payload: GenerateCaCertPayload
  ): Promise<CaCertificate> =>
    api
      .post<CaCertificate>(
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
    payload: SecuritySettings
  ): Promise<SecuritySettings> =>
    api
      .put<SecuritySettings>(
        `/api/v1/organizations/${orgId}/settings`,
        payload
      )
      .then((r) => r.data),
};
