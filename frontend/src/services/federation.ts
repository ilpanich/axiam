import api from "@/lib/api";

// ─── Domain Models ────────────────────────────────────────────────────────────

export interface SamlConfig {
  metadata_url: string;
  entity_id: string;
  sso_url: string;
  certificate: string;
}

export interface OidcConfig {
  issuer_url: string;
  client_id: string;
  client_secret: string;
  scopes: string[];
}

export interface FederationProvider {
  id: string;
  name: string;
  type: "saml" | "oidc";
  status: "active" | "inactive";
  domain: string;
  saml_config?: SamlConfig;
  oidc_config?: OidcConfig;
  last_sync_at?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateProviderRequest {
  name: string;
  type: "saml" | "oidc";
  domain: string;
  saml_config?: SamlConfig;
  oidc_config?: OidcConfig;
}

export interface UpdateProviderRequest {
  name?: string;
  status?: "active" | "inactive";
  domain?: string;
  saml_config?: Partial<SamlConfig>;
  oidc_config?: Partial<OidcConfig>;
}

export interface TestConnectionResult {
  success: boolean;
  message: string;
  response_time_ms?: number;
}

// ─── Service ──────────────────────────────────────────────────────────────────

const BASE = "/api/v1/federation/providers";

export const federationService = {
  getAll: (): Promise<FederationProvider[]> =>
    api.get<FederationProvider[]>(BASE).then((r) => r.data),

  create: (data: CreateProviderRequest): Promise<FederationProvider> =>
    api.post<FederationProvider>(BASE, data).then((r) => r.data),

  getById: (id: string): Promise<FederationProvider> =>
    api.get<FederationProvider>(`${BASE}/${id}`).then((r) => r.data),

  update: (
    id: string,
    data: UpdateProviderRequest
  ): Promise<FederationProvider> =>
    api
      .put<FederationProvider>(`${BASE}/${id}`, data)
      .then((r) => r.data),

  delete: (id: string): Promise<void> =>
    api.delete(`${BASE}/${id}`).then(() => undefined),

  testConnection: (id: string): Promise<TestConnectionResult> =>
    api
      .post<TestConnectionResult>(`${BASE}/${id}/test`)
      .then((r) => r.data),
};
