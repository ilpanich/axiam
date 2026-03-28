import api from "@/lib/api";

// ─── Domain Models ────────────────────────────────────────────────────────────

export interface OAuth2Client {
  id: string;
  client_id: string;
  name: string;
  redirect_uris: string[];
  grant_types: string[];
  scopes: string[];
  is_public: boolean;
  created_at: string;
}

// ─── Request payloads ─────────────────────────────────────────────────────────

export interface CreateOAuth2ClientPayload {
  name: string;
  redirect_uris: string[];
  grant_types: string[];
  scopes?: string[];
  is_public?: boolean;
}

export interface UpdateOAuth2ClientPayload {
  name?: string;
  redirect_uris?: string[];
  grant_types?: string[];
  scopes?: string[];
  is_public?: boolean;
}

// ─── Response types ───────────────────────────────────────────────────────────

export interface CreateOAuth2ClientResponse {
  client: OAuth2Client;
  client_secret: string;
}

// ─── Available options ────────────────────────────────────────────────────────

export const GRANT_TYPES = [
  "authorization_code",
  "client_credentials",
  "refresh_token",
] as const;

export type GrantType = (typeof GRANT_TYPES)[number];

export const OAUTH2_SCOPES = [
  "openid",
  "profile",
  "email",
  "offline_access",
] as const;

export type OAuth2Scope = (typeof OAUTH2_SCOPES)[number];

// ─── Service ──────────────────────────────────────────────────────────────────

export const oauth2ClientService = {
  list: (): Promise<OAuth2Client[]> =>
    api.get<OAuth2Client[]>("/api/v1/oauth2-clients").then((r) => r.data),

  create: (payload: CreateOAuth2ClientPayload): Promise<CreateOAuth2ClientResponse> =>
    api
      .post<CreateOAuth2ClientResponse>("/api/v1/oauth2-clients", payload)
      .then((r) => r.data),

  get: (id: string): Promise<OAuth2Client> =>
    api.get<OAuth2Client>(`/api/v1/oauth2-clients/${id}`).then((r) => r.data),

  update: (id: string, payload: UpdateOAuth2ClientPayload): Promise<OAuth2Client> =>
    api
      .put<OAuth2Client>(`/api/v1/oauth2-clients/${id}`, payload)
      .then((r) => r.data),

  remove: (id: string): Promise<void> =>
    api.delete(`/api/v1/oauth2-clients/${id}`).then(() => undefined),
};
