import api from "@/lib/api";
import { unwrapList } from "@/services/_pagination";

// ─── Domain Models ────────────────────────────────────────────────────────────

/** Backend protocol discriminator (exact strings from `protocol_to_string`). */
export type FederationProtocol = "OidcConnect" | "Saml";

/**
 * Server → client representation of a federation config.
 * Note: `client_secret` is write-only and is NEVER returned by the backend.
 */
export interface FederationConfig {
  id: string;
  tenant_id: string;
  provider: string;
  protocol: string;
  metadata_url: string | null;
  client_id: string;
  attribute_map: unknown;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

/** Client → server payload for creating a federation config. */
export interface CreateFederationConfigRequest {
  provider: string;
  protocol: FederationProtocol;
  metadata_url?: string | null;
  client_id: string;
  client_secret: string;
  attribute_map?: unknown;
  idp_signing_cert_pem?: string | null;
  allowed_algorithms?: string[];
}

/** Client → server payload for updating a federation config (all fields optional). */
export interface UpdateFederationConfigRequest {
  provider?: string;
  metadata_url?: string | null;
  client_id?: string;
  client_secret?: string;
  attribute_map?: unknown;
  enabled?: boolean;
  idp_signing_cert_pem?: string | null;
  allowed_algorithms?: string[];
}

// ─── Service ──────────────────────────────────────────────────────────────────

const BASE = "/api/v1/federation-configs";

export const federationService = {
  getAll: (): Promise<FederationConfig[]> =>
    api
      .get<FederationConfig[] | { items: FederationConfig[] }>(BASE)
      .then((r) => unwrapList(r.data)),

  create: (data: CreateFederationConfigRequest): Promise<FederationConfig> =>
    api.post<FederationConfig>(BASE, data).then((r) => r.data),

  getById: (id: string): Promise<FederationConfig> =>
    api.get<FederationConfig>(`${BASE}/${id}`).then((r) => r.data),

  update: (
    id: string,
    data: UpdateFederationConfigRequest,
  ): Promise<FederationConfig> =>
    api.put<FederationConfig>(`${BASE}/${id}`, data).then((r) => r.data),

  remove: (id: string): Promise<void> =>
    api.delete(`${BASE}/${id}`).then(() => undefined),
};
