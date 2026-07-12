import api from "@/lib/api";
import { unwrapList } from "@/services/_pagination";

// ─── Domain Models ────────────────────────────────────────────────────────────

export interface ServiceAccount {
  id: string;
  tenant_id: string;
  name: string;
  /** Optional human-readable description of the account's purpose. */
  description?: string | null;
  client_id: string;
  /** Backend `UserStatus` enum, serialized PascalCase ("Active", "Inactive", …). */
  status: string;
  created_at: string;
  updated_at: string;
}

export interface CreateServiceAccountRequest {
  name: string;
  description?: string;
}

export interface UpdateServiceAccountRequest {
  name?: string;
  description?: string;
  /** Backend `UserStatus`, e.g. "Active" / "Inactive". */
  status?: string;
}

/** Flat response — the secret is shown once at creation. */
export interface ServiceAccountCreatedResponse {
  id: string;
  tenant_id: string;
  name: string;
  description?: string | null;
  client_id: string;
  client_secret: string;
  status: string;
  created_at: string;
  updated_at: string;
}

/** Rotation returns only the new secret; client_id is unchanged. */
export interface RotateSecretResponse {
  client_secret: string;
}

// ─── Service ──────────────────────────────────────────────────────────────────

const BASE = "/api/v1/service-accounts";

export const serviceAccountService = {
  getAll: (): Promise<ServiceAccount[]> =>
    api
      .get<ServiceAccount[] | { items: ServiceAccount[] }>(BASE)
      .then((r) => unwrapList(r.data)),

  create: (
    data: CreateServiceAccountRequest,
  ): Promise<ServiceAccountCreatedResponse> =>
    api.post<ServiceAccountCreatedResponse>(BASE, data).then((r) => r.data),

  getById: (id: string): Promise<ServiceAccount> =>
    api.get<ServiceAccount>(`${BASE}/${id}`).then((r) => r.data),

  update: (
    id: string,
    data: UpdateServiceAccountRequest,
  ): Promise<ServiceAccount> =>
    api.put<ServiceAccount>(`${BASE}/${id}`, data).then((r) => r.data),

  remove: (id: string): Promise<void> =>
    api.delete(`${BASE}/${id}`).then(() => undefined),

  rotateSecret: (id: string): Promise<RotateSecretResponse> =>
    api
      .post<RotateSecretResponse>(`${BASE}/${id}/rotate-secret`)
      .then((r) => r.data),
};
