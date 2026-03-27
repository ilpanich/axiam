import api from "@/lib/api";

// ─── Domain Models ────────────────────────────────────────────────────────────

export interface ServiceAccount {
  id: string;
  name: string;
  description?: string;
  client_id: string;
  status: "active" | "disabled";
  roles: string[];
  last_used_at?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateServiceAccountRequest {
  name: string;
  description?: string;
  roles?: string[];
}

export interface UpdateServiceAccountRequest {
  name?: string;
  description?: string;
  status?: "active" | "disabled";
  roles?: string[];
}

export interface ServiceAccountCreatedResponse {
  service_account: ServiceAccount;
  client_secret: string;
}

export interface RotateSecretResponse {
  client_id: string;
  client_secret: string;
}

// ─── Service ──────────────────────────────────────────────────────────────────

const BASE = "/api/v1/service-accounts";

export const serviceAccountService = {
  getAll: (): Promise<ServiceAccount[]> =>
    api.get<ServiceAccount[]>(BASE).then((r) => r.data),

  create: (
    data: CreateServiceAccountRequest
  ): Promise<ServiceAccountCreatedResponse> =>
    api
      .post<ServiceAccountCreatedResponse>(BASE, data)
      .then((r) => r.data),

  getById: (id: string): Promise<ServiceAccount> =>
    api.get<ServiceAccount>(`${BASE}/${id}`).then((r) => r.data),

  update: (
    id: string,
    data: UpdateServiceAccountRequest
  ): Promise<ServiceAccount> =>
    api.put<ServiceAccount>(`${BASE}/${id}`, data).then((r) => r.data),

  delete: (id: string): Promise<void> =>
    api.delete(`${BASE}/${id}`).then(() => undefined),

  rotateSecret: (id: string): Promise<RotateSecretResponse> =>
    api
      .post<RotateSecretResponse>(`${BASE}/${id}/rotate-secret`)
      .then((r) => r.data),
};
