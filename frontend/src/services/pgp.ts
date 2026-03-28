import api from "@/lib/api";

// ─── Domain Models ────────────────────────────────────────────────────────────

export interface PgpKey {
  id: string;
  user_id: string;
  key_type: string;
  fingerprint: string;
  description?: string;
  status: "active" | "revoked";
  public_key_armor: string;
  created_at: string;
}

// ─── Request payloads ─────────────────────────────────────────────────────────

export interface GeneratePgpKeyPayload {
  user_id: string;
  key_type: "Ed25519Legacy" | "RSA4096";
  description?: string;
}

export interface EncryptPayload {
  data: string;
}

export interface SignAuditBatchPayload {
  audit_log_ids: string[];
}

// ─── Response types ───────────────────────────────────────────────────────────

export interface GeneratePgpKeyResponse {
  pgp_key: PgpKey;
  private_key_armor: string;
}

export interface EncryptResponse {
  encrypted: string;
}

export interface SignAuditBatchResponse {
  signature: string;
}

// ─── Service ──────────────────────────────────────────────────────────────────

export const pgpService = {
  list: (): Promise<PgpKey[]> =>
    api.get<PgpKey[]>("/api/v1/pgp-keys").then((r) => r.data),

  generate: (payload: GeneratePgpKeyPayload): Promise<GeneratePgpKeyResponse> =>
    api
      .post<GeneratePgpKeyResponse>("/api/v1/pgp-keys", payload)
      .then((r) => r.data),

  get: (id: string): Promise<PgpKey> =>
    api.get<PgpKey>(`/api/v1/pgp-keys/${id}`).then((r) => r.data),

  revoke: (id: string): Promise<void> =>
    api.post(`/api/v1/pgp-keys/${id}/revoke`).then(() => undefined),

  encrypt: (id: string, payload: EncryptPayload): Promise<EncryptResponse> =>
    api
      .post<EncryptResponse>(`/api/v1/pgp-keys/${id}/encrypt`, payload)
      .then((r) => r.data),

  signAuditBatch: (
    payload: SignAuditBatchPayload
  ): Promise<SignAuditBatchResponse> =>
    api
      .post<SignAuditBatchResponse>("/api/v1/pgp-keys/sign-audit-batch", payload)
      .then((r) => r.data),
};
