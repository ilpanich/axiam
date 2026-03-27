import api from "@/lib/api";

// ─── Domain Models ────────────────────────────────────────────────────────────

export interface Certificate {
  id: string;
  common_name: string;
  key_type: string;
  status: "active" | "revoked";
  expires_at: string;
  serial_number: string;
  created_at: string;
}

// ─── Request payloads ─────────────────────────────────────────────────────────

export interface GenerateCertificatePayload {
  common_name: string;
  key_type: "RSA4096" | "Ed25519";
  validity_days: number;
  san_dns?: string[];
  san_ip?: string[];
}

// ─── Response types ───────────────────────────────────────────────────────────

export interface GenerateCertificateResponse {
  certificate: Certificate;
  private_key_pem: string;
}

// ─── Service ──────────────────────────────────────────────────────────────────

export const certificateService = {
  list: (): Promise<Certificate[]> =>
    api.get<Certificate[]>("/api/v1/certificates").then((r) => r.data),

  generate: (
    payload: GenerateCertificatePayload
  ): Promise<GenerateCertificateResponse> =>
    api
      .post<GenerateCertificateResponse>("/api/v1/certificates", payload)
      .then((r) => r.data),

  get: (id: string): Promise<Certificate> =>
    api.get<Certificate>(`/api/v1/certificates/${id}`).then((r) => r.data),

  revoke: (id: string): Promise<void> =>
    api
      .post(`/api/v1/certificates/${id}/revoke`)
      .then(() => undefined),
};
