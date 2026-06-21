import api from "@/lib/api";
import { unwrapList } from "@/services/_pagination";
import { orgService } from "@/services/organizations";

// ─── Backend enums (PascalCase — serde default, no rename) ──────────────────────

export type KeyAlgorithm = "Rsa4096" | "Ed25519";
export type CertificateType = "User" | "Service" | "Device";
export type CertificateStatus = "Active" | "Revoked" | "Expired";

// ─── Domain Models ────────────────────────────────────────────────────────────

/**
 * Tenant certificate as serialized by the backend
 * (`axiam_core::models::certificate::Certificate`).
 */
export interface Certificate {
  id: string;
  tenant_id: string;
  issuer_ca_id: string;
  subject: string;
  public_cert_pem: string;
  fingerprint: string;
  cert_type: CertificateType;
  key_algorithm: KeyAlgorithm;
  not_before: string;
  not_after: string;
  status: CertificateStatus;
  metadata: unknown;
  created_at: string;
}

/**
 * Organization CA certificate as serialized by the backend
 * (`axiam_core::models::certificate::CaCertificate`). Only the fields the
 * certificate page consumes are typed here.
 */
export interface CaCertificateOption {
  id: string;
  organization_id: string;
  subject: string;
  fingerprint: string;
  key_algorithm: KeyAlgorithm;
  not_after: string;
  status: CertificateStatus;
  created_at: string;
}

// ─── Request payloads ─────────────────────────────────────────────────────────

/**
 * Matches `CreateCertificateRequest`
 * (crates/axiam-api-rest/src/handlers/certificates.rs). `tenant_id` is taken
 * from the authenticated session server-side and must NOT be sent.
 */
export interface GenerateCertificatePayload {
  issuer_ca_id: string;
  subject: string;
  cert_type: CertificateType;
  key_algorithm: KeyAlgorithm;
  validity_days: number;
  metadata?: Record<string, unknown>;
}

// ─── Response types ───────────────────────────────────────────────────────────

/** Matches `GeneratedCertificate` (flattened certificate + private key PEM). */
export interface GenerateCertificateResponse extends Certificate {
  private_key_pem: string;
}

// ─── Service ──────────────────────────────────────────────────────────────────

export const certificateService = {
  list: (): Promise<Certificate[]> =>
    api
      .get<Certificate[] | { items: Certificate[] }>("/api/v1/certificates")
      .then((r) => unwrapList(r.data)),

  generate: (
    payload: GenerateCertificatePayload
  ): Promise<GenerateCertificateResponse> =>
    api
      .post<GenerateCertificateResponse>("/api/v1/certificates", payload)
      .then((r) => r.data),

  get: (id: string): Promise<Certificate> =>
    api.get<Certificate>(`/api/v1/certificates/${id}`).then((r) => r.data),

  revoke: (id: string): Promise<void> =>
    api.post(`/api/v1/certificates/${id}/revoke`).then(() => undefined),

  /**
   * List the Active CA certificates for the caller's organization.
   *
   * The CA endpoint is org-scoped (`GET /api/v1/organizations/{org_id}/
   * ca-certificates`) and the backend rejects any org other than the
   * caller's own. The auth store only carries the org *slug*, so we resolve
   * the org UUID from the organizations list (the caller can only see their
   * own org) and then fetch its CAs. Only `Active` CAs can sign new certs.
   */
  listSigningCas: async (orgSlug?: string): Promise<CaCertificateOption[]> => {
    const orgs = await orgService.list();
    const org = orgSlug
      ? orgs.find((o) => o.slug === orgSlug)
      : orgs[0];
    if (!org) return [];
    const res = await api.get<
      CaCertificateOption[] | { items: CaCertificateOption[] }
    >(`/api/v1/organizations/${org.id}/ca-certificates`);
    return unwrapList(res.data).filter((ca) => ca.status === "Active");
  },
};
