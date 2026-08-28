import api from "@/lib/api";
import { fetchAllPages } from "@/services/_pagination";

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
  /**
   * The service account this certificate authenticates, or `null`.
   *
   * Present on list responses (`CertificateWithBinding` on the wire). The
   * binding is a graph edge server-side, so before it was projected here there
   * was no way for any page to show whether a certificate was bound — you could
   * bind one and find no trace of it in the product.
   */
  bound_service_account_id?: string | null;
}

/** The bind endpoint's acknowledgement. */
export interface CertificateBinding {
  certificate_id: string;
  service_account_id: string;
  status: string;
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
    fetchAllPages<Certificate>("/api/v1/certificates"),

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
   * Bind an existing tenant certificate to a service account, so that account
   * can authenticate by mTLS instead of (or as well as) its client secret.
   *
   * Routed under the service account rather than the certificate
   * (`POST /api/v1/service-accounts/{sa_id}/bind-certificate`) but handled by
   * the certificates module, which is why it lives here. Gated on
   * `certificates:bind`.
   */
  bindToServiceAccount: (
    serviceAccountId: string,
    certificateId: string
  ): Promise<CertificateBinding> =>
    api
      .post<CertificateBinding>(
        `/api/v1/service-accounts/${serviceAccountId}/bind-certificate`,
        { certificate_id: certificateId }
      )
      .then((r) => r.data),

  /**
   * List the Active CA certificates a tenant may issue under.
   *
   * These are the **organization's** CAs, inherited by every tenant beneath it:
   * a CA is an organization-scoped asset (`ca_certificate.organization_id`) and
   * every tenant in that organization issues under it, directly or through its
   * own signing CA — that inheritance is what makes one organization CA a usable
   * trust anchor across the whole estate.
   *
   * Addressed by organization id, taken from `/auth/me`. It used to be resolved
   * by listing `GET /api/v1/organizations` and matching on slug, and that list
   * is restricted to `super-admin`: for any tenant administrator below that
   * role, the call 403'd, this function returned nothing, and the certificates
   * page reported that the organization had no CA — while the organization
   * plainly had one. Nothing about listing every organization was ever needed
   * here; only the caller's own id, which the session already carries.
   *
   * Only `Active` CAs can sign new certificates.
   */
  listSigningCas: async (orgId?: string): Promise<CaCertificateOption[]> => {
    if (!orgId) return [];
    const cas = await fetchAllPages<CaCertificateOption>(
      `/api/v1/organizations/${orgId}/ca-certificates`
    );
    return cas.filter((ca) => ca.status === "Active");
  },
};
