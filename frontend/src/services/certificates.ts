import api from "@/lib/api";
import { fetchAllPages } from "@/services/_pagination";

// ─── Backend enums (PascalCase — serde default, no rename) ──────────────────────

export type KeyAlgorithm = "Rsa4096" | "Ed25519";
/**
 * `Server` (S-7) is the one type that carries `subjectAltName` and
 * `extendedKeyUsage: serverAuth`. It authenticates nobody: the server refuses
 * to bind one to a service account and device login refuses it.
 */
export type CertificateType = "User" | "Service" | "Device" | "Server";
export type CertificateStatus = "Active" | "Revoked" | "Expired";

/**
 * One name in a `Server` certificate's `subjectAltName`, exactly as the server
 * deserialises `SubjectAltName` (`crates/axiam-core/src/models/certificate.rs`,
 * `rename_all = "snake_case"`): `{ "dns": "api.lakeside.internal" }` or
 * `{ "ip": "10.0.0.5" }`. URI and e-mail names are not offered server-side.
 */
export type SubjectAltName = { dns: string } | { ip: string };

/** The kind of one SAN row in the form. */
export type SubjectAltNameKind = "dns" | "ip";

/** One editable row of the SAN list: a kind and the text typed for it. */
export interface SubjectAltNameRow {
  kind: SubjectAltNameKind;
  value: string;
}

/**
 * Turn the form's SAN rows into the request field — checking **shape only**.
 *
 * The rules here are the two the form owns: a `Server` request states at least
 * one name, and every row is a non-empty `dns` or `ip` value. Surrounding
 * whitespace is trimmed, as it is for the subject.
 *
 * Everything else is deliberately left to the server, which is the one
 * authority on names: whether a name is admitted by the tenant's
 * `server_cert_allowed_names`, whether a wildcard is a whole leftmost label,
 * whether an IP literal parses, whether a label is a Unicode U-label, whether
 * there is a trailing dot or an IPv4-mapped IPv6 address. Its 400 names the
 * offending entry and the remedy, and the form shows it verbatim. A second
 * matcher here could only ever disagree with the first.
 */
export function subjectAltNamesFromRows(
  rows: SubjectAltNameRow[]
): { names: SubjectAltName[] } | { error: string } {
  if (rows.length === 0) {
    return {
      error:
        "A Server certificate needs at least one subject alternative name (a DNS name or an IP address).",
    };
  }
  const names: SubjectAltName[] = [];
  for (const [i, row] of rows.entries()) {
    const value = row.value.trim();
    if (value.length === 0) {
      return {
        error: `Subject alternative name ${i + 1} is empty — enter a name or remove the row.`,
      };
    }
    if (row.kind === "dns") names.push({ dns: value });
    else if (row.kind === "ip") names.push({ ip: value });
    else
      return {
        error: `Subject alternative name ${i + 1} must be a DNS name or an IP address.`,
      };
  }
  return { names };
}

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
  /**
   * S-7. Required for `cert_type: "Server"` and refused for every other type,
   * so the form sends the key only for `Server` — every other request body is
   * byte-for-byte what it was before the field existed.
   */
  subject_alt_names?: SubjectAltName[];
}

/**
 * Matches `SignCertificateCsrRequest`
 * (crates/axiam-api-rest/src/handlers/certificates.rs). No `subject` and no
 * `key_algorithm`: both are read out of the CSR server-side, which is the only
 * place they can be stated without the row and the certificate being able to
 * disagree. `tenant_id` is taken from the authenticated session and must NOT
 * be sent, exactly as for `GenerateCertificatePayload`.
 */
export interface SignCsrPayload {
  issuer_ca_id: string;
  /**
   * PEM-encoded PKCS#10 request — a `BEGIN CERTIFICATE REQUEST` block. The
   * legacy OpenSSL `BEGIN NEW CERTIFICATE REQUEST` header is not accepted.
   */
  csr_pem: string;
  cert_type: CertificateType;
  validity_days: number;
  metadata?: Record<string, unknown>;
  /**
   * S-7, as on `GenerateCertificatePayload`. Stated here and never in the CSR,
   * which is still refused if it asks for a `subjectAltName`. Under a CA whose
   * key Vault holds, the server refuses a `Server` request on this path by
   * design; the form shows that 400 as it comes.
   */
  subject_alt_names?: SubjectAltName[];
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

  /**
   * Issue an end-entity certificate for a key AXIAM never sees. The response
   * is a plain [`Certificate`] — never `GenerateCertificateResponse` — because
   * there is no key to return and no field to leave empty; a type with a
   * mandatory key field that is always absent is a type that lies.
   */
  signCsr: (payload: SignCsrPayload): Promise<Certificate> =>
    api
      .post<Certificate>("/api/v1/certificates/sign-csr", payload)
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
