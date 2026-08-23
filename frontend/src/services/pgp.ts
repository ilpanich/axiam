import api from "@/lib/api";
import { fetchAllPages } from "@/services/_pagination";

// ─── Backend enums (PascalCase — serde default, no rename) ──────────────────────

export type PgpKeyAlgorithm = "Rsa4096" | "Ed25519";
export type PgpKeyPurpose = "AuditSigning" | "Export";
export type PgpKeyStatus = "Active" | "Revoked";

// ─── Domain Models ────────────────────────────────────────────────────────────

/**
 * PGP key as serialized by the backend
 * (`axiam_core::models::pgp_key::PgpKey`). `encrypted_private_key` is
 * `skip_serializing` server-side and never reaches the client.
 */
export interface PgpKey {
  id: string;
  tenant_id: string;
  name: string;
  purpose: PgpKeyPurpose;
  public_key_armored: string;
  fingerprint: string;
  algorithm: PgpKeyAlgorithm;
  status: PgpKeyStatus;
  created_at: string;
}

// ─── Request payloads ─────────────────────────────────────────────────────────

/**
 * Matches `CreatePgpKeyRequest`
 * (crates/axiam-api-rest/src/handlers/pgp_keys.rs). `tenant_id` is taken
 * from the authenticated session server-side and must NOT be sent.
 */
export interface GeneratePgpKeyPayload {
  name: string;
  email: string;
  purpose: PgpKeyPurpose;
  algorithm: PgpKeyAlgorithm;
}

/** Matches `EncryptRequest` — plaintext is base64-encoded. */
export interface EncryptPayload {
  data_base64: string;
}

/** Matches `SignAuditBatchRequest`. */
export interface SignAuditBatchPayload {
  entry_ids: string[];
}

// ─── Response types ───────────────────────────────────────────────────────────

/**
 * Matches `GeneratedPgpKey` (flattened key + optional armored private key).
 * `private_key_armored` is only present for `Export`-purpose keys; it is
 * omitted entirely for `AuditSigning` keys.
 */
export interface GeneratePgpKeyResponse extends PgpKey {
  private_key_armored?: string;
}

/** Matches `EncryptedExport`. */
export interface EncryptResponse {
  recipient_key_id: string;
  ciphertext_armored: string;
}

/** Matches `SignedAuditBatch`. */
export interface SignAuditBatchResponse {
  batch_id: string;
  tenant_id: string;
  signing_key_id: string;
  entry_ids: string[];
  signature_armored: string;
  signed_at: string;
}

// ─── Service ──────────────────────────────────────────────────────────────────

export const pgpService = {
  list: (): Promise<PgpKey[]> => fetchAllPages<PgpKey>("/api/v1/pgp-keys"),

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
