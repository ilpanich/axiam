import api from "@/lib/api";

// ─── T21.4 — RFC 7591 initial access tokens ────────────────────────────────
//
// `POST /api/v1/oauth2-clients/registration-tokens` mints the single-use
// credential the `initial_access_token` dynamic-registration mode requires.
// Source of truth: `crates/axiam-api-rest/src/handlers/dcr.rs`
// (`RegistrationTokenResponse`, `CreateRegistrationTokenResponse`).

/** Metadata only — the plaintext handle is never returned again after minting. */
export interface RegistrationToken {
  id: string;
  tenant_id: string;
  name: string;
  created_by: string;
  expires_at: string;
  used_at: string | null;
  /** Reserved; always absent in this build — see the backend doc comment. */
  used_by_client_id?: string;
  created_at: string;
}

export interface CreateRegistrationTokenPayload {
  name: string;
  /** Defaults to 24 on the server; refused above 168 (a week). */
  expires_in_hours?: number;
}

/** The one response that carries the plaintext handle, shown exactly once. */
export interface CreateRegistrationTokenResponse {
  token: RegistrationToken;
  initial_access_token: string;
}

export const DEFAULT_REGISTRATION_TOKEN_TTL_HOURS = 24;
export const MAX_REGISTRATION_TOKEN_TTL_HOURS = 168;

export const registrationTokenService = {
  /** `GET /api/v1/oauth2-clients/registration-tokens` — a bare array, not paginated. */
  list: (): Promise<RegistrationToken[]> =>
    api
      .get<RegistrationToken[]>("/api/v1/oauth2-clients/registration-tokens")
      .then((r) => r.data),

  create: (
    payload: CreateRegistrationTokenPayload
  ): Promise<CreateRegistrationTokenResponse> =>
    api
      .post<CreateRegistrationTokenResponse>(
        "/api/v1/oauth2-clients/registration-tokens",
        payload
      )
      .then((r) => r.data),
};
