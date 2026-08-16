import api from "@/lib/api";
import { unwrapList } from "@/services/_pagination";

// ─── Domain models ────────────────────────────────────────────────────────────

/**
 * Why a token is or is not currently usable. Display only — the
 * `/scim/v2` authentication path answers one 401 for every rejection and does
 * not distinguish these on the wire.
 */
export type ScimTokenStatus = "active" | "expired" | "revoked";

/**
 * A SCIM provisioning token, as the admin API returns it: metadata only.
 *
 * The handle itself appears exactly once, in
 * {@link CreateScimTokenResponse.provisioning_token}, and only its SHA-256 is
 * stored — so there is deliberately no field here that could carry it.
 */
export interface ScimToken {
  id: string;
  tenant_id: string;
  /**
   * The tenant user this token authenticates as. The token carries no
   * permissions of its own; this user's RBAC decides what it may do, which is
   * why revoking their role disables the token too.
   */
  user_id: string;
  name: string;
  created_by: string;
  status: ScimTokenStatus;
  expires_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
  created_at: string;
}

export interface CreateScimTokenPayload {
  name: string;
  user_id: string;
  /** Defaults server-side to the deployment maximum; refused above it. */
  expires_in_days?: number;
}

export interface CreateScimTokenResponse extends ScimToken {
  /** Shown once. Never retrievable again. */
  provisioning_token: string;
}

/**
 * Deployment ceiling, mirrored from `DEFAULT_MAX_LIFETIME_DAYS`.
 *
 * Only a UI default for the expiry input — the server holds the real limit
 * (`AXIAM__SCIM_TOKEN_MAX_LIFETIME_DAYS`) and refuses anything above it, so a
 * deployment that lowered it still rejects an over-long request rather than
 * trusting this number.
 */
export const DEFAULT_MAX_LIFETIME_DAYS = 365;

/** The permission a token's bound user must hold to be able to do anything. */
export const SCIM_PROVISION_PERMISSION = "scim:provision";

// ─── Service ──────────────────────────────────────────────────────────────────

const BASE = "/api/v1/scim-tokens";

export const scimTokenService = {
  list: (): Promise<ScimToken[]> =>
    api
      .get<ScimToken[] | { items: ScimToken[] }>(BASE)
      .then((r) => unwrapList(r.data)),

  create: (payload: CreateScimTokenPayload): Promise<CreateScimTokenResponse> =>
    api.post<CreateScimTokenResponse>(BASE, payload).then((r) => r.data),

  revoke: (id: string): Promise<void> =>
    api.delete(`${BASE}/${id}`).then(() => undefined),
};
