import api from "@/lib/api";
import { unwrapList } from "@/services/_pagination";

// ─── Domain Models ────────────────────────────────────────────────────────────

/** Backend protocol discriminator (exact strings from `protocol_to_string`). */
export type FederationProtocol = "OidcConnect" | "Saml";

/** How an unlinked external subject is handled (X4). */
export type SubjectMapping = "linked_only" | "jit_provision";

/**
 * X4 — trust for exchanging this provider's tokens (RFC 8693, external issuer).
 *
 * Read the server's own guide before changing any of it:
 * `docs/api/federated-token-exchange.md`. Two fields decide the blast radius:
 * `accepted_audiences` (a token not addressed to us is one we captured, not one
 * we were given) and `scope_map` (deny-by-default — an unmapped partner
 * assertion grants nothing, and there is no passthrough).
 */
export interface TokenExchangeTrust {
  enabled: boolean;
  accepted_audiences: string[];
  subject_mapping: SubjectMapping;
  /** Partner assertion → AXIAM scopes. */
  scope_map: Record<string, string[]>;
  max_token_age_secs: number;
  max_lifetime_secs?: number | null;
}

/** Server default: off, trusting nothing. Mirrors `TokenExchangeTrust::default()`. */
export const DEFAULT_TOKEN_EXCHANGE_TRUST: TokenExchangeTrust = {
  enabled: false,
  accepted_audiences: [],
  subject_mapping: "linked_only",
  scope_map: {},
  max_token_age_secs: 300,
  max_lifetime_secs: null,
};

/** Server-side bounds on `max_token_age_secs` (`axiam_core::models::federation`). */
export const MAX_TOKEN_AGE_CEILING_SECS = 3600;

/**
 * Client-side mirror of `TokenExchangeTrust::validate`.
 *
 * The server is the authority and rejects the same cases; this exists so an
 * operator finds out before they submit, not so the server can skip checking.
 * Returns a human-readable reason, or `null` when the block is acceptable.
 */
export function validateTokenExchangeTrust(
  t: TokenExchangeTrust,
): string | null {
  if (t.enabled && t.accepted_audiences.length === 0) {
    return "At least one accepted audience is required to enable token exchange — there is deliberately no accept-all value.";
  }
  if (t.accepted_audiences.some((a) => a.trim() === "")) {
    return "Accepted audiences must not contain blank entries.";
  }
  if (
    !Number.isInteger(t.max_token_age_secs) ||
    t.max_token_age_secs < 1 ||
    t.max_token_age_secs > MAX_TOKEN_AGE_CEILING_SECS
  ) {
    return `Maximum token age must be a whole number between 1 and ${MAX_TOKEN_AGE_CEILING_SECS} seconds.`;
  }
  if (
    t.max_lifetime_secs !== null &&
    t.max_lifetime_secs !== undefined &&
    t.max_lifetime_secs < 1
  ) {
    return "Maximum issued-token lifetime must be positive.";
  }
  for (const [key, scopes] of Object.entries(t.scope_map)) {
    if (key.trim() === "") {
      return "Scope-map keys must not be blank.";
    }
    if (scopes.length === 0) {
      return `Scope-map entry "${key}" maps to no AXIAM scopes — remove the entry instead.`;
    }
    if (scopes.some((s) => s.trim() === "")) {
      return `Scope-map entry "${key}" maps to a blank scope name.`;
    }
  }
  return null;
}

/**
 * Server → client representation of a federation config.
 * Note: `client_secret` is write-only and is NEVER returned by the backend.
 */
export interface FederationConfig {
  id: string;
  tenant_id: string;
  provider: string;
  protocol: string;
  metadata_url: string | null;
  client_id: string;
  attribute_map: unknown;
  enabled: boolean;
  /** X4. Always present on responses; absent on pre-X4 servers. */
  token_exchange?: TokenExchangeTrust;
  created_at: string;
  updated_at: string;
}

/** Client → server payload for creating a federation config. */
export interface CreateFederationConfigRequest {
  provider: string;
  protocol: FederationProtocol;
  metadata_url?: string | null;
  client_id: string;
  client_secret: string;
  attribute_map?: unknown;
  idp_signing_cert_pem?: string | null;
  allowed_algorithms?: string[];
  token_exchange?: TokenExchangeTrust;
}

/** Client → server payload for updating a federation config (all fields optional). */
export interface UpdateFederationConfigRequest {
  provider?: string;
  metadata_url?: string | null;
  client_id?: string;
  client_secret?: string;
  attribute_map?: unknown;
  enabled?: boolean;
  idp_signing_cert_pem?: string | null;
  allowed_algorithms?: string[];
  /**
   * Replaced **wholesale** by the server when present — never merged field by
   * field. Send the complete block, not a patch: a partial merge of a trust
   * configuration is how an operator ends up keeping an accepted audience they
   * believed they had removed.
   */
  token_exchange?: TokenExchangeTrust;
}

// ─── Service ──────────────────────────────────────────────────────────────────

const BASE = "/api/v1/federation-configs";

export const federationService = {
  getAll: (): Promise<FederationConfig[]> =>
    api
      .get<FederationConfig[] | { items: FederationConfig[] }>(BASE)
      .then((r) => unwrapList(r.data)),

  create: (data: CreateFederationConfigRequest): Promise<FederationConfig> =>
    api.post<FederationConfig>(BASE, data).then((r) => r.data),

  getById: (id: string): Promise<FederationConfig> =>
    api.get<FederationConfig>(`${BASE}/${id}`).then((r) => r.data),

  update: (
    id: string,
    data: UpdateFederationConfigRequest,
  ): Promise<FederationConfig> =>
    api.put<FederationConfig>(`${BASE}/${id}`, data).then((r) => r.data),

  remove: (id: string): Promise<void> =>
    api.delete(`${BASE}/${id}`).then(() => undefined),
};
