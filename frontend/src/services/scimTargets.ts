import api from "@/lib/api";
import { fetchAllPages } from "@/services/_pagination";

/**
 * Outbound SCIM target administration client (G-6, T23.6.4).
 *
 * Source of truth for every shape below: contract §31 (`sdks/CONTRACT.md`,
 * "Outbound SCIM targets"), `sdks/openapi.json` (tag `scim-targets`) and the
 * handler `crates/axiam-api-rest/src/handlers/scim_targets.rs`.
 *
 * # What is deliberately absent
 *
 * - **No credential on any response type.** The bearer token or OAuth2 client
 *   secret is write-only: the server never returns it, and says nothing about
 *   it either (no "is set" flag, no length). A type with a member for it would
 *   lie about every value it holds (§31.2).
 * - **No client-side URL policy beyond the obvious.** The server holds
 *   `base_url` and `token_url` to the webhook outbound address policy and the
 *   delivery-time guard is the real one; the console only checks that a URL is
 *   an absolute `https` URL, so a typo fails in the form rather than as a `400`.
 */

export const SCIM_TARGETS_URL = "/api/v1/scim-targets";

// ─── Bounds (mirror the handler's constants) ──────────────────────────────────

export const SCIM_TARGET_BOUNDS = {
  nameBytes: 128,
  scopeGroups: 100,
  credentialBytes: 4096,
  clientIdBytes: 256,
  oauthScopeBytes: 256,
  urlBytes: 2048,
} as const;

// ─── Domain types ─────────────────────────────────────────────────────────────

export const AUTH_KINDS = ["bearer", "oauth2_client_credentials"] as const;
export type AuthKind = (typeof AUTH_KINDS)[number];

export const AUTH_KIND_LABELS: Record<AuthKind, string> = {
  bearer: "Bearer token",
  oauth2_client_credentials: "OAuth 2.0 client credentials",
};

/** How AXIAM authenticates to the downstream — never the credential itself. */
export type ScimTargetAuth =
  | { type: "bearer" }
  | {
      type: "oauth2_client_credentials";
      token_url: string;
      client_id: string;
      scope?: string | null;
    };

export type ScimTargetScope =
  | { type: "all_users" }
  | { type: "groups"; group_ids: string[] };

export const USER_NAME_SOURCES = ["username", "email"] as const;
export type UserNameSource = (typeof USER_NAME_SOURCES)[number];

export const USER_NAME_SOURCE_LABELS: Record<UserNameSource, string> = {
  username: "Username",
  email: "E-mail address",
};

export const DEPROVISION_POLICIES = ["deactivate", "delete"] as const;
export type DeprovisionPolicy = (typeof DEPROVISION_POLICIES)[number];

export const DEPROVISION_LABELS: Record<DeprovisionPolicy, string> = {
  deactivate: "Deactivate (set active = false)",
  delete: "Delete the downstream account",
};

/** What the deliverer and the reconciliation job record about a target. */
export interface ScimTargetDeliveryState {
  last_success_at: string | null;
  last_failure_at: string | null;
  /** A fixed vocabulary of short phrases chosen by the server. Never parsed. */
  last_failure_reason: string | null;
  consecutive_failures: number;
  dead_lettered_total: number;
  last_reconciled_at: string | null;
}

/** What every read and write returns. */
export interface ScimTarget {
  id: string;
  tenant_id: string;
  name: string;
  base_url: string;
  enabled: boolean;
  auth: ScimTargetAuth;
  scope: ScimTargetScope;
  push_groups: boolean;
  /** Open on the way out. */
  user_name_from: string;
  /** Open on the way out. */
  deprovision: string;
  created_at: string;
  /** The version an update is conditional on (a `409` when overtaken). */
  updated_at: string;
  state: ScimTargetDeliveryState | null;
}

/** `create` and `update` (a replacement) body. */
export interface ScimTargetInput {
  name: string;
  base_url: string;
  enabled: boolean;
  auth: ScimTargetAuth;
  /**
   * Write-only. Required on create. On update, omit to keep the stored one —
   * except that moving it to another URL or switching `auth.type` requires it
   * again ({@link credentialRequiredFor}).
   */
  credential?: string;
  scope: ScimTargetScope;
  push_groups: boolean;
  user_name_from: UserNameSource;
  deprovision: DeprovisionPolicy;
  /**
   * Update only. The {@link ScimTarget.updated_at} the form was opened from: the
   * server answers `409` when the target changed since (P23W5-09, T-416).
   * Omitted, the write is last-writer-wins.
   */
  expected_updated_at?: string;
}

// ─── Client-side mirrors of the server's rules ───────────────────────────────

/**
 * Why an update must carry the credential again, or `null` when it need not
 * (D-57; contract §31.3 rule 2). The same comparison the server makes, so the
 * form can ask for the field instead of failing with a `400`.
 */
export function credentialRequiredFor(
  stored: Pick<ScimTarget, "base_url" | "auth">,
  next: Pick<ScimTargetInput, "base_url" | "auth">,
): string | null {
  if (stored.auth.type !== next.auth.type) {
    return "Switching the authentication kind";
  }
  if (
    stored.auth.type === "oauth2_client_credentials" &&
    next.auth.type === "oauth2_client_credentials" &&
    stored.auth.token_url !== next.auth.token_url
  ) {
    return "Changing the token URL";
  }
  // Both kinds: a bearer token is sent to the base URL, and so is every access
  // token a client secret yields (W5 F4 review, T-409).
  return stored.base_url !== next.base_url ? "Changing the base URL" : null;
}

const encoder = new TextEncoder();

function byteLength(text: string): number {
  return encoder.encode(text).length;
}

/** An absolute https URL, at most 2 048 bytes; the server applies the rest. */
export function validateHttpsUrl(label: string, raw: string): string | null {
  const value = raw.trim();
  if (!value) return `${label} is required.`;
  if (byteLength(value) > SCIM_TARGET_BOUNDS.urlBytes) {
    return `${label} must be at most ${SCIM_TARGET_BOUNDS.urlBytes} bytes.`;
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return `${label} must be an absolute URL.`;
  }
  if (parsed.protocol !== "https:") return `${label} must use https.`;
  if (parsed.username || parsed.password) {
    return `${label} must not carry credentials.`;
  }
  if (parsed.hash) return `${label} must not carry a fragment.`;
  return null;
}

/** The form's values checked before the round trip; the first problem, or `null`. */
export function validateScimTargetInput(input: ScimTargetInput): string | null {
  const name = input.name.trim();
  if (!name) return "Name is required.";
  if (byteLength(input.name) > SCIM_TARGET_BOUNDS.nameBytes) {
    return `Name must be at most ${SCIM_TARGET_BOUNDS.nameBytes} bytes.`;
  }
  const baseError = validateHttpsUrl("Base URL", input.base_url);
  if (baseError) return baseError;
  if (input.auth.type === "oauth2_client_credentials") {
    const tokenError = validateHttpsUrl("Token URL", input.auth.token_url);
    if (tokenError) return tokenError;
    const clientId = input.auth.client_id.trim();
    if (!clientId) return "Client ID is required.";
    if (byteLength(clientId) > SCIM_TARGET_BOUNDS.clientIdBytes) {
      return `Client ID must be at most ${SCIM_TARGET_BOUNDS.clientIdBytes} bytes.`;
    }
    if (
      input.auth.scope &&
      byteLength(input.auth.scope) > SCIM_TARGET_BOUNDS.oauthScopeBytes
    ) {
      return `Scope must be at most ${SCIM_TARGET_BOUNDS.oauthScopeBytes} bytes.`;
    }
  }
  if (input.credential !== undefined) {
    if (byteLength(input.credential) > SCIM_TARGET_BOUNDS.credentialBytes) {
      return `The credential must be at most ${SCIM_TARGET_BOUNDS.credentialBytes} bytes.`;
    }
    if (input.auth.type === "bearer" && /\s/.test(input.credential)) {
      return "A bearer token must not contain spaces.";
    }
  }
  if (input.scope.type === "groups") {
    if (input.scope.group_ids.length === 0) {
      return "Select at least one group.";
    }
    if (input.scope.group_ids.length > SCIM_TARGET_BOUNDS.scopeGroups) {
      return `Select at most ${SCIM_TARGET_BOUNDS.scopeGroups} groups.`;
    }
  }
  return null;
}

// ─── Service ──────────────────────────────────────────────────────────────────

/** What a started reconciliation answers (`202`). */
export interface ScimReconcileAccepted {
  target_id: string;
  status: string;
}

/** A tenant group, as the scope picker needs it. */
export interface ScopeGroup {
  id: string;
  name: string;
}

export const scimTargetService = {
  /** Every group of the tenant: what a `groups` scope may name. */
  listGroups: (): Promise<ScopeGroup[]> =>
    fetchAllPages<ScopeGroup>("/api/v1/groups"),

  create: (payload: ScimTargetInput): Promise<ScimTarget> =>
    api.post<ScimTarget>(SCIM_TARGETS_URL, payload).then((r) => r.data),

  /** A replacement: the credential is sent only when the administrator typed one. */
  update: (id: string, payload: ScimTargetInput): Promise<ScimTarget> =>
    api.put<ScimTarget>(`${SCIM_TARGETS_URL}/${id}`, payload).then((r) => r.data),

  /** Removes the target, its links and its state; deprovisions nothing downstream. */
  remove: (id: string): Promise<void> =>
    api.delete(`${SCIM_TARGETS_URL}/${id}`).then(() => undefined),

  /** `202` when the run was claimed, `409` when one holds the claim. */
  reconcile: (id: string): Promise<ScimReconcileAccepted> =>
    api
      .post<ScimReconcileAccepted>(`${SCIM_TARGETS_URL}/${id}/reconcile`)
      .then((r) => r.data),
};
