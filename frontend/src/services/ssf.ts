import api from "@/lib/api";

/**
 * SSF stream administration client (G-5, T23.5.2, P23W4-07).
 *
 * Source of truth for every shape below: contract §32 (`sdks/CONTRACT.md`,
 * "Shared Signals Framework"), `sdks/openapi.json` (tag `ssf`) and the handler
 * `crates/axiam-api-rest/src/handlers/ssf_admin.rs`.
 *
 * # What is deliberately absent
 *
 * - **No `authorization_header` on any response type.** The push header is a
 *   credential *to the receiver*: it is write-only, no route returns it, and
 *   `authorization_header_set` says only whether one is stored. A response type
 *   with a member for it would lie about every value it holds.
 * - **No client-side address policy.** The server holds the endpoint to the
 *   outbound address policy; the console only checks that it is an absolute
 *   `https` URL, so a typo fails in the form rather than as a `400`.
 */

/** The stream registry of one tenant. */
export const ssfStreamsPath = (tenantId: string) =>
  `/api/v1/tenants/${tenantId}/ssf/streams`;

// ─── Bounds (mirror `axiam_core::models::ssf`) ────────────────────────────────

export const SSF_BOUNDS = {
  audienceBytes: 512,
  descriptionBytes: 256,
  endpointUrlBytes: 2048,
  authorizationHeaderBytes: 4096,
  statusReasonBytes: 256,
} as const;

// ─── Domain types ─────────────────────────────────────────────────────────────

/** The six event types AXIAM transmits, as their event-type URIs. */
export const SSF_EVENT_TYPES = [
  {
    uri: "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
    label: "Session revoked",
  },
  {
    uri: "https://schemas.openid.net/secevent/caep/event-type/credential-change",
    label: "Credential change",
  },
  {
    uri: "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change",
    label: "Assurance level change",
  },
  {
    uri: "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
    label: "Account disabled",
  },
  {
    uri: "https://schemas.openid.net/secevent/risc/event-type/account-enabled",
    label: "Account enabled",
  },
  {
    uri: "https://schemas.openid.net/secevent/risc/event-type/account-purged",
    label: "Account purged",
  },
] as const;

/** The label of an event-type URI; an unknown URI is shown as it is. */
export function eventLabel(uri: string): string {
  return SSF_EVENT_TYPES.find((e) => e.uri === uri)?.label ?? uri;
}

export const DELIVERY_METHODS = ["push", "poll"] as const;
export type SsfDeliveryMethod = (typeof DELIVERY_METHODS)[number];

export const DELIVERY_METHOD_LABELS: Record<SsfDeliveryMethod, string> = {
  push: "Push (RFC 8935)",
  poll: "Poll (RFC 8936)",
};

export const STREAM_STATUSES = ["enabled", "paused", "disabled"] as const;
export type SsfStreamStatus = (typeof STREAM_STATUSES)[number];

export const STREAM_STATUS_HELP: Record<SsfStreamStatus, string> = {
  enabled: "Events are signed and transmitted.",
  paused:
    "Nothing is transmitted; events are held in a bounded buffer and sent, oldest first, when the stream is enabled again.",
  disabled:
    "Nothing is signed, transmitted or held: events for this stream are dropped.",
};

export const SUBJECT_FORMATS = ["iss_sub", "email"] as const;
export type SsfSubjectFormat = (typeof SUBJECT_FORMATS)[number];

export const SUBJECT_FORMAT_LABELS: Record<SsfSubjectFormat, string> = {
  iss_sub: "Issuer and subject id (default)",
  email: "E-mail address (releases personal data)",
};

/** What every read and write returns. */
export interface SsfStream {
  id: string;
  tenant_id: string;
  /** The OAuth2 client that is this stream's receiver on the SSF API. */
  receiver_client_id: string;
  /** The SET `aud`; unique across the deployment. */
  audience: string;
  description: string | null;
  /** Open on the way out. */
  delivery_method: string;
  /** Push only. */
  endpoint_url: string | null;
  /** Whether a header is stored. Its value is never returned. */
  authorization_header_set: boolean;
  /** The administrator's ceiling. */
  events_allowed: string[];
  /** What the receiver asked for; a subset of `events_allowed`. */
  events_requested: string[];
  /** What the stream actually carries: the intersection of the two. */
  events_delivered: string[];
  /** Open on the way out. */
  subject_format: string;
  /** Open on the way out. */
  status: string;
  status_reason: string | null;
  /** Who set the current status: `admin` or `receiver`. */
  status_actor: string;
  last_verification_at: string | null;
  created_at: string;
  updated_at: string;
  /** Whether the tenant's transmitter is active (its `ssf_enabled` is on). */
  transmitter_active: boolean;
  transmitter_inactive_reason?: string | null;
}

/** `create` and `update` (a **replacement**) body. */
export interface SsfStreamInput {
  receiver_client_id: string;
  audience: string;
  description?: string | null;
  delivery_method: SsfDeliveryMethod;
  /** Required for `push`, refused for `poll`. */
  endpoint_url?: string | null;
  /**
   * Write-only. On update, omitted keeps the stored one — except that moving
   * the endpoint to another origin requires it again
   * ({@link endpointMoveNeedsHeader}).
   */
  authorization_header?: string;
  /** Update only: remove the stored header. Refused with a header. */
  clear_authorization_header?: boolean;
  events_allowed: string[];
  /**
   * Omitted means *all of* `events_allowed`. An update is a replacement, so an
   * edit that omitted it would widen what the receiver had narrowed: the page
   * sends the stored value, cut to the new ceiling.
   */
  events_requested?: string[];
  subject_format: SsfSubjectFormat;
  status: SsfStreamStatus;
  status_reason?: string | null;
}

// ─── Client-side mirrors of the server's rules ───────────────────────────────

/** The origin of an absolute URL, or `null` when it is not one. */
function originOf(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

/**
 * Whether an edit moves a push endpoint to another origin while the stored
 * header would be kept (D-49; contract §32.3). The server refuses that with a
 * `400`; the form asks for the header instead of failing.
 */
export function endpointMoveNeedsHeader(
  stored: Pick<SsfStream, "authorization_header_set" | "endpoint_url">,
  next: Pick<
    SsfStreamInput,
    | "delivery_method"
    | "endpoint_url"
    | "authorization_header"
    | "clear_authorization_header"
  >,
): boolean {
  if (!stored.authorization_header_set) return false;
  if (next.delivery_method !== "push") return false;
  if (next.authorization_header || next.clear_authorization_header) return false;
  return originOf(stored.endpoint_url) !== originOf(next.endpoint_url);
}

const encoder = new TextEncoder();
const bytes = (text: string) => encoder.encode(text).length;

/** The form's values checked before the round trip; the first problem, or `null`. */
export function validateSsfStreamInput(input: SsfStreamInput): string | null {
  if (!input.receiver_client_id.trim()) return "Receiver client id is required.";
  const audience = input.audience.trim();
  if (!audience) return "Audience is required.";
  if (bytes(audience) > SSF_BOUNDS.audienceBytes) {
    return `Audience must be at most ${SSF_BOUNDS.audienceBytes} bytes.`;
  }
  if (
    input.description &&
    bytes(input.description) > SSF_BOUNDS.descriptionBytes
  ) {
    return `Description must be at most ${SSF_BOUNDS.descriptionBytes} bytes.`;
  }
  if (
    input.status_reason &&
    bytes(input.status_reason) > SSF_BOUNDS.statusReasonBytes
  ) {
    return `Status reason must be at most ${SSF_BOUNDS.statusReasonBytes} bytes.`;
  }
  if (input.delivery_method === "push") {
    const raw = (input.endpoint_url ?? "").trim();
    if (!raw) return "A push stream needs an endpoint URL.";
    if (bytes(raw) > SSF_BOUNDS.endpointUrlBytes) {
      return `Endpoint URL must be at most ${SSF_BOUNDS.endpointUrlBytes} bytes.`;
    }
    let parsed: URL;
    try {
      parsed = new URL(raw);
    } catch {
      return "Endpoint URL must be an absolute URL.";
    }
    if (parsed.protocol !== "https:") return "Endpoint URL must use https.";
    if (parsed.username || parsed.password) {
      return "Endpoint URL must not carry credentials.";
    }
  }
  if (
    input.authorization_header &&
    bytes(input.authorization_header) > SSF_BOUNDS.authorizationHeaderBytes
  ) {
    return `The authorization header must be at most ${SSF_BOUNDS.authorizationHeaderBytes} bytes.`;
  }
  if (input.events_allowed.length === 0) {
    return "Allow at least one event type.";
  }
  return null;
}

// ─── Service ──────────────────────────────────────────────────────────────────

export const ssfStreamService = {
  create: (tenantId: string, payload: SsfStreamInput): Promise<SsfStream> =>
    api.post<SsfStream>(ssfStreamsPath(tenantId), payload).then((r) => r.data),

  /** A replacement: the header is sent only when the administrator typed one. */
  update: (
    tenantId: string,
    id: string,
    payload: SsfStreamInput,
  ): Promise<SsfStream> =>
    api
      .put<SsfStream>(`${ssfStreamsPath(tenantId)}/${id}`, payload)
      .then((r) => r.data),

  /** Removes the stream and its buffered events. */
  remove: (tenantId: string, id: string): Promise<void> =>
    api.delete(`${ssfStreamsPath(tenantId)}/${id}`).then(() => undefined),
};
