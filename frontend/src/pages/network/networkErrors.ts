import { STALE_WRITE_ADVICE, getApiErrorMessage, getApiErrorStatus } from "@/lib/apiError";

/** The longest server sentence shown in place. */
const MAX_LENGTH = 500;

/**
 * What a network error body carries beside `message`: `action` / `resource_id`
 * on a `403 authorization_denied` (§36.3 rule 1), `reason_code` on a `409`
 * (§36.3 rule 2, §36.4).
 */
interface DeniedBody {
  error?: unknown;
  message?: unknown;
  action?: unknown;
  resource_id?: unknown;
  reason_code?: unknown;
}

/** The one `409` that is someone else's write (§36.3 rule 2). */
const STALE_VERSION = "stale_version";
const STALE_ADVICE = STALE_WRITE_ADVICE;

function bodyOf(err: unknown): DeniedBody | undefined {
  const data = (err as { response?: { data?: DeniedBody } })?.response?.data;
  return typeof data === "object" && data !== null ? data : undefined;
}

function text(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export interface NetworkErrorOptions {
  /** The page-specific last resort, as `getApiErrorMessage` takes it. */
  fallback: string;
  /**
   * Resolve the node a `403` names to something readable: the segment's path
   * when the id is one the page has loaded. The id itself otherwise.
   */
  nodeName?: (resourceId: string) => string | undefined;
  /**
   * Whether the only `409` this write can answer is a stale version (the
   * policy write). Consulted only for a `409` without `reason_code` (a server
   * before the sub-code), where the server's own sentence is what tells the
   * conflicts apart and is shown beside the generic advice.
   */
  staleOnly?: boolean;
}

/**
 * The text to show for a failed network write.
 *
 * - **`403`** names the permission and the node the write gate checked, from the
 *   body's `action` / `resource_id` members, never from `message` (§36.3 rule
 *   1: an SDK must not parse it). The internal rule that refused is not in the
 *   body and not here.
 * - **`409`** reads the body's `reason_code` (§36.4), never `message`:
 *   `stale_version` says someone else wrote first and asks for a reload, and
 *   nothing more; any other code (`strands_profile`, `has_children`,
 *   `duplicate_vlan`, …) is not someone else's write, so the server's own
 *   sentence is shown alone — it names the stranded profile and its
 *   `filter_id`, the taken VLAN or rank, or the child resources. Without a
 *   `reason_code` the advice and the sentence are shown together.
 * - **`400`** is the server's `message`, which names the rule or the unknown
 *   member.
 * - Everything else goes through {@link getApiErrorMessage}.
 */
export function networkErrorMessage(err: unknown, options: NetworkErrorOptions): string {
  const status = getApiErrorStatus(err);
  const body = bodyOf(err);
  const message = text(body?.message);

  if (status === 403) {
    const action = text(body?.action);
    const resourceId = text(body?.resource_id);
    const node = resourceId ? (options.nodeName?.(resourceId) ?? resourceId) : undefined;
    const lead = message ? message.slice(0, MAX_LENGTH) : "You are not allowed to do this.";
    if (action && node) return `${lead} Missing permission ${action} on ${node}.`;
    if (action) return `${lead} Missing permission ${action}.`;
    return lead;
  }

  if (status === 409) {
    const reasonCode = text(body?.reason_code);
    if (reasonCode === STALE_VERSION) return STALE_ADVICE;
    if (reasonCode) {
      return message
        ? message.slice(0, MAX_LENGTH)
        : "This change conflicts with the current network settings.";
    }
    if (options.staleOnly || !message) return STALE_ADVICE;
    return `${STALE_ADVICE} ${message.slice(0, MAX_LENGTH)}`;
  }

  if (status === 429) {
    return "Too many network changes in a minute — wait a moment and try again.";
  }

  return getApiErrorMessage(err, options.fallback);
}
