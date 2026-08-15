import api from "@/lib/api";
import { unwrapList } from "@/services/_pagination";

// ─── Domain Models ────────────────────────────────────────────────────────────

/** How a reactor participates in an event. Mirrors `ReactorMode` (X1). */
export type ReactorMode = "intercept" | "listen";

/**
 * What the server does when an interceptor does not produce a usable reply —
 * timeout, transport failure, bad signature, stale nonce, or a rejected patch.
 */
export type FailurePolicy = "fail_closed" | "fail_open";

export interface Reactor {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  events: string[];
  mode: ReactorMode;
  priority: number;
  timeout_ms: number;
  failure_policy: FailurePolicy;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  /** `null` means it has never connected — not the same as "silent since". */
  last_seen_at: string | null;
  /**
   * R2.3 — dispatch failures against this registration in the last 24h whose
   * cause was a timeout (as opposed to a rejected reply, a transport
   * failure, or overload), capped at 100. Read from the audit trail R2.2
   * started writing.
   */
  recent_timeout_count: number;
  /**
   * R2.3 — operations this reactor's own reply *denied* in the last 24h,
   * capped at 100. Distinct from `recent_timeout_count`: a veto is the
   * reactor working as designed; a timeout is the reactor not answering.
   */
  recent_veto_count: number;
}

/**
 * One hookable event, as the server's registry describes it.
 *
 * Deliberately fetched rather than hardcoded here (contrast `WEBHOOK_EVENTS`
 * in `services/webhooks.ts`). The backend serves `GET /reactors/events`
 * precisely so the console, the SDK generator and the dispatcher all read the
 * same list; a copy in this file is a copy that goes stale on the next hook
 * added, and it would go stale silently — the console would keep offering an
 * event the server no longer knows, or hide one it does.
 */
export interface ReactorEventDescriptor {
  name: string;
  /** `false` means the event is listen-only and refuses `intercept`. */
  interceptable: boolean;
  /** `false` means a reply may veto but never carry a patch. */
  mutable: boolean;
  /**
   * Exact field names, or a namespace prefix ending in `.` — `ext.` admits
   * `ext.department` and nothing outside the namespace.
   */
  mutable_fields: string[];
  default_failure_policy: FailurePolicy;
  description: string;
}

// ─── Request payloads ─────────────────────────────────────────────────────────

export interface CreateReactorPayload {
  name: string;
  description?: string;
  events: string[];
  mode: ReactorMode;
  priority?: number;
  /** Omit to take the server's 500 ms default. Capped at `MAX_TIMEOUT_MS`. */
  timeout_ms?: number;
  /** Omit to take the strictest default among `events`. */
  failure_policy?: FailurePolicy;
  enabled?: boolean;
}

export interface UpdateReactorPayload {
  name?: string;
  description?: string;
  events?: string[];
  mode?: ReactorMode;
  priority?: number;
  timeout_ms?: number;
  failure_policy?: FailurePolicy;
  enabled?: boolean;
}

// ─── Protocol constants ───────────────────────────────────────────────────────

// Mirrors `MAX_TIMEOUT_MS` / `DEFAULT_TIMEOUT_MS` in axiam-core. These bound a
// form control rather than a decision: the server re-validates and is the
// authority. Duplicating them buys an error message at the point of typing
// instead of a 400 after submit.
export const MAX_TIMEOUT_MS = 5_000;
export const DEFAULT_TIMEOUT_MS = 500;

// ─── Registry helpers ─────────────────────────────────────────────────────────

/**
 * The strictest `failure_policy` among `events`, which is what the server
 * applies when a registration does not name one.
 *
 * `fail_closed` wins over `fail_open` for the same reason it does server-side:
 * mixing a security hook with an enrichment hook must not let the lenient one
 * set the policy for both.
 */
export function strictestDefaultPolicy(
  events: string[],
  registry: ReactorEventDescriptor[]
): FailurePolicy {
  const selected = registry.filter((spec) => events.includes(spec.name));
  return selected.some((spec) => spec.default_failure_policy === "fail_closed")
    ? "fail_closed"
    : "fail_open";
}

/**
 * Events in `selected` that `mode` cannot legally register for.
 *
 * Mirrors `ReactorValidationError::NotInterceptable`. Surfacing it in the form
 * turns a post-submit 400 into a disabled checkbox with a reason next to it.
 */
export function notInterceptable(
  selected: string[],
  registry: ReactorEventDescriptor[]
): string[] {
  return registry
    .filter((spec) => !spec.interceptable && selected.includes(spec.name))
    .map((spec) => spec.name);
}

// ─── Service ──────────────────────────────────────────────────────────────────

export const reactorService = {
  /** The hookable-event registry, verbatim from the server. */
  listEvents: (): Promise<ReactorEventDescriptor[]> =>
    api
      .get<
        ReactorEventDescriptor[] | { items: ReactorEventDescriptor[] }
      >("/api/v1/reactors/events")
      .then((r) => unwrapList(r.data)),

  list: (): Promise<Reactor[]> =>
    api
      .get<Reactor[] | { items: Reactor[] }>("/api/v1/reactors")
      .then((r) => unwrapList(r.data)),

  create: (payload: CreateReactorPayload): Promise<Reactor> =>
    api.post<Reactor>("/api/v1/reactors", payload).then((r) => r.data),

  get: (id: string): Promise<Reactor> =>
    api.get<Reactor>(`/api/v1/reactors/${id}`).then((r) => r.data),

  update: (id: string, payload: UpdateReactorPayload): Promise<Reactor> =>
    api.put<Reactor>(`/api/v1/reactors/${id}`, payload).then((r) => r.data),

  remove: (id: string): Promise<void> =>
    api.delete(`/api/v1/reactors/${id}`).then(() => undefined),
};
