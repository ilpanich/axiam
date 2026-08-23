import api from "@/lib/api";
import { unwrapList } from "@/services/_pagination";

// ─── Domain Models ────────────────────────────────────────────────────────────

/**
 * Delivery retry policy.
 *
 * Bounds mirror `validate_retry_policy` in
 * `crates/axiam-api-rest/src/handlers/webhooks.rs`; the defaults mirror
 * `RetryPolicy::default()` in `crates/axiam-core/src/models/webhook.rs`, which
 * is what the server applies when a create request omits the block.
 */
export interface RetryPolicy {
  max_retries: number;
  initial_delay_secs: number;
  backoff_multiplier: number;
}

export const DEFAULT_RETRY_POLICY: RetryPolicy = {
  max_retries: 5,
  initial_delay_secs: 10,
  backoff_multiplier: 2,
};

export const RETRY_POLICY_BOUNDS = {
  max_retries: { min: 0, max: 10 },
  initial_delay_secs: { min: 1, max: 3600 },
  backoff_multiplier: { min: 0, max: 10 },
} as const;

/** Client-side mirror of the server's bounds, so a bad value fails in the form. */
export function validateRetryPolicy(rp: RetryPolicy): string | null {
  if (!Number.isInteger(rp.max_retries) || rp.max_retries < 0 || rp.max_retries > 10) {
    return "Max retries must be a whole number between 0 and 10.";
  }
  if (rp.initial_delay_secs < 1 || rp.initial_delay_secs > 3600) {
    return "Initial delay must be between 1 and 3600 seconds.";
  }
  if (rp.backoff_multiplier < 0 || rp.backoff_multiplier > 10) {
    return "Backoff multiplier must be between 0 and 10.";
  }
  return null;
}

export interface Webhook {
  id: string;
  url: string;
  events: string[];
  enabled: boolean;
  /** Always present on a response — the server resolves the default on read. */
  retry_policy: RetryPolicy;
  created_at: string;
}

// ─── Request payloads ─────────────────────────────────────────────────────────

export interface CreateWebhookPayload {
  url: string;
  events: string[];
  secret: string;
  /** Omit to take `RetryPolicy::default()`. */
  retry_policy?: RetryPolicy;
}

export interface UpdateWebhookPayload {
  url?: string;
  events?: string[];
  enabled?: boolean;
  retry_policy?: RetryPolicy;
  /**
   * D-02 secret rotation. Omit to leave the stored secret untouched — an empty
   * string is rejected server-side rather than treated as "clear it".
   */
  secret?: string;
}

// ─── Response types ───────────────────────────────────────────────────────────

export type CreateWebhookResponse = Webhook;

// ─── Available event types ────────────────────────────────────────────────────

export const WEBHOOK_EVENTS = [
  "user.created",
  "user.updated",
  "user.deleted",
  "user.login",
  "user.login_failed",
  "user.locked",
  "group.created",
  "group.updated",
  "group.deleted",
  "role.assigned",
  "role.unassigned",
  "certificate.generated",
  "certificate.revoked",
  "mfa.enrolled",
  "mfa.verified",
  "mfa.reset",
  "password.reset",
  "password.changed",
] as const;

export type WebhookEvent = (typeof WEBHOOK_EVENTS)[number];

export const WEBHOOK_EVENT_GROUPS: ReadonlyArray<{
  label: string;
  events: WebhookEvent[];
}> = [
  {
    label: "User Events",
    events: [
      "user.created",
      "user.updated",
      "user.deleted",
      "user.login",
      "user.login_failed",
      "user.locked",
    ],
  },
  {
    label: "Group Events",
    events: ["group.created", "group.updated", "group.deleted"],
  },
  {
    label: "Role Events",
    events: ["role.assigned", "role.unassigned"],
  },
  {
    label: "Certificate Events",
    events: ["certificate.generated", "certificate.revoked"],
  },
  {
    label: "MFA Events",
    events: ["mfa.enrolled", "mfa.verified", "mfa.reset"],
  },
  {
    label: "Password Events",
    events: ["password.reset", "password.changed"],
  },
];

// ─── Service ──────────────────────────────────────────────────────────────────

export const webhookService = {
  list: (): Promise<Webhook[]> =>
    api
      .get<Webhook[] | { items: Webhook[] }>("/api/v1/webhooks")
      .then((r) => unwrapList(r.data)),

  create: (payload: CreateWebhookPayload): Promise<CreateWebhookResponse> =>
    api
      .post<CreateWebhookResponse>("/api/v1/webhooks", payload)
      .then((r) => r.data),

  get: (id: string): Promise<Webhook> =>
    api.get<Webhook>(`/api/v1/webhooks/${id}`).then((r) => r.data),

  update: (id: string, payload: UpdateWebhookPayload): Promise<Webhook> =>
    api
      .put<Webhook>(`/api/v1/webhooks/${id}`, payload)
      .then((r) => r.data),

  remove: (id: string): Promise<void> =>
    api.delete(`/api/v1/webhooks/${id}`).then(() => undefined),
};
