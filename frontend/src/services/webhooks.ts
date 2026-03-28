import api from "@/lib/api";

// ─── Domain Models ────────────────────────────────────────────────────────────

export interface Webhook {
  id: string;
  url: string;
  event_types: string[];
  is_active: boolean;
  description?: string;
  created_at: string;
}

// ─── Request payloads ─────────────────────────────────────────────────────────

export interface CreateWebhookPayload {
  url: string;
  event_types: string[];
  secret?: string;
  is_active?: boolean;
  description?: string;
}

export interface UpdateWebhookPayload {
  url?: string;
  event_types?: string[];
  is_active?: boolean;
  description?: string;
}

// ─── Response types ───────────────────────────────────────────────────────────

export interface CreateWebhookResponse {
  webhook: Webhook;
  secret?: string;
}

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
    api.get<Webhook[]>("/api/v1/webhooks").then((r) => r.data),

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
