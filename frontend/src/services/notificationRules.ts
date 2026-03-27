import api from "@/lib/api";

// ─── Domain Models ────────────────────────────────────────────────────────────

export interface NotificationRule {
  id: string;
  event_type: string;
  recipient_emails: string[];
  is_active: boolean;
  description?: string;
  created_at: string;
}

// ─── Request payloads ─────────────────────────────────────────────────────────

export interface CreateNotificationRulePayload {
  event_type: string;
  recipient_emails: string[];
  is_active?: boolean;
  description?: string;
}

export interface UpdateNotificationRulePayload {
  event_type?: string;
  recipient_emails?: string[];
  is_active?: boolean;
  description?: string;
}

// ─── Service ──────────────────────────────────────────────────────────────────

export const notificationRuleService = {
  list: (): Promise<NotificationRule[]> =>
    api
      .get<NotificationRule[]>("/api/v1/notification-rules")
      .then((r) => r.data),

  create: (payload: CreateNotificationRulePayload): Promise<NotificationRule> =>
    api
      .post<NotificationRule>("/api/v1/notification-rules", payload)
      .then((r) => r.data),

  get: (id: string): Promise<NotificationRule> =>
    api
      .get<NotificationRule>(`/api/v1/notification-rules/${id}`)
      .then((r) => r.data),

  update: (
    id: string,
    payload: UpdateNotificationRulePayload
  ): Promise<NotificationRule> =>
    api
      .put<NotificationRule>(`/api/v1/notification-rules/${id}`, payload)
      .then((r) => r.data),

  remove: (id: string): Promise<void> =>
    api
      .delete(`/api/v1/notification-rules/${id}`)
      .then(() => undefined),
};
