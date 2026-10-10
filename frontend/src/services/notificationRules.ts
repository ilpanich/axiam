import api from "@/lib/api";
import { fetchAllPages } from "@/services/_pagination";

// ─── Notification event ids ───────────────────────────────────────────────────

/**
 * Event ids accepted by the backend `NotificationEventType` enum
 * (serialized snake_case). Source of truth:
 * crates/axiam-core/src/models/notification_rule.rs.
 *
 * `value` is the wire id (sent to / received from the API); `label` is a
 * human-readable rendering for the UI.
 */
export const NOTIFICATION_EVENTS: ReadonlyArray<{ value: string; label: string }> = [
  // Security events
  { value: "login_failure", label: "Login failure" },
  { value: "account_locked", label: "Account locked" },
  { value: "mfa_enrollment_changed", label: "MFA enrollment changed" },
  { value: "password_changed", label: "Password changed" },
  { value: "password_reset_requested", label: "Password reset requested" },
  // Privilege events
  { value: "role_assigned", label: "Role assigned" },
  { value: "role_unassigned", label: "Role unassigned" },
  { value: "permission_granted", label: "Permission granted" },
  { value: "permission_revoked", label: "Permission revoked" },
  // Certificate events
  { value: "certificate_issued", label: "Certificate issued" },
  { value: "certificate_revoked", label: "Certificate revoked" },
  { value: "ca_certificate_revoked", label: "CA certificate revoked" },
  // User lifecycle events
  { value: "user_created", label: "User created" },
  { value: "user_deleted", label: "User deleted" },
  { value: "user_updated", label: "User updated" },
  { value: "service_account_created", label: "Service account created" },
  { value: "service_account_deleted", label: "Service account deleted" },
  // Provisioning events
  { value: "scim_delivery_failed", label: "SCIM delivery failed" },
];

/** Map an event id to its human-readable label (falls back to the id). */
export function notificationEventLabel(eventId: string): string {
  return NOTIFICATION_EVENTS.find((e) => e.value === eventId)?.label ?? eventId;
}

// ─── Notification window (#551) ───────────────────────────────────────────────

/**
 * A rule mails one event type at most once per window and counts the rest;
 * the next mail says how many were not sent. Bounds and default mirror
 * crates/axiam-core/src/models/notification_rule.rs.
 */
export const NOTIFICATION_WINDOW_MINUTES = { min: 1, max: 1440, default: 15 } as const;

// ─── Domain Models ────────────────────────────────────────────────────────────

export interface NotificationRule {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  events: string[];
  recipient_emails: string[];
  enabled: boolean;
  /** Minutes in which one event type mails each recipient at most once. */
  window_minutes?: number;
  created_at: string;
  updated_at: string;
}

// ─── Request payloads ─────────────────────────────────────────────────────────

export interface CreateNotificationRulePayload {
  name: string;
  description: string;
  events: string[];
  recipient_emails: string[];
  window_minutes?: number;
}

export interface UpdateNotificationRulePayload {
  name?: string;
  description?: string;
  events?: string[];
  recipient_emails?: string[];
  enabled?: boolean;
  window_minutes?: number;
}

// ─── Service ──────────────────────────────────────────────────────────────────

export const notificationRuleService = {
  list: (): Promise<NotificationRule[]> =>
    fetchAllPages<NotificationRule>("/api/v1/notification-rules"),

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
