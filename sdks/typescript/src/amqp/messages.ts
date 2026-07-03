// AMQP message DTOs mirroring the server's wire format (CONTRACT.md §8).
//
// Mirror, never import. These interfaces reproduce field declaration order
// byte-for-byte from crates/axiam-amqp/src/messages.rs (and
// sdks/rust/src/amqp/messages.rs) so that `JSON.stringify` on a parsed
// object (after deleting `hmac_signature`) produces canonical JSON
// byte-identical to what the server signs/verifies against — see
// Pitfall 5: no schema-validator reconstruction step before HMAC
// verification, or the field order (and therefore the signed bytes) could
// silently diverge.

/**
 * Authorization check request received from `axiam.authz.request`.
 *
 * Field declaration order matches the server's `AuthzRequest`
 * (crates/axiam-amqp/src/messages.rs:56-73) exactly: correlation_id,
 * tenant_id, subject_id, action, resource_id, scope, hmac_signature.
 */
export interface AuthzRequest {
  /** Caller-provided ID to correlate request with response. */
  correlation_id: string;
  tenant_id: string;
  subject_id: string;
  action: string;
  resource_id: string;
  scope?: string;
  /**
   * HMAC-SHA256 of the JSON-serialized message body (this field removed
   * before signing). Computed with the per-tenant AMQP signing key
   * (CONTRACT.md §8). The consumer MUST verify this before processing; a
   * missing signature is rejected in strict mode (the default).
   */
  hmac_signature?: string;
}

/**
 * Authorization decision published to `axiam.authz.response`.
 *
 * Does not carry `hmac_signature` in v1.0 (CONTRACT.md §8, message-types
 * table).
 */
export interface AuthzResponse {
  correlation_id: string;
  allowed: boolean;
  reason?: string;
}

/**
 * Audit event received from external services via `axiam.audit.events`.
 *
 * Field declaration order matches the server's `AuditEventMessage`
 * (crates/axiam-amqp/src/messages.rs:88-103) exactly: tenant_id, actor_id,
 * actor_type, action, resource_id, outcome, ip_address, metadata,
 * hmac_signature.
 */
export interface AuditEventMessage {
  tenant_id: string;
  actor_id: string;
  actor_type: string;
  action: string;
  resource_id?: string;
  outcome: string;
  ip_address?: string;
  metadata?: Record<string, unknown>;
  /** HMAC-SHA256 of the JSON-serialized message body (CONTRACT.md §8). */
  hmac_signature?: string;
}

/**
 * Notification event published to `axiam.notifications`.
 *
 * Does not carry `hmac_signature` in v1.0 (CONTRACT.md §8, message-types
 * table).
 */
export interface NotificationEvent {
  event_type: string;
  tenant_id: string;
  actor_id: string;
  resource_id?: string;
  timestamp: string;
  data?: Record<string, unknown>;
}

/**
 * Message type names subject to HMAC verification per CONTRACT.md §8's
 * message-types table (`axiam.authz.request` -> AuthzRequest,
 * `axiam.audit.events` -> AuditEventMessage). `AuthzResponse` and
 * `NotificationEvent` are server-published and never carry
 * `hmac_signature`.
 */
export const HMAC_SIGNED_MESSAGE_TYPES = ['AuthzRequest', 'AuditEventMessage'] as const;

export type HmacSignedMessageType = (typeof HMAC_SIGNED_MESSAGE_TYPES)[number];
