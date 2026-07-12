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
 * (crates/axiam-amqp/src/messages.rs) v2 (`key_version = 2`, NEW-4) exactly:
 * correlation_id, tenant_id, subject_id, action, resource_id, scope,
 * key_version, nonce, issued_at, hmac_signature. `key_version`, `nonce`, and
 * `issued_at` are always emitted (never omitted) so they fall inside the
 * HMAC-signed bytes — see CONTRACT.md §8 "v2 — Replay Protection".
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
   * HKDF master-key rotation version (SECHRD-08 / D-05b). The server
   * rejects (nack, requeue:false) any message with `key_version < 2` — v1
   * predates the mandatory `nonce`/`issued_at` replay-protection fields and
   * has no grace-window acceptance path (NEW-4, hard cutover).
   */
  key_version: number;
  /**
   * Per-message unique value (UUIDv4) for replay protection (NEW-4).
   * Always emitted so it is covered by the HMAC. A nonce already seen
   * within the freshness window is a replay and MUST be rejected.
   */
  nonce: string;
  /**
   * Producer send time (RFC3339/ISO8601 UTC), always emitted so it is
   * covered by the HMAC (NEW-4). A message outside ±skew (default 5
   * minutes) of the verifier's clock MUST be rejected as stale.
   */
  issued_at: string;
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
 * (crates/axiam-amqp/src/messages.rs) v2 (`key_version = 2`, NEW-4) exactly:
 * tenant_id, actor_id, actor_type, action, resource_id, outcome, ip_address,
 * metadata, key_version, nonce, issued_at, hmac_signature. `key_version`,
 * `nonce`, and `issued_at` are always emitted (never omitted) so they fall
 * inside the HMAC-signed bytes — see CONTRACT.md §8 "v2 — Replay
 * Protection".
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
  /**
   * HKDF master-key rotation version (SECHRD-08 / D-05b). The server
   * rejects (nack, requeue:false) any message with `key_version < 2` — v1
   * predates the mandatory `nonce`/`issued_at` replay-protection fields and
   * has no grace-window acceptance path (NEW-4, hard cutover).
   */
  key_version: number;
  /**
   * Per-message unique value (UUIDv4) for replay protection (NEW-4).
   * Always emitted so it is covered by the HMAC. A nonce already seen
   * within the freshness window is a replay and MUST be rejected.
   */
  nonce: string;
  /**
   * Producer send time (RFC3339/ISO8601 UTC), always emitted so it is
   * covered by the HMAC (NEW-4). A message outside ±skew (default 5
   * minutes) of the verifier's clock MUST be rejected as stale.
   */
  issued_at: string;
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
