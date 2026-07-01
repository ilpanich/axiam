// Central status -> error mapper (CONTRACT.md §2, D-17).
//
// The single source of truth for both rest/ and grpc/ transports so the two
// cannot drift on the error taxonomy. Transcribes CONTRACT.md §2's HTTP and
// gRPC tables exactly.
//
// GrpcStatus is exported here (not imported from @grpc/grpc-js) so that
// core stays dependency-free — grpc/ imports the numeric codes from core
// rather than the other way around.

import { AuthError, AuthzError, NetworkError, type AxiamError } from './errors.js';

/** gRPC status codes referenced by CONTRACT.md §2 (subset of the full grpc.status enum). */
export const GrpcStatus = {
  DEADLINE_EXCEEDED: 4,
  PERMISSION_DENIED: 7,
  RESOURCE_EXHAUSTED: 8,
  INTERNAL: 13,
  UNAVAILABLE: 14,
  UNAUTHENTICATED: 16,
} as const;

export interface HttpErrorContext {
  action?: string;
  resourceId?: string;
  cause?: unknown;
}

/** Response header names that must never survive into a NetworkError.cause (CR-04, D-16). */
const SENSITIVE_RESPONSE_HEADERS = ['set-cookie', 'authorization', 'cookie'];

/**
 * Strip Set-Cookie (and other sensitive) response headers from an
 * axios-error-shaped `err` before it is attached as `NetworkError.cause`
 * (CR-04, D-16). On login/refresh error paths the server may have already
 * issued Set-Cookie headers containing raw `axiam_access`/`axiam_refresh`
 * values; those must never be reachable via `console.log`/`JSON.stringify`/
 * `util.inspect` of the thrown error.
 *
 * Returns a new, shallow-cloned object for any input shaped like
 * `{ response: { headers: {...} } }` — the caller's original axios error
 * object is left untouched. Non-object inputs (plain Error, string,
 * undefined) and objects with no `response.headers` are returned unchanged.
 */
export function sanitizeAxiosError(err: unknown): unknown {
  if (err === null || typeof err !== 'object') {
    return err;
  }
  const candidate = err as { response?: unknown };
  if (candidate.response === null || typeof candidate.response !== 'object') {
    return err;
  }
  const response = candidate.response as { headers?: unknown };
  if (response.headers === null || typeof response.headers !== 'object') {
    return err;
  }

  const sanitizedHeaders: Record<string, unknown> = { ...(response.headers as Record<string, unknown>) };
  for (const key of Object.keys(sanitizedHeaders)) {
    if (SENSITIVE_RESPONSE_HEADERS.includes(key.toLowerCase())) {
      delete sanitizedHeaders[key];
    }
  }

  return {
    ...err,
    response: {
      ...response,
      headers: sanitizedHeaders,
    },
  };
}

/**
 * Map an HTTP status code to an AxiamError variant per CONTRACT.md §2's HTTP
 * status table.
 *
 * | Status    | Type         |
 * |-----------|--------------|
 * | 400       | NetworkError |
 * | 401       | AuthError    |
 * | 403       | AuthzError   |
 * | 408, 429  | NetworkError |
 * | 409       | AuthzError   |
 * | 5xx       | NetworkError |
 * | other     | NetworkError |
 *
 * NetworkError's `cause` (when provided via `ctx.cause`) is always passed
 * through `sanitizeAxiosError` first (CR-04) — this is the single choke
 * point for both rest/ auth call sites and any future caller.
 */
export function mapHttpStatusToError(
  status: number,
  message: string,
  ctx?: HttpErrorContext,
): AxiamError {
  if (status === 401) {
    return new AuthError(message);
  }
  if (status === 403 || status === 409) {
    return new AuthzError(message, ctx?.action, ctx?.resourceId);
  }
  // 400, 408, 429, 5xx, and any other status fall through to NetworkError.
  return new NetworkError(message, sanitizeAxiosError(ctx?.cause));
}

/**
 * Map a gRPC status code to an AxiamError variant per CONTRACT.md §2's gRPC
 * status table.
 *
 * | Code                   | Type         |
 * |------------------------|--------------|
 * | 16 UNAUTHENTICATED     | AuthError    |
 * | 7 PERMISSION_DENIED    | AuthzError   |
 * | 14 UNAVAILABLE         | NetworkError |
 * | 4 DEADLINE_EXCEEDED    | NetworkError |
 * | 13 INTERNAL            | NetworkError |
 * | 8 RESOURCE_EXHAUSTED   | NetworkError |
 * | other                  | NetworkError |
 */
export function mapGrpcStatusToError(code: number, message: string): AxiamError {
  if (code === GrpcStatus.UNAUTHENTICATED) {
    return new AuthError(message);
  }
  if (code === GrpcStatus.PERMISSION_DENIED) {
    return new AuthzError(message);
  }
  return new NetworkError(message);
}
