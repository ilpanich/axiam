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
  return new NetworkError(message, ctx?.cause);
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
