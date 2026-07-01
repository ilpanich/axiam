// UNAUTHENTICATED single-flight-retry wrapper (D-10/D-13, CONTRACT.md §9).
//
// The interceptor (interceptor.ts) is synchronous and never triggers a
// refresh (Pitfall 3). This ASYNC call-site wrapper is where
// UNAUTHENTICATED handling actually lives: on a caught error whose
// `.code === GrpcStatus.UNAUTHENTICATED`, it awaits the session's
// per-instance single-flight refresh guard (`session.refreshGuard` — the
// SAME guard instance the REST transport for this session uses, D-13, but
// NEVER shared with a different session, CR-02), resyncs the interceptor's
// cached-token fast-path via `syncFromJar()`, then retries the call exactly
// once. A second UNAUTHENTICATED (or any other error) maps through
// `mapGrpcStatusToError` and rethrows — no further retry (§9.3).

import { GrpcStatus, mapGrpcStatusToError, type AxiamError } from '../core/index.js';
import type { NodeSession } from '../node/session.js';

interface GrpcServiceErrorLike {
  code?: number;
  message?: string;
}

function isGrpcServiceError(err: unknown): err is GrpcServiceErrorLike {
  return typeof err === 'object' && err !== null && 'code' in err;
}

/**
 * Await `fn()`. On a gRPC UNAUTHENTICATED (16) error, drive the shared
 * single-flight refresh, sync the token cache from the jar, and retry `fn()`
 * exactly once. Any other error (or a second UNAUTHENTICATED) is mapped to
 * an AxiamError via `mapGrpcStatusToError` and rethrown.
 */
export async function callWithRefresh<T>(session: NodeSession, fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    if (isGrpcServiceError(err) && err.code === GrpcStatus.UNAUTHENTICATED) {
      await session.refreshGuard(session.doRefresh);
      await session.tokenManager.syncFromJar();
      try {
        return await fn();
      } catch (retryErr) {
        throw toAxiamError(retryErr);
      }
    }
    throw toAxiamError(err);
  }
}

function toAxiamError(err: unknown): AxiamError | unknown {
  if (isGrpcServiceError(err) && typeof err.code === 'number') {
    return mapGrpcStatusToError(err.code, err.message ?? 'gRPC call failed');
  }
  return err;
}
