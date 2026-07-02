// Synchronous auth/tenant grpc-js interceptor (D-10, Pitfall 3).
//
// grpc-js's `start(metadata, listener, next)` callback is SYNCHRONOUS —
// unlike tonic's async-native interceptor trait, it must call
// `next(metadata, listener)` without ever awaiting. This interceptor
// therefore only reads the TokenManager's non-blocking, in-memory cached
// access token (populated by `syncFromJar()` after REST calls/refresh) —
// it NEVER triggers a refresh itself. UNAUTHENTICATED handling belongs to
// the async call-wrapper (callWithRefresh.ts), never here.
//
// Mirrors sdks/rust/src/grpc/interceptor.rs exactly, adapted to grpc-js's
// structurally different (non-tower) interceptor API
// (RESEARCH.md Area 3 / grpc/proposal L5-node-client-interceptors.md).

import * as grpc from '@grpc/grpc-js';
import type { Interceptor } from '@grpc/grpc-js';
import type { NodeSession } from '../node/session.js';

/**
 * Injects `authorization: Bearer <token>` (when a cached token is present)
 * and `x-tenant-id` metadata on every outgoing RPC (CONTRACT.md §5). Never
 * logs the token — `expose()` is only called at this metadata-insertion
 * boundary.
 */
export function authInterceptor(session: NodeSession): Interceptor {
  return (options, nextCall) => {
    return new grpc.InterceptingCall(nextCall(options), {
      start(metadata, listener, next) {
        // Non-blocking cached-token read — NEVER await here (Pitfall 3).
        const token = session.tokenManager.cachedAccessToken();
        if (token) {
          metadata.add('authorization', `Bearer ${token.expose()}`);
        }
        metadata.add('x-tenant-id', session.tenantHeaderValue);
        next(metadata, listener);
      },
    });
  };
}
