// Shared verify core (D-27, CONTRACT.md §10) — the ONE verification path
// both Express and Fastify middleware call. Reuses the 17-03 local-JWKS
// verifier (jose against the cached remote JWKS, EdDSA-only) — no
// per-request round-trip to the AXIAM server on a cache hit, and no
// additional TTL bookkeeping beyond jose's own `exp` check (§10 "MUST NOT
// cache session verification results longer than the token's remaining
// TTL").

import { AuthError } from '../core/index.js';
import type { Verifier } from '../node/jwks.js';

/** Minimal session shape the middleware needs: a JWKS verifier (D-11). */
export interface VerifiableSession {
  jwksVerifier: Verifier;
}

/** Authenticated identity injected as req.axiamUser / request.axiamUser (§10). */
export interface AxiamIdentity {
  userId: string;
  tenantId: string;
  roles: string[];
}

/**
 * Verify `token` locally against `session`'s cached JWKS and map the
 * verified claims to the identity shape injected by both middleware
 * modules. Roles are derived from the `scope` claim (space-separated) —
 * AXIAM's access token carries no dedicated `roles` claim server-side
 * (mirrors sdks/rust/src/middleware/actix.rs).
 *
 * Throws `AuthError` on any verification failure (missing/invalid/expired
 * token, or a malformed sub/tenant_id claim).
 */
export async function authenticateRequest(
  session: VerifiableSession,
  token: string,
): Promise<AxiamIdentity> {
  let claims;
  try {
    claims = await session.jwksVerifier.verifyAccessToken(token);
  } catch (err) {
    throw new AuthError(err instanceof Error ? err.message : 'invalid or expired token');
  }

  if (!claims.sub) {
    throw new AuthError('invalid sub claim');
  }
  if (!claims.tenant_id) {
    throw new AuthError('invalid tenant_id claim');
  }

  const roles = (claims.scope ?? '').split(' ').filter(Boolean);

  return {
    userId: claims.sub,
    tenantId: claims.tenant_id,
    roles,
  };
}
