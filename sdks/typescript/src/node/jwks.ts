// Local JWKS verification (D-11, CONTRACT.md §7 defense-in-depth via
// explicit algorithm allowlist).
//
// Endpoint: `{baseUrl}/oauth2/jwks` — organization-wide, NOT tenant-scoped,
// serving exactly one EdDSA (Ed25519) key in the common case
// (RESEARCH.md Area 3, mirrors sdks/rust/src/token/jwks.rs). `jose`'s
// `createRemoteJWKSet` handles fetch + cache + refetch-on-unknown-kid
// natively; we use its single-cooldown model rather than porting the Rust
// SDK's two-timer (TTL + forced-refetch) design (RESEARCH.md Area 3 explicit
// recommendation).
//
// Pitfall 1 (jose is ESM-only): `jose` 5+/6.x ships no CJS entry condition,
// so a tsup CJS build's transpiled `require('jose')` would throw
// `ERR_REQUIRE_ESM`. `createVerifier` obtains jose via a dynamic
// `await import('jose')`, deferring resolution to first call rather than
// module-load time — this keeps `require('axiam-sdk/grpc')` (or any other
// CJS entry that reaches this module) from throwing at import time.

export interface AxiamClaims {
  /** Subject — user ID (UUID). */
  sub: string;
  /** Tenant ID (UUID). */
  tenant_id: string;
  /** Organization ID (UUID), if present. */
  org_id?: string;
  iss: string;
  iat?: number;
  exp: number;
  /** Unique token ID / session id — needed for logout(). */
  jti?: string;
  /** Token audience — "axiam:user" | "axiam:m2m". */
  aud?: string;
  /** OAuth2 scopes (space-separated). */
  scope?: string;
}

export const JWKS_PATH = '/oauth2/jwks';

const COOLDOWN_DURATION_MS = 60_000;
const TIMEOUT_DURATION_MS = 5_000;

export interface Verifier {
  verifyAccessToken(token: string): Promise<AxiamClaims>;
}

/**
 * Build a verifier bound to `{baseUrl}/oauth2/jwks`. `jose` is loaded lazily
 * via dynamic `import()` (Pitfall 1 — CJS-safe); the remote JWKS itself is
 * also fetched/cached lazily by `jose`, not eagerly here.
 */
export function createVerifier(baseUrl: string): Verifier {
  // Lazily-resolved singleton so repeated verifyAccessToken() calls reuse
  // the same createRemoteJWKSet cache instead of rebuilding it per call.
  let jwksPromise: Promise<ReturnType<typeof import('jose').createRemoteJWKSet>> | null = null;

  async function getJwks() {
    if (!jwksPromise) {
      // eslint-disable-next-line @typescript-eslint/consistent-type-imports
      jwksPromise = import('jose').then(({ createRemoteJWKSet }) =>
        createRemoteJWKSet(new URL(`${baseUrl}${JWKS_PATH}`), {
          cooldownDuration: COOLDOWN_DURATION_MS,
          timeoutDuration: TIMEOUT_DURATION_MS,
        }),
      );
    }
    return jwksPromise;
  }

  return {
    async verifyAccessToken(token: string): Promise<AxiamClaims> {
      const { jwtVerify } = await import('jose');
      const jwks = await getJwks();
      // Explicit algorithm allowlist — never trust the token's own `alg`
      // header; defense against algorithm-confusion attacks (T-17-14).
      const { payload } = await jwtVerify(token, jwks, { algorithms: ['EdDSA'] });
      return payload as unknown as AxiamClaims;
    },
  };
}
