// createNodeSession — extends the 17-02 SharedSession with the Node
// persona's auth internals (D-13).
//
// Builds the same REST SharedSession the browser persona uses, then swaps
// in a tough-cookie jar (via wrapAxios) so httpOnly Set-Cookie tokens
// persist, and attaches a TokenManager + JWKS verifier. This is the ONE
// shared session object gRPC (interceptor.ts/callWithRefresh.ts) and REST
// both operate on — the single-flight refresh guard (`session.refreshGuard`,
// a per-session instance created in the SharedSession constructor, CR-02)
// is therefore transparently shared across both transports FOR THIS
// SESSION ONLY, since both call it with an equivalent `POST
// /api/v1/auth/refresh` closure. A different NodeSession/SharedSession
// instance gets its own independent guard — refreshes never cross-wire
// between sessions.

import type { AxiamClientOptions } from '../core/index.js';
import { createSession, SharedSession } from '../rest/session.js';
import { createJar, wrapAxios } from './cookieJar.js';
import { TokenManager } from './tokenManager.js';
import { createVerifier, type Verifier } from './jwks.js';

export class NodeSession extends SharedSession {
  readonly tokenManager: TokenManager;
  readonly jwksVerifier: Verifier;

  constructor(options: AxiamClientOptions, base: SharedSession, tokenManager: TokenManager, jwksVerifier: Verifier) {
    super(options, base.axios, base.tenantHeaderValue);
    this.tokenManager = tokenManager;
    this.jwksVerifier = jwksVerifier;
  }

  /**
   * Drives the actual `POST /api/v1/auth/refresh` HTTP call. Passed to this
   * session's per-instance `refreshGuard` (inherited from SharedSession) by
   * both REST's reactive interceptor (rest/interceptors.ts) and gRPC's
   * callWithRefresh — since `refreshGuard` is scoped to THIS session
   * instance (CR-02, D-13), both transports share exactly one in-flight
   * refresh for this session regardless of which one triggers it, while
   * remaining fully independent from any other session's guard.
   */
  doRefresh = async (): Promise<void> => {
    await this.axios.post('/api/v1/auth/refresh', {});
    await this.tokenManager.syncFromJar();
  };
}

/** Build the Node persona's session: REST SharedSession + cookie jar + TokenManager + JWKS verifier. */
export function createNodeSession(options: AxiamClientOptions): NodeSession {
  const base = createSession(options);
  const jar = createJar();
  wrapAxios(base.axios, jar);

  const tokenManager = new TokenManager(jar, options.baseUrl, base.tenantHeaderValue);
  const jwksVerifier = createVerifier(options.baseUrl);

  return new NodeSession(options, base, tokenManager, jwksVerifier);
}
