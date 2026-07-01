// AXIAM SDK — REST entry (`axiam-sdk/rest`).
//
// Isomorphic REST core (browser + Node). The AxiamClient class, SharedSession,
// and REST auth/authz methods are implemented across 17-02 (browser persona);
// the Node persona (17-03) augments the same SharedSession with a cookie jar
// and local JWKS verification.

export { AxiamClient } from './client.js';
export { SharedSession } from './session.js';
export { SKIP_REFRESH } from './interceptors.js';
export { withRetry } from './retry.js';
export type { RetryOptions } from './retry.js';
