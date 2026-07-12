// AXIAM SDK — Node entry (`axiam-sdk/node`), Node-only opt-in subpath.
//
// The Node persona's REST construction path (SDK-Q05): `createNodeClient`
// builds an `AxiamClient` backed by a `NodeSession` (tough-cookie jar +
// CSRF/refresh token sync) so httpOnly login/refresh cookies persist under
// Node. Importing this entry pulls in the Node-only deps (tough-cookie, jose,
// node:https) — it is NOT reachable from the browser-safe `.`/`/rest` entries,
// which keep bundling zero Node dependencies (SC#1, D-01/D-25).

export { createNodeClient, createNodeSession, NodeSession } from './session.js';
export { TokenManager } from './tokenManager.js';
export { createVerifier, type Verifier, type AxiamClaims, JWKS_PATH } from './jwks.js';
export {
  createJar,
  wrapAxios,
  extractCookieValue,
  ACCESS_COOKIE,
  REFRESH_COOKIE,
  CSRF_COOKIE,
} from './cookieJar.js';
