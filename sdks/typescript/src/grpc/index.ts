// AXIAM SDK — gRPC entry (`axiam-sdk/grpc`), Node-only opt-in subpath.
//
// Importing this entry augments the Node persona with gRPC transport
// methods (checkAccess/batchCheck over AuthorizationService, D-15) — it does
// not import gRPC into `core` or `rest` (D-01/D-25), so a `/rest`-only
// bundle never pulls in `@grpc/grpc-js` (SC#1).

export { authInterceptor } from './interceptor.js';
export { callWithRefresh } from './callWithRefresh.js';
export {
  AuthzGrpcClient,
  buildAuthorizationServiceClient,
  type AuthorizationServiceClientFactory,
  type WireAuthorizationServiceClient,
  type WireCheckAccessRequest,
  type WireCheckAccessResponse,
  type WireBatchCheckAccessRequest,
  type WireBatchCheckAccessResponse,
  type CheckAccessRequest,
  type AccessDecision,
} from './client.js';
export { createNodeSession, NodeSession } from '../node/session.js';
export { TokenManager } from '../node/tokenManager.js';
export { createVerifier, type Verifier, type AxiamClaims, JWKS_PATH } from '../node/jwks.js';
export { createJar, wrapAxios, extractCookieValue, ACCESS_COOKIE, REFRESH_COOKIE, CSRF_COOKIE } from '../node/cookieJar.js';
