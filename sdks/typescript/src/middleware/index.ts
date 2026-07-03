// AXIAM SDK — middleware entry point (D-27, CONTRACT.md §10).
//
// Re-exports the Express and Fastify middleware plus the shared verify
// core / cookie parser they're both built on.

export { axiamMiddleware, type AxiamRequest } from './express.js';
export { axiamPlugin, type AxiamFastifyRequest } from './fastify.js';
export { authenticateRequest, type AxiamIdentity, type VerifiableSession } from './verifyCore.js';
export { parseCookieHeader, extractToken } from './cookieHeader.js';
