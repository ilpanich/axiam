// Fastify middleware (D-27, CONTRACT.md §10) — registered as a
// `preHandler` hook via a FastifyPluginAsync, mirroring express.ts's
// verification flow through the same shared verifyCore.

import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import { AuthError, AuthzError } from '../core/index.js';
import { CSRF_HEADER_NAME, extractCredential, isCsrfValid, isSafeMethod } from './cookieHeader.js';
import { authenticateRequest, type AxiamIdentity, type VerifiableSession } from './verifyCore.js';

export interface AxiamFastifyRequest extends FastifyRequest {
  axiamUser?: AxiamIdentity;
}

interface ErrorBody {
  error: string;
  message: string;
}

function missingCredentialsBody(): ErrorBody {
  return { error: 'authentication_failed', message: 'missing authentication credentials' };
}

function invalidTokenBody(message: string): ErrorBody {
  return { error: 'authentication_failed', message };
}

function authzDeniedBody(message: string): ErrorBody {
  return { error: 'authorization_denied', message };
}

function csrfDeniedBody(): ErrorBody {
  return { error: 'authorization_denied', message: 'csrf validation failed' };
}

/**
 * `axiamPlugin(session)` — a `FastifyPluginAsync` registering a
 * `preHandler` hook that extracts the session (cookie-first, then
 * `Authorization: Bearer` fallback), verifies it locally against the
 * cached JWKS (D-11), and injects `request.axiamUser` on success.
 * Replies 401 (AuthError) or 403 (AuthzError) with a standardized JSON
 * error body on failure.
 *
 * **CSRF (cookie double-submit, CONTRACT.md §3):** when the credential was
 * sourced from the `axiam_access` COOKIE (not the `Authorization` header)
 * and the request method is state-changing (anything other than
 * GET/HEAD/OPTIONS), this hook additionally requires the `X-CSRF-Token`
 * request header to be present and equal (constant time) to the
 * `axiam_csrf` cookie value, replying 403 on mismatch/absence. Bearer-header
 * requests are CSRF-immune by construction — a cross-site attacker cannot
 * set arbitrary request headers — but a cookie automatically attached by
 * the browser is not, and in any same-site deployment where `axiam_access`
 * reaches this app, the non-`httpOnly` `axiam_csrf` cookie does too. This
 * mirrors, locally, the same double-submit check the AXIAM server performs
 * on its own endpoints (§3).
 *
 * Marked with fastify's own `skip-override` plugin symbol (the same
 * mechanism the `fastify-plugin` package wraps) so the `preHandler` hook
 * applies to routes registered as siblings of this plugin rather than
 * being scoped only to its own encapsulation context — avoids adding
 * `fastify-plugin` as a dependency for a one-line escape hatch.
 */
export const axiamPlugin: (session: VerifiableSession) => FastifyPluginAsync = (session) => {
  const plugin: FastifyPluginAsync = async (fastify) => {
    fastify.addHook('preHandler', async (request: FastifyRequest, reply: FastifyReply) => {
      const credential = extractCredential(request.headers.cookie, request.headers.authorization);
      if (!credential) {
        return reply.code(401).send(missingCredentialsBody());
      }

      if (credential.source === 'cookie' && !isSafeMethod(request.method)) {
        const csrfHeader = request.headers[CSRF_HEADER_NAME];
        const csrfValue = Array.isArray(csrfHeader) ? csrfHeader[0] : csrfHeader;
        if (!isCsrfValid(request.headers.cookie, csrfValue)) {
          return reply.code(403).send(csrfDeniedBody());
        }
      }

      try {
        const identity = await authenticateRequest(session, credential.token);
        (request as AxiamFastifyRequest).axiamUser = identity;
      } catch (err) {
        if (err instanceof AuthzError) {
          return reply.code(403).send(authzDeniedBody(err.message));
        }
        if (err instanceof AuthError) {
          return reply.code(401).send(invalidTokenBody(err.message));
        }
        return reply.code(401).send(invalidTokenBody('invalid or expired token'));
      }
    });
  };
  (plugin as unknown as Record<symbol, unknown>)[Symbol.for('skip-override')] = true;
  (plugin as unknown as Record<symbol, unknown>)[Symbol.for('fastify.display-name')] =
    'axiam-plugin';
  return plugin;
};
