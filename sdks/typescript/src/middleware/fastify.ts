// Fastify middleware (D-27, CONTRACT.md §10) — registered as a
// `preHandler` hook via a FastifyPluginAsync, mirroring express.ts's
// verification flow through the same shared verifyCore.

import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import { AuthError, AuthzError } from '../core/index.js';
import { extractToken } from './cookieHeader.js';
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

/**
 * `axiamPlugin(session)` — a `FastifyPluginAsync` registering a
 * `preHandler` hook that extracts the session (cookie-first, then
 * `Authorization: Bearer` fallback), verifies it locally against the
 * cached JWKS (D-11), and injects `request.axiamUser` on success.
 * Replies 401 (AuthError) or 403 (AuthzError) with a standardized JSON
 * error body on failure.
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
      const token = extractToken(request.headers.cookie, request.headers.authorization);
      if (!token) {
        return reply.code(401).send(missingCredentialsBody());
      }

      try {
        const identity = await authenticateRequest(session, token);
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
