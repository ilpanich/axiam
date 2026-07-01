// Express middleware (D-27, CONTRACT.md §10). Express 5 handlers may be
// async — an async middleware that rejects is automatically forwarded to
// Express's error handling, but this middleware always resolves (never
// rejects) since every failure path is caught and turned into a 401/403
// JSON response itself.

import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { AuthError, AuthzError } from '../core/index.js';
import { extractToken } from './cookieHeader.js';
import { authenticateRequest, type AxiamIdentity, type VerifiableSession } from './verifyCore.js';

export interface AxiamRequest extends Request {
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
 * `axiamMiddleware(session)` — extracts the session (cookie-first, then
 * `Authorization: Bearer` fallback), verifies it locally against the
 * cached JWKS (D-11, no per-request server round-trip on a cache hit),
 * and injects `req.axiamUser` on success. Returns 401 (AuthError) or 403
 * (AuthzError) with a standardized JSON error body on failure.
 */
export function axiamMiddleware(session: VerifiableSession): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const token = extractToken(req.headers.cookie, req.headers.authorization);
    if (!token) {
      res.status(401).json(missingCredentialsBody());
      return;
    }

    try {
      const identity = await authenticateRequest(session, token);
      (req as AxiamRequest).axiamUser = identity;
      next();
    } catch (err) {
      if (err instanceof AuthzError) {
        res.status(403).json(authzDeniedBody(err.message));
        return;
      }
      if (err instanceof AuthError) {
        res.status(401).json(invalidTokenBody(err.message));
        return;
      }
      res.status(401).json(invalidTokenBody('invalid or expired token'));
    }
  };
}
