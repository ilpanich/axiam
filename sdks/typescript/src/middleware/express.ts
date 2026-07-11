// Express middleware (D-27, CONTRACT.md §10). Express 5 handlers may be
// async — an async middleware that rejects is automatically forwarded to
// Express's error handling, but this middleware always resolves (never
// rejects) since every failure path is caught and turned into a 401/403
// JSON response itself.

import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { AuthError, AuthzError } from '../core/index.js';
import { CSRF_HEADER_NAME, extractCredential, isCsrfValid, isSafeMethod } from './cookieHeader.js';
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

function csrfDeniedBody(): ErrorBody {
  return { error: 'authorization_denied', message: 'csrf validation failed' };
}

/**
 * `axiamMiddleware(session)` — extracts the session (cookie-first, then
 * `Authorization: Bearer` fallback), verifies it locally against the
 * cached JWKS (D-11, no per-request server round-trip on a cache hit),
 * and injects `req.axiamUser` on success. Returns 401 (AuthError) or 403
 * (AuthzError) with a standardized JSON error body on failure.
 *
 * **CSRF (cookie double-submit, CONTRACT.md §3):** when the credential was
 * sourced from the `axiam_access` COOKIE (not the `Authorization` header)
 * and the request method is state-changing (anything other than
 * GET/HEAD/OPTIONS), this middleware additionally requires the
 * `X-CSRF-Token` request header to be present and equal (constant time) to
 * the `axiam_csrf` cookie value, rejecting with 403 on mismatch/absence.
 * Bearer-header requests are CSRF-immune by construction — a cross-site
 * attacker cannot set arbitrary request headers — but a cookie
 * automatically attached by the browser is not, and in any same-site
 * deployment where `axiam_access` reaches this app, the non-`httpOnly`
 * `axiam_csrf` cookie does too. This mirrors, locally, the same
 * double-submit check the AXIAM server performs on its own endpoints (§3).
 */
export function axiamMiddleware(session: VerifiableSession): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const credential = extractCredential(req.headers.cookie, req.headers.authorization);
    if (!credential) {
      res.status(401).json(missingCredentialsBody());
      return;
    }

    if (credential.source === 'cookie' && !isSafeMethod(req.method)) {
      const csrfHeader = req.headers[CSRF_HEADER_NAME];
      const csrfValue = Array.isArray(csrfHeader) ? csrfHeader[0] : csrfHeader;
      if (!isCsrfValid(req.headers.cookie, csrfValue)) {
        res.status(403).json(csrfDeniedBody());
        return;
      }
    }

    try {
      const identity = await authenticateRequest(session, credential.token);
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
