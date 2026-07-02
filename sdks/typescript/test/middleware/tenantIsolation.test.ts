// CR-03 regression (17-VERIFICATION.md): JWKS is org-wide, not tenant-scoped
// (node/jwks.ts), so signature validity alone must never be treated as
// tenant authorization. A token signed with tenant_id 'tenant-1' MUST be
// rejected when verified against a resource server configured for a
// DIFFERENT tenant ('tenant-2'), and MUST still succeed against a resource
// server configured for the matching tenant ('tenant-1').

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import type { Request, Response } from 'express';
import { createVerifier, JWKS_PATH } from '../../src/node/jwks.js';
import { AuthError } from '../../src/core/index.js';
import { authenticateRequest } from '../../src/middleware/verifyCore.js';
import { axiamMiddleware, type AxiamRequest } from '../../src/middleware/express.js';

const BASE_URL = 'https://axiam-tenant-isolation.test';

function fakeRes(): Response {
  const res: Partial<Response> = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  return res as Response;
}

async function signedToken(privateKey: CryptoKey, kid: string): Promise<string> {
  return new SignJWT({ tenant_id: 'tenant-1', scope: 'read write' })
    .setProtectedHeader({ alg: 'EdDSA', kid })
    .setSubject('user-1')
    .setIssuer('axiam')
    .setExpirationTime('1h')
    .sign(privateKey);
}

describe('tenant isolation in middleware verify core (CR-03)', () => {
  const server = setupServer();

  beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
  afterEach(() => server.resetHandlers());
  afterAll(() => server.close());

  async function setupJwks() {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const kid = 'tenant-isolation-kid';
    const jwk = await exportJWK(publicKey);
    jwk.kid = kid;
    jwk.alg = 'EdDSA';
    server.use(http.get(`${BASE_URL}${JWKS_PATH}`, () => HttpResponse.json({ keys: [jwk] })));
    return { privateKey, kid };
  }

  it('authenticateRequest rejects a tenant-1 token against a tenant-2 session', async () => {
    const { privateKey, kid } = await setupJwks();
    const token = await signedToken(privateKey, kid);
    const verifier = createVerifier(BASE_URL);
    const session = { jwksVerifier: verifier, tenantHeaderValue: 'tenant-2' };

    await expect(authenticateRequest(session, token)).rejects.toBeInstanceOf(AuthError);
    await expect(authenticateRequest(session, token)).rejects.toThrow(
      'token tenant_id does not match configured tenant',
    );
  });

  it('authenticateRequest accepts a tenant-1 token against a tenant-1 session (positive control)', async () => {
    const { privateKey, kid } = await setupJwks();
    const token = await signedToken(privateKey, kid);
    const verifier = createVerifier(BASE_URL);
    const session = { jwksVerifier: verifier, tenantHeaderValue: 'tenant-1' };

    const identity = await authenticateRequest(session, token);

    expect(identity.tenantId).toBe('tenant-1');
    expect(identity.userId).toBe('user-1');
  });

  it('axiamMiddleware responds 401 authentication_failed for a cross-tenant token', async () => {
    const { privateKey, kid } = await setupJwks();
    const token = await signedToken(privateKey, kid);
    const verifier = createVerifier(BASE_URL);
    const session = { jwksVerifier: verifier, tenantHeaderValue: 'tenant-2' };

    const req = { headers: { cookie: `axiam_access=${token}` } } as unknown as Request;
    const res = fakeRes();
    const next = vi.fn();

    await axiamMiddleware(session)(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: 'authentication_failed' }),
    );
    expect((req as AxiamRequest).axiamUser).toBeUndefined();
  });
});
