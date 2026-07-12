import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import type { Request, Response } from 'express';
import { createVerifier, JWKS_PATH } from '../../src/node/jwks.js';
import { axiamMiddleware, type AxiamRequest } from '../../src/middleware/express.js';

const BASE_URL = 'https://axiam-mw-express.test';

function fakeRes(): Response {
  const res: Partial<Response> = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  return res as Response;
}

async function signedToken(privateKey: CryptoKey, kid: string, scope = 'read write'): Promise<string> {
  return new SignJWT({ tenant_id: 'tenant-1', scope })
    .setProtectedHeader({ alg: 'EdDSA', kid })
    .setSubject('user-1')
    .setIssuer('axiam')
    .setExpirationTime('1h')
    .sign(privateKey);
}

describe('axiamMiddleware (Express)', () => {
  const server = setupServer();

  beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
  afterEach(() => server.resetHandlers());
  afterAll(() => server.close());

  async function setupJwks() {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const kid = 'express-kid';
    const jwk = await exportJWK(publicKey);
    jwk.kid = kid;
    jwk.alg = 'EdDSA';
    server.use(http.get(`${BASE_URL}${JWKS_PATH}`, () => HttpResponse.json({ keys: [jwk] })));
    return { privateKey, kid };
  }

  it('valid axiam_access cookie -> req.axiamUser set + next() called (200 path)', async () => {
    const { privateKey, kid } = await setupJwks();
    const token = await signedToken(privateKey, kid);
    const verifier = createVerifier(BASE_URL);
    const session = { jwksVerifier: verifier, tenantHeaderValue: 'tenant-1' };

    const req = { headers: { cookie: `axiam_access=${token}` } } as unknown as Request;
    const res = fakeRes();
    const next = vi.fn();

    await axiamMiddleware(session)(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(res.status).not.toHaveBeenCalled();
    const axiamUser = (req as AxiamRequest).axiamUser;
    expect(axiamUser).toBeDefined();
    expect(axiamUser?.userId).toBe('user-1');
    expect(axiamUser?.tenantId).toBe('tenant-1');
    expect(axiamUser?.roles).toEqual(['read', 'write']);
  });

  it('valid Authorization: Bearer token (no cookie) also passes', async () => {
    const { privateKey, kid } = await setupJwks();
    const token = await signedToken(privateKey, kid, 'admin');
    const verifier = createVerifier(BASE_URL);
    const session = { jwksVerifier: verifier, tenantHeaderValue: 'tenant-1' };

    const req = { headers: { authorization: `Bearer ${token}` } } as unknown as Request;
    const res = fakeRes();
    const next = vi.fn();

    await axiamMiddleware(session)(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect((req as AxiamRequest).axiamUser?.roles).toEqual(['admin']);
  });

  it('missing credentials -> 401 JSON, next() not called', async () => {
    const verifier = createVerifier(BASE_URL);
    const session = { jwksVerifier: verifier, tenantHeaderValue: 'tenant-1' };

    const req = { headers: {} } as unknown as Request;
    const res = fakeRes();
    const next = vi.fn();

    await axiamMiddleware(session)(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: 'authentication_failed' }),
    );
  });

  it('invalid/expired token -> 401 JSON', async () => {
    await setupJwks();
    const verifier = createVerifier(BASE_URL);
    const session = { jwksVerifier: verifier, tenantHeaderValue: 'tenant-1' };

    const req = { headers: { cookie: 'axiam_access=not-a-real-token' } } as unknown as Request;
    const res = fakeRes();
    const next = vi.fn();

    await axiamMiddleware(session)(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: 'authentication_failed' }),
    );
  });

  describe('CSRF (cookie double-submit, CONTRACT.md §3)', () => {
    it('cookie-auth POST without X-CSRF-Token header -> 403, next() not called', async () => {
      const { privateKey, kid } = await setupJwks();
      const token = await signedToken(privateKey, kid);
      const verifier = createVerifier(BASE_URL);
      const session = { jwksVerifier: verifier, tenantHeaderValue: 'tenant-1' };

      const req = {
        method: 'POST',
        headers: { cookie: `axiam_access=${token}` },
      } as unknown as Request;
      const res = fakeRes();
      const next = vi.fn();

      await axiamMiddleware(session)(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: 'authorization_denied' }),
      );
    });

    it('cookie-auth POST with matching X-CSRF-Token header + axiam_csrf cookie -> passes auth', async () => {
      const { privateKey, kid } = await setupJwks();
      const token = await signedToken(privateKey, kid);
      const verifier = createVerifier(BASE_URL);
      const session = { jwksVerifier: verifier, tenantHeaderValue: 'tenant-1' };

      const req = {
        method: 'POST',
        headers: {
          cookie: `axiam_access=${token}; axiam_csrf=csrf-secret-1`,
          'x-csrf-token': 'csrf-secret-1',
        },
      } as unknown as Request;
      const res = fakeRes();
      const next = vi.fn();

      await axiamMiddleware(session)(req, res, next);

      expect(next).toHaveBeenCalledOnce();
      expect(res.status).not.toHaveBeenCalled();
      expect((req as AxiamRequest).axiamUser?.userId).toBe('user-1');
    });

    it('Bearer-auth POST without CSRF header -> passes (no CSRF required for Bearer)', async () => {
      const { privateKey, kid } = await setupJwks();
      const token = await signedToken(privateKey, kid);
      const verifier = createVerifier(BASE_URL);
      const session = { jwksVerifier: verifier, tenantHeaderValue: 'tenant-1' };

      const req = {
        method: 'POST',
        headers: { authorization: `Bearer ${token}` },
      } as unknown as Request;
      const res = fakeRes();
      const next = vi.fn();

      await axiamMiddleware(session)(req, res, next);

      expect(next).toHaveBeenCalledOnce();
      expect(res.status).not.toHaveBeenCalled();
    });

    it('cookie-auth GET without CSRF -> passes (safe method)', async () => {
      const { privateKey, kid } = await setupJwks();
      const token = await signedToken(privateKey, kid);
      const verifier = createVerifier(BASE_URL);
      const session = { jwksVerifier: verifier, tenantHeaderValue: 'tenant-1' };

      const req = {
        method: 'GET',
        headers: { cookie: `axiam_access=${token}` },
      } as unknown as Request;
      const res = fakeRes();
      const next = vi.fn();

      await axiamMiddleware(session)(req, res, next);

      expect(next).toHaveBeenCalledOnce();
      expect(res.status).not.toHaveBeenCalled();
    });
  });
});
