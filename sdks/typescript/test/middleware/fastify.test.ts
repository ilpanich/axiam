import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import Fastify from 'fastify';
import { createVerifier, JWKS_PATH } from '../../src/node/jwks.js';
import { axiamPlugin, type AxiamFastifyRequest } from '../../src/middleware/fastify.js';

const BASE_URL = 'https://axiam-mw-fastify.test';

async function signedToken(privateKey: CryptoKey, kid: string, scope = 'read write'): Promise<string> {
  return new SignJWT({ tenant_id: 'tenant-1', scope })
    .setProtectedHeader({ alg: 'EdDSA', kid })
    .setSubject('user-1')
    .setIssuer('axiam')
    .setExpirationTime('1h')
    .sign(privateKey);
}

describe('axiamPlugin (Fastify)', () => {
  const server = setupServer();

  beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
  afterEach(() => server.resetHandlers());
  afterAll(() => server.close());

  async function setupJwks() {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const kid = 'fastify-kid';
    const jwk = await exportJWK(publicKey);
    jwk.kid = kid;
    jwk.alg = 'EdDSA';
    server.use(http.get(`${BASE_URL}${JWKS_PATH}`, () => HttpResponse.json({ keys: [jwk] })));
    return { privateKey, kid };
  }

  async function buildApp(session: { jwksVerifier: ReturnType<typeof createVerifier>; tenantHeaderValue: string }) {
    const app = Fastify();
    await app.register(axiamPlugin(session));
    app.get('/protected', async (request) => {
      const axiamUser = (request as AxiamFastifyRequest).axiamUser;
      return { axiamUser };
    });
    await app.ready();
    return app;
  }

  it('valid axiam_access cookie -> request.axiamUser set + handler reached (200)', async () => {
    const { privateKey, kid } = await setupJwks();
    const token = await signedToken(privateKey, kid);
    const verifier = createVerifier(BASE_URL);
    const app = await buildApp({ jwksVerifier: verifier, tenantHeaderValue: 'tenant-1' });

    const response = await app.inject({
      method: 'GET',
      url: '/protected',
      headers: { cookie: `axiam_access=${token}` },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.axiamUser.userId).toBe('user-1');
    expect(body.axiamUser.tenantId).toBe('tenant-1');
    expect(body.axiamUser.roles).toEqual(['read', 'write']);

    await app.close();
  });

  it('valid Authorization: Bearer token (no cookie) also passes', async () => {
    const { privateKey, kid } = await setupJwks();
    const token = await signedToken(privateKey, kid, 'admin');
    const verifier = createVerifier(BASE_URL);
    const app = await buildApp({ jwksVerifier: verifier, tenantHeaderValue: 'tenant-1' });

    const response = await app.inject({
      method: 'GET',
      url: '/protected',
      headers: { authorization: `Bearer ${token}` },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().axiamUser.roles).toEqual(['admin']);

    await app.close();
  });

  it('missing credentials -> 401 JSON', async () => {
    const verifier = createVerifier(BASE_URL);
    const app = await buildApp({ jwksVerifier: verifier, tenantHeaderValue: 'tenant-1' });

    const response = await app.inject({ method: 'GET', url: '/protected' });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual(
      expect.objectContaining({ error: 'authentication_failed' }),
    );

    await app.close();
  });

  it('invalid/expired token -> 401 JSON', async () => {
    await setupJwks();
    const verifier = createVerifier(BASE_URL);
    const app = await buildApp({ jwksVerifier: verifier, tenantHeaderValue: 'tenant-1' });

    const response = await app.inject({
      method: 'GET',
      url: '/protected',
      headers: { cookie: 'axiam_access=not-a-real-token' },
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual(
      expect.objectContaining({ error: 'authentication_failed' }),
    );

    await app.close();
  });

  describe('CSRF (cookie double-submit, CONTRACT.md §3)', () => {
    async function buildAppWithPost(session: {
      jwksVerifier: ReturnType<typeof createVerifier>;
      tenantHeaderValue: string;
    }) {
      const app = Fastify();
      await app.register(axiamPlugin(session));
      app.post('/protected', async (request) => {
        const axiamUser = (request as AxiamFastifyRequest).axiamUser;
        return { axiamUser };
      });
      await app.ready();
      return app;
    }

    it('cookie-auth POST without X-CSRF-Token header -> 403', async () => {
      const { privateKey, kid } = await setupJwks();
      const token = await signedToken(privateKey, kid);
      const verifier = createVerifier(BASE_URL);
      const app = await buildAppWithPost({ jwksVerifier: verifier, tenantHeaderValue: 'tenant-1' });

      const response = await app.inject({
        method: 'POST',
        url: '/protected',
        headers: { cookie: `axiam_access=${token}` },
      });

      expect(response.statusCode).toBe(403);
      expect(response.json()).toEqual(
        expect.objectContaining({ error: 'authorization_denied' }),
      );

      await app.close();
    });

    it('cookie-auth POST with matching X-CSRF-Token header + axiam_csrf cookie -> passes auth', async () => {
      const { privateKey, kid } = await setupJwks();
      const token = await signedToken(privateKey, kid);
      const verifier = createVerifier(BASE_URL);
      const app = await buildAppWithPost({ jwksVerifier: verifier, tenantHeaderValue: 'tenant-1' });

      const response = await app.inject({
        method: 'POST',
        url: '/protected',
        headers: {
          cookie: `axiam_access=${token}; axiam_csrf=csrf-secret-1`,
          'x-csrf-token': 'csrf-secret-1',
        },
      });

      expect(response.statusCode).toBe(200);
      expect(response.json().axiamUser.userId).toBe('user-1');

      await app.close();
    });

    it('Bearer-auth POST without CSRF header -> passes (no CSRF required for Bearer)', async () => {
      const { privateKey, kid } = await setupJwks();
      const token = await signedToken(privateKey, kid);
      const verifier = createVerifier(BASE_URL);
      const app = await buildAppWithPost({ jwksVerifier: verifier, tenantHeaderValue: 'tenant-1' });

      const response = await app.inject({
        method: 'POST',
        url: '/protected',
        headers: { authorization: `Bearer ${token}` },
      });

      expect(response.statusCode).toBe(200);

      await app.close();
    });

    it('cookie-auth GET without CSRF -> passes (safe method)', async () => {
      const { privateKey, kid } = await setupJwks();
      const token = await signedToken(privateKey, kid);
      const verifier = createVerifier(BASE_URL);
      const app = await buildApp({ jwksVerifier: verifier, tenantHeaderValue: 'tenant-1' });

      const response = await app.inject({
        method: 'GET',
        url: '/protected',
        headers: { cookie: `axiam_access=${token}` },
      });

      expect(response.statusCode).toBe(200);

      await app.close();
    });
  });
});
