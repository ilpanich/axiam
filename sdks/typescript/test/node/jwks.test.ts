import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createVerifier, JWKS_PATH } from '../../src/node/jwks.js';

const BASE_URL = 'https://axiam-jwks.test';

describe('jwks verifier', () => {
  const server = setupServer();

  beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
  afterEach(() => server.resetHandlers());
  afterAll(() => server.close());

  it('requests {baseUrl}/oauth2/jwks (asserted against the mocked endpoint)', async () => {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const kid = 'test-kid-1';
    const jwk = await exportJWK(publicKey);
    jwk.kid = kid;
    jwk.alg = 'EdDSA';

    let requestedPath: string | undefined;
    server.use(
      http.get(`${BASE_URL}${JWKS_PATH}`, ({ request }) => {
        requestedPath = new URL(request.url).pathname;
        return HttpResponse.json({ keys: [jwk] });
      }),
    );

    const token = await new SignJWT({ tenant_id: 't-1' })
      .setProtectedHeader({ alg: 'EdDSA', kid })
      .setSubject('user-1')
      .setIssuer('axiam')
      .setExpirationTime('1h')
      .sign(privateKey);

    const verifier = createVerifier(BASE_URL);
    const claims = await verifier.verifyAccessToken(token);

    expect(requestedPath).toBe(JWKS_PATH);
    expect(claims.sub).toBe('user-1');
    expect(claims.tenant_id).toBe('t-1');
  });

  it('accepts a validly-EdDSA-signed token and returns the claims', async () => {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const kid = 'test-kid-2';
    const jwk = await exportJWK(publicKey);
    jwk.kid = kid;
    jwk.alg = 'EdDSA';

    server.use(
      http.get(`${BASE_URL}${JWKS_PATH}`, () => HttpResponse.json({ keys: [jwk] })),
    );

    const token = await new SignJWT({ tenant_id: 'tenant-abc', org_id: 'org-1', scope: 'read write' })
      .setProtectedHeader({ alg: 'EdDSA', kid })
      .setSubject('user-42')
      .setIssuer('axiam')
      .setExpirationTime('1h')
      .sign(privateKey);

    const verifier = createVerifier(BASE_URL);
    const claims = await verifier.verifyAccessToken(token);

    expect(claims.sub).toBe('user-42');
    expect(claims.tenant_id).toBe('tenant-abc');
    expect(claims.org_id).toBe('org-1');
    expect(claims.scope).toBe('read write');
  });

  it('collapses N concurrent verifyAccessToken calls with an unknown kid to exactly one JWKS fetch (D-08/D-09)', async () => {
    // Proves/documents whether jose's createRemoteJWKSet already coalesces
    // concurrent in-flight fetches (RESEARCH.md Pattern 4, PATTERNS.md
    // TypeScript entry) — if it does not, jwks.ts must grow an inFlightFetch
    // guard mirroring the existing jwksPromise lazy-singleton shape.
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const kid = 'burst-kid-1';
    const jwk = await exportJWK(publicKey);
    jwk.kid = kid;
    jwk.alg = 'EdDSA';

    let fetchCallCount = 0;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = ((...args: Parameters<typeof fetch>) => {
      fetchCallCount += 1;
      return originalFetch(...args);
    }) as typeof fetch;

    server.use(
      http.get(`${BASE_URL}${JWKS_PATH}`, () => HttpResponse.json({ keys: [jwk] })),
    );

    try {
      const token = await new SignJWT({ tenant_id: 't-burst' })
        .setProtectedHeader({ alg: 'EdDSA', kid })
        .setSubject('user-burst')
        .setIssuer('axiam')
        .setExpirationTime('1h')
        .sign(privateKey);

      // Cold verifier — the getter/keyset has never been fetched yet.
      const verifier = createVerifier(BASE_URL);

      // Fire 8 genuinely concurrent verifyAccessToken() calls against the
      // cold cache; none is individually awaited before the rest start.
      const results = await Promise.all(
        Array.from({ length: 8 }, () => verifier.verifyAccessToken(token)),
      );

      expect(fetchCallCount).toBe(1);
      for (const claims of results) {
        expect(claims.sub).toBe('user-burst');
        expect(claims.tenant_id).toBe('t-burst');
      }

      // A subsequent verify reuses the already-resolved keyset — no extra fetch.
      await verifier.verifyAccessToken(token);
      expect(fetchCallCount).toBe(1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('rejects a token with alg other than EdDSA even if otherwise well-formed', async () => {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const kid = 'test-kid-3';
    const jwk = await exportJWK(publicKey);
    jwk.kid = kid;
    jwk.alg = 'EdDSA';

    server.use(
      http.get(`${BASE_URL}${JWKS_PATH}`, () => HttpResponse.json({ keys: [jwk] })),
    );

    // Sign a well-formed token with a symmetric HS256 key — jose will reject
    // it before ever reaching signature verification against the EdDSA JWKS,
    // since `algorithms: ['EdDSA']` is passed explicitly (algorithm-confusion
    // defense, T-17-14) rather than trusting the token's own alg header.
    const hsToken = await new SignJWT({ tenant_id: 'tenant-abc' })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject('user-1')
      .setIssuer('axiam')
      .setExpirationTime('1h')
      .sign(new TextEncoder().encode('irrelevant-shared-secret-32-bytes!!'));

    const verifier = createVerifier(BASE_URL);
    void privateKey; // unused in this branch — key pair generated for JWKS shape parity only
    await expect(verifier.verifyAccessToken(hsToken)).rejects.toThrow();
  });
});
