// Node CSRF forwarding regression (CR-01, D-05): session.csrfToken must be
// populated for the Node persona via a jar-read (mirroring
// TokenManager.syncFromJar()), invoked after onAuthenticated() (the hook
// rest/auth.ts calls post-login/verifyMfa) and after doRefresh(). This test
// intentionally uses a REAL tough-cookie jar (not `@vitest-environment
// jsdom`) — the Node persona must never depend on document.cookie.

import { CookieJar } from 'tough-cookie';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createVerifier } from '../../src/node/jwks.js';
import { ACCESS_COOKIE, CSRF_COOKIE, wrapAxios } from '../../src/node/cookieJar.js';
import { NodeSession } from '../../src/node/session.js';
import { createSession } from '../../src/rest/session.js';
import { installInterceptors } from '../../src/rest/interceptors.js';
import { TokenManager } from '../../src/node/tokenManager.js';

const BASE_URL = 'https://axiam-node-csrf.test';

let capturedHeaders: Record<string, string> = {};

function headersToRecord(headers: Headers): Record<string, string> {
  const record: Record<string, string> = {};
  headers.forEach((value, key) => {
    record[key] = value;
  });
  return record;
}

const server = setupServer(
  http.post(`${BASE_URL}/api/v1/echo`, ({ request }) => {
    capturedHeaders = headersToRecord(request.headers);
    return HttpResponse.json({ ok: true }, { status: 200 });
  }),
  http.get(`${BASE_URL}/api/v1/echo`, ({ request }) => {
    capturedHeaders = headersToRecord(request.headers);
    return HttpResponse.json({ ok: true }, { status: 200 });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => {
  server.resetHandlers();
  capturedHeaders = {};
});
afterAll(() => server.close());

/**
 * Build a real jar-backed NodeSession (mirrors
 * test/grpc/checkAccess.test.ts's buildTestSession pattern), seeded with an
 * axiam_csrf cookie as if the server had already Set-Cookie'd it during
 * login.
 */
async function buildTestSession(csrfValue: string): Promise<NodeSession> {
  const jar = new CookieJar();
  await jar.setCookie(`${ACCESS_COOKIE}=cached-access-token; Path=/`, BASE_URL);
  await jar.setCookie(`${CSRF_COOKIE}=${csrfValue}; Path=/`, BASE_URL);

  const base = createSession({ baseUrl: BASE_URL, tenantSlug: 'acme' });
  wrapAxios(base.axios, jar);
  const tokenManager = new TokenManager(jar, BASE_URL, base.tenantHeaderValue);
  const jwksVerifier = createVerifier(BASE_URL);
  const session = new NodeSession({ baseUrl: BASE_URL, tenantSlug: 'acme' }, base, tokenManager, jwksVerifier, jar);
  installInterceptors(session.axios, session);
  return session;
}

describe('Node CSRF forwarding (CR-01, D-05)', () => {
  it('onAuthenticated() syncs session.csrfToken from the jar; subsequent POST forwards X-CSRF-Token', async () => {
    const session = await buildTestSession('node-csrf-value');

    expect(session.csrfToken).toBeUndefined();

    await session.onAuthenticated();

    expect(session.csrfToken).toBe('node-csrf-value');

    await session.axios.post('/api/v1/echo', {});

    expect(capturedHeaders['x-csrf-token']).toBe('node-csrf-value');
  });

  it('GET requests still omit X-CSRF-Token after onAuthenticated() (safe methods unchanged)', async () => {
    const session = await buildTestSession('node-csrf-value');
    await session.onAuthenticated();

    await session.axios.get('/api/v1/echo');

    expect(capturedHeaders['x-csrf-token']).toBeUndefined();
  });

  it('doRefresh() resyncs session.csrfToken from the jar (cookie rotation)', async () => {
    const jar = new CookieJar();
    await jar.setCookie(`${ACCESS_COOKIE}=cached-access-token; Path=/`, BASE_URL);
    await jar.setCookie(`${CSRF_COOKIE}=initial-csrf-value; Path=/`, BASE_URL);

    const base = createSession({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    wrapAxios(base.axios, jar);
    const tokenManager = new TokenManager(jar, BASE_URL, base.tenantHeaderValue);
    const jwksVerifier = createVerifier(BASE_URL);
    const session = new NodeSession({ baseUrl: BASE_URL, tenantSlug: 'acme' }, base, tokenManager, jwksVerifier, jar);
    installInterceptors(session.axios, session);

    await session.onAuthenticated();
    expect(session.csrfToken).toBe('initial-csrf-value');

    // Simulate the refresh endpoint rotating the axiam_csrf cookie: msw
    // serves the refresh POST response, and (since axios-cookiejar-support's
    // agent-level cookie persistence does not observe msw's mocked
    // ClientRequest/response pair — msw intercepts before the custom Agent's
    // addRequest() runs) the rotated Set-Cookie is written directly into the
    // jar here, exactly as the real HttpCookieAgent would do against a live
    // server response. What THIS test proves is the code path under test:
    // that doRefresh() re-reads session.csrfToken from the jar afterward.
    server.use(
      http.post(`${BASE_URL}/api/v1/auth/refresh`, async () => {
        await jar.setCookie(`${CSRF_COOKIE}=rotated-csrf-value; Path=/`, BASE_URL);
        return HttpResponse.json({}, { status: 200 });
      }),
    );

    await session.doRefresh();

    expect(session.csrfToken).toBe('rotated-csrf-value');

    await session.axios.post('/api/v1/echo', {});
    expect(capturedHeaders['x-csrf-token']).toBe('rotated-csrf-value');
  });

  it('omits X-CSRF-Token on POST before onAuthenticated() has run (no cookie synced yet)', async () => {
    const session = await buildTestSession('node-csrf-value');

    await session.axios.post('/api/v1/echo', {});

    expect(capturedHeaders['x-csrf-token']).toBeUndefined();
  });
});
