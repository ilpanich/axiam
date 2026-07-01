// @vitest-environment jsdom
//
// CSRF double-submit forwarding (D-05, §3): X-CSRF-Token equals the
// axiam_csrf cookie value on state-changing methods (POST/PUT/PATCH/DELETE);
// absent on GET.

import { http, HttpResponse } from 'msw';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { setupServer } from 'msw/node';
import { AxiamClient } from '../../src/rest/client.js';

const BASE_URL = 'https://axiam.test';

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
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

beforeEach(() => {
  capturedHeaders = {};
  document.cookie = 'axiam_csrf=; Max-Age=0; path=/';
});

describe('CSRF forwarding (D-05/§3)', () => {
  it('sets X-CSRF-Token from the axiam_csrf cookie on POST', async () => {
    document.cookie = 'axiam_csrf=test-csrf-token';

    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    await client.session.axios.post('/api/v1/echo', {});

    expect(capturedHeaders['x-csrf-token']).toBe('test-csrf-token');
  });

  it('omits X-CSRF-Token on GET', async () => {
    document.cookie = 'axiam_csrf=test-csrf-token';

    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    await client.session.axios.get('/api/v1/echo');

    expect(capturedHeaders['x-csrf-token']).toBeUndefined();
  });

  it('omits X-CSRF-Token on POST when no cookie is present', async () => {
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    await client.session.axios.post('/api/v1/echo', {});

    expect(capturedHeaders['x-csrf-token']).toBeUndefined();
  });
});

describe('AxiamClient tenant requirement (§5)', () => {
  it('throws when constructed without tenantSlug or tenantId', () => {
    expect(() => new AxiamClient({ baseUrl: BASE_URL })).toThrow(/tenant/i);
  });
});
