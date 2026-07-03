// @vitest-environment jsdom
//
// Host-isolation (3A, defense in depth): the tenant identifier and CSRF
// token are attached only to requests bound for the client's own origin.
// A request built against an absolute third-party URL must not leak either.

import { http, HttpResponse } from 'msw';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { setupServer } from 'msw/node';
import { AxiamClient } from '../../src/rest/client.js';

const BASE_URL = 'https://axiam.test';
const FOREIGN_URL = 'https://evil.example';

let ownHeaders: Record<string, string> = {};
let foreignHeaders: Record<string, string> = {};

function headersToRecord(headers: Headers): Record<string, string> {
  const record: Record<string, string> = {};
  headers.forEach((value, key) => {
    record[key] = value;
  });
  return record;
}

const server = setupServer(
  http.post(`${BASE_URL}/api/v1/echo`, ({ request }) => {
    ownHeaders = headersToRecord(request.headers);
    return HttpResponse.json({ ok: true }, { status: 200 });
  }),
  http.post(`${FOREIGN_URL}/steal`, ({ request }) => {
    foreignHeaders = headersToRecord(request.headers);
    return HttpResponse.json({ ok: true }, { status: 200 });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

beforeEach(() => {
  ownHeaders = {};
  foreignHeaders = {};
  document.cookie = 'axiam_csrf=; Max-Age=0; path=/';
});

describe('host-isolation (3A)', () => {
  it('injects X-Tenant-ID and X-CSRF-Token on same-origin requests', async () => {
    document.cookie = 'axiam_csrf=csrf-tok';
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });

    await client.session.axios.post('/api/v1/echo', {});

    expect(ownHeaders['x-tenant-id']).toBe('acme');
    expect(ownHeaders['x-csrf-token']).toBe('csrf-tok');
  });

  it('does NOT leak X-Tenant-ID or X-CSRF-Token to an absolute foreign URL', async () => {
    document.cookie = 'axiam_csrf=csrf-tok';
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });

    await client.session.axios.post(`${FOREIGN_URL}/steal`, {});

    expect(foreignHeaders['x-tenant-id']).toBeUndefined();
    expect(foreignHeaders['x-csrf-token']).toBeUndefined();
  });

  it('isForeignHost distinguishes same-origin from off-origin targets', () => {
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    expect(client.session.isForeignHost(undefined)).toBe(false);
    expect(client.session.isForeignHost('/api/v1/echo')).toBe(false);
    expect(client.session.isForeignHost(`${BASE_URL}/api/v1/echo`)).toBe(false);
    expect(client.session.isForeignHost(`${FOREIGN_URL}/steal`)).toBe(true);
  });
});
