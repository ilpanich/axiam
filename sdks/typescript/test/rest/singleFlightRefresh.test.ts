// SC#3: 5 concurrent authenticated requests receiving 401 trigger exactly 1
// call to POST /api/v1/auth/refresh, and all 5 originals are retried and
// succeed. A 401 on the refresh endpoint itself must not trigger another
// refresh (SKIP_REFRESH + §9.3 no-retry).

import { http, HttpResponse } from 'msw';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { AxiamClient } from '../../src/rest/client.js';
import { AuthError } from '../../src/core/index.js';
import { resetRefreshGuard } from '../../src/core/index.js';
import { BASE_URL, createCounterState, createMswServer } from './mswServer.js';

const state = createCounterState(5);
const server = createMswServer(state);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => {
  server.resetHandlers();
  resetRefreshGuard();
});
afterAll(() => server.close());

describe('reactive single-flight refresh (SC#3)', () => {
  it('calls refresh exactly once for 5 concurrent 401s and retries all originals successfully', async () => {
    state.refreshCallCount = 0;
    state.protectedFailuresRemaining = 5;

    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    client.session.authenticated = true;

    const requests = Array.from({ length: 5 }, () => client.session.axios.get('/api/v1/protected'));

    const results = await Promise.all(requests);

    expect(results).toHaveLength(5);
    for (const result of results) {
      expect(result.status).toBe(200);
    }
    expect(state.refreshCallCount).toBe(1);
  });

  it('does not retry a 401 on the refresh endpoint itself (SKIP_REFRESH + no-retry)', async () => {
    server.use(
      http.post(`${BASE_URL}/api/v1/auth/refresh`, () =>
        HttpResponse.json({ error: 'authentication_failed' }, { status: 401 }),
      ),
    );

    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    client.session.authenticated = true;

    await expect(client.session.axios.post('/api/v1/auth/refresh', {})).rejects.toBeInstanceOf(AuthError);
  });
});
