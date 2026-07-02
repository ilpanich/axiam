// CR-02 regression (17-VERIFICATION.md, D-13): the single-flight refresh
// guard MUST be scoped per SharedSession/NodeSession instance, never shared
// across independent AxiamClient instances in the same process. Two
// distinct sessions each firing a concurrent 401-driven refresh must each
// call their OWN /api/v1/auth/refresh endpoint exactly once — a refresh on
// session A must never silently satisfy a concurrent refresh on session B.

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { AxiamClient } from '../../src/rest/client.js';

const BASE_URL_A = 'https://tenant-a.test';
const BASE_URL_B = 'https://tenant-b.test';

interface CounterState {
  refreshCallCount: number;
  protectedFailuresRemaining: number;
}

function makeState(protectedFailuresRemaining = 1): CounterState {
  return { refreshCallCount: 0, protectedFailuresRemaining };
}

function handlersFor(baseUrl: string, state: CounterState) {
  return [
    http.post(`${baseUrl}/api/v1/auth/refresh`, () => {
      state.refreshCallCount += 1;
      return HttpResponse.json({ expires_in: 900 }, { status: 200 });
    }),
    http.get(`${baseUrl}/api/v1/protected`, () => {
      if (state.protectedFailuresRemaining > 0) {
        state.protectedFailuresRemaining -= 1;
        return HttpResponse.json({ error: 'authentication_failed' }, { status: 401 });
      }
      return HttpResponse.json({ ok: true }, { status: 200 });
    }),
  ];
}

const stateA = makeState(1);
const stateB = makeState(1);
const server = setupServer(...handlersFor(BASE_URL_A, stateA), ...handlersFor(BASE_URL_B, stateB));

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => {
  server.resetHandlers();
});
afterAll(() => server.close());

describe('per-session single-flight refresh guard (CR-02)', () => {
  it('two independent sessions each refresh exactly once, with no cross-wiring', async () => {
    stateA.refreshCallCount = 0;
    stateA.protectedFailuresRemaining = 5;
    stateB.refreshCallCount = 0;
    stateB.protectedFailuresRemaining = 5;

    const clientA = new AxiamClient({ baseUrl: BASE_URL_A, tenantSlug: 'tenant-a' });
    const clientB = new AxiamClient({ baseUrl: BASE_URL_B, tenantSlug: 'tenant-b' });
    clientA.session.authenticated = true;
    clientB.session.authenticated = true;

    // Distinct guard instances — this is the structural CR-02 assertion:
    // two independently-constructed sessions must never share a guard.
    expect(clientA.session.refreshGuard).not.toBe(clientB.session.refreshGuard);

    const requestsA = Array.from({ length: 5 }, () => clientA.session.axios.get('/api/v1/protected'));
    const requestsB = Array.from({ length: 5 }, () => clientB.session.axios.get('/api/v1/protected'));

    const [resultsA, resultsB] = await Promise.all([Promise.all(requestsA), Promise.all(requestsB)]);

    expect(resultsA).toHaveLength(5);
    expect(resultsB).toHaveLength(5);
    for (const result of [...resultsA, ...resultsB]) {
      expect(result.status).toBe(200);
    }

    // Each session's own refresh endpoint was called exactly once — neither
    // session's concurrent refresh was silently satisfied by the other.
    expect(stateA.refreshCallCount).toBe(1);
    expect(stateB.refreshCallCount).toBe(1);
  });
});
