// Reusable msw setupServer (msw/node) with a counted /api/v1/auth/refresh
// handler and a protected endpoint that 401s until refreshed
// (RESEARCH.md Area 10). Shared by singleFlightRefresh.test.ts, csrf.test.ts,
// login.test.ts, and can.test.ts.

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';

export const BASE_URL = 'https://axiam.test';

export interface RefreshCounterState {
  refreshCallCount: number;
  /** Number of times the protected endpoint should 401 before succeeding. */
  protectedFailuresRemaining: number;
}

export function createCounterState(protectedFailuresRemaining = 0): RefreshCounterState {
  return { refreshCallCount: 0, protectedFailuresRemaining };
}

/**
 * Builds the shared msw handler set. `state` is mutable so each test can
 * inspect/reset counters between assertions.
 */
export function buildHandlers(state: RefreshCounterState) {
  return [
    http.post(`${BASE_URL}/api/v1/auth/refresh`, () => {
      state.refreshCallCount += 1;
      return HttpResponse.json({ expires_in: 900 }, { status: 200 });
    }),
    http.get(`${BASE_URL}/api/v1/protected`, () => {
      if (state.protectedFailuresRemaining > 0) {
        state.protectedFailuresRemaining -= 1;
        return HttpResponse.json({ error: 'authentication_failed' }, { status: 401 });
      }
      return HttpResponse.json({ ok: true }, { status: 200 });
    }),
  ];
}

export function createMswServer(state: RefreshCounterState) {
  return setupServer(...buildHandlers(state));
}
