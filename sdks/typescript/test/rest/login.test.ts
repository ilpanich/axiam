// login()/verifyMfa() (D-18, §1): both LoginResult discriminated-union
// branches, and no access_token/accessToken field ever appears on the
// result (tokens arrive exclusively via Set-Cookie, T-17-07).

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { AxiamClient } from '../../src/rest/client.js';

const BASE_URL = 'https://axiam.test';

const server = setupServer(
  http.post(`${BASE_URL}/api/v1/auth/login`, async ({ request }) => {
    const body = (await request.json()) as { username_or_email: string; password: string };
    if (body.username_or_email === 'mfa@example.com') {
      return HttpResponse.json(
        {
          mfa_required: true,
          challenge_token: 'challenge-abc-123',
          available_methods: ['totp'],
        },
        { status: 202 },
      );
    }
    return HttpResponse.json(
      {
        user: { id: 'user-1', username: 'alice', email: 'alice@example.com' },
        session_id: 'session-1',
        expires_in: 900,
      },
      { status: 200 },
    );
  }),
  http.post(`${BASE_URL}/api/v1/auth/mfa/verify`, async ({ request }) => {
    const body = (await request.json()) as { challenge_token: string; totp_code: string };
    if (body.challenge_token !== 'challenge-abc-123' || body.totp_code !== '123456') {
      return HttpResponse.json({ error: 'authentication_failed' }, { status: 401 });
    }
    return HttpResponse.json(
      {
        user: { id: 'user-2', username: 'mfauser', email: 'mfa@example.com' },
        session_id: 'session-2',
        expires_in: 900,
      },
      { status: 200 },
    );
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe('login() (D-18)', () => {
  it('returns the authenticated branch on a 200 response', async () => {
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    const result = await client.login('alice@example.com', 'password123');

    expect(result.status).toBe('authenticated');
    if (result.status === 'authenticated') {
      expect(result.sessionId).toBe('session-1');
      expect(result.expiresIn).toBe(900);
      expect(result.user.email).toBe('alice@example.com');
    }
    expect(result).not.toHaveProperty('access_token');
    expect(result).not.toHaveProperty('accessToken');
  });

  it('returns the mfa_required branch on a 202 response, surfacing challenge_token as mfaToken', async () => {
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    const result = await client.login('mfa@example.com', 'password123');

    expect(result.status).toBe('mfa_required');
    if (result.status === 'mfa_required') {
      expect(result.mfaToken).toBe('challenge-abc-123');
      expect(result.availableMethods).toEqual(['totp']);
    }
    expect(result).not.toHaveProperty('access_token');
    expect(result).not.toHaveProperty('accessToken');
  });
});

describe('verifyMfa() (D-18)', () => {
  it('completes the two-phase flow and returns the authenticated result', async () => {
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    const loginResult = await client.login('mfa@example.com', 'password123');
    expect(loginResult.status).toBe('mfa_required');

    if (loginResult.status !== 'mfa_required') {
      throw new Error('expected mfa_required');
    }

    const result = await client.verifyMfa(loginResult.mfaToken, '123456');
    expect(result.status).toBe('authenticated');
    if (result.status === 'authenticated') {
      expect(result.sessionId).toBe('session-2');
    }
    expect(result).not.toHaveProperty('access_token');
    expect(result).not.toHaveProperty('accessToken');
  });
});
