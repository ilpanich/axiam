// can()/checkAccess()/batchCheck() over REST (D-08, FND-04, SC#2 browser).

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { AxiamClient } from '../../src/rest/client.js';
import { AuthzError } from '../../src/core/index.js';

const BASE_URL = 'https://axiam.test';

let checkCallCount = 0;

const server = setupServer(
  http.post(`${BASE_URL}/api/v1/authz/check`, async ({ request }) => {
    checkCallCount += 1;
    const body = (await request.json()) as { action: string; resource_id: string };
    if (body.action === 'denied:action') {
      return HttpResponse.json({ error: 'authorization_denied' }, { status: 403 });
    }
    if (body.action === 'denied:with-body-fields') {
      // Structured 403 body (SDK-Q02): the server echoes back the action it
      // evaluated plus the resource_id of the denied resource. The SDK must
      // populate AuthzError from THESE fields, not the call-arg ctx.
      return HttpResponse.json(
        { error: 'authorization_denied', message: 'not authorized', action: 'users:get', resource_id: 'server-uuid-1' },
        { status: 403 },
      );
    }
    if (body.action === 'denied:action-only') {
      // Non-resource-scoped denial: body carries `action` but no `resource_id`.
      return HttpResponse.json(
        { error: 'authorization_denied', message: 'not authorized', action: 'users:list' },
        { status: 403 },
      );
    }
    return HttpResponse.json({ allowed: body.action === 'users:read' }, { status: 200 });
  }),
  http.post(`${BASE_URL}/api/v1/authz/check/batch`, async ({ request }) => {
    const body = (await request.json()) as { checks: Array<{ action: string; resource_id: string }> };
    const results = body.checks.map((check) => ({
      allowed: check.action === 'users:read',
      reason: check.action === 'users:read' ? undefined : 'denied by policy',
    }));
    return HttpResponse.json({ results }, { status: 200 });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => {
  server.resetHandlers();
  checkCallCount = 0;
});
afterAll(() => server.close());

describe('can() (SC#2 browser authz over REST)', () => {
  it('hits POST /api/v1/authz/check and returns the allowed boolean', async () => {
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    const allowed = await client.can('users:read', 'resource-1');

    expect(allowed).toBe(true);
    expect(checkCallCount).toBe(1);
  });

  it('returns false without throwing when denied', async () => {
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    const allowed = await client.can('users:delete', 'resource-1');

    expect(allowed).toBe(false);
  });
});

describe('checkAccess() (D-08)', () => {
  it('maps a 403 authz denial to AuthzError, not a transport failure', async () => {
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });

    await expect(client.checkAccess({ action: 'denied:action', resourceId: 'resource-1' })).rejects.toBeInstanceOf(
      AuthzError,
    );
  });

  it('populates AuthzError.action/resourceId from the 403 response body, not just the call-args (SDK-Q02)', async () => {
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });

    // Call-arg resourceId ('call-arg-resource') deliberately differs from the
    // body's resource_id ('server-uuid-1') so the assertion proves the body
    // value wins, rather than merely matching what was passed in.
    const error = await client
      .checkAccess({ action: 'denied:with-body-fields', resourceId: 'call-arg-resource' })
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(AuthzError);
    expect((error as AuthzError).action).toBe('users:get');
    expect((error as AuthzError).resourceId).toBe('server-uuid-1');
  });

  it('populates AuthzError.action from a 403 body carrying only action (no resource_id)', async () => {
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });

    const error = await client
      .checkAccess({ action: 'denied:action-only', resourceId: 'call-arg-resource' })
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(AuthzError);
    expect((error as AuthzError).action).toBe('users:list');
    // resource_id absent from body -> falls back to the call-arg ctx value.
    expect((error as AuthzError).resourceId).toBe('call-arg-resource');
  });
});

describe('batchCheck()', () => {
  it('hits POST /api/v1/authz/check/batch and preserves input order', async () => {
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });

    const results = await client.batchCheck([
      { action: 'users:read', resourceId: 'r1' },
      { action: 'users:delete', resourceId: 'r2' },
      { action: 'users:read', resourceId: 'r3' },
    ]);

    expect(results).toHaveLength(3);
    expect(results[0].allowed).toBe(true);
    expect(results[1].allowed).toBe(false);
    expect(results[2].allowed).toBe(true);
  });
});
