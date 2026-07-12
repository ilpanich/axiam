import { describe, expect, it } from 'vitest';
import { AuthError, AuthzError, NetworkError } from '../../src/core/errors.js';
import { GrpcStatus, mapGrpcStatusToError, mapHttpStatusToError } from '../../src/core/errorMapper.js';

describe('mapHttpStatusToError', () => {
  it.each([
    [400, NetworkError],
    [401, AuthError],
    [403, AuthzError],
    [408, NetworkError],
    [409, AuthzError],
    [429, NetworkError],
    [500, NetworkError],
    [502, NetworkError],
    [503, NetworkError],
  ] as const)('maps HTTP %i to %s', (status, ExpectedType) => {
    const err = mapHttpStatusToError(status, 'test message');
    expect(err).toBeInstanceOf(ExpectedType);
  });

  it('carries action/resourceId on AuthzError from context', () => {
    const err = mapHttpStatusToError(403, 'denied', { action: 'delete', resourceId: 'res-1' });
    expect(err).toBeInstanceOf(AuthzError);
    expect((err as AuthzError).action).toBe('delete');
    expect((err as AuthzError).resourceId).toBe('res-1');
  });

  it('prefers action/resource_id from the response body over the call-arg ctx', () => {
    const err = mapHttpStatusToError(403, 'denied', {
      action: 'ctx:action',
      resourceId: 'ctx-resource',
      body: { error: 'authorization_denied', message: 'denied', action: 'users:get', resource_id: 'body-uuid' },
    });
    expect(err).toBeInstanceOf(AuthzError);
    expect((err as AuthzError).action).toBe('users:get');
    expect((err as AuthzError).resourceId).toBe('body-uuid');
  });

  it('populates only action from the body when resource_id is absent (non-resource-scoped denial), leaving resourceId to fall back to ctx', () => {
    const err = mapHttpStatusToError(403, 'denied', {
      action: 'ctx:action',
      resourceId: 'ctx-resource',
      body: { error: 'authorization_denied', message: 'denied', action: 'users:list' },
    });
    expect(err).toBeInstanceOf(AuthzError);
    expect((err as AuthzError).action).toBe('users:list');
    // No resource_id in the body -> falls back to the call-arg ctx value.
    expect((err as AuthzError).resourceId).toBe('ctx-resource');
  });

  it('falls back entirely to ctx action/resourceId when the body has neither field (older server)', () => {
    const err = mapHttpStatusToError(403, 'denied', {
      action: 'ctx:action',
      resourceId: 'ctx-resource',
      body: { error: 'authorization_denied', message: 'denied' },
    });
    expect(err).toBeInstanceOf(AuthzError);
    expect((err as AuthzError).action).toBe('ctx:action');
    expect((err as AuthzError).resourceId).toBe('ctx-resource');
  });

  it('carries cause on NetworkError from context (plain Error, no response headers to sanitize)', () => {
    const cause = new Error('ECONNREFUSED');
    const err = mapHttpStatusToError(500, 'server error', { cause });
    expect(err).toBeInstanceOf(NetworkError);
    expect((err as NetworkError).cause).toBe(cause);
  });

  it('redacts Set-Cookie from an axios-error-shaped cause instead of preserving it verbatim (CR-04, D-16)', () => {
    const cause = {
      message: 'Request failed with status code 401',
      response: {
        status: 401,
        headers: {
          'set-cookie': ['axiam_access=eyJfake.jwt.token; Path=/', 'axiam_refresh=opaque-refresh-secret; Path=/api/v1/auth/refresh'],
          'content-type': 'application/json',
        },
      },
    };
    const err = mapHttpStatusToError(500, 'server error', { cause });

    expect(err).toBeInstanceOf(NetworkError);
    // Must NOT be the verbatim cause object — it must be sanitized.
    expect((err as NetworkError).cause).not.toBe(cause);
    expect(JSON.stringify(err)).not.toContain('axiam_access=eyJfake.jwt.token');
    expect(JSON.stringify(err)).not.toContain('opaque-refresh-secret');
    // Non-sensitive diagnostics survive redaction.
    const sanitizedCause = (err as NetworkError).cause as { response: { status: number; headers: Record<string, unknown> } };
    expect(sanitizedCause.response.status).toBe(401);
    expect(sanitizedCause.response.headers['content-type']).toBe('application/json');
    // set-cookie is not allowlisted (X-3) -> redacted to a placeholder.
    expect(sanitizedCause.response.headers['set-cookie']).toBe('[REDACTED]');
  });
});

describe('mapGrpcStatusToError', () => {
  it.each([
    [GrpcStatus.UNAUTHENTICATED, AuthError],
    [GrpcStatus.PERMISSION_DENIED, AuthzError],
    [GrpcStatus.UNAVAILABLE, NetworkError],
    [GrpcStatus.DEADLINE_EXCEEDED, NetworkError],
    [GrpcStatus.INTERNAL, NetworkError],
    [GrpcStatus.RESOURCE_EXHAUSTED, NetworkError],
  ] as const)('maps gRPC code %i to %s', (code, ExpectedType) => {
    const err = mapGrpcStatusToError(code, 'test message');
    expect(err).toBeInstanceOf(ExpectedType);
  });

  it('maps unknown gRPC codes to NetworkError', () => {
    const err = mapGrpcStatusToError(2 /* UNKNOWN */, 'test message');
    expect(err).toBeInstanceOf(NetworkError);
  });
});
