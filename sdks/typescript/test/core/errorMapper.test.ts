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

  it('carries cause on NetworkError from context', () => {
    const cause = new Error('ECONNREFUSED');
    const err = mapHttpStatusToError(500, 'server error', { cause });
    expect(err).toBeInstanceOf(NetworkError);
    expect((err as NetworkError).cause).toBe(cause);
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
