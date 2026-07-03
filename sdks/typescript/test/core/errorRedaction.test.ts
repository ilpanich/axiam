// Error redaction regression (CR-04, D-16): a NetworkError produced from a
// failed login/refresh whose underlying response carried Set-Cookie token
// material must never expose that raw cookie value through
// console.log/JSON.stringify/util.inspect of the thrown error.

import { inspect } from 'node:util';
import { describe, expect, it } from 'vitest';
import { mapHttpStatusToError, sanitizeAxiosError } from '../../src/core/errorMapper.js';
import { NetworkError } from '../../src/core/errors.js';

const RAW_ACCESS_TOKEN = 'eyJfake.jwt.token';
const RAW_REFRESH_TOKEN = 'opaque-refresh-secret';

function axiosErrorShapedCause(): unknown {
  return {
    message: 'Request failed with status code 500',
    response: {
      status: 500,
      headers: {
        'set-cookie': [
          `axiam_access=${RAW_ACCESS_TOKEN}; Path=/; HttpOnly`,
          `axiam_refresh=${RAW_REFRESH_TOKEN}; Path=/api/v1/auth/refresh; HttpOnly`,
        ],
        'content-type': 'application/json',
      },
      data: { error: 'internal_error' },
    },
  };
}

describe('sanitizeAxiosError (CR-04, D-16)', () => {
  it('strips set-cookie (case-insensitive) from response.headers, preserving other fields', () => {
    const cause = axiosErrorShapedCause();
    const sanitized = sanitizeAxiosError(cause) as {
      message: string;
      response: { status: number; headers: Record<string, unknown>; data: unknown };
    };

    expect(sanitized).not.toBe(cause);
    expect(sanitized.message).toBe('Request failed with status code 500');
    expect(sanitized.response.status).toBe(500);
    expect(sanitized.response.headers['content-type']).toBe('application/json');
    expect(sanitized.response.headers['set-cookie']).toBeUndefined();
    expect(sanitized.response.data).toEqual({ error: 'internal_error' });
  });

  it('does not mutate the original input object', () => {
    const cause = axiosErrorShapedCause() as { response: { headers: Record<string, unknown> } };
    sanitizeAxiosError(cause);
    expect(cause.response.headers['set-cookie']).toBeDefined();
  });

  it('passes through non-response-bearing causes unchanged (plain Error)', () => {
    const cause = new Error('ECONNREFUSED');
    expect(sanitizeAxiosError(cause)).toBe(cause);
  });

  it('passes through primitive/undefined causes unchanged', () => {
    expect(sanitizeAxiosError(undefined)).toBeUndefined();
    expect(sanitizeAxiosError('a string cause')).toBe('a string cause');
    expect(sanitizeAxiosError(null)).toBeNull();
  });

  it('handles an uppercase Set-Cookie header key too', () => {
    const cause = {
      response: {
        headers: { 'Set-Cookie': ['axiam_access=secret'], 'X-Other': 'kept' },
      },
    };
    const sanitized = sanitizeAxiosError(cause) as { response: { headers: Record<string, unknown> } };
    expect(sanitized.response.headers['Set-Cookie']).toBeUndefined();
    expect(sanitized.response.headers['X-Other']).toBe('kept');
  });
});

describe('NetworkError never leaks raw Set-Cookie token material (CR-04, D-16)', () => {
  it('via mapHttpStatusToError: JSON.stringify/String/util.inspect exclude raw token substrings', () => {
    const cause = axiosErrorShapedCause();
    const err = mapHttpStatusToError(500, 'server error', { cause });

    const jsonForm = JSON.stringify(err);
    const stringForm = String(err);
    const inspectForm = inspect(err, { depth: null });

    for (const form of [jsonForm, stringForm, inspectForm]) {
      expect(form).not.toContain(RAW_ACCESS_TOKEN);
      expect(form).not.toContain(RAW_REFRESH_TOKEN);
    }

    // Status/message diagnostics still make it through.
    expect(stringForm).toContain('server error');
    expect(err).toBeInstanceOf(NetworkError);
  });

  it('via a directly-constructed NetworkError(msg, sanitizeAxiosError(err)) fallback path', () => {
    const cause = axiosErrorShapedCause();
    const err = new NetworkError('login request failed', sanitizeAxiosError(cause));

    const jsonForm = JSON.stringify(err);
    const inspectForm = inspect(err, { depth: null });

    expect(jsonForm).not.toContain(RAW_ACCESS_TOKEN);
    expect(jsonForm).not.toContain(RAW_REFRESH_TOKEN);
    expect(inspectForm).not.toContain(RAW_ACCESS_TOKEN);
    expect(inspectForm).not.toContain(RAW_REFRESH_TOKEN);
  });

  it('an unsanitized NetworkError.cause WOULD have leaked (control case proving the test is meaningful)', () => {
    const cause = axiosErrorShapedCause();
    // Directly construct without sanitizing, to prove this test can detect a
    // real leak if the redaction were ever removed/bypassed.
    const unsanitizedErr = new NetworkError('login request failed', cause);

    expect(JSON.stringify(unsanitizedErr)).toContain(RAW_ACCESS_TOKEN);
  });
});
