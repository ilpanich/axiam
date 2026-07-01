import { CookieJar } from 'tough-cookie';
import { describe, expect, it } from 'vitest';
import { REDACTED } from '../../src/core/index.js';
import { ACCESS_COOKIE, REFRESH_COOKIE, extractCookieValue } from '../../src/node/cookieJar.js';
import { TokenManager } from '../../src/node/tokenManager.js';

const BASE_URL = 'https://axiam.test';

async function seededJar(): Promise<CookieJar> {
  const jar = new CookieJar();
  await jar.setCookie(`${ACCESS_COOKIE}=access-token-value; Path=/`, BASE_URL);
  await jar.setCookie(
    `${REFRESH_COOKIE}=refresh-token-value; Path=/api/v1/auth/refresh`,
    `${BASE_URL}/api/v1/auth/refresh`,
  );
  return jar;
}

describe('TokenManager', () => {
  it('cachedAccessToken() returns null before syncFromJar() has run', () => {
    const manager = new TokenManager(new CookieJar(), BASE_URL);
    expect(manager.cachedAccessToken()).toBeNull();
  });

  it('cachedAccessToken() returns a Sensitive wrapping the jar value after syncFromJar()', async () => {
    const jar = await seededJar();
    const manager = new TokenManager(jar, BASE_URL);

    await manager.syncFromJar();
    const cached = manager.cachedAccessToken();

    expect(cached).not.toBeNull();
    expect(String(cached)).toBe(REDACTED);
    expect(String(cached)).not.toContain('access-token-value');
    expect(cached?.expose()).toBe('access-token-value');
  });

  it('refreshTokenValue() reads axiam_refresh by name from the jar, wrapped in Sensitive<T>', async () => {
    const jar = await seededJar();
    const manager = new TokenManager(jar, BASE_URL);

    const refresh = await manager.refreshTokenValue();

    expect(refresh).not.toBeNull();
    expect(String(refresh)).toBe(REDACTED);
    expect(refresh?.expose()).toBe('refresh-token-value');
  });

  it('extractCookieValue reads axiam_access and axiam_refresh by name for the correct URL', async () => {
    const jar = await seededJar();

    const access = await extractCookieValue(jar, BASE_URL, ACCESS_COOKIE);
    const refresh = await extractCookieValue(jar, `${BASE_URL}/api/v1/auth/refresh`, REFRESH_COOKIE);
    const missingRefresh = await extractCookieValue(jar, BASE_URL, REFRESH_COOKIE);

    expect(access).toBe('access-token-value');
    expect(refresh).toBe('refresh-token-value');
    // axiam_refresh is path-scoped to /api/v1/auth/refresh — must not be
    // visible at the bare base URL.
    expect(missingRefresh).toBeUndefined();
  });

  it('clear() resets the cached access token', async () => {
    const jar = await seededJar();
    const manager = new TokenManager(jar, BASE_URL);
    await manager.syncFromJar();
    expect(manager.cachedAccessToken()).not.toBeNull();

    manager.clear();

    expect(manager.cachedAccessToken()).toBeNull();
  });

  it('tenantId()/setTenantId() track the resolved tenant identifier', () => {
    const manager = new TokenManager(new CookieJar(), BASE_URL, 'acme');
    expect(manager.tenantId()).toBe('acme');

    manager.setTenantId('11111111-1111-1111-1111-111111111111');
    expect(manager.tenantId()).toBe('11111111-1111-1111-1111-111111111111');
  });
});
