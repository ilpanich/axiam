// Setup helpers shared by scenarios that need a pre-existing token (introspect,
// refresh, userinfo). Run once in k6 setup() and shared with all VUs.
import http from 'k6/http';
import { adapter } from './targets.js';

// Obtain an access (+ refresh) token once, for scenarios that operate on a token.
// Tries client_credentials first (works for every target); falls back to login.
export function mintToken() {
  const a = adapter();
  for (const builder of [a.clientCredentials, a.login]) {
    const built = builder();
    const res = http.request(built.method, built.url, built.body || null, built.params || {});
    if (res.status === (built.expect || 200)) {
      let body;
      try { body = res.json(); } catch (_e) { continue; }
      const access = body.access_token || body.token;
      if (access) {
        return { access_token: access, refresh_token: body.refresh_token };
      }
    }
  }
  throw new Error('auth.mintToken: could not obtain a token for setup (check seeding + profile)');
}
