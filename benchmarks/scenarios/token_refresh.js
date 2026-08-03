// Scenario: refresh-token grant. AXIAM rotates refresh tokens single-use, so each
// VU mints its own token in setup-per-VU style and chains rotations. For targets
// without rotation the same refresh token is reusable; both are handled.
import http from 'k6/http';
import { sleep } from 'k6';
import { cfg, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { adapter } from './lib/targets.js';
import { doOp, m } from './lib/metrics.js';
import { mintUserToken, axiamRefreshOp, readAxiamRefreshCookies } from './lib/auth.js';

export const options = Object.assign(
  {
    scenarios: {
      refresh: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

// Per-VU refresh token (+ CSRF token, needed only for AXIAM's cookie-based
// grant — see axiamRefreshOp), so single-use rotation does not invalidate
// other VUs.
let vuRefresh = null;
let vuCsrf = null;

export function setup() {
  requireSeed();
}

export default function () {
  const a = adapter();
  const isAxiam = cfg.target === 'axiam';
  if (!vuRefresh) {
    let tok;
    try {
      // A8: mint via a real user login (mintUserToken), not client_credentials
      // (mintToken). No target issues a refresh token on the CC grant, so
      // minting CC-first meant every VU permanently took the fallback branch
      // below — the cell measured CC issuance, not refresh, on ALL targets.
      // mintUserToken() logs in as the seeded user first (AXIAM: axiam_refresh
      // cookie; Keycloak: ROPC JSON body), so a genuine refresh_token is
      // issued and actually exercised here.
      tok = mintUserToken();
    } catch (_e) {
      // Could not obtain a token to refresh — typically the token endpoint is
      // throttling this VU (prod rate-limit posture), or seeding/OAuth2 is
      // misconfigured. Record it as a failed logical op and back off: otherwise
      // mintUserToken's throw aborts the iteration WITHOUT touching bench_ok/
      // bench_failed, so the scenario silently under-reports its true error rate
      // (the p0-plaintext incident: 10k iterations, 26 recorded ops).
      m.failed.add(1);
      m.errorRate.add(true);
      sleep(1);
      return;
    }
    vuRefresh = tok.refresh_token;
    vuCsrf = tok.csrf_token;
    if (!vuRefresh) {
      // Target issued no refresh token off a user login either (e.g. Zitadel:
      // mintUserToken() falls back to client_credentials because its login()
      // returns a session-API `sessionToken`, not an OIDC token — a real
      // refresh token would require driving a full OIDC auth-code flow with
      // `offline_access` against Zitadel's hosted login UI, which this
      // protocol-level k6 harness cannot do — see
      // claude_dev/refresh-harness-diagnosis.md). Nothing to measure; mint
      // again as the closest comparable token-issuance op. This is not a
      // refresh, so tag + count it as a fallback (comparability:
      // fallback-op). For AXIAM/Keycloak this branch should no longer be
      // reached (G4).
      //
      // I17(a) (improvement-after-run4-benchmark.md §D) follow-up research —
      // what it would actually take to close this gap, and why it is not
      // done here:
      //   - Exchanging the v2 session token this harness already mints
      //     (zitadel.login() in lib/targets.js) directly for an OIDC token
      //     set via RFC 8693 Token Exchange is NOT implemented by Zitadel —
      //     confirmed against zitadel/zitadel#7900 ("Allow Token Exchange
      //     with Session Token"), open and still in the "investigating"
      //     stage with no grant_type/subject_token_type defined yet, and the
      //     Token Exchange guide (zitadel.com/docs/guides/integrate/
      //     token-exchange) documents exchanging EXISTING OAuth tokens only,
      //     never a v2 session token as the subject.
      //   - Zitadel does not support the Resource Owner Password Credentials
      //     grant at all (grant_type=password) — explicitly refused per
      //     zitadel.com/docs/apis/openidoauth/grant-types ("due to growing
      //     security concerns... with OAuth 2.1 it looks like this grant
      //     will be removed"), so there is no simple non-interactive
      //     grant-type swap either.
      //   - The one HTTP-only (no real browser) path that DOES appear to be
      //     designed for this — Zitadel's "Custom Login UI" API
      //     (zitadel.com/docs/guides/integrate/login-ui/oidc-standard):
      //     start an authorization request (GET /oauth/v2/authorize with
      //     PKCE + scope including offline_access) to obtain an authRequestId,
      //     then POST /v2/oidc/auth_requests/{authRequestId}/callback with
      //     the ALREADY-MINTED v2 session token to link the two and receive
      //     a callback URL carrying the authorization `code`, then the usual
      //     POST /oauth/v2/token (grant_type=authorization_code) to redeem
      //     it for an access_token + refresh_token. This is plausibly
      //     tractable as a ONE-TIME step in runner/seed.sh (not per-VU in
      //     this hot k6 loop) — but its exact request/response shapes
      //     (authRequestId extraction, callback body/response format) are
      //     unconfirmed against a live instance: no Zitadel is reachable
      //     from this sandbox (the same limitation the D5/session-API commit
      //     in lib/targets.js already flagged for the 201-vs-200 CreateSession
      //     status code). Shipping an unverified implementation of a
      //     multi-step token flow risks a silent, hard-to-diagnose failure
      //     that reads as a target-availability problem, not a harness bug —
      //     worse than the current honest `fallback-op` label. Left
      //     un-implemented; a run against a live Zitadel instance should
      //     confirm the exact shapes above before writing the code.
      m.fallback.add(1);
      doOp(a.clientCredentials());
      return;
    }
  }

  if (isAxiam) {
    // AXIAM's user-session refresh token is redeemed at the session endpoint
    // `POST /api/v1/auth/refresh`, not the OAuth2 `POST /oauth2/token`
    // grant `targets.js`'s generic `a.refresh()` builds — see the extensive
    // citation on `axiamRefreshOp` in lib/auth.js for why the two are not
    // interchangeable (different server-side token stores).
    const body = doOp(axiamRefreshOp(vuRefresh, vuCsrf));
    if (body !== null) {
      // Success: the rotated refresh/csrf pair arrives only via Set-Cookie
      // (the JSON body carries just `expires_in`), so read it back out of
      // the jar rather than out of `body`.
      const rotated = readAxiamRefreshCookies(http.cookieJar());
      vuRefresh = rotated.refresh_token || null;
      vuCsrf = rotated.csrf_token || vuCsrf;
    } else {
      vuRefresh = null; // failed → re-mint next iteration
    }
    return;
  }

  const body = doOp(a.refresh(vuRefresh));
  // Follow rotation: adopt the new refresh token if one was returned.
  if (body && body.refresh_token) vuRefresh = body.refresh_token;
  else if (body && !body.refresh_token) vuRefresh = vuRefresh; // reusable token
  else vuRefresh = null; // failed → re-mint next iteration
}
