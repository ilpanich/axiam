// Scenario: refresh-token grant. AXIAM rotates refresh tokens single-use, so each
// VU mints its own token in setup-per-VU style and chains rotations. For targets
// without rotation the same refresh token is reusable; both are handled.
import http from 'k6/http';
import { fail, sleep } from 'k6';
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
    // A5/J4: the pre-minted session pool paces itself inside the login bucket,
    // so setup can legitimately run for minutes under an rl=prod posture.
    // k6's 60s default would kill it mid-pool. `MAX_SETUP_SECS` is the budget
    // setup() itself asserts against, so the two agree by construction.
    setupTimeout: `${Number(__ENV.BENCH_MAX_SETUP_SECS || 300) + 60}s`,
  },
  tlsOptions(),
);

// Upper bound on how long the A5/J4 pre-mint may take, so a mis-set
// BENCH_LOGIN_PER_MIN fails loudly instead of quietly turning the whole cell
// into setup. k6's own `setupTimeout` is raised to match in `options` above.
const MAX_SETUP_SECS = Number(__ENV.BENCH_MAX_SETUP_SECS || 300);

// Per-VU refresh token (+ CSRF token, needed only for AXIAM's cookie-based
// grant — see axiamRefreshOp), so single-use rotation does not invalidate
// other VUs.
let vuRefresh = null;
let vuCsrf = null;

// A5/J4 — pre-minted session pool.
//
// # The problem this solves
//
// Every VU used to mint its own session by logging in, lazily, whenever it had
// no usable refresh token. Under the shipped `internet` rate-limit posture
// `/api/v1/auth/login` is **10/min per IP** and the entire k6 fleet shares one
// IP, so the moment a rotation failed the VU tried to re-login, was throttled,
// failed again, and tried again. Run 5's rl-prod refresh cell measured 516/s at
// **4.4 % errors** (run 4: 2.4 %) — errors that were login throttling wearing a
// refresh cell's clothes, not anything the refresh path did.
//
// `setup()` now mints the whole pool ONCE, up front, pacing itself inside
// `BENCH_LOGIN_PER_MIN` so the pre-mint does not itself trip the bucket. Each
// VU takes one session and chains rotations off it for the rest of the run: a
// refresh returns a fresh refresh token, so **one session per VU lasts the
// whole window** as long as rotations succeed.
//
// # The coupling this deliberately does NOT hide
//
// A deployment with short sessions has its refresh capacity gated by its login
// limit, because every expired session costs a login to replace. That is a
// real product property and belongs in the deployment docs
// (`docs/deployment/rate-limit-sizing.md`), not something for the harness to
// paper over. What the harness must not do is *misattribute* it — reporting
// login throttling as a refresh-endpoint error rate is how a real coupling
// becomes an imaginary bug.
export function setup() {
  requireSeed();

  // Only AXIAM's session-refresh path is pool-able: the other targets' refresh
  // tokens come from grants this harness mints per-VU anyway (see the fallback
  // branch below), so pre-minting would buy nothing.
  if (cfg.target !== 'axiam') return { sessions: [] };

  const perMin = cfg.loginPerMin;
  const needed = cfg.vus;

  // Self-check: refuse to start a run whose pre-mint cannot finish in a
  // sensible time, rather than silently spending ten minutes in setup and
  // reporting a cell nobody realises was mostly warm-up.
  if (perMin > 0) {
    const estimatedSecs = ((needed - 1) / perMin) * 60;
    if (estimatedSecs > MAX_SETUP_SECS) {
      fail(
        `refresh session pool: ${needed} VUs at BENCH_LOGIN_PER_MIN=${perMin} needs ` +
          `~${Math.round(estimatedSecs)}s of setup, over the ${MAX_SETUP_SECS}s budget. ` +
          `Lower BENCH_VUS, raise the login ceiling for this cell, or raise ` +
          `BENCH_MAX_SETUP_SECS deliberately.`,
      );
    }
  }

  const sessions = [];
  const gapMs = perMin > 0 ? Math.ceil(60000 / perMin) : 0;
  for (let i = 0; i < needed; i++) {
    if (i > 0 && gapMs > 0) sleep(gapMs / 1000);
    try {
      const tok = mintUserToken();
      if (tok.refresh_token) {
        sessions.push({ refresh_token: tok.refresh_token, csrf_token: tok.csrf_token });
      }
    } catch (_e) {
      // A login that fails during setup is worth knowing about but is not
      // fatal: a partially filled pool still measures refresh honestly for the
      // VUs that got one, and the assertion below reports the shortfall.
    }
  }

  // The pool must outlast the measurement window. It does so by construction
  // when it is full — rotations chain — so the only failure mode is a pool
  // that could not be filled, which means the pre-mint itself was throttled
  // and the cell would have measured that instead.
  if (sessions.length < needed) {
    fail(
      `refresh session pool: minted ${sessions.length}/${needed} sessions. The ` +
        `pre-mint was itself throttled, so this cell would measure login ` +
        `throttling rather than refresh. Set BENCH_LOGIN_PER_MIN to the ` +
        `configured login ceiling (rl=prod: 10) so setup paces itself.`,
    );
  }

  return { sessions };
}

export default function (data) {
  const a = adapter();
  const isAxiam = cfg.target === 'axiam';

  // A5/J4: take this VU's pre-minted session on its first iteration. `__VU` is
  // 1-based and the pool is sized to `cfg.vus`, so each VU gets its own.
  if (!vuRefresh && isAxiam && data && data.sessions && data.sessions.length > 0) {
    const mine = data.sessions[(__VU - 1) % data.sessions.length];
    if (mine) {
      vuRefresh = mine.refresh_token;
      vuCsrf = mine.csrf_token;
    }
  }

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
      // A5/J4: do NOT re-mint. Re-logging in here is exactly what burned the
      // 10/min login bucket and turned a refresh cell into a login-throttling
      // cell. `doOp` has already counted the failure, so the VU backs off and
      // retries the rotation it still holds — and if the refresh limiter is
      // what is rejecting us, that is now what the numbers say.
      sleep(1);
    }
    return;
  }

  const body = doOp(a.refresh(vuRefresh));
  // Follow rotation: adopt the new refresh token if one was returned.
  if (body && body.refresh_token) vuRefresh = body.refresh_token;
  else if (body && !body.refresh_token) vuRefresh = vuRefresh; // reusable token
  else vuRefresh = null; // failed → re-mint next iteration
}
