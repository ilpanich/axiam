// Scenario: authorization-code REDEMPTION by a public, MCP-shaped client —
// `POST /oauth2/token` with `grant_type=authorization_code`, PKCE S256 and an
// RFC 8707 `resource`.
//
// Why this exists. `oauth2_authorize.js` measures the request that MINTS a
// code and deliberately never redeems it; its header and
// `VERIFICATION-2026-09-11.md` §3 name the redemption as its own follow-up
// cell. The T21 MCP track made that follow-up specific: the client that now
// redeems codes at AXIAM is a desktop MCP client — public (T21.2,
// `token_endpoint_auth_method: none`), listening on an ephemeral loopback port
// (RFC 8252 §7.3), proving possession with PKCE, and naming the MCP server it
// wants a token for (T21.3, RFC 8707). This cell is that client, and only that
// client.
//
// # What is measured
//
// ONE measured call per iteration: the token request. On AXIAM's side that is
// `token.rs::handle_authorization_code`, in order —
//
//   * client lookup, then the T21.2 public-client arm of
//     `authenticate_client_credential`: no credential, so NO Argon2id secret
//     verification (the confidential cells pay for one; this one must not);
//   * the code row lookup (`get_by_hash`, keyed by the SHA-256 of the code,
//     the client and the redirect URI) and the T21.2 "a public client's code
//     must carry a challenge" refusal check;
//   * PKCE: RFC 7636 §4.1 verifier syntax, SHA-256, constant-time compare;
//   * the single-use `consume` — a conditional write;
//   * the tenant read, then `resource::resolve_bound`: the resource this
//     request repeats is normalised and compared to the one the code was bound
//     to at authorization time, and becomes the access token's `aud`;
//   * an Ed25519 access token, and — because `openid` is requested — a user
//     read plus an Ed25519 ID token.
//
// No refresh token: the seeded client is registered for `authorization_code`
// only. A client that also holds `refresh_token` adds one row write per
// redemption (and a row per iteration that outlives the run), and refresh
// rotation is `token_refresh.js`'s measurement, not this one's.
//
// # What is NOT measured, and why
//
// The authorization request that produces each code runs inside the
// iteration, unmeasured: it is plain `http.get`, not `doOp`, so it records no
// latency sample and no `bench_ok`. It has to exist — a code is single-use, so
// every redemption needs a fresh one, which is exactly why this could not be a
// second half of `oauth2_authorize.js` — but its cost is that cell's number,
// and folding it in here would make this cell's throughput describe neither
// endpoint. Two consequences to read the numbers with:
//
//   * `bench_ok`/s here is REDEMPTIONS per second while each VU also spends
//     one authorize round trip per iteration. Compare it with other cells by
//     latency, not by raw iteration rate.
//   * An authorization that does not answer 302 with a `code` is counted as a
//     FAILED logical operation (`bench_failed`, `bench_error_rate`, a failed
//     check) with no latency sample, and logged once per VU with its status
//     and body. It fails the cell rather than vanishing: a redemption cell
//     that quietly skipped its redemptions would report a perfect error rate.
//
// Authentication for the authorization leg is the bench USER's bearer token,
// exactly as in `oauth2_authorize.js` — see that header for why the W3
// browser login hop is not driven from k6. The client is registered by an
// administrator (`runner/seed.sh`), so the T21.4 external-consent gate does
// not apply to it; a DCR- or CIMD-registered client would stop at a consent
// interaction here, which k6 cannot answer.
//
// # PKCE and the load generator
//
// The verifier/challenge pairs are made ONCE, in setup(), and reused round
// robin: 64 random 32-byte verifiers (43 base64url characters, RFC 7636 §4.1)
// and their S256 challenges from `k6/crypto`, which reproduces the RFC 7636
// Appendix B vector. Reuse costs the measurement nothing — the server stores
// the challenge on the code and hashes whatever verifier the redemption
// presents, so its work is identical for a fresh pair and a reused one — and
// it keeps SHA-256 and random-byte generation out of the VU loop, where they
// would be k6's CPU reported as AXIAM's latency.
//
// # Redirect URI and resource
//
// The seed registers `http://127.0.0.1/callback` — no port, as a desktop MCP
// client registers it — and this cell presents it WITH a port, so the
// authorization leg takes the RFC 8252 §7.3 loopback allowance in
// `redirect_uri::redirect_uri_matches` (a parse of both URIs) rather than the
// exact-string fast path. The token request repeats the PRESENTED URI, port
// included: the code row stores what was presented, and `get_by_hash`
// compares it exactly.
//
// The resource comes from the seed (`BENCH_MCP_RESOURCE`), which registers it
// in the client's `allowed_resources`. It is sent on BOTH legs, as the MCP
// authorization spec requires of a client: `resolve_requested` checks it
// against the allow-list at authorization, `resolve_bound` checks the
// redemption repeats it. setup() makes one full round trip first and refuses
// to start unless the resulting access token's `aud` IS that resource — the
// end-to-end RFC 8707 property this cell exists to exercise.
//
// AXIAM-ONLY, for the reason `oauth2_authorize.js` gives: both competitors
// issue a code only through their own interactive login form.
import http from 'k6/http';
import { check } from 'k6';
import crypto from 'k6/crypto';
import encoding from 'k6/encoding';
import { cfg, baseUrl, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { doOp, m } from './lib/metrics.js';
import { loginSession, jwtClaims } from './lib/auth.js';

export const options = Object.assign(
  {
    scenarios: {
      oauth2CodePkce: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

// Presented form of the loopback redirect URI `runner/seed.sh` registers as
// `http://127.0.0.1/callback`. Any port matches (RFC 8252 §7.3); a fixed one
// keeps the authorization and token legs trivially identical. Nothing listens
// on it — the authorization leg stops at the 302 (`redirects: 0`).
const REDIRECT_URI = 'http://127.0.0.1:53682/callback';

// `openid` so the redemption mints the ID token `VERIFICATION-2026-09-11.md`
// names as part of this follow-up's work. It is the only scope the seed
// registers on this client.
const SCOPE = 'openid';

const PKCE_POOL_SIZE = 64;

function tokenUrl() {
  return `${baseUrl()}/oauth2/token?tenant_id=${cfg.tenantId}`;
}

function formBody(obj) {
  return Object.keys(obj)
    .map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(obj[k])}`)
    .join('&');
}

// One authorization request, bearer-authenticated, NOT measured. Returns
// `{ code }` on the RFC 6749 §4.1.2 redirect, or `{ res }` for anything else.
function authorize(accessToken, pair) {
  const query = [
    'response_type=code',
    `client_id=${encodeURIComponent(cfg.mcpClientId)}`,
    `redirect_uri=${encodeURIComponent(REDIRECT_URI)}`,
    `scope=${encodeURIComponent(SCOPE)}`,
    'state=bench',
    `code_challenge=${pair.challenge}`,
    'code_challenge_method=S256',
    `resource=${encodeURIComponent(cfg.mcpResource)}`,
  ].join('&');
  const res = http.get(`${baseUrl()}/oauth2/authorize?${query}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    redirects: 0,
    // Tagged so the unmeasured leg is separable in k6's own http_req_* metrics
    // and never mistaken for the cell's operation.
    tags: { leg: 'authorize_unmeasured' },
  });
  const location = res.headers.Location || res.headers.location || '';
  const match = res.status === 302 ? /[?&]code=([^&]+)/.exec(location) : null;
  return match ? { code: decodeURIComponent(match[1]) } : { res };
}

function redemption(code, pair) {
  return {
    method: 'POST',
    url: tokenUrl(),
    // `client_id` in the body and no credential anywhere: a public client
    // authenticates with nothing, and `authenticate_client_credential` REFUSES
    // a presented secret rather than ignoring it (T21.2).
    body: formBody({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: cfg.mcpClientId,
      code_verifier: pair.verifier,
      resource: cfg.mcpResource,
    }),
    params: { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
    // 200 is the only correct answer. `invalid_grant` (400) would mean a
    // PKCE mismatch or a reused/expired code, `invalid_target` (400) a
    // resource that does not repeat the bound one, `invalid_client` (401) a
    // client that is not public — all harness or seed defects, all failures.
    expect: 200,
    require: {
      'response carries an access_token': (r) => String(r.body).indexOf('"access_token"') !== -1,
    },
  };
}

function snippet(res) {
  return String(res && res.body ? res.body : '').slice(0, 300);
}

export function setup() {
  requireSeed();
  if (!cfg.mcpClientId || !cfg.mcpResource) {
    throw new Error(
      'BENCH_MCP_CLIENT_ID / BENCH_MCP_RESOURCE are empty — the seed env predates the public ' +
        'MCP client. Re-run `just target=axiam bench-seed`.',
    );
  }

  const pkce = [];
  for (let i = 0; i < PKCE_POOL_SIZE; i++) {
    const verifier = encoding.b64encode(crypto.randomBytes(32), 'rawurl');
    pkce.push({ verifier, challenge: crypto.sha256(verifier, 'base64rawurl') });
  }

  // A USER session, as in oauth2_authorize.js. loginSession() throws on
  // failure, naming the cause.
  const session = loginSession();

  // One full, unmeasured round trip, and a hard stop if it is not right. The
  // two legs have six ways to fail between them and every one of them is a
  // seed or harness defect; finding that out here costs one request, finding
  // it out from a cell of 400s costs a run.
  const probe = authorize(session.access_token, pkce[0]);
  if (!probe.code) {
    throw new Error(
      `authorization probe did not redirect with a code (HTTP ${probe.res.status}, ` +
        `Location=${probe.res.headers.Location || '<none>'}): ${snippet(probe.res)}`,
    );
  }
  const built = redemption(probe.code, pkce[0]);
  const tok = http.request(built.method, built.url, built.body, built.params);
  if (tok.status !== 200) {
    throw new Error(`redemption probe answered HTTP ${tok.status}: ${snippet(tok)}`);
  }
  const aud = jwtClaims(tok.json('access_token')).aud;
  const auds = Array.isArray(aud) ? aud : [aud];
  // The server stores and mints the RFC 3986-normalised form; the seed
  // registers an already-normalised URI, so a byte comparison is the right one.
  if (auds.indexOf(cfg.mcpResource) === -1) {
    throw new Error(
      `redemption probe minted aud=${JSON.stringify(aud)}, expected the RFC 8707 resource ` +
        `${cfg.mcpResource} — the resource indicator did not reach the token`,
    );
  }

  return { access_token: session.access_token, pkce };
}

let loggedAuthorizeFailure = false;

export default function (data) {
  const pair = data.pkce[(__VU * 7 + __ITER) % data.pkce.length];
  const grant = authorize(data.access_token, pair);

  const authorized = check(grant, {
    'authorize (unmeasured) answered 302 with a code': (g) => Boolean(g.code),
  });
  if (!authorized) {
    // The logical operation — a redemption — could not happen, so it failed.
    // No latency sample: there was no redemption to time.
    m.failed.add(1);
    m.errorRate.add(true);
    if (grant.res.status === 429) m.throttled.add(1);
    if (!loggedAuthorizeFailure) {
      loggedAuthorizeFailure = true;
      console.error(
        `[oauth2_code_pkce] VU ${__VU}: authorize answered HTTP ${grant.res.status}, ` +
          `not 302+code: ${snippet(grant.res)}`,
      );
    }
    return;
  }

  doOp(redemption(grant.code, pair));
}
