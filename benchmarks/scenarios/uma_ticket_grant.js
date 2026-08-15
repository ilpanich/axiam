// Scenario: the UMA 2.0 ticket grant (`grant_type=urn:ietf:params:oauth:
// grant-type:uma-ticket` at `POST /oauth2/token`) — the `uma_ticket` limiter
// family.
//
// Why this exists (R5.2 / A1 §5): X2's ticket-redemption grant carries
// `RateLimitConfig::uma_ticket_per_min` (default 120/min, client-identity
// keyed — see `handle_uma_ticket` in
// `crates/axiam-api-rest/src/handlers/oauth2.rs`), sized separately from
// `uma_perm_per_min` "because minting and redeeming are [different traffic
// shapes]" (that field's own doc comment). It had no k6 scenario, so
// `rl_prod_check.py` reported it as "no scenario — not checked".
//
// AXIAM-ONLY: never published head-to-head, same reasoning as uma2_perm.js.
//
// # Why every iteration mints a fresh ticket
//
// A permission ticket is single-use: `exchange_ticket` consumes it on
// redemption (`crates/axiam-oauth2/src/uma.rs`), and a spent, unknown, or
// expired ticket are all refused identically ("Refusals are uniform" —
// `handle_uma_ticket`'s own doc comment — so a caller cannot use the error to
// tell them apart). Reusing one ticket across iterations, the way
// oauth2_revoke.js reuses one *token* (RFC 7009 explicitly makes re-revoking
// idempotent), would measure the ticket-already-consumed refusal path after
// iteration one, not the grant this scenario exists to check. So each
// iteration pays for its own uncounted `/uma2/perm` mint (via `doOp`-free
// `http.post`, the same "setup-adjacent provisioning" pattern
// `authz_check_rest.js`'s G5 keyspace mode uses) before the counted
// `/oauth2/token` redemption.
//
// # Why setup() also grants the bench user the resource's `read` scope
//
// `exchange_ticket` evaluates the requesting party against the live RBAC
// engine (UMA 2.0 §3.3.6's `AccessDenied` refusal — 403). Redeeming against a
// user with NO grant on the resource would still exercise the rate limiter
// (the bucket check runs before evaluation) but every call would measure the
// short access-denied path rather than a genuine grant, which is not what
// "what this grant costs" should mean. setup() therefore does what
// `runner/seed.sh` already does for `bench-resource`: assign the seeded
// `bench-reader` role (which grants `read`) to the bench user, scoped to the
// UMA-registered resource this scenario mints tickets against — admin
// REST provisioning in setup(), the same pattern `authz_check_rest.js` uses.
import { cfg, baseUrl, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { doOp } from './lib/metrics.js';
import { loginSession } from './lib/auth.js';
import http from 'k6/http';

export const options = Object.assign(
  {
    scenarios: {
      umaTicketGrant: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
    // A ticket mint per iteration outruns k6's default setup budget only at
    // very high VU counts; harmless ceiling otherwise (see authz_check_rest.js).
    setupTimeout: cfg.setupTimeout,
  },
  tlsOptions(),
);

function formBody(obj) {
  return Object.keys(obj)
    .filter((k) => obj[k] !== undefined && obj[k] !== '')
    .map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(obj[k])}`)
    .join('&');
}

const UMA_CLAIM_TOKEN_FORMAT = 'urn:ietf:params:oauth:token-type:access_token';
const UMA_TICKET_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:uma-ticket';

// --- setup()-only provisioning helpers (never measured) -------------------

function mintPat() {
  const res = http.post(
    `${baseUrl()}/oauth2/token?tenant_id=${cfg.tenantId}`,
    formBody({
      grant_type: 'client_credentials',
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
      scope: 'openid uma_protection',
    }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
  );
  if (res.status !== 200) {
    throw new Error(
      `uma_ticket_grant: could not mint a Protection API Token (status ${res.status}): ` +
        `${String(res.body).slice(0, 200)} — the bench client must be registered with the ` +
        "'uma_protection' scope (see runner/seed.sh); re-seed if this predates that change.",
    );
  }
  const access_token = res.json().access_token;
  if (!access_token) throw new Error('uma_ticket_grant: client_credentials response carried no access_token');
  return access_token;
}

function registerResourceSet(pat) {
  const res = http.post(
    `${baseUrl()}/uma2/rreg/resource_set`,
    JSON.stringify({ name: 'bench-uma-ticket-resource', type: 'bench', resource_scopes: ['read'] }),
    { headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${pat}` } },
  );
  if (res.status !== 201) {
    throw new Error(
      `uma_ticket_grant: resource-set registration failed (status ${res.status}): ${String(res.body).slice(0, 200)}`,
    );
  }
  const id = res.json()._id;
  if (!id) throw new Error('uma_ticket_grant: resource-set registration returned no _id');
  return id;
}

// Mirrors authz_check_rest.js's adminSession() exactly (deliberately NOT
// shared via lib/auth.js — this is provisioning, not a measured operation).
function adminSession() {
  const jar = http.cookieJar();
  const url = `${baseUrl()}/api/v1/auth/login`;
  const body = { username_or_email: cfg.adminUsername, password: cfg.adminPassword };
  if (cfg.orgId) body.org_id = cfg.orgId;
  else if (cfg.orgSlug) body.org_slug = cfg.orgSlug;
  if (cfg.tenantId) body.tenant_id = cfg.tenantId;
  else if (cfg.tenantSlug) body.tenant_slug = cfg.tenantSlug;

  const res = http.post(url, JSON.stringify(body), { headers: { 'Content-Type': 'application/json' } });
  if (res.status !== 200) {
    throw new Error(
      `uma_ticket_grant: admin login failed (status ${res.status}) — this scenario grants the bench ` +
        'user a role on the UMA resource through the admin REST API. Set BENCH_ADMIN_USERNAME/' +
        'BENCH_ADMIN_PASSWORD to match runner/seed.sh.',
    );
  }
  const cookies = jar.cookiesForURL(url);
  const access = cookies.axiam_access && cookies.axiam_access[0];
  const csrf = cookies.axiam_csrf && cookies.axiam_csrf[0];
  if (!access || !csrf) {
    throw new Error('uma_ticket_grant: admin login returned no axiam_access/axiam_csrf cookie');
  }
  return {
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${access}`, 'X-CSRF-Token': csrf },
    cookies: { axiam_csrf: csrf },
  };
}

// Paginated name lookup, mirroring runner/seed.sh's find_id() — AXIAM list
// endpoints are paginated (default limit 50, clamped 200) and the bench-reader
// role is seeded alongside a large built-in registry, so an unparameterised
// single GET can miss it.
function findIdByName(sess, path, value) {
  let off = 0;
  for (;;) {
    const res = http.get(`${baseUrl()}${path}?offset=${off}&limit=200`, { headers: sess.headers });
    if (res.status !== 200) return null;
    let items;
    try {
      const parsed = res.json();
      items = Array.isArray(parsed) ? parsed : parsed.items || [];
    } catch (_e) {
      return null;
    }
    const hit = items.find((r) => r && r.name === value);
    if (hit) return hit.id;
    if (items.length < 200) return null;
    off += 200;
  }
}

function grantBenchUserRead(sess, resourceId) {
  const roleId = findIdByName(sess, '/api/v1/roles', 'bench-reader');
  const userId = __ENV.BENCH_SUBJECT_ID || '';
  if (!roleId || !userId) {
    throw new Error(
      'uma_ticket_grant: could not resolve the seeded bench-reader role id / BENCH_SUBJECT_ID — ' +
        'run runner/seed.sh first.',
    );
  }
  const res = http.post(
    `${baseUrl()}/api/v1/roles/${roleId}/users`,
    JSON.stringify({ user_id: userId, resource_id: resourceId }),
    { headers: sess.headers, cookies: sess.cookies },
  );
  // 201 on first grant; a re-run against a live (not torn-down) stack that
  // already holds this assignment gets a 409/200-idempotent response
  // depending on server semantics — either way the assignment already exists,
  // which is the only property this setup step needs.
  if (res.status !== 201 && res.status !== 200 && res.status !== 409) {
    throw new Error(`uma_ticket_grant: role grant failed (status ${res.status}): ${String(res.body).slice(0, 200)}`);
  }
}

function mintTicket(pat, resourceId) {
  const res = http.post(
    `${baseUrl()}/uma2/perm`,
    JSON.stringify([{ resource_id: resourceId, resource_scopes: ['read'] }]),
    { headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${pat}` } },
  );
  if (res.status !== 201) return null;
  try {
    return res.json().ticket;
  } catch (_e) {
    return null;
  }
}

// ---------------------------------------------------------------------------

export function setup() {
  requireSeed();
  const pat = mintPat();
  const resourceId = registerResourceSet(pat);
  const admin = adminSession();
  grantBenchUserRead(admin, resourceId);
  const session = loginSession();
  return { pat, resource_id: resourceId, claim_token: session.access_token };
}

export default function (data) {
  // Uncounted provisioning call — see the file header for why a ticket must
  // be minted fresh per iteration. A failed mint is surfaced as a thrown
  // error (not silently retried) so a provisioning regression fails loudly
  // instead of quietly starving the measured op of tickets to redeem.
  const ticket = mintTicket(data.pat, data.resource_id);
  if (!ticket) {
    throw new Error('uma_ticket_grant: setup-adjacent /uma2/perm mint failed mid-run');
  }

  doOp({
    method: 'POST',
    url: `${baseUrl()}/oauth2/token?tenant_id=${cfg.tenantId}`,
    body: formBody({
      grant_type: UMA_TICKET_GRANT_TYPE,
      ticket,
      claim_token: data.claim_token,
      claim_token_format: UMA_CLAIM_TOKEN_FORMAT,
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
    }),
    params: { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
    expect: 200,
  });
}
