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
// `runner/seed.sh` already does for `bench-resource`, but with a role of this
// scenario's own (`bench-uma-reader`): create it, attach the seeded `read`
// permission, and assign it to the bench user scoped to the UMA-registered
// resource this scenario mints tickets against — admin REST provisioning in
// setup(), the same pattern `authz_check_rest.js` uses.
//
// It must be a NEW role rather than the seeded `bench-reader`. Role
// assignments are unique on (role, user) — `resource_id` is not part of the
// key — and seed.sh has already assigned bench-reader to this user against
// `bench-resource`, so reusing it returns 409 and grants nothing here. That
// was the original defect: setup() reported success, every redemption answered
// access_denied, and the cell failed 100%. See grantBenchUserRead().
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
// This scenario's own role. It must NOT be the seeded `bench-reader` — see
// grantBenchUserRead() for the (role, user) uniqueness collision that made
// reusing it silently ineffective. Assigned to exactly one resource: the
// resource set registerResourceSet() mints below. That is what makes the 409
// on re-assignment benign here, and it holds because the harness tears each
// cell down with `bench-down -v` (fresh volume per cell), so a stale
// assignment pointing at a previous run's resource-set id cannot survive.
const UMA_ROLE_NAME = 'bench-uma-reader';

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

// Find a permission id by its `action`. Paginated like findIdByName: the
// tenant's registry holds well over 200 permissions (every users:*, roles:*,
// … the server seeds), so an unpaged first page does NOT contain the bench
// `read` permission — a lookup that reads only page one silently yields "" and
// the subsequent POST fails with a UUID parse error rather than a missing-role
// message.
function findPermissionIdByAction(sess, action) {
  let off = 0;
  for (;;) {
    const res = http.get(`${baseUrl()}/api/v1/permissions?offset=${off}&limit=200`, {
      headers: sess.headers,
    });
    if (res.status !== 200) return null;
    let items;
    try {
      const parsed = res.json();
      items = Array.isArray(parsed) ? parsed : parsed.items || [];
    } catch (_e) {
      return null;
    }
    const hit = items.find((p) => p && p.action === action);
    if (hit) return hit.id;
    if (items.length < 200) return null;
    off += 200;
  }
}

function postAdmin(sess, path, body) {
  return http.post(`${baseUrl()}${path}`, JSON.stringify(body), {
    headers: sess.headers,
    cookies: sess.cookies,
  });
}

// Give the bench user `read` on the UMA-registered resource — via a role of
// this scenario's OWN, which is the part that has to be right.
//
// This used to reuse the seeded `bench-reader` role, and it could never work:
// the role-assignment uniqueness key is (role, user) and does NOT include
// `resource_id`. `runner/seed.sh` already assigns bench-reader -> benchuser
// scoped to `bench-resource`, so re-assigning the SAME role scoped to the UMA
// resource comes back
//   409 {"error":"already_exists","message":"Entity already exists: role_assignment"}
// and the old code treated 409 as "the assignment already exists, which is the
// only property this setup step needs". It does exist — scoped to the WRONG
// resource. The UMA grant was therefore never created, `exchange_ticket`
// evaluated the requesting party against an empty grant set, and every
// redemption answered UMA 2.0 §3.3.6 access_denied
// (`uma.rpt_refused` in the audit log) while setup() reported success. The
// cell failed 100% in every run for this reason, not for a rate-limit one.
//
// A dedicated role sidesteps the collision: distinct (role, user) pair, so the
// resource-scoped assignment is accepted and `POST /api/v1/authz/check` for
// `read` on the UMA resource flips from
//   {"allowed":false,"reason":"no permission grants action 'read'"}
// to {"allowed":true}. Verified live before this change was written.
function grantBenchUserRead(sess, resourceId) {
  const userId = __ENV.BENCH_SUBJECT_ID || '';
  if (!userId) {
    throw new Error('uma_ticket_grant: BENCH_SUBJECT_ID is unset — run runner/seed.sh first.');
  }

  // Create-or-find, because bench-run may re-enter this against a live stack.
  let roleId = findIdByName(sess, '/api/v1/roles', UMA_ROLE_NAME);
  if (!roleId) {
    const created = postAdmin(sess, '/api/v1/roles', {
      name: UMA_ROLE_NAME,
      description: 'uma_ticket_grant: read on the UMA-registered bench resource',
      is_global: false,
    });
    if (created.status === 201 || created.status === 200) {
      try { roleId = created.json().id; } catch (_e) { roleId = null; }
    } else if (created.status !== 409) {
      throw new Error(
        `uma_ticket_grant: could not create the ${UMA_ROLE_NAME} role (status ${created.status}): ` +
          String(created.body).slice(0, 200),
      );
    }
    if (!roleId) roleId = findIdByName(sess, '/api/v1/roles', UMA_ROLE_NAME);
  }
  if (!roleId) throw new Error(`uma_ticket_grant: could not resolve the ${UMA_ROLE_NAME} role id`);

  const permId = findPermissionIdByAction(sess, 'read');
  if (!permId) {
    throw new Error(
      "uma_ticket_grant: could not resolve the seeded 'read' permission — run runner/seed.sh first.",
    );
  }

  // 204 on first attach, 409 once it is already on the role.
  const attach = postAdmin(sess, `/api/v1/roles/${roleId}/permissions`, { permission_id: permId });
  if (![200, 201, 204, 409].includes(attach.status)) {
    throw new Error(
      `uma_ticket_grant: attaching 'read' to ${UMA_ROLE_NAME} failed (status ${attach.status}): ` +
        String(attach.body).slice(0, 200),
    );
  }

  // Here 409 IS benign: same role, same user, and this role is assigned to
  // exactly one resource — this scenario's.
  const assign = postAdmin(sess, `/api/v1/roles/${roleId}/users`, {
    user_id: userId,
    resource_id: resourceId,
  });
  // 204 is what this endpoint actually answers on a fresh grant (it returns no
  // body); 201/200 are accepted too rather than pinning one, and 409 is the
  // already-assigned case.
  if (![200, 201, 204, 409].includes(assign.status)) {
    throw new Error(
      `uma_ticket_grant: role grant failed (status ${assign.status}): ${String(assign.body).slice(0, 200)}`,
    );
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
