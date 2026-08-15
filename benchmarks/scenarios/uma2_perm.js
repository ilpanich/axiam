// Scenario: UMA 2.0 permission-ticket minting (`POST /uma2/perm`) — the
// `uma_perm` limiter family.
//
// Why this exists (R5.2 / A1 §5): X2's Protection API endpoint carries
// `RateLimitConfig::uma_perm_per_min` (default 120/min, client-identity
// keyed — see `crates/axiam-api-rest/src/server.rs`'s `/uma2/perm` resource),
// and it had no k6 scenario, so `rl_prod_check.py` reported it as
// "no scenario — not checked".
//
// AXIAM-ONLY: UMA 2.0 has no equivalent endpoint on Keycloak/Zitadel in this
// harness's target set. Never published head-to-head.
//
// # What a "Protection API Token" (PAT) is, and why setup() mints one
//
// `POST /uma2/perm` requires a bearer token carrying the `uma_protection`
// scope, minted for an OAuth2-client subject
// (`crates/axiam-api-rest/src/handlers/uma.rs` `ProtectionApiToken`
// extractor). `runner/seed.sh` registers the bench client with that scope
// (alongside `openid`) specifically so this scenario — and
// `uma_ticket_grant.js` — can mint one; if a seed predates that change,
// setup() below fails loudly rather than degrading into a silent
// `invalid_scope` flood.
//
// # Why setup() also registers a resource set
//
// UMA 2.0 §3.2 validates every ticket request's `resource_scopes` against
// scopes the resource server has already declared
// (`crates/axiam-oauth2/src/uma.rs` `request_ticket` — "a ticket naming a
// scope no resource declares could never be redeemed"). The seeded
// `bench-resource` (`runner/seed.sh`) was never run through UMA registration,
// so it has no declared UMA scopes. setup() registers a fresh, dedicated
// resource set (`POST /uma2/rreg/resource_set`, admin-provisioning-in-setup()
// pattern already used by `authz_check_rest.js`'s G5 keyspace mode) with one
// declared scope, `read`, and every measured request asks for exactly that
// pair. Minting is the whole point of this flood — no `read` grant is needed
// on the bench user for `/uma2/perm` itself (that check only matters for the
// *ticket redemption* half, `uma_ticket_grant.js`).
//
// A ticket is a single-use, opaque handle (`MintedTicket` — consumed on
// exchange, not on mint), so re-requesting the SAME (resource_id,
// resource_scopes) pair every iteration is a legitimate, repeatable mint,
// unlike the ticket-redemption scenario which must mint fresh per iteration.
import { cfg, baseUrl, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { doOp } from './lib/metrics.js';
import http from 'k6/http';

export const options = Object.assign(
  {
    scenarios: {
      umaPerm: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

function formBody(obj) {
  return Object.keys(obj)
    .filter((k) => obj[k] !== undefined && obj[k] !== '')
    .map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(obj[k])}`)
    .join('&');
}

// Mint a Protection API Token: a client_credentials token carrying
// `uma_protection` alongside `openid`. Requires the bench client to be
// registered with that scope (see `runner/seed.sh`); fails loudly rather than
// silently degrading to a scope-less token that would 403 every iteration.
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
      `uma2_perm: could not mint a Protection API Token (status ${res.status}): ` +
        `${String(res.body).slice(0, 200)} — the bench client must be registered with the ` +
        "'uma_protection' scope (see runner/seed.sh); re-seed if this predates that change.",
    );
  }
  const body = res.json();
  if (!body.access_token) throw new Error('uma2_perm: client_credentials response carried no access_token');
  return body.access_token;
}

// Register a dedicated UMA resource set with one declared scope, `read`, so
// every measured `/uma2/perm` call names a resource+scope pair the
// permission endpoint will actually accept.
function registerResourceSet(pat) {
  const res = http.post(
    `${baseUrl()}/uma2/rreg/resource_set`,
    JSON.stringify({ name: 'bench-uma-resource', type: 'bench', resource_scopes: ['read'] }),
    { headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${pat}` } },
  );
  if (res.status !== 201) {
    throw new Error(
      `uma2_perm: resource-set registration failed (status ${res.status}): ${String(res.body).slice(0, 200)}`,
    );
  }
  const id = res.json()._id;
  if (!id) throw new Error('uma2_perm: resource-set registration returned no _id');
  return id;
}

export function setup() {
  requireSeed();
  const pat = mintPat();
  const resourceId = registerResourceSet(pat);
  return { access_token: pat, resource_id: resourceId };
}

export default function (data) {
  doOp({
    method: 'POST',
    url: `${baseUrl()}/uma2/perm`,
    body: JSON.stringify([{ resource_id: data.resource_id, resource_scopes: ['read'] }]),
    params: { headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${data.access_token}` } },
    expect: 201,
  });
}
