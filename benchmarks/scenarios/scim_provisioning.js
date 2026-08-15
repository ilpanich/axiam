// Scenario: SCIM 2.0 provisioning (B4 / R3.1) — PENDING the `axiam-scim`
// crate landing. Written now, against the documented contract, so R3.1 only
// has to make it pass rather than also write it from scratch.
//
// ============================================================================
// STATUS: PENDING — crates/axiam-scim does not exist yet (R3.1, wave R3 of
// claude_dev/remediation-plan-2026-08-15.md). This file is EXCLUDED from
// `scenario=all` auto-discovery by `runner/run-benchmark.sh`'s
// `PENDING_SCENARIOS` list — it will not run, and will not break the matrix
// — until R3.1 lands AND `BENCH_ENABLE_PENDING_SCENARIOS=1` (or an explicit
// `scenario=scim_provisioning.js`) opts it back in. See that file's header
// comment for the exact mechanism.
// ============================================================================
//
// Written against `improvement-after-run5-benchmark.md` B4's verbatim scope
// (mirrored into R3.1): a new crate mounted under `/scim/v2`, tenant-scoped
// bearer with a dedicated `scim:provision` permission; `Users` + `Groups`
// CRUD + PATCH per RFC 7644 §3.5.2. Field names, exact paths, and the mount
// point are taken from RFC 7643/7644 directly (no AXIAM source exists yet to
// verify against) — re-check every literal below against the real DTOs the
// first time this scenario is run for real, and delete this whole paragraph
// once it has been.
//
// # Flood shape
//
// One SCIM user is created once, in setup(); the flood is a repeated PATCH
// toggling `active` — RFC 7644 §3.5.2's canonical "replace a standard
// attribute" op, the operation subset the plan names Okta/Entra actually
// send, and (like oauth2_revoke.js reusing one token) idempotent enough that
// no per-iteration resource accumulates.
import { cfg, baseUrl, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { doOp } from './lib/metrics.js';
import http from 'k6/http';

export const options = Object.assign(
  {
    scenarios: {
      scimProvisioning: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
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

const SCIM_USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
const SCIM_PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

// Bearer with the `scim:provision` permission (R3.1). The bench client is
// NOT registered for this scope today — that registration is R3.1's own
// follow-on (per the plan, "F4 tenant-isolation review" and the SCIM token
// management page land after this), not something this benchmarks-only
// change can grant ahead of the crate it authorizes against. Until then this
// mint fails loudly, same shape as token_exchange.js's documented blocker.
function mintScimToken() {
  const res = http.post(
    `${baseUrl()}/oauth2/token?tenant_id=${cfg.tenantId}`,
    formBody({
      grant_type: 'client_credentials',
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
      scope: 'openid scim:provision',
    }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
  );
  if (res.status !== 200) {
    throw new Error(
      `scim_provisioning: could not mint a scim:provision token (status ${res.status}): ` +
        `${String(res.body).slice(0, 200)} — expected until R3.1 lands and registers the bench ` +
        "client for the 'scim:provision' scope; see this file's header.",
    );
  }
  const access_token = res.json().access_token;
  if (!access_token) throw new Error('scim_provisioning: client_credentials response carried no access_token');
  return access_token;
}

function createUser(token) {
  const userName = `bench-scim-user-${Date.now()}`;
  const res = http.post(
    `${baseUrl()}/scim/v2/Users`,
    JSON.stringify({
      schemas: [SCIM_USER_SCHEMA],
      userName,
      active: true,
      externalId: `bench-${userName}`,
      emails: [{ value: `${userName}@bench.dev`, primary: true }],
    }),
    { headers: { 'Content-Type': 'application/scim+json', Authorization: `Bearer ${token}` } },
  );
  if (res.status !== 201) {
    throw new Error(`scim_provisioning: SCIM user creation failed (status ${res.status}): ${String(res.body).slice(0, 200)}`);
  }
  const id = res.json().id;
  if (!id) throw new Error('scim_provisioning: SCIM user creation returned no id');
  return id;
}

export function setup() {
  requireSeed();
  const token = mintScimToken();
  const userId = createUser(token);
  return { access_token: token, user_id: userId, toggle: true };
}

export default function (data) {
  // Per-VU alternation would need shared state k6 doesn't give across VUs;
  // a fixed `replace: true` PATCH every iteration is still a real, valid
  // PATCH op (RFC 7644 §3.5.2's `replace` is idempotent by definition) and
  // keeps the flood single-purpose: measuring the PATCH path's cost under
  // the `scim` limiter bucket, not exercising toggle semantics.
  doOp({
    method: 'PATCH',
    url: `${baseUrl()}/scim/v2/Users/${data.user_id}`,
    body: JSON.stringify({
      schemas: [SCIM_PATCH_SCHEMA],
      Operations: [{ op: 'replace', path: 'active', value: true }],
    }),
    params: { headers: { 'Content-Type': 'application/scim+json', Authorization: `Bearer ${data.access_token}` } },
    expect: 200,
  });
}
