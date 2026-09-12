// Scenario: SCIM 2.0 provisioning (B4 / R3.1). Floods the `/scim/v2` limiter
// bucket so `runner/rl_prod_check.py` can compare admitted-per-minute against
// the configured `scim_per_min`.
//
// ============================================================================
// RUN HISTORY: its first-ever execution (2026-09-11) FAILED 20 of 907
// operations, and the failure was a real server defect rather than a harness
// one: concurrent `PATCH /scim/v2/Users/{id}` lost a SurrealDB
// optimistic-concurrency race and answered HTTP 500 for a write the engine
// labelled retryable. Nothing retried it. Fixed in axiam-db
// (`helpers::retry_on_write_conflict`, applied to `UserRepository::update`);
// this cell then ran clean at 470/470 checks with zero SCIM 500s in the
// server log, and was removed from PENDING_SCENARIOS in that same commit.
//
// Keep the flood shape below as it is. A single-user PATCH storm is precisely
// what found that defect, and it is also what Okta/Entra actually send.
// ============================================================================
//
// Written against `improvement-after-run5-benchmark.md` B4's verbatim scope
// (mirrored into R3.1): a new crate mounted under `/scim/v2`, tenant-scoped
// bearer with a dedicated `scim:provision` permission; `Users` + `Groups`
// CRUD + PATCH per RFC 7644 §3.5.2. Field names, exact paths, and the mount
// point below were taken from RFC 7643/7644 directly, BEFORE the crate
// existed — they have not yet been re-checked against the real DTOs, because
// this scenario has still never executed against a live server. Do that on
// its first real run, and delete this paragraph once it has happened.
//
// # Flood shape
//
// One SCIM user is created once, in setup(); the flood is a repeated PATCH
// toggling `active` — RFC 7644 §3.5.2's canonical "replace a standard
// attribute" op, the operation subset the plan names Okta/Entra actually
// send, and (like oauth2_revoke.js reusing one token) idempotent enough that
// no per-iteration resource accumulates.
import { baseUrl, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { mintUserToken } from './lib/auth.js';
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

const SCIM_USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
const SCIM_PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

// Bearer for a principal holding the `scim:provision` RBAC permission (R3.1),
// seeded by `runner/seed.sh` as a global `bench-scim` role on the bench USER.
//
// `mintUserToken()` (not `mintToken()`) because this MUST be a user token —
// see this file's header for why a client_credentials/service-account subject
// can hold no RBAC permission. `mintUserToken()` silently falls back to
// client_credentials when a login fails, which for every other scenario is a
// useful degradation and for this one is a wrong answer that would surface as
// an opaque 403 from `/scim/v2` rather than as a seeding fault. So the
// fallback is rejected explicitly here rather than being allowed to mislead.
function mintScimToken() {
  const t = mintUserToken();
  if (!t.is_user_token) {
    throw new Error(
      'scim_provisioning: mintUserToken fell back to client_credentials, which yields a ' +
        'service_account subject. That subject can hold no RBAC permission (the role edge is ' +
        "hard-scoped to the `user` table), so `scim:provision` can never be satisfied by it. " +
        'Check that seed.sh ran and that the bench user login works.',
    );
  }
  if (!t.access_token) throw new Error('scim_provisioning: user login returned no access token');
  return t.access_token;
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
