// Scenario: SCIM 2.0 provisioning (B4 / R3.1). Floods the `/scim/v2` limiter
// bucket so `runner/rl_prod_check.py` can compare admitted-per-minute against
// the configured `scim_per_min`.
//
// ============================================================================
// STATUS: SEEDING AND AUTH ARE FIXED. STILL PENDING ON ONE SUPERVISED RUN.
//
// `crates/axiam-scim` HAS landed (R3.1) and `/scim/v2` answers; the R5.2 tail
// gave it a real rate-limit bucket (`AXIAM__RATE_LIMIT__SCIM_PER_MIN`,
// shipped 600/min per IP) and folded the family into rl_prod_check.py's
// ENDPOINTS. `runner/seed.sh` now provisions the missing principal: a GLOBAL
// `bench-scim` role holding a `scim:provision` permission, assigned to the
// bench user. `mintScimToken()` below mints a USER token accordingly.
//
// The earlier note here — "that is a seed.sh change" — was only half right,
// and the half it got wrong is worth keeping written down. Two things had to
// change, because `scim:provision` is an RBAC permission, not an OAuth2
// scope:
//
//   1. Adding "scim:provision" to the bench client's `scopes` would have
//      done nothing. `require_scim_provision` calls
//      `RequirePermission::new("scim:provision", Uuid::nil()).check(...)`,
//      an RBAC check against the token's SUBJECT. The scope would have ridden
//      along on the token and the check would still have denied.
//   2. A `client_credentials` token cannot work at all, whatever it is
//      scoped for. That grant mints a `sub_kind: ServiceAccount` subject, and
//      AXIAM's role-assignment edge is hard-scoped to the `user` table today,
//      so a service_account subject can hold NO RBAC permission —
//      `scim:provision` included (`crates/axiam-scim/src/auth.rs` says so
//      explicitly). Hence the switch to a user token below.
//
// It stays in `runner/run-benchmark.sh`'s `PENDING_SCENARIOS` for ONE
// remaining reason, and it is not a code reason: this scenario has still
// never executed against a live server. Its field names and paths were
// checked statically against the real DTOs (`users.rs`'s `userName` /
// `externalId` / `emails[].primary` / `active`, and `patch.rs`'s `replace` on
// path `active` with a boolean) and they match — but "matches on inspection"
// is not "runs green", and un-pending it unrun would risk turning a skip into
// a red matrix cell, which is the exact failure this list exists to prevent.
//
// TO CLOSE THIS OUT: run it once, supervised, with
// `BENCH_ENABLE_PENDING_SCENARIOS=1`. If it passes, remove it from
// `PENDING_SCENARIOS` and delete this block. No further code change is
// expected to be needed.
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
