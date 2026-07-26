// Scenario: single authorization decision over REST (POST /api/v1/authz/check).
//
// AXIAM-ONLY: no competitor exposes an equivalent REST authorization-decision
// endpoint, so like the gRPC authz scenarios this is reported separately, never
// as a head-to-head number. It exists because SDK check_access()/batch_check()
// are REST calls in every SDK — this scenario is the wire baseline the SDK
// harness's overhead delta is measured against (sdk/collect.py, HARNESS-SPEC.md).
//
// Identity comes from the verified JWT (a self-check needs no subject_id); the
// resource_id must be the seeded resource UUID and a seeded role grant makes the
// decision allowed=true. A non-GET call under /api/v1 requires the CSRF
// double-submit (axiam_csrf cookie + X-CSRF-Token header), both taken from login.
//
// ---------------------------------------------------------------------------
// G5 — decision-cache key-space sweep (BENCH_AUTHZ_KEYSPACE)
// ---------------------------------------------------------------------------
//
// Run 3 measured the D7 decision cache with 50 VUs all hammering ONE
// (subject, resource, action, scope) tuple — cardinality K=1, the friendliest
// hit rate that can exist — and reported a ~3.0-3.15x throughput win. That
// number cannot justify flipping a security-relevant default, so this scenario
// is parameterized by the cache-key cardinality:
//
//   BENCH_AUTHZ_KEYSPACE=K   each request picks 1 of K distinct cache keys
//
//   K=1      (DEFAULT) reproduces run 3 exactly. No provisioning happens, the
//            request body is byte-identical to the pre-G5 scenario, and every
//            other cell that runs this file is unaffected.
//   K=100    small-service key space.
//   K=10000  exceeds the default DECISION_CACHE_MAX_ENTRIES (10 000 per
//            tenant), so it also exercises the FIFO eviction path.
//
// The cache key was read out of crates/axiam-authz/src/decision_cache.rs
// (`SubKey` = subject_id, resource_id, action, scope; sharded by tenant_id) —
// not taken on faith from the design doc.
//
// Both key-generation modes (see lib/config.js `authzKeyspaceMode`) keep the
// request a REAL authorization evaluation returning HTTP 200 with a real
// decision. An error path (400 on a malformed UUID, 404 on a missing object)
// would short-circuit the engine and make the whole sweep meaningless, so
// setup() probes the generated key space before the measured window starts and
// fails loudly if the probe is not the expected decision.
import http from 'k6/http';
import { cfg, baseUrl, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { doOp } from './lib/metrics.js';
import { loginSession } from './lib/auth.js';

export const options = Object.assign(
  {
    scenarios: {
      authzCheckRest: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
    // Ceiling only — provisioning 10 000 resources over REST outruns k6's 60s
    // setup default. Changes nothing about the requests the VUs send.
    setupTimeout: cfg.setupTimeout,
  },
  tlsOptions(),
);

const RESOURCE = __ENV.BENCH_RESOURCE_ID || 'bench-resource';

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

// Clamp K to a sane integer. K<=1 means "behave exactly as the pre-G5 scenario".
function keyspace() {
  const k = Math.floor(Number(cfg.authzKeyspace));
  return Number.isFinite(k) && k > 1 ? k : 1;
}

// ---------------------------------------------------------------------------
// setup() helpers — admin session + child-resource provisioning
// ---------------------------------------------------------------------------

// Log in as the bootstrap admin (runner/seed.sh's `admin` user) and return the
// cookie-session credentials needed to POST under /api/v1. Mirrors
// lib/targets.js `axiam.login()`: prefer the seeded org/tenant UUIDs, fall back
// to slugs, omit empty selectors. Deliberately NOT added to lib/auth.js — this
// is a G5-only provisioning path, not a measured operation.
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
      `authz_check_rest[G5]: admin login failed (status ${res.status}). ` +
        'BENCH_AUTHZ_KEYSPACE>1 in resource mode provisions child resources through the admin REST API; ' +
        'set BENCH_ADMIN_USERNAME/BENCH_ADMIN_PASSWORD to match runner/seed.sh, or use ' +
        'BENCH_AUTHZ_KEYSPACE_MODE=action (no provisioning).',
    );
  }
  const cookies = jar.cookiesForURL(url);
  const access = cookies.axiam_access && cookies.axiam_access[0];
  const csrf = cookies.axiam_csrf && cookies.axiam_csrf[0];
  if (!access || !csrf) {
    throw new Error('authz_check_rest[G5]: admin login returned no axiam_access/axiam_csrf cookie');
  }
  return {
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${access}`, 'X-CSRF-Token': csrf },
    cookies: { axiam_csrf: csrf },
  };
}

// Child resources are named deterministically so a re-run against a stack that
// was NOT torn down reuses what is already there instead of duplicating it
// (the G5 driver sweeps K=1 -> 100 -> 10000 against one live stack).
function childName(i) {
  return `bench-ks-${i}`;
}

// Existing bench-ks-* children of the seeded resource, as { name: id }.
// GET /api/v1/resources/{id}/children returns an UNPAGINATED Vec<Resource>
// (crates/axiam-api-rest/src/handlers/resources.rs `list_children`), so one
// call is enough even at 10 000. A failure here is non-fatal: we simply
// provision from scratch.
function existingChildren(sess) {
  const res = http.get(`${baseUrl()}/api/v1/resources/${RESOURCE}/children`, { headers: sess.headers });
  if (res.status !== 200) {
    console.warn(`authz_check_rest[G5]: children listing returned ${res.status}; provisioning from scratch`);
    return {};
  }
  let items;
  try {
    const body = res.json();
    items = Array.isArray(body) ? body : body.items || [];
  } catch (_e) {
    return {};
  }
  const byName = {};
  for (const r of items) {
    if (r && r.name && r.id) byName[r.name] = r.id;
  }
  return byName;
}

// Provision (or reuse) K-1 child resources of the seeded resource and return
// the full ordered key list: [seeded resource, child 1, ... child K-1].
//
// Children inherit the bench user's role assignment through the hierarchy
// (the seeded `bench-reader` role is assigned scoped to the parent, and
// engine.rs `applicable_role_ids` accepts an assignment scoped to any ancestor
// of the target), so every one of the K keys yields a real ALLOW on the same
// 3-round-trip evaluation path as K=1.
function provisionResourceKeyspace(k) {
  if (!UUID_RE.test(RESOURCE)) {
    throw new Error(
      `authz_check_rest[G5]: BENCH_RESOURCE_ID is "${RESOURCE}", not a UUID — the resource key-space mode ` +
        'needs the seeded resource UUID to parent its children. Source .seed/axiam.seed.env, or use ' +
        'BENCH_AUTHZ_KEYSPACE_MODE=action.',
    );
  }
  const sess = adminSession();
  const known = existingChildren(sess);

  const ids = [RESOURCE];
  const missing = [];
  for (let i = 1; i < k; i++) {
    const name = childName(i);
    if (known[name]) {
      ids.push(known[name]);
    } else {
      ids.push(null);
      missing.push({ slot: i, name });
    }
  }

  if (missing.length > 0) {
    console.log(`authz_check_rest[G5]: provisioning ${missing.length} child resources (K=${k})`);
    const batchSize = Math.max(1, Math.floor(cfg.authzKeyspaceBatch) || 1);
    for (let off = 0; off < missing.length; off += batchSize) {
      const chunk = missing.slice(off, off + batchSize);
      const reqs = chunk.map((m) => [
        'POST',
        `${baseUrl()}/api/v1/resources`,
        JSON.stringify({ name: m.name, resource_type: 'bench-keyspace', parent_id: RESOURCE }),
        { headers: sess.headers, cookies: sess.cookies },
      ]);
      const responses = http.batch(reqs);
      for (let j = 0; j < responses.length; j++) {
        const r = responses[j];
        if (r.status !== 201) {
          throw new Error(
            `authz_check_rest[G5]: creating ${chunk[j].name} failed (status ${r.status}): ` +
              String(r.body).slice(0, 200),
          );
        }
        let id;
        try {
          id = r.json().id;
        } catch (_e) {
          id = null;
        }
        if (!id) throw new Error(`authz_check_rest[G5]: create ${chunk[j].name} returned no id`);
        ids[chunk[j].slot] = id;
      }
      if ((off / batchSize) % 25 === 0) {
        console.log(`authz_check_rest[G5]: ${Math.min(off + batchSize, missing.length)}/${missing.length} created`);
      }
    }
  }

  for (let i = 0; i < ids.length; i++) {
    if (!ids[i]) throw new Error(`authz_check_rest[G5]: key-space slot ${i} was not provisioned`);
  }
  return ids;
}

// ---------------------------------------------------------------------------
// Request construction
// ---------------------------------------------------------------------------

// Build the check body for key index `i`. At i=0 this is byte-identical to the
// pre-G5 body in BOTH modes: {"action":"read","resource_id":"<seeded>"}.
function bodyFor(data, i) {
  if (data.keyspace_mode === 'action') {
    return JSON.stringify({ action: i === 0 ? 'read' : `read-ks-${i}`, resource_id: RESOURCE });
  }
  return JSON.stringify({ action: 'read', resource_id: data.resource_ids[i] });
}

// Per-VU xorshift32, seeded from __VU. Deterministic (so two cells with the
// same K draw the same sequence) and uniform over [0, k). Module scope is
// per-VU in k6, so each VU keeps its own stream across iterations.
let rngState = 0;
function nextIndex(k) {
  if (k <= 1) return 0;
  if (rngState === 0) rngState = (__VU * 2654435761) >>> 0 || 0x9e3779b9;
  rngState ^= rngState << 13;
  rngState >>>= 0;
  rngState ^= rngState >>> 17;
  rngState ^= rngState << 5;
  rngState >>>= 0;
  return rngState % k;
}

// ---------------------------------------------------------------------------

export function setup() {
  requireSeed();
  const session = loginSession();
  const k = keyspace();
  const mode = cfg.authzKeyspaceMode === 'action' ? 'action' : 'resource';

  const data = Object.assign({}, session, { keyspace: k, keyspace_mode: mode, resource_ids: [RESOURCE] });

  if (k > 1 && mode === 'resource') {
    data.resource_ids = provisionResourceKeyspace(k);
  }

  if (k > 1) {
    // Fail-closed gate: the LAST key must be a real evaluation with the
    // expected decision, otherwise the sweep would silently measure an error
    // path or the short "no applicable roles" deny instead of the full
    // evaluation the cache is supposed to be skipping.
    const probe = http.post(`${baseUrl()}/api/v1/authz/check`, bodyFor(data, k - 1), {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${session.access_token}`,
        'X-CSRF-Token': session.csrf_token,
      },
      cookies: { axiam_csrf: session.csrf_token },
    });
    if (probe.status !== 200) {
      throw new Error(
        `authz_check_rest[G5]: key-space probe returned ${probe.status}, not a decision — ` +
          `the K=${k} sweep would measure an error path. Body: ${String(probe.body).slice(0, 200)}`,
      );
    }
    const allowed = probe.json().allowed;
    if (mode === 'resource' && allowed !== true) {
      throw new Error(
        'authz_check_rest[G5]: a provisioned child resource evaluated to DENY ' +
          `(reason: ${probe.json().reason}). Hierarchy inheritance of the seeded role assignment is not ` +
          'working, so the sweep would measure the SHORT deny path (2 DB round-trips) instead of the full ' +
          'evaluation. Re-seed, or use BENCH_AUTHZ_KEYSPACE_MODE=action.',
      );
    }
    if (mode === 'action' && allowed !== false) {
      throw new Error(
        'authz_check_rest[G5]: a synthetic action evaluated to ALLOW — the bench role grants more than ' +
          '"read", so the action key space is not the intended deny-on-full-path shape.',
      );
    }
    console.log(
      `authz_check_rest[G5]: key space ready — K=${k}, mode=${mode}, ` +
        `decision at last key = ${allowed ? 'ALLOW' : 'DENY'} (both are cached verbatim)`,
    );
  }

  return data;
}

export default function (data) {
  const i = nextIndex(data.keyspace || 1);
  doOp({
    method: 'POST',
    url: `${baseUrl()}/api/v1/authz/check`,
    body: bodyFor(data, i),
    params: {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${data.access_token}`,
        'X-CSRF-Token': data.csrf_token,
      },
      cookies: { axiam_csrf: data.csrf_token },
    },
    expect: 200,
  });
}
