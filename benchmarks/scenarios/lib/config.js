// Shared k6 configuration: load model, thresholds, and environment wiring.
//
// All knobs are environment-overridable so the orchestrator (runner/run-benchmark.sh)
// can drive the same scenario at different intensities without editing scripts.
import { fail } from 'k6';

function num(name, dflt) {
  const v = __ENV[name];
  return v === undefined || v === '' ? dflt : Number(v);
}
function str(name, dflt) {
  const v = __ENV[name];
  return v === undefined || v === '' ? dflt : v;
}

export const cfg = {
  // --- target wiring (set by run-benchmark.sh from the target + profile) ---
  target: str('BENCH_TARGET', 'axiam'),
  profile: str('BENCH_PROFILE', 'p0-plaintext'),
  scheme: str('BENCH_SCHEME', 'http'),
  host: str('BENCH_HOST', 'localhost'),
  port: num('BENCH_PORT', 8090),
  grpcAddr: str('BENCH_GRPC_ADDR', 'localhost:50051'),
  // gRPC transport security is INDEPENDENT of the HTTP edge's TLS profile — the
  // nginx edge (targets/axiam/tls/*.conf) proxies HTTP only, so a p1/p3 nginx-
  // fronted profile still leaves :50051 plaintext. The connect plaintext flag
  // must NOT be derived from BENCH_SCHEME. Default plaintext for every profile.
  //
  // D2: AXIAM's own gRPC server (crates/axiam-api-grpc/src/server.rs) natively
  // terminates TLS on :50051 when AXIAM__GRPC_TLS_CERT_PATH/KEY_PATH are set
  // (no proxy involved) — the p2-tls13 native overlay
  // (targets/axiam/docker-compose.native-tls.yml) enables it and
  // profiles/p2-tls13.env sets BENCH_GRPC_PLAINTEXT=false to match, so the k6
  // gRPC dial and the server's listener agree. Any other profile that wants a
  // TLS gRPC dial (e.g. a custom nginx grpc_pass front) can also set
  // BENCH_GRPC_PLAINTEXT=false by hand.
  grpcPlaintext: str('BENCH_GRPC_PLAINTEXT', 'true') === 'true',

  // --- tenancy / credentials provisioned by runner/seed.sh ---
  orgId: str('BENCH_ORG_ID', ''),
  orgSlug: str('BENCH_ORG_SLUG', ''),
  tenantId: str('BENCH_TENANT_ID', ''),
  tenantSlug: str('BENCH_TENANT_SLUG', 'default'),
  realm: str('BENCH_REALM', 'bench'), // keycloak/zitadel realm name
  username: str('BENCH_USERNAME', 'benchuser'),
  password: str('BENCH_PASSWORD', 'Bench@User123!'),
  clientId: str('BENCH_CLIENT_ID', 'bench-client'),
  clientSecret: str('BENCH_CLIENT_SECRET', 'bench-secret'),
  // Zitadel-only: the machine-user token is minted with this project in its
  // audience so it can be introspected, and introspection authenticates as a
  // dedicated resource-server (API app) rather than the machine user (Zitadel
  // rejects machine-user creds at /oauth/v2/introspect). Empty for axiam/keycloak.
  projectId: str('BENCH_PROJECT_ID', ''),
  introspectClientId: str('BENCH_INTROSPECT_CLIENT_ID', ''),
  introspectClientSecret: str('BENCH_INTROSPECT_CLIENT_SECRET', ''),

  // --- TLS (from the security profile) ---
  // Default OFF: the bench TLS edge uses a throwaway private-CA cert
  // (runner/gen-certs.sh) that k6's OS trust store can't verify, and k6 has no
  // option to trust a custom CA. Set BENCH_VERIFY_TLS=true only when pointing the
  // harness at a target with a publicly-trusted certificate.
  verifyTls: str('BENCH_VERIFY_TLS', 'false') === 'true',
  // Informational only: k6 exposes no CA-trust option, so caCert is NOT wired into
  // tlsOptions(). Kept for non-k6 tooling / documentation of the trust chain.
  caCert: str('BENCH_CA_CERT', ''),
  clientCert: str('BENCH_CLIENT_CERT', ''),
  clientKey: str('BENCH_CLIENT_KEY', ''),

  // --- transport (J7) ---
  // k6's two connection knobs, surfaced as env so the shape a run used is a
  // deliberate, recorded choice rather than an inherited default nobody wrote
  // down. See tlsOptions()/connectionModel() for why this exists.
  noConnectionReuse: str('BENCH_NO_CONN_REUSE', 'false') === 'true',
  noVUConnectionReuse: str('BENCH_NO_VU_CONN_REUSE', 'false') === 'true',

  // --- load model ---
  vus: num('BENCH_VUS', 50),
  warmup: str('BENCH_WARMUP', '30s'),
  duration: str('BENCH_DURATION', '120s'),
  cooldown: str('BENCH_COOLDOWN', '10s'),

  // A5/J4: the login-bucket budget the harness must stay inside while
  // pre-minting its refresh-session pool. 0 (the default) = unthrottled, so
  // an ordinary run pre-mints as fast as it can and this knob costs nothing.
  //
  // Under the shipped `internet` posture `/api/v1/auth/login` is 10/min per
  // IP, and the whole k6 fleet is ONE IP. Run 5's rl-prod refresh cell burned
  // that budget on re-logins and reported 4.4% errors that were really login
  // throttling wearing a refresh cell's clothes. The rl-prod profile sets this
  // to the configured login ceiling so setup paces itself instead.
  loginPerMin: num('BENCH_LOGIN_PER_MIN', 0),

  // --- validity gates ---
  maxErrorRate: num('BENCH_MAX_ERROR', 0.01),
  maxP95: num('BENCH_MAX_P95_MS', 2000),

  // --- G5: decision-cache key-space sweep (authz_check_rest.js only) ---
  //
  // Run 3 measured the D7 decision cache at an effective cardinality of ONE:
  // 50 VUs all sending the same (subject, resource, action, scope) tuple, i.e.
  // the friendliest hit rate that exists. `BENCH_AUTHZ_KEYSPACE=K` spreads each
  // request over K distinct cache keys so the ship-decision can be made against
  // a realistic hit rate instead of a best case. K=1 (the default) reproduces
  // run 3 exactly and leaves every other cell that runs authz_check_rest.js
  // completely unchanged.
  //
  // The cache key is `(tenant_id, subject_id, resource_id, action, scope)` —
  // verified against crates/axiam-authz/src/decision_cache.rs `SubKey`, NOT
  // taken from the design doc.
  authzKeyspace: num('BENCH_AUTHZ_KEYSPACE', 1),

  // How the K distinct keys are generated. Both modes keep the request a REAL
  // authorization evaluation returning HTTP 200 with a real decision — never a
  // 400/404 error path, which would make the sweep meaningless.
  //
  //   'resource' (default) — provision K-1 CHILD resources of the seeded
  //       `bench-resource` in setup() via the admin REST API, and vary
  //       `resource_id`. The seeded `bench-reader` role is assigned scoped to
  //       `bench-resource`, so hierarchy inheritance
  //       (crates/axiam-authz/src/engine.rs `applicable_role_ids`) makes every
  //       child ALLOW, on the same 3-round-trip evaluation path as K=1. This is
  //       the mode the G5 plan asks for (K distinct subject x resource pairs).
  //   'action' — zero-provisioning fallback: keep the seeded resource and vary
  //       the `action` string. Index 0 is literally "read" (ALLOW); every other
  //       index is an action no grant covers, so the engine runs the FULL
  //       assignments -> ancestors -> grants path and returns
  //       DENY("no permission grants action '<x>'"). Denies are cached verbatim
  //       (decision_cache.rs / engine.rs `check_access` caches the full
  //       AccessDecision), so the cache is exercised identically. Use this when
  //       the admin credentials for provisioning are unavailable, or as a
  //       control that isolates pure key cardinality from DB row diversity.
  authzKeyspaceMode: str('BENCH_AUTHZ_KEYSPACE_MODE', 'resource'),

  // Parallelism of the setup()-time resource provisioning (http.batch size).
  // Only used by 'resource' mode with K > 1.
  authzKeyspaceBatch: num('BENCH_AUTHZ_KEYSPACE_BATCH', 20),

  // k6 setup() ceiling. Provisioning ~10 000 resources over REST needs more
  // than k6's 60s default. Pure ceiling — it changes no request the VUs send.
  setupTimeout: str('BENCH_SETUP_TIMEOUT', '900s'),

  // Bootstrap admin session used ONLY by the G5 keyspace provisioning in
  // setup(). Defaults deliberately mirror runner/seed.sh's `admin` /
  // BENCH_ADMIN_PASSWORD so no new secret has to be plumbed through: seed.sh
  // bootstraps the org with username `admin` and password `Bench@Admin123!`
  // unless BENCH_ADMIN_PASSWORD was overridden there. These are throwaway
  // benchmark-fixture credentials for a disposable container; never log them.
  adminUsername: str('BENCH_ADMIN_USERNAME', 'admin'),
  adminPassword: str('BENCH_ADMIN_PASSWORD', 'Bench@Admin123!'),

  // --- N1: nested-resource authorization depth sweep -----------------------
  // (authz_nested_rest.js / authz_nested_grpc.js, driven by `just bench-nested`)
  //
  // DEPTH IS DEFINED AS "how many levels the decision has to climb", not as
  // "how many resources exist". Concretely, for AXIAM it is the number of
  // ANCESTORS between the resource named in the check and the resource the
  // role assignment is scoped to:
  //
  //   BENCH_AUTHZ_DEPTH=0   check the seeded `bench-resource` itself — the
  //                         grant is scoped exactly there, zero ancestors to
  //                         walk. This is the SAME logical request
  //                         authz_check_rest.js sends, so it doubles as the
  //                         sweep's own control point.
  //   BENCH_AUTHZ_DEPTH=N   check a resource N levels BELOW `bench-resource`,
  //                         whose only applicable grant is still the one on
  //                         `bench-resource`. The engine must resolve the
  //                         ancestor chain before it can decide
  //                         (crates/axiam-authz/src/engine.rs
  //                         `applicable_role_ids` accepts an assignment scoped
  //                         to any ancestor of the target).
  //
  // Ceiling: `crates/axiam-db/src/repository/resource.rs` sets
  // MAX_ANCESTOR_DEPTH = 50 and `get_ancestors` returns an ERROR (not a
  // truncated walk) once a resource has >= 50 ancestors — so a depth at or
  // near 50 measures the failure path, not the authorization path. The
  // clamp in lib/nested.js keeps the sweep inside that bound with headroom.
  authzDepth: num('BENCH_AUTHZ_DEPTH', 0),

  // How the KEYCLOAK arm expresses "a resource nested N levels deep".
  // Keycloak Authorization Services has no parent/child resource hierarchy, so
  // there is no single mechanical translation — see lib/nested.js's header for
  // the full reasoning behind each.
  //
  //   'wildcard' (default) — ONE registered resource with the URI
  //       `/<root>/*` plus one scope-based permission, and every measured
  //       request asks for a decision on the full leaf PATH
  //       (`/<root>/l1/…/lN#read`) using Keycloak's own URI resolution
  //       (`permission_resource_format=uri`,
  //       `permission_resource_matching_uri=true`). This is Keycloak's real
  //       semantic equivalent of AXIAM's cascade: one grant covers the whole
  //       subtree, and what depth costs is the path match.
  //   'per-node' — N registered resources, one per level, each with its own
  //       scope-based permission, and the request names the leaf resource
  //       directly. Kept as an explicitly-selected control/fallback (it is the
  //       modelling many Keycloak deployments actually use, and it is the
  //       escape hatch if a Keycloak version's path matcher does not recurse
  //       through `/*`), never as the default — its admin cost is O(N) and its
  //       decision cost is depth-flat by construction.
  kcNestedMode: str('BENCH_KC_NESTED_MODE', 'wildcard'),

  // Keycloak master-realm admin credentials, used ONLY by the nested-authz
  // setup() to provision the resource server (Keycloak's Authorization
  // Services config is not reachable through any non-admin API). Defaults
  // mirror runner/seed.sh's KC_ADMIN / KC_ADMIN_PASSWORD, and the legacy
  // unprefixed names are still honoured so an operator who exported them for
  // seeding does not have to export them twice. Throwaway container
  // credentials; never logged.
  kcAdminUsername: str('BENCH_KC_ADMIN', str('KC_ADMIN', 'admin')),
  kcAdminPassword: str('BENCH_KC_ADMIN_PASSWORD', str('KC_ADMIN_PASSWORD', 'admin')),

  // Name/URI prefix for every object the nested-authz setup provisions, on
  // every target. Deterministic so a re-run against a stack that was NOT torn
  // down reuses the fixture instead of duplicating it (the sweep walks
  // depth 0 -> 1 -> 2 -> … against one live stack).
  nestedPrefix: str('BENCH_NESTED_PREFIX', 'bench-nest'),
};

export function baseUrl() {
  return `${cfg.scheme}://${cfg.host}:${cfg.port}`;
}

// k6 `options.tlsAuth` / `insecureSkipTLSVerify` derived from the profile.
// Note: k6 has no "trust this CA" option, so a private-CA edge (the bench
// default) REQUIRES insecureSkipTLSVerify — otherwise every request fails with
// "x509: certificate signed by unknown authority". tlsAuth (client cert for
// mTLS) is independent of server-cert verification.
export function tlsOptions() {
  const o = {};
  if (!cfg.verifyTls) o.insecureSkipTLSVerify = true;
  if (cfg.clientCert && cfg.clientKey) {
    o.tlsAuth = [{
      cert: open(cfg.clientCert),
      key: open(cfg.clientKey),
    }];
  }
  // J7: state the connection model EXPLICITLY rather than inheriting k6's
  // defaults silently.
  //
  // Run 5 published a TypeScript SDK row with NEGATIVE overhead — check/batch
  // p95 21–23 ms *below* the k6 wire baseline measured on the same host. A
  // client cannot beat the wire doing the same work, so one of the two was not
  // doing the same work, and nothing in the archive recorded enough about the
  // baseline's transport to say which. These two flags are k6's whole
  // connection story, and writing them down here means the next run's
  // metadata answers the question instead of re-opening it.
  //
  // Both default false, which is k6's default and the one that matches an SDK:
  // connections are pooled and reused per VU across iterations, exactly as a
  // long-lived SDK client pools them. Setting BENCH_NO_CONN_REUSE=true forces
  // a fresh TCP (and TLS) handshake per request — a legitimate thing to
  // measure, and a baseline that must never be compared against an SDK's
  // pooled numbers.
  o.noConnectionReuse = cfg.noConnectionReuse;
  o.noVUConnectionReuse = cfg.noVUConnectionReuse;
  return o;
}

// J7: a short, stable descriptor of the transport shape this run used, written
// into every cell's meta.json by run-benchmark.sh and read by sdk/collect.py,
// which refuses to publish an SDK-vs-wire overhead column when the baseline's
// model is not the pooled one an SDK client uses.
export function connectionModel() {
  if (cfg.noConnectionReuse) return 'no-reuse';
  if (cfg.noVUConnectionReuse) return 'per-iteration-vu-pool';
  return 'pooled-per-vu';
}

// k6 net/grpc `Client.connect(addr, params)` params for AXIAM's dedicated gRPC
// port (D2). Mirrors scenarios/zitadel_userinfo_grpc.js's connectParams(): when
// not plaintext, k6's grpc client takes its own `tls: { insecureSkipVerify }`
// key (distinct from tlsOptions()'s top-level `insecureSkipTLSVerify`, which
// only covers k6's http/websocket clients) — required here because the p2
// native-TLS overlay's server cert is signed by the same throwaway private CA
// as the REST edge (see tlsOptions() above), which k6 cannot verify.
export function grpcConnectParams() {
  const params = { plaintext: cfg.grpcPlaintext };
  if (!cfg.grpcPlaintext) {
    params.tls = cfg.verifyTls ? {} : { insecureSkipVerify: true };
  }
  return params;
}

// Standard three-stage closed-loop model: warm-up (uncounted) → measure → cooldown.
// k6 cannot literally exclude warm-up from a single metric, so the orchestrator
// time-slices the resource samples and we tag iterations with stage via groups;
// the report trims the warm-up window. Stages here shape the VU ramp.
export function loadStages() {
  return [
    { duration: cfg.warmup, target: cfg.vus },     // ramp to load (warm-up)
    { duration: cfg.duration, target: cfg.vus },   // hold (measured)
    { duration: cfg.cooldown, target: 0 },         // drain (cooldown)
  ];
}

export function thresholds(durationMetric) {
  const t = {};
  t[durationMetric] = [`p(95)<${cfg.maxP95}`];
  t['checks'] = [`rate>${1 - cfg.maxErrorRate}`];
  return t;
}

export function requireSeed() {
  if (cfg.target === 'axiam' && !cfg.tenantId) {
    fail('BENCH_TENANT_ID is required for the axiam target — run runner/seed.sh first');
  }
}
