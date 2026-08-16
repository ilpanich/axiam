// Scenario: authorize a resource nested N levels deep, over REST.
//
// N1. This is the depth-sweep counterpart of authz_check_rest.js: the same
// class of operation (one authorization decision, one round trip), asked about
// a resource that sits `BENCH_AUTHZ_DEPTH` levels below the one carrying the
// grant. Driven by `just bench-nested`, which runs the whole depth ladder and
// writes each rung into its own results/nested/d<N>/ subtree.
//
// COMPARABILITY — read this before publishing any number from this file.
// All three targets are wired (lib/nested.js), but they are NOT running the
// same product mechanism, because only one of them HAS the mechanism:
//
//   axiam    — a real hierarchy walk. One role assignment on the chain root
//              cascades to the leaf; the engine resolves the ancestor chain
//              before it can decide. Depth is expected to cost something.
//   keycloak — no parent/child relation exists, so nesting is expressed as URI
//              paths and one `/<root>/*` resource + permission covers the
//              subtree; the server resolves the leaf path to that resource.
//              Same administrative shape (one grant covers the subtree), a
//              different resolution mechanism.
//   zitadel  — no per-resource decision endpoint exists at all. That arm is a
//              declared capability gap measuring the role-claim round trip a
//              resource server makes before deciding locally, and it is
//              depth-invariant BY CONSTRUCTION. Never plot it as a depth curve;
//              runner/nested_report.py refuses to.
//
// So the honest published artifact is per-target depth SENSITIVITY (how each
// product's own number moves as depth grows), plus a clearly-labelled absolute
// table. `runner/nested_report.py` renders exactly that and carries the
// caveats with the numbers.
//
// Each target's setup() ends in a fail-closed probe (see lib/nested.js): the
// decision at this depth must come back with the expected verdict before the
// measured window opens. A wrongly-provisioned fixture takes the SHORT deny
// path — which is cheaper than the walk this cell exists to measure — so a
// silent deny would publish an optimistic number for the wrong code path.
import { cfg, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { doOp } from './lib/metrics.js';
import { nestedAdapter, nestedDepth } from './lib/nested.js';

export const options = Object.assign(
  {
    scenarios: {
      authzNestedRest: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
    // Ceiling only. Provisioning is O(depth) REST calls on AXIAM and a handful
    // of admin calls on Keycloak — nowhere near k6's 60s setup default at any
    // legal depth — but the ladder is driven unattended, so an over-generous
    // ceiling costs nothing and a too-tight one loses a whole rung.
    setupTimeout: cfg.setupTimeout,
  },
  tlsOptions(),
);

export function setup() {
  requireSeed();
  const depth = nestedDepth();
  const a = nestedAdapter();
  const data = a.setup(depth);
  // Echoed into the cell log so a results tree can be read back without
  // re-deriving which arm produced which rung.
  console.log(
    `authz_nested_rest: target=${a.key} depth=${depth} ` +
      `depth_invariant=${a.depthInvariant} model="${a.model}"`,
  );
  return data;
}

export default function (data) {
  doOp(nestedAdapter().buildCheck(data));
}
