// Scenario: RFC 8414 authorization-server metadata —
// `GET /.well-known/oauth-authorization-server?tenant_id=<tenant>` (T21.1).
//
// Why this exists. Every MCP client fetches this document on connect, before
// it does anything else: it is how the client learns where to register, where
// to send the user and which PKCE methods the server takes. Several client
// libraries probe this path and never fall back to the OIDC one, which is why
// T21.1 added it. It is the one request every MCP session makes, so it is the
// one request an MCP-heavy deployment makes most.
//
// # What the server does per request (read from the handler, not assumed)
//
// `server.rs` routes this path and `/.well-known/openid-configuration` to one
// handler, `handlers::oauth2::discovery`, so the two documents are the same
// bytes. It is not rate-limited (a bare `cfg.route`, no governor, no
// `RateLimitShared`), so the cell is unaffected by the settle-gate clamp and by
// `rl=prod`.
//
// It is NOT a static document once a tenant is named, and that is what makes
// it worth a cell of its own rather than one more `jwks_fetch.js`.
// `discovery_document()` resolves the three per-tenant capability rows the
// document advertises — the W7 sensitive scopes, the T21.4 registration
// endpoint and the T21.5 CIMD flag — from ONE effective-settings read, and
// that read is three sequential SurrealDB round trips with no cache in front:
//
//   1. `tenant_repo.get_by_id`            the tenant row (for its org id);
//   2. `settings_repo.get_org_settings`   the organization baseline row;
//   3. `fetch_row_with_overrides`         the tenant row + its sparse override
//                                         JSON, parsed, clamped to the org
//                                         floor and merged.
//
// Then the document is built (string formatting of the endpoint URLs, no
// cryptography) and serialised. So this cell is a floor on "three small reads
// and a JSON body", which `jwks_fetch.js` — no database at all — is not.
//
// Why `?tenant_id=` rather than the bare path. With no tenant named and no
// `AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID` (the bench compose sets neither),
// the handler skips all three reads and serves the deployment-wide document —
// the cheap path, and not the one an MCP client of a multi-tenant deployment
// gets. That client gets a tenant-described document either through a default
// tenant or through a T21.6 per-tenant issuer (`/.well-known/
// oauth-authorization-server/t/{tenant_id}`, mounted only under
// `AXIAM__AUTH__TENANT_ISSUER_PATHS`), and both of those reach the same
// `discovery_document()` with the same `Some(tenant)` this query produces. The
// query form measures that work without asking the bench stack for a
// deployment mode it does not otherwise run in.
//
// One trap, stated so nobody has to find it: an UNKNOWN tenant id is answered
// 200 with the deployment-wide capabilities (a 404 would be a
// tenant-enumeration oracle), after one failed read instead of three. A stale
// BENCH_TENANT_ID therefore passes this cell while measuring the cheaper
// path. `runner/seed.sh`'s smoke checks are what guard the tenant id.
//
// # AXIAM-only, and why
//
// Not for want of a competitor endpoint: Keycloak and Zitadel both publish
// discovery metadata, and `jwks_fetch.js` already gives the cross-vendor floor
// for "serve a small public document". Two reasons it is not head-to-head yet:
//
//   * The RFC 8414 §3.1 location is derived from the ISSUER, and the three
//     issuers are shaped differently. Keycloak's issuer is
//     `…/realms/<realm>`, so the RFC-correct location inserts the well-known
//     segment before the realm path — while the realm metadata Keycloak
//     documents is appended after it. An adapter would have to pick one, and
//     picking the one that answers is picking a different request than the
//     one an RFC 8414 client derives.
//   * Neither competitor's RFC 8414 path has been exercised against the
//     pinned images (Keycloak 26.7.0, Zitadel v4.16.2) in this harness, and an
//     adapter that 404s turns "unverified" into a red matrix cell on every
//     competitor arm — the failure `AXIAM_ONLY_SCENARIOS` exists to prevent.
//
// Promoting it is one `authorizationServerMetadata()` per adapter in
// `lib/targets.js` plus dropping the name from `AXIAM_ONLY_SCENARIOS`, once a
// live run has shown what each image serves.
import { loadStages, thresholds, tlsOptions, requireSeed, cfg } from './lib/config.js';
import { adapter } from './lib/targets.js';
import { doOp } from './lib/metrics.js';

export const options = Object.assign(
  {
    scenarios: {
      oauth2Discovery: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

export function setup() {
  // The tenant id is the whole measurement (see the header) — without it the
  // cell silently measures the database-free path.
  requireSeed();
  if (typeof adapter().authorizationServerMetadata !== 'function') {
    throw new Error(
      `target "${cfg.target}" has no authorizationServerMetadata() adapter — ` +
        'oauth2_discovery.js is AXIAM-only (run-benchmark.sh AXIAM_ONLY_SCENARIOS)',
    );
  }
}

export default function () {
  // `expect: 200` is exact: the handler's only other answers are a 500 for a
  // misconfigured issuer or mTLS alias base URL, which are deployment faults
  // this cell should report rather than average in.
  doOp(adapter().authorizationServerMetadata());
}
