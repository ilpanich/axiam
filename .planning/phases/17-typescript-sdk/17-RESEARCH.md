# Phase 17: TypeScript SDK - Research

**Researched:** 2026-07-01
**Domain:** Dual-persona (browser/Node) TypeScript IAM client SDK — axios/gRPC/AMQP transports, JWKS verification, framework middleware, npm publish CI
**Confidence:** HIGH

## Summary

This phase is almost entirely a **HOW-execution** problem, not a design problem. The behavioral
surface is fully locked by `sdks/CONTRACT.md` §1–§10 and by 28 CONTEXT.md decisions (D-01..D-28 +
CF-01..CF-03). Critically, **Phase 16 (Rust SDK) already resolved every "research MUST confirm"
open item this phase lists** — because Rust and TypeScript talk to the exact same frozen v1.0
server. The Rust SDK's source tree (`sdks/rust/src/`) is therefore not just a design reference; it
is a working, tested oracle for cookie names, the JWKS path, the AMQP HMAC wire format, and the
timeout/backoff defaults. Every "UNRESOLVED" item CONTEXT.md flagged is resolved below with
file:line evidence from either the server crates or the already-shipped Rust SDK that talks to
them.

The remaining genuine unknowns are narrow and TypeScript-specific: (1) the exact tsup multi-entry
dual-ESM/CJS config shape, (2) the `jose` `createRemoteJWKSet` cooldown/timeout API surface vs. a
hand-rolled cache (the Rust SDK hand-rolls its own JWKS cache because `jsonwebtoken` has no
built-in remote-fetch helper — TS's `jose` does, so the idiom differs even though the underlying
protocol is identical), (3) the `@grpc/grpc-js` interceptor shape (structurally different from
tonic's tower-style interceptor), and (4) the bundle-and-grep CI mechanics for SC#1. All four are
resolved below with concrete code patterns.

**Primary recommendation:** Build the TS SDK as a near-literal port of `sdks/rust/src/`'s module
boundaries (`token/{jwks,manager,refresh_guard}`, `rest/auth`, `grpc/interceptor`, `amqp/{hmac,consumer}`,
`middleware/{express,fastify}`), substituting Rust-specific mechanisms for their TS idiomatic
equivalents (tokio Mutex → module-level `Promise` guard; `reqwest::cookie::Jar` → `tough-cookie`
`CookieJar`; `jsonwebtoken` hand-cache → `jose` `createRemoteJWKSet`). Use tsup for dual ESM+CJS
per-entry builds, and model the publish CI directly on `.github/workflows/sdk-ci-rust.yml`
(dry-run-on-PR / tag-triggered-publish pattern), adding `id-token: write` + `--provenance` per
`release.yml`'s existing OIDC attestation pattern.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| REST auth flow (login/refresh/logout/MFA) | API / Backend (server, frozen) | Browser + Node SDK (client) | SDK is a pure client; server owns the actual auth logic (§1) |
| Cookie session + CSRF double-submit | Browser / Client | Node SDK (cookie jar) | Browser reads `document.cookie`; Node needs an explicit jar since there's no browser cookie store |
| Authz check (`can`/`checkAccess`/`batchCheck`) | API / Backend (REST+gRPC, frozen) | Browser (REST) / Node (gRPC) SDK | Same `AuthorizationEngine` server-side (FND-04/D-08 Phase 15); SDK only chooses transport |
| Local JWT verification (JWKS) | Node SDK only | — | Browsers cannot safely hold/verify raw tokens (D-06); Node persona proactively verifies via `jose` |
| AMQP event consumption + HMAC verify | Node SDK only | Message Broker (RabbitMQ, external) | Browser has no AMQP client story; Node SDK owns the full ack/nack loop (D-12) |
| Framework middleware (Express/Fastify) | Node SDK (SSR/backend-for-frontend tier) | — | Middleware runs server-side in the consumer's own Node process, using the SDK's local JWKS verifier (D-27) |
| Build/bundling (tree-shaking gate) | CDN / Static (browser bundler tooling) | — | SC#1 is enforced by the **consumer's** bundler (Vite/esbuild), which the SDK's `sideEffects:false` + explicit subpaths must satisfy |
| Publish/provenance | CI/CD (GitHub Actions) | — | Tag-triggered `npm publish --provenance`; no runtime tier |

## Package Legitimacy Audit

All ten pinned/推奨 packages are long-established, widely-used projects whose GitHub repo URLs
match their canonical maintainers. The `package-legitimacy check` seam flagged every one of them
`SUS` in this environment purely because the registry lookup returned `weeklyDownloads: null`
(a registry-API limitation here, not a signal about the package) and because `publishedAt`
reflects the **latest version's** publish timestamp, not the package's true age — these are all
multi-year-old, top-tier npm packages. `msw` was additionally flagged `SLOP` for a
`postinstall` script; inspection shows it only conditionally imports a local, in-package
`config/scripts/postinstall.js` (this is `msw`'s own published `mockServiceWorker.js`
registration step, a well-known and documented part of the library, not a network/filesystem
escape) — this is a false positive from the heuristic, not a genuine risk signal.

| Package | Registry | Repo | Verdict (seam) | Human assessment | Disposition |
|---------|----------|------|------------------|-------------------|-------------|
| `axios` | npm | github.com/axios/axios | SUS (too-new/unknown-downloads) | Long-established (est. 2014), ~50M+ wk downloads historically; false positive | Approved |
| `@grpc/grpc-js` | npm | github.com/grpc/grpc-node | SUS (unknown-downloads) | Official gRPC-for-Node project, maintained by Google/CNCF community | Approved |
| `amqplib` | npm | github.com/amqp-node/amqplib | SUS (unknown-downloads) | Canonical Node AMQP 0-9-1 client, ~1.5M+ wk downloads historically | Approved |
| `jose` | npm | github.com/panva/jose | SUS (unknown-downloads) | Panva's `jose` is the de facto standard JOSE/JWT library for Node/browser, zero-dependency | Approved |
| `ts-proto` | npm | github.com/stephenh/ts-proto | SUS (too-new/unknown-downloads) | Already pinned in `sdks/buf.gen.yaml` (orchestrator-confirmed 2026-06-30) | Approved (pre-confirmed) |
| `tsup` | npm | github.com/egoist/tsup | SUS (unknown-downloads) | Standard esbuild-based TS bundler, widely used for library packaging | Approved |
| `vitest` | npm | github.com/vitest-dev/vitest | SUS (too-new/unknown-downloads) | Vite-native test runner; already the frontend's test stack (D-22 continuity) | Approved |
| `msw` | npm | github.com/mswjs/msw | **SLOP** (postinstall flagged) | `postinstall` is msw's own documented `mockServiceWorker.js` init script — false positive | Approved (see note above); planner may still add a `checkpoint:human-verify` before first install out of caution |
| `tough-cookie` | npm | github.com/salesforce/tough-cookie | SUS (unknown-downloads) | Salesforce-maintained, the standard Node cookie-jar implementation (used by `request`, `needle`, etc. historically) | Approved |
| `axios-cookiejar-support` | npm | github.com/3846masa/axios-cookiejar-support | SUS (unknown-downloads) | Standard axios+tough-cookie glue package, actively maintained, small/auditable surface | Approved |
| `express` | npm | github.com/expressjs/express | SUS (unknown-downloads) | The Node web framework; no legitimacy question | Approved |
| `fastify` | npm | github.com/fastify/fastify | SUS (too-new/unknown-downloads) | Widely-used, actively maintained Node web framework | Approved |

**Packages removed due to `[SLOP]` verdict:** none (msw's SLOP flag is a documented false
positive on its own published postinstall step — kept, see note above).
**Packages flagged as suspicious `[SUS]`:** all ten above, uniformly due to a registry
`weeklyDownloads: null` limitation in this environment rather than a package-specific signal. No
`checkpoint:human-verify` gate is required beyond the standard install step, except optionally for
`msw` given its SLOP flag (planner's discretion — low risk given the concrete explanation above).

**Version verification (via `npm view <pkg> version`, run this session):**

| Package | Verified latest | TS-01 pinned major | Compatible? |
|---------|-----------------|---------------------|-------------|
| axios | 1.18.1 | 1.7 | Yes — install with `^1.7` range or take latest 1.x; both satisfy "axios 1.7" pin intent (same major, CSRF/interceptor API stable across 1.x) |
| @grpc/grpc-js | 1.14.4 | 1.14 | Yes — exact match |
| amqplib | 2.0.1 | (unpinned major in TS-01) | amqplib crossed 1.x→2.x; verify no breaking API changes relevant to `consume`/`ack`/`nack` before pinning `^2.0`, or pin `^1.10` (last 1.x) for max compatibility with existing examples online — **recommend planner pin `^2.0` and smoke-test against a real broker in CI (D-24 testcontainers), since 2.x is now current on the registry** |
| jose | 6.2.3 | (unpinned major in TS-01) | jose 6.x is current, ESM-only (breaking change from 4.x) — SDK ships ESM+CJS via tsup, so verify jose works from the CJS build (jose 5+ dropped CJS entry; **CRITICAL: tsup CJS output cannot `require('jose')` directly — must use dynamic `import()` or restrict jose usage to the ESM build path**) |
| ts-proto | 2.11.10 | 2.x | Yes |
| tsup | 8.5.1 | (Claude's discretion) | Current major, actively maintained |
| vitest | 4.1.9 | (Claude's discretion) | Current major |
| msw | 2.14.6 | (Claude's discretion) | Current major, 2.x has native Node `fetch`/`http` interception |
| tough-cookie | 6.0.1 | (Claude's discretion) | Current major |
| axios-cookiejar-support | 7.0.0 | (Claude's discretion) | Current major |
| express | 5.2.1 | (Claude's discretion, middleware) | Express 5 changed error-handling/async-route semantics vs 4.x — write middleware examples against Express 5's actual API, not 4.x muscle memory |
| fastify | 5.9.0 | (Claude's discretion, middleware) | Current major |

**`jose` + CJS interop is a real risk** (see table above) — flag for the planner as a build-config
decision, not just a version pin: **[ASSUMED — recommend the CJS build either re-exports an async
JWKS-init function, or the SDK documents Node persona as ESM-first with CJS best-effort via dynamic
import.]**

## Installation

```bash
cd sdks/typescript
npm install axios@^1.7 @grpc/grpc-js@^1.14 amqplib@^2.0 jose@^6 tough-cookie@^6 axios-cookiejar-support@^7
npm install -D tsup@^8 vitest@^4 msw@^2 ts-proto@^2 typescript@~5.9 @types/amqplib @types/express express@^5 fastify@^5
```

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| TS-01 | TypeScript SDK — browser (REST) + Node (REST+gRPC+AMQP), separate `/rest` `/grpc` `/amqp` entries, tree-shaking, CSRF, single-flight refresh, middleware, npm publish | Full section-by-section coverage below: Persona/Tree-Shaking, Browser Auth+CSRF, Node Auth+JWKS+gRPC, AMQP HMAC, Build/Packaging, Publish/Provenance CI, Testing, Middleware. Every CONTEXT.md D-XX/CF-XX cross-referenced to a concrete implementation pattern. |
</phase_requirements>

## Area 1 — Persona / Tree-Shaking (D-01..D-04, D-25, SC#1)

**CONFIRMED.** The existing scaffold's `package.json` exports map already matches D-01/D-03
exactly:

```json
"exports": {
  ".": "./dist/index.js",
  "./rest": "./dist/rest/index.js",
  "./grpc": "./dist/grpc/index.js",
  "./amqp": "./dist/amqp/index.js"
}
```
`[VERIFIED: sdks/typescript/package.json:8-13]`

The planner's job is to (a) fix this to a proper dual-condition map for tsup's `import`/`require`/
`types` outputs (currently only points at a single `.js` per entry, no CJS/types conditions —
scaffold is pre-D-19), and (b) ensure `core.ts` has zero imports of `@grpc/grpc-js` or `amqplib`
(D-04's dependency-free core).

**tsup exports map pattern (per-entry dual ESM+CJS + types), composing D-03/D-19:**
```jsonc
// package.json
{
  "type": "module",
  "sideEffects": false,
  "exports": {
    ".":       { "import": { "types": "./dist/index.d.mts",  "default": "./dist/index.mjs"  }, "require": { "types": "./dist/index.d.ts",  "default": "./dist/index.js"  } },
    "./rest":  { "import": { "types": "./dist/rest/index.d.mts", "default": "./dist/rest/index.mjs" }, "require": { "types": "./dist/rest/index.d.ts", "default": "./dist/rest/index.js" } },
    "./grpc":  { "import": { "types": "./dist/grpc/index.d.mts", "default": "./dist/grpc/index.mjs" }, "require": { "types": "./dist/grpc/index.d.ts", "default": "./dist/grpc/index.js" } },
    "./amqp":  { "import": { "types": "./dist/amqp/index.d.mts", "default": "./dist/amqp/index.mjs" }, "require": { "types": "./dist/amqp/index.d.ts", "default": "./dist/amqp/index.js" } }
  }
}
```
`[ASSUMED — standard tsup dual-format export map shape, not yet run against this exact repo; planner should verify with a local `tsup --dts` build before committing to `.mts`/`.d.mts` extension choices]`

**tsup config (multi-entry, D-19):**
```typescript
// tsup.config.ts
import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    'index': 'src/index.ts',       // root = same as /rest per D-01
    'rest/index': 'src/rest/index.ts',
    'grpc/index': 'src/grpc/index.ts',
    'amqp/index': 'src/amqp/index.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,   // avoid shared chunks that could pull grpc/amqp code into the rest bundle
  treeshake: true,
});
```
`[ASSUMED — standard tsup multi-entry config; `splitting: false` is the load-bearing setting that prevents tsup's own internal chunk-splitting from defeating SC#1 by hoisting shared code across entries into a common chunk that the rest bundle would then import]`

**SC#1 bundle-and-grep CI mechanics** (D-02, the critical verification gate):
```yaml
# In .github/workflows/sdk-ci-typescript.yml, a new job after build+test
- name: Bundle-and-grep tree-shaking gate (SC#1)
  working-directory: sdks/typescript
  run: |
    cat > /tmp/fixture.mjs <<'EOF'
    import { AxiamClient } from '../dist/rest/index.mjs';
    console.log(AxiamClient);
    EOF
    npx esbuild /tmp/fixture.mjs --bundle --platform=browser --outfile=/tmp/bundle.js --format=esm
    if grep -qE "@grpc/grpc-js|amqplib" /tmp/bundle.js; then
      echo "FAIL: /rest bundle contains @grpc/grpc-js or amqplib"
      exit 1
    fi
    echo "OK: /rest bundle is Node-transport-free"
```
`--platform=browser` is important: it forces esbuild to resolve any accidental Node built-in
(`net`, `tls`, `dns` — pulled in transitively by `@grpc/grpc-js`/`amqplib`) as an error rather than
polyfilling it, which would otherwise mask a leak. `[ASSUMED — pattern derived from standard
esbuild CLI usage; should be validated once `/rest` entry compiles in this repo]`

**D-25 (import-path-only persona selection, no runtime sniffing):** confirmed straightforward —
`core.ts` must never reference `typeof window` or `process.versions` to branch behavior. Grep gate
recommendation for CI: `grep -rn "typeof window\|process\.versions" src/core/` should return empty.

## Area 2 — Browser Persona: Auth + CSRF + Single-Flight (D-05..D-08)

**CONFIRMED** — direct 1:1 port of `frontend/src/lib/api.ts` (already read in full). Key
mechanics to preserve exactly:

- `axios.create({ withCredentials: true })` — cookies flow automatically; no manual `Cookie`
  header. `[VERIFIED: frontend/src/lib/api.ts:10-16]`
- CSRF cookie name is **`axiam_csrf`**, read via a **hardcoded, non-dynamic regex**
  (`/(?:^|;\s*)axiam_csrf=([^;]*)/`) — this hardcoding is deliberate (ReDoS/CWE-1333 avoidance
  per the code comment) and the SDK's generalized version (configurable cookie name is NOT
  needed — the cookie name is a protocol constant, not configurable) should keep the same
  hardcoded-regex pattern, not build a dynamic one. `[VERIFIED: frontend/src/lib/api.ts:18-25]`
- CSRF forwarded only on `post|put|patch|delete` (case-insensitive method check).
  `[VERIFIED: frontend/src/lib/api.ts:28-43]`
- Single-flight refresh: module-level `isRefreshing` boolean + `failedQueue` array of
  `{resolve,reject}`, with `_retry` flag set on the original request config **before** the
  refresh call (comment cites `CQ-F32` — a real prior bug where setting `_retry` after the queue
  check let a second 401 on the replay trigger a second refresh cycle). D-07 asks for a
  "shared-Promise guard" instead of the frontend's boolean+queue — this is **functionally
  equivalent but strictly simpler**; recommend the shared-Promise form per D-07's explicit choice:
  ```typescript
  // core/singleFlightRefresh.ts
  let refreshPromise: Promise<void> | null = null;

  export function refreshOnce(doRefresh: () => Promise<void>): Promise<void> {
    if (!refreshPromise) {
      refreshPromise = doRefresh().finally(() => { refreshPromise = null; });
    }
    return refreshPromise;
  }
  ```
  This directly satisfies SC#3 (5 concurrent 401s → exactly 1 `doRefresh()` call, all await the
  same promise). `[ASSUMED — straightforward Promise-memoization pattern; not yet implemented in
  this repo, but structurally simpler than and equivalent to the frontend's proven boolean+queue]`
- `SKIP_REFRESH` list — never attempt refresh on `/api/v1/auth/{refresh,login,logout}`.
  `[VERIFIED: frontend/src/lib/api.ts:64-68]`
- Set `_retry` before the queue-check/refresh call (CQ-F32 fix), not after.
  `[VERIFIED: frontend/src/lib/api.ts:92-94]`

**D-05 §3 contradiction is real and confirmed server-side:** the CSRF middleware validates
`X-CSRF-Token` header against the `axiam_csrf` **cookie** value directly — there is no
"read CSRF from response header" mechanism on the wire at all for the double-submit check itself.
`[VERIFIED: crates/axiam-api-rest/src/middleware/csrf.rs:143-156]`. D-28's contract-update
direction (make cookie-double-submit canonical for browser, response-header-capture canonical for
non-browser SDKs) is consistent with this — non-browser SDKs (Rust) do NOT read the `axiam_csrf`
cookie at all in the current Rust implementation; they capture it from the jar too (see Area 3),
which is actually the **same mechanism**, just via a jar read instead of `document.cookie`. The
distinction CONTEXT.md draws (cookie-read for browser vs. header-capture for others) does not
perfectly match what Rust actually does (`capture_csrf_from_jar` — also a cookie read, not a
response-header capture: `[VERIFIED: sdks/rust/src/client.rs:306-316]`). **Flag for the planner's
scoped CONTRACT.md §3 doc task:** the accurate description across all SDKs is "read the
`axiam_csrf` cookie" (browser: `document.cookie`; Node: jar), not "capture from response header"
for non-browser — recommend the doc-fix task state this precisely rather than perpetuating a
header-capture description that doesn't match the Rust reference implementation.

**D-08 (no built-in authz cache):** trivial — `can()`/`checkAccess()`/`batchCheck()` are plain
stateless async functions with no memoization layer.

## Area 3 — Node Persona: Auth + JWKS + gRPC (D-09..D-11, D-13)

### D-09: Cookie names — RESOLVED (was CONTEXT.md's top open item)

**CONFIRMED with exact names**, directly from the server's CSRF/cookie middleware:

| Cookie | Purpose | HttpOnly | Path | Source |
|--------|---------|----------|------|--------|
| `axiam_access` | Access token (JWT) | Yes | `/` | `[VERIFIED: crates/axiam-api-rest/src/middleware/csrf.rs:28,187-203]` |
| `axiam_refresh` | Refresh token (opaque) | Yes | `/api/v1/auth/refresh` | `[VERIFIED: crates/axiam-api-rest/src/middleware/csrf.rs:29,205-218]` |
| `axiam_csrf` | CSRF double-submit token | **No** (JS-readable) | `/` | `[VERIFIED: crates/axiam-api-rest/src/middleware/csrf.rs:30,220-236]` |

**Login/refresh response bodies do NOT return tokens in JSON** — confirmed by both the server
handler's doc comments and the Rust SDK's wire types:
- `LoginSuccessResponse { user, session_id, expires_in }` — no `access_token` field.
  `[VERIFIED: crates/axiam-api-rest/src/handlers/auth.rs:72-80]`
- `RefreshSuccessResponse { expires_in }` — no `access_token` field.
  `[VERIFIED: crates/axiam-api-rest/src/handlers/auth.rs:89-95]`
- The Rust SDK's `LoginResult` doc comment states explicitly: "**No `access_token` field exists
  here or anywhere else in this SDK's public API** — AXIAM delivers tokens exclusively via
  `Set-Cookie`." `[VERIFIED: sdks/rust/src/rest/auth.rs:1-7,95-104]`

**This means D-09's "jar-read preferred" path is the ONLY path — there is no JSON-body fallback
to design for.** The TS Node SDK must extract the access/refresh token by reading the
`tough-cookie` jar by cookie name (`axiam_access`, `axiam_refresh`), exactly mirroring
`sdks/rust/src/token/manager.rs::extract_access_token_from_jar` /
`extract_refresh_token_from_jar`. **UNRESOLVED item from CONTEXT.md is now fully CONFIRMED, not
just "planner should assume X" — this is verified against live server code, not an assumption.**

**tough-cookie jar-read pattern for TS:**
```typescript
import { CookieJar } from 'tough-cookie';

async function extractCookieValue(jar: CookieJar, url: string, name: string): Promise<string | undefined> {
  const cookies = await jar.getCookies(url);
  return cookies.find(c => c.key === name)?.value;
}
// Usage: extractCookieValue(jar, baseUrl, 'axiam_access')
```
`[ASSUMED — tough-cookie's async `getCookies(url)` API is standard/documented; not yet run in
this repo, but structurally direct]`

**Setup with axios:**
```typescript
import axios from 'axios';
import { wrapper } from 'axios-cookiejar-support';
import { CookieJar } from 'tough-cookie';

const jar = new CookieJar();
const http = wrapper(axios.create({ jar, withCredentials: true }));
```
`[ASSUMED — axios-cookiejar-support's documented `wrapper()` pattern; version 7.0.0 confirmed
current on npm this session]`

### D-11: JWKS endpoint + algorithm — RESOLVED

**CONFIRMED exact path: `/oauth2/jwks`** (NOT the generic OIDC-discovery-style path some IdPs use).
`[VERIFIED: sdks/rust/src/token/jwks.rs:9-11,27-30]` and cross-confirmed server-side:
`jwks_uri: format!("{issuer}/oauth2/jwks")` `[VERIFIED: crates/axiam-oauth2/src/oidc.rs:39]`.

**Algorithm: EdDSA (Ed25519) exclusively** — the Rust SDK rejects any non-EdDSA `alg` header
before even attempting signature verification. `[VERIFIED: sdks/rust/src/token/jwks.rs:121-125]`
and `crates/axiam-oauth2/src/oidc.rs:182` confirms the server's JWKS document declares
`alg: "EdDSA"`.

**This endpoint is organization-wide, NOT tenant-scoped**, and serves exactly one Ed25519 key in
the common case (Rust's `find_jwk` falls back to the sole key when `kid` is absent and there's
exactly one key in the set — but does NOT fall back when multiple keys exist).
`[VERIFIED: sdks/rust/src/token/jwks.rs:249-265]`

**`jose` API recommendation for D-11 (Claude's-discretion item, now resolved):**

Use `jose`'s `createRemoteJWKSet`, which handles fetch + cache + refetch-on-unknown-kid natively —
this is genuinely simpler than the Rust SDK's hand-rolled cache (Rust hand-rolls because
`jsonwebtoken` has no remote-fetch helper; `jose` does, natively):

```typescript
import { createRemoteJWKSet, jwtVerify } from 'jose';

const JWKS = createRemoteJWKSet(new URL(`${baseUrl}/oauth2/jwks`), {
  cooldownDuration: 60_000,   // matches Rust's FORCED_REFETCH_MIN_INTERVAL=60s rate-limit on unknown-kid refetch
  timeoutDuration: 5_000,     // jose default; explicit for clarity
});

async function verifyAccessToken(token: string) {
  const { payload } = await jwtVerify(token, JWKS, { algorithms: ['EdDSA'] });
  return payload; // { sub, tenant_id, org_id?, iss, iat?, exp, jti?, aud?, scope? }
}
```
`[CITED: jose GitHub docs/jwks/remote/functions/createRemoteJWKSet.md — cooldownDuration (default
30000ms) rate-limits refetch-on-unknown-kid, exactly analogous to Rust's
FORCED_REFETCH_MIN_INTERVAL; timeoutDuration (default 5000ms) bounds the HTTP fetch itself]`

Note `createRemoteJWKSet` has no direct "normal TTL cache" knob separate from cooldown — it
refetches lazily only when a `kid` isn't found in the cached set, which is actually a cleaner model
than Rust's explicit `JWKS_CACHE_TTL` (300s) + separate forced-refetch cooldown (60s): jose's
single `cooldownDuration` covers the same "don't hammer the endpoint" concern. **Recommend NOT
porting Rust's two-timer design — use jose's single-cooldown model as-is; it is the idiomatic API
for this library and functionally satisfies D-11's "cached, refetch on unknown kid" requirement.**

**`algorithms: ['EdDSA']` must be passed explicitly to `jwtVerify`** — do not rely on the JWKS
document's own `alg` field alone; matching the Rust SDK's explicit rejection of non-EdDSA headers
(defense in depth against algorithm-confusion attacks).

**Claims shape to mirror** (from Rust's `Claims` struct, itself confirmed against
`crates/axiam-auth/src/token.rs::AccessTokenClaims`):
```typescript
interface AxiamClaims {
  sub: string;          // user ID (UUID)
  tenant_id: string;    // UUID
  org_id?: string;      // UUID
  iss: string;
  iat?: number;
  exp: number;
  jti?: string;         // session id — needed for logout()
  aud?: string;         // "axiam:user" | "axiam:m2m"
  scope?: string;       // space-separated OAuth2 scopes
}
```
`[VERIFIED: sdks/rust/src/token/jwks.rs:42-70]`

### D-10/D-13: gRPC auth interceptor + shared session

**`@grpc/grpc-js` interceptor shape** (structurally different from tonic — this is genuinely
TS-specific, not a Rust port):

```typescript
import type { Interceptor, InterceptingCall } from '@grpc/grpc-js';
import * as grpc from '@grpc/grpc-js';

function authInterceptor(session: SharedSession): Interceptor {
  return (options, nextCall) => {
    return new grpc.InterceptingCall(nextCall(options), {
      start(metadata, listener, next) {
        const token = session.tokenManager.cachedAccessToken();
        if (token) metadata.add('authorization', `Bearer ${token.expose()}`);
        metadata.add('x-tenant-id', session.tenantHeaderValue());
        next(metadata, listener);
      },
    });
  };
}

const client = new AuthorizationServiceClient(address, credentials, {
  interceptors: [authInterceptor(session)],
});
```
`[CITED: grpc/proposal L5-node-client-interceptors.md — requester object with start/sendMessage/
halfClose/cancel; `metadata.add()` in `start` is the documented way to inject outbound metadata]`

**Handling `UNAUTHENTICATED` (status code 16) to trigger single-flight refresh:** grpc-js
interceptors intercept the *outbound* call; catching the *response* status to trigger a retry
requires wrapping the call at a higher level (a thin wrapper function around each generated client
method) rather than inside the interceptor's `listener`, because the interceptor chain's
`start`/`sendMessage` hooks fire before the response is known. **Recommended pattern:** wrap each
generated client stub method in a helper that calls it, catches a `grpc.ServiceError` with
`code === grpc.status.UNAUTHENTICATED`, awaits the shared `refreshOnce()` guard (Area 2), and
retries exactly once:

```typescript
async function callWithRefresh<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof Error && 'code' in err && (err as grpc.ServiceError).code === grpc.status.UNAUTHENTICATED) {
      await refreshOnce(doRefresh);
      return await fn(); // retry once; no further retry on second failure (§9.3)
    }
    throw err;
  }
}
```
`[ASSUMED — this wrapper pattern is the standard way to implement "retry-after-refresh" semantics
with grpc-js since the interceptor API itself does not expose a synchronous response-status hook
suitable for awaiting an async refresh; not yet implemented in this repo]`

**Channel reuse (D-10 "one long-lived channel"):** construct the gRPC client once per
`AxiamClient` instance and cache it (analogous to Rust's lazy `tonic::Channel`); do not construct
a new client per call.

**D-13 (one shared session object):** the `SharedSession` referenced above should hold: cookie
jar, `TokenManager` (cached-token + tenant_id, mirroring `sdks/rust/src/token/manager.rs`), the
single-flight `refreshOnce` guard, and CSRF token — exactly the same fields as Rust's
`AxiamClientInner`. `[VERIFIED pattern-analog: sdks/rust/src/client.rs:217-237]`

## Area 4 — AMQP HMAC (D-12, §8)

**CONFIRMED byte-for-byte reproducible in Node.** The server's protocol
(`crates/axiam-amqp/src/messages.rs:35-50`, already read in full) is:
1. Strip/null the `hmac_signature` field from the message body.
2. Serialize the remaining body to JSON (Rust: `serde_json::to_vec`, which serializes struct
   fields in **declaration order**, not alphabetized).
3. `HMAC-SHA256(key, json_bytes)`, hex-encoded.
4. Constant-time compare.

**Verified this session that Node's `JSON.stringify` on a `JSON.parse`'d-then-mutated object
preserves the original key insertion order** (tested live: parsing a JSON object with keys
`correlation_id, tenant_id, subject_id, action, resource_id, hmac_signature`, deleting
`hmac_signature`, and re-stringifying reproduces the exact original field order minus the deleted
key) — this matches Rust's declaration-order serialization exactly, so **the canonical-JSON
byte sequence is naturally identical between the two languages for the same source payload,
with no field-sorting step needed on either side.** `[VERIFIED: live node -e test this session]`

**Node implementation using the built-in `crypto` module** (no need for a third-party HMAC lib —
Node's `crypto.createHmac` is the direct equivalent of Rust's `hmac`/`sha2` crates):

```typescript
import { createHmac, timingSafeEqual } from 'node:crypto';

export function signPayload(key: Buffer, payloadJson: Buffer): string {
  return createHmac('sha256', key).update(payloadJson).digest('hex');
}

export function verifyPayload(key: Buffer, payloadJson: Buffer, signatureHex: string): boolean {
  const expected = createHmac('sha256', key).update(payloadJson).digest();
  let received: Buffer;
  try {
    received = Buffer.from(signatureHex, 'hex');
  } catch {
    return false;
  }
  if (received.length !== expected.length) return false; // timingSafeEqual requires equal length
  return timingSafeEqual(received, expected);
}
```
`[VERIFIED protocol match: crates/axiam-amqp/src/messages.rs:35-50; timingSafeEqual is Node's
documented constant-time buffer comparison, the direct analog of the hmac crate's `verify_slice`]`

**Consumer verify-before-handler loop** (D-12, direct analog of Rust's `verify_and_dispatch` /
`consume`, already read in full at `sdks/rust/src/amqp/consumer.rs`):

```typescript
import amqp from 'amqplib';

export async function consume(
  amqpUrl: string,
  queue: string,
  signingKey: Sensitive<Buffer>,
  handler: (event: unknown) => Promise<void>,
): Promise<void> {
  const connection = await amqp.connect(amqpUrl);
  const channel = await connection.createChannel();
  await channel.assertQueue(queue, { durable: true });

  channel.consume(queue, async (msg) => {
    if (!msg) return;
    let body: Record<string, unknown>;
    try {
      body = JSON.parse(msg.content.toString('utf8'));
    } catch {
      channel.nack(msg, false, false); // requeue=false
      return;
    }

    const sig = typeof body.hmac_signature === 'string' ? body.hmac_signature : undefined;
    delete body.hmac_signature;
    const canonical = Buffer.from(JSON.stringify(body), 'utf8');

    const verified = sig !== undefined && verifyPayload(signingKey.expose(), canonical, sig);
    if (!verified) {
      // Security event: never logs the sig value itself (§8.4)
      logger?.warn('axiam_sdk.security', 'AMQP HMAC verification failed; nacking without requeue');
      channel.nack(msg, false, false);
      return;
    }

    await handler(body);
    channel.ack(msg);
  });
}
```
`[ASSUMED code shape, VERIFIED protocol — amqplib's `channel.consume`/`ack`/`nack(msg, allUpTo,
requeue)` signature is standard/documented; the verify-then-dispatch control flow is a direct
port of the already-tested Rust `verify_and_dispatch` at sdks/rust/src/amqp/consumer.rs:74-139]`

**Signing key retrieval (D-12's "MUST be obtained from the AXIAM management API"):** confirmed no
hardcoding is acceptable — Rust's doc comment states this explicitly (`sdks/rust/src/amqp/consumer.rs:147-150`).
**UNRESOLVED (genuine gap, not just this phase's):** neither this session's grep nor the Rust SDK
source shows a concrete REST/gRPC endpoint that returns the per-tenant AMQP signing secret — no
`amqp_signing_secret` or equivalent field was found anywhere in `crates/`. **Planner should
assume X:** the signing key is supplied to `consume()` as an explicit parameter the SDK consumer
obtains out-of-band (e.g., from a tenant settings/admin API call not yet built, or a
pre-provisioned config value) — the same assumption the Rust SDK already made (its `consume()`
signature takes `signing_key: Sensitive<Vec<u8>>` as a caller-supplied parameter, not something the
SDK itself fetches). **Mirror this exactly: `consume(amqpUrl, queue, signingKey, handler)` with
`signingKey` a required, explicit argument — do not attempt to add a "fetch it from the server"
code path that doesn't exist yet.**

**Message types requiring verification:** `AuthzRequest` (`axiam.authz.request`) and
`AuditEventMessage` (`axiam.audit.events`) carry `hmac_signature`;
`AuthzResponse`/`NotificationEvent` do not (server-published, no signature in v1.0).
`[VERIFIED: sdks/CONTRACT.md §8 "Message Types Subject to HMAC Verification" table, cross-checked
against crates/axiam-amqp/src/messages.rs:57-118 field presence]`

## Area 5 — Error Model (D-16, D-17)

Straightforward TypeScript class hierarchy per §2:

```typescript
export abstract class AxiamError extends Error {}

export class AuthError extends AxiamError {
  constructor(message: string) { super(message); this.name = 'AuthError'; }
}

export class AuthzError extends AxiamError {
  constructor(message: string, public readonly action?: string, public readonly resourceId?: string) {
    super(message); this.name = 'AuthzError';
  }
}

export class NetworkError extends AxiamError {
  constructor(message: string, public readonly cause?: unknown) {
    super(message); this.name = 'NetworkError';
  }
}
```

**Status mapping table (D-17, single source of truth in `core`):** transcribe §2's HTTP and gRPC
tables directly into one mapper module (`core/errorMapper.ts`) that both `rest/` and `grpc/` call —
this is the exact analog of the Rust SDK's `AxiamError::from_http_status`.
`[VERIFIED: sdks/CONTRACT.md §2 tables; sdks/rust/src/rest/auth.rs:439-445 shows the Rust call
site pattern to mirror]`

## Area 6 — Sensitive<T> (D-26)

TypeScript needs three redaction surfaces per D-26 (`toString`, `toJSON`, `util.inspect.custom`) —
one more than Rust needs (`Debug`+`Display` only), because JS has three independent
stringification paths:

```typescript
import { inspect } from 'node:util';

const REDACTED = '[SENSITIVE]';

export class Sensitive<T> {
  #value: T;
  constructor(value: T) { this.#value = value; }

  /** @internal package-only accessor */
  expose(): T { return this.#value; }

  toString(): string { return REDACTED; }
  toJSON(): string { return REDACTED; }
  [inspect.custom](): string { return REDACTED; }
}
```
`[CITED: Node.js docs — util.inspect.custom is the documented symbol console.log/util.inspect
check for a custom representation; #value is a true private class field (ES2022), not just a
naming convention, so `expose()` is the only extraction path]`

**Browser persona never constructs a `Sensitive<T>`** (D-06 — no tokens ever enter browser JS at
all) — this class lives only in `core` but is only ever instantiated by Node-persona code paths
(`rest/auth.ts` Node variant, `grpc/interceptor.ts`, `amqp/consumer.ts`).

## Area 7 — Login/MFA Flow (D-18)

Discriminated union matching CONTRACT.md §1 and the Rust reference's two-phase design:

```typescript
export type LoginResult =
  | { status: 'mfa_required'; mfaToken: string; availableMethods: string[] }
  | { status: 'authenticated'; user: { id: string; username: string; email: string }; sessionId: string; expiresIn: number };
```

Wire shapes to mirror exactly (already confirmed above): `LoginSuccessResponse { user, session_id,
expires_in }` on 200, `MfaRequiredResponse { challenge_token, available_methods }` on 202 (or the
Rust wire-type equivalent — note the server's actual field is `challenge_token`, the TS `mfaToken`
in the public API is a camelCase rename per §1's naming convention, not a different field).
`[VERIFIED: crates/axiam-api-rest/src/handlers/auth.rs:75-87]`

## Area 8 — Build & Packaging (D-19, D-20)

**tsup dual ESM+CJS** — see Area 1 for the full config. Key additional points:

- **`typescript/src/gen` must stay gitignored** (Phase 15 D-01) — `buf generate` runs at build
  time via an npm `prebuild` script:
  ```json
  "scripts": {
    "generate": "buf generate ../ --template buf.gen.yaml",
    "prebuild": "npm run generate",
    "build": "tsup"
  }
  ```
  `[VERIFIED pattern: sdks/buf.gen.yaml:15-21 already targets `typescript/src/gen` with
  `outputServices=grpc-js`]`
- **Publish job regenerates-and-bundles** (D-20) — the CI publish job (see Area 9) must run
  `buf generate` before `tsup build` before `npm publish`, exactly mirroring the Rust publish
  job's "Regenerate gRPC stubs for the published artifact" step.
  `[VERIFIED pattern: .github/workflows/sdk-ci-rust.yml publish job, "Regenerate gRPC stubs..."
  step]`
- **`sideEffects: false`** in `package.json` is required for consumer bundlers to tree-shake
  unused exports even within the `/rest` entry itself (not just across entries) — add this
  alongside the exports map.

## Area 9 — Publish / Provenance CI (D-21)

**Model directly on `.github/workflows/sdk-ci-rust.yml`'s dry-run-on-PR / tag-triggered-publish
structure**, adding npm-specific provenance per the repo's already-established OIDC attestation
pattern in `release.yml` (`id-token: write` permission + `actions/attest-build-provenance`).
`[VERIFIED: .github/workflows/release.yml:11,25,104-105,116,195-196 — id-token: write and
attest-build-provenance are already an established repo pattern, just for Docker images; npm
provenance is the same OIDC mechanism applied to `npm publish`]`

```yaml
name: SDK CI — TypeScript

on:
  pull_request:
    branches: [main]
    paths:
      - 'sdks/typescript/**'
      - 'sdks/openapi.json'
      - 'sdks/buf.yaml'
      - 'sdks/buf.gen.yaml'
  push:
    tags:
      - 'sdks/typescript/v*'

permissions:
  contents: read

jobs:
  test:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
      - uses: actions/setup-node@<pinned-sha>
        with: { node-version: '22', registry-url: 'https://registry.npmjs.org' }
      - run: npm ci
        working-directory: sdks/typescript
      - run: npm run generate  # buf generate
        working-directory: sdks/typescript
      - run: npm run build
        working-directory: sdks/typescript
      - run: npm test
        working-directory: sdks/typescript
      - name: Bundle-and-grep tree-shaking gate (SC#1)
        working-directory: sdks/typescript
        run: |
          # ... (see Area 1 snippet)
      - name: Dry-run publish gate (SC#5)
        working-directory: sdks/typescript
        run: npm publish --dry-run

  publish:
    if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/sdks/typescript/v')
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write   # required for npm provenance (OIDC)
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
      - uses: actions/setup-node@<pinned-sha>
        with: { node-version: '22', registry-url: 'https://registry.npmjs.org' }
      - run: npm ci
        working-directory: sdks/typescript
      - run: npm run generate && npm run build  # regenerate-and-bundle (D-20)
        working-directory: sdks/typescript
      - name: Publish to npm with provenance
        working-directory: sdks/typescript
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: npm publish --access public --provenance
```
`[ASSUMED — npm provenance's documented requirement is `id-token: write` permission + `npm publish
--provenance` on npm CLI >=9.5.0/Node >=18.x running in GitHub Actions specifically (npm detects
the `ACTIONS_ID_TOKEN_REQUEST_URL` env var automatically); this exact YAML has not been run in this
repo yet but the mechanism is npm's documented standard and directly parallels the repo's own
Docker-image OIDC attestation pattern already in release.yml]`

**Tag convention:** `sdks/typescript/vX.Y.Z` (Phase 15 D-13 monorepo tag scheme).
`[VERIFIED: .planning/phases/15-sdk-foundation/15-CONTEXT.md D-13, applied identically in the
Rust workflow's `push: tags: ['sdks/rust/v*']`]`

## Area 10 — Testing (D-22..D-24)

- **vitest** — config mirrors the frontend's existing `vite.config.ts` test block (same repo test
  stack, D-22 rationale).
- **msw for browser-persona REST mocking (D-23):** use `msw/node` (not `msw/browser`) since vitest
  runs in Node/jsdom, not an actual browser. The SC#3 concurrency test drives a controllable msw
  handler that returns 401 on the first N calls to a protected endpoint, then 200 on
  `/api/v1/auth/refresh`, asserting the refresh handler is invoked **exactly once** despite 5
  concurrent callers.
  ```typescript
  import { setupServer } from 'msw/node';
  import { http, HttpResponse } from 'msw';

  let refreshCallCount = 0;
  const server = setupServer(
    http.post('/api/v1/authz/check', () => HttpResponse.json({}, { status: 401 })),
    http.post('/api/v1/auth/refresh', () => {
      refreshCallCount++;
      return HttpResponse.json({ expires_in: 900 });
    }),
  );
  ```
  `[CITED: msw v2 documented API — `msw/node` setupServer + `http`/`HttpResponse` handler shape,
  replacing the v1 `rest` API]`
- **Node tests = mocked units + optional testcontainers smoke (D-24):** unit tests for single-flight,
  HMAC verify, error mapping run against hand-mocked transports (no real broker/gRPC server); a
  separate `@testcontainers/rabbitmq`-based (or manual docker-compose) smoke test is gated behind
  an env var / separate CI job so default `npm test` stays fast and deterministic — matching the
  Rust SDK's pattern of unit tests with no live-service dependency in the default test run.

## Area 11 — Middleware (D-27, §10)

Both Express and Fastify middleware share one verification core (the same `verifyAccessToken` +
`createRemoteJWKSet` instance from Area 3), differing only in the request/response API:

```typescript
// middleware/express.ts
import type { Request, Response, NextFunction } from 'express';

export function axiamMiddleware(session: SharedSession) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const token = req.cookies?.axiam_access ?? req.headers.authorization?.replace(/^Bearer\s+/i, '');
    if (!token) return res.status(401).json({ error: 'authentication_failed', message: 'missing credentials' });
    try {
      const claims = await verifyAccessToken(session, token);
      (req as Request & { axiamUser?: unknown }).axiamUser = {
        userId: claims.sub, tenantId: claims.tenant_id, scopes: claims.scope?.split(' ') ?? [],
      };
      next();
    } catch {
      res.status(401).json({ error: 'authentication_failed', message: 'invalid or expired token' });
    }
  };
}
```

```typescript
// middleware/fastify.ts
import type { FastifyPluginAsync } from 'fastify';

export const axiamPlugin: (session: SharedSession) => FastifyPluginAsync = (session) => async (fastify) => {
  fastify.addHook('preHandler', async (request, reply) => {
    const token = request.cookies?.axiam_access ?? request.headers.authorization?.replace(/^Bearer\s+/i, '');
    if (!token) return reply.code(401).send({ error: 'authentication_failed', message: 'missing credentials' });
    try {
      const claims = await verifyAccessToken(session, token);
      (request as typeof request & { axiamUser?: unknown }).axiamUser = {
        userId: claims.sub, tenantId: claims.tenant_id, scopes: claims.scope?.split(' ') ?? [],
      };
    } catch {
      return reply.code(401).send({ error: 'authentication_failed', message: 'invalid or expired token' });
    }
  });
};
```
`[ASSUMED code shape — Express requires `cookie-parser` middleware upstream for `req.cookies` to
exist (not currently a listed dependency; planner should add `cookie-parser` as a peerDependency
or document the requirement, OR parse the `Cookie` header manually to avoid adding a peer
dependency — recommend manual parsing to keep the middleware dependency-free, matching D-04's
dependency-minimalism spirit)]`

**Fastify note:** Fastify does not parse cookies by default either — same manual-parse-or-peerDep
consideration applies (`@fastify/cookie` is the idiomatic plugin, but adding it as a required
peerDependency conflicts with keeping the SDK's own dependency surface minimal). **Recommend:**
implement a small internal cookie-header parser (10 lines) shared by both middleware modules
rather than depending on `cookie-parser`/`@fastify/cookie`, falling back to the `Authorization`
header exactly as the Rust extractor does (`sdks/rust/src/middleware/actix.rs:129-149` — cookie
first, then `Authorization: Bearer` fallback).

**Injection key naming (D-27):** `req.axiamUser` (Express) / `request.axiamUser` (Fastify) — both
lowercase-camelCase, matching D-27's exact wording.

**No per-request server round-trip** — this is the entire point of D-11's local JWKS: the
middleware calls the same `verifyAccessToken` used elsewhere, which only round-trips to
`/oauth2/jwks` on cache-miss/kid-rotation, never on every request.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| JWKS fetch/cache/rotation | Custom fetch+TTL+refetch logic (Rust had to; TS doesn't) | `jose`'s `createRemoteJWKSet` | Handles cooldown, timeout, and kid-lookup natively; hand-rolling in TS re-introduces the exact complexity Rust was forced into only because its crate lacked this helper |
| HMAC-SHA256 constant-time compare | Manual byte-loop XOR comparison | Node's built-in `crypto.timingSafeEqual` | Built into Node core, no dependency needed, avoids subtle timing-side-channel bugs in a hand-rolled comparator |
| Cookie jar | Custom `Map<name,value>` cookie store | `tough-cookie` + `axios-cookiejar-support` | Handles domain/path/expiry/secure attribute matching correctly per RFC 6265; a naive map ignores path scoping (e.g. `axiam_refresh`'s `/api/v1/auth/refresh`-only path) |
| Single-flight promise dedup | Manual boolean+array queue (the frontend's own older pattern) | Shared-`Promise` memoization (D-07) | Fewer moving parts, same guarantee; the frontend's boolean+queue is proven but D-07 explicitly chose the simpler form for the SDK |
| Dual ESM+CJS packaging | Hand-written separate `tsc` invocations per format | `tsup` | tsup wraps esbuild with dual-format + `.d.ts` generation + tree-shaking config in one tool; hand-rolling risks import/require condition mismatches that silently break one consumer type |
| gRPC retry-on-auth-failure | Ad-hoc try/catch sprinkled at every call site | One `callWithRefresh` wrapper applied uniformly | Prevents the "some call sites retry, some don't" drift that caused real bugs elsewhere in this repo (see CQ-F32 in frontend/src/lib/api.ts's own comments) |

**Key insight:** every "don't hand-roll" item above already has a battle-tested precedent either
in this repo (frontend axios client, Rust SDK) or in a de facto standard library (`jose`, Node's
`crypto`) — there is no part of this phase that requires inventing a new algorithm or protocol.

## Common Pitfalls

### Pitfall 1: CJS build cannot statically `require('jose')`
**What goes wrong:** `jose` 5+ ships ESM-only; a tsup CJS output that does `import { jwtVerify } from 'jose'` transpiled to `require('jose')` will throw `ERR_REQUIRE_ESM` at runtime.
**Why it happens:** `jose`'s package.json has no `require` export condition beyond a very old legacy version.
**How to avoid:** Either (a) restrict `jose` usage to code paths only reachable from the ESM entry, using dynamic `await import('jose')` inside the CJS build so the import is deferred to runtime (Node's dynamic `import()` can load ESM from CJS), or (b) document the Node persona as ESM-first, CJS-best-effort.
**Warning signs:** `npm run build` succeeds but `require('axiam-sdk/grpc')` (or wherever JWKS verification is reached) throws at first call, not at import time.

### Pitfall 2: tsup code-splitting defeats SC#1
**What goes wrong:** tsup/esbuild's default chunk-splitting behavior for multi-entry builds can hoist code shared between `rest`, `grpc`, and `amqp` entries into a common chunk — if any gRPC/AMQP-referencing code ends up in that shared chunk, importing `/rest` alone pulls it in transitively.
**Why it happens:** esbuild's splitting optimizes for shared-dependency dedup, not persona isolation; it doesn't know these entries are meant to be mutually exclusive at the bundler level.
**How to avoid:** Set `splitting: false` in `tsup.config.ts` (see Area 1) so each entry is fully self-contained; verify with the SC#1 bundle-and-grep CI gate rather than trusting config alone.
**Warning signs:** The SC#1 CI gate (Area 9) fails even though `core.ts` itself has no grpc/amqp imports — check for an unexpected shared-chunk file in `dist/`.

### Pitfall 3: grpc-js interceptor cannot `await` inside `start()`
**What goes wrong:** The `start(metadata, listener, next)` callback in a grpc-js interceptor is synchronous — calling `await session.tokenManager.someAsyncMethod()` inside it either silently does nothing (fire-and-forget) or requires restructuring.
**Why it happens:** grpc-js's interceptor API predates widespread async/await idioms in the ecosystem; unlike tonic's async-native interceptor trait, grpc-js's `start` must call `next(metadata, listener)` synchronously.
**How to avoid:** Keep a synchronous, fast, in-memory "cached access token" read (exactly mirroring the Rust SDK's `TokenManager::cached_access_token()` non-blocking fast-path, `sdks/rust/src/token/manager.rs:74-83`) available to the interceptor; never attempt to trigger a refresh from inside `start()` itself — handle refresh-on-401/UNAUTHENTICATED at the call-wrapper level (Area 3's `callWithRefresh`), not the interceptor level.
**Warning signs:** Requests go out with a stale/expired token even though a refresh "should have" happened first; the interceptor's metadata injection silently uses `undefined`.

### Pitfall 4: amqplib's `nack(msg, allUpTo, requeue)` argument order
**What goes wrong:** amqplib's nack signature is `channel.nack(msg, allUpTo, requeue)` — a two-boolean-argument call is easy to transpose, silently producing the exact opposite of the intended nack-without-requeue security behavior (§8.3g).
**Why it happens:** unlike lapin's named-field `BasicNackOptions { requeue, .. }`, amqplib takes positional booleans with no compiler enforcement of which is which.
**How to avoid:** Always call with `false, false` explicitly commented (`channel.nack(msg, /* allUpTo */ false, /* requeue */ false)`), and add a unit test asserting the mock channel's nack call captured `requeue === false` on every verification-failure path (mirroring the Rust SDK's `RecordingDelivery` test fixture that asserts `nacked_requeue_false` vs `nacked_requeue_true` counts separately — `sdks/rust/src/amqp/consumer.rs:379-411`).
**Warning signs:** A HMAC-mismatch test that only asserts "handler not called" without also asserting the exact nack argument values would not catch this transposition.

### Pitfall 5: `JSON.stringify` re-serialization must not reorder keys via a schema/validation library
**What goes wrong:** If the AMQP message body is parsed into a typed/validated object via a library that reconstructs the object (e.g. certain schema validators normalize/sort keys), the re-serialized canonical JSON will NOT byte-match the server's HMAC input even though the values are identical.
**Why it happens:** HMAC verification is sensitive to exact byte sequence, not semantic JSON equality; any library that doesn't preserve original key order breaks verification silently (producing false HMAC mismatches, not false accepts — fails safe, but breaks functionality).
**How to avoid:** Use plain `JSON.parse` + `delete obj.hmac_signature` + `JSON.stringify` (as shown in Area 4) with no intermediate schema-validation re-object-construction step before signing/verifying; validate the parsed shape separately (e.g., with zod) only AFTER HMAC verification succeeds, never before or as part of it.
**Warning signs:** HMAC verification fails 100% of the time in integration testing against a real server-signed message, even though the signing key is definitely correct.

## Code Examples

Already inlined per-area above (Areas 1–11). Additional cross-cutting snippet:

### Client construction (D-14, mirrors CONTRACT.md §5/§6)
```typescript
// Source: pattern mirrors sdks/rust/src/client.rs builder shape, adapted to
// TS's options-object idiom per D-14.
export interface AxiamClientOptions {
  baseUrl: string;
  tenantSlug?: string;
  tenantId?: string;
  customCa?: string; // PEM
  connectTimeoutMs?: number;  // default 10_000 (mirrors Rust DEFAULT_CONNECT_TIMEOUT)
  requestTimeoutMs?: number;  // default 30_000 (mirrors Rust DEFAULT_REQUEST_TIMEOUT)
}

export class AxiamClient {
  constructor(options: AxiamClientOptions) {
    if (!options.tenantSlug && !options.tenantId) {
      throw new AuthError(
        'a tenant identifier (tenantSlug or tenantId) is required to construct an AxiamClient ' +
        '— AXIAM is multi-tenant and there is no default tenant (CONTRACT.md §5)'
      );
    }
    // ... construct axios instance, cookie jar, JWKS verifier
  }
}
```
`[VERIFIED numeric defaults: sdks/rust/src/client.rs:34-35 — DEFAULT_CONNECT_TIMEOUT=10s,
DEFAULT_REQUEST_TIMEOUT=30s; recommend the TS SDK adopt the identical 10s/30s defaults for
cross-language consistency (CF-03's "exact numeric values = research/planner" is resolved to these
concrete numbers)]`

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| `browser`-condition field in package.json for isomorphic packages | Explicit named subpaths (`/rest`, `/grpc`, `/amqp`) | Ongoing ecosystem shift (Node.js `exports` field maturity) | D-03 already chose the explicit-subpath approach over the fragile `browser` field — no action needed, just confirms the CONTEXT.md decision is current best practice |
| msw v1 `rest`/`graphql` handler API | msw v2 `http`/`graphql` with native `fetch` Request/Response | msw 2.0 (2023) | Test code in Area 10 uses the v2 API; do not follow older msw v1 tutorials/examples found via search |
| jose 4.x CJS+ESM dual package | jose 5+/6.x ESM-only | jose v5 (2023) | Directly causes Pitfall 1 above — must be designed around, not discovered late |

**Deprecated/outdated:** the `backoff` npm package (unmaintained) is the JS-ecosystem analog of the
Rust SDK's rejected `backoff` crate (`16-RESEARCH.md` already flagged this for Rust); if a
dedicated retry/backoff library is wanted for CF-01 rather than a small hand-rolled
exponential-backoff-with-jitter helper (CF-01's scope is narrow enough — 2-3 max attempts,
idempotent-only — that hand-rolling ~15 lines is likely simpler than adding a dependency; **Claude's
discretion, lean toward hand-rolled given the narrow scope**).

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | tsup export-map `.mts`/`.d.mts` extension convention will work cleanly with the repo's existing `tsconfig` / bundler expectations | Build & Packaging | Low — easily adjusted during first local build; does not affect behavioral correctness, only file extensions |
| A2 | `jose` CJS-from-dynamic-`import()` workaround is necessary (vs. jose silently working in the CJS build) | Common Pitfalls #1 | Medium — if wrong, extra defensive code is harmless; if the risk is real and unaddressed, Node persona's CJS consumers get a runtime crash on first JWKS verification |
| A3 | Fastify/Express should hand-roll a minimal cookie-header parser rather than take `cookie-parser`/`@fastify/cookie` as a dependency | Middleware | Low — either choice works; hand-rolling saves a dependency but adds ~10 lines of maintenance surface |
| A4 | AMQP signing key retrieval has no existing server endpoint and must be an explicit caller-supplied parameter, mirroring Rust's `consume()` signature | AMQP HMAC | Medium — if a management-API endpoint for this DOES exist and was missed in this grep pass, the SDK should call it instead of requiring the caller to source the key themselves; planner should re-grep `crates/axiam-api-rest` and `crates/axiam-api-grpc` handler lists for anything AMQP-secret-related before finalizing this as a hard external dependency |
| A5 | `callWithRefresh` wrapper-per-call-site is the correct grpc-js pattern (vs. some undiscovered interceptor-level async retry mechanism) | Node gRPC | Low — grpc-js's documented interceptor API is synchronous in `start()`; this is a structural fact of the library, not really assumable-away, but the exact wrapper shape shown is one of several equally-valid implementations |
| A6 | Recommend `^2.0` for amqplib despite TS-01 not pinning an exact major, given 2.x is now current | AMQP / versions | Low — amqplib's `consume`/`ack`/`nack` API has been stable across 1.x→2.x; a downgrade to `^1.10` if a breaking change surfaces is a one-line change |

**If this table is empty:** N/A — six assumptions logged above, all low-to-medium risk with clear
mitigation paths; none block planning.

## Open Questions (RESOLVED)

1. **Does an AMQP signing-secret retrieval endpoint exist anywhere in the server API?**
   - **RESOLVED — no server endpoint exists; the SDK mirrors the Rust design: the HMAC signing key
     is a caller-supplied Sensitive<Buffer> parameter (see 17-04). Flagged as a cross-cutting
     milestone-owner gap, NOT a TS-01 blocker.**
   - What we know: Neither this session's grep nor the Rust SDK's implementation reference one;
     the Rust SDK's `consume()` takes the key as a required caller-supplied parameter.
   - What's unclear: Whether this is a genuine, permanent gap (secret is provisioned out-of-band,
     e.g. via an admin UI/ops runbook not yet built) or an oversight in both this research pass and
     Phase 16's.
   - Recommendation: Mirror Rust's caller-supplied-parameter design (A4 above) for this phase;
     flag as a cross-cutting gap for the milestone owner rather than a TS-01-specific blocker,
     since the identical gap already exists (silently) in the shipped Rust SDK.

2. **Should `amqplib` be pinned to `^2.0` (current) or `^1.10` (last 1.x, closer to most public
   tutorial code)?**
   - **RESOLVED — pin amqplib ^2.0 (current major); validated via the D-24 optional testcontainers
     smoke test.**
   - What we know: 2.x is current on the registry; the core `consume`/`channel`/`ack`/`nack` API
     used in this phase's patterns has not had documented breaking changes relevant to these calls
     between 1.x and 2.x.
   - What's unclear: Whether 2.x introduced any TypeScript type-definition changes that affect the
     exact typings used in this phase's code (e.g. `Options.Consume`, `ConsumeMessage` shape).
   - Recommendation: Pin `^2.0`, and rely on D-24's testcontainers/smoke-test path to catch any
     real incompatibility against a live broker before the first release.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Node.js runtime | Build/test/CI | ✓ (assumed CI runner) | 22.x recommended (LTS at time of writing) | — |
| npm registry access | Package installs, `npm view` verification | ✓ (confirmed this session — all package versions resolved live) | — | — |
| `buf` CLI | Proto codegen (`npm run generate`) | Not verified this session (server-crate concern, out of TS-01 scope to install) | — | Phase 15's `sdks/buf.gen.yaml` already exists and is proven working for the Rust SDK's CI; TS SDK CI job installs `buf` the same way the Rust workflow presumably does (not shown in `sdk-ci-rust.yml` excerpt read this session — planner should verify the buf-install step exists in a shared/reusable workflow step) |
| A live AXIAM server (for D-24 optional smoke tests) | Integration/smoke tests only, not unit tests | N/A for this research pass (dev-time concern) | — | Unit tests run against mocked transports per D-24; smoke tests are optional/separate CI job |
| npm registry publish credentials (`NPM_TOKEN` secret) | Publish CI only | Not verifiable from this research session (secrets are opaque) | — | Planner/ops task: confirm `NPM_TOKEN` (or trusted-publisher OIDC-only, no token) is configured in repo secrets before the first tag-triggered publish |

**Missing dependencies with no fallback:** none identified as blocking for the build/test loop this
phase actually needs to implement.

**Missing dependencies with fallback:** `buf` CLI install step verification deferred to planner
(low risk — proven pattern already exists for Rust/other SDKs in this monorepo).

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | vitest ^4 (confirmed current on npm this session) |
| Config file | `sdks/typescript/vitest.config.ts` (new — none exists yet) |
| Quick run command | `npm test -- --run` (single pass, no watch) |
| Full suite command | `npm test -- --run --coverage` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| TS-01 (SC#1) | `/rest` bundle contains zero `@grpc/grpc-js`/`amqplib` references | integration (bundle+grep, CI-only) | CI step, not a vitest test — see Area 9 YAML | ❌ Wave 0 — new CI job |
| TS-01 (SC#2, browser) | `client.can()` → `POST /api/v1/authz/check` | unit (msw-mocked) | `npx vitest run test/rest/can.test.ts` | ❌ Wave 0 |
| TS-01 (SC#2, Node) | Node `checkAccess` → gRPC `CheckAccess` | unit (mocked grpc-js client) | `npx vitest run test/grpc/checkAccess.test.ts` | ❌ Wave 0 |
| TS-01 (SC#3) | 5 parallel fetches on expired token ⇒ exactly 1 refresh; CSRF auto-forwarded | unit (msw-mocked, concurrency) | `npx vitest run test/rest/singleFlightRefresh.test.ts` | ❌ Wave 0 |
| TS-01 (D-12/§8) | AMQP HMAC verify: valid/mismatched/missing signature; nack-without-requeue on failure; security event omits sig value | unit (mocked amqplib channel) | `npx vitest run test/amqp/hmac.test.ts` | ❌ Wave 0 |
| TS-01 (D-16/D-17) | HTTP status + gRPC status → correct error class mapping | unit | `npx vitest run test/core/errorMapper.test.ts` | ❌ Wave 0 |
| TS-01 (SC#4) | Express + Fastify middleware examples compile under `strict`; protect a sample route (401/200 behavior) | unit + typecheck | `npx vitest run test/middleware/*.test.ts && npx tsc --noEmit -p examples/tsconfig.json` | ❌ Wave 0 |
| TS-01 (D-26) | `Sensitive<T>` redacts across `toString`/`toJSON`/`util.inspect` | unit | `npx vitest run test/core/sensitive.test.ts` | ❌ Wave 0 |
| TS-01 (SC#5) | `npm publish --dry-run` succeeds | integration (CI-only) | CI step — see Area 9 YAML | ❌ Wave 0 — new CI job |
| TS-01 (D-24 optional) | gRPC/AMQP work end-to-end against a live AXIAM server | smoke (testcontainers or manual) | separate, optional CI job / manual `just run` + SDK example script | ❌ Wave 0 — optional |

### Sampling Rate
- **Per task commit:** `npm test -- --run` (fast unit suite, msw/mocked — no real broker/gRPC server, seconds-scale)
- **Per wave merge:** full suite + SC#1 bundle-and-grep + `npm publish --dry-run` gates
- **Phase gate:** all of the above green, plus a manual/CI-optional testcontainers smoke run before tagging the first release

### Wave 0 Gaps
- [ ] `sdks/typescript/vitest.config.ts` — no test framework config exists yet
- [ ] `sdks/typescript/test/` directory structure (`rest/`, `grpc/`, `amqp/`, `core/`, `middleware/`) — none exists
- [ ] `sdks/typescript/tsup.config.ts` — no build config exists yet (scaffold only has `tsc`)
- [ ] Framework install: `npm install -D vitest msw @grpc/grpc-js amqplib jose tough-cookie axios-cookiejar-support tsup ts-proto express fastify` (see Installation section)
- [ ] New CI job in `.github/workflows/sdk-ci-typescript.yml` for the bundle-and-grep SC#1 gate and the `npm publish --dry-run` gate (currently the workflow only has a `scaffold-check` job)

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | Yes | Cookie-session (browser) / JWKS-verified JWT (Node) per §1/§7; no custom crypto, delegates signature verification to `jose` |
| V3 Session Management | Yes | `axiam_access`/`axiam_refresh` httpOnly cookies (server-controlled attributes, SDK does not set these — SDK only reads/forwards); single-flight refresh guard (§9) |
| V4 Access Control | Yes | `checkAccess`/`can`/`batchCheck` delegate entirely to server-side `AuthorizationEngine` (FND-04/D-08) — SDK performs no local authz decision logic, only local *authentication* verification |
| V5 Input Validation | Partial | SDK parses/deserializes server responses; recommend `zod` (or similar) schema validation on wire response bodies is Claude's-discretion — not a hard CONTEXT.md requirement, but good practice given AMQP Pitfall 5's caution against pre-HMAC-verify schema mutation |
| V6 Cryptography | Yes | HMAC-SHA256 via Node's built-in `crypto` (no third-party crypto lib); JWKS/EdDSA verification via `jose` (never hand-rolled signature verification) |
| V9 Communications | Yes | `withCredentials`/cookie jar over HTTPS (server enforces TLS 1.3 min per CLAUDE.md); SDK's `customCa` escape hatch (§6) mirrors the Rust SDK's PEM-only validation-at-construction-time pattern |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| CSRF on state-changing REST calls | Tampering / Spoofing | Cookie double-submit (`axiam_csrf` → `X-CSRF-Token`), constant-time server-side compare already in place; SDK's job is only correct forwarding, not the security boundary itself |
| Token leakage via logs/console | Information Disclosure | `Sensitive<T>` redaction across `toString`/`toJSON`/`util.inspect.custom` (D-26); CI leak-gate analog to Rust's `grep -r 'eyJ' target/debug/` should be added for the TS build output too (`grep -r 'eyJ' dist/` after a build with a test token baked in — or simpler, a runtime assertion test) |
| AMQP message tampering/replay | Tampering | HMAC-SHA256 verify-before-handler, constant-time compare, nack-without-requeue + security event on any failure (never processes an unverified message) |
| Algorithm confusion attack on JWT (`alg: none` or HMAC-with-RSA-public-key-as-secret) | Spoofing | Explicit `algorithms: ['EdDSA']` allowlist passed to `jose`'s `jwtVerify` — never trust the token header's own `alg` claim alone |
| Thundering-herd refresh (many concurrent 401s exhausting refresh-token single-use rotation) | Denial of Service (self-inflicted) | Single-flight guard (§9/D-07) — exactly the mechanism SC#3 tests |
| TLS downgrade / cert bypass shortcuts creeping into SDK code over time | Tampering / Spoofing | CI lint gate (mirroring Rust's `grep -rniE 'danger_accept_invalid_certs|...'`) — TS equivalent: `grep -rniE "rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED" src/` should return empty in CI |

## Sources

### Primary (HIGH confidence)
- `sdks/CONTRACT.md` §1–§10 — normative behavioral contract, read in full this session
- `crates/axiam-api-rest/src/middleware/csrf.rs` — cookie names/attributes/CSRF validation, read in full
- `crates/axiam-api-rest/src/handlers/auth.rs` (lines 1-120) — login/refresh/logout wire shapes
- `crates/axiam-amqp/src/messages.rs` — AMQP HMAC sign/verify reference + message types, read in full
- `crates/axiam-oauth2/src/oidc.rs` (jwks_uri, alg) — JWKS path + algorithm confirmation
- `sdks/rust/src/token/jwks.rs`, `sdks/rust/src/token/manager.rs`, `sdks/rust/src/client.rs`,
  `sdks/rust/src/rest/auth.rs`, `sdks/rust/src/amqp/{hmac,consumer}.rs`,
  `sdks/rust/src/middleware/actix.rs` — the already-shipped, already-tested reference
  implementation against the same server; read in full
- `frontend/src/lib/api.ts` — proven browser CSRF/single-flight reference, read in full
- `.github/workflows/sdk-ci-rust.yml`, `.github/workflows/release.yml` — CI/publish/provenance
  patterns already established in this repo, read in full
- `npm view <pkg> version` (live, this session) — current versions for all 12 pinned/recommended
  packages
- Live `node -e` test (this session) — confirmed `JSON.stringify` key-order preservation after
  `delete` on a parsed object, load-bearing for AMQP HMAC byte-identical claim

### Secondary (MEDIUM confidence)
- jose GitHub docs (`docs/jwks/remote/functions/createRemoteJWKSet.md`) — `cooldownDuration`/
  `timeoutDuration` API, via WebSearch this session
- grpc/proposal `L5-node-client-interceptors.md` — interceptor requester-object shape, via WebFetch
  this session
- ts-proto GitHub issues (#471, #774) — `outputServices=grpc-js` output confirmation, via
  WebSearch this session

### Tertiary (LOW confidence)
- General msw v2 API familiarity (training knowledge, not re-verified against msw's current docs
  this session beyond the version number) — recommend planner spot-check the exact `http`/
  `HttpResponse` import names against `node_modules/msw`'s actual type definitions once installed
- tsup multi-entry `splitting: false` + export-map `.mts` convention (training knowledge pattern,
  not run against this repo) — recommend a local `tsup` smoke build early in Wave 0 to validate
  before committing task plans to this exact shape

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — every version verified live via `npm view`; every pinned dep matches or
  closely tracks TS-01's stated pins
- Architecture (persona split, cookie names, JWKS path, AMQP protocol): HIGH — confirmed via
  server source code AND the already-shipped Rust SDK talking to the same server; this is the
  strongest possible evidence short of running the TS code itself
- gRPC interceptor / tsup build config specifics: MEDIUM — correct per documented library APIs,
  but not yet run against this exact repo; flagged as such throughout
- Pitfalls: HIGH for AMQP/JWKS/cookie pitfalls (grounded in the Rust SDK's own solved problems);
  MEDIUM for the jose-CJS-interop and tsup-splitting pitfalls (grounded in documented library
  behavior, not yet reproduced locally)

**Research date:** 2026-07-01
**Valid until:** 30 days for the server-side facts (cookie names/JWKS path/AMQP protocol are
frozen v1.0 API, effectively stable indefinitely); 14 days for the npm package version table
(fast-moving ecosystem — re-verify versions immediately before Wave 0 if planning is delayed)

## RESEARCH COMPLETE
