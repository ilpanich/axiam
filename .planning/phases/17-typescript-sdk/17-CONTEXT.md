# Phase 17: TypeScript SDK - Context

**Gathered:** 2026-07-01
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 17 delivers `sdks/typescript/` — the publishable **`axiam-sdk` npm package**, a
**dual-persona** TypeScript/JavaScript client:

- **Browser persona (REST-only):** cookie-session auth (`withCredentials`), reactive
  single-flight refresh, and authz via the FND-04 REST endpoint (`POST /api/v1/authz/check`).
  Zero Node-only modules in a browser bundle.
- **Node persona (REST + gRPC + AMQP):** full transport coverage — REST (axios 1.7), gRPC
  (`@grpc/grpc-js` 1.14, ts-proto stubs), AMQP (amqplib) — with local JWKS verification
  (`jose`) for proactive refresh and Express + Fastify middleware.

It conforms to `sdks/CONTRACT.md` §1–§10 in full and **inherits the Rust reference patterns**
(Phase 16 D-01..D-14) wherever a browser/Node analog exists. The novel work this phase resolves
is everything the persona split forces that the single-runtime Rust reference never faced.

**In scope (TS-01):** the `axiam-sdk` package + both personas + all viable transports per persona
+ Express/Fastify middleware + examples + npm publish CI, with per-persona transport selection,
tree-shaking, CSRF, and single-flight concurrency proven by test.

**Out of scope:** any change to the AXIAM server (v1.0 APIs are frozen; the SDK is a pure external
client and MUST NOT depend on server crates); the other 5 remaining language SDKs (Phases 18–22);
the shared foundation already delivered in Phase 15 (`buf.gen.yaml`, `CONTRACT.md`, FND-04 endpoint,
scaffold).

</domain>

<decisions>
## Implementation Decisions

> **Note:** The SDK's *behavioral* surface is already locked by the binding `sdks/CONTRACT.md`
> §1–§10 (method map, error taxonomy, CSRF, cookie jar, tenant context, TLS policy, `Sensitive<T>`,
> AMQP HMAC, single-flight refresh, middleware interface) and by `TS-01` (pinned deps: axios 1.7,
> `@grpc/grpc-js` 1.14, amqplib, `jose`, ts-proto 2.x). The decisions below are the **open HOW
> choices** resolved in this discussion. They do not restate the contract — downstream agents MUST
> read CONTRACT.md.

### Persona Architecture & Tree-Shaking
- **D-01:** **Isomorphic REST core at the root `.` entry.** `import { AxiamClient } from 'axiam-sdk'`
  resolves to a browser-safe REST + auth core that works in both runtimes; `axiam-sdk/grpc` and
  `axiam-sdk/amqp` are **Node-only opt-in subpaths**. `axiam-sdk/rest` aliases the core for SC#1
  clarity. An accidental root import can never break a browser build.
- **D-02:** **SC#1 proven by CI bundle-and-grep assertion.** Entry files have no cross-imports and
  `sideEffects: false`; a CI test bundles a `/rest` fixture (Vite/esbuild) and asserts the output
  contains **no `@grpc/grpc-js` and no `amqplib`**. The criterion is a verified gate, not a config
  promise.
- **D-03:** **Explicit subpaths are the boundary** (`/rest` `/grpc` `/amqp`), each with
  `import`/`require`/`types` conditions for dual ESM+CJS. **No** magic `browser`-condition swapping
  (fragile across bundlers, hard to lint).
- **D-04:** **One internal dependency-free `core` module** (no Node- or browser-only imports) defines
  the error taxonomy, `Sensitive<T>`, CSRF handling, and the single-flight guard once; the
  rest/grpc/amqp adapters layer on top.

### Browser Persona
- **D-05:** **Cookie double-submit CSRF.** Read the `axiam_csrf` cookie via `document.cookie` and echo
  it as `X-CSRF-Token` on POST/PUT/PATCH/DELETE — exactly as `frontend/src/lib/api.ts` does today
  (proven against the live server). **This contradicts CONTRACT §3's "read from response header" note
  — flag §3 for an update** (see canonical refs / deferred).
- **D-06:** **Cookie-session only; no local token/JWKS/`Sensitive` in the browser.** Browsers cannot
  read httpOnly tokens, so the browser persona relies on `withCredentials` cookies + reactive
  single-flight 401→refresh. No JS token reading, no local JWKS verification, no `Sensitive<T>`
  (no raw tokens ever enter JS). Local JWKS + `Sensitive` are **Node-persona only**.
- **D-07:** **Module-level shared-Promise refresh guard** (§9 TS guidance). One in-flight refresh
  Promise held in a module var; concurrent 401s await the same Promise. Directly satisfies SC#3
  (5 fetches → exactly 1 refresh). Functionally equivalent to the frontend's `isRefreshing` +
  `failedQueue`, chosen for fewer moving parts.
- **D-08:** **No built-in authz cache.** The SDK stays stateless on authz; callers use `batchCheck`
  to gate a whole page in one round-trip and cache via their own layer (React Query, etc.) — matches
  how the frontend already works. SDK owns no cache-invalidation/staleness semantics.

### Node Persona
- **D-09:** **tough-cookie jar, read token by name.** Persistent per-client cookie store via
  `tough-cookie` + `axios-cookiejar-support` (mirrors Rust `reqwest` `cookie_store`, satisfies §4).
  Server httpOnly cookies flow transparently for REST; for gRPC metadata + JWKS the SDK reads the
  access-token cookie from the jar by name. **Resolves Rust D-05's open item toward jar-read** — but
  research MUST still confirm the exact cookie name and whether `login`/`refresh` also return tokens
  in the JSON body (fallback path).
- **D-10:** **gRPC auth = client interceptor + reused channel.** A `@grpc/grpc-js` client interceptor
  injects `authorization` + `x-tenant-id` metadata from the shared session on every RPC and triggers
  the shared single-flight refresh on `UNAUTHENTICATED`; one long-lived channel is reused. Direct
  analog of Rust D-04.
- **D-11:** **Local JWKS via `jose`, proactive refresh.** Node verifies access-token signature + `exp`
  locally against OIDC `/.well-known/jwks.json` (cached, refetch on unknown `kid`) to refresh before
  expiry. Mirrors Rust D-03/D-11. Requires the D-09 token access. Reactive 401/`UNAUTHENTICATED`
  remains the fallback.
- **D-12:** **Closure-handler AMQP consumer, verify-before-handler.** API shape
  `consume(queue, async (event) => { ... })`. The SDK owns the ack/nack loop, performs §8
  HMAC-SHA256 verification **before** invoking the handler, and on mismatch nacks-without-requeue +
  emits a security event — the handler never sees an unverified message. Direct analog of Rust D-07.
- **D-13:** **One shared session, transports attached to it.** The Node client holds a single
  session/config object (cookie jar, single-flight guard, tenant, JWKS cache); rest/grpc/amqp are
  transport modules attached to it, so **one `login()` drives all three transports** and the
  single-flight guard is shared across REST + gRPC (Rust D-04).

### Client Surface & API Shape
- **D-14:** **Canonical class name is `AxiamClient`.** Fix the CONTRACT.md `AximaClient` and scaffold
  (`index.ts`/README) `AximClient` occurrences as typos — they don't match the AXIAM product name or
  the `axiam-sdk` package. Construction uses an options object per §5/§6:
  `new AxiamClient({ baseUrl, tenantSlug | tenantId, customCa? })` (tenant required at construction).
- **D-15:** **Single `AxiamClient` class; transports layer per imported entry.** The REST entry
  constructs a REST-only instance; importing `/grpc` or `/amqp` augments the same client with those
  transport methods (uninmported transports aren't bundled). Consistent name + shared config/session
  across entries (composes with D-13).

### Error Model
- **D-16:** **Base `AxiamError extends Error` + 3 subclasses.** `AuthError` / `AuthzError` /
  `NetworkError` (§2). Discriminate via `instanceof`; `NetworkError` carries the transport `cause`;
  `AuthzError` carries optional `action`/`resourceId`. No raw token strings in any message/field.
- **D-17:** **Central status→error mapper in `core`.** One module maps both the HTTP status (§2 table)
  and gRPC status codes to the three error types, used by every transport — one source of truth so
  REST and gRPC cannot drift on the taxonomy.

### Login / MFA Flow
- **D-18:** **Discriminated-union return from `login()`.** `login()` returns
  `{ status: 'mfa_required', mfaToken } | { status: 'authenticated', user }`; the caller narrows on
  `status` and calls `verifyMfa(mfaToken, code)`. Type-safe, no control-flow-by-exception (the MFA
  requirement is an expected outcome, not an error).

### Build & Packaging
- **D-19:** **tsup (esbuild) dual ESM+CJS.** Produces per-entry outputs (rest/grpc/amqp), `.d.ts`, and
  `sideEffects: false` for clean tree-shaking — replacing the scaffold's plain `tsc`. Publishes
  **both ESM and CJS** via `import`/`require` export conditions (broad consumer support; composes
  with D-03).
- **D-20:** **Gitignored stubs + regenerate-and-bundle at publish.** `typescript/src/gen` stays
  gitignored (Phase 15 D-01 generate-on-build); `buf generate` runs on build/CI; the publish job
  regenerates and includes the **compiled** ts-proto stubs in the `dist` tarball so npm consumers
  never run buf. Direct analog of Rust D-09 / Phase 15 D-02.
- **D-21:** **Dry-run PR gate + tag-triggered publish with provenance.** `npm publish --dry-run` gate
  on PRs touching `sdks/typescript/**`; real `npm publish --access public` with **npm provenance
  (OIDC)** triggered by tag `sdks/typescript/vX.Y.Z` (Phase 15 D-13 tag convention, satisfies SC#5).

### Testing
- **D-22:** **vitest** — ESM-native, matches the frontend's Vite tooling (one test stack across the
  repo), native jsdom support for the REST persona.
- **D-23:** **msw + jsdom for browser-persona tests** — realistic REST request/response mocking
  (login, refresh, `can`/`batchCheck`, CSRF-header assertions); the SC#3 concurrency test drives a
  controllable msw handler.
- **D-24:** **Node tests = mocked units + optional testcontainers smoke.** Unit/concurrency tests
  (SC#3 single-flight, HMAC verify, error mapping) run against mocked transports for determinism and
  speed; a separate optional testcontainers-based smoke test exercises gRPC/AMQP against a real AXIAM
  server in CI.

### Carried Forward from the Rust Reference (Phase 16) — apply unless research contradicts
- **CF-01 (D-12 Rust):** Bounded backoff, **idempotent operations only** — auto-retry only GET /
  read-only authz checks for transient `NetworkError` (timeouts, gRPC `UNAVAILABLE`), honor
  `Retry-After` on 429, exponential backoff + jitter, small max-attempt cap (~2–3). State-changing
  requests never auto-retry. Contract auth-retry bars remain in force.
- **CF-02 (D-13 Rust analog):** Observability = **injectable, redaction-aware logger, OFF by
  default** (TS has no Cargo features; the analog is an optional logger the consumer supplies).
  Never emit token values (respect `Sensitive<T>`).
- **CF-03 (D-14 Rust):** Sane connect/request **timeouts (builder-overridable)**; lapin-equivalent
  amqplib auto-reconnect with backoff; `baseUrl` required. Exact numeric values = research/planner.

### Claude's Discretion
- Exact internal module/file layout (`core`/`rest`/`grpc`/`amqp`/`auth`/`middleware`), the
  `Sensitive<T>` private-accessor naming, and single-flight guard internals — planner's call within
  the locked contract.
- Concrete numeric timeout/backoff/retry values (CF-01, CF-03).
- Package-manager/workspace tooling (pnpm vs npm, workspace vs standalone), `engines.node` matrix,
  examples directory layout, and versioning tooling (changesets vs manual) — left to research/planner.
- Exact `jose` API usage for JWKS caching + rotation (D-11) — research selects within the stated
  shape (must support EdDSA/Ed25519).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Binding contract & phase definition (read FIRST)
- `sdks/CONTRACT.md` §1–§10 — **normative/binding** cross-language behavioral contract. The TS SDK
  *implements* this. Relevant §: §1 camelCase method map (`login`/`verifyMfa`/`refresh`/`logout`/
  `checkAccess`+`can`/`batchCheck`), §2 error taxonomy + HTTP/gRPC status mapping (D-16/D-17), §3 CSRF
  (**note D-05 contradicts §3's browser note — §3 needs an update**), §4 cookie jar (D-09), §5 tenant
  context (D-14), §6 TLS/`customCa` (D-14), §7 `Sensitive<T>` (Node only per D-06), §8 AMQP HMAC
  protocol (D-12), §9 single-flight refresh (D-07/D-13), §10 middleware interface (Express/Fastify).
- `.planning/ROADMAP.md` — Phase 17 goal + 5 success criteria; v1.1 SDK milestone framing; the
  `sdks/<lang>/vX.Y.Z` tag convention (D-21).
- `.planning/REQUIREMENTS.md` §TS-01 — acceptance criteria + pinned deps (axios 1.7, `@grpc/grpc-js`
  1.14, amqplib, `jose`, ts-proto 2.x).

### Prior-phase decisions this phase inherits
- `.planning/phases/16-rust-sdk/16-CONTEXT.md` — the **reference implementation**. D-01 (async-first),
  D-03/D-11 (local JWKS, OIDC discovery + rotation → D-11 here), D-04 (shared channel + interceptor →
  D-10/D-13), D-05 (token-source open item → D-09 resolution), D-06 (single error enum → TS classes
  D-16), D-07 (closure-handler AMQP → D-12), D-09 (regenerate-and-bundle publish → D-20/D-21), D-12
  (retry → CF-01), D-13 (tracing off → CF-02), D-14 (defaults → CF-03).
- `.planning/phases/15-sdk-foundation/15-CONTEXT.md` — D-01 (generate-on-build, no committed stubs →
  D-20), D-02 (regenerate-and-bundle at publish), D-05 (FND-04 `/authz/check` + `/batch` the browser
  `can`/`batchCheck` call), D-09/D-10 (binding contract + locked vocabulary), D-11/D-12/D-13 (package
  identities: npm `axiam-sdk`, monorepo tag scheme).

### SDK domain research (read for rationale)
- `.planning/research/ARCHITECTURE.md` — codegen source-of-truth, monorepo + path-filtered CI.
- `.planning/research/STACK.md` — buf toolchain + plugin set (ts-proto).
- `.planning/research/PITFALLS.md` — cross-language divergence trap + proto-codegen pitfalls (D-20).
- `.planning/research/FEATURES.md` — per-SDK feature matrix.
- `.planning/research/SUMMARY.md` — consolidated research synthesis.

### Code the SDK consumes / mirrors (reuse semantics; do NOT depend on server crates)
- `frontend/src/lib/api.ts` — **the browser-persona reference pattern**: axios instance with
  `withCredentials`, the `axiam_csrf` cookie→`X-CSRF-Token` interceptor (D-05), and a single-flight
  refresh (`isRefreshing` + `failedQueue`, D-07). Also `SKIP_REFRESH` list (never refresh on
  login/logout/refresh endpoints).
- `crates/axiam-amqp/src/messages.rs` — **AMQP HMAC reference impl** (§8): `sign_payload`,
  `verify_payload` (constant-time), canonical-JSON + hex-HMAC-SHA256 protocol the TS Node verify
  (D-12) must match byte-for-byte.
- `proto/axiam/v1/authorization.proto`, `user.proto`, `token.proto` — proto surface ts-proto covers;
  `CheckAccess`/`BatchCheckAccess` request/response shapes for D-10.
- `crates/axiam-api-grpc/src/services/authorization.rs` — gRPC `check_access`/`batch_check_access`
  semantics the Node gRPC client targets.
- REST `POST /api/v1/authz/check` + `/api/v1/authz/check/batch` (Phase 15 FND-04) — the endpoints
  browser `can`/`checkAccess`/`batchCheck` call.
- `sdks/buf.gen.yaml` — ts-proto plugin config (`out: typescript/src/gen`, `target=ts`,
  `outputServices=grpc-js`) driving D-20.
- `sdks/typescript/{package.json,src/index.ts,README.md,LICENSE}` — existing scaffold (exports map
  `.`/`/rest`/`/grpc`/`/amqp` already declared; `AximClient` name to fix per D-14) — Phase 17 fills
  it in.
- OIDC `/.well-known/jwks.json` (exact path to confirm in research) — JWKS source for D-11.

### Project-wide constraints
- License is **Apache-2.0** repo-wide — `sdks/typescript/LICENSE` must match (do not trust the stale
  workspace `Cargo.toml` license field); see project memory `project_license_apache.md`.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `frontend/src/lib/api.ts` — a proven, production browser client the SDK's browser persona mirrors
  almost 1:1: `withCredentials`, cookie-double-submit CSRF, single-flight refresh, and the
  never-refresh-on-auth-endpoints list. The SDK generalizes it (configurable `baseUrl`, tenant header,
  no app-store coupling) rather than reinventing it.
- `crates/axiam-amqp/src/messages.rs` — canonical HMAC sign/verify; the Node consumer reimplements
  *verification* in TS (cannot depend on the crate) but the canonical-JSON + hex-HMAC-SHA256 protocol
  must be byte-identical (§8 / D-12).
- `sdks/buf.gen.yaml` ts-proto entry + `proto/axiam/v1/*.proto` — the codegen pipeline (Phase 15);
  the SDK runs `buf generate` into a gitignored dir at build time and bundles compiled stubs at
  publish (D-20).
- `sdks/typescript/` scaffold (package.json exports map, LICENSE, README stating CONTRACT.md
  conformance) — Phase 17 fills it in.

### Established Patterns
- **CONTRACT.md is binding (Phase 15 D-09):** "CONTRACT.md §1–§10 conformance verified" is a required
  acceptance checklist item for this phase.
- **Cookie double-submit CSRF** (`axiam_csrf` → `X-CSRF-Token`) is the server's actual mechanism, as
  implemented by the frontend — D-05 follows it over CONTRACT §3's note.
- **Additive-only / allow-wins / default-deny RBAC** constrains how the SDK surfaces authz `reason`
  semantics (mirrors gRPC).
- **Monorepo tag release** (`sdks/<lang>/vX.Y.Z`, Phase 15 D-13) — D-21 follows it.
- **Frontend TS stack** — TypeScript ~5.9, Vite/vitest — the SDK aligns (D-22) for a single repo test
  stack.

### Integration Points
- New `sdks/typescript/src/` source tree (`core` + rest/grpc/amqp adapters + middleware + examples).
- New per-SDK GitHub Actions workflow under `.github/workflows/` with `paths: sdks/typescript/**`
  filter (dry-run gate + tag-triggered publish with provenance, D-21).
- ts-proto stubs generated from `proto/axiam/v1/` via buf into a gitignored `typescript/src/gen`.
- A CI bundle-and-grep job proving SC#1 (D-02).

</code_context>

<specifics>
## Specific Ideas

- The browser persona should feel like a thin, familiar axios client — model it directly on
  `frontend/src/lib/api.ts` so a frontend dev recognizes it instantly.
- Success-criterion proof points to preserve as concrete tests: (#1) bundle a `/rest` fixture and grep
  for `@grpc/grpc-js`/`amqplib` → empty; (#2) browser `can()` hits REST, Node `checkAccess` hits gRPC;
  (#3) 5 parallel fetches on an expired token ⇒ exactly 1 refresh + CSRF auto-forwarded via the axios
  interceptor; (#4) Express + Fastify middleware examples compile under `strict`; (#5)
  `npm publish --dry-run` succeeds.
- `AxiamClient` (not `AximaClient`/`AximClient`) is canonical — this discussion also produces a
  CONTRACT.md §3 + naming follow-up (see deferred).

</specifics>

<deferred>
## Deferred Ideas

- **CONTRACT.md §3 + class-name fixups** — D-05 (cookie double-submit) contradicts §3's browser note,
  and D-14 fixes `AximaClient`/`AximClient` typos. These are contract/doc edits that touch the shared
  `sdks/CONTRACT.md` (affecting later SDKs), so surface them to the planner as an explicit, scoped
  documentation task rather than silently diverging. **Do not lose.**
- **Browser JS-readable token / proactive refresh in the browser** — considered (D-06) and rejected
  because httpOnly cookies + XSS posture forbid it; revisit only if a non-cookie browser auth model
  is ever adopted.
- **Built-in authz cache** — considered (D-08); deferred in favor of caller-owned caching. Revisit if
  a cross-SDK caching convention emerges.
- **EventEmitter/stream AMQP consumer** — considered (D-12) for composability; deferred for the safer
  closure-handler (inherited from Rust D-07's same call).
- **testcontainers for all Node tests** — considered (D-24); kept optional/smoke-only to preserve
  deterministic concurrency tests.
- **pnpm workspace / changesets / engines matrix** — noted as Claude's-discretion tooling; not blocked,
  just not pinned here.
- **Automated cross-language conformance harness** — inherited from Phase 15/16 deferred list; Phase 17
  verifies conformance via its own §1–§10 checklist.

### Reviewed Todos (not folded)
None — no pending todos matched this phase.

</deferred>

---

*Phase: 17-typescript-sdk*
*Context gathered: 2026-07-01*
