# Phase 17: TypeScript SDK - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-01
**Phase:** 17-typescript-sdk
**Areas discussed:** Persona split & tree-shaking, Browser CSRF & token model, Node persona session mechanism, Build & packaging tooling, Client construction & class surface, Error-class hierarchy, Login/MFA flow ergonomics, Testing strategy

---

## Area Selection (Round 1)

| Option | Description | Selected |
|--------|-------------|----------|
| Persona split & tree-shaking | Root `.` entry behavior + SC#1 enforcement | ✓ |
| Browser CSRF & token model | CSRF source + httpOnly token implications | ✓ |
| Node persona session mechanism | Cookie jar vs body tokens | ✓ |
| Build & packaging tooling | tsc vs tsup/rollup, dual format | ✓ |

**User's choice:** All four.

---

## Persona split & tree-shaking

| Option | Description | Selected |
|--------|-------------|----------|
| Isomorphic REST core | Root `.` = browser-safe REST core; `/grpc` `/amqp` Node-only opt-in | ✓ |
| Full Node client at root | `.` re-exports gRPC+AMQP; browser must use `/rest` | |
| Separate entries + CI bundle assertion | No cross-imports, sideEffects:false, CI grep proof | ✓ |
| Config-only (browser field/stubs) | Rely on package.json config, no CI proof | |
| Explicit subpaths + import/require | Subpaths as boundary, ESM+CJS conditions | ✓ |
| `browser`/`node` auto-swap | Same import resolves differently per condition | |
| Internal isomorphic core module | One dependency-free core for errors/Sensitive/CSRF/single-flight | ✓ |
| You decide | Planner's discretion | |

**User's choice:** Isomorphic REST core; CI bundle-and-grep assertion; explicit subpaths + import/require conditions; internal isomorphic core module. (D-01..D-04)
**Notes:** SC#1 becomes a verified CI gate, not a config promise.

---

## Browser CSRF & token model

| Option | Description | Selected |
|--------|-------------|----------|
| Cookie double-submit, match frontend | Read `axiam_csrf` cookie → `X-CSRF-Token` (as frontend/src/lib/api.ts) | ✓ |
| Response-header store, per §3 literal | Capture X-CSRF-Token from responses | |
| Cookie-session only, no local token/JWKS | withCredentials + reactive refresh; no Sensitive in browser | ✓ |
| Read a JS-visible token for proactive refresh | Requires weakening httpOnly posture | |
| Module-level shared Promise (§9) | Single in-flight refresh Promise | ✓ |
| Port frontend isRefreshing + failedQueue | Reuse queue pattern verbatim | |
| No built-in cache; can() + batchCheck | SDK stateless on authz; caller caches | ✓ |
| Built-in short-TTL authz cache | SDK owns cache/invalidation | |

**User's choice:** Cookie double-submit; cookie-session only (no local token/JWKS/Sensitive in browser); module-level shared Promise; no built-in authz cache. (D-05..D-08)
**Notes:** D-05 contradicts CONTRACT §3's browser note — flagged for a §3 update (deferred).

---

## Node persona session mechanism

| Option | Description | Selected |
|--------|-------------|----------|
| tough-cookie jar, read token by name | Persistent jar; read access token from jar for gRPC/JWKS | ✓ |
| Manual token handling from response body | Parse tokens from JSON body, hold in-memory | |
| Client interceptor + reused channel | @grpc/grpc-js interceptor injects metadata, triggers shared refresh | ✓ |
| Per-call CallCredentials generator | Attach metadata per call | |
| Local JWKS via jose, proactive refresh | Verify token locally, refresh before expiry | ✓ |
| Reactive-only, no local JWKS | Refresh only on 401/UNAUTHENTICATED | |
| Closure handler, verify-before-handler | SDK owns ack/nack, HMAC-verify before handler | ✓ |
| EventEmitter / async-iterator stream | Consumer drives ack/nack | |

**User's choice:** tough-cookie jar (read token by name); gRPC client interceptor + reused channel; local JWKS via jose (proactive); closure-handler AMQP consumer. (D-09..D-12)
**Notes:** Resolves Rust D-05's open item toward jar-read; research still confirms exact cookie name / body fallback. Shared single-flight across REST+gRPC carried forward from Rust D-04 (D-13).

---

## Build & packaging tooling

| Option | Description | Selected |
|--------|-------------|----------|
| tsup (esbuild) dual-format | Dual ESM+CJS, per-entry, .d.ts, sideEffects:false | ✓ |
| rollup | Manual config, max control | |
| tsc-only | Single format, simplest | |
| Dual ESM + CJS | Both via import/require conditions | ✓ |
| ESM-only | Simpler, excludes CJS consumers | |
| Gitignored + regenerate-and-bundle at publish | Stubs gitignored, bundled into dist | ✓ |
| Commit generated stubs to git | Diverges from Phase 15 D-01 | |
| Dry-run PR gate + tag publish w/ provenance | --dry-run on PR, publish on tag w/ OIDC | ✓ |
| Tag publish, no provenance | Simpler, loses supply-chain attestation | |

**User's choice:** tsup dual-format; dual ESM+CJS; gitignored + regenerate-and-bundle; dry-run PR gate + tag-triggered publish with npm provenance. (D-19..D-21)

---

## Client construction & class surface

| Option | Description | Selected |
|--------|-------------|----------|
| AxiamClient — fix the typos | Fix CONTRACT `AximaClient` + scaffold `AximClient` | ✓ |
| AximaClient — honor contract spelling | Keep contract spelling | |
| Single AxiamClient, transports layer per entry | One class; entries augment transports | ✓ |
| Distinct client class per entry | AxiamRestClient / AxiamGrpcClient etc. | |
| One session, transports attached to it | Shared session; one login drives all transports | ✓ |
| Separate clients sharing a config object | Independent session state | |

**User's choice:** `AxiamClient` (fix typos); single class with transports layered per entry; one shared session with transports attached. (D-14, D-15, D-13)
**Notes:** Options-object construction with tenant required at construction (§5/§6).

---

## Error-class hierarchy

| Option | Description | Selected |
|--------|-------------|----------|
| Base class + 3 Error subclasses | AxiamError + AuthError/AuthzError/NetworkError, instanceof, cause | ✓ |
| Single error with a `kind` field | One class, string discriminant | |
| Central status→error mapper in core | One HTTP+gRPC status mapping module | ✓ |
| Per-transport inline mapping | Each transport maps its own statuses | |

**User's choice:** Base `AxiamError` + 3 subclasses (instanceof, cause chaining, structured fields); central status→error mapper in core. (D-16, D-17)

---

## Login / MFA flow ergonomics

| Option | Description | Selected |
|--------|-------------|----------|
| Discriminated-union return from login | `{status:'mfa_required'|'authenticated'}` | ✓ |
| Throw MfaRequiredError | Exception for MFA-required flow | |

**User's choice:** Discriminated-union return from `login()`. (D-18)
**Notes:** MFA-required is an expected outcome, not an error.

---

## Testing strategy

| Option | Description | Selected |
|--------|-------------|----------|
| vitest | ESM-native, matches frontend Vite | ✓ |
| jest | Mature, heavier ESM config | |
| msw + jsdom | Realistic REST mocking for browser tests | ✓ |
| Manual fetch/axios mocks | Lighter, more brittle | |
| Mocked units + optional testcontainers smoke | Deterministic units + real-server smoke | ✓ |
| testcontainers for all Node tests | Highest fidelity, slow/flaky | |
| Mocked only | Fastest, no real wire | |

**User's choice:** vitest; msw + jsdom for browser; mocked units + optional testcontainers smoke for Node. (D-22..D-24)

---

## Claude's Discretion

- Internal module/file layout, `Sensitive<T>` accessor naming, single-flight guard internals.
- Concrete numeric timeout/backoff/retry values (CF-01, CF-03).
- Package-manager/workspace tooling (pnpm vs npm), `engines.node` matrix, examples layout, versioning tooling.
- Exact `jose` JWKS caching/rotation API usage (D-11).

## Post-Context Refinements (Round 2 — 2026-07-01)

Re-opened the four areas (persona selection, Node auth internals, middleware verification, §3
reconciliation) to pin the genuinely-open nuances the first pass left to §7/planner discretion.

| Area | Question | Options considered | Selected → CONTEXT |
|------|----------|--------------------|--------------------|
| Persona selection | Import path vs runtime detection | Explicit import path only / runtime auto-detection | Explicit import path only → **D-25** |
| `Sensitive<T>` surface | Redaction ceiling | `toString`+`toJSON`+`util.inspect` / §7 minimum (`toString` only) | Full three-surface redaction → **D-26** |
| Middleware verification | Local vs server round-trip | Local JWKS (`jose`), inject `req.axiamUser` / per-request server round-trip | Local JWKS, `req.axiamUser` → **D-27** |
| §3 reconciliation | Contract-edit direction | Update §3 to cookie double-submit canonical / document a browser-only divergence | Update §3 → **D-28** |

_Note: the Round-2 interactive prompt hit an environment permission-stream error mid-session; the
four recommended directions (each consistent with CONTRACT.md and the Rust reference D-03/D-11) were
applied to close the areas the user had opted to discuss._

## Deferred Ideas

- CONTRACT.md §3 (CSRF browser note) + class-name (`AximaClient`/`AximClient`) fixups — scoped doc task for the planner. Direction decided (D-28): update §3, don't document a divergence.
- Browser JS-readable token / proactive browser refresh — rejected (httpOnly + XSS).
- Built-in authz cache — deferred to caller-owned caching.
- EventEmitter/stream AMQP consumer — deferred for the safer closure-handler.
- testcontainers for all Node tests — kept optional/smoke-only.
- pnpm workspace / changesets / engines matrix — discretion tooling, not pinned.
- Automated cross-language conformance harness — inherited deferral; per-phase checklist for now.
