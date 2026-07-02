# Phase 18: Go SDK - Context

**Gathered:** 2026-07-01
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 18 delivers `sdks/go/` — the publishable Go module
`github.com/ilpanich/axiam/sdks/go` and the **second server-side reference SDK** (after the Rust
reference, Phase 16). It implements the full client capability baseline against the frozen v1.0 APIs
using idiomatic Go:

- **REST** (`net/http` + `net/http/cookiejar`) — auth flow (`Login` → `VerifyMfa`), `Refresh`,
  `Logout`, `CheckAccess`/`Can`, `BatchCheck`.
- **gRPC** (`grpc-go` 1.81) — `CheckAccess`, `BatchCheckAccess`.
- **AMQP** (`amqp091-go` 1.10) — event consumer with HMAC-SHA256 verify-before-handler.
- Local JWKS verification via `lestrrat-go/jwx/v3` (EdDSA/Ed25519) for proactive refresh; a
  `net/http` middleware/route-guard.

It conforms to `sdks/CONTRACT.md` §1–§10 in full and **inherits the Rust (Phase 16) and TypeScript
(Phase 17) reference patterns** wherever a Go analog exists. Go is a **non-browser** SDK, so §3 CSRF =
capture `X-CSRF-Token` from the response header (not the browser cookie double-submit that the TS
browser persona uses). The novel work this phase resolves is everything Go's toolchain/idiom forces
that the Rust/TS references never faced (source-distributed codegen, module partitioning, functional
options, `errors.Is/As`, `context.Context` propagation).

**In scope (GO-01):** the `sdks/go` module + all three transports + `net/http` middleware + examples +
Go module publish CI, with `sync.Mutex` single-flight concurrency, HMAC verify, and the no-TLS-bypass
gate proven by test.

**Out of scope:** any change to the AXIAM server (v1.0 APIs are frozen; the SDK is a pure external
client and MUST NOT depend on server crates); the other remaining language SDKs (Phases 19–22); the
shared foundation already delivered in Phase 15 (`buf.gen.yaml`, `CONTRACT.md`, FND-04 endpoint,
scaffold).

</domain>

<decisions>
## Implementation Decisions

> **Note:** The SDK's *behavioral* surface is already locked by the binding `sdks/CONTRACT.md`
> §1–§10 (method map, error taxonomy, CSRF, cookie jar, tenant context, TLS policy, `Sensitive<T>`,
> AMQP HMAC, single-flight refresh, middleware interface) and by `GO-01` (pinned deps: `net/http` +
> `net/http/cookiejar`, `grpc-go` 1.81, `amqp091-go` 1.10, `lestrrat-go/jwx/v3`, `sync.Mutex`
> single-flight). The decisions below are the **open HOW choices** resolved in this discussion. They
> do not restate the contract — downstream agents MUST read CONTRACT.md.

### Codegen Distribution (the real conflict with Phase 15 D-01)
- **D-01:** **Committed gRPC stubs + CI drift-check.** The buf-generated `.pb.go` / `_grpc.pb.go`
  files are **committed into the `sdks/go/` source tree** (e.g. `sdks/go/internal/gen`). Rationale:
  `go get` fetches **source** from the git tag and consumers **cannot run buf**, so the stubs MUST be
  present in the tree — there is no separate build artifact to bundle into (unlike Rust crates.io /
  npm tarball). Go is therefore the **documented codegen-distribution exception** to Phase 15 D-01's
  generate-on-build/gitignore model (analogous to C#'s documented `Grpc.Tools` exception in
  CONTRACT.md closing notes). A CI job regenerates the stubs with the pinned buf config and runs
  `git diff --exit-code` to **block staleness/drift** — committed stubs must always match the protos.

### Module Partitioning (Go analog of Rust Cargo features / TS subpaths)
- **D-02:** **Single module, sub-packages.** One module `github.com/ilpanich/axiam/sdks/go` (matches
  the existing scaffold `go.mod`) with sub-packages: the module root for the REST core, `.../grpc`,
  and `.../amqp`. Go compiles **only imported packages** into a consumer binary, so a REST-only
  consumer never compiles `grpc-go`/`amqp091-go` into their binary — the only cost is extra entries in
  the module graph (`go.sum`), not binary bloat. One version tag covers the whole SDK. Split
  per-transport modules were rejected as un-idiomatic and as multiplying tag/release choreography while
  complicating shared internal code (session, single-flight) across module boundaries.

### Client API Idiom
- **D-03:** **Functional options; required params positional.**
  `NewClient(baseURL, tenantSlug string, opts ...Option) (*Client, error)`. `baseURL` and `tenantSlug`
  are **positional/required** — compile-time enforcement of §5 (tenant required) and SC#1
  ("`tenantSlug` enforced at call time"). Optional config via functional options: `WithCustomCA([]byte)`
  (the §6-only TLS escape hatch), `WithTimeout(time.Duration)`, `WithHTTPClient(*http.Client)`.
  Idiomatic modern Go, extensible without breaking the constructor signature. A config struct was
  rejected because required-vs-optional isn't type-enforced (zero-value `TenantSlug` would compile).

### Error Model
- **D-04:** **Typed error structs + `errors.As`, redact-before-wrap.** Three exported struct types
  `AuthError` / `AuthzError` / `NetworkError`, each implementing `error` (§2). Discriminate via
  `errors.As(err, &AuthError{})`; sentinel vars (`ErrAuth`/`ErrAuthz`/`ErrNetwork`) also provided for
  `errors.Is` convenience. `AuthzError` carries optional `Action`/`ResourceID` (§2 construction rule).
  `NetworkError` exposes `Unwrap()` for the transport cause **BUT its constructor first redacts
  `Set-Cookie`/`Authorization`/`Cookie` headers from any wrapped `*http.Response`/error** — a **direct
  Phase 17 CR-04 carry-forward** (raw session/refresh tokens must never enter the error chain, since a
  4xx alongside a fresh `Set-Cookie` would otherwise leak the token via `fmt`/log/JSON of the error).

### Concurrency & Context (Go idiom — locked without a separate question)
- **D-05:** **`context.Context` first parameter on every I/O method.** `Login(ctx, …)`,
  `VerifyMfa(ctx, …)`, `Refresh(ctx, …)`, `Logout(ctx, …)`, `CheckAccess(ctx, …)`, `BatchCheck(ctx, …)`,
  `Consume(ctx, …)` — required by `grpc-go` and standard Go practice for cancellation/deadlines. The
  §9 single-flight refresh uses `sync.Mutex` (GO-01-pinned) shared across REST + gRPC on one session.

### Middleware (§10, `net/http`)
- **D-06:** **Identity injected via `context.WithValue`.** The `net/http` middleware
  (`func(next http.Handler) http.Handler`) verifies the session and injects the authenticated identity
  (`user_id`, `tenant_id`, `roles`) into the request context, retrieved with an exported
  `axiam.UserFromContext(ctx) (*User, bool)` helper. Verification is **local** via `jwx/v3` against the
  cached JWKS (no per-request server round-trip; honors §10's short-TTL cache rule) — mirrors Rust D-03.
  Surfaces `AuthError`→401 / `AuthzError`→403 with a standardized JSON error body.

### AMQP Consumer
- **D-07:** **Closure-handler `Consume`, return-err = requeue, sentinel/HMAC-fail = drop.**
  `Consume(ctx, queue string, handler func(ctx context.Context, e Event) error) error`, sequential per
  consumer with a **configurable prefetch (QoS)**. The SDK owns the ack/nack loop and performs §8
  HMAC-SHA256 verification **before** invoking the handler. Semantics:
  - handler returns `nil` → **ack**;
  - handler returns non-nil error → **nack WITH requeue** (transient/retryable, e.g. a downstream
    timeout gets redelivered);
  - handler returns the exported sentinel `amqp.ErrDrop` → **nack WITHOUT requeue** (poison message);
  - HMAC verification failure (before the handler ever runs) → **nack WITHOUT requeue** + security
    event log, and the handler never sees the message (§8 locked). Mirrors Rust D-07's closure model.

### Token Safety — `Sensitive` type
- **D-08:** **`type Sensitive string` redacting across String + Format + GoString + MarshalJSON.**
  §7's floor is `String() → "[SENSITIVE]"`; the ceiling pinned here **also** implements
  `Format(fmt.State, rune)` (covers `%v`/`%+v`/`%s`/`%q`), `GoString()` (covers `%#v`), and
  `MarshalJSON()` — all emit `[SENSITIVE]`. This closes the `fmt`-verb, struct-logging, and
  JSON-encoding leak paths (the CR-04 leak class), not just direct stringification. The raw value is
  reachable only via a **package-internal accessor**, never a public getter. Go analog of TS D-26.

### Client Override Safety
- **D-09:** **SDK always owns the cookie jar + TLS; `WithHTTPClient` overrides transport/timeouts
  only.** Ship sane defaults (builder-overridable), then: `WithHTTPClient` may set the `Transport`/
  timeout, but the SDK **re-applies its own `cookiejar` (§4) and TLS config (§6) over any supplied
  client** so an override can never silently drop the jar (which would break every post-login request)
  or bypass TLS verification. Full client replacement was rejected for pushing safety-critical
  invariants onto the caller.

### Examples & Testing
- **D-10:** **Per-capability example `main` packages; mocked units + optional testcontainers smoke.**
  `examples/` holds separate `main` packages per capability (login+MFA, `CheckAccess`+`BatchCheck`+`Can`,
  gRPC `CheckAccess`, AMQP consumer, `net/http` middleware) — mirroring the Rust example set and
  doubling as the §1–§10 conformance demonstration. Deterministic tests (SC#2 `sync.Mutex` single-flight
  **table-driven** test, §8 HMAC verify, D-04 error redaction, the SC#3 `InsecureSkipVerify` grep gate)
  run against **mocked interfaces / `httptest`** so `go test ./...` stays fast and hermetic. gRPC + AMQP
  get an **optional, build-tagged testcontainers smoke test** against a real AXIAM server in CI — never
  part of the default `go test ./...` run (keeps the concurrency test deterministic).

### Carried Forward from the Rust/TS References — apply unless research contradicts
- **CF-01 (Rust D-12 / TS CF-01):** Bounded backoff, **idempotent operations only** — auto-retry only
  read-only ops (GET / read-only authz checks) for transient `NetworkError` (timeouts, gRPC
  `UNAVAILABLE`), honor `Retry-After` on 429, exponential backoff + jitter, small max-attempt cap
  (~2–3). State-changing requests never auto-retry. Contract auth-retry bars remain in force.
- **CF-02 (Rust D-13 / TS CF-02):** Observability = **injectable, redaction-aware logger, OFF by
  default** (Go analog of the optional consumer-supplied logger; e.g. accept a `slog.Logger` via an
  option). Never emit token values (respect `Sensitive`).
- **CF-03 (Rust D-14 / TS CF-03):** Sane connect/request **timeouts (option-overridable, per D-09)**;
  `amqp091-go` auto-reconnect with exponential backoff+jitter; `baseURL` required. Exact numeric values
  = research/planner.
- **CF-04 (TS D-18):** **`Login` returns a typed result discriminating MFA-required from
  authenticated** (Go idiom: a `LoginResult` struct with an `MFARequired bool` + `MFAToken Sensitive`,
  or a small result type the caller switches on) — the MFA requirement is an expected outcome, not an
  error. Then `VerifyMfa(ctx, mfaToken, code)`.

### Claude's Discretion
- Exact internal package/file layout (`rest`/`grpc`/`amqp`/`auth`/`middleware`/`internal/gen`), the
  `Sensitive` internal-accessor naming, and single-flight guard internals — planner's call within the
  locked contract.
- Concrete numeric timeout/backoff/retry values and default prefetch/QoS count (CF-01, CF-03, D-07).
- The precise `LoginResult` shape (struct vs small union) for CF-04.
- Exact `jwx/v3` API usage for JWKS caching + rotation (D-06) — research selects within the stated
  shape (must support EdDSA/Ed25519 and unknown-`kid` refetch).
- Go version floor (`go.mod` currently `go 1.22`) and whether to bump for a dependency floor — planner,
  CI-enforced like Rust D-10.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Binding contract & phase definition (read FIRST)
- `sdks/CONTRACT.md` §1–§10 — **normative/binding** cross-language behavioral contract. The Go SDK
  *implements* this. Relevant §: §1 PascalCase method map (`Login`/`VerifyMfa`/`Refresh`/`Logout`/
  `CheckAccess`+`Can`/`BatchCheck`), §2 error taxonomy + HTTP/gRPC status mapping (D-04), §3 CSRF
  (**Go = non-browser → capture `X-CSRF-Token` from response header**, §3.1/3.4), §4 cookie jar
  (`net/http/cookiejar`, D-09), §5 tenant context (D-03), §6 TLS/`WithCustomCA` (D-03/D-09; the SC#3
  no-`InsecureSkipVerify` gate), §7 `Sensitive` (D-08), §8 AMQP HMAC protocol (D-07), §9 single-flight
  refresh (`sync.Mutex`), §10 middleware interface (`net/http`, D-06). Go example builder pattern is
  shown in §6 (`client.WithCustomCA(pemBytes)`). C# `Grpc.Tools` exception in the closing notes is the
  precedent for D-01's Go codegen exception.
- `.planning/ROADMAP.md` — Phase 18 goal + 5 success criteria; the `sdks/<lang>/vX.Y.Z` tag convention
  (Phase 15 D-13) the publish CI follows.
- `.planning/REQUIREMENTS.md` §GO-01 — acceptance criteria + pinned deps. **NOTE the stale module path
  / tag** (`github.com/axiam/axiam-go-sdk`, `sdk/go/vX.Y.Z`) — see Deferred; the scaffold is canonical.

### Prior-phase decisions this phase inherits
- `.planning/phases/16-rust-sdk/16-CONTEXT.md` — the **first reference implementation**. D-03/D-11
  (local JWKS, OIDC discovery + rotation → D-06), D-04 (shared channel + interceptor → the gRPC auth
  pattern), D-06 (single error enum → Go typed structs D-04), D-07 (closure-handler AMQP → D-07),
  D-09 (regenerate-and-bundle publish → D-01's Go variant: commit-and-drift-check), D-12 (retry →
  CF-01), D-13 (tracing off → CF-02), D-14 (defaults → CF-03).
- `.planning/phases/17-typescript-sdk/17-CONTEXT.md` — second reference. D-16/D-17 (typed error classes
  + central status mapper → D-04), D-18 (discriminated login result → CF-04), D-26 (`Sensitive`
  multi-surface redaction → D-08), D-20/D-21 (regenerate-and-bundle publish, tag-triggered → D-01/publish).
- `.planning/phases/17-typescript-sdk/17-REVIEW.md` §CR-04 + `17-VERIFICATION.md` — the **token-leak-via-
  error-`cause`** finding and its `sanitizeAxiosError()` fix. **D-04's redact-before-wrap is the direct
  Go carry-forward of this fix.** Read CR-04 before implementing `NetworkError`.
- `.planning/phases/15-sdk-foundation/15-CONTEXT.md` — D-01 (generate-on-build; **D-01 here is the
  documented Go exception**), D-02 (buf codegen pipeline), D-05 (FND-04 `/authz/check` + `/batch`),
  D-09/D-10 (binding contract + locked vocabulary), D-11/D-12/D-13 (package identities + monorepo tag
  scheme `sdks/go/vX.Y.Z`).

### SDK domain research (read for rationale)
- `.planning/research/ARCHITECTURE.md` — codegen source-of-truth, monorepo + path-filtered CI.
- `.planning/research/STACK.md` — buf toolchain + plugin set (protoc-gen-go / protoc-gen-go-grpc for Go).
- `.planning/research/PITFALLS.md` — cross-language divergence trap + the **TLS-bypass pitfall**
  (`InsecureSkipVerify`/`WithInsecure`/`TrustAllCerts` lint patterns, lines 167/183/366 → SC#3 gate).
- `.planning/research/FEATURES.md` — per-SDK feature matrix.
- `.planning/research/SUMMARY.md` — consolidated research synthesis (TLS-disabled anti-pattern, line 139).

### Code the SDK consumes / mirrors (reuse semantics; do NOT depend on server crates)
- `crates/axiam-amqp/src/messages.rs` — **AMQP HMAC reference impl** (§8): `sign_payload`,
  `verify_payload` (constant-time), canonical-JSON + hex-HMAC-SHA256 protocol the Go verify (D-07) must
  match byte-for-byte (use `crypto/hmac` + `hmac.Equal` for constant-time compare).
- `sdks/rust/src/` — the Rust reference tree (`token/`, `grpc/interceptor.rs`, `amqp/consumer.rs`,
  `middleware/actix.rs`, `sensitive.rs`) — structural analogs for the Go packages.
- `sdks/typescript/src/core/errorMapper.ts` (`sanitizeAxiosError`) + `core/sensitive.ts` — the TS
  redaction implementations D-04/D-08 mirror in Go.
- `proto/axiam/v1/authorization.proto`, `user.proto`, `token.proto` — proto surface the Go stubs cover;
  `CheckAccess`/`BatchCheckAccess` request/response shapes for the gRPC client.
- `crates/axiam-api-grpc/src/services/authorization.rs` — gRPC `check_access`/`batch_check_access`
  semantics the Go gRPC client targets.
- REST `POST /api/v1/authz/check` + `/api/v1/authz/check/batch` (Phase 15 FND-04,
  `crates/axiam-api-rest/src/handlers/authz_check.rs`) — the endpoints `CheckAccess`/`Can`/`BatchCheck`
  call.
- `sdks/buf.gen.yaml` — buf codegen config; add/confirm the Go plugin entry driving D-01's committed
  stubs.
- `sdks/go/{go.mod,README.md,LICENSE}` — existing scaffold (module `github.com/ilpanich/axiam/sdks/go`,
  `go 1.22`, tag convention `sdks/go/vX.Y.Z`, README states CONTRACT.md conformance) — Phase 18 fills it in.
- OIDC `/.well-known/jwks.json` (exact path to confirm in research) — JWKS source for D-06.

### Project-wide constraints
- License is **Apache-2.0** repo-wide — `sdks/go/LICENSE` already matches; keep it (do not trust the
  stale workspace `Cargo.toml` license field); see project memory `project_license_apache.md`.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `sdks/rust/` (Phase 16) and `sdks/typescript/` (Phase 17) — two complete reference implementations of
  the same contract; the Go SDK ports their structure (session + single-flight guard, gRPC interceptor,
  closure-handler AMQP consumer, JWKS cache, middleware) into idiomatic Go rather than reinventing.
- `sdks/typescript/src/core/errorMapper.ts` `sanitizeAxiosError()` — the exact redaction the Go
  `NetworkError` constructor mirrors (D-04 / CR-04 carry-forward).
- `crates/axiam-amqp/src/messages.rs` — canonical HMAC sign/verify; the Go consumer reimplements
  *verification* (cannot depend on the crate) but the canonical-JSON + hex-HMAC-SHA256 protocol must be
  byte-identical (§8 / D-07); use `crypto/hmac` + `hmac.Equal`.
- `sdks/buf.gen.yaml` + `proto/axiam/v1/*.proto` — the codegen pipeline (Phase 15); D-01 commits the
  Go stubs generated from it into `sdks/go/` with a CI drift-check.
- `sdks/go/` scaffold (`go.mod`, LICENSE, README stating CONTRACT.md conformance) — Phase 18 fills it in.

### Established Patterns
- **CONTRACT.md is binding (Phase 15 D-09):** "CONTRACT.md §1–§10 conformance verified" is a required
  acceptance checklist item for this phase.
- **No TLS bypass (§6 / SC#3):** the SDK exposes only `WithCustomCA`; a CI `grep -rn 'InsecureSkipVerify'
  sdks/go/` gate MUST return empty. Extend the pitfall lint to `WithInsecure`/`TrustAllCerts` too.
- **Additive-only / allow-wins / default-deny RBAC** constrains how the SDK surfaces authz `reason`
  semantics (mirrors gRPC).
- **Monorepo tag release** (`sdks/go/vX.Y.Z`, Phase 15 D-13) — the publish CI follows it.
- **Codegen distribution differs by ecosystem:** Rust/TS bundle stubs into a build artifact; Go has no
  such artifact (`go get` = source), so D-01 commits them + drift-checks — the documented Go exception.

### Integration Points
- New `sdks/go/` source tree (REST core at module root + `grpc`/`amqp`/`auth`/`middleware` sub-packages
  + `internal/gen` committed stubs + `examples/` main packages).
- New per-SDK GitHub Actions workflow under `.github/workflows/` with `paths: sdks/go/**` filter:
  `go test ./...` + `go vet` + the `InsecureSkipVerify` grep gate + the buf drift-check (D-01) +
  tag-triggered module publish (`sdks/go/vX.Y.Z`, SC#5).
- Committed Go stubs generated from `proto/axiam/v1/` via buf into `sdks/go/internal/gen`.

</code_context>

<specifics>
## Specific Ideas

- The Go SDK is the **second server-side reference** — decisions favor idiomatic Go that other future
  consumers recognize instantly (functional options, `errors.As`, `context.Context`-first, `sync.Mutex`
  single-flight) while staying byte-faithful to the shared contract.
- Success-criterion proof points to preserve as concrete tests: (#1) `go get …/sdks/go` installs +
  `net/http` middleware example compiles + `tenantSlug` required at call time; (#2) 5 concurrent
  goroutines on an expired token ⇒ **exactly 1 refresh** (table-driven `sync.Mutex` single-flight test);
  (#3) `grep -rn 'InsecureSkipVerify' sdks/go/` → empty (CI gate); (#4) AMQP consumer HMAC-verifies each
  body, **nacks WITHOUT requeue** on mismatch; (#5) `go test ./...` passes + tag `sdks/go/vX.Y.Z`
  publishes.
- **CR-04 must not recur in Go:** never wrap a raw `*http.Response`/transport error carrying
  `Set-Cookie`/`Authorization` into `NetworkError` without redacting first (D-04). Add a Go regression
  test analogous to TS `errorRedaction.test.ts` (assert the raw `axiam_access`/`axiam_refresh` value
  never appears in `%v`/`%+v`/`%#v`/`json.Marshal` of a thrown error, with a control case proving the
  test is non-vacuous).

</specifics>

<deferred>
## Deferred Ideas

- **REQUIREMENTS GO-01 module-path / tag reconciliation** — GO-01 reads module
  `github.com/axiam/axiam-go-sdk` + tag `sdk/go/vX.Y.Z`, but the actual scaffold (canonical) is
  `github.com/ilpanich/axiam/sdks/go` + tag `sdks/go/vX.Y.Z` (correct per Phase 15 D-13 and SC#1).
  GO-01's wording is stale. **Planner should reconcile REQUIREMENTS.md GO-01 to the scaffold** (a scoped
  doc edit) rather than silently diverging. **Do not lose.**
- **Split per-transport modules** — considered (D-02) for minimal REST-only module graphs; rejected as
  un-idiomatic and tag-heavy. Revisit only if a consumer's module-graph size becomes a real complaint.
- **Blocking-only (no `context.Context`) surface** — never on the table for Go; noted for completeness
  (ctx-first is non-negotiable idiom, D-05).
- **Mandatory testcontainers integration in `go test ./...`** — considered (D-10); kept optional/
  build-tagged to preserve deterministic, Docker-free default test runs.
- **Automated cross-language conformance harness** — inherited from Phase 15/16/17 deferred list; Phase
  18 verifies conformance via its own §1–§10 checklist, not a mechanical suite.

### Reviewed Todos (not folded)
None — no pending todos matched this phase.

</deferred>

---

*Phase: 18-go-sdk*
*Context gathered: 2026-07-01*
