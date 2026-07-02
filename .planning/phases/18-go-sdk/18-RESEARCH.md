# Phase 18: Go SDK - Research

**Researched:** 2026-07-01
**Domain:** Go SDK implementation of `sdks/CONTRACT.md` — REST + gRPC + AMQP, idiomatic Go
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Codegen Distribution (the real conflict with Phase 15 D-01)**
- **D-01:** Committed gRPC stubs + CI drift-check. The buf-generated `.pb.go` / `_grpc.pb.go`
  files are committed into the `sdks/go/` source tree (e.g. `sdks/go/internal/gen`). Rationale:
  `go get` fetches source from the git tag and consumers cannot run buf, so the stubs MUST be
  present in the tree — there is no separate build artifact to bundle into (unlike Rust crates.io
  / npm tarball). Go is therefore the documented codegen-distribution exception to Phase 15 D-01's
  generate-on-build/gitignore model (analogous to C#'s documented `Grpc.Tools` exception in
  CONTRACT.md closing notes). A CI job regenerates the stubs with the pinned buf config and runs
  `git diff --exit-code` to block staleness/drift — committed stubs must always match the protos.

**Module Partitioning (Go analog of Rust Cargo features / TS subpaths)**
- **D-02:** Single module, sub-packages. One module `github.com/ilpanich/axiam/sdks/go` (matches
  the existing scaffold `go.mod`) with sub-packages: the module root for the REST core, `.../grpc`,
  and `.../amqp`. Go compiles only imported packages into a consumer binary, so a REST-only
  consumer never compiles `grpc-go`/`amqp091-go` into their binary — the only cost is extra entries
  in the module graph (`go.sum`), not binary bloat. One version tag covers the whole SDK.

**Client API Idiom**
- **D-03:** Functional options; required params positional.
  `NewClient(baseURL, tenantSlug string, opts ...Option) (*Client, error)`. `baseURL` and
  `tenantSlug` are positional/required — compile-time enforcement of §5 (tenant required) and
  SC#1 ("`tenantSlug` enforced at call time"). Optional config via functional options:
  `WithCustomCA([]byte)` (the §6-only TLS escape hatch), `WithTimeout(time.Duration)`,
  `WithHTTPClient(*http.Client)`.

**Error Model**
- **D-04:** Typed error structs + `errors.As`, redact-before-wrap. Three exported struct types
  `AuthError` / `AuthzError` / `NetworkError`, each implementing `error` (§2). Discriminate via
  `errors.As(err, &AuthError{})`; sentinel vars (`ErrAuth`/`ErrAuthz`/`ErrNetwork`) also provided
  for `errors.Is` convenience. `AuthzError` carries optional `Action`/`ResourceID` (§2 construction
  rule). `NetworkError` exposes `Unwrap()` for the transport cause BUT its constructor first
  redacts `Set-Cookie`/`Authorization`/`Cookie` headers from any wrapped `*http.Response`/error —
  a direct Phase 17 CR-04 carry-forward (raw session/refresh tokens must never enter the error
  chain, since a 4xx alongside a fresh `Set-Cookie` would otherwise leak the token via `fmt`/log/
  JSON of the error).

**Concurrency & Context (Go idiom — locked without a separate question)**
- **D-05:** `context.Context` first parameter on every I/O method. `Login(ctx, …)`,
  `VerifyMfa(ctx, …)`, `Refresh(ctx, …)`, `Logout(ctx, …)`, `CheckAccess(ctx, …)`,
  `BatchCheck(ctx, …)`, `Consume(ctx, …)`. The §9 single-flight refresh uses `sync.Mutex`
  (GO-01-pinned) shared across REST + gRPC on one session.

**Middleware (§10, `net/http`)**
- **D-06:** Identity injected via `context.WithValue`. The `net/http` middleware
  (`func(next http.Handler) http.Handler`) verifies the session and injects the authenticated
  identity (`user_id`, `tenant_id`, `roles`) into the request context, retrieved with an exported
  `axiam.UserFromContext(ctx) (*User, bool)` helper. Verification is local via `jwx/v3` against the
  cached JWKS (no per-request server round-trip; honors §10's short-TTL cache rule) — mirrors Rust
  D-03. Surfaces `AuthError`→401 / `AuthzError`→403 with a standardized JSON error body.

**AMQP Consumer**
- **D-07:** Closure-handler `Consume`, return-err = requeue, sentinel/HMAC-fail = drop.
  `Consume(ctx, queue string, handler func(ctx context.Context, e Event) error) error`, sequential
  per consumer with a configurable prefetch (QoS). The SDK owns the ack/nack loop and performs §8
  HMAC-SHA256 verification before invoking the handler. Semantics:
  - handler returns `nil` → ack;
  - handler returns non-nil error → nack WITH requeue (transient/retryable);
  - handler returns the exported sentinel `amqp.ErrDrop` → nack WITHOUT requeue (poison message);
  - HMAC verification failure (before the handler ever runs) → nack WITHOUT requeue + security
    event log, and the handler never sees the message (§8 locked).

**Token Safety — `Sensitive` type**
- **D-08:** `type Sensitive string` redacting across String + Format + GoString + MarshalJSON.
  §7's floor is `String() → "[SENSITIVE]"`; the ceiling pinned here also implements
  `Format(fmt.State, rune)` (covers `%v`/`%+v`/`%s`/`%q`), `GoString()` (covers `%#v`), and
  `MarshalJSON()` — all emit `[SENSITIVE]`. The raw value is reachable only via a
  package-internal accessor, never a public getter.

**Client Override Safety**
- **D-09:** SDK always owns the cookie jar + TLS; `WithHTTPClient` overrides transport/timeouts
  only. Ship sane defaults (builder-overridable), then: `WithHTTPClient` may set the
  `Transport`/timeout, but the SDK re-applies its own `cookiejar` (§4) and TLS config (§6) over any
  supplied client so an override can never silently drop the jar or bypass TLS verification.

**Examples & Testing**
- **D-10:** Per-capability example `main` packages; mocked units + optional testcontainers smoke.
  `examples/` holds separate `main` packages per capability (login+MFA, `CheckAccess`+
  `BatchCheck`+`Can`, gRPC `CheckAccess`, AMQP consumer, `net/http` middleware). Deterministic
  tests (SC#2 `sync.Mutex` single-flight table-driven test, §8 HMAC verify, D-04 error redaction,
  the SC#3 `InsecureSkipVerify` grep gate) run against mocked interfaces / `httptest` so
  `go test ./...` stays fast and hermetic. gRPC + AMQP get an optional, build-tagged testcontainers
  smoke test — never part of the default `go test ./...` run.

**Carried Forward from the Rust/TS References — apply unless research contradicts**
- **CF-01:** Bounded backoff, idempotent operations only — auto-retry only read-only ops
  (GET / read-only authz checks) for transient `NetworkError` (timeouts, gRPC `UNAVAILABLE`),
  honor `Retry-After` on 429, exponential backoff + jitter, small max-attempt cap (~2–3).
  State-changing requests never auto-retry.
- **CF-02:** Observability = injectable, redaction-aware logger, OFF by default (accept a
  `slog.Logger` via an option). Never emit token values (respect `Sensitive`).
- **CF-03:** Sane connect/request timeouts (option-overridable, per D-09); `amqp091-go`
  auto-reconnect with exponential backoff+jitter; `baseURL` required. Exact numeric values =
  research/planner (resolved below).
- **CF-04:** `Login` returns a typed result discriminating MFA-required from authenticated (a
  `LoginResult` struct with an `MFARequired bool` + `MFAToken Sensitive`, or a small result type
  the caller switches on). Then `VerifyMfa(ctx, mfaToken, code)`.

### Claude's Discretion
- Exact internal package/file layout (`rest`/`grpc`/`amqp`/`auth`/`middleware`/`internal/gen`), the
  `Sensitive` internal-accessor naming, and single-flight guard internals.
- Concrete numeric timeout/backoff/retry values and default prefetch/QoS count (CF-01, CF-03, D-07)
  — resolved in this research (see Common Pitfalls / Code Examples).
- The precise `LoginResult` shape (struct vs small union) for CF-04 — resolved below (mirrors Rust
  `LoginResult` struct shape, adapted to Go idiom).
- Exact `jwx/v3` API usage for JWKS caching + rotation (D-06) — resolved below.
- Go version floor (`go.mod` currently `go 1.22`) and whether to bump for a dependency floor —
  resolved below (keep 1.22; no dependency in this phase requires newer).

### Deferred Ideas (OUT OF SCOPE)
- **REQUIREMENTS GO-01 module-path / tag reconciliation** — GO-01 reads module
  `github.com/axiam/axiam-go-sdk` + tag `sdk/go/vX.Y.Z`, but the actual scaffold (canonical) is
  `github.com/ilpanich/axiam/sdks/go` + tag `sdks/go/vX.Y.Z`. GO-01's wording is stale. Planner
  should reconcile REQUIREMENTS.md GO-01 to the scaffold (a scoped doc edit) rather than silently
  diverging. Do not lose.
- **Split per-transport modules** — rejected (D-02); revisit only if a consumer's module-graph
  size becomes a real complaint.
- **Blocking-only (no `context.Context`) surface** — never on the table for Go.
- **Mandatory testcontainers integration in `go test ./...`** — kept optional/build-tagged.
- **Automated cross-language conformance harness** — Phase 18 verifies conformance via its own
  §1–§10 checklist, not a mechanical suite.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| GO-01 | Deliver `sdks/go/` (second server-side reference): full SDK Capability Baseline; `sync.Mutex` single-flight refresh; `net/http/cookiejar`; net/http REST + grpc-go 1.81 + amqp091-go 1.10; lestrrat-go/jwx/v3 for EdDSA/JWKS; no `InsecureSkipVerify` anywhere (CI lint gate); net/http middleware; examples; Go module publish. | This document — Standard Stack (verified versions), Architecture Patterns (package layout, functional options, error taxonomy), Code Examples (JWKS verifier, gRPC TLS+interceptor, AMQP consumer, Sensitive type), Common Pitfalls (grpc.NewClient vs Dial, NotifyClose deadlock, org_id requirement, CSRF header capture), Validation Architecture (test-to-requirement map), Security Domain (ASVS mapping) |
</phase_requirements>

## Summary

Phase 18 ports the proven Rust (Phase 16) and TypeScript (Phase 17) reference SDK patterns into
idiomatic Go. All three pinned dependencies — `google.golang.org/grpc@v1.81.x`,
`github.com/rabbitmq/amqp091-go@v1.10.0`, `github.com/lestrrat-go/jwx/v3@latest (v3.1.x)` — were
directly confirmed against the official Go module proxy (`proxy.golang.org`) with legitimate
GitHub source origins (`grpc/grpc-go`, `rabbitmq/amqp091-go`, `lestrrat-go/jwx`), so all three are
`[VERIFIED: Go module proxy]`. The behavioral surface (method names, error taxonomy, CSRF, cookie
jar, tenant context, TLS policy, `Sensitive` redaction, AMQP HMAC, single-flight refresh,
middleware) is already locked by `sdks/CONTRACT.md` §1–§10 and by the 10 CONTEXT.md decisions
above; this research resolves the Go-toolchain-specific HOW that the Rust/TS references never
faced.

Three findings materially affect planning beyond what CONTEXT.md anticipated. First, the
**JWKS endpoint is `{baseURL}/oauth2/jwks`** — organization-wide, not tenant-scoped, serving
exactly one Ed25519 key today — confirmed by direct codebase inspection of both prior SDKs and
`server.rs`'s route table; do not substitute a generic `/.well-known/jwks.json` path. Second,
`buf.gen.yaml`'s existing Go plugin entries output to `go/gen` (relative to `sdks/`), which
resolves to `sdks/go/gen` — this must be corrected or the buf config's `out:` must be updated to
`sdks/go/internal/gen` to match D-01's committed-stub location; **this is a Wave-0 config fix, not
an assumption to carry silently**. Third, and highest-impact: the real
`POST /api/v1/auth/login` and `POST /api/v1/auth/refresh` endpoints require an `org_id`/`org_slug`
beyond what CONTRACT.md §5 documents (organizations are the top-level multi-tenant entity above
tenants per CLAUDE.md's domain model) — the Rust SDK's `client.rs` already documents this as a
deliberate deviation from the contract's stated minimum. The Go SDK MUST add an optional
`WithOrgSlug`/`WithOrgID` functional option and resolve/cache the org UUID from the access token's
`org_id` claim after first login, exactly mirroring the Rust pattern, or `Login`/`Refresh` will not
work against the real server.

For the Go-specific toolchain unknowns: `jwx/v3`'s `jwk.Cache` (constructed with `jwk.NewCache(ctx,
httprc.Client)`) plus `Register`/`Refresh`/`CachedSet` gives the JWKS caching + forced-refetch-on-
unknown-`kid` behavior the Rust SDK hand-rolled with `RwLock`+`Instant`; `jws.Verify(buf,
jws.WithKeySet(keySet, jws.WithInferAlgorithmFromKey(true)))` is the v3 verification call, and the
explicit-algorithm-allowlist requirement (never trust the token's own `alg` header) is satisfied by
checking the JWS protected header's `alg` before calling `Verify`, matching the Rust/TS pattern of
rejecting non-EdDSA headers up front. `grpc-go` 1.81's modern client construction is
`grpc.NewClient(target, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
grpc.WithUnaryInterceptor(...))` — NOT the deprecated `grpc.Dial`/`grpc.WithInsecure`, and this
distinction matters directly for SC#3 (the `InsecureSkipVerify` grep gate would not catch a
`WithInsecure()` gRPC dial option, so the CI grep pattern list must be extended, per D-09/§6).
`amqp091-go`'s `Channel.Qos(prefetchCount, prefetchSize, global)` plus `Connection.NotifyClose(chan
*Error)` give the QoS-prefetch and reconnect-detection primitives CF-03 requires; `NotifyClose`
only fires on abnormal closure and the receiving channel MUST be buffered (capacity ≥1) or the
library's synchronous send-then-close deadlocks the connection goroutine.

**Primary recommendation:** Port the Rust reference's module boundaries 1:1 into Go sub-packages
(root=REST+core, `grpc/`, `amqp/`, `middleware/`), reuse its exact numeric defaults (10s connect /
30s request timeout, 300s JWKS TTL, 60s forced-refetch cooldown, 3-attempt bounded backoff), add
the org_id/org_slug functional options the real login/refresh endpoints require, fix `buf.gen.yaml`'s
Go output path to `sdks/go/internal/gen` in Wave 0, and extend the CI TLS-bypass grep gate beyond
`InsecureSkipVerify` to also catch `WithInsecure(` and `grpc.WithTransportCredentials(insecure.NewCredentials())`.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Login / MFA / Refresh / Logout (REST) | API / Backend (consumed) | — | SDK is a pure external client; server owns auth state, SDK only orchestrates the HTTP calls + cookie jar |
| Token cache + single-flight refresh | SDK (client-side library) | — | In-process state per `*Client` instance; not a server responsibility |
| Local JWT/JWKS verification (proactive refresh + middleware) | SDK (client-side library) | API / Backend (JWKS source of truth) | SDK caches and verifies locally to avoid a server round-trip per request (§10); server remains the signing authority |
| `CheckAccess`/`BatchCheck`/`Can` (gRPC + REST) | API / Backend (consumed) | SDK (client wrapper) | Authorization decision is always computed server-side by `AuthzChecker`; SDK is a thin typed wrapper over gRPC/REST |
| AMQP event consumption + HMAC verify | SDK (client-side library) | Message Broker (RabbitMQ, external) | SDK owns the ack/nack loop and signature verification before any user handler runs; broker is external infra, not part of this phase |
| `net/http` middleware / route-guard | SDK (client-side library) | — | Runs inside the *consumer's* Go process, wrapping their own handlers — not the AXIAM server |
| gRPC codegen (`.pb.go`/`_grpc.pb.go` stubs) | Build/CI tooling | SDK source tree (committed) | Go has no build-time codegen step for `go get` consumers (source-only distribution) — stubs must be committed, generated by a separate CI drift-check job |
| Go module publish (tag → proxy.golang.org) | CI/CD | — | Tag-triggered; the Go module proxy has no manual publish step, unlike npm/crates.io/PyPI |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `net/http` + `net/http/cookiejar` | stdlib (go 1.22) | REST transport, cookie persistence | Contract §4 mandates a persistent cookie jar; stdlib is idiomatic and has zero extra deps |
| `google.golang.org/grpc` | v1.81.0/v1.81.1 `[VERIFIED: Go module proxy]` | gRPC transport for `CheckAccess`/`BatchCheckAccess` | GO-01-pinned; official gRPC Go implementation, confirmed on proxy.golang.org with source at `github.com/grpc/grpc-go` |
| `github.com/rabbitmq/amqp091-go` | v1.10.0 `[VERIFIED: Go module proxy]` | AMQP 0-9-1 client for event consumption | GO-01-pinned; official RabbitMQ-maintained Go client (successor to `streadway/amqp`), confirmed on proxy.golang.org with source at `github.com/rabbitmq/amqp091-go` |
| `github.com/lestrrat-go/jwx/v3` | v3.1.1 (latest; module in active development, v3.0.0 GA→v3.1.1 as of this research) `[VERIFIED: Go module proxy]` | JWKS fetch/cache + EdDSA/Ed25519 JWT verification | GO-01-pinned; most complete pure-Go JOSE/JWX implementation, RFC 9864-compliant EdDSA support in v3, confirmed on proxy.golang.org with source at `github.com/lestrrat-go/jwx` |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `crypto/hmac` + `crypto/sha256` (stdlib) | go 1.22 | HMAC-SHA256 AMQP message signing/verification | §8's canonical protocol — always, no third-party HMAC lib needed; `hmac.Equal` is the constant-time comparator |
| `log/slog` (stdlib) | go 1.22 | Injectable, redaction-aware logger (CF-02) | Optional `WithLogger(*slog.Logger)` client option, OFF by default |
| `google.golang.org/protobuf` (transitive via buf-generated stubs) | matches grpc-go's pinned version | Protobuf runtime for generated `.pb.go` types | Pulled in automatically by the committed gRPC stubs (D-01); do not hand-pin separately, let `go.sum` resolve it |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `net/http` stdlib REST client | `resty`/`go-resty` or similar HTTP wrapper libs | Rejected: CONTRACT.md §4/§6/§9 require precise cookie-jar and TLS-config control the SDK must own outright; a wrapper library adds an unnecessary dependency and an extra layer to audit for TLS-bypass footguns (SC#3) |
| `lestrrat-go/jwx/v3` | `golang-jwt/jwt/v5` + manual JWKS fetch/cache | Rejected: GO-01 pins `jwx/v3` specifically for its built-in `jwk.Cache` (auto-refresh + forced-refetch-on-unknown-kid), which `golang-jwt` does not provide out of the box — would require hand-rolling the same TTL+cooldown logic the Rust SDK already had to write manually |
| `amqp091-go` | `streadway/amqp` (predecessor) | Rejected: `streadway/amqp` is unmaintained (archived); `amqp091-go` is the RabbitMQ team's official fork/successor and is GO-01-pinned |

**Installation:**
```bash
cd sdks/go
go get google.golang.org/grpc@v1.81.0
go get github.com/rabbitmq/amqp091-go@v1.10.0
go get github.com/lestrrat-go/jwx/v3@v3.1.1
go get google.golang.org/protobuf@latest   # pulled transitively by grpc stubs; pin explicitly if `go mod tidy` under-resolves
```

**Version verification:** All three pinned dependencies were verified live against
`proxy.golang.org` in this research session via `go list -m -versions <module>` and
`go list -m -json <module>@<version>` (confirms VCS origin + tag + timestamp). Results:
- `google.golang.org/grpc@v1.81.0` — published 2026-05-04, origin `github.com/grpc/grpc-go`
  tag `refs/tags/v1.81.0`. `v1.81.1` also exists (patch release); either satisfies GO-01's "1.81" pin.
- `github.com/rabbitmq/amqp091-go@v1.10.0` — published 2024-05-08, origin
  `github.com/rabbitmq/amqp091-go` tag `refs/tags/v1.10.0`. Note: v1.12.0 is the current latest on
  the registry; GO-01 explicitly pins 1.10, which still resolves and is a valid, non-yanked version.
- `github.com/lestrrat-go/jwx/v3@v3.1.1` — published 2026-05-07, origin
  `github.com/lestrrat-go/jwx` tag `refs/tags/v3.1.1`. GO-01 pins "v3" generically (major version);
  use the latest v3.x patch (v3.1.1) unless a specific minor is later locked by the planner.

## Package Legitimacy Audit

> Note: `gsd-tools query package-legitimacy check` does not support the `go` ecosystem
> (only `npm|pypi|crates` are implemented in the current seam). All three packages below were
> instead verified directly against the authoritative Go module proxy (`go list -m -json
> <module>@<version>`), which returns the resolved VCS origin, commit hash, and git tag — a
> stronger signal than a registry-existence check alone, since it also confirms the module's
> source repository identity (not just that *a* package with that name exists).

| Package | Registry | Age | Downloads | Source Repo | Verdict | Disposition |
|---------|----------|-----|-----------|-------------|---------|-------------|
| `google.golang.org/grpc` | Go module proxy | 10+ years (v1.0.0 in registry history back to 2016) | N/A (Go proxy has no public download counter) | `github.com/grpc/grpc-go` — official gRPC org | OK | Approved |
| `github.com/rabbitmq/amqp091-go` | Go module proxy | v1.1.0 through v1.10.0+ (multi-year history) | N/A | `github.com/rabbitmq/amqp091-go` — official RabbitMQ org | OK | Approved |
| `github.com/lestrrat-go/jwx/v3` | Go module proxy | v3 line active since alpha releases through v3.1.1 (v1/v2 predate it for years) | N/A | `github.com/lestrrat-go/jwx` — long-standing, widely-used author (`lestrrat-go`) | OK | Approved |

**Packages removed due to [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

All three packages are GO-01-pinned (already locked by the requirement, not newly discovered by
this research), have multi-year commit/tag histories on the module proxy, and resolve to
well-known, actively-maintained GitHub organizations. No `[ASSUMED]` package-name risk applies
here since these were confirmed via direct registry query rather than WebSearch/training-data
recall alone — however, per the provenance rule, the *specific patch versions* recommended above
(v1.81.0, v1.10.0, v3.1.1) should still be re-verified by the planner/executor at implementation
time in case newer patches have shipped.

## Architecture Patterns

### System Architecture Diagram

```
Go consumer application
      │
      │ import "github.com/ilpanich/axiam/sdks/go"
      ▼
┌─────────────────────────────────────────────────────────────────┐
│ axiam.NewClient(baseURL, tenantSlug, opts...)                   │
│   ├─ http.Client{ Jar: cookiejar.New(nil), Transport: tlsConf } │
│   ├─ sync.Mutex-guarded token cache (access/refresh/exp)        │
│   └─ jwx/v3 jwk.Cache bound to {baseURL}/oauth2/jwks             │
└───────────────┬───────────────────┬──────────────────┬─────────┘
                │                   │                  │
        REST (root pkg)       grpc/ subpkg        amqp/ subpkg
                │                   │                  │
   Login/VerifyMfa/Refresh/   CheckAccess/       Consume(ctx, queue,
   Logout/CheckAccess/        BatchCheckAccess   handler) — owns
   Can/BatchCheck             (AuthInterceptor    ack/nack loop
                │              injects Bearer +          │
                │              x-tenant-id)               │
                ▼                   ▼                     ▼
   POST /api/v1/auth/*      grpc.NewClient(target,   amqp091-go Channel
   POST /api/v1/authz/*     credentials.NewTLS(...), .Consume(...) →
   (cookiejar carries        WithUnaryInterceptor)   verify HMAC-SHA256
    axiam_access/refresh)         │                   BEFORE handler runs
                │                  │                        │
                ▼                  ▼                        ▼
        AXIAM REST API      AXIAM gRPC AuthorizationService  RabbitMQ
        (Actix-Web)         (Tonic)                          (axiam.audit.events,
                │                                              axiam.authz.request)
                │
                ▼
   401 response ──► sync.Mutex single-flight Refresh()
                     (exactly 1 in-flight POST /api/v1/auth/refresh
                      across N concurrent goroutines) ──► retry once

Separately, inside the CONSUMER's own net/http server:
┌─────────────────────────────────────────────────────┐
│ axiamMiddleware(next http.Handler) http.Handler      │
│   1. extract Authorization: Bearer / cookie          │
│   2. verify locally via cached jwk.Cache (no server  │
│      round-trip on cache hit)                        │
│   3. context.WithValue(ctx, userKey, *User)          │
│   4. AuthError→401 / AuthzError→403 JSON body         │
│   5. next.ServeHTTP(w, r.WithContext(ctx))            │
└─────────────────────────────────────────────────────┘
```

### Recommended Project Structure
```
sdks/go/
├── go.mod                     # module github.com/ilpanich/axiam/sdks/go, go 1.22
├── client.go                  # NewClient, functional options, TenantIdentifier/OrgIdentifier
├── errors.go                  # AuthError/AuthzError/NetworkError, sentinels, status mappers
├── sensitive.go                # type Sensitive string + String/Format/GoString/MarshalJSON
├── login.go                   # Login/VerifyMfa/Refresh/Logout (REST auth flow, LoginResult)
├── authz.go                   # CheckAccess/Can/BatchCheck (REST authz-check, FND-04)
├── internal/
│   ├── gen/                   # D-01: committed buf-generated .pb.go / _grpc.pb.go stubs
│   ├── refreshguard/          # sync.Mutex single-flight refresh (§9)
│   └── jwks/                  # jwx/v3-backed JWKS cache + EdDSA verifier (shared by REST + middleware)
├── grpc/
│   ├── client.go               # grpc.NewClient + credentials.NewTLS + interceptor wiring
│   └── interceptor.go          # UnaryClientInterceptor: Bearer + x-tenant-id metadata injection
├── amqp/
│   ├── consumer.go             # Consume(ctx, queue, handler) — ack/nack loop, QoS, reconnect
│   ├── hmac.go                  # sign/verify mirroring crates/axiam-amqp/src/messages.rs byte-for-byte
│   └── errdrop.go               # var ErrDrop = errors.New(...) sentinel
├── middleware/
│   └── nethttp.go               # func Middleware(next http.Handler) http.Handler + UserFromContext
├── examples/
│   ├── login-mfa/main.go
│   ├── authz-check/main.go
│   ├── grpc-checkaccess/main.go
│   ├── amqp-consumer/main.go
│   └── middleware-guard/main.go
├── README.md                    # states "This SDK conforms to CONTRACT.md §1-§10."
└── LICENSE                      # Apache-2.0 (already present)
```

### Pattern 1: Functional Options with Positional Required Params (D-03)
**What:** Required params (`baseURL`, `tenantSlug`) are positional constructor arguments;
everything else is a `...Option`.
**When to use:** Client construction — compile-time enforcement that a tenant identifier cannot be
omitted (mirrors Rust's `build()`-time error, but Go achieves it at the type level since the
positional param cannot be skipped at a call site).
**Example:**
```go
// Source: pattern ported from sdks/rust/src/client.rs AxiamClientBuilder,
// adapted to Go idiom per D-03.
type Option func(*clientConfig)

func WithCustomCA(pem []byte) Option {
	return func(c *clientConfig) { c.customCAPEM = pem }
}

func WithTimeout(d time.Duration) Option {
	return func(c *clientConfig) { c.requestTimeout = d }
}

func WithHTTPClient(hc *http.Client) Option {
	return func(c *clientConfig) { c.baseHTTPClient = hc }
}

// Real login/refresh endpoints require an org identifier beyond §5's
// documented minimum (see Common Pitfalls #3) — mirrors Rust client.rs
// org_slug/org_id builder methods.
func WithOrgSlug(slug string) Option {
	return func(c *clientConfig) { c.org = orgIdentifier{slug: slug} }
}

func WithOrgID(id uuid.UUID) Option {
	return func(c *clientConfig) { c.org = orgIdentifier{id: &id} }
}

func NewClient(baseURL, tenantSlug string, opts ...Option) (*Client, error) {
	if tenantSlug == "" {
		return nil, &AuthError{Message: "tenantSlug is required — AXIAM is multi-tenant and there is no default tenant (CONTRACT.md §5)"}
	}
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}
	return buildClient(baseURL, tenantSlug, cfg)
}
```

### Pattern 2: `sync.Mutex` Single-Flight Refresh with Double-Check (§9, SC#2)
**What:** Exactly one in-flight `POST /api/v1/auth/refresh` call across N concurrent goroutines
observing the same expired access token.
**When to use:** Every 401 (REST) or `UNAUTHENTICATED` (gRPC) response triggers a call into this
guard.
**Example:**
```go
// Source: pattern ported from sdks/rust/src/token/refresh_guard.rs
// (tokio::sync::Mutex + double-check) — Go's sync.Mutex is synchronous so
// no async lock-await distinction is needed, simplifying the port.
type refreshGuard struct {
	mu      sync.Mutex
	access  Sensitive
	refresh Sensitive
	exp     int64
}

// RefreshIfNeeded performs at most one underlying HTTP refresh call across
// any number of concurrent callers that observed the same expired
// observedAccess token. doRefresh is invoked at most once.
func (g *refreshGuard) RefreshIfNeeded(ctx context.Context, observedAccess string, doRefresh func(ctx context.Context) (RefreshedTokens, error)) (Sensitive, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Double-check: another goroutine may have already refreshed while we
	// waited for the lock.
	if string(g.access) != "" && string(g.access) != observedAccess {
		return g.access, nil
	}

	tokens, err := doRefresh(ctx) // §9.3: no retry loop on failure — propagate as-is
	if err != nil {
		return "", err
	}
	g.access = tokens.Access
	if tokens.Refresh != "" {
		g.refresh = tokens.Refresh
	}
	g.exp = tokens.Exp
	return g.access, nil
}
```
**Test requirement (SC#2):** table-driven test firing 5 goroutines against a `httptest.Server` that
counts `/api/v1/auth/refresh` invocations; assert the counter equals exactly 1 after all 5
goroutines complete, using a `sync.WaitGroup` to synchronize the fan-out and an atomic counter on
the test server handler.

### Pattern 3: gRPC Auth Interceptor + Strict TLS (§5, §6, SC#3)
**What:** A `grpc.UnaryClientInterceptor` injecting `authorization: Bearer <token>` and
`x-tenant-id` metadata on every outgoing RPC, built on a `credentials.NewTLS` transport that never
exposes an insecure path.
**When to use:** `grpc.NewClient` construction in the `grpc/` sub-package.
**Example:**
```go
// Source: grpc-go credentials package docs (pkg.go.dev/google.golang.org/grpc/credentials)
// + interceptor pattern mirrored from sdks/rust/src/grpc/interceptor.rs
func newTLSCredentials(customCAPEM []byte) (credentials.TransportCredentials, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13} // project-wide TLS 1.3 minimum (CLAUDE.md)
	if len(customCAPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(customCAPEM) {
			return nil, &NetworkError{Message: "invalid custom CA PEM"}
		}
		tlsConfig.RootCAs = pool
	}
	// No InsecureSkipVerify field is ever set — SC#3's absolute prohibition.
	return credentials.NewTLS(tlsConfig), nil
}

func authUnaryInterceptor(tm *tokenManager, tenantID string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		token, ok := tm.CachedAccessToken() // non-blocking read, mirrors Rust Pitfall 3 — never lock the async refresh mutex synchronously here
		if !ok {
			return &AuthError{Message: "no cached access token"}
		}
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+string(token), "x-tenant-id", tenantID)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func NewGRPCClient(target string, creds credentials.TransportCredentials, interceptor grpc.UnaryClientInterceptor) (*grpc.ClientConn, error) {
	// grpc.NewClient (1.63+), NOT the deprecated grpc.Dial — see Common Pitfalls #1.
	return grpc.NewClient(target,
		grpc.WithTransportCredentials(creds),
		grpc.WithUnaryInterceptor(interceptor),
	)
}
```

### Pattern 4: Local JWKS Verification via `jwx/v3` (D-06, D-11 carry-forward)
**What:** A `jwk.Cache` bound to `{baseURL}/oauth2/jwks`, refreshed on a TTL and force-refetched on
an unknown `kid`, feeding `jws.Verify` for local (no-round-trip) token verification.
**When to use:** Proactive token-expiry checks and the `net/http` middleware (§10).
**Example:**
```go
// Source: pkg.go.dev/github.com/lestrrat-go/jwx/v3/jwk + jws docs (this research session)
// Endpoint confirmed via sdks/rust/src/token/jwks.rs, sdks/typescript/src/node/jwks.ts,
// and crates/axiam-api-rest/src/server.rs route table: {baseURL}/oauth2/jwks
// (organization-wide, NOT tenant-scoped, NOT a generic OIDC discovery path).
const jwksPath = "/oauth2/jwks"

type jwksVerifier struct {
	cache   *jwk.Cache
	jwksURL string
}

func newJWKSVerifier(ctx context.Context, baseURL string, hc *http.Client) (*jwksVerifier, error) {
	client := httprc.NewClient(httprc.WithHTTPClient(hc))
	cache, err := jwk.NewCache(ctx, client)
	if err != nil {
		return nil, err
	}
	jwksURL := strings.TrimRight(baseURL, "/") + jwksPath
	if err := cache.Register(ctx, jwksURL,
		jwk.WithMinInterval(60*time.Second),   // forced-refetch cooldown floor (CF-03)
		jwk.WithMaxInterval(300*time.Second),  // matches Rust JWKS_CACHE_TTL
	); err != nil {
		return nil, err
	}
	return &jwksVerifier{cache: cache, jwksURL: jwksURL}, nil
}

func (v *jwksVerifier) Verify(ctx context.Context, token []byte) (Claims, error) {
	// Reject non-EdDSA alg BEFORE any keyset lookup — defense against
	// algorithm-confusion attacks (mirrors Rust/TS behavior).
	msg, err := jws.Parse(token)
	if err != nil {
		return Claims{}, &AuthError{Message: "invalid token header"}
	}
	for _, sig := range msg.Signatures() {
		if sig.ProtectedHeaders().Algorithm() != jwa.EdDSA() {
			return Claims{}, &AuthError{Message: "unexpected alg: only EdDSA is accepted"}
		}
	}

	keySet, err := v.cache.CachedSet(v.jwksURL)
	if err != nil {
		return Claims{}, &NetworkError{Message: "JWKS fetch failed", cause: err}
	}
	payload, err := jws.Verify(token, jws.WithKeySet(keySet, jws.WithInferAlgorithmFromKey(true)))
	if err != nil {
		// Unknown kid → forced refetch once, then retry verification.
		if _, rerr := v.cache.Refresh(ctx, v.jwksURL); rerr == nil {
			refreshed, _ := v.cache.CachedSet(v.jwksURL)
			if payload, err = jws.Verify(token, jws.WithKeySet(refreshed, jws.WithInferAlgorithmFromKey(true))); err == nil {
				return parseClaims(payload)
			}
		}
		return Claims{}, &AuthError{Message: "token signature invalid"}
	}
	return parseClaims(payload)
}
```

### Pattern 5: AMQP Consumer — HMAC-Verify-Before-Handler (§8, D-07, SC#4)
**What:** The SDK owns the ack/nack loop; every delivery is HMAC-SHA256-verified before the
caller's handler closure ever runs.
**When to use:** `amqp.Consume(ctx, queue, handler)` in the `amqp/` sub-package.
**Example:**
```go
// Source: canonical protocol from crates/axiam-amqp/src/messages.rs (sign_payload/
// verify_payload), ack/nack semantics from D-07 + amqp091-go docs (this research session).
var ErrDrop = errors.New("axiam: drop message without requeue")

func verifyHMAC(signingKey []byte, body []byte) bool {
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return false
	}
	sigRaw, ok := msg["hmac_signature"]
	if !ok {
		return false // strict mode default (§8.3): missing signature = reject
	}
	var sigHex string
	if err := json.Unmarshal(sigRaw, &sigHex); err != nil {
		return false
	}
	delete(msg, "hmac_signature")
	canonical, err := json.Marshal(msg) // canonical-JSON re-serialization, matches Rust serde_json::to_vec
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, signingKey)
	mac.Write(canonical)
	return hmac.Equal(mac.Sum(nil), expected) // constant-time compare
}

func Consume(ctx context.Context, ch *amqp091.Channel, queue string, signingKey []byte, handler func(ctx context.Context, e Event) error) error {
	if err := ch.Qos(10, 0, false); err != nil { // prefetch=10 default (CF-03), no size limit, per-consumer not global
		return &NetworkError{Message: "failed to set QoS", cause: err}
	}
	deliveries, err := ch.Consume(queue, "axiam-sdk-consumer", false, false, false, false, nil)
	if err != nil {
		return &NetworkError{Message: "failed to start consumer", cause: err}
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case d, ok := <-deliveries:
			if !ok {
				return &NetworkError{Message: "delivery channel closed"}
			}
			if !verifyHMAC(signingKey, d.Body) {
				slog.Warn("axiam_sdk_security: AMQP HMAC verification failed; nacking without requeue")
				_ = d.Nack(false, false) // multiple=false, requeue=false
				continue
			}
			event, perr := parseEvent(d.Body)
			if perr != nil {
				_ = d.Nack(false, false)
				continue
			}
			if err := handler(ctx, event); err != nil {
				if errors.Is(err, ErrDrop) {
					_ = d.Nack(false, false) // poison message
				} else {
					_ = d.Nack(false, true) // transient — requeue
				}
				continue
			}
			_ = d.Ack(false)
		}
	}
}
```

### Pattern 6: `Sensitive` Multi-Surface Redaction (§7, D-08)
**What:** `type Sensitive string` redacting across `String()`, `fmt.Format`, `GoString()`, and
`MarshalJSON()`.
**When to use:** Every token-carrying field (access token, refresh token, MFA challenge token,
AMQP signing key).
**Example:**
```go
// Source: pattern ported from sdks/typescript/src/core/sensitive.ts + CONTRACT.md §7 Go row
// ("String type with String() method returning [SENSITIVE]"), extended per D-08's ceiling.
type Sensitive string

const redacted = "[SENSITIVE]"

func (Sensitive) String() string { return redacted }

// Format covers %v, %+v, %s, %q, %x, etc. — closes the fmt-verb leak path
// (the CR-04 leak class) that a bare String() method alone would not catch
// for %#v (handled separately by GoString) or width/precision verbs.
func (Sensitive) Format(f fmt.State, verb rune) {
	_, _ = io.WriteString(f, redacted)
}

func (Sensitive) GoString() string { return redacted } // covers %#v

func (Sensitive) MarshalJSON() ([]byte, error) {
	return json.Marshal(redacted)
}

// expose is package-internal only — never exported. The single accessor
// path for the raw value, analogous to Rust's pub(crate) expose().
func (s Sensitive) expose() string { return string(s) }
```

### Pattern 7: `NetworkError` Redact-Before-Wrap (D-04, CR-04 carry-forward)
**What:** Strip `Set-Cookie`/`Authorization`/`Cookie` response headers from any wrapped
`*http.Response`/transport error before it becomes `NetworkError.Unwrap()`'s target.
**When to use:** Every REST call site that constructs a `NetworkError` from a failed
`*http.Response` or `error`.
**Example:**
```go
// Source: pattern ported from sdks/typescript/src/core/errorMapper.ts sanitizeAxiosError
// (the exact fix for Phase 17 CR-04 — token-leak-via-error-cause).
var sensitiveResponseHeaders = []string{"Set-Cookie", "Authorization", "Cookie"}

// sanitizeResponse returns a shallow copy of resp's Header with sensitive
// headers stripped, WITHOUT mutating the caller's original *http.Response —
// mirrors the TS sanitizeAxiosError's non-mutating contract.
func sanitizeResponse(resp *http.Response) *http.Response {
	if resp == nil {
		return nil
	}
	clone := *resp
	clone.Header = resp.Header.Clone()
	for _, h := range sensitiveResponseHeaders {
		clone.Header.Del(h)
	}
	return &clone
}

type NetworkError struct {
	Message string
	cause   error // wraps a SANITIZED *http.Response-derived error only
}

func newNetworkError(message string, resp *http.Response, cause error) *NetworkError {
	if resp != nil {
		resp = sanitizeResponse(resp) // CR-04: redact BEFORE wrap, never after
	}
	return &NetworkError{Message: message, cause: cause}
}

func (e *NetworkError) Error() string { return "network error: " + e.Message }
func (e *NetworkError) Unwrap() error { return e.cause }
```
**Regression test (per CONTEXT.md Specific Ideas):** assert the raw `axiam_access`/
`axiam_refresh` cookie value never appears in `fmt.Sprintf("%v"/"%+v"/"%#v", err)` or
`json.Marshal(err)` output for a `NetworkError` constructed from a response carrying a
`Set-Cookie` header — with a control case (an error WITHOUT redaction) proving the test would
fail without the fix, so the test is non-vacuous.

### Anti-Patterns to Avoid
- **`grpc.Dial` / `grpc.DialContext`:** deprecated since grpc-go 1.63; use `grpc.NewClient` +
  `conn.Connect()` (or lazy connect) instead — mixing old and new APIs risks confusing
  connection-lifecycle semantics.
- **Any `insecure.NewCredentials()` or `grpc.WithInsecure()` anywhere in `sdks/go/`:** these are
  the gRPC-specific TLS-bypass equivalents of `InsecureSkipVerify` — the SC#3 grep gate as
  literally specified (`grep -rn 'InsecureSkipVerify' sdks/go/`) would NOT catch these; the CI
  gate must be extended (see Common Pitfalls #1).
- **Blocking `.Lock()` in the gRPC interceptor:** the interceptor closure runs synchronously on
  every RPC; never acquire the async-refresh mutex there directly — read the cached token via a
  non-blocking accessor (mirrors Rust `cached_access_token()`, RESEARCH.md Pitfall 3 carried
  forward from Phase 16).
- **Unbuffered `NotifyClose` channel:** `amqp091-go` sends synchronously then closes — an
  unbuffered receiver risks a goroutine leak/deadlock if nothing is actively selecting on it at
  the moment of closure; always use `make(chan *amqp091.Error, 1)`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| JWKS fetch/cache/TTL/forced-refetch-on-unknown-kid | A hand-rolled `RwLock`+timestamp cache (as Rust had to do — no equivalent existed for `jsonwebtoken` in Rust at the time) | `jwk.Cache` (`jwx/v3`) with `Register`/`Refresh`/`CachedSet` | `jwx/v3` ships this exact feature natively — using it avoids re-implementing TTL/cooldown bookkeeping the Rust SDK had to write by hand |
| EdDSA/Ed25519 JWS verification | Manual signature-byte comparison | `jws.Verify` with `jws.WithKeySet(...)` | Handles JWK→key material conversion, algorithm negotiation, and base64url decoding correctly; hand-rolling risks subtle canonicalization bugs |
| Constant-time HMAC comparison | `bytes.Equal` or `==` on hex strings | `hmac.Equal` (stdlib `crypto/hmac`) | `bytes.Equal`/`==` are timing-attack-vulnerable; `hmac.Equal` is specifically designed for constant-time comparison of MACs |
| AMQP auto-reconnect with backoff | A custom reconnect loop from scratch | `Connection.NotifyClose` + a `slog`-observable exponential-backoff+jitter retry wrapper around `amqp091.Dial` | The reconnect *signal* (`NotifyClose`) is provided by the library; only the backoff policy itself needs writing — don't also reimplement connection-state detection |
| Cookie jar / TLS verification | A custom `http.RoundTripper` for cookies or a hand-rolled cert-pinning verifier | `net/http/cookiejar.New(nil)` + stdlib `crypto/tls`/`crypto/x509` | Both are stdlib, battle-tested, and exactly what CONTRACT.md §4/§6 specify per-language |

**Key insight:** Every "don't hand-roll" item above has a direct stdlib or GO-01-pinned-library
answer — the Go ecosystem's batteries-included stdlib (`net/http`, `crypto/*`) plus `jwx/v3`'s
purpose-built JWKS cache cover the full surface this phase needs. The only genuinely new code is
the SDK's *own* single-flight guard (§9) and the AMQP ack/nack orchestration (§8/D-07), both of
which are behavioral contracts unique to AXIAM, not generic problems with existing libraries.

## Common Pitfalls

### Pitfall 1: SC#3's literal grep gate does not catch gRPC's TLS-bypass equivalent
**What goes wrong:** `grep -rn 'InsecureSkipVerify' sdks/go/` returning empty is necessary but not
sufficient — `grpc.WithInsecure()` (deprecated but still compiles) or
`grpc.WithTransportCredentials(insecure.NewCredentials())` (the modern gRPC equivalent, from
`google.golang.org/grpc/credentials/insecure`) bypass TLS just as completely and would not be
caught by that single pattern.
**Why it happens:** SC#1 in the ROADMAP phrases the gate narrowly around the REST/`tls.Config`
field name; gRPC has its own, differently-named escape hatches.
**How to avoid:** Extend the CI lint step to a pattern set:
`grep -rnE 'InsecureSkipVerify|WithInsecure\(|insecure\.NewCredentials\(' sdks/go/` — all three
must return empty. This mirrors `.planning/research/PITFALLS.md`'s documented lint patterns
(lines 167/183/366) and CONTRACT.md §6's "any other API surface that bypasses TLS verification"
absolute prohibition.
**Warning signs:** A gRPC example or test that connects to a local dev server without a CA cert
supplied — if it compiles and runs without `WithCustomCA`, check it isn't silently using an
insecure credential.

### Pitfall 2: `buf.gen.yaml`'s Go plugin `out:` path does not match D-01's committed-stub location
**What goes wrong:** The current `sdks/buf.gen.yaml` (Phase 15 artifact) has:
```yaml
- remote: buf.build/protocolbuffers/go
  out: go/gen
- remote: buf.build/grpc/go
  out: go/gen
```
which resolves to `sdks/go/gen` (relative to the `sdks/` working directory where `buf generate`
runs) — but D-01 explicitly names the committed-stub destination `sdks/go/internal/gen`.
**Why it happens:** Phase 15 scaffolded the buf config before D-01's Go-specific `internal/gen`
decision was made in Phase 18's discuss-phase.
**How to avoid:** This phase's Wave 0 must either (a) update `buf.gen.yaml`'s Go `out:` entries to
`go/internal/gen`, or (b) formally accept `sdks/go/gen` as the committed location and update D-01's
wording to match — pick (a) since `internal/` is the idiomatic Go way to prevent external packages
from importing generated stubs directly (bypassing the SDK's public API), and it's cheaper to fix
a config file than to reinterpret a locked decision.
**Warning signs:** `go build ./...` failing to find generated types after running `buf generate`,
or the CI drift-check comparing the wrong directory.

### Pitfall 3: Real login/refresh REST endpoints need `org_id`/`org_slug`, beyond CONTRACT.md §5
**What goes wrong:** Implementing `Login`/`Refresh` strictly per CONTRACT.md §5 (tenant-only) fails
against the live server — `crates/axiam-api-rest/src/handlers/auth.rs`'s actual login/refresh
request bodies require an organization identifier (organizations are the top-level entity above
tenants in AXIAM's domain model, per CLAUDE.md), and the Rust reference SDK (`sdks/rust/src/
client.rs`) already documents this exact deviation with an inline comment explaining why an
optional `org_slug`/`org_id` builder parameter was added beyond the contract's stated minimum.
**Why it happens:** `sdks/CONTRACT.md` was authored to describe the cross-language *behavioral*
contract (tenant scoping, error taxonomy, etc.), not every literal wire-body field of AXIAM's REST
API — the org requirement is a codebase-level fact CONTRACT.md doesn't enumerate.
**How to avoid:** Add `WithOrgSlug(string)`/`WithOrgID(uuid.UUID)` functional options (both
optional, mutually exclusive, last-call-wins — matching Rust's `org_slug`/`org_id` builder
methods). If neither is supplied at construction, resolve and cache the org UUID from the access
token's `org_id` claim after the first successful `Login`/`VerifyMfa`, exactly as the Rust SDK
does, so `Refresh` (which requires `org_id` in its body) can succeed on subsequent calls without
requiring the caller to have supplied it up front.
**Warning signs:** `Login` succeeds but `Refresh` fails with a 400/validation error; or `Login`
itself fails validation when no org identifier was ever configured and the caller's account
belongs to a non-default organization.

### Pitfall 4: `Connection.NotifyClose` deadlocks the connection goroutine if the receiver channel is unbuffered or unread
**What goes wrong:** `amqp091-go` sends the closing `*Error` synchronously to every registered
`NotifyClose` channel and then closes it — if the receiving goroutine isn't actively selecting on
that channel (or the channel has zero buffer capacity and nothing is reading), the library's
internal dispatch goroutine blocks indefinitely, silently wedging the connection's shutdown path.
**Why it happens:** This is documented but easy to miss — `NotifyClose`'s doc comment explicitly
warns "you must read from the channel" but the zero-value pattern (unbuffered `make(chan *Error)`)
is the most natural-looking Go code to write first.
**How to avoid:** Always allocate with capacity ≥1: `notifyClose := conn.NotifyClose(make(chan
*amqp091.Error, 1))`, and ensure a dedicated goroutine or `select` loop consumes it continuously
for the connection's lifetime (this is also the hook point for CF-03's auto-reconnect-with-backoff
logic).
**Warning signs:** AMQP consumer appears to hang on shutdown or after a broker-initiated
disconnect; no reconnect ever occurs despite `NotifyClose` being wired up.

### Pitfall 5: `grpc.NewClient` does not dial eagerly — a misconfigured TLS/target error surfaces late
**What goes wrong:** Unlike the deprecated `grpc.Dial`'s (still-present) blocking-connect option,
`grpc.NewClient` never blocks or dials during construction — connection errors (bad target, TLS
handshake failure) only surface on the first actual RPC call, not at `NewGRPCClient(...)` call
time.
**Why it happens:** This is an intentional API design change in modern grpc-go (lazy connection
establishment), but it differs from the Rust SDK's `tonic::Endpoint::connect()` behavior which the
CONTEXT.md canonical refs describe as the precedent pattern.
**How to avoid:** Document this explicitly in the Go SDK's godoc for `NewGRPCClient`/`NewClient`
(gRPC variant) — do not assume `err != nil` at construction means "TLS/target was validated";
consider an optional explicit `conn.Connect()` + `conn.WaitForStateChange` call in the constructor
if eager-failure semantics are desired for the middleware/examples (matching the Rust reference's
observable behavior more closely), gated behind a functional option if made non-default.
**Warning signs:** A gRPC example's error-handling path never triggers even with a deliberately
wrong `target` string in manual testing — the error only appears once `CheckAccess` is actually
called.

## Code Examples

Verified patterns from official sources — see Architecture Patterns section above (Patterns 1–7)
for the complete, load-bearing code for this phase. Each pattern cites its exact source (jwx/v3
pkg.go.dev docs, grpc-go credentials package docs, amqp091-go pkg.go.dev docs, or the Rust/TS
reference file it was ported from) inline in its source comment.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| `grpc.Dial` / `grpc.DialContext` | `grpc.NewClient` | grpc-go 1.63 (2024); GO-01 pins 1.81, well past this change | `Dial` still compiles (deprecated, not removed) but has different connection-establishment semantics (blocking vs lazy) — new code must use `NewClient` |
| `github.com/streadway/amqp` | `github.com/rabbitmq/amqp091-go` | streadway/amqp archived; amqp091-go is the RabbitMQ-team-maintained successor, same wire protocol | GO-01 already pins the correct, current library — no migration needed for this phase |
| `jwx/v2` polymorphic `EdDSA` algorithm | `jwx/v3` explicit `Ed25519`/`Ed448` algorithms (RFC 9864), with `EdDSA` deprecated but still usable | jwx v3.0.0 GA | Use `jwa.EdDSA()` for compatibility with the server's current single-key-type issuance, but be aware `jwx/v3` also supports the more specific `Ed25519` constant if the codebase later wants stricter typing |

**Deprecated/outdated:**
- `grpc.WithInsecure()`: fully removed in recent grpc-go major versions in favor of
  `grpc.WithTransportCredentials(insecure.NewCredentials())` — either form is a TLS-bypass and
  both must be caught by the CI lint gate (Pitfall 1).
- `streadway/amqp`: archived upstream; not a concern here since GO-01 already pins the correct
  successor.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Default numeric values not explicitly re-derived from a fresh server-side SLA doc — connect timeout 10s / request timeout 30s / JWKS cache TTL 300s / forced-refetch cooldown 60s / AMQP prefetch 10 / retry max-attempts 3 — are carried forward directly from the Rust SDK's already-shipped, reviewed defaults (Phase 16) rather than independently re-derived for Go | Code Examples, Pattern 4 & 5 | Low — these are proven, reviewed values from a sibling reference implementation of the same server; if the planner wants Go-specific tuning, it's a one-line constant change, not an architectural risk |
| A2 | `jwx/v3` is assumed to be at `v3.1.1` as "the latest v3.x" for planning purposes; GO-01 only pins the major version "v3" | Standard Stack | Low — if a newer v3.x patch has shipped by execution time, `go get github.com/lestrrat-go/jwx/v3@latest` resolves it automatically; API surface (`jwk.Cache`, `jws.Verify`) is stable within v3 per the module's own versioning discipline |
| A3 | The `httprc.Client` wiring shown in Pattern 4 (`httprc.NewClient(httprc.WithHTTPClient(hc))`) is inferred from the `jwk.NewCache(ctx, client *httprc.Client)` signature returned by WebFetch against pkg.go.dev, not independently confirmed against a live compiled example in this session (no network egress to `go build` against the real module in this environment beyond `go list -m`) | Code Examples, Pattern 4 | Medium — the exact `httprc` sub-package API (option names) should be double-checked by the planner/executor against `pkg.go.dev/github.com/lestrrat-go/jwx/v3/internal/httprc` or the top-level `httprc` package once the module is actually vendored, since WebFetch summarization can lose precise option-function names |

## Open Questions

1. **Exact `httprc.Client` construction options for `jwk.NewCache`**
   - What we know: `jwk.NewCache(ctx, client *httprc.Client)` requires an `httprc.Client` that must
     NOT be started before being passed in (per the WebFetch-summarized pkg.go.dev docs).
   - What's unclear: The precise option-function names for constructing that `httprc.Client` (e.g.
     whether `httprc.NewClient` takes a `*http.Client` directly or requires a different
     configuration shape) were not independently verified against source/godoc examples beyond the
     summarized WebFetch response.
   - Recommendation: The executor should run `go doc github.com/lestrrat-go/jwx/v3/internal/httprc`
     (or the public `httprc` package if it's been promoted out of `internal/`) once the dependency
     is vendored in Wave 0, and adjust Pattern 4's exact construction call if the API differs from
     what's shown here — the overall `jwk.Cache`/`Register`/`Refresh`/`CachedSet` control flow is
     confirmed correct; only the client bootstrap call is a residual detail.

2. **Whether `grpc.NewClient`'s lazy-connect semantics should be made eager for this SDK**
   - What we know: `grpc.NewClient` never blocks/dials at construction time (Pitfall 5); the Rust
     reference's `tonic::Endpoint::connect()` does establish the connection at construction.
   - What's unclear: Whether Phase 18's examples/tests should force an eager connect (via
     `conn.Connect()` + a `WaitForStateChange` poll) to match the Rust reference's observable
     behavior, or embrace Go's lazy-connect idiom and document the difference.
   - Recommendation: Default to Go idiom (lazy connect, matches most Go gRPC client code found in
     the wild) and document the behavioral difference from the Rust SDK explicitly in the Go
     package's godoc — this is a planner judgment call, not a blocking unknown.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Go toolchain | Building/testing the entire `sdks/go/` module | ✓ | go1.24.7 linux/amd64 | — (exceeds the `go 1.22` floor in go.mod; no action needed) |
| Network egress to `proxy.golang.org` | `go get`/`go mod tidy` for GO-01-pinned deps | ✓ (confirmed live in this research session via `go list -m -versions`) | — | — |
| `buf` CLI | D-01's committed-stub regeneration + CI drift-check | Not verified in this environment (no `buf` binary probed) | — | CI job (GitHub Actions) is the actual execution environment for `buf generate`; local absence in this research sandbox does not block planning — matches the precedent noted in `.planning/STATE.md` for Phase 16 (`buf` CLI unavailable locally, `cargo build --features grpc` used instead; Go plan should note the equivalent: stubs can be regenerated in CI even if `buf` is absent locally) |
| RabbitMQ broker (for AMQP integration/testcontainers smoke tests) | D-10's optional build-tagged AMQP smoke test | Not probed (out of scope for default `go test ./...` per D-10) | — | Deterministic unit tests use the `AckableDelivery`-equivalent seam (a Go interface over `amqp091.Delivery`'s Ack/Nack methods) with a recording fake, exactly mirroring the Rust reference's `RecordingDelivery` — no live broker needed for the required tests |

**Missing dependencies with no fallback:** none — all phase-blocking dependencies (Go toolchain,
module proxy egress) are confirmed available in this environment.

**Missing dependencies with fallback:** `buf` CLI (not probed locally; CI is authoritative per
Phase 16 precedent) and a live RabbitMQ broker (not required for the deterministic default test
suite per D-10).

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Go stdlib `testing` package (table-driven tests), `net/http/httptest` for REST mocking |
| Config file | none — Go's `testing` package requires no config file; `go.mod`'s `go 1.22` directive is the only relevant toolchain pin |
| Quick run command | `go test ./...` (default default `go test ./...` run — no live broker, no testcontainers, per D-10) |
| Full suite command | `go test -tags=integration ./...` (includes the optional, build-tagged testcontainers gRPC + AMQP smoke tests, per D-10) |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| GO-01 (SC#1) | `go get .../sdks/go` installs; `net/http` middleware example compiles; `tenantSlug` required at call time | unit + compile | `go build ./examples/middleware-guard/... && go test -run TestNewClient_RequiresTenantSlug ./...` | ❌ Wave 0 |
| GO-01 (SC#2) | 5 concurrent goroutines on expired token ⇒ exactly 1 refresh call | unit (table-driven, `httptest.Server` counting refresh calls) | `go test -run TestRefreshGuard_SingleFlight -race ./internal/refreshguard/...` | ❌ Wave 0 |
| GO-01 (SC#3) | No `InsecureSkipVerify`/`WithInsecure`/`insecure.NewCredentials` anywhere in `sdks/go/` | CI lint (not a Go test — shell/grep gate) | `grep -rnE 'InsecureSkipVerify|WithInsecure\(|insecure\.NewCredentials\(' sdks/go/` (must return empty; wire into CI as a failing-exit-code step) | ❌ Wave 0 (CI workflow) |
| GO-01 (SC#4) | AMQP consumer HMAC-verifies each body, nacks WITHOUT requeue on mismatch, handler never invoked on failure | unit (recording-fake `AckableDelivery`-equivalent, no live broker) | `go test -run TestVerifyAndDispatch ./amqp/...` | ❌ Wave 0 |
| GO-01 (SC#5) | `go test ./...` passes; tag `sdks/go/vX.Y.Z` triggers module publish | unit (full suite) + CI workflow | `go test ./...` (unit); tag-triggered GitHub Actions step (not a `go test` assertion) | ❌ Wave 0 |
| D-04 / CR-04 carry-forward | `NetworkError` never leaks `Set-Cookie`/`Authorization`/`Cookie` via `%v`/`%+v`/`%#v`/`json.Marshal` | unit (regression, with a non-redacted control case proving non-vacuousness) | `go test -run TestNetworkError_RedactsSensitiveHeaders ./...` | ❌ Wave 0 |
| D-08 | `Sensitive` redacts across `String`/`Format`/`GoString`/`MarshalJSON` | unit | `go test -run TestSensitive_RedactsAllSurfaces ./...` | ❌ Wave 0 |
| §3 CSRF (non-browser) | `X-CSRF-Token` response header captured and echoed on state-changing requests | unit (`httptest.Server` asserting header round-trip) | `go test -run TestCSRF_CaptureAndForward ./...` | ❌ Wave 0 |
| §5 tenant context | `X-Tenant-ID` header (REST) / `x-tenant-id` metadata (gRPC) injected on every request | unit | `go test -run TestTenantHeader_InjectedOnEveryRequest ./...` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `go test ./...` (quick run — excludes build-tagged integration tests)
- **Per wave merge:** `go test -tags=integration ./...` plus the CI TLS-bypass grep gate
- **Phase gate:** Full suite green (`go test -tags=integration ./...`, grep gate, `go vet ./...`,
  buf drift-check) before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `sdks/go/internal/gen/` — buf-generated stubs must exist before any gRPC test compiles;
      requires the `buf.gen.yaml` Go `out:` path fix (Pitfall 2) as a prerequisite
- [ ] `sdks/go/go.sum` — populated once the three pinned deps are `go get`-ed
- [ ] `.github/workflows/sdk-ci-go.yml` — new per-SDK CI workflow (`paths: sdks/go/**` filter):
      `go build ./...`, `go vet ./...`, `go test ./...`, the TLS-bypass grep gate, the buf
      drift-check, and the tag-triggered `sdks/go/vX.Y.Z` publish step
- [ ] No existing Go test infrastructure in `sdks/go/` (scaffold-only currently) — the entire test
      suite is new in this phase

*(No gaps beyond scaffold-to-implementation — this is expected for a phase delivering a brand-new
SDK from a placeholder scaffold.)*

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-------------------|
| V2 Authentication | yes | Login/VerifyMfa/Refresh/Logout via `net/http` + `net/http/cookiejar`; single-flight refresh (§9); no client-side credential caching beyond the `Sensitive`-wrapped in-memory token |
| V3 Session Management | yes | httpOnly cookie jar (`net/http/cookiejar`), `axiam_access`/`axiam_refresh` never read by SDK code except via the jar's opaque `http.CookieJar` interface (never `document.cookie`-equivalent parsing since Go has no browser context) |
| V4 Access Control | yes | `CheckAccess`/`BatchCheckAccess`/`Can` (gRPC + REST) delegate the actual decision to the server's `AuthorizationEngine`; SDK never makes a local allow/deny decision |
| V5 Input Validation | yes | `encoding/json` struct-tag-based (de)serialization for all wire types (mirrors Rust `serde`/TS response-shape validation); JWKS/JWT claims validated via `jwx/v3`'s `jws.Verify` (rejects malformed tokens, wrong algorithm, expired `exp`) |
| V6 Cryptography | yes | Never hand-rolled: `crypto/hmac`+`crypto/sha256` (stdlib) for §8 AMQP HMAC-SHA256, `jwx/v3` for EdDSA/Ed25519 JWT verification, `crypto/tls`+`crypto/x509` (stdlib) for TLS 1.3 transport security |

### Known Threat Patterns for Go SDK stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|-----------------------|
| TLS bypass via `InsecureSkipVerify`/`WithInsecure`/`insecure.NewCredentials` | Tampering / Information Disclosure | Absolute prohibition per CONTRACT.md §6; CI grep gate extended beyond the literal SC#3 pattern (Pitfall 1) |
| Token leak via error `Unwrap()`/`fmt` verbs carrying a raw `*http.Response` with `Set-Cookie` | Information Disclosure | D-04 redact-before-wrap (`sanitizeResponse` strips sensitive headers before `NetworkError` construction), mirroring the CR-04 fix from Phase 17 |
| AMQP message tampering / replay | Tampering | §8 HMAC-SHA256-verify-before-handler with constant-time `hmac.Equal`; nack-without-requeue on any mismatch; missing signature rejected by default (strict mode) |
| Thundering-herd refresh (concurrent 401s each triggering their own refresh, potentially invalidating each other's single-use rotating refresh token) | Denial of Service (self-inflicted) | §9 `sync.Mutex` single-flight guard with double-check-after-lock-acquire pattern |
| Algorithm confusion (attacker-supplied `alg: none` or `alg: HS256` against an expected-EdDSA key) | Spoofing / Tampering | Explicit `alg` allowlist check before `jws.Verify` — never trust the token's own header to select the algorithm (Pattern 4) |
| Cross-tenant token replay (a validly-signed token minted for org-wide JWKS but a different tenant) | Elevation of Privilege | Mirrors TS CR-03 fix: after JWKS signature verification succeeds, the middleware must additionally check `claims.tenant_id == configuredTenant` before trusting the token — JWKS is org-wide, not tenant-scoped, so signature validity alone is insufficient |

## Sources

### Primary (HIGH confidence)
- `sdks/CONTRACT.md` §1–§10 — normative/binding cross-language behavioral contract (direct file read)
- `.planning/phases/18-go-sdk/18-CONTEXT.md` — 10 locked decisions (D-01..D-10), 4 carry-forwards
  (CF-01..CF-04), canonical refs (direct file read)
- `.planning/REQUIREMENTS.md` §GO-01 (direct file read)
- `sdks/rust/src/{client.rs,error.rs,sensitive.rs,token/{jwks.rs,refresh_guard.rs},grpc/
  interceptor.rs,amqp/consumer.rs,rest/auth.rs}` — Phase 16 reference implementation (direct file reads)
- `sdks/typescript/src/{core/{errorMapper.ts,sensitive.ts},middleware/verifyCore.ts,rest/retry.ts,
  node/jwks.ts}` — Phase 17 reference implementation (direct file reads)
- `.planning/phases/17-typescript-sdk/17-REVIEW.md` §CR-04 — token-leak-via-error-cause finding (direct file read)
- `crates/axiam-amqp/src/messages.rs` — canonical HMAC sign/verify protocol (direct file read)
- `crates/axiam-api-rest/src/handlers/authz_check.rs`, `server.rs` — REST authz-check endpoint +
  route table incl. `/oauth2/jwks` (direct file reads)
- `proto/axiam/v1/authorization.proto` — gRPC service/message definitions (direct file read)
- `sdks/buf.gen.yaml`, `sdks/go/{go.mod,README.md}` — existing scaffold + codegen config (direct file reads)
- Go module proxy (`proxy.golang.org`) — `go list -m -versions`/`go list -m -json` live queries for
  `google.golang.org/grpc`, `github.com/rabbitmq/amqp091-go`, `github.com/lestrrat-go/jwx/v3`
  (VERIFIED via tool call, this session)

### Secondary (MEDIUM confidence)
- pkg.go.dev `github.com/lestrrat-go/jwx/v3/jwk` and `.../jws` (WebFetch summary, this session) —
  `jwk.Cache`/`Register`/`Refresh`/`CachedSet` and `jws.Verify`/`WithKeySet` API shapes
- pkg.go.dev `google.golang.org/grpc/credentials` (WebFetch summary, this session) —
  `credentials.NewTLS`, `grpc.NewClient` vs deprecated `grpc.Dial`, `PerRPCCredentials`
- pkg.go.dev `github.com/rabbitmq/amqp091-go` (WebFetch summary, this session) — `Channel.Qos`,
  `Channel.Consume`, `Delivery.Ack/Nack/Reject`, `Connection.NotifyClose`

### Tertiary (LOW confidence)
- WebSearch results on Go monorepo module-tag conventions (general community sources — Streamdal
  blog, golang/go wiki, Medium posts) — used only to corroborate that `sdks/go/vX.Y.Z` (Phase 15
  D-13's existing convention) is a standard, working pattern; not load-bearing since the convention
  was already locked before this research

## Metadata

**Confidence breakdown:**
- Standard Stack: HIGH — all three pinned dependencies directly confirmed against the authoritative
  Go module proxy with verified VCS origin, not just registry-existence
- Architecture: HIGH — ported directly from two working, reviewed reference implementations (Rust
  Phase 16, TypeScript Phase 17) plus the binding CONTRACT.md; the org_id/JWKS-path/buf-output-path
  findings were cross-checked against three independent codebase sources each
- Pitfalls: MEDIUM-HIGH — the grpc.NewClient/Dial and NotifyClose pitfalls are well-documented
  upstream facts (WebFetch-sourced); the org_id requirement and buf.gen.yaml path mismatch are
  HIGH confidence (direct codebase reads); the exact `httprc.Client` construction API (Open
  Question #1) is the one genuinely MEDIUM-confidence gap in this research

**Research date:** 2026-07-01
**Valid until:** 2026-07-31 (30 days — stable dependency set, but grpc-go and jwx/v3 both ship
frequent patch releases; re-verify exact pinned versions at execution time)
