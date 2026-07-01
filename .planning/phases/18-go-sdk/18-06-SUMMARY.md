---
phase: 18-go-sdk
plan: 06
subsystem: go-sdk-examples-ci
tags: [go, sdk, examples, ci, github-actions, buf, tls, publish]
dependency_graph:
  requires:
    - "18-01: sdks/go.Sensitive, sdks/go.AuthError/AuthzError/NetworkError + sentinels, committed internal/gen stubs"
    - "18-02: sdks/go.NewClient/Login/VerifyMfa/CheckAccess/Can/BatchCheck"
    - "18-03: sdks/go/amqp.Consume/ErrDrop/Event"
    - "18-04: sdks/go/grpc.NewGRPCClient/NewAuthzClient/CheckAccessRequest, sdks/go/internal/jwks.Verifier"
    - "18-05: sdks/go/middleware.Middleware/UserFromContext"
  provides:
    - "sdks/go/examples/{login-mfa,authz-check,grpc-checkaccess,amqp-consumer,middleware-guard}/main.go — five runnable per-capability examples (D-10)"
    - "sdks/go.NewJWKSVerifier — public root-package wrapper over internal/jwks.NewVerifier"
    - "sdks/go/grpc.NewTLSCredentials — exported wrapper over the package's strict-TLS credentials constructor"
    - ".github/workflows/sdk-ci-go.yml — full Go CI (test/vet/test + TLS-bypass gate + buf drift-check + tag-triggered publish)"
  affects:
    - "Phase 18 close-out — this is the final plan in the go-sdk phase; SC#1, SC#3, SC#5 and D-01 are now CI-enforced"
tech_stack:
  added: []
  patterns:
    - "Examples import only the SDK's public API (root axiam package, grpc, amqp, middleware) — no example reaches into internal/ packages"
    - "Root-package thin re-export (axiam.JWKSVerifier / axiam.NewJWKSVerifier) so middleware examples never import internal/jwks directly"
    - "grpc.NewTLSCredentials exported alongside the existing unexported newTLSCredentials so external callers can build strict TLS credentials without reimplementing tls.Config wiring"
key_files:
  created:
    - sdks/go/examples/login-mfa/main.go
    - sdks/go/examples/authz-check/main.go
    - sdks/go/examples/grpc-checkaccess/main.go
    - sdks/go/examples/amqp-consumer/main.go
    - sdks/go/examples/middleware-guard/main.go
    - sdks/go/jwks.go
  modified:
    - sdks/go/README.md
    - sdks/go/grpc/tls.go
    - .gitignore
    - .github/workflows/sdk-ci-go.yml
decisions:
  - "Exported grpc.NewTLSCredentials as a thin wrapper over the existing unexported newTLSCredentials — the gRPC example needs a public way to build strict TLS credentials.TransportCredentials for NewGRPCClient's second argument, and no such constructor existed outside the package before this plan (Rule 2 fix: missing critical functionality for external consumers, not just internal tests)"
  - "Added root-package axiam.JWKSVerifier (type alias) + axiam.NewJWKSVerifier wrapping internal/jwks.NewVerifier — the middleware example needs a way to construct the verifier middleware.Middleware requires; internal/ packages ARE importable from any code within the same module (Go's internal/ visibility rule), but a public re-export keeps the SDK's supported entry points in the root/grpc/amqp/middleware packages only, matching the rest of the public API surface (Rule 2 fix)"
  - "The grpc-checkaccess example builds its own grpc.UnaryClientInterceptor inline (mirroring the internal, unexported authUnaryInterceptor in package grpc) since the grpc package deliberately does not export an interceptor constructor (18-04's design keeps the interceptor package-private, callers wire tokenFn themselves) — this uses only public SDK API (grpc.NewGRPCClient/NewAuthzClient/CheckAccessRequest) plus public grpc-go API (google.golang.org/grpc/metadata), no internal package reached into"
  - "CI workflow pins actions/setup-go@v5.5.0 to go-version 1.25.0, matching the actual go.mod floor after 18-01's documented toolchain-driven bump from 1.22 to 1.25.0 (grpc v1.81.0 requires go>=1.25.0) — the plan text's stated '1.22 floor' predates that dependency-driven bump"
  - "publish job's final step verifies the Go module resolves via the public module proxy (go install .../sdks/go@<version>) rather than performing an explicit registry publish call — unlike crates.io/npm, the Go module proxy has no publish API; pushing the sdks/go/vX.Y.Z tag IS the release, so this step is a confirmation, not a side-effecting publish action, with a documented non-fatal note about proxy propagation delay"
  - "Added Go SDK example build-artifact patterns to .gitignore (/sdks/go/{login-mfa,authz-check,grpc-checkaccess,amqp-consumer,middleware-guard}) after go build ./examples/... left a same-named binary in sdks/go/ — no prior Go binary-artifact pattern existed in .gitignore (Rule 1 bug fix: repo hygiene gap discovered mid-task)"
metrics:
  duration: 20min
  completed: 2026-07-01
status: complete
---

# Phase 18 Plan 06: Go SDK Examples + CI Summary

Delivered the five per-capability example `main` packages (D-10), a README conformance/usage rewrite, and the full `sdk-ci-go.yml` workflow replacing the scaffold placeholder — enforcing SC#1 (middleware example compiles), SC#3 (extended TLS-bypass grep gate), the D-01 buf drift-check, and SC#5's tag-triggered `sdks/go/vX.Y.Z` publish. This is the final plan in Phase 18 (go-sdk).

## What Was Built

**Task 1 — Five per-capability examples + README conformance (D-10, SC#1):**
- `examples/login-mfa/main.go`: `axiam.NewClient` with required `tenantSlug` → `Login` → branch on `LoginResult.MFARequired` → `VerifyMfa`.
- `examples/authz-check/main.go`: `CheckAccess` + `Can` + `BatchCheck` over the REST FND-04 authz surface after a login.
- `examples/grpc-checkaccess/main.go`: `grpc.NewGRPCClient` + `grpc.NewAuthzClient` + `CheckAccess`/`BatchCheck`, with a locally-built `grpc.UnaryClientInterceptor` (the package's own interceptor constructor is intentionally unexported) injecting bearer/tenant metadata.
- `examples/amqp-consumer/main.go`: `amqp.Consume` with a closure handler demonstrating the full ack/nack matrix (nil → ack, `amqp.ErrDrop` → nack-no-requeue, any other error → nack-with-requeue).
- `examples/middleware-guard/main.go`: wraps a sample `net/http` route with `middleware.Middleware`, reading `middleware.UserFromContext` in the handler — builds and serves without a live server for SC#1.
- `sdks/go/README.md`: kept the "This SDK conforms to CONTRACT.md §1-§10." statement, added per-capability usage snippets for all five capabilities, `go get` install instructions, and a Versioning section documenting the `sdks/go/vX.Y.Z` tag convention.

**Task 2 — Go CI workflow (SC#3, SC#5, D-01):**
- Replaced `.github/workflows/sdk-ci-go.yml`'s scaffold placeholder with five jobs: `scaffold-check` (LICENSE presence), `test` (`go build`/`go vet`/`go test ./...` + both example-build verification commands), `tls-bypass-gate` (the extended `InsecureSkipVerify|WithInsecure\(|insecure\.NewCredentials\(` grep across `sdks/go/`), `buf-drift-check` (`buf generate` + `git diff --exit-code sdks/go/internal/gen`), and `publish` (tag-only, `refs/tags/sdks/go/v*`, unreachable from `pull_request`).
- Kept the existing `sdks/go/**` + `sdks/openapi.json` + `sdks/buf.yaml` + `sdks/buf.gen.yaml` PR path filter; added the `push: tags: ['sdks/go/v*']` trigger.
- All actions SHA-pinned (`actions/checkout@11bd719...` v4.2.2, `actions/setup-go@d35c59a...` v5.5.0); `bufbuild/buf-action@v1.4.0` used with `setup_only: true`, matching the exact pattern already established in `sdk-buf-gates.yml`/`sdk-ci-typescript.yml`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] `grpc.NewTLSCredentials` did not exist — gRPC example had no public way to build strict TLS credentials**
- **Found during:** Task 1, writing `examples/grpc-checkaccess/main.go`
- **Issue:** `grpc.NewGRPCClient(target, creds, interceptor)` requires a `credentials.TransportCredentials` value, but the package's only credentials constructor (`newTLSCredentials`) was unexported — reachable only from within `package grpc` itself (its own tests). An external caller (this example, or any real consumer) had no public API to build the SDK's strict-TLS credentials.
- **Fix:** Added `grpc.NewTLSCredentials(customCAPEM []byte)` as a thin, behavior-identical exported wrapper over `newTLSCredentials` in `sdks/go/grpc/tls.go`. No TLS behavior changed — same TLS 1.3 floor, same single `WithCustomCA`-equivalent escape hatch, same absolute prohibition on any bypass surface.
- **Files modified:** `sdks/go/grpc/tls.go`
- **Verification:** `go build ./examples/grpc-checkaccess/...` compiles; `grep -rnE 'InsecureSkipVerify|WithInsecure\(|insecure\.NewCredentials\(' sdks/go/` still empty.
- **Commit:** `f0f2206`

**2. [Rule 2 - Missing Critical] No public constructor for the JWKS verifier the middleware requires**
- **Found during:** Task 1, writing `examples/middleware-guard/main.go`
- **Issue:** `middleware.Middleware(verifier, configuredTenant, opts...)` requires a value satisfying `middleware`'s local `jwksVerifier` interface (`Verify(ctx, []byte) (jwks.Claims, error)`). The only constructor, `internal/jwks.NewVerifier`, lives in an `internal/` package. While Go's `internal/` visibility rule technically permits any code within the same module (including `examples/`) to import it, doing so directly would mean the SDK's "supported public API" boundary is inconsistent — every other example imports only the root `axiam` package, `grpc`, `amqp`, or `middleware`.
- **Fix:** Added `sdks/go/jwks.go` with a root-package `JWKSVerifier` type alias and `NewJWKSVerifier(ctx, baseURL, hc)` wrapping `internal/jwks.NewVerifier` — the example now constructs the verifier via `axiam.NewJWKSVerifier`, consistent with the rest of the public surface, and no example imports an `internal/` package.
- **Files modified:** `sdks/go/jwks.go` (new)
- **Verification:** `go build ./examples/middleware-guard/...` compiles (confirms `*axiam.JWKSVerifier` satisfies `middleware`'s local interface); full `go build ./...`/`go vet ./...`/`go test ./...` still clean (95 tests, no regressions).
- **Commit:** `f0f2206`

**3. [Rule 1 - Bug] Stray build artifact in `sdks/go/` after example verification, no `.gitignore` pattern to catch it**
- **Found during:** Task 1, running the plan's exact verify command (`go build ./examples/... && go build ./examples/middleware-guard/...`)
- **Issue:** `go build ./examples/...` with multiple `main` packages and no `-o` flag compiles each example to a same-named binary in the current working directory (`sdks/go/`) — this left an 11MB `sdks/go/middleware-guard` ELF binary as an untracked file. No prior `.gitignore` pattern in the repo covered Go build artifacts (the existing `.gitignore` only had Rust/Node/generic patterns).
- **Fix:** Deleted the stray binary and added five explicit `.gitignore` entries (`/sdks/go/{login-mfa,authz-check,grpc-checkaccess,amqp-consumer,middleware-guard}`) so a future contributor running the same verify command never accidentally commits a compiled binary.
- **Files modified:** `.gitignore`
- **Commit:** `f0f2206`

## Known Stubs

None — all five examples call real, fully-implemented SDK methods against the actual server wire shapes established in Plans 02–05. One doc-comment in `examples/grpc-checkaccess/main.go` uses the word "placeholder" to describe example-only token-cache wiring (not a functional stub); confirmed via `grep -rn "TODO|FIXME|coming soon|not available|placeholder" examples/` that no other stub markers exist.

## Threat Flags

None beyond what the plan's own `<threat_model>` already covers (T-18-23 through T-18-26, T-18-SC) — no new security-relevant surface was introduced outside the threat register. The two new exported constructors (`grpc.NewTLSCredentials`, `axiam.NewJWKSVerifier`) are thin wrappers with identical security behavior to their existing internal/unexported counterparts — no new TLS or verification logic was written, only visibility was widened for legitimate external callers.

## Verification

- `cd sdks/go && go build ./examples/... && go build ./examples/middleware-guard/... && go vet ./examples/... && grep -q 'conforms to CONTRACT.md' README.md` — all pass (Task 1's exact verify command).
- `cd sdks/go && go build ./... && go vet ./... && go test ./...` — clean, 95 tests passed across 12 packages, no regressions from the 18-05 baseline.
- `gofmt -l sdks/go/` — empty (all files correctly formatted).
- `grep -rnE 'InsecureSkipVerify|WithInsecure\(|insecure\.NewCredentials\(' sdks/go/` — empty (SC#3, including all five new examples).
- `test -f .github/workflows/sdk-ci-go.yml && grep -q "InsecureSkipVerify|WithInsecure" ... && grep -q 'git diff --exit-code' ... && grep -q "refs/tags/sdks/go/v" ... && grep -q 'go test ./...' ... && python3 -c "import yaml,sys; yaml.safe_load(open(...))"` — all pass (Task 2's exact verify command); YAML parses cleanly (the PyYAML `True`-as-key artifact for the bare `on:` key is the same GitHub Actions YAML 1.1 quirk present in the already-working `sdk-ci-rust.yml`, not a defect).

## Self-Check: PASSED

All 6 `key_files` created (`examples/login-mfa/main.go`, `examples/authz-check/main.go`, `examples/grpc-checkaccess/main.go`, `examples/amqp-consumer/main.go`, `examples/middleware-guard/main.go`, `jwks.go`) confirmed present on disk. All 4 `key_files` modified (`README.md`, `grpc/tls.go`, `.gitignore`, `.github/workflows/sdk-ci-go.yml`) confirmed present with expected changes. Both commit hashes referenced in this summary (`f0f2206`, `7dc2097`) confirmed present in `git log --oneline --all`.
