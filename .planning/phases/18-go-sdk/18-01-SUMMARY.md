---
phase: 18-go-sdk
plan: 01
subsystem: go-sdk-foundation
tags: [go, sdk, codegen, grpc, errors, sensitive-redaction, security]
dependency_graph:
  requires: []
  provides:
    - "sdks/go/internal/gen/axiam/v1 committed gRPC stubs (axiamv1 package)"
    - "sdks/go.Sensitive type"
    - "sdks/go.AuthError / AuthzError / NetworkError + sentinels"
    - "sdks/go.errorFromHTTPStatus / errorFromGRPCStatus status mappers"
    - "sdks/go.sanitizeResponse / newNetworkError redact-before-wrap"
  affects:
    - "all later 18-go-sdk plans (02-06): REST/gRPC/AMQP transports, middleware, examples all import Sensitive + the error taxonomy; gRPC tests depend on the committed internal/gen stubs"
tech_stack:
  added:
    - "google.golang.org/grpc v1.81.0"
    - "github.com/rabbitmq/amqp091-go v1.10.0"
    - "github.com/lestrrat-go/jwx/v3 v3.1.1"
    - "google.golang.org/protobuf v1.36.11 (transitive via generated stubs)"
  patterns:
    - "type Sensitive string with String/Format/GoString/MarshalJSON all redacting to [SENSITIVE]; raw value only via unexported expose()"
    - "typed error structs (AuthError/AuthzError/NetworkError) implementing error + Is(target) for errors.Is against exported sentinels"
    - "newNetworkError as single choke point: builds cause exclusively from sanitizeResponse()-scrubbed *http.Response, never from caller-supplied unredacted data"
key_files:
  created:
    - sdks/go/internal/gen/axiam/v1/authorization.pb.go
    - sdks/go/internal/gen/axiam/v1/authorization_grpc.pb.go
    - sdks/go/sensitive.go
    - sdks/go/sensitive_test.go
    - sdks/go/errors.go
    - sdks/go/errors_test.go
  modified:
    - sdks/buf.gen.yaml
    - .gitignore
    - sdks/go/go.mod
    - sdks/go/go.sum
    - .planning/REQUIREMENTS.md
decisions:
  - "buf CLI unavailable locally (confirmed per RESEARCH.md Environment Availability) — generated the axiam.v1 stubs with protoc + protoc-gen-go/protoc-gen-go-grpc, using an explicit M-mapping (Maxiam/v1/authorization.proto=...;axiamv1) since proto/axiam/v1/authorization.proto has no go_package option and editing the shared proto file was out of this plan's scope"
  - "go.mod go directive auto-bumped from 1.22 to 1.25.0 by `go get google.golang.org/grpc@v1.81.0`, which requires go >=1.25.0 — accepted as a Rule 1 auto-fix since go1.24.7 (< 1.25) would otherwise fail to build the module; the plan's 'keep go 1.22' guidance predates this dependency-floor constraint discovered during install"
  - "amqp091-go and jwx/v3 landed as // indirect requires in go.mod (go mod tidy drops unused-import direct requires) since Task 2 does not import either yet — both are pinned and present in go.sum per the plan's requirement; they will promote to direct once a later plan (AMQP consumer / JWKS verifier) imports them"
  - "newNetworkError redesigned to build its wrapped cause exclusively from the sanitized response (never accept a pre-built, potentially-tainted cause when resp is non-nil) — this closes a gap where a caller could construct a cause from the raw *http.Response before calling the constructor and bypass redaction entirely"
metrics:
  duration: 25min
  completed: 2026-07-01
status: complete
---

# Phase 18 Plan 01: Go SDK Foundation Summary

Fixed the Phase-15 buf codegen distribution config so Go gRPC stubs land at `sdks/go/internal/gen` (not `sdks/go/gen`), generated and committed the `axiam.v1` `AuthorizationService` stubs via `protoc` (buf CLI unavailable locally), populated `go.sum` with the three GO-01-pinned dependencies, and implemented the two cross-cutting primitives every later transport plan depends on: a four-surface redacting `Sensitive` string type and a three-type error taxonomy (`AuthError`/`AuthzError`/`NetworkError`) whose `NetworkError` constructor redacts `Set-Cookie`/`Authorization`/`Cookie` headers before any wrapping occurs (the Phase-17 CR-04 carry-forward).

## What Was Built

**Task 1 — Codegen distribution + committed stubs:**
- `sdks/buf.gen.yaml`: both Go plugin `out:` entries corrected from `go/gen` to `go/internal/gen` (D-01).
- `.gitignore`: removed the `sdks/go/gen/` ignore line and added an explicit comment documenting that Go is the codegen-distribution exception — `sdks/go/internal/gen` is committed and CI-drift-checked, never gitignored.
- Generated `sdks/go/internal/gen/axiam/v1/authorization.pb.go` and `authorization_grpc.pb.go` via `protoc` + `protoc-gen-go`/`protoc-gen-go-grpc` (both installed via `go install .../latest`), package `axiamv1`, declaring `CheckAccessRequest`, `CheckAccessResponse`, `BatchCheckAccessRequest`, `BatchCheckAccessResponse`, and `AuthorizationServiceClient`/`AuthorizationServiceServer`.
- `sdks/go/go.mod`/`go.sum`: added `google.golang.org/grpc v1.81.0`, `github.com/rabbitmq/amqp091-go v1.10.0`, `github.com/lestrrat-go/jwx/v3 v3.1.1`, and the transitive `google.golang.org/protobuf v1.36.11`.

**Task 2 — Sensitive type + error taxonomy (TDD):**
- RED: wrote `sensitive_test.go` (`TestSensitive_RedactsAllSurfaces`, 8 subtests covering `String()`, `%v`, `%+v`, `%s`, `%q`, `%#v`, `MarshalJSON`, struct-embedded JSON, and the `expose()` accessor) and `errors_test.go` (`TestNetworkError_RedactsSensitiveHeaders` with a non-vacuous control case, `TestErrors_As_Is`, `TestErrorFromHTTPStatus`, `TestErrorFromGRPCStatus`) against no implementation — confirmed `go vet` failure (`undefined: newNetworkError`).
- GREEN: implemented `sdks/go/sensitive.go` (`type Sensitive string` with `String`/`Format`/`GoString`/`MarshalJSON` all emitting `[SENSITIVE]`, plus unexported `expose()`) and `sdks/go/errors.go` (`AuthError`, `AuthzError` with optional `Action`/`ResourceID`, `NetworkError` with unexported `cause` + `Unwrap()`, sentinels `ErrAuth`/`ErrAuthz`/`ErrNetwork` each matched via a type-level `Is(target error) bool`, `sanitizeResponse`, `newNetworkError`, `errorFromHTTPStatus`, `errorFromGRPCStatus`).
- All 34 tests pass; `go build ./...`, `go vet ./...`, and `gofmt -l .` are clean.

**Task 3 — REQUIREMENTS.md GO-01 reconciliation:**
- Scoped one-line edit: module `github.com/axiam/axiam-go-sdk` → `github.com/ilpanich/axiam/sdks/go`; tag `sdk/go/vX.Y.Z` → `sdks/go/vX.Y.Z`, matching the committed `go.mod`, ROADMAP Phase 18 SC#1/SC#5, and Phase 15 D-13's monorepo tag convention. No other GO-01 acceptance item touched.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] buf CLI absent locally — used protoc + protoc-gen-go/protoc-gen-go-grpc fallback**
- **Found during:** Task 1
- **Issue:** `buf` binary not installed in this environment (confirmed absent, matching RESEARCH.md's documented Environment Availability finding and the Phase 16 Rust precedent).
- **Fix:** Installed `protoc-gen-go`/`protoc-gen-go-grpc` via `go install .../latest` (both from the official `google.golang.org` module paths) and drove code generation with the locally available `protoc` (libprotoc 3.21.12) binary directly, exactly as the plan's fallback instructions specify.
- **Files modified:** `sdks/go/internal/gen/axiam/v1/authorization.pb.go`, `authorization_grpc.pb.go`
- **Commit:** `0c648da`

**2. [Rule 3 - Blocking] proto file has no `go_package` option — used an explicit M-mapping**
- **Found during:** Task 1
- **Issue:** `protoc-gen-go` refused to generate without a Go import path; `proto/axiam/v1/authorization.proto` has no `go_package` option set (none of the shared `proto/` files do).
- **Fix:** Passed `--go_opt=Maxiam/v1/authorization.proto=github.com/ilpanich/axiam/sdks/go/internal/gen/axiam/v1;axiamv1` (and the equivalent `--go-grpc_opt`) on the `protoc` command line rather than editing the shared `.proto` file, which is out of this plan's file scope and would affect every other language's codegen pipeline.
- **Files modified:** none beyond the generated stubs (command-line only)
- **Commit:** `0c648da`

**3. [Rule 1 - Bug] `go.mod` go directive auto-bumped 1.22 → 1.25.0**
- **Found during:** Task 1
- **Issue:** `go get google.golang.org/grpc@v1.81.0` requires `go >= 1.25.0`; the toolchain (go1.24.7, above the plan's stated `go 1.22` floor) auto-negotiated and rewrote `go.mod`'s `go` directive to `1.25.0` during dependency resolution. Reverting this would break the build with the GO-01-pinned grpc version.
- **Fix:** Accepted the toolchain's automatic bump; `go.mod` now reads `go 1.25.0`. Documented here so later plans/CI don't treat this as unintentional drift.
- **Files modified:** `sdks/go/go.mod`
- **Commit:** `0c648da`

**4. [Rule 1 - Bug] `newNetworkError` initially discarded its own sanitized response — fixed to actually redact-before-wrap**
- **Found during:** Task 2 (writing the non-vacuous control test)
- **Issue:** First implementation called `sanitizeResponse(resp)` but discarded the result (`_ = sanitized`) and passed the caller-supplied `cause` through unchanged — meaning a caller who pre-built `cause` from the raw, unredacted response before calling `newNetworkError` would bypass redaction entirely. The non-vacuous control test caught this design gap (not a typo — a real correctness bug in the constructor's contract).
- **Fix:** Redesigned `newNetworkError` so that when `resp` is non-nil, it is the SOLE source of the wrapped cause — a `fmt.Errorf` built from `sanitizeResponse(resp)`'s status/headers, ignoring any caller-supplied `cause` in that branch. `cause` is only used as-is when `resp` is nil (pure transport failure with no HTTP response, e.g. DNS/connection-refused).
- **Files modified:** `sdks/go/errors.go`, `sdks/go/errors_test.go`
- **Commit:** `5e7787f`

## Known Stubs

None — this plan produces cross-cutting primitives (types, not UI/data-flow), so the stub-tracking concern (hardcoded empty values flowing to rendering) does not apply.

## Threat Flags

None beyond what the plan's own `<threat_model>` already covers (T-18-01, T-18-02, T-18-03) — no new security-relevant surface was introduced outside the threat register.

## Verification

- `cd sdks/go && go build ./... && go vet ./...` — clean.
- `cd sdks/go && go test ./...` — 34 passed, 0 failed, across the root `axiam` package and `internal/gen/axiam/v1` (no test files, as expected for generated code).
- `go test -run 'TestSensitive_RedactsAllSurfaces|TestNetworkError_RedactsSensitiveHeaders' ./...` — 13/13 subtests pass, including the non-vacuous control case.
- `grep -rnE 'InsecureSkipVerify|WithInsecure\(|insecure\.NewCredentials\(' sdks/go/` — empty (no TLS-bypass surface introduced).
- `gofmt -l sdks/go/` — empty (all files correctly formatted).
- buf `out:` resolves to `sdks/go/internal/gen`; `git status --porcelain sdks/go/internal/gen` shows the stubs tracked (committed in `0c648da`), not ignored.
- `.planning/REQUIREMENTS.md` GO-01 module path/tag reconciled; no stale identifiers remain.

## Self-Check: PASSED

All 11 files listed under `key_files` (created + modified) confirmed present on disk. All 5 commit hashes referenced in this summary (`0c648da`, `a751b0e`, `5e7787f`, `0854a64`, and this summary's own commit) confirmed present in `git log --oneline --all`.
