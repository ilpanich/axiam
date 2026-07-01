---
phase: 18
slug: go-sdk
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-01
---

# Phase 18 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Seeded from `18-RESEARCH.md` § Validation Architecture. The planner fills the
> Per-Task Verification Map with concrete task IDs; execution flips statuses green.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Go stdlib `testing` (table-driven tests) + `net/http/httptest` for REST/JWKS mocking |
| **Config file** | none — Go `testing` needs no config; `go.mod` `go 1.22` directive is the only toolchain pin |
| **Quick run command** | `cd sdks/go && go test ./...` (no live broker / no testcontainers, per D-10) |
| **Full suite command** | `cd sdks/go && go test -tags=integration ./... && go vet ./...` (adds optional build-tagged gRPC + AMQP testcontainers smoke, per D-10) |
| **Estimated runtime** | ~a few seconds (unit, hermetic — `httptest` + recording fakes; `-race` on the single-flight test) |

Notes:
- gRPC + AMQP live smoke tests are **build-tagged (`integration`)** and never part of the default `go test ./...` run — keeps SC#2's single-flight test deterministic and Docker-free.
- The `buf` CLI is absent from the sandbox; the buf codegen + drift-check + module-publish gates run only in CI (`.github/workflows/sdk-ci-go.yml`). See Manual-Only below.

---

## Sampling Rate

- **After every task commit:** Run `go test ./...` (quick — excludes build-tagged integration tests)
- **After every plan wave:** Run `go test -tags=integration ./...` + `go vet ./...` + the CI TLS-bypass grep gate
- **Before `/gsd-verify-work`:** Full suite green (`go test -tags=integration ./...`, grep gate, `go vet ./...`, buf drift-check)
- **Max feedback latency:** ~5 seconds

---

## Per-Task Verification Map

Requirement for the whole phase is **GO-01** (Go SDK — REST + gRPC + AMQP). Seed rows
below come from the research Req→Test map; the planner replaces `{N}-PP-TT` placeholders
with real task IDs and adds threat refs from each PLAN's `<threat_model>`.

| Deliverable | Req | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|-------------|-----|------------|-----------------|-----------|-------------------|-------------|--------|
| `NewClient` requires `tenantSlug` at call time; `net/http` middleware example compiles (SC#1) | GO-01 | — | tenant required, compile-enforced | unit + compile | `go build ./examples/middleware-guard/... && go test -run TestNewClient_RequiresTenantSlug ./...` | ❌ W0 | ⬜ pending |
| 5 concurrent goroutines on expired token ⇒ exactly 1 refresh (SC#2) | GO-01 | thundering-herd refresh | one refresh under concurrency | unit (table-driven, `-race`) | `go test -run TestRefreshGuard_SingleFlight -race ./...` | ❌ W0 | ⬜ pending |
| No `InsecureSkipVerify`/`WithInsecure`/`insecure.NewCredentials` in `sdks/go/` (SC#3) | GO-01 | TLS bypass | no TLS-bypass surface | CI lint | `grep -rnE 'InsecureSkipVerify\|WithInsecure\(\|insecure\.NewCredentials\(' sdks/go/` (empty) | ❌ W0 (CI) | ⬜ pending |
| AMQP consumer HMAC-verifies each body; nacks WITHOUT requeue on mismatch; handler never runs on failure (SC#4) | GO-01 | AMQP tampering/replay | verify-before-handler; drop poison | unit (recording fake) | `go test -run TestVerifyAndDispatch ./amqp/...` | ❌ W0 | ⬜ pending |
| `go test ./...` passes; tag `sdks/go/vX.Y.Z` publishes (SC#5) | GO-01 | — | reproducible module publish | unit + CI | `go test ./...`; tag-triggered GH Actions | ❌ W0 (CI) | ⬜ pending |
| `NetworkError` never leaks `Set-Cookie`/`Authorization`/`Cookie` via `%v`/`%+v`/`%#v`/`json.Marshal` (D-04 / CR-04) | GO-01 | token leak via error `Unwrap`/`fmt` | redact-before-wrap; non-vacuous control | unit (regression) | `go test -run TestNetworkError_RedactsSensitiveHeaders ./...` | ❌ W0 | ⬜ pending |
| `Sensitive` redacts across `String`/`Format`/`GoString`/`MarshalJSON` (D-08) | GO-01 | token leak via fmt/log/JSON | raw value only via internal accessor | unit | `go test -run TestSensitive_RedactsAllSurfaces ./...` | ❌ W0 | ⬜ pending |
| `X-CSRF-Token` response-header capture + echo on state-changing requests (§3 non-browser) | GO-01 | CSRF | header round-trip on mutating verbs | unit (`httptest`) | `go test -run TestCSRF_CaptureAndForward ./...` | ❌ W0 | ⬜ pending |
| Tenant header (REST `X-Tenant-ID` / gRPC `x-tenant-id` metadata) injected every request (§5) | GO-01 | cross-tenant | tenant context on every call | unit | `go test -run TestTenantHeader_InjectedOnEveryRequest ./...` | ❌ W0 | ⬜ pending |
| Middleware tenant-claim check after JWKS verify (org-wide JWKS ≠ tenant scope) | GO-01 | cross-tenant token replay | `claims.tenant_id == configured` | unit | `go test -run TestMiddleware_RejectsCrossTenant ./...` | ❌ W0 | ⬜ pending |
| JWKS EdDSA/Ed25519 alg-allowlist (reject `none`/`HS256`) | GO-01 | algorithm confusion | explicit alg allowlist pre-verify | unit | `go test -run TestJWKS_RejectsWrongAlg ./...` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `sdks/buf.gen.yaml` Go `out:` path fix — stubs must land in `sdks/go/internal/gen` (D-01), not `sdks/go/gen` (research Pitfall 2); prerequisite for any gRPC test to compile
- [ ] `sdks/go/internal/gen/` — buf-generated committed stubs (must exist before gRPC tests compile)
- [ ] `sdks/go/go.sum` — populated once the three pinned deps are added
- [ ] `.github/workflows/sdk-ci-go.yml` — new per-SDK CI (`paths: sdks/go/**`): `go build ./...`, `go vet ./...`, `go test ./...`, TLS-bypass grep gate, buf drift-check, tag-triggered `sdks/go/vX.Y.Z` publish
- [ ] No existing Go test infrastructure in `sdks/go/` (scaffold-only) — the entire suite is new this phase

*Expected for a phase delivering a brand-new SDK from a placeholder scaffold.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| buf codegen + `git diff --exit-code` drift-check, and module publish (SC#5) | GO-01 | The `buf` CLI is not installed in the sandbox; codegen/drift/publish run in CI where buf is available. | In a buf-enabled env or CI: `cd sdks && buf generate` then `git diff --exit-code sdks/go/internal/gen`; publish is the tag-triggered `sdks/go/vX.Y.Z` GH Actions job. |
| Live RabbitMQ / real AXIAM gRPC smoke (build-tagged) | GO-01 | Consumer + gRPC contracts are covered against recording fakes / `httptest` (D-10, no live broker in default run); end-to-end broker/server exercise is optional. | Optional: `go test -tags=integration ./...` against a live RabbitMQ + AXIAM server (testcontainers). |

*Automated tests cover every phase behavior; the items above are environment/tooling gates (CI-run), not gaps in automated verification.*

---

## Validation Sign-Off

- [ ] All tasks have automated verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags (`go test` is one-shot)
- [ ] Feedback latency < 5s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
