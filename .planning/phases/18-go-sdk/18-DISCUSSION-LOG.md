# Phase 18: Go SDK - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-01
**Phase:** 18-go-sdk
**Areas discussed:** gRPC stub distribution, Module granularity, Client API idiom, Error taxonomy idiom, AMQP consumer signature & ack semantics, Sensitive token type redaction surface, Timeout/reconnect defaults & client override safety, Examples & test layout

---

## gRPC Stub Distribution

| Option | Description | Selected |
|--------|-------------|----------|
| Commit stubs to source tree + CI drift-check | Commit `.pb.go`/`_grpc.pb.go` into `sdks/go/`; documented Go exception to Phase 15 D-01; CI regenerates + `git diff --exit-code` blocks drift | ✓ |
| Generate only at release-tag time | Keep stubs gitignored on main, commit only into the tag commit | |

**User's choice:** Commit stubs to source tree + CI drift-check.
**Notes:** `go get` fetches source and cannot run buf, so stubs must be present in the tree — there is no separate build artifact to bundle into (unlike Rust crates.io / npm tarball). → CONTEXT D-01.

---

## Module Granularity

| Option | Description | Selected |
|--------|-------------|----------|
| Single module, sub-packages | One `github.com/ilpanich/axiam/sdks/go` module with `/grpc` `/amqp` sub-packages; Go compiles only imported packages (no binary bloat); one tag | ✓ |
| Split modules per transport | Separate `go.mod` per transport for minimal REST-only module graph | |

**User's choice:** Single module, sub-packages.
**Notes:** Matches the existing scaffold `go.mod`. Go's per-package compilation means REST-only consumers never compile grpc-go/amqp091 into their binary; the only cost is module-graph entries. → CONTEXT D-02.

---

## Client API Idiom

| Option | Description | Selected |
|--------|-------------|----------|
| Functional options, required params positional | `NewClient(baseURL, tenantSlug string, opts ...Option)`; `WithCustomCA`/`WithTimeout`/`WithHTTPClient` optional; compile-time tenant enforcement | ✓ |
| Config struct | `NewClient(Config{...})`; required-vs-optional not type-enforced (zero-value compiles) | |

**User's choice:** Functional options, required params positional.
**Notes:** Positional `baseURL`/`tenantSlug` give compile-time enforcement of §5 + SC#1 ("enforced at call time"). → CONTEXT D-03.

---

## Error Taxonomy Idiom

| Option | Description | Selected |
|--------|-------------|----------|
| Typed structs + errors.As, redact-before-wrap | `AuthError`/`AuthzError`/`NetworkError` structs; `errors.As` discrimination; `NetworkError.Unwrap()` but constructor redacts Set-Cookie/Authorization/Cookie first (CR-04); sentinel vars for `errors.Is` | ✓ |
| Sentinel values only | `ErrAuth`/`ErrAuthz`/`ErrNetwork` matched via `errors.Is`; no structured fields/cause | |

**User's choice:** Typed structs + errors.As, redact-before-wrap.
**Notes:** Direct carry-forward of Phase 17 CR-04 (token leak via `NetworkError.cause` carrying `Set-Cookie`). Typed structs also carry §2's `Action`/`ResourceID`. → CONTEXT D-04.

---

## AMQP Consumer Signature & Ack Semantics

| Option | Description | Selected |
|--------|-------------|----------|
| Return-err = requeue; HMAC-fail/sentinel = drop | `Consume(ctx, queue, func(ctx, Event) error)`; nil→ack, err→nack-WITH-requeue, `amqp.ErrDrop`/HMAC-fail→nack-WITHOUT-requeue; configurable prefetch | ✓ |
| Any handler error = nack-without-requeue | Any error drops the message permanently | |

**User's choice:** Return-err = requeue; HMAC-fail/sentinel = drop.
**Notes:** Preserves a redelivery path for transient failures while keeping the §8 nack-without-requeue guarantee for HMAC failures and poison messages. Mirrors Rust D-07. → CONTEXT D-07.

---

## Sensitive Token Type Redaction Surface

| Option | Description | Selected |
|--------|-------------|----------|
| String + Format + GoString + MarshalJSON | `type Sensitive string`; redacts across `%v/%+v/%s/%q`, `%#v`, and `json.Marshal`; package-internal raw accessor | ✓ |
| §7 minimum (String only) | Only `String() → [SENSITIVE]`; `%#v`/`%+v`/JSON could still leak | |

**User's choice:** String + Format + GoString + MarshalJSON redaction.
**Notes:** Closes the same leak class as CR-04 across all Go output surfaces; Go analog of TS D-26. → CONTEXT D-08.

---

## Timeout/Reconnect Defaults & Client Override Safety

| Option | Description | Selected |
|--------|-------------|----------|
| SDK-owned jar+TLS, override transport/timeouts only | Sane defaults; `WithHTTPClient` sets Transport/timeout but SDK re-applies cookiejar (§4) + TLS (§6) over any supplied client | ✓ |
| Full client replacement | `WithHTTPClient` fully replaces the internal client; caller owns jar/TLS invariants | |

**User's choice:** SDK-owned jar+TLS, override transport/timeouts only.
**Notes:** Prevents an override from silently dropping the cookie jar (breaks post-login) or bypassing TLS (§6). Exact numeric defaults left to planner (CF-03). → CONTEXT D-09.

---

## Examples & Test Layout

| Option | Description | Selected |
|--------|-------------|----------|
| Per-capability example mains; mocked units + optional testcontainers smoke | `examples/` main packages per capability; deterministic mocked/httptest unit tests; optional build-tagged testcontainers smoke for gRPC/AMQP | ✓ |
| Live-server examples; mandatory testcontainers integration | Examples hit a live server; testcontainers integration mandatory in default `go test ./...` | |

**User's choice:** Per-capability example mains; mocked units + optional testcontainers smoke.
**Notes:** Keeps `go test ./...` fast, hermetic, and the SC#2 concurrency test deterministic; mirrors the Rust example set. → CONTEXT D-10.

---

## Claude's Discretion

- Internal package/file layout, `Sensitive` internal-accessor naming, single-flight guard internals.
- Concrete numeric timeout/backoff/retry values and default prefetch/QoS count.
- Precise `LoginResult` shape (CF-04).
- Exact `jwx/v3` JWKS caching/rotation API usage (D-06).
- Go version floor (`go.mod` `go 1.22`) — planner, CI-enforced.

## Locked as Go-idiom (no question needed)

- **D-05:** `context.Context` first param on every I/O method (grpc-go + Go convention).
- **D-06:** `net/http` middleware injects identity via `context.WithValue`, retrieved with
  `axiam.UserFromContext(ctx)`; local JWKS verification (no per-request round-trip).
- **CF-04:** `Login` returns a typed MFA-required-vs-authenticated result (carried from TS D-18).

## Deferred Ideas

- REQUIREMENTS GO-01 module-path/tag reconciliation (`github.com/axiam/axiam-go-sdk` + `sdk/go/vX.Y.Z`
  stale vs canonical scaffold `github.com/ilpanich/axiam/sdks/go` + `sdks/go/vX.Y.Z`) — scoped planner doc edit.
- Split per-transport modules — rejected (un-idiomatic/tag-heavy); revisit only on real module-graph complaints.
- Mandatory testcontainers integration in default `go test ./...` — kept optional/build-tagged.
- Automated cross-language conformance harness — inherited deferral; per-phase §1–§10 checklist for now.
