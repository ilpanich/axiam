# Phase 16: Rust SDK - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-30
**Phase:** 16-rust-sdk
**Areas discussed:** Async model, Transport feature-gating, Token model & cross-transport auth, Error idiom, gRPC channel pattern, AMQP consumer shape, Example apps scope, Publish/CI trigger, MSRV policy, JWKS endpoint & cache, Retry/backoff, Observability/tracing, Timeouts & config defaults, Token-from-cookie mechanics

> **Framing:** `sdks/CONTRACT.md` §1–§10 (binding) and `RUST-01` already locked the SDK's behavioral *what* (method names, error taxonomy, CSRF, cookie jar, tenant context, TLS, `Sensitive<T>`, AMQP HMAC, single-flight refresh, middleware, pinned crate versions). Discussion covered only the open *how* choices, which carry extra weight because Rust is the reference implementation for Phases 17–22.

---

## Async Model & API Surface

| Option | Description | Selected |
|--------|-------------|----------|
| Async-only (tokio) | One async surface; gRPC/AMQP force async, blocking wrapper doubles maintenance for uneven coverage | ✓ |
| Async + blocking facade | Feature-gated blocking REST over reqwest::blocking; gRPC/AMQP can't be made blocking cleanly | |

**User's choice:** Async-only (tokio)
**Notes:** Sets async-first precedent; Python's sync+async (Ph19) is the documented exception.

---

## Transport Packaging (Cargo Features)

| Option | Description | Selected |
|--------|-------------|----------|
| All-on default, each gated | `default=[rest,grpc,amqp]` so `cargo add` is full coverage; each transport its own feature so REST-only users opt out | ✓ |
| REST-only default, opt-in | Lightest default but contradicts "cargo add = full coverage" criterion | |
| No features, always all | Simplest code; every dependent pays tonic+lapin compile cost | |

**User's choice:** All-on default, each gated
**Notes:** Modularity pattern the TS persona-split (Ph17) mirrors.

---

## Token Validation & Cross-Transport Auth

| Option | Description | Selected |
|--------|-------------|----------|
| Local JWKS verification | Fetch+cache JWKS, verify Ed25519 + exp locally; enables proactive refresh + per-request-free §10 middleware | ✓ |
| Opaque / reactive only | No local JWT parsing; refresh only on 401; §10 middleware must call server per request | |

**User's choice:** Local JWKS verification
**Notes:** Matches JWKS libs every other SDK pulls (jose/PyJWT/nimbus/jwx). Single-flight 401 handling stays as fallback.

---

## gRPC Channel / Auth Pattern

| Option | Description | Selected |
|--------|-------------|----------|
| Shared channel + interceptor | One lazy tonic::Channel reused; interceptor injects auth + x-tenant-id metadata, triggers single-flight refresh | ✓ |
| Per-call metadata, no interceptor | Caller attaches metadata per RPC; repetitive, weaker reference pattern | |

**User's choice:** Shared channel + interceptor

---

## AMQP Consumer API Shape

| Option | Description | Selected |
|--------|-------------|----------|
| Closure handler | `consume(queue, \|event\| ...)`; SDK owns ack/nack loop, HMAC-verifies before handler, nacks-without-requeue on failure | ✓ |
| Async Stream of events | User drives ack/nack; more flexible but pushes nack-without-requeue correctness onto the user | |
| You decide | Leave to planner | |

**User's choice:** Closure handler

---

## Error Idiom

| Option | Description | Selected |
|--------|-------------|----------|
| Single AxiamError enum | thiserror enum, Auth/Authz/Network variants; one `?`-friendly return type | ✓ |
| Three distinct error types | Mirrors contract names literally but forces a wrapper enum at call sites anyway | |

**User's choice:** Single AxiamError enum

---

## Example Apps Scope

| Option | Description | Selected |
|--------|-------------|----------|
| Full per-capability set | login+MFA, REST check (+batch/can), gRPC Check/BatchCheck, AMQP consumer, Actix-protected route | ✓ |
| Minimal (auth + one authz path) | Faster but leaves gRPC/AMQP/middleware undemonstrated | |
| You decide | Planner chooses | |

**User's choice:** Full per-capability set
**Notes:** Doubles as the CONTRACT §1–§10 conformance demonstration.

---

## Publish / CI Trigger Model

| Option | Description | Selected |
|--------|-------------|----------|
| Path-tag + bundle-on-publish | Dry-run gate on PRs to `sdks/rust/**`; publish on tag `sdks/rust/vX.Y.Z`; regenerate+bundle buf stubs (D-02) | ✓ |
| GitHub Release-triggered | Publish on published Release; diverges from per-SDK monorepo tag scheme | |
| You decide | Planner decides mechanics | |

**User's choice:** Path-tag + bundle-on-publish

---

## MSRV Policy

| Option | Description | Selected |
|--------|-------------|----------|
| Derive from dep floors, CI-enforce | MSRV = highest min among tonic/reqwest/lapin/tokio; documented + CI job | ✓ |
| Latest stable only | No MSRV guarantee; unfriendly to pinned-toolchain enterprises | |
| You decide | Research picks from dep floors | |

**User's choice:** Derive from dep floors, CI-enforce

---

## JWKS Endpoint & Cache Policy

| Option | Description | Selected |
|--------|-------------|----------|
| OIDC discovery + cache w/ rotation | OIDC `/.well-known/jwks.json`, TTL cache, refetch on unknown kid | ✓ |
| You decide / research | Treat endpoint+caching as research detail | |

**User's choice:** OIDC discovery + cache w/ rotation
**Notes:** Exact path confirmed in research against the chosen OIDC crate.

---

## Retry / Backoff Policy

| Option | Description | Selected |
|--------|-------------|----------|
| Bounded backoff, idempotent only | Auto-retry idempotent ops only, honor Retry-After on 429, exp backoff+jitter, ~2-3 max; mutations never retried | ✓ |
| No auto-retry | Surface every NetworkError immediately; every consumer reimplements backoff | |
| You decide | Planner decides within no-auth-retry rule | |

**User's choice:** Bounded backoff, idempotent only

---

## Observability / Tracing

| Option | Description | Selected |
|--------|-------------|----------|
| `tracing` spans, on by default | Instrument lifecycle/refresh/gRPC/AMQP, redaction-aware; users add a subscriber | |
| `tracing`, feature-gated off | Same instrumentation behind an `observability` feature, off by default; leaner baseline | ✓ |
| You decide | Planner decides depth | |

**User's choice:** `tracing`, feature-gated off
**Notes:** User chose off-by-default, differing from the on-by-default recommendation. Instrumentation must remain redaction-aware (never emit token values).

---

## Client Timeouts & Config Defaults

| Option | Description | Selected |
|--------|-------------|----------|
| Sane defaults, builder-overridable | ~10s connect / ~30s request, lapin auto-reconnect, base_url required, all overridable | ✓ |
| You decide | Research/planner picks values | |

**User's choice:** Sane defaults, builder-overridable

---

## Token-from-Cookie Mechanics

| Option | Description | Selected |
|--------|-------------|----------|
| Confirm in research, prefer jar-read | Research-confirm whether SDK reads tokens from cookie jar or login-response body; prefer jar-read | ✓ |
| Assume login-response-body tokens | Design assuming tokens in JSON body, decide now | |
| You decide | Leave entirely to research | |

**User's choice:** Confirm in research, prefer jar-read
**Notes:** Partly a server-contract fact; either way the raw token is wrapped in `Sensitive<T>` immediately.

---

## Claude's Discretion

- Crate module/file layout and internal organization of the single-flight guard.
- Specific numeric timeout/backoff values and max-attempt counts.
- Name of the `tracing`/observability feature.
- Choice of OAuth2/OIDC + JWKS crate (must support Ed25519/EdDSA JWKS verification).

## Deferred Ideas

- Blocking/sync facade for Rust (rejected for the reference; revisit on demand).
- On-by-default tracing (user chose off; revisit if cross-SDK expectation shifts).
- Async Stream-based AMQP consumer (deferred in favor of closure-handler safety).
- Automated cross-language conformance harness (inherited from Phase 15 deferred; per-phase checklist used instead).
