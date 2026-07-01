# Phase 19: Python SDK - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-01
**Phase:** 19-python-sdk
**Areas discussed:** Sync/async architecture, Packaging & gRPC stubs, Token safety & models, FastAPI + Django helpers

> **Process note:** The user selected all four gray areas for discussion via the
> area-selection question. The follow-up per-area question round (AskUserQuestion)
> could not complete — the tool's permission stream closed on a resumed session.
> Decisions were therefore resolved to the **recommended option** for each (all
> grounded in the Rust/TS/Go reference SDKs and the binding CONTRACT.md), with the
> genuinely-open ones flagged `[recommended — revisable]` in CONTEXT.md for user
> override before planning.

---

## Sync/async architecture

| Option | Description | Selected |
|--------|-------------|----------|
| Two classes (`AxiamClient` / `AsyncAxiamClient`) | httpx-native split; cleanest state/lock separation but breaks SC#1's literal `client.async_login` | |
| One unified client (sync + `async_*` methods) | Both `login()` and `async_login()` on one object; satisfies SC#1 verbatim; holds both httpx clients + both lock types | ✓ |
| Async-core + sync wrapper | Async internals, sync wraps via event loop; footgun-prone for a security SDK | |

**Chosen:** Unified `AxiamClient` (D-01). **AMQP scope (D-02):** async-only via `aio-pika` — locked by PY-01 acceptance, not a free choice.
**Notes:** Unified client picked specifically to honor SC#1's literal test (`client.login` AND `await client.async_login`). `asyncio.Lock` guards async single-flight (SC#2 via pytest-asyncio); `threading.Lock` guards sync. Two-class idiom deferred behind an SC#1 wording reconciliation.

---

## Packaging & gRPC stubs

| Option | Description | Selected |
|--------|-------------|----------|
| Build backend: Hatchling | Modern PEP 517/621, clean stub inclusion | (alt) |
| Build backend: `setuptools.build_meta` | Standard; consistent with scaffold's declared setuptools toolchain | ✓ |
| Build backend: PDM/uv build | Modern but less ubiquitous | |
| Stubs: commit + drift-check + ship in wheel | Go D-01 analog; pip consumers can't run protoc | ✓ |
| Stubs: generate-at-build into wheel | No committed codegen but adds build-time protoc + hurts reproducibility | |

**Chosen:** `setuptools.build_meta` fixing the broken `setuptools.backends.legacy:build` (D-03, Hatchling acceptable alternative); commit stubs + CI drift-check + ship in wheel/sdist (D-04); tag-triggered PyPI publish with Trusted Publishing/OIDC (D-05).
**Notes:** The scaffold's current build backend value is invalid and must be fixed regardless. Stub distribution mirrors Go exactly because the ecosystem constraint (consumers can't codegen) is identical.

---

## Token safety & models

| Option | Description | Selected |
|--------|-------------|----------|
| Models: Pydantic v2 | Locked by PY-01; idiomatic, validation, FastAPI-native | ✓ |
| Sensitive: Pydantic `SecretStr` | Redacts repr/str/model_dump; raw via `.get_secret_value()` — is the §7 type | ✓ |
| Sensitive: custom wrapper | Extra code; unnecessary when SecretStr covers the leak surfaces | |

**Chosen:** Pydantic v2 models (D-06, locked); `LoginResult` with `mfa_required: bool` discriminating MFA-required from authenticated; `SecretStr` as the §7 Sensitive type (D-07); exception taxonomy + redact-before-wrap `NetworkError` (D-08, CR-04 carry-forward); PyJWT for JWKS.
**Notes:** Models library was not truly open (PY-01 pins Pydantic v2). The real decision was the §7 Sensitive mechanism → SecretStr, plus the CR-04 error-redaction carry-forward.

---

## FastAPI + Django helpers

| Option | Description | Selected |
|--------|-------------|----------|
| FastAPI: `Depends` dependency returning identity | Idiomatic FastAPI; local JWKS verify; 401/403 via HTTPException | ✓ |
| Django: sync WSGI middleware (`request.axiam_user`) | Broadest compatibility; async-capable flags for ASGI when cheap | ✓ |

**Chosen:** FastAPI dependency-injection callable returning the authenticated identity (D-09); Django middleware class attaching `request.axiam_user`, sync-WSGI primary with ASGI compatibility (D-10). Both demonstrated in runnable examples (SC#4).
**Notes:** Verification is local (PyJWT + cached JWKS), no per-request server round-trip, honoring §10.

---

## Claude's Discretion

- Internal package/module layout and file names.
- Numeric timeout/backoff/retry values and default AMQP prefetch/QoS.
- Exact `LoginResult` shape and `async_*` method naming.
- src-layout vs flat; Python version floor (scaffold `requires-python >=3.9`).
- Exact PyJWT JWKS-cache/rotation API usage.

## Deferred Ideas

- SC#1 wording ↔ two-class idiom reconciliation (flag for planner; do not silently diverge).
- Sync AMQP (`pika`) — rejected (PY-01 pins aio-pika); revisit only on real demand.
- REQUIREMENTS PY-01 wording audit (package/tag/module identifiers vs scaffold).
- Automated cross-language conformance harness — inherited deferred item.
