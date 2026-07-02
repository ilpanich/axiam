# Phase 19: Python SDK - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-01 (interactive session; supersedes the earlier interrupted session)
**Phase:** 19-python-sdk
**Areas discussed:** Sync/async architecture · Packaging build backend · FastAPI integration · Django integration · Python version floor · gRPC async coverage · Examples breadth · Package layout · Logging · JWKS · HTTP resilience · CI matrix · Client lifecycle · Type/lint toolchain · LoginResult shape

> **Process note:** An earlier session (same date) could not complete the per-area
> question round — the tool's permission stream closed on a resumed session — so its
> decisions were resolved to the recommended option and flagged `[recommended —
> revisable]`. This session re-opened the discussion; the user **interactively
> confirmed all four original decisions** and **locked eleven additional decisions**
> across four question rounds. All 15 are now user-locked in CONTEXT.md.

---

## Round 1 — the four originally-open gray areas (all confirmed)

## Sync/async architecture

| Option | Description | Selected |
|--------|-------------|----------|
| Unified client (sync + `async_*` on one object) | Both `login()` and `async_login()` on one object; shared session; threading.Lock + asyncio.Lock; satisfies SC#1 verbatim | ✓ |
| Two-class split (`AxiamClient` / `AsyncAxiamClient`) | httpx-idiomatic; cleaner internally but breaks SC#1's literal `client.async_login` | |

**Chosen:** Unified `AxiamClient` (D-01, now LOCKED). **Notes:** confirmed to honor SC#1's literal test. Two-class idiom stays deferred behind an SC#1 wording reconciliation.

## Packaging build backend

| Option | Description | Selected |
|--------|-------------|----------|
| `setuptools.build_meta` | Standard PEP 517; matches scaffold's setuptools>=68 + PEP 621; smallest correct fix | ✓ |
| Hatchling | Modern; cleaner stub/package-data inclusion; larger departure | |

**Chosen:** `setuptools.build_meta` (D-03, now LOCKED), fixing the invalid `setuptools.backends.legacy:build`.

## FastAPI integration

| Option | Description | Selected |
|--------|-------------|----------|
| `Depends(...)` dependency only | Local PyJWT verify → returns identity; HTTPException 401/403; minimal surface | ✓ |
| Dependency + ASGI middleware | Also app-wide middleware variant; more surface to test/maintain | |

**Chosen:** FastAPI dependency-only (D-09, now LOCKED).

## Django integration

| Option | Description | Selected |
|--------|-------------|----------|
| Sync WSGI middleware, ASGI-capable | `request.axiam_user`; broadest compat; declares sync_capable/async_capable | ✓ |
| Async ASGI-first | Optimize for async Django; sync via adapter | |
| Both first-class | Separate hand-tuned sync + async paths; most work | |

**Chosen:** Django middleware, sync-WSGI-primary + ASGI-capable (D-10, now LOCKED).

---

## Round 2 — reach, transports, layout

## Python version floor

| Option | Description | Selected |
|--------|-------------|----------|
| `>=3.10` | Drops EOL 3.9; oldest non-EOL; `X | Y` unions + match; broad reach; CI 3.10–3.13 | ✓ |
| `>=3.9` (max reach) | Scaffold default but EOL; older typing idioms | |
| `>=3.11` (modern) | Faster, Self type, tomllib; narrower reach | |

**Chosen:** `requires-python = ">=3.10"` (D-11). **Notes:** scaffold's `>=3.9` is now EOL.

## gRPC async coverage

| Option | Description | Selected |
|--------|-------------|----------|
| Both sync + `grpc.aio` | Sync + async gRPC clients from one codegen; matches unified client | ✓ |
| Sync-only gRPC | Async authz via REST/executor; less surface | |

**Chosen:** Both sync + `grpc.aio` (D-12).

## Examples breadth

| Option | Description | Selected |
|--------|-------------|----------|
| Full per-capability set | login+MFA, REST, gRPC, AMQP, FastAPI, Django (sibling parity) | ✓ |
| Minimal (SC#4 only) | Just FastAPI + Django; others shown via tests/README | |

**Chosen:** Full per-capability examples set (D-13).

## Package layout

| Option | Description | Selected |
|--------|-------------|----------|
| src-layout (`src/axiam_sdk/`) | Modern best practice; catches package-data gaps (committed stubs) | ✓ |
| Flat layout | Keep scaffold's `axiam_sdk/`; zero restructure but import-shadowing risk | |
| Planner's call | Delegate | |

**Chosen:** src-layout (D-14).

---

## Round 3 — runtime behavior & CI

## Logging / observability

| Option | Description | Selected |
|--------|-------------|----------|
| Injectable stdlib `logging.Logger` | NullHandler (off by default); integrates with app config; no token values | ✓ |
| Custom callback protocol | Framework-agnostic but non-idiomatic | |
| structlog | Structured output but adds a dependency | |

**Chosen:** stdlib `logging.Logger`, off by default (D-15).

## JWKS verification

| Option | Description | Selected |
|--------|-------------|----------|
| PyJWT `PyJWKClient` | Built-in fetch/cache/rotation on unknown kid; least custom crypto | ✓ |
| Hand-rolled JWKS cache | More control; more security-sensitive code | |

**Chosen:** PyJWT `PyJWKClient` (D-16).

## HTTP timeouts & retry

| Option | Description | Selected |
|--------|-------------|----------|
| Sane defaults, overridable | Timeouts + bounded backoff+jitter on idempotent ops (429/503, Retry-After) | ✓ |
| httpx defaults only | No SDK auto-retry; caller adds it | |

**Chosen:** Sane defaults, overridable (D-17).

## CI test matrix

| Option | Description | Selected |
|--------|-------------|----------|
| 3.10–3.13 on Linux | pytest + verify=False gate + buf drift-check; floor-to-latest at reasonable cost | ✓ |
| Add macOS + Windows | Cross-platform assurance; ~3x CI minutes | |
| Minimal (3.10 + 3.13) | Fastest; misses 3.11/3.12 regressions | |

**Chosen:** 3.10–3.13 on `ubuntu-latest` (D-18). macOS/Windows deferred.

---

## Round 4 — lifecycle, tooling, result modeling

## Client lifecycle

| Option | Description | Selected |
|--------|-------------|----------|
| Both sync + async context managers | `with` / `async with` + `.close()`/`.aclose()`; tears down httpx/gRPC/aio-pika | ✓ |
| Explicit close() only | No CM protocol; callers must remember to close | |

**Chosen:** sync + async context managers + explicit close (D-19).

## Type/lint toolchain

| Option | Description | Selected |
|--------|-------------|----------|
| `py.typed` + mypy-strict + ruff | PEP 561 marker; strong CI quality bar for a typed Pydantic-v2 SDK | ✓ |
| `py.typed` + ruff only | Types + lint; mypy advisory | |
| Minimal (ruff only) | Lint/format only; no shipped types | |

**Chosen:** `py.typed` + `mypy --strict` + `ruff` (D-20).

## LoginResult shape

| Option | Description | Selected |
|--------|-------------|----------|
| Single model + `mfa_required` flag | One `LoginResult` (Pydantic) with the flag; SC#1-literal; Go CF-04 / TS D-18 analog | ✓ |
| Discriminated union | `LoginSuccess | MfaRequired`; more type-safe but SC#1 tests the flat field | |

**Chosen:** Single `LoginResult` model with `mfa_required: bool` (D-21).

---

## Claude's Discretion (remaining after this session)

- Internal module layout and file names within `src/axiam_sdk/`.
- Numeric timeout/backoff/retry values and default AMQP prefetch/QoS (policy set; numbers to planner).
- Exact `async_*` method naming and `LoginResult` optional-field set beyond `mfa_required`.
- Exact `PyJWKClient` cache-TTL/rotation API usage.
- `__init__.py` public export surface and README structure.

## Deferred Ideas

- SC#1 wording ↔ two-class idiom reconciliation (flag for planner; do not silently diverge).
- Sync AMQP (`pika`) — rejected (PY-01 pins aio-pika); revisit only on real demand.
- REQUIREMENTS PY-01 wording audit (package/tag/module identifiers vs scaffold).
- Automated cross-language conformance harness — inherited deferred item.
- macOS/Windows CI matrix — deferred (Linux-only) for CI cost.
